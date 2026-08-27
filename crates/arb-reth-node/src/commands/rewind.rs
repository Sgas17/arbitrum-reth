//! `arb-reth rewind`: unwind the node's database to an earlier L2 block after a divergence.
//!
//! A state-root mismatch is deterministic and monotone-forward: if block `N` is wrong, every
//! descendant `N+1..tip` was built on the bad state and is wrong too. The parity monitor pins the
//! first divergent block `N`; this tool discards the poisoned suffix by unwinding the DB to keep
//! `N-1` as the new tip, then truncates the L1-resume log to a boundary at or below `N-1` so a
//! subsequent sync resumes derivation from there instead of re-syncing 200M blocks
//! from Nitro genesis.
//!
//! It reuses reth's `remove_block_and_execution_above` (the exact storage-v2 unwind the engine
//! tree runs on a reorg), so blocks, receipts, state, hashed state, trie, history indices, and
//! stage checkpoints are all rolled back consistently.
//!
//! Note: this does not fix the STF bug that caused the divergence. Re-syncing past `N` with the
//! same binary will diverge again at `N`. Rewind is for after you have a fix (or to re-derive a
//! suspicious range under the parity monitor). Run it only while the node is stopped (MDBX is
//! single-writer).
//!
//! ## Usage
//!
//! ```text
//! # keep block N-1 as the new tip (drop the first divergent block N and everything above)
//! arb-reth rewind --datadir /tmp/arb1-sync --snapshot-head head-block.stream --diverged-at <N>
//!
//! # equivalently, name the block to KEEP as the new tip
//! arb-reth rewind --datadir /tmp/arb1-sync --snapshot-head head-block.stream --to <N-1>
//! ```

use std::path::PathBuf;
use std::sync::Arc;

use crate::{read_head_header, ArbNode, L1ResumeLog, ARB_ONE_CHAIN_ID};
use clap::Parser;
use reth_chainspec::ChainSpec;
use reth_db::{init_db, mdbx::DatabaseArguments, ClientVersion};
use reth_db_api::models::StorageSettings;
use reth_node_types::NodeTypesWithDBAdapter;
use reth_provider::{
    providers::{RocksDBProvider, StaticFileProvider},
    BlockNumReader, HeaderProvider, ProviderFactory, StorageSettingsCache,
};
use reth_tasks::Runtime;
use reth_tracing::tracing::info;

type ArbNodeTypesWithDB = NodeTypesWithDBAdapter<ArbNode, reth_db::DatabaseEnv>;

#[derive(Debug, Parser)]
#[command(name = "arb-rewind", about = "Unwind the arb-reth database to an earlier L2 block")]
pub struct RewindArgs {
    /// Data directory of the node to rewind (the dir holding `db/`, `static_files/`, `rocksdb/`).
    #[arg(long, value_name = "PATH")]
    datadir: PathBuf,

    /// Snapshot head stream (`reth-export --mode blocks`), used to build the chain spec so the DB
    /// opens: the same file passed to `arb-reth --snapshot-head`. For a snapshot-seeded datadir
    /// (Arbitrum One). Alternative to the orbit `--chain-info`/`--genesis` pair.
    #[arg(long = "snapshot-head", value_name = "PATH")]
    snapshot_head: Option<PathBuf>,

    /// Orbit boot: Nitro `chaininfo.json`. Paired with `--genesis`, builds the chain spec for a
    /// datadir booted from genesis files (not a snapshot), e.g. Robinhood. Alternative to
    /// `--snapshot-head`; the genesis floor is that chain's genesis block (0 for a fresh chain).
    #[arg(long = "chain-info", value_name = "PATH", requires = "genesis_json")]
    chain_info: Option<PathBuf>,

    /// Orbit boot: Nitro `genesis.json` (paired with `--chain-info`).
    #[arg(long = "genesis", value_name = "PATH")]
    genesis_json: Option<PathBuf>,

    /// New chain tip to keep (this block survives; everything above it is removed).
    #[arg(long = "to", value_name = "BLOCK", conflicts_with = "diverged_at", required_unless_present = "diverged_at")]
    to: Option<u64>,

    /// First divergent block `N` (from the parity monitor). Keeps `N-1` as the new tip.
    #[arg(long = "diverged-at", value_name = "BLOCK")]
    diverged_at: Option<u64>,

    /// Arbitrum chain id (matches `arb-reth --chain-id`).
    #[arg(long, default_value_t = ARB_ONE_CHAIN_ID)]
    chain_id: u64,

    /// Report what would happen without modifying the database or the resume log.
    #[arg(long)]
    dry_run: bool,
}

pub fn run(args: RewindArgs) -> eyre::Result<()> {
    // New tip: `--to` names it directly; `--diverged-at N` keeps N-1. Clap guarantees exactly one.
    let new_tip = match (args.to, args.diverged_at) {
        (Some(to), _) => to,
        (None, Some(n)) => n
            .checked_sub(1)
            .ok_or_else(|| eyre::eyre!("--diverged-at must be >= 1 (block 0 is genesis)"))?,
        (None, None) => unreachable!("clap requires --to or --diverged-at"),
    };

    // Build the chain spec and the genesis floor (the block we cannot rewind below). Two boot modes:
    // a snapshot-seeded datadir (Arbitrum One) reads its genesis header from the head stream; an
    // orbit datadir (booted from chaininfo + genesis files, e.g. Robinhood) builds the spec from
    // those files and sits at its genesis block. `snapshot_seeded` gates the changeset-layout
    // migration below (only the snapshot import mis-seeds those segments).
    let (genesis_num, chain_spec, snapshot_seeded): (u64, Arc<ChainSpec>, bool) =
        match (&args.snapshot_head, &args.chain_info, &args.genesis_json) {
            (Some(head), _, _) => {
                let (genesis_num, genesis_hash, genesis_header) = read_head_header(head)?;
                let spec = crate::arb_chain_spec_with_header(args.chain_id, genesis_header, genesis_hash);
                (genesis_num, spec, true)
            }
            (None, Some(ci), Some(g)) => {
                let ci_json = std::fs::read(ci).map_err(|e| eyre::eyre!("read chain-info {ci:?}: {e}"))?;
                let g_json = std::fs::read(g).map_err(|e| eyre::eyre!("read genesis {g:?}: {e}"))?;
                let (spec, init, _info) = crate::orbit_chain_from_files(&ci_json, &g_json)?;
                (init.genesis_block_number, Arc::new(spec), false)
            }
            (None, _, _) => {
                return Err(eyre::eyre!(
                    "provide either --snapshot-head (snapshot-seeded datadir, e.g. Arbitrum One) or \
                     --chain-info together with --genesis (orbit datadir, e.g. Robinhood)"
                ))
            }
        };

    let db_path = args.datadir.join("db");
    let static_files_path = args.datadir.join("static_files");
    let rocksdb_path = args.datadir.join("rocksdb");
    if !db_path.exists() {
        return Err(eyre::eyre!("no database at {} (is --datadir correct?)", db_path.display()));
    }

    // Correct the genesis-import changeset-segment layout before opening the DB (so no reth code,
    // `check_consistency` in particular, touches the mis-seeded files first). The snapshot import
    // seeded the changeset segments with `set_block_range(head, head)`, which left
    // `expected_block_start` at the fixed 500k-slot boundary (22000000) and `block_range.start` at
    // genesis. That breaks stock reth two ways on unwind: `truncate_changesets` keys off
    // `expected_block_start` (which corrupts the offset map), and reads are shifted +1 (genesis
    // carries no changeset, so csoff[0] is really block genesis+1). Realign both to genesis+1 (the
    // first block that actually has a changeset) and rename the files to match, after which stock
    // reth's unwind and reads are correct with no reth patch. Idempotent + guarded. See
    // `arb-snapshot-import.rs`, which mirrors reth's `init_genesis` for fresh imports.
    // Only snapshot-seeded datadirs carry the mis-seeded layout; an orbit datadir booted fresh from
    // genesis files writes stock-aligned changeset segments, so skip the migration there.
    if snapshot_seeded {
        crate::recovery::normalize_snapshot_changeset_layout(&static_files_path, genesis_num)?;
    }

    let db = init_db(&db_path, DatabaseArguments::new(ClientVersion::default()))?;
    let static_file_provider = StaticFileProvider::read_write(static_files_path)?;
    let rocksdb_provider = RocksDBProvider::builder(&rocksdb_path)
        .with_default_tables()
        .build()
        .map_err(|e| eyre::eyre!("RocksDB open error: {e}"))?;

    let factory: ProviderFactory<ArbNodeTypesWithDB> =
        ProviderFactory::new(db, chain_spec, static_file_provider, rocksdb_provider, Runtime::test())
            .map_err(|e| eyre::eyre!("ProviderFactory::new: {e}"))?;
    // The node persists in storage v2; the unwind must read/write with the same adapter.
    factory.set_storage_settings_cache(StorageSettings::v2());

    // Heal a crash-torn datadir before unwinding. A `kill -9` during async persistence can leave the
    // static files ahead of MDBX (commit order is static-files, RocksDB, MDBX) with a partially
    // written trailing entry: reading that entry back during the unwind panics in the codec
    // (`len - 52` underflow). `check_consistency` truncates the partial static-file tail to match
    // MDBX (the same heal the node runs at startup). If it still reports the DB layers can't be
    // reconciled without a full pipeline unwind, bail with guidance rather than corrupt further.
    let (rocksdb_unwind, sf_unwind) = factory
        .check_consistency()
        .map_err(|e| eyre::eyre!("static-file/db consistency check failed: {e}"))?;
    if let Some(target) = [rocksdb_unwind, sf_unwind].into_iter().flatten().min() {
        return Err(eyre::eyre!(
            "datadir needs a pipeline unwind to block {target} before it is consistent (static \
             files/RocksDB and MDBX disagree beyond a healable tail); start and cleanly stop \
             `arb-reth` once to heal it, then re-run the rewind"
        ));
    }

    let current_tip = factory.provider()?.last_block_number()?;
    info!(target: "arb-rewind", current_tip, genesis = genesis_num, new_tip, "opened database (consistency healed)");

    // Equality is allowed so a run interrupted after DB commit can finish sidecar recovery.
    if new_tip > current_tip {
        return Err(eyre::eyre!(
            "new tip {new_tip} is above the current tip {current_tip}"
        ));
    }
    if new_tip < genesis_num {
        return Err(eyre::eyre!(
            "new tip {new_tip} is below the imported genesis block {genesis_num}; \
             reset the datadir instead (arb-reset-db.sh)"
        ));
    }

    let target_header = factory
        .provider()?
        .sealed_header(new_tip)?
        .ok_or_else(|| eyre::eyre!("rewind target block {new_tip} is missing"))?;
    let target_hash = target_header.hash();
    arb_reth_engine::validate_journal_target_at(&args.datadir, new_tip, target_hash)?;

    // Truncate the resume log to a boundary at or below the new tip, so the next start resumes
    // derivation from there. Preview it first; without a surviving boundary the caller must supply
    // --l1-start-block on the next run (or reset).
    let log_path = L1ResumeLog::path_in(&args.datadir);
    let mut log = L1ResumeLog::load(&log_path);
    let surviving = log.as_ref().and_then(|l| l.checkpoints.iter().rev().find(|cp| cp.l2_block <= new_tip).copied());
    match &surviving {
        Some(cp) => info!(
            target: "arb-rewind",
            l1_block = cp.l1_block, delayed = cp.delayed_count, l2_block = cp.l2_block,
            "resume log will keep this boundary; next sync re-derives from it up to the new tip",
        ),
        None => info!(
            target: "arb-rewind",
            "no resume-log boundary at or below {new_tip}; the next sync will re-derive from Nitro \
             genesis and verify already-present blocks against the message journal",
        ),
    }

    if new_tip < current_tip {
        crate::recovery::validate_changeset_coverage(&factory, new_tip, current_tip)?;

        if args.dry_run {
            info!(target: "arb-rewind", "dry run: no changes written");
            return Ok(());
        }

        // Unwind the DB: remove every block/receipt/state/trie/history entry above `new_tip`.
        info!(target: "arb-rewind", removing_above = new_tip, "unwinding database (this may take a while)");
        crate::recovery::commit_storage_v2_unwind(&factory, new_tip)?;
    }

    if args.dry_run {
        info!(target: "arb-rewind", "dry run: no changes written");
        return Ok(());
    }

    // Sidecars follow the authoritative DB commit. Re-running the same target is idempotent.
    arb_reth_engine::truncate_journal_at(&args.datadir, new_tip, target_hash)?;

    // Now truncate the resume log to match (only after the DB unwind committed).
    if let Some(log) = log.as_mut() {
        log.truncate_to(new_tip);
        if log.checkpoints.is_empty() {
            // Nothing survives: remove the stale log so the next start doesn't refuse on an
            // all-above-tip log; the operator resumes via --l1-start-block or reset.
            L1ResumeLog::remove(&log_path)
                .map_err(|e| eyre::eyre!("remove resume log: {e}"))?;
        } else {
            log.save(&log_path).map_err(|e| eyre::eyre!("rewrite resume log: {e}"))?;
        }
    }

    let final_tip = factory.provider()?.last_block_number()?;
    info!(target: "arb-rewind", final_tip, "rewind complete");
    if final_tip != new_tip {
        return Err(eyre::eyre!(
            "post-rewind tip is {final_tip}, expected {new_tip}; unwind did not land where expected"
        ));
    }
    arb_reth_engine::clear_divergence_marker_at(&args.datadir)?;
    println!("rewound {current_tip} -> {new_tip}  (removed {} blocks)", current_tip - new_tip);
    Ok(())
}
