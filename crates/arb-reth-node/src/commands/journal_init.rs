//! One-shot trusted v2 journal plus lifecycle initialization.

use std::{path::PathBuf, sync::Arc};

use alloy_consensus::Header;
use arb_reth_engine::{JournalDirectory, MessageJournalAnchor, initialize_journal_v2};
use clap::Parser;
use eyre::{ensure, eyre};
use reth_chainspec::EthChainSpec;
use reth_db::{ClientVersion, mdbx::DatabaseArguments, open_db_read_only};
use reth_db_api::models::StorageSettings;
use reth_node_types::NodeTypesWithDBAdapter;
use reth_provider::{
    BlockNumReader, ProviderFactory, StorageSettingsCache,
    providers::{RocksDBProvider, StaticFileProvider},
};
use reth_storage_api::HeaderProvider;
use reth_tasks::Runtime;

use crate::{
    ArbNode,
    lifecycle::LifecycleGuard,
    snapshot_trust::{load_approved_descriptor, read_completion},
};

type ArbNodeTypesWithDB = NodeTypesWithDBAdapter<ArbNode, reth_db::DatabaseEnv>;

#[derive(Debug, Parser)]
#[command(
    name = "arb-journal-v2-init",
    about = "One-shot trusted Phase-A journal and lifecycle initialization"
)]
pub struct JournalV2InitArgs {
    /// Existing stopped datadir containing the read-only reopened store.
    #[arg(long, value_name = "PATH")]
    datadir: PathBuf,

    /// Arbitrum chain-config JSON for exact-genesis initialization.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["chain_info", "genesis_json"])]
    chain: Option<PathBuf>,

    /// Nitro chaininfo.json, paired with --genesis.
    #[arg(long = "chain-info", value_name = "PATH", requires = "genesis_json")]
    chain_info: Option<PathBuf>,

    /// Nitro genesis.json, paired with --chain-info.
    #[arg(long = "genesis", value_name = "PATH", requires = "chain_info")]
    genesis_json: Option<PathBuf>,

    /// Exact allowlisted descriptor for a completed Robinhood full snapshot.
    #[arg(
        long = "snapshot-trust-descriptor",
        value_name = "PATH",
        requires_all = ["chain_info", "genesis_json"]
    )]
    snapshot_trust_descriptor: Option<PathBuf>,
}

pub fn run(args: JournalV2InitArgs) -> eyre::Result<()> {
    ensure!(
        args.datadir.is_dir(),
        "journal-v2-init datadir does not exist"
    );
    let directory = JournalDirectory::open(&args.datadir)?;
    reject_preexisting_authority(&args, &directory)?;

    let (chain_spec, configured_genesis) = configured_chain(&args)?;
    let factory = open_read_only_factory(&args.datadir, chain_spec)?;
    let provider = factory.provider()?;
    ensure!(
        provider.cached_storage_settings() == StorageSettings::v2(),
        "journal-v2-init requires persisted Reth storage-v2"
    );
    let head_number = provider.last_block_number()?;
    let head = provider
        .sealed_header(head_number)?
        .ok_or_else(|| eyre!("reopened store head {head_number} is missing"))?;

    let anchor = if let Some(path) = &args.snapshot_trust_descriptor {
        let trust = load_approved_descriptor(path)?;
        ensure!(
            read_completion(&directory)? == trust,
            "snapshot completion and descriptor differ"
        );
        ensure!(
            head_number == trust.head_number
                && head.hash() == trust.head_hash
                && head.state_root == trust.head_state_root,
            "reopened snapshot store does not match frozen completion identity"
        );
        MessageJournalAnchor {
            sequence: head_number
                .checked_sub(configured_genesis.number)
                .ok_or_else(|| eyre!("snapshot head precedes configured genesis"))?,
            block_number: head_number,
            block_hash: head.hash(),
        }
    } else {
        ensure!(
            head_number == configured_genesis.number
                && head.hash() == configured_genesis.hash_slow()
                && head.state_root == configured_genesis.state_root,
            "reopened store is not exactly the configured genesis identity"
        );
        ensure!(
            provider
                .sealed_header(
                    head_number
                        .checked_add(1)
                        .ok_or_else(|| eyre!("genesis number overflow"))?
                )?
                .is_none(),
            "exact-genesis store contains a successor"
        );
        MessageJournalAnchor {
            sequence: 0,
            block_number: head_number,
            block_hash: head.hash(),
        }
    };
    drop(provider);
    drop(factory);

    initialize_combined_authority(&directory, anchor)
}

fn initialize_combined_authority(
    directory: &JournalDirectory,
    anchor: MessageJournalAnchor,
) -> eyre::Result<()> {
    let inspection = initialize_journal_v2(directory, anchor)?;
    ensure!(
        inspection.anchor() == anchor,
        "freshly reopened lineage-zero anchor changed"
    );
    combined_init_failpoint("journal_final");
    let lifecycle = LifecycleGuard::initialize(directory, anchor)?;
    ensure!(
        lifecycle.selected().state == crate::lifecycle::LifecycleState::Clean,
        "combined initialization did not commit CLEAN lifecycle evidence"
    );
    Ok(())
}

fn combined_init_failpoint(name: &str) {
    if std::env::var_os("ARB_RETH_COMBINED_INIT_FAILPOINT").as_deref()
        == Some(std::ffi::OsStr::new(name))
    {
        unsafe extern "C" {
            fn _exit(status: i32) -> !;
        }
        // SAFETY: this production test seam intentionally simulates sudden process loss.
        unsafe { _exit(86) }
    }
}

fn configured_chain(
    args: &JournalV2InitArgs,
) -> eyre::Result<(Arc<reth_chainspec::ChainSpec>, Header)> {
    match (&args.chain, &args.chain_info, &args.genesis_json) {
        (Some(chain), None, None) => {
            let bytes = std::fs::read(chain)?;
            let init = crate::arbos_init_from_chain_config_json(&bytes)?;
            let spec = Arc::new(crate::arb_chain_spec(&init)?);
            Ok((spec.clone(), spec.genesis_header().clone()))
        }
        (None, Some(chain_info), Some(genesis)) => {
            let chain_info = std::fs::read(chain_info)?;
            let genesis = std::fs::read(genesis)?;
            let (spec, _, _) = crate::orbit_chain_from_files(&chain_info, &genesis)?;
            let spec = Arc::new(spec);
            Ok((spec.clone(), spec.genesis_header().clone()))
        }
        _ => Err(eyre!(
            "journal-v2-init requires either --chain or the exact --chain-info/--genesis pair"
        )),
    }
}

fn open_read_only_factory(
    datadir: &std::path::Path,
    chain_spec: Arc<reth_chainspec::ChainSpec>,
) -> eyre::Result<ProviderFactory<ArbNodeTypesWithDB>> {
    let db = open_db_read_only(
        datadir.join("db"),
        DatabaseArguments::new(ClientVersion::default()),
    )?;
    let static_files = StaticFileProvider::read_only(datadir.join("static_files"))?;
    let rocksdb = RocksDBProvider::builder(datadir.join("rocksdb"))
        .with_default_tables()
        .with_read_only(true)
        .build()
        .map_err(|error| eyre!("open RocksDB read-only for journal-v2-init: {error}"))?;
    let factory: ProviderFactory<ArbNodeTypesWithDB> =
        ProviderFactory::new(db, chain_spec, static_files, rocksdb, Runtime::test())?;
    factory.set_storage_settings_cache(StorageSettings::v2());
    Ok(factory)
}

fn reject_preexisting_authority(
    args: &JournalV2InitArgs,
    directory: &JournalDirectory,
) -> eyre::Result<()> {
    for name in directory.entry_names()? {
        let allowed_completion = args.snapshot_trust_descriptor.is_some()
            && name == crate::snapshot_trust::SNAPSHOT_COMPLETION_FILE;
        if !allowed_completion
            && (name.starts_with("arb-message-journal")
                || name.starts_with("arb-node-lifecycle-v1")
                || name.starts_with("arb-snapshot-completion-v1")
                || name.starts_with("snapshot-import.json")
                || name.starts_with("arb-message-divergence.json")
                || name.starts_with("arb-message-recovery.json")
                || name.starts_with("arb-l1-resume.json"))
        {
            return Err(eyre!(
                "journal-v2-init target contains authority artifact {name}"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;
    use arb_reth_engine::{LIFECYCLE_FILE, inspect_message_journal};

    use super::*;
    use crate::lifecycle::LifecycleState;

    fn anchor() -> MessageJournalAnchor {
        MessageJournalAnchor {
            sequence: 0,
            block_number: 100,
            block_hash: B256::repeat_byte(0x42),
        }
    }

    #[test]
    fn combined_initialization_crash_matrix() {
        const CHILD_DATADIR: &str = "ARB_RETH_COMBINED_INIT_TEST_DATADIR";
        if let Some(datadir) = std::env::var_os(CHILD_DATADIR) {
            let directory = JournalDirectory::open(std::path::Path::new(&datadir)).unwrap();
            initialize_combined_authority(&directory, anchor()).unwrap();
            return;
        }

        let points = [
            ("journal_final", None),
            ("provisional_full_written", None),
            ("provisional_synced", None),
            ("provisional_entry_proved", None),
            ("a_initializing_body_written", None),
            (
                "a_initializing_checksum_written",
                Some(LifecycleState::Initializing),
            ),
            (
                "a_initializing_full_written",
                Some(LifecycleState::Initializing),
            ),
            ("a_initializing_synced", Some(LifecycleState::Initializing)),
            (
                "a_initializing_entry_proved",
                Some(LifecycleState::Initializing),
            ),
            (
                "b_initializing_body_written",
                Some(LifecycleState::Initializing),
            ),
            (
                "b_initializing_checksum_written",
                Some(LifecycleState::Initializing),
            ),
            (
                "b_initializing_full_written",
                Some(LifecycleState::Initializing),
            ),
            ("b_initializing_synced", Some(LifecycleState::Initializing)),
            ("b_initializing_reread", Some(LifecycleState::Initializing)),
            (
                "b_initializing_parent_synced",
                Some(LifecycleState::Initializing),
            ),
            (
                "b_initializing_entry_proved",
                Some(LifecycleState::Initializing),
            ),
            ("b_clean_body_written", Some(LifecycleState::Initializing)),
            ("b_clean_checksum_written", Some(LifecycleState::Clean)),
            ("b_clean_full_written", Some(LifecycleState::Clean)),
            ("b_clean_synced", Some(LifecycleState::Clean)),
            ("b_clean_reread", Some(LifecycleState::Clean)),
            ("b_clean_entry_proved", Some(LifecycleState::Clean)),
        ];
        let executable = std::env::current_exe().unwrap();
        for (point, expected) in points {
            let dir = tempfile::tempdir().unwrap();
            let mut command = std::process::Command::new(&executable);
            command
                .args([
                    "--exact",
                    "commands::journal_init::tests::combined_initialization_crash_matrix",
                    "--nocapture",
                ])
                .env(CHILD_DATADIR, dir.path());
            if point == "journal_final" {
                command.env("ARB_RETH_COMBINED_INIT_FAILPOINT", point);
            } else {
                command.env("ARB_RETH_LIFECYCLE_FAILPOINT", point);
            }
            let status = command.status().unwrap();
            assert_eq!(status.code(), Some(86), "failpoint {point} did not crash");

            let directory = JournalDirectory::open(dir.path()).unwrap();
            let journal = inspect_message_journal(&directory, 100).unwrap();
            assert_eq!(journal.anchor(), anchor());
            let reopened = LifecycleGuard::open_existing(&directory, anchor());
            match expected {
                Some(state) => assert_eq!(
                    reopened.unwrap().selected().state,
                    state,
                    "failpoint {point} selected the wrong lifecycle state"
                ),
                None => {
                    assert!(!directory.entry_exists(LIFECYCLE_FILE).unwrap() || reopened.is_err())
                }
            }
            assert!(
                initialize_combined_authority(&directory, anchor()).is_err(),
                "interrupted combined initialization was resumable at {point}"
            );
        }
    }
}
