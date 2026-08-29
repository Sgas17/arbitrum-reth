//! `arb-reth`: single entrypoint for the Arbitrum (ArbOS-on-reth) toolchain.
//!
//! Dispatches clap subcommands into the per-command implementations in
//! [`arb_reth_node::commands`]:
//!
//! - `node`             the standalone no-engine node (feed / L1-derivation block producer + RPC)
//! - `snapshot import`  import a Nitro genesis-state stream into reth MDBX
//! - `snapshot import-full`  convert a full-snapshot stream (blocks + history + state)
//! - `snapshot read`    read hashed-state from a converted snapshot
//! - `genesis verify`   verify the Arbitrum One Nitro-genesis state root from the classic export
//! - `genesis verify-export`  verify a `reth-export --mode state` stream (stdin)
//! - `rewind`           unwind the database to an earlier L2 block after a divergence
//! - `dump-blocks`      dump block headers + tx hashes + receipt status

#![allow(missing_docs)]

use arb_reth_node::commands::{
    self,
    dump_blocks::DumpBlocksArgs,
    genesis::{GenesisVerifyArgs, GenesisVerifyExportArgs},
    journal_init::JournalV2InitArgs,
    node::NodeArgs,
    rewind::RewindArgs,
    snapshot::{
        SnapshotBuildPreimagesArgs, SnapshotImportArgs, SnapshotReadArgs, SnapshotRepairHistoryArgs,
    },
    snapshot_full::{SnapshotFinalizeArgs, SnapshotImportFullArgs},
};
use clap::{Args, Parser, Subcommand};
use reth_cli_runner::CliRunner;
use reth_tracing::{RethTracer, Tracer};

/// Stack-probe shim for x86_64: wasmer references `__rust_probestack` which recent
/// `compiler-builtins` no longer exports; this satisfies the linker. No-op on aarch64.
///
/// # Safety
///
/// Defined for the linker only; never called from Rust.
#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rust_probestack() {}

#[derive(Debug, Parser)]
#[command(
    name = "arb-reth",
    about = "Standalone no-engine Arbitrum (ArbOS-on-reth) node"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Run the standalone no-engine Arbitrum node.
    Node(NodeArgs),
    /// One-shot trusted Phase-A journal and lifecycle initialization.
    JournalV2Init(JournalV2InitArgs),
    /// Snapshot import/read tools.
    Snapshot(SnapshotCmd),
    /// Genesis verification tools.
    Genesis(GenesisCmd),
    /// Unwind the database to an earlier L2 block.
    Rewind(RewindArgs),
    /// Dump block headers + tx hashes + receipt status.
    DumpBlocks(DumpBlocksArgs),
}

#[derive(Debug, Args)]
struct SnapshotCmd {
    #[command(subcommand)]
    command: SnapshotSub,
}

#[derive(Debug, Subcommand)]
enum SnapshotSub {
    /// Build Reth's slot-preimage sidecar from a Nitro Classic export.
    BuildPreimages(SnapshotBuildPreimagesArgs),
    /// Import a Nitro genesis state stream into reth MDBX and verify the state root.
    Import(SnapshotImportArgs),
    /// Convert a `reth-export --mode full-snapshot` stream into a reth datadir.
    ImportFull(SnapshotImportFullArgs),
    /// Finish a converted datadir that stopped after its state root.
    Finalize(SnapshotFinalizeArgs),
    /// Read hashed-state from a converted Arbitrum reth MDBX snapshot.
    Read(SnapshotReadArgs),
    /// Add missing history-boundary metadata to an existing snapshot import.
    RepairHistory(SnapshotRepairHistoryArgs),
}

#[derive(Debug, Args)]
struct GenesisCmd {
    #[command(subcommand)]
    command: GenesisSub,
}

#[derive(Debug, Subcommand)]
enum GenesisSub {
    /// Verify the Arbitrum One Nitro-genesis state root from the classic-state export.
    Verify(GenesisVerifyArgs),
    /// Verify the hashed state-trie root of a `reth-export --mode state` stream (stdin).
    VerifyExport(GenesisVerifyExportArgs),
}

fn main() -> eyre::Result<()> {
    if arb_reth_node::run_recovery_validation_child_from_env()? {
        return Ok(());
    }

    // Idiomatic reth tracing; guard is held for the process lifetime.
    let _guard = RethTracer::new().init()?;

    // rustls 0.23 carries both the aws-lc-rs and ring backends in our dep tree, so it can't pick a
    // process-default CryptoProvider on its own; the first wss:// feed connect (connect_async builds
    // a rustls ClientConfig) would otherwise panic with "no process-level CryptoProvider available".
    // Install the aws-lc-rs provider once here. Err just means one is already installed, so ignore.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cli = Cli::parse();

    match cli.command {
        Command::Node(args) => {
            let runner = CliRunner::try_default_runtime()?;
            commands::node::run_until_exit(runner, args)
        }
        Command::JournalV2Init(args) => commands::journal_init::run(args),
        Command::Snapshot(cmd) => match cmd.command {
            SnapshotSub::BuildPreimages(args) => commands::snapshot::build_preimages(args),
            SnapshotSub::Import(args) => commands::snapshot::import(args),
            SnapshotSub::ImportFull(args) => commands::snapshot_full::import_full(args),
            SnapshotSub::Finalize(args) => commands::snapshot_full::finalize_datadir(args),
            SnapshotSub::Read(args) => commands::snapshot::read(args),
            SnapshotSub::RepairHistory(args) => commands::snapshot::repair_history(args),
        },
        Command::Genesis(cmd) => match cmd.command {
            GenesisSub::Verify(args) => commands::genesis::verify(args),
            GenesisSub::VerifyExport(args) => commands::genesis::verify_export(args),
        },
        Command::Rewind(args) => commands::rewind::run(args),
        Command::DumpBlocks(args) => commands::dump_blocks::run(args),
    }
}
