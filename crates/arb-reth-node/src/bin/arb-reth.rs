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
    canonical_observe::CanonicalObserveArgs,
    dump_blocks::DumpBlocksArgs,
    genesis::{GenesisVerifyArgs, GenesisVerifyExportArgs},
    journal_init::JournalV3InitArgs,
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

const KZG_HELPER_ENV: &str = "ARB_RETH_INTERNAL_KZG_COMMITMENT_HELPER";
const KZG_TRUSTED_SETUP_DIGEST: [u8; 32] =
    alloy_primitives::hex!("d39b9f2d047cc9dca2de58f264b6a09448ccd34db967881a6713eacacf0f26b7");

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
    /// Observe canonical Ethereum L1 once against a stopped Robinhood datadir.
    CanonicalObserve(CanonicalObserveArgs),
    /// One-shot trusted compact-storage journal and lifecycle initialization.
    JournalV3Init(JournalV3InitArgs),
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
    if std::env::var_os(KZG_HELPER_ENV).is_some() {
        return run_kzg_commitment_helper();
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
        Command::CanonicalObserve(args) => commands::canonical_observe::run(args),
        Command::JournalV3Init(args) => commands::journal_init::run(args),
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

fn run_kzg_commitment_helper() -> eyre::Result<()> {
    use std::io::{Read as _, Write as _};

    reject_inherited_descriptors()?;
    eyre::ensure!(
        std::env::args_os().len() == 1,
        "internal KZG helper accepts no arguments"
    );
    let mut digest = [0u8; 32];
    std::io::stdin().read_exact(&mut digest)?;
    eyre::ensure!(
        digest == KZG_TRUSTED_SETUP_DIGEST,
        "internal KZG helper trusted-setup identity mismatch"
    );
    let mut blob = Box::new([0u8; c_kzg::BYTES_PER_BLOB]);
    std::io::stdin().read_exact(blob.as_mut_slice())?;
    let mut trailing = [0u8; 1];
    eyre::ensure!(
        std::io::stdin().read(&mut trailing)? == 0,
        "internal KZG helper received trailing input"
    );
    let blob = c_kzg::Blob::new(*blob);
    let commitment = c_kzg::ethereum_kzg_settings(0)
        .blob_to_kzg_commitment(&blob)
        .map_err(|error| eyre::eyre!("internal KZG commitment failed: {error:?}"))?
        .to_bytes()
        .into_inner();
    std::io::stdout().write_all(&commitment)?;
    std::io::stdout().flush()?;
    Ok(())
}

fn reject_inherited_descriptors() -> eyre::Result<()> {
    let descriptors = std::fs::read_dir("/proc/self/fd")?
        .map(|entry| {
            entry?
                .file_name()
                .to_string_lossy()
                .parse::<i32>()
                .map_err(std::io::Error::other)
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    for descriptor in descriptors.into_iter().filter(|descriptor| *descriptor > 2) {
        let result = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        eyre::ensure!(
            result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF),
            "internal KZG helper inherited descriptor {descriptor}"
        );
    }
    Ok(())
}
