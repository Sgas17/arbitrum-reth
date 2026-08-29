//! Phase-A manual rewind gate.

use std::path::PathBuf;

use clap::Parser;

use crate::ARB_ONE_CHAIN_ID;

#[derive(Debug, Parser)]
#[command(name = "arb-rewind", about = "Unavailable until canonical-L1 Phase B")]
pub struct RewindArgs {
    #[arg(long, value_name = "PATH")]
    datadir: PathBuf,

    #[arg(long = "snapshot-head", value_name = "PATH")]
    snapshot_head: Option<PathBuf>,

    #[arg(long = "chain-info", value_name = "PATH", requires = "genesis_json")]
    chain_info: Option<PathBuf>,

    #[arg(long = "genesis", value_name = "PATH")]
    genesis_json: Option<PathBuf>,

    #[arg(
        long = "to",
        value_name = "BLOCK",
        conflicts_with = "diverged_at",
        required_unless_present = "diverged_at"
    )]
    to: Option<u64>,

    #[arg(long = "diverged-at", value_name = "BLOCK")]
    diverged_at: Option<u64>,

    #[arg(long, default_value_t = ARB_ONE_CHAIN_ID)]
    chain_id: u64,

    #[arg(long)]
    dry_run: bool,
}

pub fn run(args: RewindArgs) -> eyre::Result<()> {
    let _ = (
        args.datadir,
        args.snapshot_head,
        args.chain_info,
        args.genesis_json,
        args.to,
        args.diverged_at,
        args.chain_id,
        args.dry_run,
    );
    eyre::bail!(
        "manual rewind is unavailable in Phase A because canonical L1 and recovery authority are not implemented"
    )
}
