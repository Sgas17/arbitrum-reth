//! `arb-reth node`: permanently storage-only Phase-B1 entrypoint.
//!
//! B1 authenticates the stopped v3 journal, lifecycle, completion, and reopened L2 store through
//! read-only handles, then returns [`CanonicalAuthorityStorageOnly`]. It never constructs an
//! ordinary launcher, provider URL, network service, writable database, or task.

use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

#[cfg(test)]
use std::path::Path;

use crate::ARB_ONE_CHAIN_ID;
#[cfg(test)]
use crate::arb_chain_spec;
#[cfg(test)]
use crate::arbos_init_from_parsed;
use crate::feed;
#[cfg(test)]
use crate::launcher::ArbNodeHandle;
use crate::launcher::{TerminalSignalObserver, terminal_signal_channel};
use crate::lifecycle::LifecycleState;
#[cfg(test)]
use crate::recovery::preflight_before_l1_genesis;
use crate::recovery::{OrdinaryAuthorityEvidence, preflight_ordinary_authority};
use alloy_primitives::Address;
#[cfg(test)]
use alloy_provider::{Provider, ProviderBuilder};
use arb_reth_engine::{
    JournalDirectory, MessageJournalInspection, StorageContextV3, inspect_message_journal,
    inspect_selected_journal_header,
};
#[cfg(test)]
use arb_reth_l1::DelayedInboxReader;
#[cfg(test)]
use arbitrum_alloy_sequencer::init_message::parse_init_message_from_body;
use clap::Parser;
use reth_chainspec::{ChainSpec, EthChainSpec};
use reth_cli_runner::{CliContext, CliRunner};
use reth_db_api::models::StorageSettings;
use reth_node_core::args::PruningArgs;
use reth_provider::{BlockNumReader, HeaderProvider, StorageSettingsCache};

#[cfg(any())]
struct ProcessSignals {
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
}

#[cfg(any())]
impl ProcessSignals {
    fn install() -> std::io::Result<Self> {
        Ok(Self {
            #[cfg(unix)]
            terminate: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
        })
    }

    async fn next(&mut self) -> std::io::Result<&'static str> {
        #[cfg(unix)]
        {
            tokio::select! {
                result = tokio::signal::ctrl_c() => {
                    result?;
                    Ok("SIGINT")
                }
                signal = self.terminate.recv() => {
                    signal.ok_or_else(|| std::io::Error::other("SIGTERM stream closed"))?;
                    Ok("SIGTERM")
                }
            }
        }
        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c().await?;
            Ok("SIGINT")
        }
    }
}

#[cfg(any())]
async fn own_process_signals(
    mut signals: ProcessSignals,
    owner: TerminalSignalOwner,
    runtime: reth_tasks::Runtime,
) {
    loop {
        let signal = match signals.next().await {
            Ok(signal) => signal,
            Err(error) => {
                reth_tracing::tracing::error!(
                    target: "arb-reth",
                    %error,
                    "process signal owner failed",
                );
                return;
            }
        };
        if owner.capture_first() {
            info!(target: "arb-reth", signal, "received first graceful shutdown signal");
            if runtime.initiate_graceful_shutdown().is_err() {
                reth_tracing::tracing::error!(
                    target: "arb-reth",
                    "failed to initiate runtime shutdown after process signal",
                );
                return;
            }
        } else {
            warn!(
                target: "arb-reth",
                signal,
                "ignoring repeated shutdown signal; the original deadline remains authoritative",
            );
        }
    }
}

/// Drive the node command to a terminal result without Reth's signal race dropping its owner.
pub fn run_until_exit(runner: CliRunner, args: NodeArgs) -> eyre::Result<()> {
    let runtime = runner.runtime();
    let (_, signal_observer) = terminal_signal_channel();
    runner.block_on(run(
        CliContext {
            task_executor: runtime,
        },
        args,
        signal_observer,
    ))
}

/// `arb-reth`: standalone no-engine Arbitrum (ArbOS-on-reth) node.
#[derive(Debug, Parser)]
#[command(
    name = "arb-reth",
    about = "Standalone no-engine Arbitrum (ArbOS-on-reth) node"
)]
pub struct NodeArgs {
    /// Data directory for the node's database and static files.
    /// Defaults to the platform-specific reth data directory for this chain.
    #[arg(long, value_name = "PATH")]
    datadir: Option<PathBuf>,

    /// Enable the `eth_*` JSON-RPC HTTP server.
    #[arg(long = "http")]
    http: bool,

    /// HTTP-RPC server bind address.
    #[arg(long = "http.addr", default_value = "127.0.0.1")]
    http_addr: IpAddr,

    /// HTTP-RPC server port.
    #[arg(long = "http.port", default_value_t = 8545)]
    http_port: u16,

    /// Enable the reth Prometheus endpoint at this address.
    #[arg(long = "metrics", alias = "metrics.prometheus", value_name = "ADDR")]
    metrics: Option<SocketAddr>,

    /// Path to a local Unix socket that receives one newline-delimited JSON event immediately
    /// after each ArbOS transaction executes. This is a best-effort, pre-canonical stream: an
    /// enclosing block can still fail during root calculation or engine insertion.
    #[arg(long = "mev-tx-log-ipc", value_name = "PATH")]
    mev_tx_log_ipc: Option<PathBuf>,

    /// Engine-tree persistence threshold: persist once the canonical tip is this many blocks
    /// ahead of the last persisted block (larger = bigger, less frequent commit batches).
    #[arg(long, default_value_t = 2)]
    persistence_threshold: u64,

    /// Engine-tree memory buffer target: keep this many recent blocks in memory before flushing.
    #[arg(long = "memory-buffer-target", default_value_t = 0)]
    memory_buffer_target: u64,

    /// Engine-tree backpressure threshold: stall block production once this many blocks are
    /// unpersisted (bounds memory; larger = production runs further ahead of the disk).
    #[arg(long = "persistence-backpressure", default_value_t = 16)]
    persistence_backpressure: u64,

    /// Size in MiB of reth's cross-block account, storage, and bytecode cache.
    ///
    /// The Arbitrum default is 256 MiB. Reth's generic TreeConfig default is 4 GiB, which makes
    /// its fixed-cache tables needlessly sparse for this serial producer.
    #[arg(
        long = "engine.cross-block-cache-size",
        default_value_t = 256,
        value_name = "MiB"
    )]
    execution_cache_size_mb: usize,

    /// Share reth's cross-block execution cache with the serial native payload builder.
    #[arg(
        long = "share-execution-cache-with-payload-builder",
        default_value_t = true,
        action = clap::ArgAction::Set,
    )]
    share_execution_cache_with_payload_builder: bool,

    /// Let the native payload builder use reth's sparse trie task to overlap state-root work
    /// with ArbOS execution. Recommended for this serial Arbitrum producer on a multi-core host.
    #[arg(
        long = "share-sparse-trie-with-payload-builder",
        default_value_t = false
    )]
    share_sparse_trie_with_payload_builder: bool,

    /// Arbitrum execution chain id used by the block driver.
    #[arg(long, default_value_t = ARB_ONE_CHAIN_ID)]
    chain_id: u64,

    /// Path to an Arbitrum chain-config JSON file (the `ChainConfig` Go format:
    /// `{"chainId":..., "arbitrum":{...}}`). When provided, the node boots with a
    /// real ArbOS genesis allocation instead of the mainnet placeholder.
    #[arg(long = "chain", value_name = "PATH")]
    chain_config: Option<PathBuf>,

    /// Path to a Nitro `chaininfo.json` (array of chains: chain-id, parent-chain-id, chain-config,
    /// and the rollup deployment addresses). With `--genesis`, boots an Orbit chain end to end: the
    /// chain spec + prealloc come from the genesis file and the L1 rollup addresses (sequencer
    /// inbox, bridge, deployed-at) come from here. Must be given together with `--genesis`.
    #[arg(long = "chain-info", value_name = "PATH")]
    chain_info: Option<PathBuf>,

    /// Path to a Nitro `genesis.json` (geth-style `alloc` + `arbOSInit.initialL1BaseFee` +
    /// `serializedChainConfig`). Supplies the Orbit chain's genesis state (prealloc contracts +
    /// funded accounts) layered under the ArbOS init state. Must be given together with
    /// `--chain-info`.
    #[arg(long = "genesis", value_name = "PATH")]
    genesis_json: Option<PathBuf>,

    /// Initial L1 base fee (wei) baked into the ArbOS genesis when booting from --chain.
    /// Defaults to Nitro's `DefaultInitialL1BaseFee` of 50 GWei. This value is part of the
    /// genesis state, so a chain created with a different initial base fee (a nitro-testnode
    /// commonly uses a tiny value) needs this set to reproduce its genesis root.
    #[arg(long = "initial-l1-base-fee", value_name = "WEI")]
    initial_l1_base_fee: Option<u128>,

    /// Path to an NDJSON replay-feed file (one `BroadcastFeedMessage` JSON per line).
    /// After launch all messages are pushed into the feed channel so the block driver
    /// processes them, then the node stays alive for RPC inspection.
    ///
    /// Sender lifecycle: after pushing all messages the original sender is kept alive
    /// (not dropped) so the driver does not exit; the node serves RPC until SIGTERM.
    /// This lets you replay a finite file and then query the produced blocks.
    #[arg(long = "replay-feed", value_name = "PATH")]
    replay_feed: Option<PathBuf>,

    /// Live sequencer-feed relay to follow, e.g. `ws://127.0.0.1:9642` (a nitro-testnode) or
    /// `wss://arb1.arbitrum.io/feed` (Arbitrum One). Repeat the option to race distinct relays. The
    /// first decoded copy of each sequence wins and later copies are discarded before execution.
    ///
    /// The relay is a TIP source, not history: its backlog starts at a recent sequence, so this
    /// cannot sync a chain from scratch. Reach the tip via `--l1-rpc` derivation (or a snapshot),
    /// then let the feed ride it. The feed and derivation MAY run together: the driver reconciles by
    /// message sequence (drop already-applied, buffer feed-ahead, drain as the gap fills), so
    /// derivation fills the confirmed prefix while the feed rides the tip. The follower requests our
    /// current tip's sequence on connect. Use `--no-l1-derive` to run the feed as the sole producer
    /// (e.g. resuming an already-synced datadir). Not handled: a feed vs L1 content disagreement
    /// (feed publishes a block L1 later contradicts) — L1 is authoritative and the reorg/resequence
    /// that Nitro does is future work; on an honest sequencer the two never disagree.
    #[arg(long = "feed-url", value_name = "URL", action = clap::ArgAction::Append)]
    feed_urls: Vec<String>,

    /// OS-selected WebSocket connections opened to each `--feed-url`. When neither this option nor
    /// `--feed-source` is supplied, one ordinary connection is opened. When any source declaration
    /// is present, omission means zero unbound connections rather than one hidden primary-IP lane.
    #[arg(long = "feed-connections", value_name = "COUNT")]
    feed_connections: Option<usize>,

    /// Source-bound connections per relay, as `IP=COUNT`. Repeat for every available local IP.
    /// These declarations may be combined with explicit OS-selected `--feed-connections`.
    #[arg(long = "feed-source", value_name = "IP=COUNT", action = clap::ArgAction::Append)]
    feed_sources: Vec<feed::FeedSourceSpec>,

    /// Skip the L1-derivation catch-up loop, making `--feed-url` the sole block source. Genesis is
    /// still bootstrapped from `--l1-rpc` (chain id, spec, initial L1 base fee). Use this to follow a
    /// chain purely through its sequencer feed: the driver applies each feed message as the next
    /// block, so derivation must not also produce (both feed the one channel and would double-apply).
    #[arg(long = "no-l1-derive")]
    no_l1_derive: bool,

    /// L1 execution-layer RPC endpoint. When set, the node runs trustless L1-derivation
    /// catch-up: it reads SequencerInbox batches + the delayed inbox and feeds the
    /// derived messages to the block driver. Requires an archive endpoint (historical
    /// `getLogs`).
    #[arg(long = "l1-rpc", value_name = "URL")]
    l1_rpc: Option<String>,

    /// L1 beacon (consensus-layer) REST endpoint for blob sidecars. Required to derive
    /// post-Dencun blob batches; calldata-era ranges work without it.
    #[arg(long = "l1-beacon", value_name = "URL")]
    l1_beacon: Option<String>,

    /// First L1 block to derive from. Optional override: without it Phase A re-derives from the
    /// chain's batch-0 delivery block. Pass this only to force a start block: it must be the batch
    /// boundary the current L2 tip was built from.
    #[arg(long = "l1-start-block")]
    l1_start_block: Option<u64>,

    /// Last L1 block to derive (inclusive). Omit to follow the L1 head indefinitely.
    #[arg(long = "l1-end-block")]
    l1_end_block: Option<u64>,

    /// Concurrent L1 `resolve_batches` prefetch depth during catch-up (overlaps getLogs/blob
    /// RPC latency). Higher = faster catch-up until the L1 provider rate-limits. 1 = serial.
    #[arg(long = "l1-prefetch", default_value_t = 6)]
    l1_prefetch: u64,

    /// Max `eth_getLogs` block span per request. Set to your provider's cap when it rejects wide
    /// ranges (e.g. `--l1-getlogs-range 10` for Alchemy's free tier). Bounds every L1 log scan:
    /// the batch window, the delayed-message scan, and the startup batch-0 lookup. Omit to keep the
    /// defaults (1k batch / 10k delayed), which suit an unmetered archive endpoint. Smaller = many
    /// more requests, so slower catch-up.
    #[arg(long = "l1-getlogs-range", value_name = "BLOCKS")]
    l1_getlogs_range: Option<u64>,

    /// Delayed cursor before the start block. Optional override: defaults to the current durable L2
    /// tip header's nonce (`delayedMessagesRead`), so it normally need not be supplied.
    #[arg(long = "l1-start-delayed")]
    l1_start_delayed: Option<u64>,

    /// `SequencerInbox` contract address on L1. This and --l1-bridge are one rollup deployment:
    /// set both to target a custom chain (a nitro-testnode or an Orbit chain), or neither to use
    /// the built-in Arbitrum One deployment. Setting only one is an error.
    #[arg(long = "l1-sequencer-inbox", value_name = "ADDR")]
    l1_sequencer_inbox: Option<Address>,

    /// `Bridge` contract address on L1 (delayed-inbox metadata source). Paired with
    /// --l1-sequencer-inbox; see its help for the set-together rule.
    #[arg(long = "l1-bridge", value_name = "ADDR")]
    l1_bridge: Option<Address>,

    /// L1 block the rollup was deployed at, used as the anchor for reading batch 0 and the
    /// Initialize message (Nitro's `DeployedAt`). Defaults to the Arbitrum One deploy height when
    /// targeting Arbitrum One, or block 0 for a custom deployment.
    #[arg(long = "l1-inbox-deploy-block")]
    l1_inbox_deploy_block: Option<u64>,

    /// L2 block the chain's genesis sits at, the L2-numbering anchor for genesis-start derivation.
    /// Defaults to the Arbitrum One Nitro genesis (22207817) when targeting Arbitrum One, or block 0
    /// for a custom deployment (a fresh chain).
    #[arg(long = "l2-genesis-block")]
    l2_genesis_block: Option<u64>,

    /// Boot on a snapshot-imported datadir: path to the `reth-export --mode blocks` head stream
    /// (`H <num> <hash> <headerRLP>`). The node builds its chain spec from that head header so the
    /// genesis-hash check accepts the imported DB and anchors numbering at the snapshot head.
    /// Use with `--datadir <imported-dir>` (do not pass `--chain`).
    #[arg(long = "snapshot-head", value_name = "PATH")]
    snapshot_head: Option<PathBuf>,

    /// Exact compile-time-allowlisted descriptor required with `--snapshot-head`.
    #[arg(
        long = "snapshot-trust-descriptor",
        value_name = "PATH",
        requires = "snapshot_head"
    )]
    snapshot_trust_descriptor: Option<PathBuf>,

    /// History-pruning / full-node configuration: reth's standard `--full` and granular
    /// `--prune.*` flags (e.g. `--prune.account-history.distance <BLOCKS>`,
    /// `--prune.storage-history.distance <BLOCKS>`, `--prune.receipts.distance <BLOCKS>`,
    /// `--prune.transaction-lookup.full`, `--prune.sender-recovery.full`).
    ///
    /// With none of these set the node stays a full archive (keeps all state history). When any is
    /// set, the engine-tree persistence service runs reth's pruner after each commit batch, dropping
    /// the configured segments older than the requested window. `--full` applies reth's full-node
    /// preset (keep only the most recent unwind-safe distance of account/storage history + receipts).
    #[command(flatten)]
    pruning: PruningArgs,
}

/// The L1 rollup deployment arb-reth reads from: the contract addresses plus the L1 block the
/// rollup was deployed at, resolved as one coherent set the way Nitro resolves its
/// `RollupAddresses` from chain info (`chaininfo.GetRollupAddressesConfig`). The addresses always
/// travel together; you do not mix one chain's inbox with another's bridge.
#[cfg(any())]
struct RollupDeployment {
    sequencer_inbox: Address,
    bridge: Address,
    /// L1 block the rollup was deployed at; the anchor for reading batch 0 and the Initialize
    /// message. Nitro's `RollupAddresses.DeployedAt`.
    deployed_at: u64,
    /// L2 block the chain's genesis sits at: 0 for a fresh chain, the Nitro-migration block for
    /// Arbitrum One. Nitro's `ArbitrumChainParams.GenesisBlockNum`.
    l2_genesis_block: u64,
}

/// Validates the pair of files required to boot an Orbit chain.
#[cfg(test)]
fn orbit_boot_paths<'a>(
    chain_info: Option<&'a Path>,
    genesis: Option<&'a Path>,
) -> eyre::Result<Option<(&'a Path, &'a Path)>> {
    match (chain_info, genesis) {
        (Some(chain_info), Some(genesis)) => Ok(Some((chain_info, genesis))),
        (Some(_), None) => Err(eyre::eyre!(
            "--chain-info requires --genesis (the genesis state and prealloc are chain-specific)"
        )),
        (None, Some(_)) => Err(eyre::eyre!(
            "--genesis requires --chain-info (the rollup addresses live there)"
        )),
        (None, None) => Ok(None),
    }
}

/// Returns the delayed-message cursor encoded in the actual L2 genesis header.
///
/// Snapshot chain specs use the imported snapshot head as reth's genesis header, so only use its
/// nonce when its block number matches the rollup's L2 genesis block.
#[cfg(test)]
fn genesis_delayed_messages_read(chain_spec: &ChainSpec, l2_genesis_block: u64) -> Option<u64> {
    let header = chain_spec.genesis_header();
    (header.number == l2_genesis_block).then(|| u64::from_be_bytes(header.nonce.0))
}

/// Returns the delayed-message cursor stored in a persisted L2 header's nonce.
#[cfg(test)]
fn header_delayed_messages_read<P>(provider: &P, block: u64) -> eyre::Result<Option<u64>>
where
    P: HeaderProvider<Header = alloy_consensus::Header>,
{
    Ok(provider
        .sealed_header(block)?
        .map(|header| u64::from_be_bytes(header.nonce.0)))
}

/// Resolve the rollup deployment from the CLI, with Nitro-like set/unset semantics:
///
/// - Neither `--l1-sequencer-inbox` nor `--l1-bridge` set: the built-in Arbitrum One deployment,
///   like Nitro resolving chain-id 42161 from its embedded chain info. `deployed_at` and the L2
///   genesis default to Arbitrum One's heights.
/// - Both set: a custom rollup. Since the addresses are one deployment, `deployed_at` and the L2
///   genesis default to a fresh chain (block 0), not Arbitrum One's heights. Either can still be
///   overridden explicitly.
/// - Exactly one set: rejected, rather than pairing a custom address with an Arbitrum One one.
#[cfg(any())]
fn resolve_rollup_deployment(args: &NodeArgs) -> eyre::Result<RollupDeployment> {
    match (args.l1_sequencer_inbox, args.l1_bridge) {
        (None, None) => Ok(RollupDeployment {
            sequencer_inbox: arb_reth_l1::SEQUENCER_INBOX_MAINNET,
            bridge: arb_reth_l1::BRIDGE_MAINNET,
            deployed_at: args
                .l1_inbox_deploy_block
                .unwrap_or(arb_reth_l1::SEQUENCER_INBOX_DEPLOY_BLOCK_MAINNET),
            l2_genesis_block: args
                .l2_genesis_block
                .unwrap_or(arb_reth_l1::NITRO_GENESIS_BLOCK_MAINNET),
        }),
        (Some(sequencer_inbox), Some(bridge)) => Ok(RollupDeployment {
            sequencer_inbox,
            bridge,
            deployed_at: args.l1_inbox_deploy_block.unwrap_or(0),
            l2_genesis_block: args.l2_genesis_block.unwrap_or(0),
        }),
        _ => Err(eyre::eyre!(
            "--l1-sequencer-inbox and --l1-bridge are one rollup deployment and must be set \
             together: set both for a custom chain, or neither for Arbitrum One"
        )),
    }
}

/// Build the genesis chain spec from the chain's Initialize message on L1, the way Nitro
/// bootstraps a fresh chain. The Initialize message is delayed-inbox message 0; it carries the
/// chain id, the serialized chain config, and the initial L1 base fee (version 1), so none of
/// those need to be supplied by hand. Used for fresh chains (a nitro-testnode or a new Orbit
/// chain) that start at L2 block 0; Arbitrum One instead boots from a snapshot, because its
/// genesis is the classic-state migration block, not an Initialize message.
/// Reject a malformed `--l1-rpc` before any task is spawned.
///
/// Only the genesis derivation-start path builds a provider up front, and it does so incidentally, to
/// resolve batch 0. Without this check, whether an operator gets a clear error or a node that
/// boots and then silently stops depends on which derivation start the flags select. The sync
/// runtime parses the same string again inside its task, where the failure is not recoverable and
/// reaches only a log line.
#[cfg(test)]
fn validate_l1_rpc(l1_rpc: &str) -> eyre::Result<()> {
    l1_rpc
        .parse::<url::Url>()
        .map_err(|e| eyre::eyre!("invalid --l1-rpc URL: {e}"))?;
    Ok(())
}

#[cfg(test)]
async fn derive_genesis_from_l1(
    l1_rpc: &str,
    bridge: Address,
    from_block: u64,
    base_fee_override: Option<u128>,
) -> eyre::Result<(std::sync::Arc<reth_chainspec::ChainSpec>, u64)> {
    let provider = ProviderBuilder::new().connect_http(
        l1_rpc
            .parse()
            .map_err(|e| eyre::eyre!("invalid --l1-rpc URL: {e}"))?,
    );
    let head = provider
        .get_block_number()
        .await
        .map_err(|e| eyre::eyre!("l1 get_block_number: {e}"))?;
    let reader = DelayedInboxReader::new(provider, bridge);
    let msgs = reader
        .fetch_delayed(from_block, head)
        .await
        .map_err(|e| eyre::eyre!("fetch delayed messages for L1 genesis: {e}"))?;
    let init = msgs.iter().find(|m| m.inbox_seq_num == 0).ok_or_else(|| {
        eyre::eyre!("no delayed message 0 (Initialize) in L1 blocks {from_block}..={head}")
    })?;
    let parsed = parse_init_message_from_body(init.kind, &init.data)
        .map_err(|e| eyre::eyre!("parse Initialize message: {e}"))?;
    let mut arbos_init = arbos_init_from_parsed(&parsed)?;
    // The Initialize message carries the base fee; an explicit flag still wins if passed.
    if let Some(fee) = base_fee_override {
        arbos_init.initial_l1_base_fee = alloy_primitives::U256::from(fee);
    }
    let chain_id = arbos_init.chain_id.to::<u64>();
    let spec = std::sync::Arc::new(arb_chain_spec(&arbos_init)?);
    Ok((spec, chain_id))
}

#[cfg(test)]
async fn derive_genesis_from_l1_after_preflight(
    datadir: &Path,
    genesis_block: u64,
    l1_rpc: &str,
    bridge: Address,
    from_block: u64,
    base_fee_override: Option<u128>,
) -> eyre::Result<(std::sync::Arc<reth_chainspec::ChainSpec>, u64)> {
    preflight_before_l1_genesis(datadir, genesis_block)?;
    derive_genesis_from_l1(l1_rpc, bridge, from_block, base_fee_override).await
}

#[cfg(any())]
fn run_recovery_worker_subprocess() -> eyre::Result<()> {
    let status = std::process::Command::new(std::env::current_exe()?)
        .args(std::env::args_os().skip(1))
        .env(RECOVERY_WORKER_ENV, "1")
        .status()?;
    eyre::ensure!(
        status.success(),
        "recovery worker exited before a quiesced durable frontier was acknowledged: {status}"
    );
    Ok(())
}

#[cfg(test)]
pub(crate) async fn complete_terminal_shutdown<P, F, C>(
    handle: ArbNodeHandle<P>,
    stop_services: F,
    mark_clean: C,
) -> eyre::Result<()>
where
    F: std::future::Future<Output = eyre::Result<()>>,
    C: FnOnce(tokio::time::Instant) -> eyre::Result<()>,
{
    let deadline = handle
        .wait_for_node_exit_after_services(stop_services)
        .await?;
    mark_clean(deadline)
}

#[derive(Debug)]
pub struct CanonicalAuthorityStorageOnly {
    lifecycle: LifecycleState,
}

impl std::fmt::Display for CanonicalAuthorityStorageOnly {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "CanonicalAuthorityStorageOnly(lifecycle={:?})",
            self.lifecycle
        )
    }
}

impl std::error::Error for CanonicalAuthorityStorageOnly {}

#[derive(Debug)]
pub struct DivergenceEvidencePhaseUnavailable;

impl std::fmt::Display for DivergenceEvidencePhaseUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "DivergenceEvidencePhaseUnavailable: valid divergence evidence requires a later authorized canonical-evidence phase",
        )
    }
}

impl std::error::Error for DivergenceEvidencePhaseUnavailable {}

#[derive(Debug)]
pub struct RecoveryEvidencePhaseUnavailable;

impl std::fmt::Display for RecoveryEvidencePhaseUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "RecoveryEvidencePhaseUnavailable: valid recovery evidence requires a later authorized canonical-recovery phase",
        )
    }
}

impl std::error::Error for RecoveryEvidencePhaseUnavailable {}

pub(crate) fn require_no_phase_a_evidence(evidence: OrdinaryAuthorityEvidence) -> eyre::Result<()> {
    match evidence {
        OrdinaryAuthorityEvidence::None => Ok(()),
        OrdinaryAuthorityEvidence::Divergence => Err(DivergenceEvidencePhaseUnavailable.into()),
        OrdinaryAuthorityEvidence::Recovery => Err(RecoveryEvidencePhaseUnavailable.into()),
    }
}

fn validate_reopened_storage(
    args: &NodeArgs,
    directory: &JournalDirectory,
    chain_spec: std::sync::Arc<ChainSpec>,
    configured_genesis: &alloy_consensus::Header,
    journal: &MessageJournalInspection,
) -> eyre::Result<()> {
    let factory = super::journal_init::open_read_only_factory(directory.path(), chain_spec)?;
    let provider = factory.provider()?;
    eyre::ensure!(
        provider.cached_storage_settings() == StorageSettings::v2(),
        "ordinary B1 startup requires persisted Reth storage-v2"
    );
    let tip_number = provider.last_block_number()?;
    let tip = provider
        .sealed_header(tip_number)?
        .ok_or_else(|| eyre::eyre!("reopened store tip {tip_number} is missing"))?;
    eyre::ensure!(
        tip_number == journal.watermark.block_number && tip.hash() == journal.watermark.block_hash,
        "reopened stopped store does not equal exact journal J"
    );
    let anchor = provider
        .sealed_header(journal.header.anchor.block_number)?
        .ok_or_else(|| eyre::eyre!("reopened store journal anchor is missing"))?;
    eyre::ensure!(
        anchor.hash() == journal.header.anchor.block_hash,
        "reopened store journal anchor hash mismatch"
    );
    match (
        args.snapshot_head.as_ref(),
        args.snapshot_trust_descriptor.as_ref(),
    ) {
        (Some(head_path), Some(descriptor_path)) => {
            let head = crate::read_head_header(head_path)?;
            super::snapshot::validate_snapshot_import_for_launch(
                directory,
                &head,
                descriptor_path,
            )?;
            let trust = crate::snapshot_trust::load_approved_descriptor(descriptor_path)?;
            eyre::ensure!(
                journal.header.anchor.sequence
                    == trust
                        .head_number
                        .checked_sub(configured_genesis.number)
                        .ok_or_else(|| eyre::eyre!("approved snapshot head precedes L2 genesis"))?
                    && journal.header.anchor.block_number == trust.head_number
                    && journal.header.anchor.block_hash == trust.head_hash
                    && anchor.state_root == trust.head_state_root,
                "journal anchor does not equal approved completion/reopened snapshot store"
            );
        }
        (None, None) => {
            eyre::ensure!(
                journal.header.anchor.sequence == 0
                    && journal.header.anchor.block_number == configured_genesis.number
                    && journal.header.anchor.block_hash == configured_genesis.hash_slow()
                    && anchor.state_root == configured_genesis.state_root,
                "journal anchor does not equal exact configured genesis/reopened store"
            );
        }
        _ => {
            return Err(eyre::eyre!(
                "--snapshot-head and --snapshot-trust-descriptor are required together"
            ));
        }
    }
    drop(provider);
    drop(factory);
    Ok(())
}

fn classify_storage_only(args: &NodeArgs) -> eyre::Result<CanonicalAuthorityStorageOnly> {
    let datadir = args
        .datadir
        .as_deref()
        .ok_or_else(|| eyre::eyre!("B1 storage classification requires an explicit --datadir"))?;
    eyre::ensure!(datadir.is_dir(), "B1 storage datadir does not exist");
    let directory = JournalDirectory::open(datadir)?;
    let snapshot_expected = args.snapshot_trust_descriptor.is_some();
    let evidence = preflight_ordinary_authority(&directory, snapshot_expected)?;
    require_no_phase_a_evidence(evidence)?;
    let selected_header = inspect_selected_journal_header(&directory)?;
    eyre::ensure!(
        args.l1_sequencer_inbox.is_none()
            && args.l1_bridge.is_none()
            && args.l1_inbox_deploy_block.is_none()
            && args.l2_genesis_block.is_none()
            && args.initial_l1_base_fee.is_none(),
        "B1 storage context cannot be supplied or overridden by node CLI authority"
    );
    let (chain_spec, configured_genesis, deployment) = super::journal_init::reviewed_storage_chain(
        args.chain_config.as_deref(),
        args.chain_info.as_deref(),
        args.genesis_json.as_deref(),
        args.snapshot_trust_descriptor.as_deref(),
    )?;
    let context = StorageContextV3 {
        l2_chain_id: chain_spec.chain().id(),
        l2_genesis_number: configured_genesis.number,
        l2_genesis_hash: configured_genesis.hash_slow(),
        sequencer_inbox: deployment.sequencer_inbox,
        bridge: deployment.bridge,
        deployment_block: deployment.deployed_at,
        anchor: selected_header.anchor,
    };
    let journal = inspect_message_journal(&directory, context)?;
    let lifecycle = crate::lifecycle::inspect_existing_read_only(&directory, context.anchor)?;
    validate_reopened_storage(args, &directory, chain_spec, &configured_genesis, &journal)?;
    Ok(CanonicalAuthorityStorageOnly {
        lifecycle: lifecycle.state,
    })
}

pub async fn run(
    _ctx: CliContext,
    args: NodeArgs,
    _terminal_signal: TerminalSignalObserver,
) -> eyre::Result<()> {
    Err(classify_storage_only(&args)?.into())
}

#[cfg(any())]
pub async fn removed_ordinary_runtime_path(
    ctx: CliContext,
    args: NodeArgs,
    terminal_signal: TerminalSignalObserver,
) -> eyre::Result<()> {
    let task_executor = ctx.task_executor;
    warn!(
        target: "arb-reth",
        trading_permitted = crate::metrics::TRADING_PERMITTED,
        phase_complete = crate::metrics::PHASE_COMPLETE,
        "Phase A is a closed test artifact: canonical L1/recovery and admission/runtime phases are incomplete"
    );
    let feed_sources =
        feed::expand_feed_sources(&args.feed_urls, args.feed_connections, &args.feed_sources)?;
    if args.no_l1_derive && feed_sources.is_empty() {
        return Err(eyre::eyre!(
            "--no-l1-derive requires at least one --feed-url"
        ));
    }
    if args.no_l1_derive {
        warn!(target: "arb-reth", "L1 derivation disabled; feed-only message journal history cannot be compacted");
    }
    let tx_log_stream = args
        .mev_tx_log_ipc
        .as_ref()
        .map(|_| ArbTxLogBroadcaster::new());

    // --chain-info plus --genesis boots an Orbit chain. The pair supplies both the chain spec and
    // prealloc state, plus the L1 rollup deployment. Accepting either file alone would silently
    // construct a different genesis.
    let orbit = match orbit_boot_paths(args.chain_info.as_deref(), args.genesis_json.as_deref())? {
        Some((ci, genesis)) => {
            let ci_json = fs::read(ci).map_err(|e| eyre::eyre!("read chain-info {ci:?}: {e}"))?;
            let genesis_json =
                fs::read(genesis).map_err(|e| eyre::eyre!("read genesis {genesis:?}: {e}"))?;
            let (spec, init, info) = crate::orbit_chain_from_files(&ci_json, &genesis_json)?;
            Some((std::sync::Arc::new(spec), init, info))
        }
        None => None,
    };

    // Resolve the rollup addresses + deploy/genesis anchors as one set up front, so a
    // half-specified custom deployment fails fast rather than mid-boot. An Orbit boot takes them
    // straight from the chaininfo file.
    let rollup = match &orbit {
        Some((_, init, info)) => RollupDeployment {
            sequencer_inbox: info.rollup.sequencer_inbox,
            bridge: info.rollup.bridge,
            deployed_at: info.rollup.deployed_at,
            l2_genesis_block: init.genesis_block_number,
        },
        None => resolve_rollup_deployment(&args)?,
    };

    // --snapshot-head: boot on an imported snapshot DB by building the chain spec from its head
    // header (so reth's genesis-hash check accepts the DB). Takes precedence over --chain.
    // When --chain is provided the chain id is derived from the JSON so eth_chainId and the
    // driver agree. When not provided, the mainnet placeholder is used with --chain-id.
    let mut snapshot_launch_head = None;
    let (chain_spec, effective_chain_id) = match (&orbit, &args.snapshot_head, &args.chain_config) {
        (Some((spec, init, info)), _, _) => {
            info!(
                target: "arb-reth",
                chain_id = init.chain_id.to::<u64>(),
                arbos_version = init.initial_arbos_version,
                chain_name = %info.chain_name,
                parent_chain_id = info.parent_chain_id,
                sequencer_inbox = %info.rollup.sequencer_inbox,
                deployed_at = info.rollup.deployed_at,
                "booting Orbit chain from chaininfo + genesis files",
            );
            (spec.clone(), init.chain_id.to::<u64>())
        }
        (None, Some(head_path), _) => {
            let (num, hash, header) = crate::read_head_header(head_path)?;
            eyre::ensure!(
                args.datadir.is_some(),
                "--snapshot-head requires an explicit --datadir"
            );
            snapshot_launch_head = Some((num, hash, header.clone()));
            let delayed_messages_read = u64::from_be_bytes(header.nonce.0);
            info!(
                target: "arb-reth",
                head_block = num, %hash, chain_id = args.chain_id,
                delayed_messages_read,
                "booting on snapshot head header",
            );
            (
                crate::arb_chain_spec_with_header(args.chain_id, header, hash),
                args.chain_id,
            )
        }
        (None, None, Some(path)) => {
            let json = fs::read(path)
                .map_err(|e| eyre::eyre!("failed to read chain config file {:?}: {}", path, e))?;
            let mut init = arbos_init_from_chain_config_json(&json)?;
            if let Some(fee) = args.initial_l1_base_fee {
                init.initial_l1_base_fee = alloy_primitives::U256::from(fee);
            }
            let derived_chain_id = init.chain_id.to::<u64>();
            info!(
                target: "arb-reth",
                chain_id = derived_chain_id,
                arbos_version = init.initial_arbos_version,
                "loaded ArbOS genesis from chain config"
            );
            let spec = std::sync::Arc::new(arb_chain_spec(&init)?);
            (spec, derived_chain_id)
        }
        (None, None, None) => match &args.l1_rpc {
            // No genesis file given but an L1 is: bootstrap genesis from the chain's Initialize
            // message on that L1 (chain id + config + base fee all come from it). This is the
            // zero-config path for a fresh chain like a nitro-testnode.
            Some(l1_rpc) => {
                let datadir = args.datadir.as_deref().ok_or_else(|| {
                    eyre::eyre!(
                        "L1-backed genesis requires an explicit --datadir so local recovery markers and stopped storage are classified before parent RPC access"
                    )
                })?;
                let (spec, cid) = derive_genesis_from_l1_after_preflight(
                    datadir,
                    rollup.l2_genesis_block,
                    l1_rpc,
                    rollup.bridge,
                    rollup.deployed_at,
                    args.initial_l1_base_fee,
                )
                .await?;
                info!(
                    target: "arb-reth",
                    chain_id = cid,
                    "bootstrapped ArbOS genesis from the L1 Initialize message",
                );
                (spec, cid)
            }
            None => (MAINNET.clone(), args.chain_id),
        },
    };
    let genesis_delayed =
        genesis_delayed_messages_read(chain_spec.as_ref(), rollup.l2_genesis_block);

    // Resolve the pruning configuration from the `--prune.*` / `--full` flags before `chain_spec` is
    // moved into the node config (the prune modes for `--full`/pre-merge presets are keyed off the
    // chain's hardfork activations). `prune_config` returns `None` when no pruning flag is set, which
    // keeps the node a full archive. The launcher passes the resulting config to both reth's
    // provider factory and its pruner: the provider needs the modes while writing static files,
    // while the pruner needs them when retiring old history.
    let prune_config = args.pruning.prune_config(chain_spec.as_ref());
    match &prune_config {
        Some(pc) => info!(
            target: "arb-reth",
            segments = ?pc.segments,
            block_interval = pc.block_interval,
            minimum_pruning_distance = pc.minimum_pruning_distance,
            "history pruning enabled",
        ),
        None => {
            info!(target: "arb-reth", "archive node (no pruning configured; keeping all history)")
        }
    }
    let datadir_args = match args.datadir.clone() {
        Some(path) => DatadirArgs {
            datadir: MaybePlatformPath::<DataDirPath>::from(path),
            ..Default::default()
        },
        None => DatadirArgs::default(),
    };
    let config = NodeConfig::new(chain_spec.clone())
        .with_datadir_args(datadir_args)
        .with_metrics(MetricArgs {
            prometheus: args.metrics,
            ..Default::default()
        });
    let data_dir = config.datadir();
    let journal_directory = JournalDirectory::open(data_dir.data_dir())?;

    // Pin and prove both authority files before any ordinary mutable store or service opens. The
    // lifecycle binding uses the immutable anchor from the uniquely selected, validated lineage.
    preflight_ordinary_authority(&journal_directory, snapshot_launch_head.is_some())?;
    let (journal, journal_recovery_required) =
        inspect_stopped_message_journal(&journal_directory, rollup.l2_genesis_block)?;
    let lifecycle_anchor = journal.header.anchor;
    let mut lifecycle = LifecycleGuard::open_existing(&journal_directory, lifecycle_anchor)?;
    if journal_recovery_required {
        eyre::ensure!(
            lifecycle.selected().state == LifecycleState::RunningUnclean,
            "recoverable journal transition without RUNNING lifecycle quarantine"
        );
        if is_recovery_worker() {
            recover_stopped_message_journal(&journal_directory, rollup.l2_genesis_block)?;
            return Ok(());
        }
        run_recovery_worker_subprocess()?;
        let (reopened, still_pending) =
            inspect_stopped_message_journal(&journal_directory, rollup.l2_genesis_block)?;
        eyre::ensure!(
            !still_pending,
            "journal recovery worker left an unfinished transition"
        );
        eyre::ensure!(
            reopened.header.anchor == journal.header.anchor,
            "journal recovery changed the immutable anchor"
        );
    }
    drop(journal);

    if let Some(head) = snapshot_launch_head.as_ref() {
        super::snapshot::validate_snapshot_import_for_launch(
            &journal_directory,
            head,
            args.snapshot_trust_descriptor.as_deref().ok_or_else(|| {
                eyre::eyre!("--snapshot-head requires --snapshot-trust-descriptor")
            })?,
        )?;
    }

    let lifecycle_evidence = lifecycle.selected().state;
    match lifecycle_evidence {
        LifecycleState::Clean => lifecycle.mark_running()?,
        LifecycleState::Initializing => {
            return Err(eyre::eyre!(
                "selected lifecycle state is INITIALIZING; snapshot/operator recovery required"
            ));
        }
        LifecycleState::RunningUnclean => {}
    }

    let parent_chain_claim = orbit
        .as_ref()
        .map(|(_, _, info)| ParentChainClaim {
            chain_id: (info.parent_chain_id != 0).then_some(info.parent_chain_id),
            classification: if info.parent_chain_is_arbitrum {
                ParentChainClassification::Arbitrum
            } else {
                ParentChainClassification::NonArbitrum
            },
        })
        .unwrap_or(ParentChainClaim {
            chain_id: None,
            classification: ParentChainClassification::Unspecified,
        });
    let recovery = prepare_recovery(RecoveryConfig {
        datadir: data_dir.data_dir().to_path_buf(),
        directory: journal_directory.clone(),
        chain_spec: chain_spec.clone(),
        chain_id: effective_chain_id,
        genesis_block: rollup.l2_genesis_block,
        sequencer_inbox: rollup.sequencer_inbox,
        bridge: rollup.bridge,
        deployed_at: rollup.deployed_at,
        parent_chain_claim,
        snapshot_seeded: snapshot_launch_head.is_some(),
        prune_config: prune_config.clone(),
        no_l1_derive: args.no_l1_derive,
        l1_rpc: args.l1_rpc.clone(),
        l1_beacon: args.l1_beacon.clone(),
        l1_start_block: args.l1_start_block,
        l1_start_delayed: args.l1_start_delayed,
        l1_end_block: args.l1_end_block,
        lifecycle_state: lifecycle_evidence,
    })
    .await?;
    let recovery_gate = recovery.gate;
    let mut recovery_runtime = recovery.runtime;
    if is_recovery_worker() && recovery_runtime.is_some() {
        // The disposable child owns only the stopped DB>J unwind. `prepare_recovery` completed the
        // repair and durably updated its marker; exiting now releases every storage handle.
        return Ok(());
    }
    if let Some(runtime) = recovery_runtime.as_ref() {
        // Rederivation owns a writable Reth storage epoch. Run it in a disposable process so a
        // successful process exit proves every MDBX/static/Rocks handle and cached writer was
        // dropped before this parent reopens the datadir for the final exact proof.
        if runtime.needs_worker {
            run_recovery_worker_subprocess()?;
            recovery_failpoint("recovery_worker_exited_before_reopen");
        }
        finalize_recovery_and_release(runtime, &recovery_gate)?;
        recovery_runtime = None;
    }

    // Normal startup preserves fail-fast socket binding. Recovery creates no public socket until
    // the marker is durably removed and the shared gate releases services.
    let mev_tx_log_ipc = if recovery_gate.is_ready() {
        args.mev_tx_log_ipc
            .as_ref()
            .zip(tx_log_stream.as_ref())
            .map(|(path, broadcaster)| {
                MevTxLogIpc::bind_with_broadcaster(path.clone(), broadcaster.clone())
            })
            .transpose()?
    } else {
        None
    };

    let db_path = data_dir.db();
    info!(target: "arb-reth", path = ?db_path, "opening database");
    let db_args = DatabaseArguments::new(ClientVersion::default());
    let db = init_db(db_path, db_args)?;

    let node_builder = NodeBuilder::new(config).with_database(db).node(ArbNode);

    // The held senders keep the driver parked (and the node alive) until SIGTERM. Keep the
    // live-feed backlog separate from authoritative L1 derivation so a relay reconnect cannot
    // place the L1 gap-closer behind thousands of feed-ahead messages.
    let (feed_tx, feed_rx) = tokio::sync::mpsc::channel::<crate::ArbEngineInput>(4096);
    let (l1_tx, l1_rx) = tokio::sync::mpsc::channel::<BroadcastFeedMessage>(4096);
    // Only live WebSocket messages carry an ingress timestamp. L1-derived and replay messages
    // still drive the same engine callback, but have no sample to record.
    let feed_latency = (!feed_sources.is_empty()).then(FeedLatencyTracker::new);

    let rpc_addr = args.http.then(|| (args.http_addr, args.http_port).into());
    let terminal_journal_directory = journal_directory.clone();
    let terminal_genesis_block = rollup.l2_genesis_block;

    let launcher = ArbLauncher {
        journal_directory,
        ctx: LaunchContext::new(task_executor.clone(), data_dir),
        terminal_signal,
        chain_id: effective_chain_id,
        genesis_block: rollup.l2_genesis_block,
        tuning: crate::ArbEngineTuning {
            persistence_threshold: if recovery_runtime.is_some() {
                0
            } else {
                args.persistence_threshold
            },
            memory_block_buffer_target: args.memory_buffer_target,
            persistence_backpressure_threshold: args.persistence_backpressure,
            execution_cache_size: args.execution_cache_size_mb.saturating_mul(1024 * 1024),
            share_execution_cache_with_payload_builder: args
                .share_execution_cache_with_payload_builder,
            share_sparse_trie_with_payload_builder: args.share_sparse_trie_with_payload_builder,
        },
        prune_config,
        feed_messages: feed_rx,
        l1_messages: l1_rx,
        feed_latency: feed_latency.clone(),
        rpc_addr,
        tx_log_stream: tx_log_stream.clone(),
        recovery_gate: recovery_gate.clone(),
        recovery: recovery_runtime,
        #[cfg(test)]
        driver_test_control: None,
    };

    let handle = launcher.launch_node(node_builder).await?;
    let mut service_tasks = Vec::new();

    match handle.http_url() {
        Some(url) => info!(target: "arb-reth", %url, "arb-reth node started; eth_* RPC serving"),
        None => {
            info!(target: "arb-reth", "arb-reth node started (RPC disabled; pass --http to enable)")
        }
    }

    if let Some(ipc) = mev_tx_log_ipc {
        let path = ipc.path().to_owned();
        service_tasks.push(task_executor.spawn_with_graceful_shutdown_signal(
            |shutdown| async move {
                ipc.serve(shutdown).await;
            },
        ));
        info!(target: "arb-reth::mev", path = %path.display(), "MEV transaction-log IPC listening");
    } else if let Some((path, broadcaster)) = args
        .mev_tx_log_ipc
        .clone()
        .zip(tx_log_stream.clone())
        .filter(|_| !recovery_gate.is_ready())
    {
        let gate = recovery_gate.clone();
        service_tasks.push(
            task_executor.spawn_with_graceful_shutdown_signal(|shutdown| async move {
                gate.wait_ready().await;
                match MevTxLogIpc::bind_with_broadcaster(path.clone(), broadcaster) {
                    Ok(ipc) => {
                        info!(target: "arb-reth::mev", path = %path.display(), "MEV transaction-log IPC listening after recovery");
                        ipc.serve(shutdown).await;
                    }
                    Err(error) => reth_tracing::tracing::error!(
                        target: "arb-reth::mev",
                        %error,
                        "failed to bind MEV transaction-log IPC after recovery",
                    ),
                }
            }),
        );
    }

    if let Some(feed_path) = args.replay_feed {
        let tx = feed_tx.clone();
        let gate = recovery_gate.clone();
        service_tasks.push(task_executor.spawn_task(async move {
            gate.wait_ready().await;
            let content = match fs::read_to_string(&feed_path) {
                Ok(c) => c,
                Err(e) => {
                    reth_tracing::tracing::error!(
                        target: "arb-reth",
                        path = ?feed_path,
                        err = %e,
                        "failed to read replay-feed file"
                    );
                    return;
                }
            };

            let mut pushed = 0usize;
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                match serde_json::from_str::<feed::FeedWireMessage>(line) {
                    Ok(msg) => {
                        if tx.send(msg.into_engine_input()).await.is_err() {
                            reth_tracing::tracing::warn!(
                                target: "arb-reth",
                                "feed channel closed before replay finished"
                            );
                            break;
                        }
                        pushed += 1;
                    }
                    Err(e) => {
                        reth_tracing::tracing::warn!(
                            target: "arb-reth",
                            err = %e,
                            "skipping malformed replay-feed line"
                        );
                    }
                }
            }
            info!(target: "arb-reth", pushed, "replay-feed push complete; node remains up for RPC");
            // tx (clone) is dropped here; the original feed_tx below keeps the channel open.
        }));
    }

    // Live sequencer-feed followers: all connections race into a bounded coordinator. Only the
    // first decoded copy of a sequence reaches the engine channel, so redundant sockets reduce
    // ingress tail latency without multiplying execution-channel work.
    if !feed_sources.is_empty() {
        let feed_latency = feed_latency.expect("feed latency tracker exists with --feed-url");
        // Ask the relay to start at our tip's next message index (block - genesis + 1). The relay is
        // a bounded tip backlog: if this predates what it holds it just streams its current backlog,
        // and the driver's sequence guard dedups/buffers regardless, so this is an optimization.
        let feed_genesis_block = rollup.l2_genesis_block;
        let feed_start_seq = handle
            .provider
            .last_block_number()
            .unwrap_or(feed_genesis_block)
            .saturating_sub(feed_genesis_block)
            + 1;
        let resume_sequence =
            std::sync::Arc::new(std::sync::atomic::AtomicU64::new(feed_start_seq));
        let (ingress_tx, ingress_rx) = feed::ingress_channel();
        let gate = recovery_gate.clone();
        let coordinator_resume = resume_sequence.clone();
        let coordinator_feed = feed_tx.clone();
        service_tasks.push(task_executor.spawn_task(async move {
            gate.wait_ready().await;
            feed::coordinate(
                ingress_rx,
                coordinator_feed,
                feed_latency,
                coordinator_resume,
            )
            .await;
        }));
        for source in feed_sources {
            let gate = recovery_gate.clone();
            let ingress_tx = ingress_tx.clone();
            let resume_sequence = resume_sequence.clone();
            let ingress_metrics = handle.ingress_metrics.clone();
            service_tasks.push(task_executor.spawn_task(async move {
                gate.wait_ready().await;
                feed::follow(source, ingress_tx, resume_sequence, ingress_metrics).await;
            }));
        }
    }

    // Trustless L1-derivation catch-up. Runs as a feed producer on the
    // same channel the driver drains, so derived blocks execute through the validated
    // STF path. The held sender keeps the node alive even after a bounded run finishes.
    // Skipped under --no-l1-derive so --feed-url is the sole producer (genesis already bootstrapped
    // from --l1-rpc above; the derivation loop and the feed must not both feed the channel).
    // Carries a terminal L1 derivation failure out of its task. Declared unconditionally so the
    // wait below can select on it even when derivation never starts; in that case the sender is
    // dropped here and the branch simply never fires.
    let (l1_fatal_tx, l1_fatal_rx) = tokio::sync::oneshot::channel::<crate::L1SyncError>();

    if let Some(l1_rpc) = args.l1_rpc.filter(|_| !args.no_l1_derive) {
        validate_l1_rpc(&l1_rpc)?;

        // The current durable L2 tip (`last_block_number` = the persisted DB head, not the
        // in-memory canonical head). The driver already boots its production tip from this block
        // (via reth's `lookup_head`). Re-derived blocks at or below `db_tip` are forwarded to the
        // driver for comparison with the durable message journal before new history is accepted.
        let db_tip = handle.provider.last_block_number()?;

        // The rollup addresses and genesis anchors, resolved as one set (Arbitrum One by default,
        // or a custom deployment when the addresses are supplied together).
        let RollupDeployment {
            sequencer_inbox,
            bridge,
            deployed_at: inbox_deploy_block,
            l2_genesis_block,
        } = rollup;

        // Resolve the L1 derivation start: (start_block, start_delayed, start_l2_block).
        // `start_l2_block` is the L2 block the start point sits *after*; derived blocks are numbered
        // from it so already-present ones can be compared with the v2 journal. Phase A accepts an
        // explicit override or re-derives from genesis; resume artifacts are rejected at startup.
        let (start_block, start_delayed, start_l2_block) = if let Some(b) = args.l1_start_block {
            // Manual override: the operator asserts `b` is the batch boundary the tip was built
            // from, so the next derived block is `db_tip + 1`.
            let delayed = match args.l1_start_delayed {
                Some(delayed) => delayed,
                None => {
                    header_delayed_messages_read(&handle.provider, db_tip)?.ok_or_else(|| {
                        eyre::eyre!(
                            "cannot recover the delayed-message cursor: durable L2 tip header \
                         {db_tip} is missing; pass --l1-start-delayed explicitly"
                        )
                    })?
                }
            };
            info!(target: "arb-reth", l1_block = b, delayed, l2_block = db_tip, "L1 derivation start: --l1-start-block override");
            (b, delayed, db_tip)
        } else {
            // Phase A always re-derives from Nitro genesis (batch 0), anchoring L2 numbering at
            // genesis. For a fresh genesis DB this is the normal bootstrap. For an advanced DB the
            // L1-sync runtime re-derives every durable overlap; it creates no resume artifact.
            if db_tip != l2_genesis_block {
                info!(
                    target: "arb-reth", db_tip,
                    genesis = l2_genesis_block,
                    "Phase A re-deriving from genesis and verifying already-present blocks",
                );
            }
            // Resolve batch 0's delivery block on-chain (anchored at the SequencerInbox deploy
            // block) rather than assuming a literal.
            let provider = ProviderBuilder::new().connect_http(
                l1_rpc
                    .parse()
                    .map_err(|e| eyre::eyre!("invalid --l1-rpc URL: {e}"))?,
            );
            let reader = SequencerInboxReader::new(provider, sequencer_inbox);
            let block = reader
                .delivery_block_of_batch(
                    0,
                    inbox_deploy_block,
                    args.l1_getlogs_range.map(|n| n.max(1)).unwrap_or(1_000),
                )
                .await
                .map_err(|e| eyre::eyre!("resolve batch 0 delivery block: {e}"))?
                .ok_or_else(|| {
                    eyre::eyre!("batch 0 not found near the SequencerInbox deploy block")
                })?;
            // The genesis header nonce is Nitro's cumulative delayed-messages-read count. It is
            // normally 1 because block 0 consumes the Initialize message.
            let delayed = args.l1_start_delayed.or(genesis_delayed).unwrap_or(0);
            info!(target: "arb-reth", batch = 0, l1_block = block, delayed, "L1 derivation start: genesis (batch 0)");
            (block, delayed, l2_genesis_block)
        };

        let mut sync_cfg = crate::L1SyncConfig::mainnet(l1_rpc, start_block, start_delayed);
        sync_cfg.sequencer_inbox = sequencer_inbox;
        sync_cfg.bridge = bridge;
        sync_cfg.l1_beacon = args.l1_beacon;
        sync_cfg.end_block = args.l1_end_block;
        sync_cfg.prefetch_windows = args.l1_prefetch;
        // Cap every getLogs span to the provider's limit when set (free-tier friendly).
        if let Some(n) = args.l1_getlogs_range {
            let n = n.max(1);
            sync_cfg.batch_window = n;
            sync_cfg.delayed_window = n;
        }
        sync_cfg.start_l2_block = start_l2_block;
        sync_cfg.db_tip_l2 = db_tip;
        // Messages are numbered by message index (block - genesis_block) for the driver's
        // sequence-reconciliation; without this a non-zero genesis (Arbitrum One) mis-numbers every
        // derived block and the driver applies none.
        sync_cfg.genesis_block = l2_genesis_block;

        // Read the durable L2 tip on demand for overlap/retry progress. Phase A writes no resume
        // checkpoint (`last_block_number` is not journal authority or the in-memory canonical head).
        let tip_provider = handle.provider.clone();
        let persisted_tip = move || tip_provider.last_block_number().unwrap_or(0);

        let tx = l1_tx.clone();
        let fatal_tx = l1_fatal_tx;
        service_tasks.push(task_executor.spawn_with_graceful_shutdown_signal(
            |shutdown| async move {
                if let Err(e) =
                    crate::supervise_l1_sync(sync_cfg, tx, persisted_tip, shutdown).await
                {
                    reth_tracing::tracing::error!(
                        target: "arb-reth",
                        err = %e,
                        "L1 sync stopped after a non-retryable failure",
                    );
                    // The supervisor already retried everything it treats as transient, so the
                    // chain cannot advance from here. Report it rather than leaving the node serving a tip
                    // that will never move: to a health check that looks like a live RPC reporting
                    // `eth_syncing: false`, which reads as fully synced.
                    let _ = fatal_tx.send(e);
                }
            },
        ));
        info!(target: "arb-reth", start_block, start_delayed, start_l2_block, db_tip, "L1-derivation catch-up started");
    }

    // Hold both senders alive so the driver parks on the channels rather than exiting.
    let _feed_tx = feed_tx;
    let _l1_tx = l1_tx;

    // Park until the node exits normally, or until L1 derivation gives up. A fatal L1 result is
    // cleanup-only: initiate runtime shutdown, continue driving this same terminal owner through
    // producer joins, and preserve the original non-zero result. Because no process signal owns a
    // deadline, that path cannot cross the lifecycle CLEAN preflight.
    let terminal = complete_terminal_shutdown(
        handle,
        async {
            for task in service_tasks {
                task.await
                    .map_err(|error| eyre::eyre!("node service task failed to join: {error}"))?;
            }
            Ok(())
        },
        |deadline| {
            let final_journal =
                inspect_message_journal(&terminal_journal_directory, terminal_genesis_block)
                    .wrap_err("final pre-CLEAN journal-context proof")?;
            eyre::ensure!(
                final_journal.header.anchor == lifecycle_anchor,
                "final pre-CLEAN journal context changed its immutable anchor"
            );
            lifecycle.mark_clean_until(deadline)
        },
    );
    tokio::pin!(terminal);
    tokio::select! {
        result = &mut terminal => result,
        Ok(err) = l1_fatal_rx => {
            let fatal = eyre::eyre!("L1 derivation stopped and cannot continue: {err}");
            if task_executor.initiate_graceful_shutdown().is_err() {
                reth_tracing::tracing::error!(
                    target: "arb-reth",
                    "failed to initiate cleanup shutdown after fatal L1 derivation",
                );
            }
            if let Err(shutdown_error) = terminal.await {
                reth_tracing::tracing::error!(
                    target: "arb-reth",
                    %shutdown_error,
                    "terminal cleanup also failed after fatal L1 derivation",
                );
            }
            Err(fatal)
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::Header;
    use alloy_primitives::{B64, B256};
    use reth_provider::test_utils::MockEthProvider;

    const ROBINHOOD_CHAIN_INFO: &[u8] =
        include_bytes!("../../tests/fixtures/robinhood-chain-info.json");
    const ROBINHOOD_GENESIS: &[u8] = include_bytes!("../../tests/fixtures/robinhood-genesis.json");

    /// A bad `--l1-rpc` used to be caught only on the genesis-start path, which parses it to resolve
    /// batch 0. Explicit start overrides never built a provider, so the same input booted a node
    /// that logged one error and then served a tip that never advanced.
    #[test]
    fn a_malformed_l1_rpc_is_rejected_before_anything_is_spawned() {
        for bad in ["not-a-url", "", "://missing-scheme", "   "] {
            let err = validate_l1_rpc(bad)
                .expect_err("a URL without a base must not reach the sync task");
            assert!(
                err.to_string().contains("invalid --l1-rpc URL"),
                "unexpected message for {bad:?}: {err}"
            );
        }

        for good in [
            "http://localhost:8545",
            "https://example.invalid/rpc",
            "https://user:pass@example.invalid:8545/path?query=1",
        ] {
            validate_l1_rpc(good).unwrap_or_else(|e| panic!("{good:?} should parse: {e}"));
        }
    }

    #[tokio::test]
    async fn divergence_and_recovery_markers_precede_l1_genesis_provider_access() {
        for shape in ["divergence", "recovery", "orphan_static"] {
            let dir = tempfile::tempdir().unwrap();
            match shape {
                "divergence" => {
                    std::fs::write(dir.path().join("arb-message-divergence.json"), b"{").unwrap();
                }
                "recovery" => {
                    std::fs::write(dir.path().join("arb-message-recovery.json"), b"{").unwrap();
                }
                "orphan_static" => {
                    std::fs::create_dir(dir.path().join("static_files")).unwrap();
                    std::fs::write(dir.path().join("static_files").join("orphan"), b"x").unwrap();
                }
                _ => unreachable!(),
            }
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());

            assert!(
                derive_genesis_from_l1_after_preflight(
                    dir.path(),
                    0,
                    &endpoint,
                    Address::ZERO,
                    0,
                    None,
                )
                .await
                .is_err(),
                "{shape} must stop before parent provider construction"
            );
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
                    .await
                    .is_err(),
                "parent endpoint was touched before {shape} classification"
            );
        }
    }

    #[test]
    fn robinhood_genesis_delayed_cursor_comes_from_header_nonce() {
        let (spec, init, _) =
            crate::orbit_chain_from_files(ROBINHOOD_CHAIN_INFO, ROBINHOOD_GENESIS)
                .expect("build Robinhood chain spec");

        assert_eq!(
            genesis_delayed_messages_read(&spec, init.genesis_block_number),
            Some(1)
        );
        assert_eq!(
            genesis_delayed_messages_read(&spec, init.genesis_block_number + 1),
            None,
            "a snapshot head must not be mistaken for the actual L2 genesis"
        );
    }

    #[test]
    fn manual_start_delayed_cursor_comes_from_durable_tip_header() {
        let provider: MockEthProvider = MockEthProvider::new();
        let tip = 3_117;
        provider.add_header(
            B256::ZERO,
            Header {
                number: tip,
                nonce: B64::new(393u64.to_be_bytes()),
                ..Default::default()
            },
        );

        assert_eq!(
            header_delayed_messages_read(&provider, tip).unwrap(),
            Some(393)
        );
        assert_eq!(
            header_delayed_messages_read(&provider, tip + 1).unwrap(),
            None
        );
    }

    #[test]
    fn orbit_boot_requires_chain_info_and_genesis_together() {
        let chain_info = Path::new("chaininfo.json");
        let genesis = Path::new("genesis.json");

        assert_eq!(
            orbit_boot_paths(Some(chain_info), Some(genesis)).unwrap(),
            Some((chain_info, genesis))
        );
        assert!(orbit_boot_paths(None, None).unwrap().is_none());
        assert!(
            orbit_boot_paths(Some(chain_info), None)
                .unwrap_err()
                .to_string()
                .contains("--chain-info requires --genesis")
        );
        assert!(
            orbit_boot_paths(None, Some(genesis))
                .unwrap_err()
                .to_string()
                .contains("--genesis requires --chain-info")
        );
    }

    #[test]
    fn removed_durability_bypass_flags_are_rejected_by_clap() {
        for flag in ["--no-fsync", "--init-message-journal-at-tip"] {
            let error = NodeArgs::try_parse_from(["arb-reth", flag])
                .expect_err("removed Phase-A flag must fail during parsing");
            assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
            assert!(error.to_string().contains(flag));
        }
    }

    #[test]
    fn b1_entrypoint_call_graph_is_permanently_storage_only() {
        let source = include_str!("node.rs");
        let run = source
            .split_once("pub async fn run(")
            .unwrap()
            .1
            .split_once("#[cfg(any())]\npub async fn removed_ordinary_runtime_path")
            .unwrap()
            .0;
        assert!(run.contains("Err(classify_storage_only(&args)?.into())"));
        for prohibited in [
            "spawn",
            "connect",
            "bind",
            "NodeBuilder",
            "ArbLauncher",
            "LifecycleGuard",
            "prepare_recovery",
            "mark_running",
            "mark_clean",
            "feed::",
            "l1_rpc",
            "rpc_addr",
        ] {
            assert!(
                !run.contains(prohibited),
                "B1 run body contains prohibited operation {prohibited}"
            );
        }
    }

    #[tokio::test]
    async fn storage_only_rejection_touches_no_configured_socket_or_provider() {
        let dir = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let args = NodeArgs::try_parse_from([
            "arb-reth",
            "--datadir",
            dir.path().to_str().unwrap(),
            "--l1-rpc",
            &endpoint,
            "--feed-url",
            &endpoint,
            "--http",
        ])
        .unwrap();
        let runtime = reth_tasks::Runtime::test();
        let (_, terminal_signal) = terminal_signal_channel();
        let error = run(
            CliContext {
                task_executor: runtime,
            },
            args,
            terminal_signal,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("missing v3 journal lineage"));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "storage-only rejection touched a configured provider/feed endpoint"
        );
    }

    #[test]
    fn cli_accepts_repeated_feed_urls_and_parallel_connections() {
        let args = NodeArgs::try_parse_from([
            "arb-reth",
            "--feed-url",
            "wss://relay-a.example/feed",
            "--feed-url",
            "wss://relay-b.example/feed",
            "--feed-connections",
            "3",
        ])
        .unwrap();

        assert_eq!(
            args.feed_urls,
            ["wss://relay-a.example/feed", "wss://relay-b.example/feed"]
        );
        assert_eq!(args.feed_connections, Some(3));
        assert!(args.feed_sources.is_empty());
    }

    #[test]
    fn cli_accepts_counted_feed_sources_without_an_implicit_unbound_lane() {
        let args = NodeArgs::try_parse_from([
            "arb-reth",
            "--feed-url",
            "wss://relay.example/feed",
            "--feed-source",
            "192.0.2.10=3",
            "--feed-source",
            "192.0.2.11=2",
        ])
        .unwrap();

        assert_eq!(args.feed_connections, None);
        assert_eq!(
            args.feed_sources[0].local_ip,
            "192.0.2.10".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(args.feed_sources[0].connections, 3);
        assert_eq!(args.feed_sources[1].connections, 2);
    }
}
