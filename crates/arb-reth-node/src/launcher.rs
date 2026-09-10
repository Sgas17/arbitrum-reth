//! `ArbLauncher`, a custom `LaunchNode` for the Arbitrum engine-tree node.
//!
//! Mirrors reth's `EngineNodeLauncher::launch_node` type-state chain but stops after
//! `.with_components(...)` (no pipeline, no consensus-engine orchestrator, no RpcAddOns;
//! AddOns = ()). After standing up the provider stack it extracts `ProviderFactory` +
//! `BlockchainProvider`, spawns reth's engine tree via [`ArbEngineDriver::spawn`], and runs a
//! background task that calls `driver.advance()` per feed message (produce → InsertExecutedBlock
//! → ForkchoiceUpdated); the tree owns async persistence and the in-memory overlay.
//!
//! Deadlock rule: never hold a read provider across a `provider_rw()`/`save_blocks()` call.

use core::{future::Future, pin::Pin};
use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use crate::metrics::FeedLatencyTracker;
use alloy_consensus::Header;
use arbitrum_alloy_consensus::reth::ArbPrimitives;
use arbitrum_alloy_sequencer::sequencer::feed::BroadcastFeedMessage;
use eyre::eyre;
use futures_util::StreamExt;
use reth_chain_state::CanonicalInMemoryState;
use reth_db::{Database, database_metrics::DatabaseMetrics};
use reth_evm::ConfigureEvm;
use reth_node_api::{AddOnsContext, FullNodeTypes, NodeAddOns, NodeTypes, NodeTypesWithDBAdapter};
use reth_node_builder::hooks::NodeHooks;
use reth_node_builder::{
    AddOns, LaunchContext, LaunchNode, Node, NodeAdapter, NodeBuilderWithComponents,
    NodeComponents, NodeComponentsBuilder, NodeTypesAdapter, RethFullAdapter, rpc::RethRpcAddOns,
};
use reth_primitives_traits::SealedHeader;
use reth_provider::{
    BalProvider, BlockNumReader, BlockReader, ChangeSetReader, DatabaseProviderFactory,
    HashedPostStateProvider, ProviderFactory, StateProviderFactory, StateReader,
    StorageChangeSetReader,
    providers::{BlockchainProvider, NodeTypesForProvider, ProviderNodeTypes},
};
use reth_rpc_builder::RpcServerHandle;
use reth_storage_api::{
    HeaderProvider, MetadataProvider, MetadataWriter, PruneCheckpointReader, StageCheckpointReader,
    StorageSettingsCache,
};
use reth_storage_overlay::OverlayManager;
use reth_tasks::TaskExecutor;
use tokio::sync::oneshot;

use arbitrum_alloy_consensus::{ArbReceiptEnvelope, reth::ArbBlock};

use arb_reth_engine::{ArbEngineDriver, ArbEngineTuning, ArbTxLogBroadcaster};

/// Handle returned by `ArbLauncher` after the node has been launched.
///
/// Generic over the provider type `P` so the concrete `BlockchainProvider<...>` type flows
/// through without a transmute.
pub struct ArbNodeHandle<P> {
    /// The blockchain provider: cloneable and queryable.
    pub provider: P,
    exit_rx: oneshot::Receiver<eyre::Result<()>>,
    /// Running RPC server handle. Dropping this shuts down the HTTP server.
    pub rpc_handle: Option<RpcServerHandle>,
    finite_frontier: Option<u64>,
    finite_input_close: Option<FiniteInputClose>,
}

/// Completion authority for a finite run's bounded input.
///
/// This deliberately is not a message sender: only typed derivation completion can close the
/// receiver, rejecting retained producers and discarding their queued tail.
struct FiniteInputClose {
    closed: Arc<AtomicBool>,
    close_tx: oneshot::Sender<()>,
}

impl FiniteInputClose {
    fn close(self) {
        self.closed.store(true, Ordering::Release);
        let _ = self.close_tx.send(());
    }
}

struct FiniteInputCloseReceiver {
    closed: Arc<AtomicBool>,
    close_rx: oneshot::Receiver<()>,
}

/// Launcher behavior for ordinary serving nodes and bounded recovery execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArbLaunchMode {
    /// The ordinary node: arbitrate live-feed and L1 inputs and honor configured RPC/metrics.
    Ordinary,
    /// A non-serving run which accepts only the bounded L1-derived input and stops at `frontier`.
    Finite { frontier: u64 },
}

impl ArbLaunchMode {
    const fn frontier(self) -> Option<u64> {
        match self {
            Self::Ordinary => None,
            Self::Finite { frontier } => Some(frontier),
        }
    }

    const fn is_serving(self) -> bool {
        matches!(self, Self::Ordinary)
    }
}

/// A total-domain failure while mapping a feed sequence into an L2 block for engine handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EngineHandoffAdmissionError {
    FrontierBelowGenesis {
        frontier: u64,
        genesis_block: u64,
    },
    SequenceNumberOverflow {
        sequence_number: u64,
        genesis_block: u64,
    },
    TipBelowGenesis {
        tip: u64,
        genesis_block: u64,
    },
    NextSequenceOverflow {
        tip: u64,
        genesis_block: u64,
    },
}

impl std::fmt::Display for EngineHandoffAdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FrontierBelowGenesis {
                frontier,
                genesis_block,
            } => write!(
                f,
                "finite frontier {frontier} is below genesis block {genesis_block}"
            ),
            Self::SequenceNumberOverflow {
                sequence_number,
                genesis_block,
            } => write!(
                f,
                "sequence number {sequence_number} overflows L2 block conversion with genesis block {genesis_block}"
            ),
            Self::TipBelowGenesis { tip, genesis_block } => {
                write!(f, "driver tip {tip} is below genesis block {genesis_block}")
            }
            Self::NextSequenceOverflow { tip, genesis_block } => write!(
                f,
                "driver tip {tip} overflows next sequence conversion with genesis block {genesis_block}"
            ),
        }
    }
}

impl std::error::Error for EngineHandoffAdmissionError {}

/// The immutable admission decision immediately preceding every engine handoff.
///
/// Finite mode never hands a message above its L2 frontier to `ArbEngineDriver`, irrespective of
/// completion/receiver-close timing. Arithmetic is checked over the full `u64` domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EngineHandoffAdmission {
    Admitted { block_number: u64 },
    RejectedAboveFrontier { block_number: u64, frontier: u64 },
}

fn admit_engine_handoff(
    mode: ArbLaunchMode,
    sequence_number: u64,
    genesis_block: u64,
) -> Result<EngineHandoffAdmission, EngineHandoffAdmissionError> {
    let block_number = sequence_number.checked_add(genesis_block).ok_or(
        EngineHandoffAdmissionError::SequenceNumberOverflow {
            sequence_number,
            genesis_block,
        },
    )?;
    match mode {
        ArbLaunchMode::Ordinary => Ok(EngineHandoffAdmission::Admitted { block_number }),
        ArbLaunchMode::Finite { frontier } => {
            if frontier < genesis_block {
                return Err(EngineHandoffAdmissionError::FrontierBelowGenesis {
                    frontier,
                    genesis_block,
                });
            }
            if block_number > frontier {
                Ok(EngineHandoffAdmission::RejectedAboveFrontier {
                    block_number,
                    frontier,
                })
            } else {
                Ok(EngineHandoffAdmission::Admitted { block_number })
            }
        }
    }
}

fn finite_max_sequence(
    mode: ArbLaunchMode,
    genesis_block: u64,
) -> Result<Option<u64>, EngineHandoffAdmissionError> {
    match mode {
        ArbLaunchMode::Ordinary => Ok(None),
        ArbLaunchMode::Finite { frontier } => frontier.checked_sub(genesis_block).map(Some).ok_or(
            EngineHandoffAdmissionError::FrontierBelowGenesis {
                frontier,
                genesis_block,
            },
        ),
    }
}

fn next_driver_sequence(tip: u64, genesis_block: u64) -> Result<u64, EngineHandoffAdmissionError> {
    let sequence = tip
        .checked_sub(genesis_block)
        .ok_or(EngineHandoffAdmissionError::TipBelowGenesis { tip, genesis_block })?;
    sequence
        .checked_add(1)
        .ok_or(EngineHandoffAdmissionError::NextSequenceOverflow { tip, genesis_block })
}

impl<P> ArbNodeHandle<P> {
    /// Wait for the driver task to exit, returning its result.
    pub async fn wait_for_node_exit(self) -> eyre::Result<()> {
        self.exit_rx.await?
    }

    /// Wait for a finite run to flush and verify its durable tip is exactly the requested frontier.
    pub async fn wait_for_finite_execution(
        self,
    ) -> eyre::Result<crate::trusted_l2::HeaderObservation>
    where
        P: Clone + BlockNumReader + HeaderProvider<Header = Header>,
    {
        let frontier = self
            .finite_frontier
            .ok_or_else(|| eyre!("finite execution wait requested from ordinary launcher"))?;
        let provider = self.provider.clone();
        self.wait_for_node_exit().await?;
        let tip = provider.last_block_number()?;
        if tip != frontier {
            return Err(eyre!(
                "finite execution durable tip {tip} does not equal requested frontier {frontier}"
            ));
        }
        let header = provider
            .sealed_header(frontier)?
            .ok_or_else(|| eyre!("finite execution durable header {frontier} is missing"))?;
        Ok(crate::trusted_l2::HeaderObservation {
            number: frontier,
            hash: header.hash(),
            state_root: header.state_root,
        })
    }

    /// Close the bounded L1 receiver once derivation reaches its exact frontier, then flush and
    /// verify the durable provider tip. Completion is deliberately separate from the producer:
    /// retained producer clones cannot keep the finite engine alive or extend its boundary.
    pub async fn finish_finite_l1_execution<F>(
        mut self,
        derivation: F,
    ) -> eyre::Result<crate::trusted_l2::HeaderObservation>
    where
        P: Clone + BlockNumReader + HeaderProvider<Header = Header>,
        F: Future<Output = Result<arb_reth_sync::L1SyncCompletion, arb_reth_sync::L1SyncError>>,
    {
        let frontier = self
            .finite_frontier
            .ok_or_else(|| eyre!("finite execution completion requested from ordinary launcher"))?;
        match derivation.await.map_err(|error| eyre!(error))? {
            arb_reth_sync::L1SyncCompletion::FrontierReached { frontier: reached }
                if reached == frontier => {}
            completion => {
                return Err(eyre!(
                    "finite derivation completed without requested frontier {frontier}: {completion:?}"
                ));
            }
        }
        self.finite_input_close
            .take()
            .ok_or_else(|| eyre!("finite input close requested from ordinary launcher"))?
            .close();
        self.wait_for_finite_execution().await
    }

    /// Returns the HTTP URL of the running RPC server, or `None` if RPC was not enabled.
    pub fn http_url(&self) -> Option<String> {
        self.rpc_handle.as_ref()?.http_url()
    }
}

/// A custom `LaunchNode` for the self-driven Arbitrum node.
///
/// Reuses reth's `LaunchContext` type-state chain for DB/provider/blockchain-db/task
/// infrastructure but skips the sync pipeline and consensus-engine orchestrator. Spawns
/// an [`ArbEngineDriver`] background task that drives reth's engine tree, producing exactly
/// one block per sequencer feed message.
pub struct ArbLauncher {
    /// Base launch context: task executor + data directory.
    pub ctx: LaunchContext,
    /// Arbitrum chain id (42161 = mainnet, 421614 = Sepolia).
    pub chain_id: u64,
    /// L2 genesis block number (`GenesisBlockNum`): message index 0 is the init/genesis block, so a
    /// feed message's sequence number maps to L2 block `seq + genesis_block`. Seeds the driver's
    /// sequence-dedup cursor so feed and L1-derivation messages reconcile without double-applying.
    pub genesis_block: u64,
    /// Engine-tree persistence tuning (batch/buffer/backpressure knobs).
    pub tuning: ArbEngineTuning,
    /// Whether this is an ordinary serving node or a finite non-serving L1-only execution.
    pub mode: ArbLaunchMode,
    /// Live-feed and replay messages. These may be ahead of the local canonical cursor when the
    /// relay's bounded backlog begins after the database tip.
    pub feed_messages: tokio::sync::mpsc::Receiver<BroadcastFeedMessage>,
    /// Authoritative L1-derived messages. These are kept separate from the live feed so a large
    /// feed-ahead backlog cannot delay the message that closes a derivation gap.
    pub l1_messages: tokio::sync::mpsc::Receiver<BroadcastFeedMessage>,
    /// Correlates live WebSocket feed messages with canonical in-memory state for Prometheus.
    /// `None` keeps replay and L1-only operation free of feed-latency instrumentation.
    pub feed_latency: Option<FeedLatencyTracker>,
    /// Optional best-effort publisher for per-transaction execution logs.
    pub tx_log_stream: Option<ArbTxLogBroadcaster>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MessageSource {
    L1,
    Feed,
}

const MAX_MESSAGE_BATCH: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BatchKind {
    Ordinary,
    GapCloser,
}

struct SelectedBatch {
    source: MessageSource,
    messages: Vec<BroadcastFeedMessage>,
    kind: BatchKind,
}

/// Deterministic, work-conserving bounded-fair arbitration over the two ingress channels.
struct IngressScheduler {
    feed_messages: tokio::sync::mpsc::Receiver<BroadcastFeedMessage>,
    l1_messages: tokio::sync::mpsc::Receiver<BroadcastFeedMessage>,
    feed_pending: Option<BroadcastFeedMessage>,
    l1_pending: Option<BroadcastFeedMessage>,
    l1_buffered: VecDeque<BroadcastFeedMessage>,
    feed_open: bool,
    l1_open: bool,
    owed: MessageSource,
}

impl IngressScheduler {
    fn new(
        feed_messages: tokio::sync::mpsc::Receiver<BroadcastFeedMessage>,
        l1_messages: tokio::sync::mpsc::Receiver<BroadcastFeedMessage>,
    ) -> Self {
        Self {
            feed_messages,
            l1_messages,
            feed_pending: None,
            l1_pending: None,
            l1_buffered: VecDeque::new(),
            feed_open: true,
            l1_open: true,
            owed: MessageSource::Feed,
        }
    }

    fn l1_only(l1_messages: tokio::sync::mpsc::Receiver<BroadcastFeedMessage>) -> Self {
        let (feed_tx, feed_messages) = tokio::sync::mpsc::channel(1);
        drop(feed_tx);
        Self::new(feed_messages, l1_messages)
    }

    /// Reject future L1 sends, retain only the bounded input, and discard the queued tail.
    fn close_l1_input(&mut self, max_sequence: u64) {
        self.l1_messages.close();
        if self
            .l1_pending
            .as_ref()
            .is_some_and(|message| message.sequence_number > max_sequence)
        {
            self.l1_pending = None;
        }
        while let Ok(message) = self.l1_messages.try_recv() {
            if message.sequence_number <= max_sequence {
                self.l1_buffered.push_back(message);
            }
        }
        self.l1_open = !self.l1_buffered.is_empty();
    }

    fn try_fill_head(&mut self, source: MessageSource) {
        if source == MessageSource::L1
            && self.l1_open
            && self.l1_pending.is_none()
            && let Some(message) = self.l1_buffered.pop_front()
        {
            self.l1_pending = Some(message);
            return;
        }
        let (open, pending, messages) = match source {
            MessageSource::Feed => (
                &mut self.feed_open,
                &mut self.feed_pending,
                &mut self.feed_messages,
            ),
            MessageSource::L1 => (
                &mut self.l1_open,
                &mut self.l1_pending,
                &mut self.l1_messages,
            ),
        };
        if !*open || pending.is_some() {
            return;
        }
        match messages.try_recv() {
            Ok(message) => *pending = Some(message),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => *open = false,
        }
    }

    async fn wait_for_head(&mut self) {
        let received = match self.owed {
            MessageSource::Feed => {
                tokio::select! {
                    biased;
                    message = self.feed_messages.recv(), if self.feed_open => (MessageSource::Feed, message),
                    message = self.l1_messages.recv(), if self.l1_open => (MessageSource::L1, message),
                }
            }
            MessageSource::L1 => {
                tokio::select! {
                    biased;
                    message = self.l1_messages.recv(), if self.l1_open => (MessageSource::L1, message),
                    message = self.feed_messages.recv(), if self.feed_open => (MessageSource::Feed, message),
                }
            }
        };
        match received {
            (MessageSource::Feed, Some(message)) => self.feed_pending = Some(message),
            (MessageSource::L1, Some(message)) => self.l1_pending = Some(message),
            (MessageSource::Feed, None) => self.feed_open = false,
            (MessageSource::L1, None) => self.l1_open = false,
        }
    }

    async fn next_batch(&mut self, next_sequence: u64) -> Option<SelectedBatch> {
        loop {
            self.try_fill_head(MessageSource::Feed);
            self.try_fill_head(MessageSource::L1);
            if self.feed_pending.is_none() && self.l1_pending.is_none() {
                if !self.feed_open && !self.l1_open {
                    return None;
                }
                self.wait_for_head().await;
                continue;
            }

            let gap_closer = matches!(
                (&self.feed_pending, &self.l1_pending),
                (Some(feed), Some(l1))
                    if l1.sequence_number == next_sequence && feed.sequence_number > next_sequence
            );
            let source = if gap_closer {
                MessageSource::L1
            } else {
                match (self.feed_pending.is_some(), self.l1_pending.is_some()) {
                    (true, true) => self.owed,
                    (true, false) => MessageSource::Feed,
                    (false, true) => MessageSource::L1,
                    (false, false) => unreachable!(),
                }
            };
            let kind = if gap_closer {
                BatchKind::GapCloser
            } else {
                BatchKind::Ordinary
            };
            let first = match source {
                MessageSource::Feed => self.feed_pending.take().unwrap(),
                MessageSource::L1 => self.l1_pending.take().unwrap(),
            };
            let mut messages = Vec::with_capacity(MAX_MESSAGE_BATCH);
            messages.push(first);

            if kind == BatchKind::Ordinary {
                while messages.len() < MAX_MESSAGE_BATCH {
                    if source == MessageSource::L1
                        && let Some(message) = self.l1_buffered.pop_front()
                    {
                        messages.push(message);
                        continue;
                    }
                    let (open, receiver) = match source {
                        MessageSource::Feed => (&mut self.feed_open, &mut self.feed_messages),
                        MessageSource::L1 => (&mut self.l1_open, &mut self.l1_messages),
                    };
                    match receiver.try_recv() {
                        Ok(message) => messages.push(message),
                        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                            *open = false;
                            break;
                        }
                    }
                }
            }
            return Some(SelectedBatch {
                source,
                messages,
                kind,
            });
        }
    }

    fn complete_batch(&mut self, source: MessageSource, kind: BatchKind) {
        match kind {
            BatchKind::GapCloser => self.owed = MessageSource::Feed,
            BatchKind::Ordinary if source == self.owed => {
                self.owed = match source {
                    MessageSource::Feed => MessageSource::L1,
                    MessageSource::L1 => MessageSource::Feed,
                };
            }
            BatchKind::Ordinary => {}
        }
    }
}

impl<N, DB, T, CB, AO> LaunchNode<NodeBuilderWithComponents<T, CB, AO>> for ArbLauncher
where
    N: Node<RethFullAdapter<DB, N>>
        + NodeTypesForProvider
        + NodeTypes<
            Primitives = ArbPrimitives,
            Payload = arb_reth_engine::ArbPayloadTypes,
            ChainSpec: reth_chainspec::EthChainSpec
                           + reth_chainspec::EthereumHardforks
                           + reth_chainspec::Hardforks,
        >,
    DB: Database + DatabaseMetrics + Clone + Unpin + 'static,
    T: FullNodeTypes<
            Types = N,
            Provider = BlockchainProvider<NodeTypesWithDBAdapter<N, DB>>,
            DB = DB,
        >,
    CB: NodeComponentsBuilder<T> + 'static,
    AO: RethRpcAddOns<NodeAdapter<T, CB::Components>> + 'static,
    <CB::Components as NodeComponents<T>>::Evm:
        ConfigureEvm<Primitives = ArbPrimitives> + Into<arb_reth_evm::ArbEvmConfig> + Clone,
    CB::Components: NodeComponents<T, Evm = arb_reth_evm::ArbEvmConfig>,
    NodeTypesWithDBAdapter<N, DB>: ProviderNodeTypes<Primitives = ArbPrimitives>,
    // Explicit equality bounds to help the compiler resolve the associated type projections
    // from NodeTypesWithDBAdapter<N, DB>.
    NodeTypesWithDBAdapter<N, DB>:
        NodeTypes<ChainSpec = <N as NodeTypes>::ChainSpec, Primitives = ArbPrimitives>,
    NodeTypesWithDBAdapter<N, DB>: reth_node_api::NodeTypesWithDB<DB = DB>,
    // Engine-tree (Tier-1) bounds: mirror `EngineApiTreeHandler::spawn_new`'s P-bounds with
    // P = BlockchainProvider<NodeTypesWithDBAdapter<N, DB>> (see engine.rs).
    BlockchainProvider<NodeTypesWithDBAdapter<N, DB>>: DatabaseProviderFactory<DB = DB>
        + BlockReader<Block = ArbBlock, Header = Header>
        + reth_storage_api::TransactionsProvider<
            Transaction = arbitrum_alloy_consensus::ArbTxEnvelope,
        > + reth_storage_api::ReceiptProvider<Receipt = ArbReceiptEnvelope>
        + StateProviderFactory
        + StateReader<Receipt = ArbReceiptEnvelope>
        + HashedPostStateProvider
        + BalProvider
        + ChangeSetReader
        + BlockNumReader
        + Clone
        + 'static,
    <BlockchainProvider<NodeTypesWithDBAdapter<N, DB>> as DatabaseProviderFactory>::Provider:
        BlockReader<Block = ArbBlock, Header = Header>
            + StageCheckpointReader
            + PruneCheckpointReader
            + ChangeSetReader
            + StorageChangeSetReader
            + BlockNumReader
            + StorageSettingsCache,
{
    type Node = ArbNodeHandle<BlockchainProvider<NodeTypesWithDBAdapter<N, DB>>>;
    type Future = Pin<Box<dyn Future<Output = eyre::Result<Self::Node>> + Send>>;

    fn launch_node(self, target: NodeBuilderWithComponents<T, CB, AO>) -> Self::Future {
        Box::pin(self.launch_impl(target))
    }
}

impl ArbLauncher {
    /// Core async launch body. Separated from `launch_node` so it can be `async fn`
    /// (the trait requires a boxed future; `launch_node` boxes it).
    async fn launch_impl<N, DB, T, CB, AO>(
        self,
        target: NodeBuilderWithComponents<T, CB, AO>,
    ) -> eyre::Result<ArbNodeHandle<BlockchainProvider<NodeTypesWithDBAdapter<N, DB>>>>
    where
        N: Node<RethFullAdapter<DB, N>>
            + NodeTypesForProvider
            + NodeTypes<
                Primitives = ArbPrimitives,
                Payload = arb_reth_engine::ArbPayloadTypes,
                ChainSpec: reth_chainspec::EthChainSpec
                               + reth_chainspec::EthereumHardforks
                               + reth_chainspec::Hardforks,
            >,
        DB: Database + DatabaseMetrics + Clone + Unpin + 'static,
        T: FullNodeTypes<
                Types = N,
                Provider = BlockchainProvider<NodeTypesWithDBAdapter<N, DB>>,
                DB = DB,
            >,
        CB: NodeComponentsBuilder<T> + 'static,
        AO: RethRpcAddOns<NodeAdapter<T, CB::Components>> + 'static,
        <CB::Components as NodeComponents<T>>::Evm:
            ConfigureEvm<Primitives = ArbPrimitives> + Into<arb_reth_evm::ArbEvmConfig> + Clone,
        CB::Components: NodeComponents<T, Evm = arb_reth_evm::ArbEvmConfig>,
        NodeTypesWithDBAdapter<N, DB>: ProviderNodeTypes<Primitives = ArbPrimitives>,
        NodeTypesWithDBAdapter<N, DB>:
            NodeTypes<ChainSpec = <N as NodeTypes>::ChainSpec, Primitives = ArbPrimitives>,
        NodeTypesWithDBAdapter<N, DB>: reth_node_api::NodeTypesWithDB<DB = DB>,
    {
        let Self {
            ctx,
            chain_id,
            genesis_block,
            tuning,
            mode,
            feed_messages,
            l1_messages,
            feed_latency,
            tx_log_stream,
        } = self;
        let serving = mode.is_serving();

        let NodeBuilderWithComponents {
            adapter: NodeTypesAdapter { database },
            rocksdb_provider,
            components_builder,
            add_ons:
                AddOns {
                    hooks,
                    exexs: _,
                    add_ons: _,
                },
            config,
        } = target;
        let NodeHooks {
            on_component_initialized,
            ..
        } = hooks;

        // The native command owns public RPC configuration. This node is self-driven from L1
        // derivation, so its authenticated Engine API server must always stay disabled.
        let mut config = config;
        config.rpc.disable_auth_server = true;
        if !serving {
            config.rpc.http = false;
            config.rpc.ws = false;
            config.rpc.ipcdisable = true;
        }

        let overlay_manager = OverlayManager::<ArbPrimitives>::new(
            ctx.task_executor.state_trie_overlay_worker_pool(),
        );
        let disabled_stages = N::disabled_stages();

        let ctx = ctx
            .with_configured_globals(0)
            .with_loaded_toml_config(config)?
            .attach(database.clone());

        // TOML is intentionally allowed to configure the public Reth RPC servers, but this
        // standalone node has no beacon-engine service to back an authenticated Engine API.
        // Apply this after TOML merging so no config file can inadvertently expose it.
        let mut ctx = ctx;
        ctx.node_config_mut().rpc.disable_auth_server = true;
        if !serving {
            let rpc = &mut ctx.node_config_mut().rpc;
            rpc.http = false;
            rpc.ws = false;
            rpc.ipcdisable = true;
        }

        // Use Reth's effective configuration after the native CLI and persisted `reth.toml` have
        // been merged. The provider factory and persistence pruner must use these exact same modes:
        // otherwise a run can try to append a static-file segment that an earlier run pruned.
        let prune_config = ctx.prune_config();
        if prune_config.is_default() {
            reth_tracing::tracing::info!(
                target: "arb-reth",
                "archive node (no pruning configured; keeping all history)",
            );
        } else {
            reth_tracing::tracing::info!(
                target: "arb-reth",
                segments = ?prune_config.segments,
                block_interval = prune_config.block_interval,
                minimum_pruning_distance = prune_config.minimum_pruning_distance,
                "history pruning enabled",
            );
        }
        let prune_builder =
            (!prune_config.is_default()).then(|| reth_prune::PrunerBuilder::new(prune_config));

        let ctx = ctx
            .with_adjusted_configs()
            .with_provider_factory::<NodeTypesWithDBAdapter<N, DB>, <CB::Components as NodeComponents<T>>::Evm>(
                overlay_manager.clone(),
                rocksdb_provider,
                disabled_stages,
            )
            .await?;

        // Ordinary nodes install and serve Prometheus when configured. Finite recovery execution
        // deliberately owns no metrics server.
        let ctx = if serving {
            ctx.with_prometheus_server().await?
        } else {
            ctx
        };

        // Open the DB in storage v2 (hashed-state canonical, `PackedKeyAdapter`). This has to
        // happen before `with_genesis()` uses the factory. Cache the flag so every provider
        // uses v2, and persist it idempotently: an importer-made DB already has v2 in metadata, so
        // we only write when no settings flag is persisted (fresh DB) or it differs.
        {
            let factory = ctx.provider_factory();
            factory.set_storage_settings_cache(reth_db_api::models::StorageSettings::v2());
            let current = {
                let p = factory.database_provider_ro()?;
                p.storage_settings()?
            };
            if current != Some(reth_db_api::models::StorageSettings::v2()) {
                let provider_rw = factory.provider_rw()?;
                provider_rw.write_storage_settings(reth_db_api::models::StorageSettings::v2())?;
                provider_rw
                    .commit()
                    .map_err(|e| eyre!("persist storage settings v2: {e}"))?;
            }
        }

        let ctx = ctx.with_genesis()?.with_metrics_task();
        let ctx = ctx
            .with_blockchain_db::<T, _>(move |provider_factory| {
                Ok(BlockchainProvider::new(provider_factory)?)
            })?
            .with_components(components_builder, on_component_initialized)
            .await?;

        let rpc = &ctx.node_config().rpc;
        let rpc_enabled = rpc.http || rpc.ws || !rpc.ipcdisable;

        let provider: BlockchainProvider<NodeTypesWithDBAdapter<N, DB>> =
            ctx.node_adapter().provider.clone();
        // `with_provider_factory` already applied the merged pruning modes above.
        let provider_factory: ProviderFactory<NodeTypesWithDBAdapter<N, DB>> =
            ctx.provider_factory().clone();
        let task_executor: TaskExecutor = ctx.task_executor().clone();
        let head = ctx.head();
        let engine_events = reth_tokio_util::EventSender::default();
        // Reth's generic `CanonicalBlockAdded` log treats the consensus header gas limit as
        // executable block capacity and its event elapsed time as execution throughput. Neither
        // interpretation is valid for Arbitrum: the header carries Nitro's permissive `2^50`
        // envelope, and ArbOS execution happened before insertion into the engine tree. The
        // driver emits an Arbitrum-aware replacement with its measured production timings.
        let node_events = engine_events.new_listener().filter_map(|event| {
            futures_util::future::ready(
                (!matches!(
                    &event,
                    reth_engine_primitives::ConsensusEngineEvent::CanonicalBlockAdded(..)
                ))
                .then(|| event.into()),
            )
        });
        if serving {
            task_executor.spawn_critical_task(
                "events task",
                reth_node_events::node::handle_events(None, Some(head.number), node_events),
            );
        }

        // Clone the in-memory state from the provider so the tree updates the same instance that
        // BlockchainProvider serves for RPC queries.
        let canonical: CanonicalInMemoryState<ArbPrimitives> = provider.canonical_in_memory_state();

        let genesis_tip: SealedHeader<Header> =
            HeaderProvider::sealed_header(&provider, head.number)?
                .ok_or_else(|| eyre!("missing head header at block {}", head.number))?;

        // `arb_evm_config` (hoisted from the RPC block below): also drives the engine tree.
        let arb_evm_config: arb_reth_evm::ArbEvmConfig =
            ctx.node_adapter().components.evm_config().clone();
        let frontier_store = serving
            .then(|| {
                tx_log_stream
                    .as_ref()
                    .map(ArbTxLogBroadcaster::frontier_store)
            })
            .flatten();

        // Stand up reth's engine tree (Tier-1 `InsertExecutedBlock` seam) and drive the
        // sequencer feed through it. Persistence to MDBX is async (tree background service).
        let mut driver: ArbEngineDriver<NodeTypesWithDBAdapter<N, DB>> = ArbEngineDriver::spawn(
            provider_factory,
            provider.clone(),
            arb_evm_config.clone(),
            chain_id,
            genesis_tip,
            genesis_block,
            canonical,
            task_executor.clone(),
            tuning,
            prune_builder,
            serving.then_some(tx_log_stream).flatten(),
            engine_events.clone(),
        )?;

        // Validate the finite bound before starting the driver. The same immutable conversion is
        // repeated by `admit_engine_handoff` immediately before every engine handoff.
        let finite_max_sequence = finite_max_sequence(mode, genesis_block)?;
        let (exit_tx, exit_rx) = oneshot::channel::<eyre::Result<()>>();
        let mut scheduler = if serving {
            IngressScheduler::new(feed_messages, l1_messages)
        } else {
            drop(feed_messages);
            IngressScheduler::l1_only(l1_messages)
        };
        let (finite_input_close, mut finite_input_close_rx) = match mode {
            ArbLaunchMode::Finite { .. } => {
                let closed = Arc::new(AtomicBool::new(false));
                let (close_tx, close_rx) = oneshot::channel();
                (
                    Some(FiniteInputClose {
                        closed: Arc::clone(&closed),
                        close_tx,
                    }),
                    Some(FiniteInputCloseReceiver { closed, close_rx }),
                )
            }
            ArbLaunchMode::Ordinary => (None, None),
        };

        task_executor.spawn_critical_task("arb-engine-driver", async move {
            let res: eyre::Result<()> = async {
                // Periodically summarize progress while distinguishing source wait from local
                // production. Per-block and per-payload details remain available at DEBUG.
                let mut status_recv_us: u128 = 0;
                let mut status_work_us: u128 = 0;
                let mut status_window_messages: u64 = 0;
                let mut status_window_blocks: u64 = 0;
                let mut status_total_blocks: u64 = 0;
                let mut status_last_applied_sequence: Option<u64> = None;
                let mut status_window = std::time::Instant::now();
                const STATUS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
                'drive: loop {
                    let __r = std::time::Instant::now();
                    // An L1 message may bypass the normal 64-item bound only when it closes the
                    // exact gap ahead of a feed head. Ordinary batches alternate while both
                    // sources are ready, starting with Feed.
                    let next_sequence = next_driver_sequence(driver.tip().number, genesis_block)?;
                    if finite_input_close_rx
                        .as_ref()
                        .is_some_and(|close| close.closed.load(Ordering::Acquire))
                    {
                        scheduler.close_l1_input(
                            finite_max_sequence.expect("finite input close only exists in finite mode"),
                        );
                    }
                    let selected = if let Some(close) = finite_input_close_rx.as_mut()
                        && !close.closed.load(Ordering::Acquire)
                    {
                        tokio::select! {
                            biased;
                            _ = &mut close.close_rx => {
                                scheduler.close_l1_input(
                                    finite_max_sequence.expect("finite input close only exists in finite mode"),
                                );
                                continue 'drive;
                            }
                            selected = scheduler.next_batch(next_sequence) => selected,
                        }
                    } else {
                        scheduler.next_batch(next_sequence).await
                    };
                    let Some(SelectedBatch {
                        source,
                        messages: batch,
                        kind,
                    }) = selected
                    else {
                        break;
                    };
                    status_recv_us += __r.elapsed().as_micros();

                    // A batch is a deterministic proof that another message is ready. It replaces
                    // the receiver's racy `is_empty()` hint: historical catch-up can overlap the
                    // final FCU of every non-tail message, while a one-message live-feed batch
                    // remains fully settled before the next frame arrives.
                    let batch_len = batch.len();
                    for (index, msg) in batch.into_iter().enumerate() {
                        if finite_input_close_rx
                            .as_ref()
                            .is_some_and(|close| close.closed.load(Ordering::Acquire))
                        {
                            scheduler.close_l1_input(
                                finite_max_sequence.expect("finite input close only exists in finite mode"),
                            );
                        }
                        let driver_dequeued_at = std::time::Instant::now();
                        if source == MessageSource::Feed
                            && let Some(feed_latency) = feed_latency.as_ref()
                        {
                            feed_latency
                                .record_driver_dequeue(msg.sequence_number, driver_dequeued_at);
                        }
                        let __w = std::time::Instant::now();
                        let mut applied_blocks = 0u64;
                        let mut last_applied_sequence = None;
                        // This is deliberately the final decision before `driver.advance`: an
                        // already-selected batch cannot hand frontier + 1 to the engine, even if
                        // typed completion closes the receiver concurrently.
                        let EngineHandoffAdmission::Admitted { .. } = admit_engine_handoff(
                            mode,
                            msg.sequence_number,
                            genesis_block,
                        )?
                        else {
                            continue;
                        };
                        driver
                            .advance_with_applied_overlap(
                                &msg,
                                index + 1 < batch_len,
                                |sequence_number, applied| {
                                    applied_blocks += 1;
                                    last_applied_sequence = Some(sequence_number);
                                    if let Some(feed_latency) = feed_latency.as_ref() {
                                        feed_latency.record_canonical(sequence_number, applied);
                                    }
                                },
                            )
                            .await?;
                        status_work_us += __w.elapsed().as_micros();
                        status_window_messages += 1;
                        status_window_blocks += applied_blocks;
                        status_total_blocks += applied_blocks;
                        if last_applied_sequence.is_some() {
                            status_last_applied_sequence = last_applied_sequence;
                        }
                        if status_window.elapsed() >= STATUS_INTERVAL {
                            let wall_ms = status_window.elapsed().as_millis().max(1);
                            tracing::info!(
                                target: "arb-reth::status",
                                last_applied_sequence = ?status_last_applied_sequence,
                                processed = status_total_blocks,
                                input_messages = status_window_messages,
                                window_blocks = status_window_blocks,
                                blk_per_s =
                                    (status_window_blocks as u128 * 1000 / wall_ms) as u64,
                                source_wait_ms = (status_recv_us / 1000) as u64,
                                processing_ms = (status_work_us / 1000) as u64,
                                source_wait_pct = (100 * status_recv_us
                                    / (status_recv_us + status_work_us).max(1)) as u64,
                                "Arbitrum sync status",
                            );
                            status_recv_us = 0;
                            status_work_us = 0;
                            status_window_messages = 0;
                            status_window_blocks = 0;
                            status_window = std::time::Instant::now();
                        }
                    }

                    scheduler.complete_batch(source, kind);
                }
                driver.shutdown().await.map_err(|error| eyre!(error))?;
                Ok(())
            }
            .await;
            let _ = exit_tx.send(res); // ignore error if receiver was dropped
        });

        // Serve RPC through reth's canonical `RpcAddOns::launch_add_ons` (full fleet + ws +
        // subscriptions via `NodeConfig.rpc`), not the bespoke server. This node is self-driven
        // from L1 derivation, so the beacon-engine handle is a stub (dangling receiver: engine_*
        // calls would return `EngineUnavailable`), and the auth/engine server is disabled, so
        // nothing ever reaches it.
        let rpc_handle = if serving && rpc_enabled {
            let (engine_tx, _engine_rx) = tokio::sync::mpsc::unbounded_channel();
            let beacon_engine_handle =
                reth_engine_primitives::ConsensusEngineHandle::new(engine_tx);
            let add_ons_ctx = AddOnsContext {
                node: ctx.node_adapter().clone(),
                config: ctx.node_config(),
                beacon_engine_handle,
                engine_events,
                jwt_secret: ctx.auth_jwt_secret()?,
            };
            let mut add_ons = crate::addons::arb_add_ons();
            if let Some(frontier_store) = frontier_store {
                let frontier_provider = provider.clone();
                let frontier_evm_config = arb_evm_config.clone();
                let frontier_gas_cap = ctx.node_config().rpc.rpc_gas_cap;
                add_ons = add_ons.extend_rpc_modules(move |rpc| {
                    let module = crate::mev_frontier_rpc::module(
                        frontier_store,
                        frontier_provider,
                        frontier_evm_config,
                        frontier_gas_cap,
                    )?;
                    rpc.modules.merge_configured(module)?;
                    Ok(())
                });
            }
            let handle = add_ons.launch_add_ons(add_ons_ctx).await?;
            Some(handle.rpc_server_handles.rpc)
        } else {
            None
        };

        Ok(ArbNodeHandle {
            provider,
            exit_rx,
            rpc_handle,
            finite_frontier: mode.frontier(),
            finite_input_close,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use alloy_primitives::{U256, address};
    use arb_revm::arbos_init::ArbosInitConfig;
    use arbitrum_alloy_sequencer::sequencer::feed::BroadcastFeedMessage;
    use reth_chainspec::MAINNET;
    use reth_node_builder::{LaunchNode, NodeBuilder, NodeConfig};
    use reth_node_core::args::PruningArgs;
    use reth_provider::{BlockNumReader, HeaderProvider, StateProviderFactory};
    use reth_storage_api::AccountReader;
    use reth_tasks::Runtime;

    use crate::ArbNode;

    fn scheduler_with(
        feed: impl IntoIterator<Item = u64>,
        l1: impl IntoIterator<Item = u64>,
    ) -> IngressScheduler {
        let feed = feed.into_iter().collect::<Vec<_>>();
        let l1 = l1.into_iter().collect::<Vec<_>>();
        let fixture = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/deposit_message_only.json"),
        )
        .expect("read scheduler fixture");
        let message: BroadcastFeedMessage =
            serde_json::from_str(&fixture).expect("parse scheduler fixture");
        let (feed_tx, feed_rx) = tokio::sync::mpsc::channel(feed.len().max(1));
        let (l1_tx, l1_rx) = tokio::sync::mpsc::channel(l1.len().max(1));
        for sequence_number in feed {
            let mut input = message.clone();
            input.sequence_number = sequence_number;
            feed_tx.try_send(input).expect("queue feed input");
        }
        for sequence_number in l1 {
            let mut input = message.clone();
            input.sequence_number = sequence_number;
            l1_tx.try_send(input).expect("queue L1 input");
        }
        drop((feed_tx, l1_tx));
        IngressScheduler::new(feed_rx, l1_rx)
    }

    #[tokio::test]
    async fn both_ready_is_feed_first_then_bounded_fair_at_exact_quantum() {
        let mut scheduler = scheduler_with(1..=65, 100..=164);

        let feed = scheduler.next_batch(1_000).await.unwrap();
        assert_eq!(feed.source, MessageSource::Feed);
        assert_eq!(feed.kind, BatchKind::Ordinary);
        assert_eq!(feed.messages.len(), MAX_MESSAGE_BATCH);
        assert_eq!(feed.messages[0].sequence_number, 1);
        assert_eq!(feed.messages[63].sequence_number, 64);
        scheduler.complete_batch(feed.source, feed.kind);

        let l1 = scheduler.next_batch(1_000).await.unwrap();
        assert_eq!(l1.source, MessageSource::L1);
        assert_eq!(l1.messages.len(), MAX_MESSAGE_BATCH);
        assert_eq!(l1.messages[0].sequence_number, 100);
        assert_eq!(l1.messages[63].sequence_number, 163);
        scheduler.complete_batch(l1.source, l1.kind);
        assert_eq!(scheduler.owed, MessageSource::Feed);
    }

    #[tokio::test]
    async fn open_empty_peer_never_delays_ready_source() {
        let fixture = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/deposit_message_only.json"),
        )
        .expect("read scheduler fixture");
        let mut message: BroadcastFeedMessage =
            serde_json::from_str(&fixture).expect("parse scheduler fixture");
        message.sequence_number = 10;
        let (feed_tx, feed_rx) = tokio::sync::mpsc::channel(1);
        let (l1_tx, l1_rx) = tokio::sync::mpsc::channel(1);
        l1_tx.try_send(message).expect("queue L1 input");
        let mut scheduler = IngressScheduler::new(feed_rx, l1_rx);

        let l1 = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            scheduler.next_batch(1_000),
        )
        .await
        .expect("open-empty Feed must not delay L1")
        .unwrap();
        assert_eq!(l1.source, MessageSource::L1);
        scheduler.complete_batch(l1.source, l1.kind);
        assert_eq!(scheduler.owed, MessageSource::Feed);

        let mut feed = l1.messages[0].clone();
        feed.sequence_number = 11;
        feed_tx.try_send(feed).expect("queue Feed input");
        let feed = scheduler.next_batch(1_000).await.unwrap();
        assert_eq!(feed.source, MessageSource::Feed);
        drop((feed_tx, l1_tx));
    }

    #[tokio::test]
    async fn finite_close_discards_queued_tail_despite_retained_sender() {
        let fixture = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/deposit_message_only.json"),
        )
        .expect("read scheduler fixture");
        let mut message: BroadcastFeedMessage =
            serde_json::from_str(&fixture).expect("parse scheduler fixture");
        let (feed_tx, _feed_rx) = tokio::sync::mpsc::channel::<BroadcastFeedMessage>(1);
        let (l1_tx, l1_rx) = tokio::sync::mpsc::channel::<BroadcastFeedMessage>(2);
        let retained_l1_tx = l1_tx.clone();
        drop(feed_tx);
        for sequence_number in [4, 5] {
            message.sequence_number = sequence_number;
            l1_tx.send(message.clone()).await.expect("queue L1 input");
        }
        let mut scheduler = IngressScheduler::l1_only(l1_rx);

        scheduler.close_l1_input(4);

        assert!(
            retained_l1_tx.is_closed(),
            "receiver close rejects retained senders"
        );
        let batch = scheduler
            .next_batch(4)
            .await
            .expect("bounded input remains");
        assert_eq!(
            batch
                .messages
                .iter()
                .map(|message| message.sequence_number)
                .collect::<Vec<_>>(),
            vec![4]
        );
        scheduler.complete_batch(batch.source, batch.kind);
        assert!(
            scheduler.next_batch(5).await.is_none(),
            "queued tail is discarded"
        );
    }

    #[tokio::test]
    async fn finite_admission_rejects_selected_frontier_plus_one_before_close() {
        // Deliberately do not close the receiver: both messages have already been selected when
        // typed completion races this batch. Only the immutable handoff admission can decide the
        // second message, because receiver closure cannot retract a selected batch.
        let mut scheduler = scheduler_with([], [4, 5]);
        let selected = scheduler.next_batch(4).await.expect("select both messages");
        assert_eq!(selected.source, MessageSource::L1);
        assert_eq!(
            selected
                .messages
                .iter()
                .map(|message| message.sequence_number)
                .collect::<Vec<_>>(),
            vec![4, 5],
            "frontier and frontier + 1 are already selected before completion/close"
        );

        let decisions = selected
            .messages
            .iter()
            .map(|message| {
                admit_engine_handoff(
                    ArbLaunchMode::Finite { frontier: 4 },
                    message.sequence_number,
                    0,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("valid finite-domain arithmetic");
        assert_eq!(
            decisions,
            vec![
                EngineHandoffAdmission::Admitted { block_number: 4 },
                EngineHandoffAdmission::RejectedAboveFrontier {
                    block_number: 5,
                    frontier: 4,
                },
            ],
            "frontier + 1 is rejected before an engine handoff"
        );
    }

    #[test]
    fn finite_admission_reports_invalid_u64_domain() {
        assert_eq!(
            admit_engine_handoff(ArbLaunchMode::Finite { frontier: 3 }, 0, 4),
            Err(EngineHandoffAdmissionError::FrontierBelowGenesis {
                frontier: 3,
                genesis_block: 4,
            })
        );
        assert_eq!(
            admit_engine_handoff(ArbLaunchMode::Finite { frontier: u64::MAX }, 1, u64::MAX),
            Err(EngineHandoffAdmissionError::SequenceNumberOverflow {
                sequence_number: 1,
                genesis_block: u64::MAX,
            })
        );
    }

    #[tokio::test]
    async fn one_item_l1_gap_closer_rearbitrates_to_feed() {
        let mut scheduler = scheduler_with([2], [1, 2]);
        let closer = scheduler.next_batch(1).await.unwrap();
        assert_eq!(closer.source, MessageSource::L1);
        assert_eq!(closer.kind, BatchKind::GapCloser);
        assert_eq!(closer.messages.len(), 1);
        scheduler.complete_batch(closer.source, closer.kind);

        let feed = scheduler.next_batch(2).await.unwrap();
        assert_eq!(feed.source, MessageSource::Feed);
        assert_eq!(feed.messages[0].sequence_number, 2);
    }

    #[tokio::test]
    async fn l1_overlap_does_not_suppress_contiguous_feed() {
        let mut scheduler = scheduler_with([5], [4]);
        let selected = scheduler.next_batch(5).await.unwrap();
        assert_eq!(selected.source, MessageSource::Feed);
        assert_eq!(selected.messages[0].sequence_number, 5);
    }

    /// `ArbLauncher` boots over reth's `LaunchContext` with full pruning, then persists two
    /// consecutive batches. The first batch deletes transaction-sender static files; the second
    /// must not recreate them, because the provider factory receives the same prune modes.
    #[tokio::test(flavor = "multi_thread")]
    async fn launcher_full_pruning_persists_successive_batches() {
        run_full_pruning_persistence().await;
    }

    async fn run_full_pruning_persistence() {
        let fixtures_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let json = std::fs::read_to_string(fixtures_dir.join("deposit_message_only.json"))
            .expect("read fixture");
        let feed_msg: BroadcastFeedMessage =
            serde_json::from_str(&json).expect("parse BroadcastFeedMessage");

        let task_executor = Runtime::test();

        let chain_id = 412346u64;
        let init = ArbosInitConfig {
            initial_arbos_version: 40,
            initial_chain_owner: address!("5E1497dD1f08C87b2d8FE23e9AAB6c1De833D927"),
            chain_id: U256::from(chain_id),
            genesis_block_number: 0,
            initial_l1_base_fee: U256::from(167u64),
            serialized_chain_config: include_bytes!(
                "../tests/fixtures/testnode_l2_chain_config.json"
            )
            .to_vec(),
            debug_precompiles: true,
        };
        let chain_spec = Arc::new(crate::arb_chain_spec(&init).expect("build ArbOS chain spec"));

        // The driver dedups by sequence number, so messages must be sequential (a fresh genesis
        // DB has genesis_block 0, so the first digested message is index 1). The queued fifth
        // message and retained sender model a producer that races finite typed completion.
        let (feed_tx, feed_rx) = tokio::sync::mpsc::channel::<BroadcastFeedMessage>(1);
        let (l1_tx, l1_rx) = tokio::sync::mpsc::channel::<BroadcastFeedMessage>(5);
        let retained_l1_tx = l1_tx.clone();
        drop(feed_tx);
        for sequence_number in 1..=5 {
            let mut message = feed_msg.clone();
            message.sequence_number = sequence_number;
            l1_tx.send(message).await.unwrap();
        }

        let mut prune_config = PruningArgs {
            full: true,
            ..Default::default()
        }
        .prune_config(chain_spec.as_ref())
        .expect("--full must resolve to a prune config");
        prune_config.block_interval = 1;
        prune_config.minimum_pruning_distance = 0;

        let datadir = reth_db::test_utils::tempdir_path();
        let db = reth_db::test_utils::create_test_rw_db_with_datadir(&datadir);

        // Build the ChainPath (data_dir) that LaunchContext needs.
        let maybe_path =
            reth_node_core::dirs::MaybePlatformPath::<reth_node_core::dirs::DataDirPath>::from(
                datadir.clone(),
            );
        let config = NodeConfig::test()
            .with_chain(chain_spec.clone())
            .with_datadir_args(reth_node_core::args::DatadirArgs {
                datadir: maybe_path.clone(),
                ..Default::default()
            });
        let data_dir =
            maybe_path.unwrap_or_chain_default(chain_spec.chain(), config.datadir.clone());

        // Persist pruning only in reth.toml. This exercises the same restart path as a datadir
        // whose sender static files were pruned by an earlier run without repeating `--full`.
        let mut reth_config = reth_config::Config::default();
        reth_config.set_prune_config(prune_config);
        reth_config
            .save(&data_dir.config())
            .expect("save test pruning config");

        let node_builder_with_components = NodeBuilder::new(config).with_database(db).node(ArbNode);

        let launcher = ArbLauncher {
            ctx: LaunchContext::new(task_executor.clone(), data_dir),
            chain_id,
            genesis_block: 0,
            tuning: ArbEngineTuning::reth_defaults(),
            mode: ArbLaunchMode::Finite { frontier: 4 },
            feed_messages: feed_rx,
            l1_messages: l1_rx,
            feed_latency: None,
            tx_log_stream: None,
        };

        let handle = launcher
            .launch_node(node_builder_with_components)
            .await
            .expect("launch must succeed");

        assert!(
            handle.rpc_handle.is_none(),
            "finite launcher must not create RPC handles"
        );
        let provider = handle.provider.clone();
        let durable = handle
            .finish_finite_l1_execution(async {
                Ok(arb_reth_sync::L1SyncCompletion::FrontierReached { frontier: 4 })
            })
            .await
            .expect("finite driver must flush the exact frontier");
        assert_eq!(durable.number, 4);
        assert!(
            retained_l1_tx.is_closed(),
            "typed completion must close the finite receiver despite retained producers"
        );

        // The launcher opens the DB in storage v2; confirm the flag is persisted.
        {
            use reth_provider::DatabaseProviderFactory;
            use reth_storage_api::MetadataProvider;
            let p = provider.database_provider_ro().expect("ro provider");
            assert_eq!(
                p.storage_settings().expect("storage_settings"),
                Some(reth_db_api::models::StorageSettings::v2()),
                "launcher DB must be storage v2"
            );
        }

        assert_eq!(
            provider.best_block_number().unwrap(),
            4,
            "best block must be 4"
        );
        assert!(
            provider.header_by_number(1).unwrap().is_some(),
            "block 1 must exist"
        );
        assert!(
            provider.header_by_number(4).unwrap().is_some(),
            "block 4 must exist"
        );

        let deposit_to = address!("3f1eae7d46d88f08fc2f8ed27fcb2ab183eb2d0e");
        let single_deposit = U256::from(111_000_000_000_000_000u128);
        let state = provider.latest().expect("latest state must open");
        let acct = state
            .basic_account(&deposit_to)
            .expect("account lookup")
            .expect("deposit recipient must exist");
        assert_eq!(
            acct.balance,
            single_deposit * U256::from(4),
            "cumulative balance must be 4× single deposit"
        );
    }

    /// Drives the production parent-state provider path as fast as the local CPU can execute it.
    ///
    /// This is intentionally ignored in normal CI. It feeds sequential deposits directly into the
    /// real launcher, so every block performs ArbOS execution, engine-tree canonicalization, and
    /// async Storage V2 persistence. The deep persistence window is deliberate: it creates the
    /// maximum opportunity for `state_by_block_hash` to observe a persistence handoff.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "manual persistence stress test; run with ARB_RACE_BLOCKS=<n>"]
    async fn deep_buffer_persistence_stress() {
        let blocks = std::env::var("ARB_RACE_BLOCKS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|&value| value > 0)
            .unwrap_or(10_000);
        let fixtures_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let json = std::fs::read_to_string(fixtures_dir.join("deposit_message_only.json"))
            .expect("read fixture");
        let feed_msg: BroadcastFeedMessage =
            serde_json::from_str(&json).expect("parse BroadcastFeedMessage");
        let deposit_to = address!("3f1eae7d46d88f08fc2f8ed27fcb2ab183eb2d0e");
        let single_deposit = U256::from(111_000_000_000_000_000u128);

        let task_executor = Runtime::test();
        let (tx, feed_rx) = tokio::sync::mpsc::channel::<BroadcastFeedMessage>(4096);
        let (l1_tx, l1_rx) = tokio::sync::mpsc::channel::<BroadcastFeedMessage>(1);
        drop(l1_tx);
        let datadir = reth_db::test_utils::tempdir_path();
        let db = reth_db::test_utils::create_test_rw_db_with_datadir(&datadir);
        let maybe_path =
            reth_node_core::dirs::MaybePlatformPath::<reth_node_core::dirs::DataDirPath>::from(
                datadir.clone(),
            );
        let config = NodeConfig::test()
            .with_chain(MAINNET.clone())
            .with_datadir_args(reth_node_core::args::DatadirArgs {
                datadir: maybe_path.clone(),
                ..Default::default()
            });
        let data_dir = maybe_path.unwrap_or_chain_default(MAINNET.chain(), config.datadir.clone());
        let node_builder_with_components = NodeBuilder::new(config).with_database(db).node(ArbNode);
        let launcher = ArbLauncher {
            ctx: LaunchContext::new(task_executor, data_dir),
            chain_id: crate::ARB_ONE_CHAIN_ID,
            genesis_block: 0,
            tuning: ArbEngineTuning::from_tree_config(
                reth_engine_primitives::TreeConfig::default()
                    .with_persistence_backpressure_threshold(512)
                    .with_persistence_threshold(128)
                    .with_memory_block_buffer_target(0)
                    .with_cross_block_cache_size(256 * 1024 * 1024)
                    .with_share_execution_cache_with_payload_builder(true)
                    .with_share_sparse_trie_with_payload_builder(false),
            ),
            mode: ArbLaunchMode::Ordinary,
            feed_messages: feed_rx,
            l1_messages: l1_rx,
            feed_latency: None,
            tx_log_stream: None,
        };
        let handle = launcher
            .launch_node(node_builder_with_components)
            .await
            .expect("launch must succeed");
        let provider = handle.provider.clone();

        let started = std::time::Instant::now();
        for sequence_number in 1..=blocks {
            let mut message = feed_msg.clone();
            message.sequence_number = sequence_number;
            tx.send(message)
                .await
                .expect("driver must accept the next message");
        }
        drop(tx);
        handle
            .wait_for_node_exit()
            .await
            .expect("driver task must complete without a state-provider error");

        let elapsed = started.elapsed();
        assert_eq!(provider.best_block_number().expect("best block"), blocks);
        // The driver exits when the input channel closes, while the engine tree intentionally
        // owns persistence independently. Validate the canonical provider state here; a graceful
        // node shutdown is responsible for flushing a remaining sub-threshold tail to MDBX.
        let state = provider.latest().expect("latest state must open");
        let account = state
            .basic_account(&deposit_to)
            .expect("account lookup")
            .expect("deposit recipient must exist");
        assert_eq!(account.balance, single_deposit * U256::from(blocks));
        eprintln!(
            "deep-buffer stress: blocks={blocks} elapsed={elapsed:?} blocks_per_second={:.1}",
            blocks as f64 / elapsed.as_secs_f64()
        );
    }
}
