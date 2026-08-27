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
use std::net::SocketAddr;

use crate::{
    metrics::{FeedLatencyTracker, IngressMetrics},
    recovery::{RecoveryGate, RecoveryRuntime},
};
use alloy_consensus::Header;
use arbitrum_alloy_consensus::reth::ArbPrimitives;
use arbitrum_alloy_sequencer::sequencer::feed::BroadcastFeedMessage;
use eyre::{WrapErr as _, ensure, eyre};
use reth_chain_state::CanonicalInMemoryState;
use reth_db::{Database, database_metrics::DatabaseMetrics};
use reth_evm::ConfigureEvm;
use reth_node_api::{AddOnsContext, FullNodeTypes, NodeAddOns, NodeTypes, NodeTypesWithDBAdapter};
use reth_node_builder::hooks::NodeHooks;
use reth_node_builder::{
    AddOns, LaunchContext, LaunchNode, Node, NodeBuilderWithComponents, NodeComponents,
    NodeComponentsBuilder, NodeTypesAdapter, RethFullAdapter,
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

#[cfg(test)]
use arb_reth_engine::ArbEngineLifecycleProbe;
use arb_reth_engine::{
    ArbEngineDriver, ArbEngineInput, ArbEngineInputSource, ArbEngineTuning, ArbTxLogBroadcaster,
};

const MAX_MESSAGE_BATCH: usize = 64;

#[cfg(test)]
#[derive(Default)]
struct DriverTestObservations {
    selected_batches: std::sync::atomic::AtomicU64,
    completed_batches: std::sync::atomic::AtomicU64,
    selected_l1_batches: std::sync::atomic::AtomicU64,
    engine_reconciliation_calls: std::sync::atomic::AtomicU64,
    benchmark_executed: std::sync::atomic::AtomicU64,
    sampler_stops: std::sync::atomic::AtomicU64,
}

#[cfg(test)]
pub(crate) struct DriverTestControl {
    pause_after_input_sequence: Option<u64>,
    input_paused: tokio::sync::Notify,
    resume_input: tokio::sync::Notify,
    selected_batch_pauses: std::sync::atomic::AtomicU64,
    selected_batch_paused: tokio::sync::Notify,
    resume_selected_batch: tokio::sync::Notify,
    wait_for_head_pauses: std::sync::atomic::AtomicU64,
    wait_for_head_paused: tokio::sync::Notify,
    resume_wait_for_head: tokio::sync::Notify,
    closure_pauses: std::sync::atomic::AtomicU64,
    closure_paused: tokio::sync::Notify,
    resume_closure: tokio::sync::Notify,
    pause_terminal: bool,
    terminal_paused: tokio::sync::Notify,
    resume_terminal: tokio::sync::Notify,
    completion_pauses: std::sync::atomic::AtomicU64,
    completion_paused: tokio::sync::Notify,
    resume_completion: tokio::sync::Notify,
    pause_sampler_start: bool,
    sampler_start_paused: tokio::sync::Notify,
    resume_sampler_start: tokio::sync::Notify,
    sampler_capture_pauses: std::sync::atomic::AtomicU64,
    sampler_capture_paused: tokio::sync::Notify,
    resume_sampler_capture: tokio::sync::Notify,
    sampler_published: tokio::sync::Notify,
    post_batch_frontier_pauses: std::sync::atomic::AtomicU64,
    post_batch_frontier_paused: tokio::sync::Notify,
    resume_post_batch_frontier: tokio::sync::Notify,
    durable_samples: std::sync::Mutex<std::collections::VecDeque<Result<u64, &'static str>>>,
    durable_sampled: tokio::sync::Notify,
}

#[cfg(test)]
impl DriverTestControl {
    fn new() -> Self {
        Self {
            pause_after_input_sequence: None,
            input_paused: tokio::sync::Notify::new(),
            resume_input: tokio::sync::Notify::new(),
            selected_batch_pauses: std::sync::atomic::AtomicU64::new(0),
            selected_batch_paused: tokio::sync::Notify::new(),
            resume_selected_batch: tokio::sync::Notify::new(),
            wait_for_head_pauses: std::sync::atomic::AtomicU64::new(0),
            wait_for_head_paused: tokio::sync::Notify::new(),
            resume_wait_for_head: tokio::sync::Notify::new(),
            closure_pauses: std::sync::atomic::AtomicU64::new(0),
            closure_paused: tokio::sync::Notify::new(),
            resume_closure: tokio::sync::Notify::new(),
            pause_terminal: false,
            terminal_paused: tokio::sync::Notify::new(),
            resume_terminal: tokio::sync::Notify::new(),
            completion_pauses: std::sync::atomic::AtomicU64::new(0),
            completion_paused: tokio::sync::Notify::new(),
            resume_completion: tokio::sync::Notify::new(),
            pause_sampler_start: false,
            sampler_start_paused: tokio::sync::Notify::new(),
            resume_sampler_start: tokio::sync::Notify::new(),
            sampler_capture_pauses: std::sync::atomic::AtomicU64::new(0),
            sampler_capture_paused: tokio::sync::Notify::new(),
            resume_sampler_capture: tokio::sync::Notify::new(),
            sampler_published: tokio::sync::Notify::new(),
            post_batch_frontier_pauses: std::sync::atomic::AtomicU64::new(0),
            post_batch_frontier_paused: tokio::sync::Notify::new(),
            resume_post_batch_frontier: tokio::sync::Notify::new(),
            durable_samples: std::sync::Mutex::new(std::collections::VecDeque::new()),
            durable_sampled: tokio::sync::Notify::new(),
        }
    }

    fn pause_after_input(sequence: u64) -> Self {
        let mut control = Self::new();
        control.pause_after_input_sequence = Some(sequence);
        control
    }

    fn pause_for_dynamic_metrics(sequence: u64) -> Self {
        let control = Self::pause_after_input(sequence);
        control
            .selected_batch_pauses
            .store(2, std::sync::atomic::Ordering::Relaxed);
        control
            .closure_pauses
            .store(1, std::sync::atomic::Ordering::Relaxed);
        control
    }

    fn pause_after_input_and_completion(sequence: u64, pause_terminal: bool) -> Self {
        let mut control = Self::pause_after_input(sequence);
        control
            .completion_pauses
            .store(1, std::sync::atomic::Ordering::Relaxed);
        control.pause_terminal = pause_terminal;
        control
    }

    fn with_durable_samples(samples: impl IntoIterator<Item = Result<u64, &'static str>>) -> Self {
        let control = Self::new();
        control
            .durable_samples
            .lock()
            .expect("durable sample lock poisoned")
            .extend(samples);
        control
    }

    fn pause_sampler_at_start() -> Self {
        let mut control = Self::new();
        control.pause_sampler_start = true;
        control
    }

    fn pause_sampler_after_capture_and_input(sequence: u64) -> Self {
        let control = Self::pause_after_input(sequence);
        control
            .sampler_capture_pauses
            .store(1, std::sync::atomic::Ordering::Relaxed);
        control
    }

    fn pause_next_sampler_capture(&self) {
        self.sampler_capture_pauses
            .store(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn pause_next_post_batch_frontier(&self) {
        self.post_batch_frontier_pauses
            .store(1, std::sync::atomic::Ordering::Relaxed);
    }

    async fn pause_if_requested(&self, sequence: u64) {
        if self.pause_after_input_sequence == Some(sequence) {
            self.input_paused.notify_one();
            self.resume_input.notified().await;
        }
    }

    async fn pause_selected_batch_if_requested(&self) {
        if self
            .selected_batch_pauses
            .fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |remaining| remaining.checked_sub(1),
            )
            .is_ok()
        {
            self.selected_batch_paused.notify_one();
            self.resume_selected_batch.notified().await;
        }
    }

    fn pause_next_selected_batch(&self) {
        self.selected_batch_pauses
            .store(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn pause_next_wait_for_head(&self) {
        self.wait_for_head_pauses
            .store(1, std::sync::atomic::Ordering::Relaxed);
    }

    async fn pause_before_wait_for_head_if_requested(&self) {
        if self
            .wait_for_head_pauses
            .fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |remaining| remaining.checked_sub(1),
            )
            .is_ok()
        {
            self.wait_for_head_paused.notify_one();
            self.resume_wait_for_head.notified().await;
        }
    }

    async fn pause_closure_if_requested(&self) {
        if self
            .closure_pauses
            .fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |remaining| remaining.checked_sub(1),
            )
            .is_ok()
        {
            self.closure_paused.notify_one();
            self.resume_closure.notified().await;
        }
    }

    async fn pause_before_terminal_lifecycle(&self) {
        if self.pause_terminal {
            self.terminal_paused.notify_one();
            self.resume_terminal.notified().await;
        }
    }

    async fn pause_after_batch_completion(&self) {
        if self
            .completion_pauses
            .fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |remaining| remaining.checked_sub(1),
            )
            .is_ok()
        {
            self.completion_paused.notify_one();
            self.resume_completion.notified().await;
        }
    }

    async fn pause_before_sampler_start(&self) {
        if self.pause_sampler_start {
            self.sampler_start_paused.notify_one();
            self.resume_sampler_start.notified().await;
        }
    }

    async fn pause_after_sampler_capture(&self) {
        if self
            .sampler_capture_pauses
            .fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |remaining| remaining.checked_sub(1),
            )
            .is_ok()
        {
            self.sampler_capture_paused.notify_one();
            self.resume_sampler_capture.notified().await;
        }
    }

    async fn pause_after_post_batch_frontier(&self) {
        if self
            .post_batch_frontier_pauses
            .fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |remaining| remaining.checked_sub(1),
            )
            .is_ok()
        {
            self.post_batch_frontier_paused.notify_one();
            self.resume_post_batch_frontier.notified().await;
        }
    }

    fn next_durable_sample(&self) -> Option<Result<u64, &'static str>> {
        let sample = self
            .durable_samples
            .lock()
            .expect("durable sample lock poisoned")
            .pop_front();
        if sample.is_some() {
            self.durable_sampled.notify_one();
        }
        sample
    }
}

#[cfg(test)]
struct SchedulerReceivePause {
    head_received: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}

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
    /// Source-independent ingress metrics shared with live-feed followers.
    pub(crate) ingress_metrics: IngressMetrics,
    #[cfg(test)]
    driver_test_observations: std::sync::Arc<DriverTestObservations>,
    #[cfg(test)]
    engine_lifecycle_probe: ArbEngineLifecycleProbe,
}

impl<P> ArbNodeHandle<P> {
    /// Wait for the driver task to exit, returning its result.
    pub async fn wait_for_node_exit(self) -> eyre::Result<()> {
        self.exit_rx.await?
    }

    /// Returns the HTTP URL of the running RPC server, or `None` if RPC was not enabled.
    pub fn http_url(&self) -> Option<String> {
        self.rpc_handle.as_ref()?.http_url()
    }
}

/// A custom `LaunchNode` for the no-engine Arbitrum node.
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
    /// Optional history-pruning configuration from `--prune.*` / `--full`. `None` keeps the node
    /// an archive node. A configured mode is applied to both the provider factory and the
    /// engine-tree persistence pruner so static-file writes follow the same segment policy.
    pub prune_config: Option<reth_config::PruneConfig>,
    /// One-shot operator acknowledgement that a pre-journal durable tip is a trusted anchor.
    pub init_message_journal_at_tip: bool,
    /// Highest block whose L1 authority is durable in the message journal.
    pub l1_verified_tip: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Live-feed and replay messages. These may be ahead of the local canonical cursor when the
    /// relay's bounded backlog begins after the database tip.
    pub feed_messages: tokio::sync::mpsc::Receiver<ArbEngineInput>,
    /// Authoritative L1-derived messages. These are kept separate from the live feed so a large
    /// feed-ahead backlog cannot delay the message that closes a derivation gap.
    pub l1_messages: tokio::sync::mpsc::Receiver<BroadcastFeedMessage>,
    /// Correlates live WebSocket feed messages with canonical in-memory state for Prometheus.
    /// `None` keeps replay and L1-only operation free of feed-latency instrumentation.
    pub feed_latency: Option<FeedLatencyTracker>,
    /// Optional HTTP bind address for the `eth_*` RPC server (`None` disables RPC).
    pub rpc_addr: Option<SocketAddr>,
    /// Optional best-effort publisher for per-transaction execution logs.
    pub tx_log_stream: Option<ArbTxLogBroadcaster>,
    /// Shared production readiness gate for sources and externally visible services.
    #[doc(hidden)]
    pub recovery_gate: RecoveryGate,
    /// Frozen recovery transaction, present only while authoritative L1 rederivation is required.
    #[doc(hidden)]
    pub recovery: Option<RecoveryRuntime>,
    #[cfg(test)]
    pub(crate) driver_test_control: Option<std::sync::Arc<DriverTestControl>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BatchKind {
    Ordinary,
    GapCloser,
}

struct SelectedBatch {
    source: ArbEngineInputSource,
    inputs: Vec<ArbEngineInput>,
    kind: BatchKind,
}

enum DriverAction<G> {
    Shutdown(G),
    Batch(Option<SelectedBatch>),
}

/// Deterministic, work-conserving bounded-fair arbitration over the two bounded driver channels.
struct IngressScheduler {
    feed_messages: tokio::sync::mpsc::Receiver<ArbEngineInput>,
    l1_messages: tokio::sync::mpsc::Receiver<BroadcastFeedMessage>,
    feed_pending: Option<ArbEngineInput>,
    l1_pending: Option<ArbEngineInput>,
    feed_open: bool,
    l1_open: bool,
    owed: ArbEngineInputSource,
    metrics: IngressMetrics,
    feed_latency: Option<FeedLatencyTracker>,
    #[cfg(test)]
    receive_pause: Option<std::sync::Arc<SchedulerReceivePause>>,
    #[cfg(test)]
    test_control: Option<std::sync::Arc<DriverTestControl>>,
}

impl IngressScheduler {
    fn new(
        feed_messages: tokio::sync::mpsc::Receiver<ArbEngineInput>,
        l1_messages: tokio::sync::mpsc::Receiver<BroadcastFeedMessage>,
        metrics: IngressMetrics,
        feed_latency: Option<FeedLatencyTracker>,
    ) -> Self {
        let scheduler = Self {
            feed_messages,
            l1_messages,
            feed_pending: None,
            l1_pending: None,
            feed_open: true,
            l1_open: true,
            owed: ArbEngineInputSource::Feed,
            metrics,
            feed_latency,
            #[cfg(test)]
            receive_pause: None,
            #[cfg(test)]
            test_control: None,
        };
        scheduler.publish_queue_depths();
        scheduler
    }

    fn publish_queue_depths(&self) {
        self.metrics.set_queue_depths(
            self.feed_messages.len() + usize::from(self.feed_pending.is_some()),
            self.l1_messages.len() + usize::from(self.l1_pending.is_some()),
        );
    }

    fn record_dequeue(&self, input: &ArbEngineInput) {
        match input.source() {
            ArbEngineInputSource::Feed => {
                self.metrics.record_feed_dequeues(1);
                if let Some(feed_latency) = self.feed_latency.as_ref() {
                    feed_latency
                        .record_driver_dequeue(input.sequence_number(), std::time::Instant::now());
                }
            }
            ArbEngineInputSource::L1 => self.metrics.record_l1_dequeues(1),
        }
    }

    fn try_fill_feed(&mut self) -> bool {
        if !self.feed_open || self.feed_pending.is_some() {
            return false;
        }
        match self.feed_messages.try_recv() {
            Ok(input) => {
                self.record_dequeue(&input);
                self.feed_pending = Some(input);
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                self.feed_open = false;
                self.publish_queue_depths();
                return true;
            }
        }
        false
    }

    fn try_fill_l1(&mut self) -> bool {
        if !self.l1_open || self.l1_pending.is_some() {
            return false;
        }
        match self.l1_messages.try_recv() {
            Ok(message) => {
                let input = ArbEngineInput::l1(message);
                self.record_dequeue(&input);
                self.l1_pending = Some(input);
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                self.l1_open = false;
                self.publish_queue_depths();
                return true;
            }
        }
        false
    }

    fn try_fill_heads(&mut self) -> bool {
        let feed_closed = self.try_fill_feed();
        let l1_closed = self.try_fill_l1();
        feed_closed || l1_closed
    }

    async fn wait_for_head(&mut self) {
        #[cfg(test)]
        if let Some(control) = self.test_control.as_ref() {
            control.pause_before_wait_for_head_if_requested().await;
        }
        let received = match self.owed {
            ArbEngineInputSource::Feed => {
                tokio::select! {
                    biased;
                    message = self.feed_messages.recv(), if self.feed_open => {
                        (ArbEngineInputSource::Feed, message)
                    }
                    message = self.l1_messages.recv(), if self.l1_open => {
                        (ArbEngineInputSource::L1, message.map(ArbEngineInput::l1))
                    }
                }
            }
            ArbEngineInputSource::L1 => {
                tokio::select! {
                    biased;
                    message = self.l1_messages.recv(), if self.l1_open => {
                        (ArbEngineInputSource::L1, message.map(ArbEngineInput::l1))
                    }
                    message = self.feed_messages.recv(), if self.feed_open => {
                        (ArbEngineInputSource::Feed, message)
                    }
                }
            }
        };
        let _observed_closure = match received {
            (ArbEngineInputSource::Feed, Some(input)) => {
                self.record_dequeue(&input);
                self.feed_pending = Some(input);
                false
            }
            (ArbEngineInputSource::L1, Some(input)) => {
                self.record_dequeue(&input);
                self.l1_pending = Some(input);
                false
            }
            (ArbEngineInputSource::Feed, None) => {
                self.feed_open = false;
                self.publish_queue_depths();
                true
            }
            (ArbEngineInputSource::L1, None) => {
                self.l1_open = false;
                self.publish_queue_depths();
                true
            }
        };
        #[cfg(test)]
        if _observed_closure && let Some(control) = self.test_control.as_ref() {
            control.pause_closure_if_requested().await;
        }
        #[cfg(test)]
        if (self.feed_pending.is_some() || self.l1_pending.is_some())
            && let Some(pause) = self.receive_pause.as_ref()
        {
            pause.head_received.notify_one();
            pause.resume.notified().await;
        }
    }

    async fn next_batch(&mut self, next_sequence: u64) -> Option<SelectedBatch> {
        loop {
            let _observed_closure = self.try_fill_heads();
            #[cfg(test)]
            if _observed_closure && let Some(control) = self.test_control.as_ref() {
                control.pause_closure_if_requested().await;
            }
            if self.feed_pending.is_none() && self.l1_pending.is_none() {
                if !self.feed_open && !self.l1_open {
                    self.publish_queue_depths();
                    return None;
                }
                self.wait_for_head().await;
                continue;
            }

            let gap_closer = matches!(
                (&self.feed_pending, &self.l1_pending),
                (Some(feed), Some(l1))
                    if l1.sequence_number() == next_sequence
                        && feed.sequence_number() > next_sequence
            );
            let source = if gap_closer {
                ArbEngineInputSource::L1
            } else {
                match (self.feed_pending.is_some(), self.l1_pending.is_some()) {
                    (true, true) => self.owed,
                    (true, false) => ArbEngineInputSource::Feed,
                    (false, true) => ArbEngineInputSource::L1,
                    (false, false) => unreachable!(),
                }
            };
            let kind = if gap_closer {
                BatchKind::GapCloser
            } else {
                BatchKind::Ordinary
            };
            let first = match source {
                ArbEngineInputSource::Feed => self.feed_pending.take().unwrap(),
                ArbEngineInputSource::L1 => self.l1_pending.take().unwrap(),
            };
            let mut inputs = Vec::with_capacity(MAX_MESSAGE_BATCH);
            inputs.push(first);

            if kind == BatchKind::Ordinary {
                while inputs.len() < MAX_MESSAGE_BATCH {
                    let next = match source {
                        ArbEngineInputSource::Feed => self.feed_messages.try_recv(),
                        ArbEngineInputSource::L1 => {
                            self.l1_messages.try_recv().map(ArbEngineInput::l1)
                        }
                    };
                    match next {
                        Ok(input) => {
                            self.record_dequeue(&input);
                            inputs.push(input);
                        }
                        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                            match source {
                                ArbEngineInputSource::Feed => self.feed_open = false,
                                ArbEngineInputSource::L1 => self.l1_open = false,
                            }
                            self.publish_queue_depths();
                            break;
                        }
                    }
                }
            }
            self.publish_queue_depths();
            return Some(SelectedBatch {
                source,
                inputs,
                kind,
            });
        }
    }

    fn complete_batch(&mut self, source: ArbEngineInputSource, kind: BatchKind) {
        match kind {
            BatchKind::GapCloser => self.owed = ArbEngineInputSource::Feed,
            BatchKind::Ordinary if source == self.owed => {
                self.owed = match source {
                    ArbEngineInputSource::Feed => ArbEngineInputSource::L1,
                    ArbEngineInputSource::L1 => ArbEngineInputSource::Feed,
                };
            }
            BatchKind::Ordinary => {}
        }
        self.publish_queue_depths();
    }
}

async fn next_driver_action<F>(
    shutdown: Pin<&mut F>,
    scheduler: &mut IngressScheduler,
    next_sequence: u64,
) -> DriverAction<F::Output>
where
    F: Future + ?Sized,
{
    tokio::select! {
        biased;
        guard = shutdown => DriverAction::Shutdown(guard),
        batch = scheduler.next_batch(next_sequence) => DriverAction::Batch(batch),
    }
}

fn record_applied_executed_tip(metrics: &IngressMetrics, genesis_block: u64, sequence: u64) {
    // `ArbEngineDriver::record_applied_message` checked this same canonical mapping before an
    // applied callback can fire. Keep metrics observational if that invariant ever changes.
    if let Some(block_number) = genesis_block.checked_add(sequence) {
        metrics.set_executed_tip(block_number);
    }
}

async fn run_frontier_sampler<E, R>(
    metrics: IngressMetrics,
    verified_tip: std::sync::Arc<std::sync::atomic::AtomicU64>,
    initial_durable_tip: u64,
    cancel: oneshot::Receiver<()>,
    mut read_durable_tip: R,
    #[cfg(test)] test_control: Option<std::sync::Arc<DriverTestControl>>,
) where
    E: std::fmt::Display,
    R: FnMut() -> Result<u64, E>,
{
    let mut cancel = Box::pin(cancel);
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Consume Tokio's immediate first tick: startup was sampled synchronously by the launcher.
    interval.tick().await;
    #[cfg(test)]
    if let Some(control) = test_control.as_ref() {
        control.pause_before_sampler_start().await;
    }
    let mut durable_tip = initial_durable_tip;
    let mut consecutive_read_failures = 0u64;
    loop {
        tokio::select! {
            biased;
            _ = &mut cancel => break,
            _ = interval.tick() => {
                let durable_read = read_durable_tip();
                let verified = verified_tip.load(std::sync::atomic::Ordering::Acquire);
                let captured_executed = metrics.executed_tip();
                #[cfg(test)]
                if let Some(control) = test_control.as_ref() {
                    control.pause_after_sampler_capture().await;
                }
                match metrics.refresh_frontiers(
                    &mut durable_tip,
                    durable_read,
                    verified,
                    captured_executed,
                ) {
                    Ok(()) => {
                        consecutive_read_failures = 0;
                    }
                    Err(error) => {
                        consecutive_read_failures = consecutive_read_failures.saturating_add(1);
                        if consecutive_read_failures == 1 || consecutive_read_failures % 60 == 0 {
                            tracing::warn!(
                                target: "arb-reth::metrics",
                                %error,
                                consecutive_read_failures,
                                "failed to sample durable ingress tip; retaining previous sample",
                            );
                        }
                    }
                }
                #[cfg(test)]
                if let Some(control) = test_control.as_ref() {
                    control.sampler_published.notify_one();
                }
            }
        }
    }
}

impl<N, DB, T, CB> LaunchNode<NodeBuilderWithComponents<T, CB, ()>> for ArbLauncher
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

    fn launch_node(self, target: NodeBuilderWithComponents<T, CB, ()>) -> Self::Future {
        Box::pin(self.launch_impl(target))
    }
}

impl ArbLauncher {
    /// Core async launch body. Separated from `launch_node` so it can be `async fn`
    /// (the trait requires a boxed future; `launch_node` boxes it).
    async fn launch_impl<N, DB, T, CB>(
        self,
        target: NodeBuilderWithComponents<T, CB, ()>,
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
            prune_config,
            init_message_journal_at_tip,
            l1_verified_tip,
            feed_messages,
            l1_messages,
            feed_latency,
            rpc_addr,
            tx_log_stream,
            recovery_gate,
            recovery,
            #[cfg(test)]
            driver_test_control,
        } = self;

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

        // Drive RPC config from the explicit `rpc_addr`: canonical `RpcAddOns` reads addresses from
        // `NodeConfig.rpc`, not an arg. Enable http+ws with the full module fleet; this node is
        // self-driven from L1 derivation, so the auth/engine server is disabled.
        let mut config = config;
        if let Some(addr) = rpc_addr {
            config.rpc.http = true;
            config.rpc.http_addr = addr.ip();
            config.rpc.http_port = addr.port();
            config.rpc.http_api = Some(reth_rpc_server_types::RpcModuleSelection::All);
            config.rpc.ws = true;
            config.rpc.ws_addr = addr.ip();
            config.rpc.ws_port = addr.port();
            config.rpc.ws_api = Some(reth_rpc_server_types::RpcModuleSelection::All);
            config.rpc.disable_auth_server = true;
        }

        let overlay_manager = OverlayManager::<ArbPrimitives>::new(
            ctx.task_executor.state_trie_overlay_worker_pool(),
        );
        let disabled_stages = N::disabled_stages();

        let ctx = ctx
            .with_configured_globals(0)
            .with_loaded_toml_config(config)?
            .attach(database.clone())
            .with_adjusted_configs()
            .with_provider_factory::<NodeTypesWithDBAdapter<N, DB>, <CB::Components as NodeComponents<T>>::Evm>(
                overlay_manager.clone(),
                rocksdb_provider,
                disabled_stages,
            )
            .await?;

        // Install reth's Prometheus recorder before any feed metric handles are initialized, and
        // serve it when `--metrics <addr>` is configured.
        let ctx = ctx.with_prometheus_server().await?;
        recovery_gate.register_metric();
        let ingress_metrics = IngressMetrics::new();

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

        let ctx = ctx
            .with_genesis()?
            .with_metrics_task()
            .with_blockchain_db::<T, _>(move |provider_factory| {
                Ok(BlockchainProvider::new(provider_factory)?)
            })?
            .with_components(components_builder, on_component_initialized)
            .await?;

        let provider: BlockchainProvider<NodeTypesWithDBAdapter<N, DB>> =
            ctx.node_adapter().provider.clone();
        // Reth's provider factory consults `PruneModes` while it writes static-file segments. In
        // particular, full sender recovery pruning stops new TransactionSenders writes. Feeding
        // the configuration only to `PrunerBuilder` would let the writer append to a segment the
        // pruner deletes, breaking its contiguous-block invariant on the next persistence batch.
        let provider_factory: ProviderFactory<NodeTypesWithDBAdapter<N, DB>> =
            ctx.provider_factory().clone().with_prune_modes(
                prune_config
                    .as_ref()
                    .map(|config| config.segments.clone())
                    .unwrap_or_default(),
            );
        let task_executor: TaskExecutor = ctx.task_executor().clone();
        let head = ctx.head();

        // Clone the in-memory state from the provider so the tree updates the same instance that
        // BlockchainProvider serves for RPC queries.
        let canonical: CanonicalInMemoryState<ArbPrimitives> = provider.canonical_in_memory_state();

        let genesis_tip: SealedHeader<Header> =
            HeaderProvider::sealed_header(&provider, head.number)?
                .ok_or_else(|| eyre!("missing head header at block {}", head.number))?;

        // `arb_evm_config` (hoisted from the RPC block below): also drives the engine tree.
        let arb_evm_config: arb_reth_evm::ArbEvmConfig =
            ctx.node_adapter().components.evm_config().clone();
        let frontier_store = tx_log_stream
            .as_ref()
            .map(ArbTxLogBroadcaster::frontier_store);

        // Stand up reth's engine tree (Tier-1 `InsertExecutedBlock` seam) and drive the
        // sequencer feed through it. Persistence to MDBX is async (tree background service).
        let driver: ArbEngineDriver<NodeTypesWithDBAdapter<N, DB>> = ArbEngineDriver::spawn(
            provider_factory,
            provider.clone(),
            arb_evm_config.clone(),
            chain_id,
            genesis_tip,
            genesis_block,
            canonical,
            task_executor.clone(),
            tuning,
            prune_config.map(reth_prune::PrunerBuilder::new),
            init_message_journal_at_tip,
            l1_verified_tip.clone(),
            tx_log_stream,
        )?;
        #[cfg(test)]
        let engine_lifecycle_probe = driver.lifecycle_probe();
        let mut driver = Some(driver);

        let initial_executed_tip = driver.as_ref().expect("driver initialized").tip().number;
        let initial_durable_tip = provider.last_block_number()?;
        let initial_verified_tip = l1_verified_tip.load(std::sync::atomic::Ordering::Acquire);
        ingress_metrics.initialize_frontiers(
            initial_executed_tip,
            initial_durable_tip,
            initial_verified_tip,
        );

        let (sampler_cancel_tx, sampler_cancel_rx) = oneshot::channel::<()>();
        let (sampler_done_tx, sampler_done_rx) = oneshot::channel::<()>();
        let sampler_provider = provider.clone();
        let sampler_metrics = ingress_metrics.clone();
        let sampler_verified_tip = l1_verified_tip.clone();
        #[cfg(test)]
        let sampler_test_control = driver_test_control.clone();
        #[cfg(test)]
        let sampler_read_test_control = sampler_test_control.clone();
        task_executor.spawn_task(async move {
            run_frontier_sampler(
                sampler_metrics,
                sampler_verified_tip,
                initial_durable_tip,
                sampler_cancel_rx,
                || {
                    #[cfg(test)]
                    if let Some(sample) = sampler_read_test_control
                        .as_ref()
                        .and_then(|control| control.next_durable_sample())
                    {
                        return sample.map_err(|error| eyre!(error));
                    }
                    sampler_provider
                        .last_block_number()
                        .map_err(|error| eyre!(error.to_string()))
                },
                #[cfg(test)]
                sampler_test_control,
            )
            .await;
            let _ = sampler_done_tx.send(());
        });

        let (exit_tx, exit_rx) = oneshot::channel::<eyre::Result<()>>();
        let mut scheduler = IngressScheduler::new(
            feed_messages,
            l1_messages,
            ingress_metrics.clone(),
            feed_latency.clone(),
        );
        #[cfg(test)]
        {
            scheduler.test_control = driver_test_control.clone();
        }
        let driver_metrics = ingress_metrics.clone();
        #[cfg(test)]
        let driver_test_observations = std::sync::Arc::new(DriverTestObservations::default());
        #[cfg(test)]
        let task_test_observations = driver_test_observations.clone();

        #[cfg(test)]
        let lifecycle_observations = driver_test_observations.clone();
        task_executor.spawn_critical_with_graceful_shutdown_signal(
            "arb-engine-driver",
            |shutdown| async move {
            let mut shutdown = Box::pin(shutdown);
            let mut shutdown_guard = None;
            let recovery = recovery;
            let res: eyre::Result<()> = async {
                // Bench accounting: separate time spent WAITING for the next derived feed
                // message (L1-fetch-bound) from time spent in advance() (compute/persist-bound).
                // Emitted every 1000 blocks at target "arb-reth::bench"; harmless at info off.
                let mut bench_recv_us: u128 = 0;
                let mut bench_work_us: u128 = 0;
                let mut bench_n: u64 = 0;
                let mut bench_wall = std::time::Instant::now();
                loop {
                    let __r = std::time::Instant::now();
                    let selected = match next_driver_action(
                        shutdown.as_mut(),
                        &mut scheduler,
                        driver
                            .as_ref()
                            .expect("driver exists while selecting work")
                            .next_sequence(),
                    )
                    .await
                    {
                        DriverAction::Shutdown(guard) => {
                            shutdown_guard = Some(guard);
                            None
                        }
                        DriverAction::Batch(selected) => selected,
                    };
                    let Some(SelectedBatch { source, inputs: batch, kind }) = selected else {
                        break;
                    };
                    #[cfg(test)]
                    lifecycle_observations
                        .selected_batches
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    #[cfg(test)]
                    if let Some(control) = driver_test_control.as_ref() {
                        control.pause_selected_batch_if_requested().await;
                    }
                    bench_recv_us += __r.elapsed().as_micros();

                    let mut execution_inputs = None;
                    if source == ArbEngineInputSource::L1 {
                        #[cfg(test)]
                        {
                            task_test_observations
                                .selected_l1_batches
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        let __w = std::time::Instant::now();
                        let reconciliation = driver
                            .as_mut()
                            .expect("driver exists while reconciling")
                            .reconcile_applied_l1_chunk(&batch, |sequence_number, applied| {
                                record_applied_executed_tip(
                                    &driver_metrics,
                                    genesis_block,
                                    sequence_number,
                                );
                                if let Some(feed_latency) = feed_latency.as_ref() {
                                    feed_latency.record_canonical(sequence_number, applied);
                                }
                            })
                            .await;
                        #[cfg(test)]
                        task_test_observations.engine_reconciliation_calls.store(
                            driver
                                .as_ref()
                                .expect("driver exists after reconciliation")
                                .reconciliation_call_count(),
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        match reconciliation {
                            Ok(resolved_suffix) => execution_inputs = Some(resolved_suffix),
                            Err(error) => {
                                tracing::error!(
                                    target: "arb-reth::engine",
                                    %error,
                                    "engine driver stopped while reconciling L1 chunk",
                                );
                                if arb_reth_engine::is_message_divergence(&error) {
                                    let failed = arb_reth_engine::message_divergence_sequence(&error)
                                        .and_then(|sequence| {
                                            batch.iter().find(|input| {
                                                input.sequence_number() == sequence
                                            })
                                        })
                                        .unwrap_or(&batch[0]);
                                    driver
                                        .as_ref()
                                        .expect("driver exists after reconciliation failure")
                                        .write_divergence_marker_for_error(failed, &error)
                                        .wrap_err("failed to persist divergence marker before shutdown")?;
                                }
                                return Err(error);
                            }
                        }
                        bench_work_us += __w.elapsed().as_micros();
                    }

                    let execution_inputs = execution_inputs.unwrap_or(batch);
                    let suffix_len = execution_inputs.len();
                    for (index, input) in execution_inputs.into_iter().enumerate() {
                        let __w = std::time::Instant::now();
                        if let Err(error) = driver
                            .as_mut()
                            .expect("driver exists while applying messages")
                            .advance_with_applied_overlap(
                                &input,
                                index + 1 < suffix_len,
                                source == ArbEngineInputSource::Feed || index + 1 == suffix_len,
                                |sequence_number, applied| {
                                    record_applied_executed_tip(
                                        &driver_metrics,
                                        genesis_block,
                                        sequence_number,
                                    );
                                    if let Some(feed_latency) = feed_latency.as_ref() {
                                        feed_latency.record_canonical(sequence_number, applied);
                                    }
                                },
                            )
                            .await
                        {
                            tracing::error!(
                                target: "arb-reth::engine",
                                %error,
                                "engine driver stopped while applying message",
                            );
                            if arb_reth_engine::is_message_divergence(&error) {
                                driver
                                    .as_ref()
                                    .expect("driver exists after apply failure")
                                    .write_divergence_marker_for_error(&input, &error)
                                    .wrap_err("failed to persist divergence marker before shutdown")?;
                            }
                            return Err(error);
                        }
                        #[cfg(test)]
                        if let Some(control) = driver_test_control.as_ref() {
                            control.pause_if_requested(input.sequence_number()).await;
                        }
                        bench_work_us += __w.elapsed().as_micros();
                    }
                    driver_metrics.set_executed_tip(
                        driver
                            .as_ref()
                            .expect("driver exists after batch execution")
                            .tip()
                            .number,
                    );
                    #[cfg(test)]
                    if let Some(control) = driver_test_control.as_ref() {
                        control.pause_after_post_batch_frontier().await;
                    }
                    if source == ArbEngineInputSource::L1
                        && recovery
                            .as_ref()
                            .is_some_and(|runtime| {
                                driver
                                    .as_ref()
                                    .expect("driver exists at recovery barrier")
                                    .tip()
                                    .number
                                    >= runtime.marker.old_db_tip_number
                            })
                    {
                        let barrier_tip = driver
                            .as_ref()
                            .expect("driver exists at recovery barrier")
                            .tip()
                            .number;
                        let quiesced_tip = driver
                            .take()
                            .expect("driver exists at recovery barrier")
                            .quiesce_for_recovery()
                            .await?;
                        ensure!(
                            quiesced_tip.number == barrier_tip,
                            "recovery quiescence acknowledged unexpected frontier {} instead of {barrier_tip}",
                            quiesced_tip.number
                        );
                        ensure!(
                            crate::recovery::is_recovery_worker(),
                            "recovery rederivation must run in the disposable storage-owner process"
                        );
                        crate::recovery::recovery_failpoint(
                            "recovery_worker_quiesced_before_process_exit",
                        );
                        return Ok(())
                    }
                    scheduler.complete_batch(source, kind);
                    #[cfg(test)]
                    if let Some(control) = driver_test_control.as_ref() {
                        control.pause_after_batch_completion().await;
                    }
                    #[cfg(test)]
                    lifecycle_observations
                        .completed_batches
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    bench_n += suffix_len as u64;
                    #[cfg(test)]
                    task_test_observations
                        .benchmark_executed
                        .store(bench_n, std::sync::atomic::Ordering::Relaxed);
                    if bench_n >= 1000 {
                            let wall_ms = bench_wall.elapsed().as_millis().max(1);
                            tracing::info!(
                                target: "arb-reth::bench",
                                blocks = bench_n,
                                blk_per_s = (bench_n as u128 * 1000 / wall_ms) as u64,
                                recv_ms = (bench_recv_us / 1000) as u64,
                                work_ms = (bench_work_us / 1000) as u64,
                                recv_pct = (100 * bench_recv_us
                                    / (bench_recv_us + bench_work_us).max(1)) as u64,
                                "bench: 1000-block window",
                            );
                            bench_recv_us = 0;
                            bench_work_us = 0;
                            bench_n = 0;
                            bench_wall = std::time::Instant::now();
                    }

                }
                Ok(())
            }
            .await;
            let _ = sampler_cancel_tx.send(());
            let _ = sampler_done_rx.await;
            #[cfg(test)]
            lifecycle_observations
                .sampler_stops
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            #[cfg(test)]
            if let Some(control) = driver_test_control.as_ref() {
                control.pause_before_terminal_lifecycle().await;
            }
            // Flush and terminate the engine tree on both normal channel closure and fail-closed
            // driver errors. Dropping the guard requests termination, but awaiting shutdown here
            // also settles persistence before the node reports its terminal result.
            let (shutdown_result, journal_result) = if let Some(driver) = driver.as_mut() {
                (
                    driver.shutdown().await,
                    driver.flush_durable_message_journal(),
                )
            } else {
                (Ok(()), Ok(()))
            };
            let res = match (res, shutdown_result, journal_result) {
                (Ok(()), Ok(()), journal_result) => journal_result,
                (Ok(()), Err(shutdown_error), Ok(())) => Err(shutdown_error),
                (Ok(()), Err(shutdown_error), Err(journal_error)) => {
                    tracing::error!(
                        target: "arb-reth::journal",
                        %journal_error,
                        "failed to flush message journal after engine shutdown failure",
                    );
                    Err(shutdown_error)
                }
                (Err(driver_error), shutdown_result, journal_result) => {
                    if let Err(shutdown_error) = shutdown_result {
                        tracing::error!(
                            target: "arb-reth::engine",
                            %shutdown_error,
                            "engine shutdown also failed after driver failure",
                        );
                    }
                    if let Err(journal_error) = journal_result {
                        tracing::error!(
                            target: "arb-reth::journal",
                            %journal_error,
                            "failed to flush message journal after driver failure",
                        );
                    }
                    Err(driver_error)
                }
            };
            let _ = exit_tx.send(res); // ignore error if receiver was dropped
            drop(shutdown_guard);
        });

        // Serve RPC through reth's canonical `RpcAddOns::launch_add_ons` (full fleet + ws +
        // subscriptions via `NodeConfig.rpc`), not the bespoke server. This node is self-driven
        // from L1 derivation, so the beacon-engine handle is a stub (dangling receiver: engine_*
        // calls would return `EngineUnavailable`), and the auth/engine server is disabled, so
        // nothing ever reaches it.
        let rpc_handle = if rpc_addr.is_some() {
            let (engine_tx, _engine_rx) = tokio::sync::mpsc::unbounded_channel();
            let beacon_engine_handle =
                reth_engine_primitives::ConsensusEngineHandle::new(engine_tx);
            let rpc_node = ctx.node_adapter().clone();
            let rpc_config = ctx.node_config().clone();
            let jwt_secret = ctx.auth_jwt_secret()?;
            let mut add_ons = crate::addons::arb_add_ons();
            if let Some(frontier_store) = frontier_store {
                let frontier_provider = provider.clone();
                let frontier_evm_config = arb_evm_config.clone();
                let frontier_gas_cap = rpc_config.rpc.rpc_gas_cap;
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
            let launch_rpc = async move {
                let add_ons_ctx = AddOnsContext {
                    node: rpc_node,
                    config: &rpc_config,
                    beacon_engine_handle,
                    engine_events: reth_tokio_util::EventSender::default(),
                    jwt_secret,
                };
                let handle = add_ons.launch_add_ons(add_ons_ctx).await?;
                Ok::<RpcServerHandle, eyre::Report>(handle.rpc_server_handles.rpc)
            };
            if recovery_gate.is_ready() {
                Some(launch_rpc.await?)
            } else {
                let gate = recovery_gate.clone();
                task_executor.spawn_with_graceful_shutdown_signal(|shutdown| async move {
                    let mut shutdown = Box::pin(shutdown);
                    tokio::select! {
                        biased;
                        guard = &mut shutdown => {
                            drop(guard);
                            return;
                        }
                        _ = gate.wait_ready() => {}
                    }
                    match launch_rpc.await {
                        Ok(handle) => {
                            tracing::info!(
                                target: "arb-reth::rpc",
                                "RPC released after durable recovery finalization",
                            );
                            let guard = shutdown.await;
                            drop(handle);
                            drop(guard);
                        }
                        Err(error) => tracing::error!(
                            target: "arb-reth::rpc",
                            %error,
                            "failed to launch RPC after recovery",
                        ),
                    }
                });
                None
            }
        } else {
            None
        };

        Ok(ArbNodeHandle {
            provider,
            exit_rx,
            rpc_handle,
            ingress_metrics,
            #[cfg(test)]
            driver_test_observations,
            #[cfg(test)]
            engine_lifecycle_probe,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use alloy_primitives::{B256, U256, address};
    use arb_revm::arbos_init::ArbosInitConfig;
    use arbitrum_alloy_sequencer::sequencer::feed::BroadcastFeedMessage;
    use reth_chainspec::MAINNET;
    use reth_node_builder::{LaunchNode, NodeBuilder, NodeConfig};
    use reth_node_core::args::PruningArgs;
    use reth_provider::{BlockNumReader, HeaderProvider, StateProviderFactory};
    use reth_storage_api::AccountReader;
    use reth_tasks::Runtime;

    use crate::ArbNode;

    fn scheduler_input(source: ArbEngineInputSource, sequence: u64) -> ArbEngineInput {
        let message = BroadcastFeedMessage {
            sequence_number: sequence,
            ..Default::default()
        };
        match source {
            ArbEngineInputSource::Feed => ArbEngineInput::feed(message, None),
            ArbEngineInputSource::L1 => ArbEngineInput::l1(message),
        }
    }

    fn scheduler_with(
        feed: impl IntoIterator<Item = u64>,
        l1: impl IntoIterator<Item = u64>,
    ) -> IngressScheduler {
        let feed = feed.into_iter().collect::<Vec<_>>();
        let l1 = l1.into_iter().collect::<Vec<_>>();
        let (feed_tx, feed_rx) = tokio::sync::mpsc::channel(feed.len().max(1));
        let (l1_tx, l1_rx) = tokio::sync::mpsc::channel(l1.len().max(1));
        for sequence in feed {
            feed_tx
                .try_send(scheduler_input(ArbEngineInputSource::Feed, sequence))
                .unwrap();
        }
        for sequence in l1 {
            l1_tx
                .try_send(
                    scheduler_input(ArbEngineInputSource::L1, sequence)
                        .message()
                        .clone(),
                )
                .unwrap();
        }
        drop(feed_tx);
        drop(l1_tx);
        IngressScheduler::new(feed_rx, l1_rx, IngressMetrics::new(), None)
    }

    fn production_test_chain_spec() -> Arc<reth_chainspec::ChainSpec> {
        let init = ArbosInitConfig {
            initial_arbos_version: 40,
            initial_chain_owner: address!("5E1497dD1f08C87b2d8FE23e9AAB6c1De833D927"),
            chain_id: U256::from(412346u64),
            genesis_block_number: 0,
            initial_l1_base_fee: U256::from(167u64),
            serialized_chain_config: include_bytes!(
                "../tests/fixtures/testnode_l2_chain_config.json"
            )
            .to_vec(),
            debug_precompiles: true,
        };
        Arc::new(crate::arb_chain_spec(&init).expect("build ArbOS chain spec"))
    }

    async fn scrape_metrics(addr: std::net::SocketAddr) -> String {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect to production metrics endpoint");
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("request production metrics");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read production metrics");
        String::from_utf8(response).expect("Prometheus response is UTF-8")
    }

    fn ingress_metric(exposition: &str, suffix: &str) -> f64 {
        let name = format!("reth_arb_reth_ingress_{suffix}");
        exposition
            .lines()
            .find_map(|line| {
                line.strip_prefix(&name)
                    .and_then(|value| value.strip_prefix(' '))
                    .and_then(|value| value.parse().ok())
            })
            .unwrap_or_else(|| panic!("missing unlabeled metric {name}: {exposition}"))
    }

    async fn wait_for_ingress_metrics(
        addr: std::net::SocketAddr,
        expected: &[(&str, f64)],
    ) -> String {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let exposition = scrape_metrics(addr).await;
                if expected
                    .iter()
                    .all(|(name, value)| ingress_metric(&exposition, name) == *value)
                {
                    break exposition;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for ingress metrics {expected:?}"))
    }

    fn run_isolated_test_phase(
        test_name: &str,
        phase_env: &str,
        phase: &str,
        datadir: &std::path::Path,
    ) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
            .env(phase_env, phase)
            .env("ITE104_TEST_DATADIR", datadir)
            .output()
            .expect("run isolated production test phase");
        assert!(
            output.status.success(),
            "isolated {phase} phase failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    fn production_metrics_addr() -> std::net::SocketAddr {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        addr
    }

    #[tokio::test]
    async fn both_ready_is_feed_first_then_bounded_fair_at_exact_quantum() {
        let mut scheduler = scheduler_with(1..=65, 100..=164);

        let feed = scheduler.next_batch(1_000).await.unwrap();
        assert_eq!(feed.source, ArbEngineInputSource::Feed);
        assert_eq!(feed.kind, BatchKind::Ordinary);
        assert_eq!(feed.inputs.len(), MAX_MESSAGE_BATCH);
        assert_eq!(feed.inputs[0].sequence_number(), 1);
        assert_eq!(feed.inputs[63].sequence_number(), 64);
        assert_eq!(scheduler.feed_messages.len(), 1);
        assert_eq!(scheduler.l1_messages.len(), 64);
        assert_eq!(
            scheduler
                .l1_pending
                .as_ref()
                .map(ArbEngineInput::sequence_number),
            Some(100),
            "L1 is prefetched but has not entered service",
        );
        scheduler.complete_batch(feed.source, feed.kind);

        let l1 = scheduler.next_batch(1_000).await.unwrap();
        assert_eq!(l1.source, ArbEngineInputSource::L1);
        assert_eq!(l1.inputs.len(), MAX_MESSAGE_BATCH);
        assert_eq!(l1.inputs[0].sequence_number(), 100);
        assert_eq!(l1.inputs[63].sequence_number(), 163);
        scheduler.complete_batch(l1.source, l1.kind);

        assert_eq!(scheduler.owed, ArbEngineInputSource::Feed);
        assert_eq!(scheduler.feed_messages.len(), 0);
        assert_eq!(scheduler.l1_messages.len(), 1);
        assert_eq!(
            scheduler
                .feed_pending
                .as_ref()
                .map(ArbEngineInput::sequence_number),
            Some(65),
        );
    }

    #[tokio::test]
    async fn open_empty_peer_never_delays_ready_source_and_remains_owed() {
        let (feed_tx, feed_rx) = tokio::sync::mpsc::channel(2);
        let (l1_tx, l1_rx) = tokio::sync::mpsc::channel(2);
        l1_tx
            .send(
                scheduler_input(ArbEngineInputSource::L1, 10)
                    .message()
                    .clone(),
            )
            .await
            .unwrap();
        let mut scheduler = IngressScheduler::new(feed_rx, l1_rx, IngressMetrics::new(), None);
        let l1 = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            scheduler.next_batch(1_000),
        )
        .await
        .expect("open-empty Feed must not delay L1")
        .unwrap();
        assert_eq!(l1.source, ArbEngineInputSource::L1);
        scheduler.complete_batch(l1.source, l1.kind);
        assert_eq!(scheduler.owed, ArbEngineInputSource::Feed);

        feed_tx
            .send(scheduler_input(ArbEngineInputSource::Feed, 20))
            .await
            .unwrap();
        let feed = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            scheduler.next_batch(1_000),
        )
        .await
        .expect("ready Feed must progress while L1 remains open")
        .unwrap();
        assert_eq!(feed.source, ArbEngineInputSource::Feed);
        drop((feed_tx, l1_tx));
    }

    #[tokio::test]
    async fn one_item_gap_exception_rearbitrates_to_contiguous_feed() {
        let mut scheduler = scheduler_with([2], [1, 2]);
        let closer = scheduler.next_batch(1).await.unwrap();
        assert_eq!(closer.source, ArbEngineInputSource::L1);
        assert_eq!(closer.kind, BatchKind::GapCloser);
        assert_eq!(closer.inputs.len(), 1);
        scheduler.complete_batch(closer.source, closer.kind);

        let contiguous_feed = scheduler.next_batch(2).await.unwrap();
        assert_eq!(contiguous_feed.source, ArbEngineInputSource::Feed);
        assert_eq!(contiguous_feed.inputs[0].sequence_number(), 2);
        assert_eq!(contiguous_feed.kind, BatchKind::Ordinary);
    }

    #[tokio::test]
    async fn l1_overlap_does_not_suppress_contiguous_feed() {
        let mut scheduler = scheduler_with([5], [4]);
        let selected = scheduler.next_batch(5).await.unwrap();
        assert_eq!(selected.source, ArbEngineInputSource::Feed);
        assert_eq!(selected.inputs[0].sequence_number(), 5);
    }

    #[tokio::test]
    async fn fifo_no_loss_and_closure_preserves_pending_head() {
        let mut scheduler = scheduler_with([1, 2, 3], [101, 102, 103]);
        let mut observed = Vec::new();
        let feed = scheduler.next_batch(1_000).await.unwrap();
        assert_eq!(feed.source, ArbEngineInputSource::Feed);
        assert_eq!(scheduler.feed_messages.len(), 0);
        assert_eq!(scheduler.l1_messages.len(), 2);
        assert_eq!(
            scheduler
                .l1_pending
                .as_ref()
                .map(ArbEngineInput::sequence_number),
            Some(101),
        );
        observed.extend(
            feed.inputs
                .iter()
                .map(|input| (feed.source, input.sequence_number())),
        );
        scheduler.complete_batch(feed.source, feed.kind);

        while let Some(batch) = scheduler.next_batch(1_000).await {
            observed.extend(
                batch
                    .inputs
                    .iter()
                    .map(|input| (batch.source, input.sequence_number())),
            );
            scheduler.complete_batch(batch.source, batch.kind);
        }
        assert_eq!(
            observed,
            [
                (ArbEngineInputSource::Feed, 1),
                (ArbEngineInputSource::Feed, 2),
                (ArbEngineInputSource::Feed, 3),
                (ArbEngineInputSource::L1, 101),
                (ArbEngineInputSource::L1, 102),
                (ArbEngineInputSource::L1, 103),
            ]
        );
        assert!(scheduler.feed_pending.is_none());
        assert!(scheduler.l1_pending.is_none());
        assert_eq!(scheduler.feed_messages.len(), 0);
        assert_eq!(scheduler.l1_messages.len(), 0);
    }

    #[tokio::test]
    async fn idle_shutdown_wins_before_any_ready_channel_dequeue() {
        let (feed_tx, feed_rx) = tokio::sync::mpsc::channel(1);
        let (l1_tx, l1_rx) = tokio::sync::mpsc::channel(1);
        feed_tx
            .send(scheduler_input(ArbEngineInputSource::Feed, 1))
            .await
            .unwrap();
        l1_tx
            .send(
                scheduler_input(ArbEngineInputSource::L1, 1)
                    .message()
                    .clone(),
            )
            .await
            .unwrap();
        let mut scheduler = IngressScheduler::new(feed_rx, l1_rx, IngressMetrics::new(), None);
        let shutdown = std::future::ready(());
        tokio::pin!(shutdown);

        assert!(matches!(
            next_driver_action(shutdown.as_mut(), &mut scheduler, 1).await,
            DriverAction::Shutdown(())
        ));
        assert!(scheduler.feed_pending.is_none());
        assert!(scheduler.l1_pending.is_none());
        assert_eq!(scheduler.feed_messages.len(), 1);
        assert_eq!(scheduler.l1_messages.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn shutdown_during_in_flight_production_batch_finishes_only_that_batch() {
        const PHASE_ENV: &str = "ITE104_SHUTDOWN_TEST_PHASE";
        const TEST_NAME: &str =
            "launcher::tests::shutdown_during_in_flight_production_batch_finishes_only_that_batch";
        let Some(phase) = std::env::var_os(PHASE_ENV) else {
            let completion_datadir =
                tempfile::tempdir().expect("create completion metrics datadir");
            run_isolated_test_phase(
                TEST_NAME,
                PHASE_ENV,
                "completion",
                completion_datadir.path(),
            );
            let shutdown_datadir = tempfile::tempdir().expect("create shutdown durability datadir");
            run_isolated_test_phase(TEST_NAME, PHASE_ENV, "shutdown", shutdown_datadir.path());
            run_isolated_test_phase(TEST_NAME, PHASE_ENV, "restart", shutdown_datadir.path());
            return;
        };
        let phase = phase.to_str().expect("shutdown test phase is UTF-8");
        let datadir = std::path::PathBuf::from(
            std::env::var_os("ITE104_TEST_DATADIR").expect("shutdown child receives datadir"),
        );
        let runtime = Runtime::test();
        let chain_spec = production_test_chain_spec();
        let db = Arc::new(
            reth_db::init_db(
                datadir.join("db"),
                reth_db::mdbx::DatabaseArguments::new(reth_db::ClientVersion::default()),
            )
            .expect("open persistent shutdown test database"),
        );
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

        if phase == "restart" {
            let (feed_tx, feed_rx) = tokio::sync::mpsc::channel(1);
            let (l1_tx, l1_rx) = tokio::sync::mpsc::channel(1);
            drop((feed_tx, l1_tx));
            let handle = ArbLauncher {
                ctx: LaunchContext::new(runtime, data_dir),
                chain_id: 412346,
                genesis_block: 0,
                tuning: ArbEngineTuning::reth_defaults(),
                prune_config: None,
                init_message_journal_at_tip: false,
                l1_verified_tip: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                feed_messages: feed_rx,
                l1_messages: l1_rx,
                feed_latency: None,
                rpc_addr: None,
                tx_log_stream: None,
                recovery_gate: RecoveryGate::new(true),
                recovery: None,
                driver_test_control: None,
            }
            .launch_node(NodeBuilder::new(config).with_database(db).node(ArbNode))
            .await
            .expect("reopened database and journal must agree after shutdown");
            assert_eq!(handle.provider.best_block_number().unwrap(), 3);
            handle
                .wait_for_node_exit()
                .await
                .expect("restarted driver must shut down cleanly");
            return;
        }
        assert!(matches!(phase, "completion" | "shutdown"));

        let metrics_addr = production_metrics_addr();
        let mut config = config;
        config.metrics.prometheus = Some(metrics_addr);
        let (feed_tx, feed_rx) = tokio::sync::mpsc::channel(4);
        let (l1_tx, l1_rx) = tokio::sync::mpsc::channel(1);
        for sequence in 1..=3 {
            let mut message = deposit_message();
            message.sequence_number = sequence;
            feed_tx
                .send(ArbEngineInput::feed(message, None))
                .await
                .unwrap();
        }
        let control = Arc::new(DriverTestControl::pause_after_input_and_completion(
            2,
            phase == "shutdown",
        ));
        let launcher = ArbLauncher {
            ctx: LaunchContext::new(runtime.clone(), data_dir),
            chain_id: 412346,
            genesis_block: 0,
            tuning: ArbEngineTuning::reth_defaults(),
            prune_config: None,
            init_message_journal_at_tip: false,
            l1_verified_tip: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            feed_messages: feed_rx,
            l1_messages: l1_rx,
            feed_latency: None,
            rpc_addr: None,
            tx_log_stream: None,
            recovery_gate: RecoveryGate::new(true),
            recovery: None,
            driver_test_control: Some(control.clone()),
        };
        let handle = launcher
            .launch_node(NodeBuilder::new(config).with_database(db).node(ArbNode))
            .await
            .expect("launch must succeed");
        let metrics = handle.ingress_metrics.clone();
        let observations = handle.driver_test_observations.clone();
        let engine_lifecycle = handle.engine_lifecycle_probe.clone();
        let provider = handle.provider.clone();
        let task_manager = runtime
            .take_task_manager_handle()
            .expect("shutdown test runtime owns its task manager");

        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            control.input_paused.notified(),
        )
        .await
        .expect("production batch must be in flight");
        let mut fourth = deposit_message();
        fourth.sequence_number = 4;
        feed_tx
            .send(ArbEngineInput::feed(fourth, None))
            .await
            .expect("queue post-selection input");
        let before_shutdown = wait_for_ingress_metrics(
            metrics_addr,
            &[("feed_dequeued_total", 3.0), ("feed_queue_depth", 0.0)],
        )
        .await;
        assert!(ingress_metric(&before_shutdown, "last_feed_dequeue_timestamp_seconds") > 0.0);
        assert_eq!(
            observations
                .sampler_stops
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "sampler remains active while the selected batch is in flight",
        );

        if phase == "completion" {
            control.resume_input.notify_one();
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                control.completion_paused.notified(),
            )
            .await
            .expect("driver must pause immediately after production batch completion");
            wait_for_ingress_metrics(
                metrics_addr,
                &[
                    ("feed_dequeued_total", 3.0),
                    ("l1_dequeued_total", 0.0),
                    ("feed_queue_depth", 1.0),
                    ("l1_queue_depth", 0.0),
                ],
            )
            .await;
            assert_eq!(
                feed_tx.capacity(),
                3,
                "queued input 4 remains unread while completion depth is sampled",
            );
            drop((feed_tx, l1_tx));
            control.resume_completion.notify_one();
            handle
                .wait_for_node_exit()
                .await
                .expect("completion metrics phase must finish queued input and close cleanly");
            drop((provider, metrics));
            drop(
                runtime
                    .initiate_graceful_shutdown()
                    .expect("stop completion metrics runtime"),
            );
            tokio::time::timeout(std::time::Duration::from_secs(10), task_manager)
                .await
                .expect("completion metrics runtime tasks must stop")
                .expect("join completion metrics task manager")
                .expect("completion metrics task manager must not panic");
            return;
        }

        let shutdown_seen = runtime.on_shutdown_signal().clone();
        drop(
            runtime
                .initiate_graceful_shutdown()
                .expect("signal graceful shutdown"),
        );
        tokio::time::timeout(std::time::Duration::from_secs(3), shutdown_seen)
            .await
            .expect("shutdown signal must be active before releasing the batch");
        control.resume_input.notify_one();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            control.completion_paused.notified(),
        )
        .await
        .expect("selected batch must complete before terminal shutdown lifecycle");
        assert_eq!(
            feed_tx.capacity(),
            3,
            "queued input 4 remains unread after completion and before shutdown arbitration",
        );
        control.resume_completion.notify_one();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            control.terminal_paused.notified(),
        )
        .await
        .expect("driver must reach terminal lifecycle after finishing its selected batch");
        assert_eq!(provider.best_block_number().unwrap(), 3);
        assert_eq!(
            feed_tx.capacity(),
            3,
            "queued input 4 must remain unread at the actual terminal lifecycle boundary",
        );
        assert_eq!(
            observations
                .sampler_stops
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "sampler must stop before engine shutdown starts",
        );
        assert_eq!(
            engine_lifecycle.shutdown_calls(),
            0,
            "engine shutdown must not start before the selected batch and sampler finish",
        );
        assert_eq!(
            engine_lifecycle.journal_flush_calls(),
            3,
            "only the three apply-path durability checks may precede terminal lifecycle",
        );
        control.resume_terminal.notify_one();
        handle
            .wait_for_node_exit()
            .await
            .expect("selected in-flight batch must finish before shutdown");

        assert_eq!(provider.best_block_number().unwrap(), 3);
        assert_eq!(
            observations
                .selected_batches
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "no post-shutdown batch begins",
        );
        assert_eq!(
            observations
                .completed_batches
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
        );
        assert_eq!(
            observations
                .sampler_stops
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
        );
        assert_eq!(
            engine_lifecycle.shutdown_calls(),
            1,
            "the actual engine shutdown method must run exactly once",
        );
        assert_eq!(
            engine_lifecycle.journal_flush_calls(),
            4,
            "three apply-path checks plus exactly one terminal journal flush must run",
        );
        drop((feed_tx, l1_tx));
        drop(provider);
        tokio::time::timeout(std::time::Duration::from_secs(10), task_manager)
            .await
            .expect("all runtime tasks must release their handles")
            .expect("join shutdown test task manager")
            .expect("shutdown test task manager must not panic");
        drop(runtime);

        let journal = std::fs::read_to_string(datadir.join("arb-message-journal.ndjson"))
            .expect("reopen durable message journal after runtime termination");
        let last = journal
            .lines()
            .last()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .expect("journal contains its final selected-batch entry");
        assert_eq!(last["entry"]["sequence"], 3);
        assert_eq!(last["entry"]["block_number"], 3);
        assert_eq!(last["entry"]["source"], "feed");
        drop(metrics);
    }

    enum PayloadServiceTestExit {
        Panic,
        OrdinaryReturn,
    }

    async fn assert_payload_service_exit_is_terminal_node_failure(exit: PayloadServiceTestExit) {
        let runtime = Runtime::test();
        let chain_spec = production_test_chain_spec();
        let datadir = tempfile::tempdir().expect("create payload failure datadir");
        let db = Arc::new(
            reth_db::init_db(
                datadir.path().join("db"),
                reth_db::mdbx::DatabaseArguments::new(reth_db::ClientVersion::default()),
            )
            .expect("open payload failure database"),
        );
        let maybe_path =
            reth_node_core::dirs::MaybePlatformPath::<reth_node_core::dirs::DataDirPath>::from(
                datadir.path().to_path_buf(),
            );
        let config = NodeConfig::test()
            .with_chain(chain_spec.clone())
            .with_datadir_args(reth_node_core::args::DatadirArgs {
                datadir: maybe_path.clone(),
                ..Default::default()
            });
        let data_dir =
            maybe_path.unwrap_or_chain_default(chain_spec.chain(), config.datadir.clone());
        let (feed_tx, feed_rx) = tokio::sync::mpsc::channel(1);
        let (l1_tx, l1_rx) = tokio::sync::mpsc::channel(1);
        let handle = ArbLauncher {
            ctx: LaunchContext::new(runtime.clone(), data_dir),
            chain_id: 412346,
            genesis_block: 0,
            tuning: ArbEngineTuning::reth_defaults(),
            prune_config: None,
            init_message_journal_at_tip: false,
            l1_verified_tip: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            feed_messages: feed_rx,
            l1_messages: l1_rx,
            feed_latency: None,
            rpc_addr: None,
            tx_log_stream: None,
            recovery_gate: RecoveryGate::new(true),
            recovery: None,
            driver_test_control: None,
        }
        .launch_node(NodeBuilder::new(config).with_database(db).node(ArbNode))
        .await
        .expect("launch payload failure node");
        let lifecycle = handle.engine_lifecycle_probe.clone();
        let task_manager = runtime
            .take_task_manager_handle()
            .expect("payload failure runtime owns its task manager");

        match exit {
            PayloadServiceTestExit::Panic => lifecycle.panic_payload_service_for_test(),
            PayloadServiceTestExit::OrdinaryReturn => lifecycle.return_payload_service_for_test(),
        }
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            handle.wait_for_node_exit(),
        )
        .await
        .expect("unexpected payload exit must terminate the node")
        .expect_err("unexpected payload exit must not report successful node exit");
        assert!(
            error
                .to_string()
                .contains("arb payload service terminated unexpectedly"),
            "unexpected terminal error: {error:?}",
        );
        assert_eq!(lifecycle.shutdown_calls(), 1);
        assert_eq!(lifecycle.journal_flush_calls(), 1);
        drop((feed_tx, l1_tx));
        tokio::time::timeout(std::time::Duration::from_secs(10), task_manager)
            .await
            .expect("payload failure runtime tasks must stop")
            .expect("join payload failure task manager")
            .expect("payload failure task manager must not panic");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn payload_service_panic_is_terminal_node_failure() {
        assert_payload_service_exit_is_terminal_node_failure(PayloadServiceTestExit::Panic).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn payload_service_ordinary_return_is_terminal_node_failure() {
        assert_payload_service_exit_is_terminal_node_failure(
            PayloadServiceTestExit::OrdinaryReturn,
        )
        .await;
    }

    #[tokio::test]
    async fn cancelled_arbitration_retains_prefetched_scheduler_head_exactly_once() {
        let (feed_tx, feed_rx) = tokio::sync::mpsc::channel(1);
        let (l1_tx, l1_rx) = tokio::sync::mpsc::channel(1);
        let mut scheduler = IngressScheduler::new(feed_rx, l1_rx, IngressMetrics::new(), None);
        let receive_pause = Arc::new(SchedulerReceivePause {
            head_received: tokio::sync::Notify::new(),
            resume: tokio::sync::Notify::new(),
        });
        scheduler.receive_pause = Some(receive_pause.clone());

        let mut arbitration = Box::pin(scheduler.next_batch(1_000));
        let mut producer = Box::pin(async {
            feed_tx
                .send(scheduler_input(ArbEngineInputSource::Feed, 7))
                .await
                .unwrap();
            std::future::pending::<()>().await;
        });
        tokio::select! {
            biased;
            _ = receive_pause.head_received.notified() => {}
            _ = &mut arbitration => panic!("head must remain scheduler-owned before selection"),
            _ = &mut producer => unreachable!(),
        }
        drop(arbitration);
        drop(producer);
        assert_eq!(
            scheduler
                .feed_pending
                .as_ref()
                .map(ArbEngineInput::sequence_number),
            Some(7),
            "successful receive must remain owned by the scheduler after cancellation",
        );

        scheduler.receive_pause = None;
        drop((feed_tx, l1_tx));
        let batch = scheduler.next_batch(1_000).await.unwrap();
        assert_eq!(batch.inputs.len(), 1);
        assert_eq!(batch.inputs[0].sequence_number(), 7);
        scheduler.complete_batch(batch.source, batch.kind);
        assert!(scheduler.next_batch(1_000).await.is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn production_prometheus_tracks_dynamic_ingress_and_frontier_values() {
        const PHASE_ENV: &str = "ITE104_DYNAMIC_METRICS_TEST_PHASE";
        const TEST_NAME: &str =
            "launcher::tests::production_prometheus_tracks_dynamic_ingress_and_frontier_values";
        let Some(phase) = std::env::var_os(PHASE_ENV) else {
            let datadir = tempfile::tempdir().expect("create dynamic metrics datadir");
            run_isolated_test_phase(TEST_NAME, PHASE_ENV, "closure-first", datadir.path());
            let datadir = tempfile::tempdir().expect("create L1-first dynamic metrics datadir");
            run_isolated_test_phase(TEST_NAME, PHASE_ENV, "l1-first", datadir.path());
            return;
        };
        let l1_first = match phase.to_str().expect("dynamic metrics phase is UTF-8") {
            "closure-first" => false,
            "l1-first" => true,
            phase => panic!("unknown dynamic metrics phase {phase}"),
        };

        let runtime = Runtime::test();
        let chain_spec = production_test_chain_spec();
        let datadir = std::path::PathBuf::from(
            std::env::var_os("ITE104_TEST_DATADIR").expect("metrics child receives datadir"),
        );
        let db = Arc::new(
            reth_db::init_db(
                datadir.join("db"),
                reth_db::mdbx::DatabaseArguments::new(reth_db::ClientVersion::default()),
            )
            .expect("open dynamic metrics database"),
        );
        let maybe_path =
            reth_node_core::dirs::MaybePlatformPath::<reth_node_core::dirs::DataDirPath>::from(
                datadir,
            );
        let metrics_addr = production_metrics_addr();
        let mut config = NodeConfig::test()
            .with_chain(chain_spec.clone())
            .with_datadir_args(reth_node_core::args::DatadirArgs {
                datadir: maybe_path.clone(),
                ..Default::default()
            });
        config.metrics.prometheus = Some(metrics_addr);
        let data_dir =
            maybe_path.unwrap_or_chain_default(chain_spec.chain(), config.datadir.clone());
        let (feed_tx, feed_rx) = tokio::sync::mpsc::channel(4);
        let (l1_tx, l1_rx) = tokio::sync::mpsc::channel(3);
        for sequence in 1..=3 {
            let mut message = deposit_message();
            message.sequence_number = sequence;
            feed_tx
                .send(ArbEngineInput::feed(message, None))
                .await
                .unwrap();
        }
        for sequence in 1..=2 {
            let mut message = deposit_message();
            message.sequence_number = sequence;
            l1_tx.send(message).await.unwrap();
        }
        let control = Arc::new(DriverTestControl::pause_for_dynamic_metrics(2));
        let verified = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let handle = ArbLauncher {
            ctx: LaunchContext::new(runtime, data_dir),
            chain_id: 412346,
            genesis_block: 0,
            tuning: ArbEngineTuning::reth_defaults(),
            prune_config: None,
            init_message_journal_at_tip: false,
            l1_verified_tip: verified,
            feed_messages: feed_rx,
            l1_messages: l1_rx,
            feed_latency: None,
            rpc_addr: None,
            tx_log_stream: None,
            recovery_gate: RecoveryGate::new(true),
            recovery: None,
            driver_test_control: Some(control.clone()),
        }
        .launch_node(NodeBuilder::new(config).with_database(db).node(ArbNode))
        .await
        .expect("launch dynamic production metrics node");
        let ingress_metrics = handle.ingress_metrics.clone();

        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            control.selected_batch_paused.notified(),
        )
        .await
        .expect("Feed batch must pause after production selection");
        let selected_feed = wait_for_ingress_metrics(
            metrics_addr,
            &[
                ("feed_dequeued_total", 3.0),
                ("l1_dequeued_total", 1.0),
                ("feed_queue_depth", 0.0),
                ("l1_queue_depth", 2.0),
                ("executed_tip", 0.0),
                ("last_feed_frame_timestamp_seconds", 0.0),
            ],
        )
        .await;
        let dequeue_timestamp =
            ingress_metric(&selected_feed, "last_feed_dequeue_timestamp_seconds");
        assert!(dequeue_timestamp > 0.0);

        assert!(
            crate::feed::data_frame_text(
                tokio_tungstenite::tungstenite::Message::Binary(vec![0xff].into()),
                &ingress_metrics,
            )
            .is_err()
        );
        let malformed = scrape_metrics(metrics_addr).await;
        let malformed_timestamp = ingress_metric(&malformed, "last_feed_frame_timestamp_seconds");
        assert!(malformed_timestamp > 0.0);
        assert_eq!(
            ingress_metric(&malformed, "last_feed_dequeue_timestamp_seconds"),
            dequeue_timestamp,
        );
        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        assert!(
            crate::feed::data_frame_text(
                tokio_tungstenite::tungstenite::Message::Text("duplicate".into()),
                &ingress_metrics,
            )
            .is_ok()
        );
        let duplicate = scrape_metrics(metrics_addr).await;
        let duplicate_timestamp = ingress_metric(&duplicate, "last_feed_frame_timestamp_seconds");
        assert!(duplicate_timestamp > malformed_timestamp);
        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        assert_eq!(
            crate::feed::data_frame_text(
                tokio_tungstenite::tungstenite::Message::Ping(Vec::new().into()),
                &ingress_metrics,
            )
            .unwrap(),
            None,
        );
        let control_frame = scrape_metrics(metrics_addr).await;
        assert_eq!(
            ingress_metric(&control_frame, "last_feed_frame_timestamp_seconds"),
            duplicate_timestamp,
        );

        ingress_metrics.pause_next_frame_before_max();
        let older_metrics = ingress_metrics.clone();
        let older_before_max = std::thread::spawn(move || {
            crate::feed::data_frame_text(
                tokio_tungstenite::tungstenite::Message::Text("older-before-max".into()),
                &older_metrics,
            )
        });
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            ingress_metrics.wait_frame_before_max_paused(),
        )
        .await
        .expect("older frame writer must pause before its atomic maximum");
        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        crate::feed::data_frame_text(
            tokio_tungstenite::tungstenite::Message::Text("newer-before-max".into()),
            &ingress_metrics,
        )
        .expect("newer frame is valid text");
        let newer_before_max = ingress_metric(
            &scrape_metrics(metrics_addr).await,
            "last_feed_frame_timestamp_seconds",
        );
        ingress_metrics.resume_frame_before_max();
        older_before_max
            .join()
            .expect("older frame writer must not panic")
            .expect("older frame is valid text");
        assert_eq!(
            ingress_metric(
                &scrape_metrics(metrics_addr).await,
                "last_feed_frame_timestamp_seconds",
            ),
            newer_before_max,
            "an older writer resuming before atomic max must not regress the gauge",
        );

        ingress_metrics.pause_next_frame_after_max();
        let older_metrics = ingress_metrics.clone();
        let older_after_max = std::thread::spawn(move || {
            crate::feed::data_frame_text(
                tokio_tungstenite::tungstenite::Message::Text("older-after-max".into()),
                &older_metrics,
            )
        });
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            ingress_metrics.wait_frame_after_max_paused(),
        )
        .await
        .expect("older frame writer must pause after its atomic maximum");
        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        crate::feed::data_frame_text(
            tokio_tungstenite::tungstenite::Message::Text("newer-after-max".into()),
            &ingress_metrics,
        )
        .expect("newer frame is valid text");
        let newer_after_max = ingress_metric(
            &scrape_metrics(metrics_addr).await,
            "last_feed_frame_timestamp_seconds",
        );
        ingress_metrics.resume_frame_after_max();
        older_after_max
            .join()
            .expect("older frame writer must not panic")
            .expect("older frame is valid text");
        assert_eq!(
            ingress_metric(
                &scrape_metrics(metrics_addr).await,
                "last_feed_frame_timestamp_seconds",
            ),
            newer_after_max,
            "an older writer resuming before gauge publication must recheck the atomic maximum",
        );

        control.resume_selected_batch.notify_one();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            control.input_paused.notified(),
        )
        .await
        .expect("Feed batch must pause after its second production input");
        wait_for_ingress_metrics(
            metrics_addr,
            &[
                ("executed_tip", 1.0),
                ("l1_verified_tip", 0.0),
                ("verification_distance", 1.0),
            ],
        )
        .await;

        control.resume_input.notify_one();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            control.selected_batch_paused.notified(),
        )
        .await
        .expect("L1 overlap batch must pause after production selection");
        wait_for_ingress_metrics(
            metrics_addr,
            &[
                ("feed_dequeued_total", 3.0),
                ("l1_dequeued_total", 2.0),
                ("feed_queue_depth", 0.0),
                ("l1_queue_depth", 0.0),
                ("executed_tip", 3.0),
                ("durable_tip", 3.0),
                ("l1_verified_tip", 0.0),
                ("verification_distance", 3.0),
            ],
        )
        .await;
        control.pause_next_wait_for_head();
        control.resume_selected_batch.notify_one();
        wait_for_ingress_metrics(
            metrics_addr,
            &[
                ("executed_tip", 3.0),
                ("durable_tip", 3.0),
                ("l1_verified_tip", 2.0),
                ("verification_distance", 1.0),
            ],
        )
        .await;
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            control.wait_for_head_paused.notified(),
        )
        .await
        .expect("scheduler must park before receiving the final L1 item or Feed closure");

        let mut final_overlap = deposit_message();
        final_overlap.sequence_number = 3;
        l1_tx.send(final_overlap).await.unwrap();
        if l1_first {
            control.pause_next_selected_batch();
            control.resume_wait_for_head.notify_one();
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                control.selected_batch_paused.notified(),
            )
            .await
            .expect("ready final L1 item must pause after selection before Feed closure");
            wait_for_ingress_metrics(
                metrics_addr,
                &[
                    ("feed_dequeued_total", 3.0),
                    ("l1_dequeued_total", 3.0),
                    ("feed_queue_depth", 0.0),
                    ("l1_queue_depth", 0.0),
                ],
            )
            .await;
            drop(feed_tx);
            control.resume_selected_batch.notify_one();
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                control.closure_paused.notified(),
            )
            .await
            .expect("Feed closure must be observed after the selected L1 batch completes");
            let closure = wait_for_ingress_metrics(
                metrics_addr,
                &[
                    ("feed_dequeued_total", 3.0),
                    ("l1_dequeued_total", 3.0),
                    ("feed_queue_depth", 0.0),
                    ("l1_queue_depth", 0.0),
                    ("executed_tip", 3.0),
                    ("l1_verified_tip", 3.0),
                ],
            )
            .await;
            assert_eq!(ingress_metric(&closure, "verification_distance"), 0.0);
            control.resume_closure.notify_one();
        } else {
            drop(feed_tx);
            control.resume_wait_for_head.notify_one();
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                control.closure_paused.notified(),
            )
            .await
            .expect("Feed closure must pause before the pending L1 head enters service");
            let closure = wait_for_ingress_metrics(
                metrics_addr,
                &[
                    ("feed_queue_depth", 0.0),
                    ("l1_queue_depth", 1.0),
                    ("l1_dequeued_total", 2.0),
                ],
            )
            .await;
            assert_eq!(ingress_metric(&closure, "feed_dequeued_total"), 3.0);
            control.pause_next_selected_batch();
            control.resume_closure.notify_one();
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                control.selected_batch_paused.notified(),
            )
            .await
            .expect("final L1 batch must pause after production selection");
            wait_for_ingress_metrics(
                metrics_addr,
                &[
                    ("feed_dequeued_total", 3.0),
                    ("l1_dequeued_total", 3.0),
                    ("feed_queue_depth", 0.0),
                    ("l1_queue_depth", 0.0),
                ],
            )
            .await;
            control.resume_selected_batch.notify_one();
        }
        wait_for_ingress_metrics(
            metrics_addr,
            &[
                ("feed_dequeued_total", 3.0),
                ("l1_dequeued_total", 3.0),
                ("feed_queue_depth", 0.0),
                ("l1_queue_depth", 0.0),
                ("executed_tip", 3.0),
                ("durable_tip", 3.0),
                ("l1_verified_tip", 3.0),
                ("verification_distance", 0.0),
            ],
        )
        .await;
        drop(l1_tx);
        handle
            .wait_for_node_exit()
            .await
            .expect("metrics node exits cleanly");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn production_sampler_cannot_regress_concurrent_executed_frontier() {
        const PHASE_ENV: &str = "ITE104_FRONTIER_RACE_TEST_PHASE";
        const TEST_NAME: &str =
            "launcher::tests::production_sampler_cannot_regress_concurrent_executed_frontier";
        if std::env::var_os(PHASE_ENV).is_none() {
            let datadir = tempfile::tempdir().expect("create frontier race datadir");
            run_isolated_test_phase(TEST_NAME, PHASE_ENV, "run", datadir.path());
            return;
        }

        let runtime = Runtime::test();
        let chain_spec = production_test_chain_spec();
        let datadir = std::path::PathBuf::from(
            std::env::var_os("ITE104_TEST_DATADIR").expect("frontier race child receives datadir"),
        );
        let db = Arc::new(
            reth_db::init_db(
                datadir.join("db"),
                reth_db::mdbx::DatabaseArguments::new(reth_db::ClientVersion::default()),
            )
            .expect("open frontier race database"),
        );
        let maybe_path =
            reth_node_core::dirs::MaybePlatformPath::<reth_node_core::dirs::DataDirPath>::from(
                datadir,
            );
        let metrics_addr = production_metrics_addr();
        let mut config = NodeConfig::test()
            .with_chain(chain_spec.clone())
            .with_datadir_args(reth_node_core::args::DatadirArgs {
                datadir: maybe_path.clone(),
                ..Default::default()
            });
        config.metrics.prometheus = Some(metrics_addr);
        let data_dir =
            maybe_path.unwrap_or_chain_default(chain_spec.chain(), config.datadir.clone());
        let (feed_tx, feed_rx) = tokio::sync::mpsc::channel(1);
        let (l1_tx, l1_rx) = tokio::sync::mpsc::channel(1);
        let control = Arc::new(DriverTestControl::pause_sampler_after_capture_and_input(2));
        let verified = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let handle = ArbLauncher {
            ctx: LaunchContext::new(runtime, data_dir),
            chain_id: 412346,
            genesis_block: 0,
            tuning: ArbEngineTuning::reth_defaults(),
            prune_config: None,
            init_message_journal_at_tip: false,
            l1_verified_tip: verified.clone(),
            feed_messages: feed_rx,
            l1_messages: l1_rx,
            feed_latency: None,
            rpc_addr: None,
            tx_log_stream: None,
            recovery_gate: RecoveryGate::new(true),
            recovery: None,
            driver_test_control: Some(control.clone()),
        }
        .launch_node(NodeBuilder::new(config).with_database(db).node(ArbNode))
        .await
        .expect("launch frontier race node");
        let ingress_metrics = handle.ingress_metrics.clone();

        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            control.sampler_capture_paused.notified(),
        )
        .await
        .expect("sampler must pause after capturing executed tip zero");
        let mut message = deposit_message();
        message.sequence_number = 1;
        feed_tx
            .send(ArbEngineInput::feed(message, None))
            .await
            .unwrap();
        wait_for_ingress_metrics(
            metrics_addr,
            &[
                ("executed_tip", 1.0),
                ("l1_verified_tip", 0.0),
                ("verification_distance", 1.0),
            ],
        )
        .await;

        control.resume_sampler_capture.notify_one();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            control.sampler_published.notified(),
        )
        .await
        .expect("paused sampler tick must publish");
        let raced = scrape_metrics(metrics_addr).await;
        assert_eq!(ingress_metric(&raced, "executed_tip"), 1.0);
        assert_eq!(ingress_metric(&raced, "verification_distance"), 1.0);

        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            control.sampler_published.notified(),
        )
        .await
        .expect("idle sampler tick must continue from current executed frontier");
        let idle = scrape_metrics(metrics_addr).await;
        assert_eq!(ingress_metric(&idle, "executed_tip"), 1.0);
        assert_eq!(ingress_metric(&idle, "verification_distance"), 1.0);

        ingress_metrics.pause_next_executed_publish();
        let mut second = deposit_message();
        second.sequence_number = 2;
        feed_tx
            .send(ArbEngineInput::feed(second, None))
            .await
            .unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            ingress_metrics.wait_executed_publish_paused(),
        )
        .await
        .expect("production callback must pause after loading sampled verified tip zero");
        verified.store(1, std::sync::atomic::Ordering::Release);
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            control.sampler_published.notified(),
        )
        .await
        .expect("sampler must publish verified tip one while callback is paused");
        control.pause_next_sampler_capture();
        ingress_metrics.resume_executed_publish();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            control.input_paused.notified(),
        )
        .await
        .expect("production batch must pause before its post-batch frontier repair");
        let verified_race = scrape_metrics(metrics_addr).await;
        assert_eq!(ingress_metric(&verified_race, "executed_tip"), 2.0);
        assert_eq!(ingress_metric(&verified_race, "l1_verified_tip"), 1.0);
        assert_eq!(ingress_metric(&verified_race, "verification_distance"), 1.0);
        control.resume_input.notify_one();
        control.resume_sampler_capture.notify_one();

        drop((feed_tx, l1_tx));
        handle
            .wait_for_node_exit()
            .await
            .expect("frontier race node exits cleanly");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn startup_and_overlap_only_frontiers_publish_before_sampler() {
        const PHASE_ENV: &str = "ITE104_STARTUP_OVERLAP_FRONTIER_TEST_PHASE";
        const TEST_NAME: &str =
            "launcher::tests::startup_and_overlap_only_frontiers_publish_before_sampler";
        let Some(phase) = std::env::var_os(PHASE_ENV) else {
            let datadir = tempfile::tempdir().expect("create startup overlap datadir");
            run_isolated_test_phase(TEST_NAME, PHASE_ENV, "seed", datadir.path());
            run_isolated_test_phase(TEST_NAME, PHASE_ENV, "verify", datadir.path());
            return;
        };
        let phase = phase.to_str().expect("startup overlap phase is UTF-8");
        let runtime = Runtime::test();
        let chain_spec = production_test_chain_spec();
        let datadir = std::path::PathBuf::from(
            std::env::var_os("ITE104_TEST_DATADIR")
                .expect("startup overlap child receives datadir"),
        );
        let db = Arc::new(
            reth_db::init_db(
                datadir.join("db"),
                reth_db::mdbx::DatabaseArguments::new(reth_db::ClientVersion::default()),
            )
            .expect("open startup overlap database"),
        );
        let maybe_path =
            reth_node_core::dirs::MaybePlatformPath::<reth_node_core::dirs::DataDirPath>::from(
                datadir,
            );
        let mut config = NodeConfig::test()
            .with_chain(chain_spec.clone())
            .with_datadir_args(reth_node_core::args::DatadirArgs {
                datadir: maybe_path.clone(),
                ..Default::default()
            });
        let data_dir =
            maybe_path.unwrap_or_chain_default(chain_spec.chain(), config.datadir.clone());
        let (feed_tx, feed_rx) = tokio::sync::mpsc::channel(1);
        let (l1_tx, l1_rx) = tokio::sync::mpsc::channel(3);

        if phase == "seed" {
            drop(feed_tx);
            for sequence in 1..=3 {
                let mut message = deposit_message();
                message.sequence_number = sequence;
                l1_tx.send(message).await.unwrap();
            }
            drop(l1_tx);
            let handle = ArbLauncher {
                ctx: LaunchContext::new(runtime, data_dir),
                chain_id: 412346,
                genesis_block: 0,
                tuning: ArbEngineTuning::reth_defaults(),
                prune_config: None,
                init_message_journal_at_tip: false,
                l1_verified_tip: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                feed_messages: feed_rx,
                l1_messages: l1_rx,
                feed_latency: None,
                rpc_addr: None,
                tx_log_stream: None,
                recovery_gate: RecoveryGate::new(true),
                recovery: None,
                driver_test_control: None,
            }
            .launch_node(NodeBuilder::new(config).with_database(db).node(ArbNode))
            .await
            .expect("launch frontier seed node");
            handle
                .wait_for_node_exit()
                .await
                .expect("seed journal-authoritative tip three");
            return;
        }
        assert_eq!(phase, "verify");

        let metrics_addr = production_metrics_addr();
        config.metrics.prometheus = Some(metrics_addr);
        let control = Arc::new(DriverTestControl::pause_sampler_at_start());
        let handle = ArbLauncher {
            ctx: LaunchContext::new(runtime, data_dir),
            chain_id: 412346,
            genesis_block: 0,
            tuning: ArbEngineTuning::reth_defaults(),
            prune_config: None,
            init_message_journal_at_tip: false,
            l1_verified_tip: Arc::new(std::sync::atomic::AtomicU64::new(999)),
            feed_messages: feed_rx,
            l1_messages: l1_rx,
            feed_latency: None,
            rpc_addr: None,
            tx_log_stream: None,
            recovery_gate: RecoveryGate::new(true),
            recovery: None,
            driver_test_control: Some(control.clone()),
        }
        .launch_node(NodeBuilder::new(config).with_database(db).node(ArbNode))
        .await
        .expect("launch startup overlap verification node");
        let ingress_metrics = handle.ingress_metrics.clone();
        let observations = handle.driver_test_observations.clone();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            control.sampler_start_paused.notified(),
        )
        .await
        .expect("sampler must pause before its first periodic publication");
        wait_for_ingress_metrics(
            metrics_addr,
            &[
                ("executed_tip", 3.0),
                ("durable_tip", 3.0),
                ("l1_verified_tip", 3.0),
                ("verification_distance", 0.0),
            ],
        )
        .await;

        ingress_metrics.set_executed_tip(0);
        let stale = scrape_metrics(metrics_addr).await;
        assert_eq!(ingress_metric(&stale, "executed_tip"), 0.0);
        assert_eq!(ingress_metric(&stale, "verification_distance"), 0.0);
        control.pause_next_post_batch_frontier();
        for sequence in 1..=3 {
            let mut message = deposit_message();
            message.sequence_number = sequence;
            l1_tx.send(message).await.unwrap();
        }
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            control.post_batch_frontier_paused.notified(),
        )
        .await
        .expect("overlap-only batch must pause after post-batch frontier publication");
        wait_for_ingress_metrics(
            metrics_addr,
            &[
                ("l1_dequeued_total", 3.0),
                ("executed_tip", 3.0),
                ("l1_verified_tip", 3.0),
                ("verification_distance", 0.0),
            ],
        )
        .await;
        assert_eq!(
            observations
                .engine_reconciliation_calls
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
        );
        assert_eq!(
            observations
                .benchmark_executed
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "overlap-only selected L1 batch executes and benchmarks no suffix",
        );

        drop((feed_tx, l1_tx));
        control.resume_post_batch_frontier.notify_one();
        control.resume_sampler_start.notify_one();
        handle
            .wait_for_node_exit()
            .await
            .expect("startup overlap verification node exits cleanly");
        assert_eq!(
            observations
                .benchmark_executed
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn production_sampler_exports_failed_then_successful_idle_samples() {
        const PHASE_ENV: &str = "ITE104_SAMPLER_METRICS_TEST_PHASE";
        const TEST_NAME: &str =
            "launcher::tests::production_sampler_exports_failed_then_successful_idle_samples";
        if std::env::var_os(PHASE_ENV).is_none() {
            let datadir = tempfile::tempdir().expect("create sampler metrics datadir");
            run_isolated_test_phase(TEST_NAME, PHASE_ENV, "run", datadir.path());
            return;
        }

        let runtime = Runtime::test();
        let chain_spec = production_test_chain_spec();
        let datadir = std::path::PathBuf::from(
            std::env::var_os("ITE104_TEST_DATADIR").expect("sampler child receives datadir"),
        );
        let db = Arc::new(
            reth_db::init_db(
                datadir.join("db"),
                reth_db::mdbx::DatabaseArguments::new(reth_db::ClientVersion::default()),
            )
            .expect("open sampler metrics database"),
        );
        let maybe_path =
            reth_node_core::dirs::MaybePlatformPath::<reth_node_core::dirs::DataDirPath>::from(
                datadir,
            );
        let metrics_addr = production_metrics_addr();
        let mut config = NodeConfig::test()
            .with_chain(chain_spec.clone())
            .with_datadir_args(reth_node_core::args::DatadirArgs {
                datadir: maybe_path.clone(),
                ..Default::default()
            });
        config.metrics.prometheus = Some(metrics_addr);
        let data_dir =
            maybe_path.unwrap_or_chain_default(chain_spec.chain(), config.datadir.clone());
        let (feed_tx, feed_rx) = tokio::sync::mpsc::channel(1);
        let (l1_tx, l1_rx) = tokio::sync::mpsc::channel(1);
        let verified = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let control = Arc::new(DriverTestControl::with_durable_samples([
            Err("injected durable read failure"),
            Ok(9),
        ]));
        let handle = ArbLauncher {
            ctx: LaunchContext::new(runtime, data_dir),
            chain_id: 412346,
            genesis_block: 0,
            tuning: ArbEngineTuning::reth_defaults(),
            prune_config: None,
            init_message_journal_at_tip: false,
            l1_verified_tip: verified.clone(),
            feed_messages: feed_rx,
            l1_messages: l1_rx,
            feed_latency: None,
            rpc_addr: None,
            tx_log_stream: None,
            recovery_gate: RecoveryGate::new(true),
            recovery: None,
            driver_test_control: Some(control.clone()),
        }
        .launch_node(NodeBuilder::new(config).with_database(db).node(ArbNode))
        .await
        .expect("launch idle sampler metrics node");
        verified.store(2, std::sync::atomic::Ordering::Release);

        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            control.durable_sampled.notified(),
        )
        .await
        .expect("sampler must perform injected failed read");
        wait_for_ingress_metrics(
            metrics_addr,
            &[
                ("executed_tip", 0.0),
                ("durable_tip", 0.0),
                ("l1_verified_tip", 2.0),
                ("verification_distance", 0.0),
            ],
        )
        .await;
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            control.durable_sampled.notified(),
        )
        .await
        .expect("sampler must continue to the successful read");
        wait_for_ingress_metrics(
            metrics_addr,
            &[
                ("executed_tip", 0.0),
                ("durable_tip", 9.0),
                ("l1_verified_tip", 2.0),
                ("verification_distance", 0.0),
            ],
        )
        .await;
        drop((feed_tx, l1_tx));
        handle
            .wait_for_node_exit()
            .await
            .expect("sampler metrics node exits cleanly");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn restart_uses_journal_frontier_and_l1_only_launcher_registers_all_metrics() {
        const PHASE_ENV: &str = "ITE104_RESTART_TEST_PHASE";
        const DATADIR_ENV: &str = "ITE104_RESTART_TEST_DATADIR";
        let Some(phase) = std::env::var_os(PHASE_ENV) else {
            let datadir = tempfile::tempdir().expect("create cross-process restart datadir");
            for phase in ["seed", "verify"] {
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "launcher::tests::restart_uses_journal_frontier_and_l1_only_launcher_registers_all_metrics",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(PHASE_ENV, phase)
                    .env(DATADIR_ENV, datadir.path())
                    .output()
                    .expect("run isolated production restart phase");
                assert!(
                    output.status.success(),
                    "restart {phase} phase failed\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr),
                );
            }
            return;
        };
        let phase = phase.to_str().expect("restart phase is UTF-8");
        assert!(matches!(phase, "seed" | "verify"));
        let chain_spec = production_test_chain_spec();
        let datadir = std::path::PathBuf::from(
            std::env::var_os(DATADIR_ENV).expect("restart child receives datadir"),
        );
        let db = Arc::new(
            reth_db::init_db(
                datadir.join("db"),
                reth_db::mdbx::DatabaseArguments::new(reth_db::ClientVersion::default()),
            )
            .expect("open persistent restart test database"),
        );
        let mut authoritative = deposit_message();
        authoritative.sequence_number = 1;

        if phase == "seed" {
            let (first_feed_tx, first_feed_rx) = tokio::sync::mpsc::channel(1);
            drop(first_feed_tx);
            let (first_l1_tx, first_l1_rx) = tokio::sync::mpsc::channel(1);
            first_l1_tx.send(authoritative.clone()).await.unwrap();
            drop(first_l1_tx);
            let first_path = reth_node_core::dirs::MaybePlatformPath::<
                reth_node_core::dirs::DataDirPath,
            >::from(datadir.clone());
            let first_config = NodeConfig::test()
                .with_chain(chain_spec.clone())
                .with_datadir_args(reth_node_core::args::DatadirArgs {
                    datadir: first_path.clone(),
                    ..Default::default()
                });
            let first_data_dir = first_path
                .unwrap_or_chain_default(chain_spec.chain(), first_config.datadir.clone());
            let first_verified = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let first_runtime = Runtime::test();
            let first_handle = ArbLauncher {
                ctx: LaunchContext::new(first_runtime.clone(), first_data_dir),
                chain_id: 412346,
                genesis_block: 0,
                tuning: ArbEngineTuning::reth_defaults(),
                prune_config: None,
                init_message_journal_at_tip: false,
                l1_verified_tip: first_verified.clone(),
                feed_messages: first_feed_rx,
                l1_messages: first_l1_rx,
                feed_latency: None,
                rpc_addr: None,
                tx_log_stream: None,
                recovery_gate: RecoveryGate::new(true),
                recovery: None,
                driver_test_control: None,
            }
            .launch_node(
                NodeBuilder::new(first_config)
                    .with_database(db.clone())
                    .node(ArbNode),
            )
            .await
            .expect("first L1-only launch must succeed");
            first_handle
                .wait_for_node_exit()
                .await
                .expect("first L1-only launch must make its journal durable");
            assert_eq!(first_verified.load(std::sync::atomic::Ordering::Acquire), 1,);
            let first_task_manager = first_runtime
                .take_task_manager_handle()
                .expect("test runtime owns its task manager");
            drop(
                first_runtime
                    .initiate_graceful_shutdown()
                    .expect("stop first launch before reopening its datadir"),
            );
            tokio::time::timeout(std::time::Duration::from_secs(3), first_task_manager)
                .await
                .expect("first launch task manager must stop")
                .expect("join first launch task manager")
                .expect("first launch task manager must not panic");
            drop(first_runtime);
            return;
        }

        let metrics_probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let metrics_addr = metrics_probe.local_addr().unwrap();
        drop(metrics_probe);
        let (restart_feed_tx, restart_feed_rx) = tokio::sync::mpsc::channel(1);
        drop(restart_feed_tx);
        let (restart_l1_tx, restart_l1_rx) = tokio::sync::mpsc::channel(1);
        let restart_path = reth_node_core::dirs::MaybePlatformPath::<
            reth_node_core::dirs::DataDirPath,
        >::from(datadir);
        let mut restart_config = NodeConfig::test()
            .with_chain(chain_spec.clone())
            .with_datadir_args(reth_node_core::args::DatadirArgs {
                datadir: restart_path.clone(),
                ..Default::default()
            });
        restart_config.metrics.prometheus = Some(metrics_addr);
        let restart_data_dir = restart_path
            .unwrap_or_chain_default(chain_spec.chain(), restart_config.datadir.clone());
        let restart_verified = Arc::new(std::sync::atomic::AtomicU64::new(999));
        let restart_handle = ArbLauncher {
            ctx: LaunchContext::new(Runtime::test(), restart_data_dir),
            chain_id: 412346,
            genesis_block: 0,
            tuning: ArbEngineTuning::reth_defaults(),
            prune_config: None,
            init_message_journal_at_tip: false,
            l1_verified_tip: restart_verified.clone(),
            feed_messages: restart_feed_rx,
            l1_messages: restart_l1_rx,
            feed_latency: None,
            rpc_addr: None,
            tx_log_stream: None,
            recovery_gate: RecoveryGate::new(true),
            recovery: None,
            driver_test_control: None,
        }
        .launch_node(
            NodeBuilder::new(restart_config)
                .with_database(db)
                .node(ArbNode),
        )
        .await
        .expect("restart over the durable journal must succeed");
        let restart_observations = restart_handle.driver_test_observations.clone();
        assert_eq!(
            restart_verified.load(std::sync::atomic::Ordering::Acquire),
            1,
            "journal authority must overwrite an invalid higher caller seed",
        );

        let exposition = wait_for_ingress_metrics(
            metrics_addr,
            &[
                ("feed_queue_depth", 0.0),
                ("l1_queue_depth", 0.0),
                ("feed_dequeued_total", 0.0),
                ("l1_dequeued_total", 0.0),
                ("executed_tip", 1.0),
                ("durable_tip", 1.0),
                ("l1_verified_tip", 1.0),
                ("verification_distance", 0.0),
                ("last_feed_frame_timestamp_seconds", 0.0),
                ("last_feed_dequeue_timestamp_seconds", 0.0),
            ],
        )
        .await;
        let expected_families = [
            "reth_arb_reth_ingress_feed_queue_depth",
            "reth_arb_reth_ingress_l1_queue_depth",
            "reth_arb_reth_ingress_feed_dequeued_total",
            "reth_arb_reth_ingress_l1_dequeued_total",
            "reth_arb_reth_ingress_executed_tip",
            "reth_arb_reth_ingress_durable_tip",
            "reth_arb_reth_ingress_l1_verified_tip",
            "reth_arb_reth_ingress_verification_distance",
            "reth_arb_reth_ingress_last_feed_frame_timestamp_seconds",
            "reth_arb_reth_ingress_last_feed_dequeue_timestamp_seconds",
        ];
        let registered = exposition
            .lines()
            .filter_map(|line| line.strip_prefix("# TYPE reth_arb_reth_ingress_"))
            .count();
        assert_eq!(registered, expected_families.len(), "{exposition}");
        for family in expected_families {
            assert!(
                exposition.contains(&format!("# TYPE {family} ")),
                "missing production metric family {family}: {exposition}",
            );
            assert!(
                !exposition.contains(&format!("{family}{{")),
                "ingress metric family must have no labels: {family}",
            );
        }

        restart_l1_tx.send(authoritative).await.unwrap();
        drop(restart_l1_tx);
        wait_for_ingress_metrics(
            metrics_addr,
            &[
                ("feed_queue_depth", 0.0),
                ("l1_queue_depth", 0.0),
                ("feed_dequeued_total", 0.0),
                ("l1_dequeued_total", 1.0),
                ("executed_tip", 1.0),
                ("durable_tip", 1.0),
                ("l1_verified_tip", 1.0),
                ("verification_distance", 0.0),
                ("last_feed_frame_timestamp_seconds", 0.0),
                ("last_feed_dequeue_timestamp_seconds", 0.0),
            ],
        )
        .await;
        restart_handle
            .wait_for_node_exit()
            .await
            .expect("restart overlap verification must succeed");
        assert_eq!(
            restart_observations
                .selected_l1_batches
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
        );
        assert_eq!(
            restart_observations
                .engine_reconciliation_calls
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn direct_feed_execution_rejects_wrong_block_hash() {
        let mut message = deposit_message();
        message.sequence_number = 1;

        assert_driver_result(
            vec![ArbEngineInput::feed(message, Some(B256::repeat_byte(0xff)))],
            None,
            Some("sequencer feed block hash mismatch at sequence 1"),
            false,
            Some(0),
            0,
            Some(ArbEngineInputSource::Feed),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn buffered_feed_ahead_execution_rejects_wrong_block_hash() {
        let mut ahead = deposit_message();
        ahead.sequence_number = 2;
        let mut gap_closer = ahead.clone();
        gap_closer.sequence_number = 1;

        assert_driver_result(
            vec![
                ArbEngineInput::feed(ahead, Some(B256::repeat_byte(0xff))),
                ArbEngineInput::feed(gap_closer, None),
            ],
            None,
            Some("sequencer feed block hash mismatch at sequence 2"),
            false,
            Some(1),
            0,
            Some(ArbEngineInputSource::Feed),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn applied_feed_message_rejects_conflicting_l1_copy() {
        let mut feed = deposit_message();
        feed.sequence_number = 1;
        let mut l1 = feed.clone();
        l1.message_with_meta_data.delayed_messages_read += 1;

        assert_driver_result(
            vec![ArbEngineInput::feed(feed, None)],
            Some((1, vec![l1])),
            Some("feed/L1 message disagreement at applied sequence 1"),
            false,
            Some(1),
            0,
            Some(ArbEngineInputSource::L1),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn applied_feed_message_accepts_matching_l1_copy() {
        let mut feed = deposit_message();
        feed.sequence_number = 1;

        assert_driver_result(
            vec![ArbEngineInput::feed(feed.clone(), None)],
            Some((1, vec![feed])),
            None,
            false,
            None,
            1,
            None,
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn l1_overlap_plus_suffix_executes_and_counts_only_the_suffix() {
        let mut first = deposit_message();
        first.sequence_number = 1;
        let mut second = first.clone();
        second.sequence_number = 2;

        assert_driver_result(
            vec![ArbEngineInput::feed(first.clone(), None)],
            Some((1, vec![first, second])),
            None,
            false,
            None,
            2,
            None,
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn initial_l1_chunk_gap_is_deterministic_divergence() {
        let mut l1 = deposit_message();
        l1.sequence_number = 2;

        assert_driver_result(
            Vec::new(),
            Some((0, vec![l1])),
            Some("L1 reconciliation starts after the next executable sequence"),
            false,
            Some(0),
            0,
            Some(ArbEngineInputSource::L1),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn l1_gap_closing_suffix_compares_buffered_feed_before_execution() {
        let mut l1_first = deposit_message();
        l1_first.sequence_number = 1;
        let mut l1_second = l1_first.clone();
        l1_second.sequence_number = 2;
        let mut feed_ahead = l1_second.clone();
        feed_ahead
            .message_with_meta_data
            .l1_incoming_message
            .header
            .timestamp += 1;

        assert_driver_result(
            vec![ArbEngineInput::feed(feed_ahead, None)],
            Some((0, vec![l1_first, l1_second])),
            Some("feed/L1 message disagreement at sequence 2"),
            true,
            Some(0),
            0,
            Some(ArbEngineInputSource::Feed),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn l1_gap_closing_suffix_preserves_feed_hash_claim() {
        let mut l1_first = deposit_message();
        l1_first.sequence_number = 1;
        let mut l1_second = l1_first.clone();
        l1_second.sequence_number = 2;

        assert_driver_result(
            vec![ArbEngineInput::feed(
                l1_second.clone(),
                Some(B256::repeat_byte(0xff)),
            )],
            Some((0, vec![l1_first, l1_second])),
            Some("sequencer feed block hash mismatch at sequence 2"),
            true,
            Some(1),
            1,
            Some(ArbEngineInputSource::Feed),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn later_buffered_mismatch_cannot_mutate_overlap_authority() {
        let mut feed_first = deposit_message();
        feed_first.sequence_number = 1;
        let mut l1_second = feed_first.clone();
        l1_second.sequence_number = 2;
        let mut l1_third = feed_first.clone();
        l1_third.sequence_number = 3;
        let mut feed_third = l1_third.clone();
        feed_third
            .message_with_meta_data
            .l1_incoming_message
            .header
            .timestamp += 1;

        assert_driver_result(
            vec![
                ArbEngineInput::feed(feed_first.clone(), None),
                ArbEngineInput::feed(feed_third, None),
            ],
            Some((1, vec![feed_first, l1_second, l1_third])),
            Some("feed/L1 message disagreement at sequence 3"),
            true,
            Some(1),
            0,
            Some(ArbEngineInputSource::Feed),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn first_l1_chunk_cannot_skip_unverified_applied_prefix() {
        let mut feed_inputs = Vec::new();
        for sequence in 1..=4 {
            let mut message = deposit_message();
            message.sequence_number = sequence;
            feed_inputs.push(ArbEngineInput::feed(message, None));
        }
        let mut l1 = deposit_message();
        l1.sequence_number = 5;

        assert_driver_result(
            feed_inputs,
            Some((4, vec![l1])),
            Some("L1 overlap starts after the contiguous authority frontier"),
            false,
            Some(4),
            0,
            Some(ArbEngineInputSource::L1),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn l1_chunk_bulk_promotes_matching_prefix_and_leaves_feed_suffix_unsafe() {
        let mut feed_inputs = Vec::new();
        let mut l1_chunk = Vec::new();
        for sequence in 1..=3 {
            let mut message = deposit_message();
            message.sequence_number = sequence;
            feed_inputs.push(ArbEngineInput::feed(message.clone(), None));
            if sequence <= 2 {
                l1_chunk.push(message);
            }
        }

        assert_driver_result(feed_inputs, Some((3, l1_chunk)), None, false, None, 2, None).await;
    }

    fn deposit_message() -> BroadcastFeedMessage {
        serde_json::from_str(include_str!("../tests/fixtures/deposit_message_only.json"))
            .expect("parse feed fixture")
    }

    async fn assert_driver_result(
        inputs: Vec<ArbEngineInput>,
        l1_after_head: Option<(u64, Vec<BroadcastFeedMessage>)>,
        expected_error: Option<&str>,
        wait_for_feed_dequeue: bool,
        expected_error_tip: Option<u64>,
        expected_l1_verified_tip: u64,
        expected_marker_source: Option<ArbEngineInputSource>,
    ) {
        let expected_canonical_tip =
            inputs
                .iter()
                .map(ArbEngineInput::sequence_number)
                .chain(l1_after_head.iter().flat_map(|(_, messages)| {
                    messages.iter().map(|message| message.sequence_number)
                }))
                .max()
                .unwrap_or(0);
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
        let (feed_tx, feed_rx) = tokio::sync::mpsc::channel(inputs.len().max(1));
        let l1_capacity = l1_after_head
            .as_ref()
            .map_or(1, |(_, messages)| messages.len().max(1));
        let (l1_tx, l1_rx) = tokio::sync::mpsc::channel(l1_capacity);
        for input in inputs {
            feed_tx.send(input).await.expect("queue feed input");
        }
        let feed_tx = wait_for_feed_dequeue.then_some(feed_tx);

        let datadir = reth_db::test_utils::tempdir_path();
        let db = reth_db::test_utils::create_test_rw_db_with_datadir(&datadir);
        let maybe_path =
            reth_node_core::dirs::MaybePlatformPath::<reth_node_core::dirs::DataDirPath>::from(
                datadir,
            );
        let config = NodeConfig::test()
            .with_chain(chain_spec.clone())
            .with_datadir_args(reth_node_core::args::DatadirArgs {
                datadir: maybe_path.clone(),
                ..Default::default()
            });
        let data_dir =
            maybe_path.unwrap_or_chain_default(chain_spec.chain(), config.datadir.clone());
        let l1_verified_tip = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let launcher = ArbLauncher {
            ctx: LaunchContext::new(task_executor, data_dir),
            chain_id,
            genesis_block: 0,
            tuning: ArbEngineTuning::reth_defaults(),
            prune_config: None,
            init_message_journal_at_tip: false,
            l1_verified_tip: l1_verified_tip.clone(),
            feed_messages: feed_rx,
            l1_messages: l1_rx,
            feed_latency: None,
            rpc_addr: None,
            tx_log_stream: None,
            recovery_gate: RecoveryGate::new(true),
            recovery: None,
            driver_test_control: None,
        };
        let handle = launcher
            .launch_node(NodeBuilder::new(config).with_database(db).node(ArbNode))
            .await
            .expect("launch must succeed");
        let marker_path = {
            use reth_storage_api::StoragePath;
            handle
                .provider
                .database_provider_ro()
                .expect("open provider for marker path")
                .storage_path()
                .parent()
                .expect("database path has parent")
                .join("arb-message-divergence.json")
        };
        let result_provider = handle.provider.clone();
        let driver_test_observations = handle.driver_test_observations.clone();
        if let Some(feed_tx) = feed_tx {
            tokio::time::timeout(std::time::Duration::from_secs(10), feed_tx.reserve())
                .await
                .expect("launcher must dequeue the feed-ahead input")
                .expect("feed channel must remain open");
        }
        if let Some((head, messages)) = l1_after_head {
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    if handle.provider.best_block_number().unwrap_or_default() >= head {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("feed message must become canonical");
            for message in messages {
                l1_tx
                    .try_send(message)
                    .expect("queue complete L1 reconciliation chunk");
            }
        }
        drop(l1_tx);

        let result = handle.wait_for_node_exit().await;
        match expected_error {
            Some(expected) => {
                let error = result.expect_err("fail-closed input must stop the driver");
                let divergence_sequence = arb_reth_engine::message_divergence_sequence(&error)
                    .expect("deterministic message failure must identify its sequence");
                let detail = format!("{error:#}");
                assert!(detail.contains(expected), "unexpected error: {detail}");
                let marker: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(&marker_path).expect("divergence marker must be readable"),
                )
                .expect("divergence marker must contain JSON");
                assert_eq!(
                    marker["incoming_message"]["sequenceNumber"].as_u64(),
                    Some(divergence_sequence),
                    "marker must retain the exact input that caused a buffered failure",
                );
                assert_eq!(
                    marker["incoming_source"].as_str(),
                    expected_marker_source.map(|source| match source {
                        ArbEngineInputSource::Feed => "feed",
                        ArbEngineInputSource::L1 => "l1",
                    }),
                    "marker must retain the exact source representation that diverged",
                );
                if let Some(expected_tip) = expected_error_tip {
                    assert_eq!(
                        result_provider.best_block_number().unwrap_or_default(),
                        expected_tip,
                        "no mismatching buffered message may execute before reconciliation",
                    );
                }
            }
            None => {
                result.expect("matching L1 chunk must be accepted");
                assert_eq!(
                    result_provider.best_block_number().unwrap_or_default(),
                    expected_canonical_tip,
                    "already-applied overlap must not execute another block",
                );
            }
        }
        assert_eq!(
            l1_verified_tip.load(std::sync::atomic::Ordering::Acquire),
            expected_l1_verified_tip,
        );
        assert_eq!(
            marker_path.exists(),
            expected_error.is_some(),
            "only deterministic message failures create the startup-blocking marker",
        );
        assert_eq!(
            driver_test_observations
                .selected_l1_batches
                .load(std::sync::atomic::Ordering::Relaxed),
            driver_test_observations
                .engine_reconciliation_calls
                .load(std::sync::atomic::Ordering::Relaxed),
            "every selected production L1 batch must invoke bulk reconciliation exactly once",
        );
        if expected_error.is_none() {
            assert_eq!(
                driver_test_observations
                    .benchmark_executed
                    .load(std::sync::atomic::Ordering::Relaxed),
                result_provider.best_block_number().unwrap_or_default(),
                "overlap-only production work must add zero to benchmark execution accounting",
            );
        }
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
        // DB has genesis_block 0, so the first digested message is index 1). Four messages with a
        // persistence threshold of two guarantee a second save after sender pruning has run.
        let (tx, feed_rx) = tokio::sync::mpsc::channel::<ArbEngineInput>(4);
        let (l1_tx, l1_rx) = tokio::sync::mpsc::channel::<BroadcastFeedMessage>(1);
        drop(l1_tx);
        for sequence_number in 1..=4 {
            let mut message = feed_msg.clone();
            message.sequence_number = sequence_number;
            tx.send(ArbEngineInput::feed(message, None)).await.unwrap();
        }
        drop(tx);

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

        let node_builder_with_components = NodeBuilder::new(config).with_database(db).node(ArbNode);

        let launcher = ArbLauncher {
            ctx: LaunchContext::new(task_executor.clone(), data_dir),
            chain_id,
            genesis_block: 0,
            tuning: ArbEngineTuning::reth_defaults(),
            prune_config: Some(prune_config),
            init_message_journal_at_tip: false,
            l1_verified_tip: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            feed_messages: feed_rx,
            l1_messages: l1_rx,
            feed_latency: None,
            rpc_addr: None,
            tx_log_stream: None,
            recovery_gate: RecoveryGate::new(true),
            recovery: None,
            driver_test_control: None,
        };

        let handle = launcher
            .launch_node(node_builder_with_components)
            .await
            .expect("launch must succeed");

        let provider = handle.provider.clone();
        handle
            .wait_for_node_exit()
            .await
            .expect("driver task must succeed");

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
        let (tx, feed_rx) = tokio::sync::mpsc::channel::<ArbEngineInput>(4096);
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
            tuning: ArbEngineTuning {
                persistence_threshold: 128,
                memory_block_buffer_target: 0,
                persistence_backpressure_threshold: 512,
                execution_cache_size: 256 * 1024 * 1024,
                share_execution_cache_with_payload_builder: true,
                share_sparse_trie_with_payload_builder: false,
            },
            prune_config: None,
            init_message_journal_at_tip: false,
            l1_verified_tip: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            feed_messages: feed_rx,
            l1_messages: l1_rx,
            feed_latency: None,
            rpc_addr: None,
            tx_log_stream: None,
            recovery_gate: RecoveryGate::new(true),
            recovery: None,
            driver_test_control: None,
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
            tx.send(ArbEngineInput::feed(message, None))
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
