//! Metrics for the live sequencer-feed path.

use arb_reth_engine::ArbAppliedMessageTiming;
use reth_metrics::{
    Metrics,
    metrics::{Counter, Gauge, Histogram},
};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const MAX_TRACKED_MESSAGES: usize = 16_384;

/// Source-independent ingress and execution-frontier metrics.
#[derive(Metrics)]
#[metrics(scope = "arb_reth.ingress")]
struct IngressMetricHandles {
    /// Sampled logical Feed backlog, including an unselected scheduler-owned head.
    feed_queue_depth: Gauge,
    /// Sampled logical L1 backlog, including an unselected scheduler-owned head.
    l1_queue_depth: Gauge,
    /// Feed items physically removed from the bounded driver channel.
    feed_dequeued_total: Counter,
    /// L1 items physically removed from the bounded driver channel.
    l1_dequeued_total: Counter,
    /// Latest canonical in-memory block number observed by the driver.
    executed_tip: Gauge,
    /// Latest sampled durable database block number.
    durable_tip: Gauge,
    /// Latest journal-durable contiguous L1-authoritative block number.
    l1_verified_tip: Gauge,
    /// Executed blocks not yet covered by the journal-durable L1 authority frontier.
    verification_distance: Gauge,
    /// Unix timestamp seconds of the latest live-feed WebSocket text or binary frame.
    last_feed_frame_timestamp_seconds: Gauge,
    /// Unix timestamp seconds of the latest physical Feed driver-channel dequeue.
    last_feed_dequeue_timestamp_seconds: Gauge,
}

struct IngressMetricsInner {
    handles: IngressMetricHandles,
    executed_tip: AtomicU64,
    sampled_verified_tip: AtomicU64,
    latest_feed_frame_timestamp: AtomicU64,
    #[cfg(test)]
    executed_publish_pause: ExecutedPublishPause,
    #[cfg(test)]
    frame_before_max_pause: ExecutedPublishPause,
    #[cfg(test)]
    frame_after_max_pause: ExecutedPublishPause,
}

#[cfg(test)]
#[derive(Default)]
struct ExecutedPublishPause {
    requested: std::sync::atomic::AtomicBool,
    paused: tokio::sync::Notify,
    resumed: std::sync::Mutex<bool>,
    resume: std::sync::Condvar,
}

/// Cloneable, lock-free handle shared by ingress, feed followers, and the frontier sampler.
#[derive(Clone)]
pub(crate) struct IngressMetrics {
    inner: Arc<IngressMetricsInner>,
}

impl IngressMetrics {
    /// Register all ten metrics. Construct this only after the Prometheus recorder is installed.
    pub(crate) fn new() -> Self {
        Self::from_handles(IngressMetricHandles::default())
    }

    fn from_handles(handles: IngressMetricHandles) -> Self {
        handles.feed_queue_depth.set(0.0);
        handles.l1_queue_depth.set(0.0);
        handles.feed_dequeued_total.increment(0);
        handles.l1_dequeued_total.increment(0);
        handles.executed_tip.set(0.0);
        handles.durable_tip.set(0.0);
        handles.l1_verified_tip.set(0.0);
        handles.verification_distance.set(0.0);
        handles.last_feed_frame_timestamp_seconds.set(0.0);
        handles.last_feed_dequeue_timestamp_seconds.set(0.0);
        Self {
            inner: Arc::new(IngressMetricsInner {
                handles,
                executed_tip: AtomicU64::new(0),
                sampled_verified_tip: AtomicU64::new(0),
                latest_feed_frame_timestamp: AtomicU64::new(0),
                #[cfg(test)]
                executed_publish_pause: ExecutedPublishPause::default(),
                #[cfg(test)]
                frame_before_max_pause: ExecutedPublishPause::default(),
                #[cfg(test)]
                frame_after_max_pause: ExecutedPublishPause::default(),
            }),
        }
    }

    pub(crate) fn set_queue_depths(&self, feed: usize, l1: usize) {
        self.inner.handles.feed_queue_depth.set(feed as f64);
        self.inner.handles.l1_queue_depth.set(l1 as f64);
    }

    pub(crate) fn record_feed_dequeues(&self, count: usize) {
        self.inner
            .handles
            .feed_dequeued_total
            .increment(count as u64);
        let timestamp = unix_timestamp_seconds();
        self.inner
            .handles
            .last_feed_dequeue_timestamp_seconds
            .set(timestamp as f64);
    }

    pub(crate) fn record_l1_dequeues(&self, count: usize) {
        self.inner.handles.l1_dequeued_total.increment(count as u64);
    }

    pub(crate) fn record_feed_frame(&self) {
        let timestamp = unix_timestamp_seconds();
        #[cfg(test)]
        Self::pause_test_publish(&self.inner.frame_before_max_pause);
        let previous = self
            .inner
            .latest_feed_frame_timestamp
            .fetch_max(timestamp, Ordering::AcqRel);
        let mut latest = previous.max(timestamp);
        #[cfg(test)]
        Self::pause_test_publish(&self.inner.frame_after_max_pause);
        loop {
            self.inner
                .handles
                .last_feed_frame_timestamp_seconds
                .set(latest as f64);
            let current = self
                .inner
                .latest_feed_frame_timestamp
                .load(Ordering::Acquire);
            if current == latest {
                break;
            }
            latest = current;
        }
    }

    pub(crate) fn set_executed_tip(&self, tip: u64) {
        self.inner.executed_tip.store(tip, Ordering::Release);
        loop {
            self.inner.handles.executed_tip.set(tip as f64);
            let verified = self.inner.sampled_verified_tip.load(Ordering::Acquire);
            #[cfg(test)]
            self.pause_executed_publish_after_verified_load();
            self.inner
                .handles
                .verification_distance
                .set(tip.saturating_sub(verified) as f64);
            if self.inner.sampled_verified_tip.load(Ordering::Acquire) == verified {
                break;
            }
        }
    }

    pub(crate) fn executed_tip(&self) -> u64 {
        self.inner.executed_tip.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn pause_next_executed_publish(&self) {
        self.inner
            .executed_publish_pause
            .requested
            .store(true, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) async fn wait_executed_publish_paused(&self) {
        self.inner.executed_publish_pause.paused.notified().await;
    }

    #[cfg(test)]
    pub(crate) fn resume_executed_publish(&self) {
        let mut resumed = self
            .inner
            .executed_publish_pause
            .resumed
            .lock()
            .expect("executed publish pause lock poisoned");
        *resumed = true;
        self.inner.executed_publish_pause.resume.notify_one();
    }

    #[cfg(test)]
    fn pause_executed_publish_after_verified_load(&self) {
        Self::pause_test_publish(&self.inner.executed_publish_pause);
    }

    #[cfg(test)]
    fn pause_test_publish(pause: &ExecutedPublishPause) {
        if !pause.requested.swap(false, Ordering::AcqRel) {
            return;
        }
        pause.paused.notify_one();
        let mut resumed = pause
            .resumed
            .lock()
            .expect("metric publish pause lock poisoned");
        while !*resumed {
            resumed = pause
                .resume
                .wait(resumed)
                .expect("metric publish pause lock poisoned");
        }
        *resumed = false;
    }

    #[cfg(test)]
    pub(crate) fn pause_next_frame_before_max(&self) {
        self.inner
            .frame_before_max_pause
            .requested
            .store(true, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) async fn wait_frame_before_max_paused(&self) {
        self.inner.frame_before_max_pause.paused.notified().await;
    }

    #[cfg(test)]
    pub(crate) fn resume_frame_before_max(&self) {
        Self::resume_test_publish(&self.inner.frame_before_max_pause);
    }

    #[cfg(test)]
    pub(crate) fn pause_next_frame_after_max(&self) {
        self.inner
            .frame_after_max_pause
            .requested
            .store(true, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) async fn wait_frame_after_max_paused(&self) {
        self.inner.frame_after_max_pause.paused.notified().await;
    }

    #[cfg(test)]
    pub(crate) fn resume_frame_after_max(&self) {
        Self::resume_test_publish(&self.inner.frame_after_max_pause);
    }

    #[cfg(test)]
    fn resume_test_publish(pause: &ExecutedPublishPause) {
        let mut resumed = pause
            .resumed
            .lock()
            .expect("metric publish pause lock poisoned");
        *resumed = true;
        pause.resume.notify_one();
    }

    /// Initialize the shared executed frontier and all four frontier gauges from one startup sample.
    pub(crate) fn initialize_frontiers(&self, executed: u64, durable: u64, verified: u64) {
        let distance = executed.saturating_sub(verified);
        self.inner.executed_tip.store(executed, Ordering::Release);
        self.inner
            .sampled_verified_tip
            .store(verified, Ordering::Release);
        self.inner.handles.executed_tip.set(executed as f64);
        self.inner.handles.durable_tip.set(durable as f64);
        self.inner.handles.l1_verified_tip.set(verified as f64);
        self.inner
            .handles
            .verification_distance
            .set(distance as f64);
    }

    /// Apply one sampler tick while preserving the previous durable value on a read failure.
    pub(crate) fn refresh_frontiers<E>(
        &self,
        durable: &mut u64,
        durable_read: Result<u64, E>,
        verified: u64,
        captured_executed: u64,
    ) -> Result<(), E> {
        let result = match durable_read {
            Ok(sample) => {
                *durable = sample;
                Ok(())
            }
            Err(error) => Err(error),
        };
        self.inner
            .sampled_verified_tip
            .store(verified, Ordering::Release);
        self.inner.handles.durable_tip.set(*durable as f64);
        self.inner.handles.l1_verified_tip.set(verified as f64);

        let mut executed = captured_executed;
        loop {
            self.inner.handles.executed_tip.set(executed as f64);
            self.inner
                .handles
                .verification_distance
                .set(executed.saturating_sub(verified) as f64);
            let current = self.executed_tip();
            if current == executed {
                break;
            }
            executed = current;
        }
        result
    }
}

fn unix_timestamp_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// End-to-end latency from receiving a WebSocket data frame to the corresponding block becoming
/// the canonical in-memory head.
#[derive(Metrics)]
#[metrics(scope = "arb_reth.feed")]
struct FeedLatencyMetrics {
    /// Time from receiving a sequencer-feed WebSocket frame to canonical in-memory state.
    frame_to_canonical_seconds: Histogram,
    /// WebSocket text/binary conversion and JSON decoding before a message is ready for the channel.
    frame_decode_seconds: Histogram,
    /// Channel send backpressure and time waiting in the driver input channel.
    channel_wait_seconds: Histogram,
    /// Time after driver dequeue before this sequence becomes eligible for in-order application.
    sequencing_wait_seconds: Histogram,
    /// Constructing native payload attributes from the ordered message and current parent.
    payload_attributes_seconds: Histogram,
    /// Full Reth payload-job lifecycle, including the builder execution nested within it.
    payload_job_seconds: Histogram,
    /// Payload-job launch through the attributes FCU response.
    payload_job_launch_seconds: Histogram,
    /// Waiting for the launched payload job after the attributes FCU response.
    payload_job_resolve_seconds: Histogram,
    /// Payload-job lifecycle time outside measured block production.
    payload_job_overhead_seconds: Histogram,
    /// ArbOS execution, state-root calculation, and block/header construction.
    block_production_seconds: Histogram,
    /// Block-production work outside the named production sub-phases.
    block_production_unattributed_seconds: Histogram,
    /// Parent-state provider setup before block production.
    block_parent_state_seconds: Histogram,
    /// Feed-message digesting and next-block environment construction.
    block_message_preparation_seconds: Histogram,
    /// Creation of revm's journaled state over the parent provider.
    block_state_setup_seconds: Histogram,
    /// ArbOS pre-execution and transaction execution.
    block_execution_seconds: Histogram,
    /// Block-builder creation, ArbOS pre-execution changes, and base-fee setup.
    block_execution_setup_seconds: Histogram,
    /// Construction of ArbOS's mandatory internal start-block transaction.
    block_start_block_transaction_construction_seconds: Histogram,
    /// Execution of ArbOS's mandatory internal start-block transaction.
    block_start_block_transaction_seconds: Histogram,
    /// Execution of derived user and retry transactions, including retry scheduling.
    block_derived_transactions_seconds: Histogram,
    /// Derived transaction execution and commit work, excluding retry scheduling.
    block_derived_transaction_execution_seconds: Histogram,
    /// Extraction and enqueueing of retries emitted by successful derived transactions.
    block_derived_retry_scheduling_seconds: Histogram,
    /// Remainder after named derived-transaction phases, retained for exact accounting.
    block_derived_transactions_unattributed_seconds: Histogram,
    /// Remainder after named block-execution phases, retained for exact accounting.
    block_execution_unattributed_seconds: Histogram,
    /// Total generic block finalization after ArbOS transactions complete.
    block_finish_seconds: Histogram,
    /// ArbOS executor finalization, principally reading post-execution header metadata.
    block_finish_executor_seconds: Histogram,
    /// Hashing the executed bundle into the post-state representation used by the trie.
    block_finish_hashed_state_seconds: Histogram,
    /// Computing the post-state root and trie updates.
    block_finish_state_root_seconds: Histogram,
    /// Waiting for the sparse state-root task after ArbOS execution.
    block_finish_state_root_task_wait_seconds: Histogram,
    /// Transaction/receipt roots, logs bloom, and Arbitrum header/block assembly.
    block_finish_assembly_seconds: Histogram,
    /// Generic finalization work not assigned to one of the named phases.
    block_finish_unattributed_seconds: Histogram,
    /// Full engine-tree handoff until canonical state is observable.
    engine_handoff_seconds: Histogram,
    /// Sending the executed block to reth's engine tree.
    engine_insert_seconds: Histogram,
    /// Forkchoice request and response through reth's engine tree.
    engine_forkchoice_seconds: Histogram,
    /// Waiting for the canonical in-memory provider state to observe the block.
    canonicalization_wait_seconds: Histogram,
    /// In-order apply-path work not covered by the named engine phases.
    engine_apply_overhead_seconds: Histogram,
    /// Total in-order apply path from payload attributes through canonical state.
    engine_apply_total_seconds: Histogram,
    /// Samples that could not be tracked without blocking the feed or execution task.
    tracking_dropped_total: Counter,
}

struct FeedLatencyInner {
    messages: Mutex<BTreeMap<u64, FeedMessageTiming>>,
    metrics: OnceLock<FeedLatencyMetrics>,
}

#[derive(Clone, Copy)]
struct FeedMessageTiming {
    frame_received_at: Instant,
    ready_for_channel_at: Option<Instant>,
    driver_dequeued_at: Option<Instant>,
}

/// Correlates an inbound feed message with the point at which its block is canonical in reth's
/// shared in-memory state. Contention intentionally drops a sample instead of delaying either the
/// WebSocket reader or the engine driver.
#[derive(Clone)]
pub struct FeedLatencyTracker {
    inner: Arc<FeedLatencyInner>,
}

impl FeedLatencyTracker {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(FeedLatencyInner {
                messages: Mutex::new(BTreeMap::new()),
                metrics: OnceLock::new(),
            }),
        }
    }

    /// Records the instant at which a WebSocket data frame was received, before parsing it.
    pub(crate) fn record_frame_arrival(&self, sequence_number: u64, received_at: Instant) {
        let mut messages = match self.inner.messages.try_lock() {
            Ok(messages) => messages,
            Err(_) => {
                self.metrics().tracking_dropped_total.increment(1);
                return;
            }
        };

        // Keep the first receipt for a sequence. A duplicated frame must not overwrite the
        // latency start of the message that was actually queued first.
        if messages.contains_key(&sequence_number) {
            return;
        }
        if messages.len() == MAX_TRACKED_MESSAGES {
            messages.pop_first();
            self.metrics().tracking_dropped_total.increment(1);
        }
        messages.insert(
            sequence_number,
            FeedMessageTiming {
                frame_received_at: received_at,
                ready_for_channel_at: None,
                driver_dequeued_at: None,
            },
        );
    }

    /// Records the instant after a WebSocket frame has been decoded and the message is ready to
    /// send through the driver channel.
    pub(crate) fn record_ready_for_channel(&self, sequence_number: u64, ready_at: Instant) {
        let mut messages = match self.inner.messages.try_lock() {
            Ok(messages) => messages,
            Err(_) => {
                self.metrics().tracking_dropped_total.increment(1);
                return;
            }
        };
        if let Some(timing) = messages.get_mut(&sequence_number) {
            timing.ready_for_channel_at = Some(ready_at);
        }
    }

    /// Records the instant at which the engine driver dequeues a message.
    pub(crate) fn record_driver_dequeue(&self, sequence_number: u64, dequeued_at: Instant) {
        let mut messages = match self.inner.messages.try_lock() {
            Ok(messages) => messages,
            Err(_) => {
                self.metrics().tracking_dropped_total.increment(1);
                return;
            }
        };
        if let Some(timing) = messages.get_mut(&sequence_number) {
            timing.driver_dequeued_at = Some(dequeued_at);
        }
    }

    /// Records the end of the measurement and each engine phase after reth has canonicalized the
    /// corresponding block.
    pub(crate) fn record_canonical(&self, sequence_number: u64, applied: ArbAppliedMessageTiming) {
        let timing = match self.inner.messages.try_lock() {
            Ok(mut messages) => messages.remove(&sequence_number),
            Err(_) => {
                self.metrics().tracking_dropped_total.increment(1);
                return;
            }
        };

        if let Some(timing) = timing {
            let metrics = self.metrics();
            metrics.frame_to_canonical_seconds.record(
                applied
                    .completed_at
                    .saturating_duration_since(timing.frame_received_at)
                    .as_secs_f64(),
            );
            if let Some(ready_at) = timing.ready_for_channel_at {
                metrics.frame_decode_seconds.record(
                    ready_at
                        .saturating_duration_since(timing.frame_received_at)
                        .as_secs_f64(),
                );
                if let Some(dequeued_at) = timing.driver_dequeued_at {
                    metrics.channel_wait_seconds.record(
                        dequeued_at
                            .saturating_duration_since(ready_at)
                            .as_secs_f64(),
                    );
                    metrics.sequencing_wait_seconds.record(
                        applied
                            .started_at
                            .saturating_duration_since(dequeued_at)
                            .as_secs_f64(),
                    );
                }
            }
            metrics
                .payload_attributes_seconds
                .record(applied.payload_attributes.as_secs_f64());
            metrics
                .payload_job_seconds
                .record(applied.payload_job.as_secs_f64());
            metrics
                .payload_job_launch_seconds
                .record(applied.payload_job_launch.as_secs_f64());
            metrics
                .payload_job_resolve_seconds
                .record(applied.payload_job_resolve.as_secs_f64());
            metrics
                .payload_job_overhead_seconds
                .record(applied.payload_job_overhead.as_secs_f64());
            metrics
                .block_production_seconds
                .record(applied.block_production.as_secs_f64());
            metrics
                .block_production_unattributed_seconds
                .record(applied.block_production_unattributed.as_secs_f64());
            metrics
                .block_parent_state_seconds
                .record(applied.block_parent_state.as_secs_f64());
            metrics
                .block_message_preparation_seconds
                .record(applied.block_message_preparation.as_secs_f64());
            metrics
                .block_state_setup_seconds
                .record(applied.block_state_setup.as_secs_f64());
            metrics
                .block_execution_seconds
                .record(applied.block_execution.as_secs_f64());
            metrics
                .block_execution_setup_seconds
                .record(applied.block_execution_setup.as_secs_f64());
            metrics
                .block_start_block_transaction_construction_seconds
                .record(
                    applied
                        .block_start_block_transaction_construction
                        .as_secs_f64(),
                );
            metrics
                .block_start_block_transaction_seconds
                .record(applied.block_start_block_transaction.as_secs_f64());
            metrics
                .block_derived_transactions_seconds
                .record(applied.block_derived_transactions.as_secs_f64());
            metrics
                .block_derived_transaction_execution_seconds
                .record(applied.block_derived_transaction_execution.as_secs_f64());
            metrics
                .block_derived_retry_scheduling_seconds
                .record(applied.block_derived_retry_scheduling.as_secs_f64());
            metrics
                .block_derived_transactions_unattributed_seconds
                .record(
                    applied
                        .block_derived_transactions_unattributed
                        .as_secs_f64(),
                );
            metrics
                .block_execution_unattributed_seconds
                .record(applied.block_execution_unattributed.as_secs_f64());
            metrics
                .block_finish_seconds
                .record(applied.block_finish.as_secs_f64());
            metrics
                .block_finish_executor_seconds
                .record(applied.block_finish_executor.as_secs_f64());
            metrics
                .block_finish_hashed_state_seconds
                .record(applied.block_finish_hashed_state.as_secs_f64());
            metrics
                .block_finish_state_root_seconds
                .record(applied.block_finish_state_root.as_secs_f64());
            if let Some(wait) = applied.block_finish_state_root_task_wait {
                metrics
                    .block_finish_state_root_task_wait_seconds
                    .record(wait.as_secs_f64());
            }
            metrics
                .block_finish_assembly_seconds
                .record(applied.block_finish_assembly.as_secs_f64());
            metrics
                .block_finish_unattributed_seconds
                .record(applied.block_finish_unattributed.as_secs_f64());
            metrics
                .engine_handoff_seconds
                .record(applied.engine_handoff.as_secs_f64());
            metrics
                .engine_insert_seconds
                .record(applied.engine_insert.as_secs_f64());
            metrics
                .engine_forkchoice_seconds
                .record(applied.engine_forkchoice.as_secs_f64());
            metrics
                .canonicalization_wait_seconds
                .record(applied.canonicalization_wait.as_secs_f64());
            // The builder execution is nested inside `payload_job`; forkchoice and canonical
            // observation are nested inside `engine_handoff`. Only subtract the exclusive outer
            // phases so this remainder stays additive with the end-to-end apply duration.
            let named = applied.payload_attributes + applied.payload_job + applied.engine_handoff;
            metrics
                .engine_apply_overhead_seconds
                .record(applied.total.saturating_sub(named).as_secs_f64());
            metrics
                .engine_apply_total_seconds
                .record(applied.total.as_secs_f64());
        }
    }

    fn metrics(&self) -> &FeedLatencyMetrics {
        // The live-feed task starts only after `with_prometheus_server` has installed reth's
        // recorder, so metric handles are never initialized against the no-op recorder.
        self.inner.metrics.get_or_init(FeedLatencyMetrics::default)
    }
}
