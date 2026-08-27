//! `arb-reth-engine`: the engine-tree driver and the payload-type plumbing it needs.
//!
//! [`ArbEngineDriver`] stands up reth's `EngineApiTreeHandler` and mints execute-to-derive blocks
//! by sending `InsertExecutedBlock` + `ForkchoiceUpdated` to the tree (no re-execution), reading
//! parent state through reth's native provider path. This crate also owns
//! the payload-type stubs ([`ArbPayloadTypes`] and friends) that exist only to satisfy
//! `NodeTypes::Payload`, and the minimal [`ArbPayloadValidator`] / `ConfigureEngineEvm` impls the
//! engine-tree generics require. They live here rather than in the node crate so the driver can
//! depend on them without a dependency cycle.

extern crate alloc;

use alloc::sync::Arc;

use alloy_eips::eip4895::Withdrawal;
use alloy_primitives::{B256, Bytes, U256};
use alloy_rpc_types_engine::{ExecutionData, ExecutionPayload as AlloyExecutionPayload, PayloadId};
use reth_execution_cache::CacheStats;
use reth_payload_primitives::{
    BuiltPayload, BuiltPayloadExecutedBlock, ExecutionPayload, PayloadAttributes, PayloadTypes,
};
use reth_primitives_traits::{NodePrimitives, SealedBlock};

use arbitrum_alloy_consensus::reth::ArbPrimitives;

pub mod engine;
pub mod engine_spike;
mod message_compare;
mod message_journal;
pub mod native_payload;
mod storage_v2;
mod tx_log_stream;

#[cfg(debug_assertions)]
pub use engine::ArbEngineLifecycleProbe;
pub use engine::{
    ArbAppliedMessageTiming, ArbEngineDriver, ArbEngineTuning, ArbMessageDivergence,
    is_message_divergence, message_divergence_sequence, wait_for_head,
};
pub use engine_spike::ArbPayloadValidator;
pub use message_compare::{ArbMessageEnrichment, ArbMessageFingerprint, fingerprint_message};
pub use message_journal::{
    DIVERGENCE_MARKER_FILE, MESSAGE_JOURNAL_FILE, MessageJournalAnchor, MessageJournalEntry,
    MessageJournalInspection, clear_divergence_marker_at, divergence_marker_path,
    inspect_message_journal, message_journal_path, rewrite_journal_to_identity_at,
    truncate_journal_at, validate_journal_target_at,
};
pub use native_payload::ArbPayloadBuilder;
pub use tx_log_stream::{
    ArbExecutionFrontier, ArbExecutionFrontierStore, ArbTxExecutionKind, ArbTxLogBroadcaster,
    ArbTxLogEvent,
};

/// Provenance of an ordered message submitted to the engine driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArbEngineInputSource {
    /// Message decoded from a sequencer feed or replay file.
    Feed,
    /// Message derived from canonical L1 data.
    L1,
}

/// Source-aware input for one locally produced Arbitrum block.
#[derive(Clone, Debug)]
pub struct ArbEngineInput {
    message: arbitrum_alloy_sequencer::sequencer::feed::BroadcastFeedMessage,
    source: ArbEngineInputSource,
    claimed_block_hash: Option<B256>,
}

impl ArbEngineInput {
    /// Wraps a sequencer-feed message and its optional top-level `blockHash` claim.
    pub const fn feed(
        message: arbitrum_alloy_sequencer::sequencer::feed::BroadcastFeedMessage,
        claimed_block_hash: Option<B256>,
    ) -> Self {
        Self {
            message,
            source: ArbEngineInputSource::Feed,
            claimed_block_hash,
        }
    }

    /// Wraps an L1-derived message, which has no sequencer-feed hash claim.
    pub const fn l1(
        message: arbitrum_alloy_sequencer::sequencer::feed::BroadcastFeedMessage,
    ) -> Self {
        Self {
            message,
            source: ArbEngineInputSource::L1,
            claimed_block_hash: None,
        }
    }

    /// Returns the ordered message body.
    pub const fn message(
        &self,
    ) -> &arbitrum_alloy_sequencer::sequencer::feed::BroadcastFeedMessage {
        &self.message
    }

    /// Returns this input's provenance.
    pub const fn source(&self) -> ArbEngineInputSource {
        self.source
    }

    /// Returns the optional sequencer-feed block hash claim.
    pub const fn claimed_block_hash(&self) -> Option<B256> {
        self.claimed_block_hash
    }

    pub(crate) const fn with_claimed_block_hash(
        mut self,
        claimed_block_hash: Option<B256>,
    ) -> Self {
        self.claimed_block_hash = claimed_block_hash;
        self
    }

    /// Returns the feed sequence number used for ordering.
    pub const fn sequence_number(&self) -> u64 {
        self.message.sequence_number
    }
}

/// An executed Arbitrum payload produced by the local payload builder.
#[derive(Debug, Clone)]
pub struct ArbBuiltPayload {
    executed: BuiltPayloadExecutedBlock<ArbPrimitives>,
    fees: U256,
    production_timing: engine::ArbBlockProductionTiming,
    execution_cache_stats: Option<Arc<CacheStats>>,
}

impl ArbBuiltPayload {
    /// Wraps a block that was executed during local payload construction.
    pub(crate) fn from_executed(
        executed: BuiltPayloadExecutedBlock<ArbPrimitives>,
        fees: U256,
        production_timing: engine::ArbBlockProductionTiming,
        execution_cache_stats: Option<Arc<CacheStats>>,
    ) -> Self {
        Self {
            executed,
            fees,
            production_timing,
            execution_cache_stats,
        }
    }

    /// Returns the local build breakdown captured before the payload entered the engine tree.
    pub(crate) const fn production_timing(&self) -> engine::ArbBlockProductionTiming {
        self.production_timing
    }

    /// Returns cache statistics collected during this payload's execution.
    pub(crate) fn execution_cache_stats(&self) -> Option<Arc<CacheStats>> {
        self.execution_cache_stats.clone()
    }
}

impl BuiltPayload for ArbBuiltPayload {
    type Primitives = ArbPrimitives;

    fn block(&self) -> &SealedBlock<<Self::Primitives as NodePrimitives>::Block> {
        self.executed.recovered_block.sealed_block()
    }

    fn fees(&self) -> U256 {
        self.fees
    }

    fn requests(&self) -> Option<alloy_eips::eip7685::Requests> {
        None
    }

    fn executed_block(&self) -> Option<BuiltPayloadExecutedBlock<Self::Primitives>> {
        Some(self.executed.clone())
    }
}

/// Thin wrapper around [`ExecutionData`] for Arbitrum.
///
/// Wraps alloy's `ExecutionData` so that `From<ArbBuiltPayload>` can be implemented (orphan rule:
/// we own both types). Exists solely to satisfy `NodeTypes::Payload`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ArbExecutionData(pub ExecutionData);

impl From<ArbBuiltPayload> for ArbExecutionData {
    fn from(payload: ArbBuiltPayload) -> Self {
        let block_hash = payload.executed.recovered_block.hash();
        let block = Arc::unwrap_or_clone(payload.executed.recovered_block).into_block();
        let (execution_payload, sidecar) = AlloyExecutionPayload::from_block_unchecked_with_extras(
            block_hash, &block, None, // no block access list
        );
        ArbExecutionData(ExecutionData {
            payload: execution_payload,
            sidecar,
        })
    }
}

impl ExecutionPayload for ArbExecutionData {
    fn parent_hash(&self) -> alloy_primitives::B256 {
        self.0.parent_hash()
    }

    fn block_hash(&self) -> alloy_primitives::B256 {
        self.0.block_hash()
    }

    fn block_number(&self) -> u64 {
        self.0.block_number()
    }

    fn withdrawals(&self) -> Option<&alloc::vec::Vec<Withdrawal>> {
        self.0.withdrawals()
    }

    fn block_access_list(&self) -> Option<&Bytes> {
        self.0.block_access_list()
    }

    fn parent_beacon_block_root(&self) -> Option<alloy_primitives::B256> {
        self.0.parent_beacon_block_root()
    }

    fn timestamp(&self) -> u64 {
        self.0.timestamp()
    }

    fn gas_used(&self) -> u64 {
        self.0.gas_used()
    }

    fn gas_limit(&self) -> u64 {
        self.0.gas_limit()
    }

    fn transaction_count(&self) -> usize {
        self.0.transaction_count()
    }

    fn slot_number(&self) -> Option<u64> {
        self.0.slot_number()
    }
}

/// The ArbOS message and environment for one locally-derived L2 block.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ArbPayloadAttributes {
    /// Arbitrum's next-block timestamp: `max(message L1 timestamp, parent timestamp)`.
    pub timestamp: u64,
    /// Ordered sequencer/L1 message which ArbOS expands into the block's transactions.
    pub message: arbitrum_alloy_sequencer::sequencer::feed::BroadcastFeedMessage,
}

impl PayloadAttributes for ArbPayloadAttributes {
    fn payload_id(&self, parent: &alloy_primitives::B256) -> PayloadId {
        // Payload IDs are local job identifiers. Include the message sequence number so two
        // Arbitrum messages with an equal timestamp never alias the same build job.
        reth_payload_primitives::payload_id(
            parent,
            &alloy_rpc_types_engine::PayloadAttributes {
                timestamp: self.timestamp,
                prev_randao: Default::default(),
                suggested_fee_recipient: Default::default(),
                withdrawals: None,
                parent_beacon_block_root: None,
                slot_number: Some(self.message.sequence_number),
                target_gas_limit: None,
            },
        )
    }

    fn timestamp(&self) -> u64 {
        self.timestamp
    }

    fn withdrawals(&self) -> Option<&alloc::vec::Vec<Withdrawal>> {
        None
    }

    fn parent_beacon_block_root(&self) -> Option<alloy_primitives::B256> {
        None
    }

    fn slot_number(&self) -> Option<u64> {
        None
    }
}

/// Payload-types stub for `ArbNode`. Exists solely to satisfy `NodeTypes::Payload`.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ArbPayloadTypes;

impl PayloadTypes for ArbPayloadTypes {
    type ExecutionData = ArbExecutionData;
    type BuiltPayload = ArbBuiltPayload;
    type PayloadAttributes = ArbPayloadAttributes;

    fn block_to_payload(
        block: SealedBlock<
            <<ArbBuiltPayload as BuiltPayload>::Primitives as NodePrimitives>::Block,
        >,
        _bal: Option<Bytes>,
    ) -> Self::ExecutionData {
        let block_hash = block.hash();
        let (execution_payload, sidecar) = AlloyExecutionPayload::from_block_unchecked_with_extras(
            block_hash,
            &block.into_block(),
            None,
        );
        ArbExecutionData(ExecutionData {
            payload: execution_payload,
            sidecar,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_id_distinguishes_equal_timestamp_messages() {
        let parent = alloy_primitives::B256::repeat_byte(0x11);
        let first_message = arbitrum_alloy_sequencer::sequencer::feed::BroadcastFeedMessage {
            sequence_number: 7,
            ..Default::default()
        };
        let mut second_message = first_message.clone();
        second_message.sequence_number = 8;

        let first = ArbPayloadAttributes {
            timestamp: 1_234,
            message: first_message,
        };
        let second = ArbPayloadAttributes {
            timestamp: 1_234,
            message: second_message,
        };

        assert_ne!(first.payload_id(&parent), second.payload_id(&parent));
    }

    #[test]
    fn arb_defaults_share_only_the_execution_cache() {
        let config = ArbEngineTuning::reth_defaults().to_tree_config();

        assert_eq!(config.cross_block_cache_size(), 256 * 1024 * 1024);
        assert!(config.share_execution_cache_with_payload_builder());
        assert!(!config.share_sparse_trie_with_payload_builder());
    }
}

#[cfg(test)]
mod engine_tuning_tests {
    use super::ArbEngineTuning;

    #[test]
    fn arb_default_execution_cache_is_256_mib() {
        assert_eq!(
            ArbEngineTuning::reth_defaults()
                .to_tree_config()
                .cross_block_cache_size(),
            256 * 1024 * 1024,
        );
    }
}
