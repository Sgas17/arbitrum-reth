//! `arb-reth-l1`: the L1-derivation fetch layer.
//!
//! Reads `SequencerInbox` batches from an L1 RPC and turns them into the
//! [`DerivedMessage`](arb_reth_derive::message::DerivedMessage) stream that the
//! decoders in `arb-reth-derive` produce. This is the trustless-sync source the
//! node uses to catch up from a snapshot height to the L1 head before following
//! the live feed for the tip.
//!
//! What lives where:
//! * [`contracts`] - the `SequencerInbox` ABI surface (event topic + call selectors).
//! * [`reader`] - [`SequencerInboxReader`], which fetches batch logs and resolves
//!   each batch's payload (calldata or blob sidecars).
//! * [`extract_calldata_payload`] / [`decode_batch_messages`] - the pure decode glue
//!   bridging recovered calldata to the derive pipeline.

pub mod assemble;
pub mod batch_serialize;
pub mod beacon;
pub mod canonical;
pub mod contracts;
pub mod delayed;
pub mod feed;
pub mod reader;
pub mod sync;

use alloy_primitives::{B256, U256};
use alloy_sol_types::{SolCall, SolEvent};
use arb_reth_derive::batch::{self, BatchError};
use arb_reth_derive::delayed::DelayedSource;
use arb_reth_derive::message::DerivedMessage;
use arb_reth_derive::multiplexer::{MultiplexerError, extract_messages};

pub use arb_reth_derive::batch::{
    SequencerBatchDeliveredData, data_location, parse_sequencer_batch_delivered,
};
pub use arb_reth_derive::blob::BYTES_PER_BLOB;
pub use arb_reth_derive::delayed::{DelayedMap, DelayedMessage};
pub use assemble::{
    assemble_feed_messages, assemble_feed_messages_with_seed, batch_to_feed_messages,
    batch_to_feed_messages_cancellable,
};
pub use batch_serialize::{
    batch_data_hash, batch_data_stats, report_batch_num, report_data_hash, serialize_batch,
};
pub use beacon::BeaconClient;
pub use canonical::{
    CanonicalBeaconClient, CanonicalBlobSidecar, CanonicalCancellation, CanonicalError,
    CanonicalExecutionClient, CanonicalExecutionHeader, CanonicalExecutionLog,
    CanonicalExecutionReceipt, CanonicalExecutionTransaction, CanonicalMemoryBudget,
    CanonicalMemoryReservation, CanonicalRpcClient, ObservationDeadlines, ReservedValue,
    RetryDisposition, decode_canonical_blob_payload, sequencer_accumulator,
    validate_ordered_blob_commitments,
};
pub use contracts::{
    BRIDGE_MAINNET, NITRO_GENESIS_BLOCK_MAINNET, SEQUENCER_INBOX_DEPLOY_BLOCK_MAINNET,
    SEQUENCER_INBOX_MAINNET,
};
pub use delayed::{DelayedInboxReader, verify_accumulator_chain};
pub use delayed::{parse_inbox_message_data, parse_message_delivered};
pub use feed::{derived_to_feed_message, derived_to_feed_message_with_stats};
pub use reader::decode_separate_batch_event_data;
pub use reader::{BatchPayload, DeliveredBatch, SequencerInboxReader};

pub const SEQUENCER_BATCH_DELIVERED_TOPIC: B256 =
    contracts::SequencerBatchDelivered::SIGNATURE_HASH;
pub const SEQUENCER_BATCH_DATA_TOPIC: B256 = contracts::SequencerBatchData::SIGNATURE_HASH;
pub const MESSAGE_DELIVERED_TOPIC: B256 = contracts::MessageDelivered::SIGNATURE_HASH;
pub const INBOX_MESSAGE_DELIVERED_TOPIC: B256 = contracts::InboxMessageDelivered::SIGNATURE_HASH;
pub const INBOX_MESSAGE_DELIVERED_FROM_ORIGIN_TOPIC: B256 =
    contracts::InboxMessageDeliveredFromOrigin::SIGNATURE_HASH;

pub fn encode_sequencer_accumulator_call(sequence: u64) -> Vec<u8> {
    contracts::bridge_accumulators::sequencerInboxAccsCall {
        batchSequence: U256::from(sequence),
    }
    .abi_encode()
}

pub fn encode_delayed_accumulator_call(index: u64) -> Vec<u8> {
    contracts::bridge_accumulators::delayedInboxAccsCall {
        messageIndex: U256::from(index),
    }
    .abi_encode()
}

/// Decode the body of an `InboxMessageDeliveredFromOrigin` posting transaction.
pub fn decode_from_origin_message(input: &[u8]) -> Result<Vec<u8>, L1Error> {
    let call = contracts::from_origin::sendL2MessageFromOriginCall::abi_decode(input)?;
    if call.abi_encode() != input {
        return Err(L1Error::Missing(
            "sendL2MessageFromOrigin calldata is not canonical ABI",
        ));
    }
    Ok(call.messageData.to_vec())
}

/// Errors from the L1 fetch + decode glue.
#[derive(Debug)]
pub enum L1Error {
    /// Transaction input shorter than a 4-byte selector.
    CalldataTooShort(usize),
    /// Batch-poster selector not recognised (likely a blob/delay-proof variant not
    /// yet wired).
    UnknownSelector([u8; 4]),
    /// ABI decode of the batch-poster call failed.
    Abi(alloy_sol_types::Error),
    /// Batch framing/decompression error from arb-reth-derive.
    Batch(BatchError),
    /// Multiplexer error from arb-reth-derive.
    Mux(MultiplexerError),
    /// Blob field-element decode failed.
    Blob(String),
    /// `dataLocation` enum value with no decode path here yet (e.g. blobs).
    UnsupportedDataLocation(u8),
    /// A log/transaction lacked a field needed to resolve the batch.
    Missing(&'static str),
    /// Transport/RPC failure (stringified to avoid leaking the provider error type).
    Rpc(String),
}

impl core::fmt::Display for L1Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            L1Error::CalldataTooShort(n) => write!(f, "calldata too short: {n} bytes"),
            L1Error::UnknownSelector(s) => {
                write!(
                    f,
                    "unknown batch-poster selector: 0x{}",
                    alloy_primitives::hex::encode(s)
                )
            }
            L1Error::Abi(e) => write!(f, "abi decode: {e}"),
            L1Error::Batch(e) => write!(f, "batch decode: {e:?}"),
            L1Error::Mux(e) => write!(f, "multiplexer: {e:?}"),
            L1Error::Blob(e) => write!(f, "blob decode: {e}"),
            L1Error::UnsupportedDataLocation(d) => write!(f, "unsupported dataLocation: {d}"),
            L1Error::Missing(what) => write!(f, "missing {what}"),
            L1Error::Rpc(e) => write!(f, "rpc: {e}"),
        }
    }
}

impl std::error::Error for L1Error {}

impl From<alloy_sol_types::Error> for L1Error {
    fn from(e: alloy_sol_types::Error) -> Self {
        L1Error::Abi(e)
    }
}

/// Recover the batch payload (header-flag byte + compressed segments) from a
/// batch-poster transaction's calldata.
///
/// Dispatches on the 4-byte selector. Returns the `data` argument for the calldata
/// posters; blob/delay-proof variants are not handled here and surface as
/// [`L1Error::UnknownSelector`].
pub fn extract_calldata_payload(input: &[u8]) -> Result<Vec<u8>, L1Error> {
    if input.len() < 4 {
        return Err(L1Error::CalldataTooShort(input.len()));
    }
    let selector: [u8; 4] = input[..4].try_into().unwrap();

    if selector == contracts::origin::addSequencerL2BatchFromOriginCall::SELECTOR {
        let call = contracts::origin::addSequencerL2BatchFromOriginCall::abi_decode(input)?;
        if call.abi_encode() != input {
            return Err(L1Error::Missing(
                "batch posting calldata is not canonical ABI",
            ));
        }
        return Ok(call.data.to_vec());
    }
    if selector == contracts::origin_legacy::addSequencerL2BatchFromOriginCall::SELECTOR {
        let call = contracts::origin_legacy::addSequencerL2BatchFromOriginCall::abi_decode(input)?;
        if call.abi_encode() != input {
            return Err(L1Error::Missing(
                "batch posting calldata is not canonical ABI",
            ));
        }
        return Ok(call.data.to_vec());
    }
    if selector
        == contracts::origin_delay_proof::addSequencerL2BatchFromOriginDelayProofCall::SELECTOR
    {
        let call =
            contracts::origin_delay_proof::addSequencerL2BatchFromOriginDelayProofCall::abi_decode(
                input,
            )?;
        if call.abi_encode() != input {
            return Err(L1Error::Missing(
                "batch posting calldata is not canonical ABI",
            ));
        }
        return Ok(call.data.to_vec());
    }
    Err(L1Error::UnknownSelector(selector))
}

/// Decode a resolved batch payload (the brotli-flagged byte stream from either the
/// calldata or blob path) into its `DerivedMessage` stream, given the batch header.
///
/// `before_delayed_count` is the number of delayed messages read before this batch
/// (the previous batch's `afterDelayedMessagesRead`); the multiplexer needs it to
/// index `DelayedMessages` segments. For batches with no delayed-message segments
/// the value is unused.
pub fn decode_payload_messages(
    header: &arb_reth_derive::batch::BatchHeader,
    payload: &[u8],
    before_delayed_count: u64,
    delayed: &dyn DelayedSource,
) -> Result<Vec<DerivedMessage>, L1Error> {
    // An empty payload is a valid empty sequencer message (Nitro `ParseSequencerMessage`
    // logs "empty sequencer message" and returns zero segments rather than erroring).
    // Early Arbitrum One batches do this: batch 0 is a `SeparateBatchEvent` with empty
    // data. The multiplexer still runs so any delayed messages this batch reads
    // (force-inclusion: `afterDelayedMessages > before_delayed_count`) are emitted; only
    // the segment list is empty.
    let segments = if payload.is_empty() {
        Vec::new()
    } else {
        let seg_bytes = batch::decompress_payload(payload).map_err(L1Error::Batch)?;
        batch::parse_segments(&seg_bytes).map_err(L1Error::Batch)?
    };
    extract_messages(header, &segments, before_delayed_count, delayed).map_err(L1Error::Mux)
}

/// Decode with the B2 output bound and cooperative Brotli cancellation.
pub fn decode_payload_messages_cancellable(
    header: &arb_reth_derive::batch::BatchHeader,
    payload: &[u8],
    before_delayed_count: u64,
    delayed: &dyn DelayedSource,
    mut cancelled: impl FnMut() -> bool,
) -> Result<Vec<DerivedMessage>, L1Error> {
    let segments = if payload.is_empty() {
        Vec::new()
    } else {
        let seg_bytes = batch::decompress_payload_bounded(
            payload,
            canonical::MAX_DECOMPRESSED_BATCH_BYTES,
            &mut cancelled,
        )
        .map_err(L1Error::Batch)?;
        batch::parse_segments_cancellable(&seg_bytes, &mut cancelled).map_err(L1Error::Batch)?
    };
    extract_messages(header, &segments, before_delayed_count, delayed).map_err(L1Error::Mux)
}

/// Decode a resolved calldata batch into its `DerivedMessage` stream.
///
/// Blob batches must first be resolved to a payload via
/// [`SequencerInboxReader::resolve_blob_payload`](reader::SequencerInboxReader) and
/// then decoded with [`decode_payload_messages`].
pub fn decode_batch_messages(
    batch: &DeliveredBatch,
    before_delayed_count: u64,
    delayed: &dyn DelayedSource,
) -> Result<Vec<DerivedMessage>, L1Error> {
    let payload = match &batch.payload {
        BatchPayload::Calldata(p) => p.as_slice(),
        BatchPayload::None => return Ok(Vec::new()),
        BatchPayload::Blob { .. } => {
            return Err(L1Error::UnsupportedDataLocation(data_location::BLOB_HASHES));
        }
    };
    decode_payload_messages(
        &batch.event.batch_header(),
        payload,
        before_delayed_count,
        delayed,
    )
}

#[cfg(test)]
mod selector_tests {
    use super::contracts;
    use alloy_sol_types::SolCall;

    /// The delay-proof origin poster selector must match the on-chain 0x69cacded, or the reader
    /// would fall through to `UnknownSelector` on a current nitro-testnode / Orbit chain.
    #[test]
    fn origin_delay_proof_selector() {
        assert_eq!(
            contracts::origin_delay_proof::addSequencerL2BatchFromOriginDelayProofCall::SELECTOR,
            [0x69, 0xca, 0xcd, 0xed],
        );
    }
}
