//! Canonical comparison for sequencer-feed and L1-derived messages.
//!
//! The two transports use JSON-shaped fields and may differ in derived batch-posting metadata.
//! Comparing their JSON bytes would therefore be both unstable and too strict. This module parses
//! the consensus fields into their typed forms, hashes an unambiguous binary encoding, and retains
//! the optional batch-cost fields for Nitro-compatible enrichment checks.

use alloy_primitives::{B256, keccak256};
use arbitrum_alloy_sequencer::sequencer::feed::{BroadcastFeedMessage, L1Header};
use base64::{Engine as _, prelude::BASE64_STANDARD};
use eyre::{WrapErr as _, eyre};

const FINGERPRINT_DOMAIN: &[u8] = b"arb-reth-message-fingerprint-v1";

/// Optional batch-posting metadata excluded from the core digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ArbMessageEnrichment {
    /// Legacy calldata gas cost carried by pre-ArbOS-50 batch posting reports.
    pub legacy_batch_gas_cost: Option<u64>,
    /// Deterministically derived serialized-batch statistics used by newer ArbOS versions.
    pub batch_data_stats: Option<(u64, u64)>,
}

/// Stable identity of one ordered Arbitrum message.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ArbMessageFingerprint {
    /// Hash of all consensus fields other than optional batch-cost enrichment.
    pub core: B256,
    /// Optional batch-cost fields compared with Nitro's missing-enrichment rule.
    pub enrichment: ArbMessageEnrichment,
}

impl ArbMessageFingerprint {
    /// Returns true when two source representations describe the same ordered message.
    ///
    /// Nitro permits one side to lack `BatchDataStats`: those stats and the interchangeable legacy
    /// gas-cost cache can be filled after the batch bytes are fetched. If both sides have stats,
    /// all enrichment fields must agree exactly.
    pub fn semantically_matches(self, other: Self) -> bool {
        if self.core != other.core {
            return false;
        }
        match (
            self.enrichment.batch_data_stats,
            other.enrichment.batch_data_stats,
        ) {
            (Some(_), Some(_)) => self.enrichment == other.enrichment,
            _ => true,
        }
    }
}

/// Parse and fingerprint a message independently of its feed JSON representation.
pub fn fingerprint_message(message: &BroadcastFeedMessage) -> eyre::Result<ArbMessageFingerprint> {
    let metadata = &message.message_with_meta_data;
    let incoming = &metadata.l1_incoming_message;
    let header = L1Header::from_header(&incoming.header, metadata.delayed_messages_read)
        .map_err(|error| eyre!("invalid L1 message header: {error}"))?;
    let l2_message = BASE64_STANDARD
        .decode(&incoming.l2msg)
        .wrap_err("invalid base64 L2 message")?;

    let mut encoded = Vec::with_capacity(FINGERPRINT_DOMAIN.len() + l2_message.len() + 160);
    encoded.extend_from_slice(FINGERPRINT_DOMAIN);
    encoded.extend_from_slice(&message.sequence_number.to_be_bytes());
    encoded.push(header.kind);
    encoded.extend_from_slice(header.poster.as_slice());
    encoded.extend_from_slice(&header.block_number.to_be_bytes());
    encoded.extend_from_slice(&header.timestamp.to_be_bytes());
    encode_option(&mut encoded, header.request_id.map(|value| value.0));
    encode_option(
        &mut encoded,
        header.base_fee_l1.map(|value| value.to_be_bytes::<32>()),
    );
    encoded.extend_from_slice(&header.delayed_messages_read.to_be_bytes());
    encoded.extend_from_slice(&(l2_message.len() as u64).to_be_bytes());
    encoded.extend_from_slice(&l2_message);

    Ok(ArbMessageFingerprint {
        core: keccak256(encoded),
        enrichment: ArbMessageEnrichment {
            legacy_batch_gas_cost: incoming.legacy_batch_gas_cost,
            batch_data_stats: incoming
                .batch_data_stats
                .as_ref()
                .map(|stats| (stats.length, stats.non_zeros)),
        },
    })
}

fn encode_option<const N: usize>(out: &mut Vec<u8>, value: Option<[u8; N]>) {
    match value {
        Some(value) => {
            out.push(1);
            out.extend_from_slice(&value);
        }
        None => out.push(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbitrum_alloy_sequencer::sequencer::feed::{BatchDataStats, BroadcastFeedMessage};

    fn message() -> BroadcastFeedMessage {
        serde_json::from_str(include_str!(
            "../../arb-reth-node/tests/fixtures/deposit_message_only.json"
        ))
        .expect("fixture must parse")
    }

    #[test]
    fn stable_across_equivalent_sender_spelling() {
        let first = message();
        let mut second = first.clone();
        second
            .message_with_meta_data
            .l1_incoming_message
            .header
            .sender = second
            .message_with_meta_data
            .l1_incoming_message
            .header
            .sender
            .to_ascii_uppercase()
            .replace("0X", "0x");

        assert_eq!(
            fingerprint_message(&first).unwrap(),
            fingerprint_message(&second).unwrap()
        );
    }

    #[test]
    fn missing_batch_stats_are_compatible_with_enrichment() {
        let mut first = message();
        first.message_with_meta_data.l1_incoming_message.header.kind = 13;
        let mut second = first.clone();
        second
            .message_with_meta_data
            .l1_incoming_message
            .batch_data_stats = Some(BatchDataStats {
            length: 1234,
            non_zeros: 1000,
        });
        second
            .message_with_meta_data
            .l1_incoming_message
            .legacy_batch_gas_cost = Some(16_000);

        let first = fingerprint_message(&first).unwrap();
        let second = fingerprint_message(&second).unwrap();
        assert!(first.semantically_matches(second));
    }

    #[test]
    fn conflicting_complete_batch_stats_do_not_match() {
        let mut first = message();
        first
            .message_with_meta_data
            .l1_incoming_message
            .batch_data_stats = Some(BatchDataStats {
            length: 1234,
            non_zeros: 1000,
        });
        let mut second = first.clone();
        second
            .message_with_meta_data
            .l1_incoming_message
            .batch_data_stats = Some(BatchDataStats {
            length: 1234,
            non_zeros: 999,
        });

        let first = fingerprint_message(&first).unwrap();
        let second = fingerprint_message(&second).unwrap();
        assert!(!first.semantically_matches(second));
    }

    #[test]
    fn consensus_field_difference_does_not_match() {
        let first = message();
        let mut second = first.clone();
        second.message_with_meta_data.delayed_messages_read += 1;

        let first = fingerprint_message(&first).unwrap();
        let second = fingerprint_message(&second).unwrap();
        assert!(!first.semantically_matches(second));
    }
}
