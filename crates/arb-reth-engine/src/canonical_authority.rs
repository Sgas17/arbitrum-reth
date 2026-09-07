//! Frozen B2 compact canonical-observation and divergence codecs.
//!
//! These are deliberately single-version fixed-width codecs. They are not transport envelopes,
//! extensible registries, or historical proof formats.

use alloy_primitives::{B256, b256};
use eyre::{ensure, eyre};
use sha2::{Digest as _, Sha256};

use crate::{
    ArbMessageFingerprint, DIVERGENCE_MARKER_FILE, EvidenceLocatorV1, JournalDirectory,
    MessageJournalInspection,
};

pub const CANONICAL_OBSERVATION_V1_LEN: usize = 448;
pub const DIVERGENCE_MARKER_V4_LEN: usize = 512;

const OBSERVATION_MAGIC: &[u8; 8] = b"ARBOBSV1";
const DIVERGENCE_MAGIC: &[u8; 8] = b"ARBDIVV4";
const EVIDENCE_DOMAIN: &str = "arb-reth-journal-v3-evidence";
const DIVERGENCE_DOMAIN: &str = "arb-reth-divergence-v4";
const FINGERPRINT_DOMAIN: &str = "arb-reth-divergence-v4-fingerprint";
const PRODUCTION_CONTEXT_ID: u16 = 1;
const PRODUCTION_CONTEXT_DIGEST: B256 =
    b256!("eb0d03086218827bd1b8e4afafe6612f29a009c4dac82920c7084936d4f8c64f");

fn put_u16(out: &mut [u8], value: u16) {
    out.copy_from_slice(&value.to_be_bytes());
}

fn put_u32(out: &mut [u8], value: u32) {
    out.copy_from_slice(&value.to_be_bytes());
}

fn put_u64(out: &mut [u8], value: u64) {
    out.copy_from_slice(&value.to_be_bytes());
}

fn get_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes(bytes.try_into().expect("fixed-width u16"))
}

fn get_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().expect("fixed-width u32"))
}

fn get_u64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().expect("fixed-width u64"))
}

fn framed_hash(domain: &str, payload: &[u8]) -> B256 {
    let mut hasher = Sha256::new();
    hasher.update(
        u16::try_from(domain.len())
            .expect("frozen domain length fits u16")
            .to_be_bytes(),
    );
    hasher.update(domain.as_bytes());
    hasher.update(
        u64::try_from(payload.len())
            .expect("bounded payload length fits u64")
            .to_be_bytes(),
    );
    hasher.update(payload);
    B256::from_slice(&hasher.finalize())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CanonicalPayloadKind {
    Calldata = 1,
    SeparateEvent = 2,
    NoData = 3,
    Blobs = 4,
}

impl TryFrom<u8> for CanonicalPayloadKind {
    type Error = eyre::Report;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Calldata),
            2 => Ok(Self::SeparateEvent),
            3 => Ok(Self::NoData),
            4 => Ok(Self::Blobs),
            _ => Err(eyre!("unknown canonical payload kind {value}")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalObservationV1 {
    pub context_id: u16,
    pub context_digest: B256,
    pub safe_l1_number: u64,
    pub safe_l1_hash: B256,
    pub containing_l1_number: u64,
    pub containing_l1_hash: B256,
    pub posting_transaction_hash: B256,
    pub posting_transaction_index: u32,
    pub delivery_log_index: u32,
    pub batch_sequence: u64,
    pub terminal_message_ordinal: u32,
    pub decoded_message_count: u32,
    pub start_delayed_count: u64,
    pub terminal_delayed_count: u64,
    pub terminal_sequencer_accumulator: B256,
    pub terminal_delayed_accumulator: B256,
    pub payload_kind: CanonicalPayloadKind,
    pub payload_digest: B256,
    pub promoted_start_sequence: u64,
    pub promoted_end_sequence: u64,
    pub terminal_l2_block_number: u64,
    pub terminal_l2_block_hash: B256,
    pub promoted_identities_digest: B256,
}

impl CanonicalObservationV1 {
    pub fn encode(self) -> [u8; CANONICAL_OBSERVATION_V1_LEN] {
        let mut out = [0u8; CANONICAL_OBSERVATION_V1_LEN];
        out[..8].copy_from_slice(OBSERVATION_MAGIC);
        put_u16(&mut out[8..10], 1);
        put_u16(&mut out[10..12], 1);
        put_u16(&mut out[12..14], self.context_id);
        out[16..48].copy_from_slice(self.context_digest.as_slice());
        put_u64(&mut out[48..56], self.safe_l1_number);
        out[56..88].copy_from_slice(self.safe_l1_hash.as_slice());
        put_u64(&mut out[88..96], self.containing_l1_number);
        out[96..128].copy_from_slice(self.containing_l1_hash.as_slice());
        out[128..160].copy_from_slice(self.posting_transaction_hash.as_slice());
        put_u32(&mut out[160..164], self.posting_transaction_index);
        put_u32(&mut out[164..168], self.delivery_log_index);
        put_u64(&mut out[168..176], self.batch_sequence);
        put_u32(&mut out[176..180], self.terminal_message_ordinal);
        put_u32(&mut out[180..184], self.decoded_message_count);
        put_u64(&mut out[184..192], self.start_delayed_count);
        put_u64(&mut out[192..200], self.terminal_delayed_count);
        out[200..232].copy_from_slice(self.terminal_sequencer_accumulator.as_slice());
        out[232..264].copy_from_slice(self.terminal_delayed_accumulator.as_slice());
        out[264] = self.payload_kind as u8;
        out[272..304].copy_from_slice(self.payload_digest.as_slice());
        put_u64(&mut out[304..312], self.promoted_start_sequence);
        put_u64(&mut out[312..320], self.promoted_end_sequence);
        put_u64(&mut out[320..328], self.terminal_l2_block_number);
        out[328..360].copy_from_slice(self.terminal_l2_block_hash.as_slice());
        out[360..392].copy_from_slice(self.promoted_identities_digest.as_slice());
        out
    }

    pub fn decode(bytes: &[u8]) -> eyre::Result<Self> {
        ensure!(
            bytes.len() == CANONICAL_OBSERVATION_V1_LEN,
            "canonical observation length is not {CANONICAL_OBSERVATION_V1_LEN}"
        );
        ensure!(
            &bytes[..8] == OBSERVATION_MAGIC,
            "invalid observation magic"
        );
        ensure!(
            get_u16(&bytes[8..10]) == 1,
            "unsupported observation version"
        );
        ensure!(
            get_u16(&bytes[10..12]) == 1,
            "unsupported observation evidence schema"
        );
        ensure!(
            bytes[14..16].iter().all(|byte| *byte == 0)
                && bytes[265..272].iter().all(|byte| *byte == 0)
                && bytes[392..].iter().all(|byte| *byte == 0),
            "nonzero observation reserved bytes"
        );
        let observation = Self {
            context_id: get_u16(&bytes[12..14]),
            context_digest: B256::from_slice(&bytes[16..48]),
            safe_l1_number: get_u64(&bytes[48..56]),
            safe_l1_hash: B256::from_slice(&bytes[56..88]),
            containing_l1_number: get_u64(&bytes[88..96]),
            containing_l1_hash: B256::from_slice(&bytes[96..128]),
            posting_transaction_hash: B256::from_slice(&bytes[128..160]),
            posting_transaction_index: get_u32(&bytes[160..164]),
            delivery_log_index: get_u32(&bytes[164..168]),
            batch_sequence: get_u64(&bytes[168..176]),
            terminal_message_ordinal: get_u32(&bytes[176..180]),
            decoded_message_count: get_u32(&bytes[180..184]),
            start_delayed_count: get_u64(&bytes[184..192]),
            terminal_delayed_count: get_u64(&bytes[192..200]),
            terminal_sequencer_accumulator: B256::from_slice(&bytes[200..232]),
            terminal_delayed_accumulator: B256::from_slice(&bytes[232..264]),
            payload_kind: CanonicalPayloadKind::try_from(bytes[264])?,
            payload_digest: B256::from_slice(&bytes[272..304]),
            promoted_start_sequence: get_u64(&bytes[304..312]),
            promoted_end_sequence: get_u64(&bytes[312..320]),
            terminal_l2_block_number: get_u64(&bytes[320..328]),
            terminal_l2_block_hash: B256::from_slice(&bytes[328..360]),
            promoted_identities_digest: B256::from_slice(&bytes[360..392]),
        };
        observation.validate()?;
        Ok(observation)
    }

    pub fn validate(self) -> eyre::Result<()> {
        ensure!(
            self.context_id != 0
                && self.context_digest != B256::ZERO
                && self.safe_l1_hash != B256::ZERO
                && self.containing_l1_hash != B256::ZERO
                && self.posting_transaction_hash != B256::ZERO
                && self.terminal_sequencer_accumulator != B256::ZERO
                && self.payload_digest != B256::ZERO
                && self.terminal_l2_block_hash != B256::ZERO
                && self.promoted_identities_digest != B256::ZERO,
            "zero required observation commitment"
        );
        ensure!(
            self.containing_l1_number <= self.safe_l1_number,
            "observation containing L1 is above safe L1"
        );
        ensure!(
            self.decoded_message_count != 0
                && self.terminal_message_ordinal < self.decoded_message_count,
            "invalid observation terminal ordinal"
        );
        ensure!(
            self.start_delayed_count <= self.terminal_delayed_count,
            "observation delayed count regressed"
        );
        ensure!(
            (self.terminal_delayed_count == 0 && self.terminal_delayed_accumulator == B256::ZERO)
                || (self.terminal_delayed_count > 0
                    && self.terminal_delayed_accumulator != B256::ZERO),
            "observation delayed accumulator/count mismatch"
        );
        ensure!(
            self.promoted_start_sequence <= self.promoted_end_sequence
                && self.terminal_l2_block_number == self.promoted_end_sequence,
            "invalid observation promoted range"
        );
        Ok(())
    }

    pub fn locator(self) -> EvidenceLocatorV1 {
        EvidenceLocatorV1 {
            context_id: self.context_id,
            context_digest: self.context_digest,
            safe_l1_number: self.safe_l1_number,
            safe_l1_hash: self.safe_l1_hash,
            containing_l1_number: self.containing_l1_number,
            containing_l1_hash: self.containing_l1_hash,
            posting_transaction_hash: self.posting_transaction_hash,
            posting_transaction_index: self.posting_transaction_index,
            delivery_log_index: self.delivery_log_index,
            batch_sequence: self.batch_sequence,
            terminal_message_ordinal: self.terminal_message_ordinal,
            decoded_message_count: self.decoded_message_count,
            terminal_delayed_count: self.terminal_delayed_count,
            terminal_sequence: self.promoted_end_sequence,
            terminal_l2_block_number: self.terminal_l2_block_number,
            terminal_l2_block_hash: self.terminal_l2_block_hash,
        }
    }

    pub fn evidence_digest(self) -> B256 {
        let mut payload = [0u8; 2 + CANONICAL_OBSERVATION_V1_LEN];
        put_u16(&mut payload[..2], 1);
        payload[2..].copy_from_slice(&self.encode());
        framed_hash(EVIDENCE_DOMAIN, &payload)
    }
}

pub fn decode_production_bootstrap_observation() -> CanonicalObservationV1 {
    const BYTES: [u8; CANONICAL_OBSERVATION_V1_LEN] = alloy_primitives::hex!(
        "4152424f425356310001000100010000eb0d03086218827bd1b8e4afafe6612f29a009c4dac82920c7084936d4f8c64f00000000018aedf427183b30d80126283ab880afd3cb05860d85402e94875dfd8a656d6199512a1e00000000018866720b23cbbe3df15b5b1cc462e7939612afc0ec5c7831e70f2ab74044a145e1a2bc80a9642ebe2d93d4ce307275536134f9fd10f3f57223fb3dfe05bec02dd300d2000000140000020d0000000000016704000001400000015a000000000001b32d000000000001b32d98b2f4714ccc57e7dc4aa2256e97eb7feb763e5559557bc9dee9abf60b5fa52c213fc1b2524be3d5f36c7554238be0a0c43be936b2cd9e7c51cb98f46f83ad750400000000000000baf0c248491c20a8d1439cfaee7d713b39f7d8b8a1266403e0c5affa14976d2d0000000001e54ed80000000001e54ed80000000001e54ed8cc8b407211b69dbac3e16dc083a980db25da7133de714d5f69b7f3d0682789900e98af206c759354b4e4c518158334cd032cd12eef2a190081a31221f6b6249d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    );
    CanonicalObservationV1::decode(&BYTES).expect("compiled bootstrap observation is valid")
}

pub fn fingerprint_commitment(fingerprint: ArbMessageFingerprint) -> B256 {
    let mut encoded = [0u8; 58];
    encoded[..32].copy_from_slice(fingerprint.core.as_slice());
    if let Some(value) = fingerprint.enrichment.legacy_batch_gas_cost {
        encoded[32] = 1;
        put_u64(&mut encoded[33..41], value);
    }
    if let Some((length, nonzeros)) = fingerprint.enrichment.batch_data_stats {
        encoded[41] = 1;
        put_u64(&mut encoded[42..50], length);
        put_u64(&mut encoded[50..58], nonzeros);
    }
    framed_hash(FINGERPRINT_DOMAIN, &encoded)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum DivergenceCauseV4 {
    FeedL1IdentityMismatch = 1,
    ExistingAuthorityInvalidatedBySafeReorg = 2,
    SequencerAccumulatorMismatch = 3,
    DelayedAccumulatorMismatch = 4,
    CompactObservationMismatch = 5,
    ImpossibleDurablePredecessorContradiction = 6,
}

impl TryFrom<u16> for DivergenceCauseV4 {
    type Error = eyre::Report;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::FeedL1IdentityMismatch),
            2 => Ok(Self::ExistingAuthorityInvalidatedBySafeReorg),
            3 => Ok(Self::SequencerAccumulatorMismatch),
            4 => Ok(Self::DelayedAccumulatorMismatch),
            5 => Ok(Self::CompactObservationMismatch),
            6 => Ok(Self::ImpossibleDurablePredecessorContradiction),
            _ => Err(eyre!("unknown divergence-v4 cause {value}")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DivergenceMarkerV4 {
    pub cause: DivergenceCauseV4,
    pub journal_operation_generation: u64,
    pub authority_chain_position: u64,
    pub context_id: u16,
    pub context_digest: B256,
    pub j_sequence: u64,
    pub j_l2_block_number: u64,
    pub j_l2_block_hash: B256,
    pub v_sequence: u64,
    pub v_l2_block_number: u64,
    pub v_l2_block_hash: B256,
    pub candidate_sequence: u64,
    pub candidate_l2_block_number: u64,
    pub expected_fingerprint: B256,
    pub observed_fingerprint: B256,
    pub safe_l1_number: u64,
    pub safe_l1_hash: B256,
    pub containing_l1_number: u64,
    pub containing_l1_hash: B256,
    pub posting_transaction_hash: B256,
    pub posting_transaction_index: u32,
    pub delivery_log_index: u32,
    pub batch_sequence: u64,
    pub terminal_message_ordinal: u32,
    pub decoded_message_count: u32,
    pub cause_authority_id: B256,
    pub expected_value: B256,
    pub observed_value: B256,
}

impl DivergenceMarkerV4 {
    pub fn encode(self) -> eyre::Result<[u8; DIVERGENCE_MARKER_V4_LEN]> {
        self.validate_fields()?;
        let mut out = [0u8; DIVERGENCE_MARKER_V4_LEN];
        out[..8].copy_from_slice(DIVERGENCE_MAGIC);
        put_u16(&mut out[8..10], 4);
        put_u16(&mut out[10..12], self.cause as u16);
        put_u32(&mut out[12..16], DIVERGENCE_MARKER_V4_LEN as u32);
        put_u64(&mut out[16..24], self.journal_operation_generation);
        put_u64(&mut out[24..32], self.authority_chain_position);
        put_u16(&mut out[32..34], self.context_id);
        put_u16(&mut out[34..36], 1);
        out[40..72].copy_from_slice(self.context_digest.as_slice());
        put_u64(&mut out[72..80], self.j_sequence);
        put_u64(&mut out[80..88], self.j_l2_block_number);
        out[88..120].copy_from_slice(self.j_l2_block_hash.as_slice());
        put_u64(&mut out[120..128], self.v_sequence);
        put_u64(&mut out[128..136], self.v_l2_block_number);
        out[136..168].copy_from_slice(self.v_l2_block_hash.as_slice());
        put_u64(&mut out[168..176], self.candidate_sequence);
        put_u64(&mut out[176..184], self.candidate_l2_block_number);
        out[184..216].copy_from_slice(self.expected_fingerprint.as_slice());
        out[216..248].copy_from_slice(self.observed_fingerprint.as_slice());
        put_u64(&mut out[248..256], self.safe_l1_number);
        out[256..288].copy_from_slice(self.safe_l1_hash.as_slice());
        put_u64(&mut out[288..296], self.containing_l1_number);
        out[296..328].copy_from_slice(self.containing_l1_hash.as_slice());
        out[328..360].copy_from_slice(self.posting_transaction_hash.as_slice());
        put_u32(&mut out[360..364], self.posting_transaction_index);
        put_u32(&mut out[364..368], self.delivery_log_index);
        put_u64(&mut out[368..376], self.batch_sequence);
        put_u32(&mut out[376..380], self.terminal_message_ordinal);
        put_u32(&mut out[380..384], self.decoded_message_count);
        out[384..416].copy_from_slice(self.cause_authority_id.as_slice());
        out[416..448].copy_from_slice(self.expected_value.as_slice());
        out[448..480].copy_from_slice(self.observed_value.as_slice());
        let checksum = framed_hash(DIVERGENCE_DOMAIN, &out[..480]);
        out[480..].copy_from_slice(checksum.as_slice());
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> eyre::Result<Self> {
        ensure!(
            bytes.len() == DIVERGENCE_MARKER_V4_LEN,
            "divergence-v4 length is not {DIVERGENCE_MARKER_V4_LEN}"
        );
        ensure!(
            &bytes[..8] == DIVERGENCE_MAGIC,
            "invalid divergence-v4 magic"
        );
        ensure!(
            get_u16(&bytes[8..10]) == 4,
            "unsupported divergence version"
        );
        ensure!(
            get_u32(&bytes[12..16]) as usize == DIVERGENCE_MARKER_V4_LEN,
            "invalid divergence-v4 length field"
        );
        ensure!(
            get_u16(&bytes[34..36]) == 1,
            "divergence-v4 requires only V-present flag"
        );
        ensure!(
            bytes[36..40].iter().all(|byte| *byte == 0),
            "nonzero divergence-v4 reserved bytes"
        );
        ensure!(
            framed_hash(DIVERGENCE_DOMAIN, &bytes[..480]).as_slice() == &bytes[480..],
            "invalid divergence-v4 checksum"
        );
        let marker = Self {
            cause: DivergenceCauseV4::try_from(get_u16(&bytes[10..12]))?,
            journal_operation_generation: get_u64(&bytes[16..24]),
            authority_chain_position: get_u64(&bytes[24..32]),
            context_id: get_u16(&bytes[32..34]),
            context_digest: B256::from_slice(&bytes[40..72]),
            j_sequence: get_u64(&bytes[72..80]),
            j_l2_block_number: get_u64(&bytes[80..88]),
            j_l2_block_hash: B256::from_slice(&bytes[88..120]),
            v_sequence: get_u64(&bytes[120..128]),
            v_l2_block_number: get_u64(&bytes[128..136]),
            v_l2_block_hash: B256::from_slice(&bytes[136..168]),
            candidate_sequence: get_u64(&bytes[168..176]),
            candidate_l2_block_number: get_u64(&bytes[176..184]),
            expected_fingerprint: B256::from_slice(&bytes[184..216]),
            observed_fingerprint: B256::from_slice(&bytes[216..248]),
            safe_l1_number: get_u64(&bytes[248..256]),
            safe_l1_hash: B256::from_slice(&bytes[256..288]),
            containing_l1_number: get_u64(&bytes[288..296]),
            containing_l1_hash: B256::from_slice(&bytes[296..328]),
            posting_transaction_hash: B256::from_slice(&bytes[328..360]),
            posting_transaction_index: get_u32(&bytes[360..364]),
            delivery_log_index: get_u32(&bytes[364..368]),
            batch_sequence: get_u64(&bytes[368..376]),
            terminal_message_ordinal: get_u32(&bytes[376..380]),
            decoded_message_count: get_u32(&bytes[380..384]),
            cause_authority_id: B256::from_slice(&bytes[384..416]),
            expected_value: B256::from_slice(&bytes[416..448]),
            observed_value: B256::from_slice(&bytes[448..480]),
        };
        marker.validate_fields()?;
        Ok(marker)
    }

    fn validate_fields(self) -> eyre::Result<()> {
        ensure!(
            self.context_id == PRODUCTION_CONTEXT_ID
                && self.context_digest == PRODUCTION_CONTEXT_DIGEST,
            "divergence-v4 is not in the sole production context"
        );
        ensure!(
            self.j_l2_block_hash != B256::ZERO
                && self.v_l2_block_hash != B256::ZERO
                && self.safe_l1_hash != B256::ZERO
                && self.containing_l1_hash != B256::ZERO
                && self.posting_transaction_hash != B256::ZERO,
            "zero required divergence-v4 identity"
        );
        ensure!(
            self.v_sequence <= self.j_sequence
                && self.containing_l1_number <= self.safe_l1_number
                && self.candidate_l2_block_number == self.candidate_sequence
                && self.decoded_message_count != 0
                && self.terminal_message_ordinal < self.decoded_message_count,
            "invalid divergence-v4 common ordering"
        );
        let fingerprint_cause = self.cause == DivergenceCauseV4::FeedL1IdentityMismatch;
        if fingerprint_cause {
            ensure!(
                self.expected_fingerprint != B256::ZERO
                    && self.observed_fingerprint != B256::ZERO
                    && self.expected_fingerprint != self.observed_fingerprint,
                "cause-1 fingerprint commitments are invalid"
            );
        } else {
            ensure!(
                self.expected_fingerprint == B256::ZERO && self.observed_fingerprint == B256::ZERO,
                "non-cause-1 fingerprint commitments must be zero"
            );
        }
        match self.cause {
            DivergenceCauseV4::FeedL1IdentityMismatch => ensure!(
                self.v_sequence < self.candidate_sequence
                    && self.candidate_sequence <= self.j_sequence
                    && self.cause_authority_id != B256::ZERO
                    && self.expected_value != B256::ZERO
                    && self.observed_value != B256::ZERO,
                "invalid cause-1 divergence contract"
            ),
            DivergenceCauseV4::ExistingAuthorityInvalidatedBySafeReorg => ensure!(
                self.candidate_sequence <= self.v_sequence
                    && self.cause_authority_id != B256::ZERO
                    && self.expected_value != B256::ZERO
                    && self.observed_value != B256::ZERO
                    && self.expected_value != self.observed_value,
                "invalid cause-2 divergence contract"
            ),
            DivergenceCauseV4::SequencerAccumulatorMismatch => ensure!(
                self.v_sequence < self.candidate_sequence
                    && self.candidate_sequence <= self.j_sequence
                    && self.cause_authority_id != B256::ZERO
                    && self.expected_value != B256::ZERO
                    && self.observed_value != B256::ZERO
                    && self.expected_value != self.observed_value,
                "invalid cause-3 divergence contract"
            ),
            DivergenceCauseV4::DelayedAccumulatorMismatch => ensure!(
                self.v_sequence < self.candidate_sequence
                    && self.candidate_sequence <= self.j_sequence
                    && self.cause_authority_id != B256::ZERO
                    && self.expected_value != self.observed_value,
                "invalid cause-4 divergence contract"
            ),
            DivergenceCauseV4::CompactObservationMismatch => ensure!(
                self.v_sequence < self.candidate_sequence
                    && self.candidate_sequence <= self.j_sequence
                    && self.cause_authority_id != B256::ZERO
                    && self.expected_value != B256::ZERO
                    && self.observed_value != B256::ZERO
                    && self.expected_value != self.observed_value,
                "invalid cause-5 divergence contract"
            ),
            DivergenceCauseV4::ImpossibleDurablePredecessorContradiction => ensure!(
                self.v_sequence < self.candidate_sequence
                    && self.candidate_sequence <= self.j_sequence
                    && self.cause_authority_id != B256::ZERO
                    && self.expected_value == self.cause_authority_id
                    && self.observed_value != B256::ZERO
                    && self.observed_value != self.cause_authority_id,
                "invalid cause-6 divergence contract"
            ),
        }
        Ok(())
    }

    pub fn validate_against(
        self,
        journal: &MessageJournalInspection,
        observation: CanonicalObservationV1,
    ) -> eyre::Result<()> {
        self.validate_fields()?;
        let v = journal.v.ok_or_else(|| eyre!("divergence-v4 requires V"))?;
        ensure!(
            (
                self.j_sequence,
                self.j_l2_block_number,
                self.j_l2_block_hash
            ) == (
                journal.watermark.sequence,
                journal.watermark.block_number,
                journal.watermark.block_hash,
            ) && (
                self.v_sequence,
                self.v_l2_block_number,
                self.v_l2_block_hash
            ) == (v.sequence, v.block_number, v.block_hash)
                && self.journal_operation_generation == journal.last_operation_generation
                && self.authority_chain_position == journal.authority_operation_count,
            "divergence-v4 journal fence mismatch"
        );
        ensure!(
            observation.context_id == self.context_id
                && observation.context_digest == self.context_digest
                && observation.safe_l1_number == self.safe_l1_number
                && observation.safe_l1_hash == self.safe_l1_hash
                && observation.containing_l1_number == self.containing_l1_number
                && observation.containing_l1_hash == self.containing_l1_hash
                && observation.posting_transaction_hash == self.posting_transaction_hash
                && observation.posting_transaction_index == self.posting_transaction_index
                && observation.delivery_log_index == self.delivery_log_index
                && observation.batch_sequence == self.batch_sequence
                && observation.terminal_message_ordinal == self.terminal_message_ordinal
                && observation.decoded_message_count == self.decoded_message_count,
            "divergence-v4 canonical observation fence mismatch"
        );
        let current_predecessor = journal.latest_authority_id;
        match self.cause {
            DivergenceCauseV4::FeedL1IdentityMismatch => {
                let identity = journal
                    .entry(self.candidate_sequence)
                    .ok_or_else(|| eyre!("cause-1 durable candidate identity is absent"))?;
                ensure!(
                    self.candidate_sequence == observation.promoted_start_sequence
                        && self.candidate_sequence <= observation.promoted_end_sequence
                        && fingerprint_commitment(identity.fingerprint)
                            == self.expected_fingerprint
                        && self.cause_authority_id == current_predecessor
                        && self.expected_value == journal.latest_authority_chain_digest
                        && self.observed_value == observation.evidence_digest(),
                    "cause-1 authenticated journal/observation contract mismatch"
                );
            }
            DivergenceCauseV4::ExistingAuthorityInvalidatedBySafeReorg => {
                let invalidated = journal
                    .bootstrap_authority()
                    .into_iter()
                    .chain(journal.retained_grid.iter().map(|record| record.authority))
                    .find(|record| record.authority_id == self.cause_authority_id)
                    .ok_or_else(|| eyre!("cause-2 retained invalidated authority is absent"))?;
                let mut advanced_locator = invalidated.locator;
                advanced_locator.safe_l1_number = observation.safe_l1_number;
                advanced_locator.safe_l1_hash = observation.safe_l1_hash;
                ensure!(
                    observation.locator() != advanced_locator,
                    "safe advancement alone cannot invalidate retained authority"
                );
                ensure!(
                    self.candidate_sequence == invalidated.start_sequence
                        && self.candidate_sequence >= journal.anchor().sequence
                        && self.candidate_sequence <= v.sequence
                        && self.expected_value == invalidated.evidence_digest
                        && self.observed_value == observation.evidence_digest(),
                    "cause-2 authenticated retained-authority contract mismatch"
                );
            }
            DivergenceCauseV4::SequencerAccumulatorMismatch => ensure!(
                self.candidate_sequence == observation.promoted_start_sequence
                    && self.cause_authority_id == current_predecessor
                    && self.expected_value == observation.terminal_sequencer_accumulator,
                "cause-3 authenticated accumulator contract mismatch"
            ),
            // The cause values describe the complete batch's event/getter and local formula;
            // the observation terminal may precede its delayed tail when J ends mid-batch.
            DivergenceCauseV4::DelayedAccumulatorMismatch => ensure!(
                self.candidate_sequence == observation.promoted_start_sequence
                    && observation.terminal_delayed_count > 0
                    && self.cause_authority_id == current_predecessor,
                "cause-4 authenticated accumulator contract mismatch"
            ),
            DivergenceCauseV4::CompactObservationMismatch => ensure!(
                self.candidate_sequence == observation.promoted_start_sequence
                    && self.cause_authority_id == current_predecessor
                    && self.observed_value == observation.evidence_digest(),
                "cause-5 authenticated observation contract mismatch"
            ),
            DivergenceCauseV4::ImpossibleDurablePredecessorContradiction => ensure!(
                self.candidate_sequence == observation.promoted_start_sequence
                    && self.observed_value == current_predecessor,
                "cause-6 fresh locked predecessor contract mismatch"
            ),
        }
        Ok(())
    }

    /// Authenticate every marker field that can be re-established from the stopped durable
    /// journal alone. Full observation/provider reproduction is required at write time; startup
    /// still rejects a structurally valid frame that was transplanted onto another journal state.
    pub fn validate_journal_state(self, journal: &MessageJournalInspection) -> eyre::Result<()> {
        self.validate_fields()?;
        let v = journal.v.ok_or_else(|| eyre!("divergence-v4 requires V"))?;
        ensure!(
            journal.anchor().sequence <= self.candidate_sequence
                && self.candidate_sequence <= journal.watermark.sequence
                && (
                    self.j_sequence,
                    self.j_l2_block_number,
                    self.j_l2_block_hash
                ) == (
                    journal.watermark.sequence,
                    journal.watermark.block_number,
                    journal.watermark.block_hash,
                )
                && (
                    self.v_sequence,
                    self.v_l2_block_number,
                    self.v_l2_block_hash
                ) == (v.sequence, v.block_number, v.block_hash)
                && self.journal_operation_generation == journal.last_operation_generation
                && self.authority_chain_position == journal.authority_operation_count,
            "divergence-v4 durable journal identity mismatch"
        );
        match self.cause {
            DivergenceCauseV4::FeedL1IdentityMismatch => {
                let durable = journal
                    .entry(self.candidate_sequence)
                    .ok_or_else(|| eyre!("cause-1 durable candidate identity is absent"))?;
                ensure!(
                    fingerprint_commitment(durable.fingerprint) == self.expected_fingerprint
                        && self.cause_authority_id == journal.latest_authority_id
                        && self.expected_value == journal.latest_authority_chain_digest,
                    "cause-1 durable journal authentication failed"
                );
            }
            DivergenceCauseV4::ExistingAuthorityInvalidatedBySafeReorg => {
                let authority = journal
                    .bootstrap_authority()
                    .into_iter()
                    .chain(journal.retained_grid.iter().map(|record| record.authority))
                    .find(|record| record.authority_id == self.cause_authority_id)
                    .ok_or_else(|| eyre!("cause-2 retained invalidated authority is absent"))?;
                ensure!(
                    self.candidate_sequence == authority.start_sequence
                        && self.expected_value == authority.evidence_digest,
                    "cause-2 durable authority authentication failed"
                );
            }
            DivergenceCauseV4::SequencerAccumulatorMismatch
            | DivergenceCauseV4::DelayedAccumulatorMismatch
            | DivergenceCauseV4::CompactObservationMismatch => ensure!(
                self.cause_authority_id == journal.latest_authority_id,
                "divergence-v4 durable predecessor authentication failed"
            ),
            DivergenceCauseV4::ImpossibleDurablePredecessorContradiction => ensure!(
                self.expected_value == self.cause_authority_id
                    && self.observed_value == journal.latest_authority_id,
                "cause-6 durable predecessor authentication failed"
            ),
        }
        Ok(())
    }
}

pub fn read_divergence_marker_v4(directory: &JournalDirectory) -> eyre::Result<DivergenceMarkerV4> {
    let bytes = directory.read_entry(DIVERGENCE_MARKER_FILE, DIVERGENCE_MARKER_V4_LEN)?;
    DivergenceMarkerV4::decode(&bytes)
}

pub fn write_divergence_marker_v4(
    directory: &JournalDirectory,
    marker: DivergenceMarkerV4,
) -> eyre::Result<()> {
    ensure!(
        !directory.entry_exists(DIVERGENCE_MARKER_FILE)?,
        "divergence-v4 marker already exists"
    );
    let bytes = marker.encode()?;
    directory.write_entry_atomic(
        "arb-message-divergence.json.tmp",
        DIVERGENCE_MARKER_FILE,
        &bytes,
        false,
    )?;
    ensure!(
        read_divergence_marker_v4(directory)? == marker,
        "divergence-v4 durable reread mismatch"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::keccak256;

    #[test]
    fn exact_bootstrap_observation_vector_and_mutations() {
        let observation = decode_production_bootstrap_observation();
        let encoded = observation.encode();
        assert_eq!(
            B256::from_slice(&Sha256::digest(encoded)),
            b256!("30de22c19e7000c11f36f9680692a48069f470d710a83e4565e925bc2c78318b")
        );
        assert_eq!(
            observation.evidence_digest(),
            b256!("7dd7b8fc3cff04bda62c089fabc806d2be3be9e09a29e80eab392231cca81514")
        );
        assert_eq!(
            CanonicalObservationV1::decode(&encoded).unwrap(),
            observation
        );
        for offset in [0, 8, 10, 14, 264, 265, 447] {
            let mut changed = encoded;
            changed[offset] ^= 1;
            assert!(
                CanonicalObservationV1::decode(&changed).is_err(),
                "offset {offset}"
            );
        }
        let mut changed_commitment = encoded;
        changed_commitment[391] ^= 1;
        assert_ne!(
            CanonicalObservationV1::decode(&changed_commitment).unwrap(),
            observation
        );

        let mut zero_delayed = observation;
        zero_delayed.start_delayed_count = 0;
        zero_delayed.terminal_delayed_count = 0;
        zero_delayed.terminal_delayed_accumulator = B256::ZERO;
        CanonicalObservationV1::decode(&zero_delayed.encode()).unwrap();
        zero_delayed.terminal_delayed_accumulator = keccak256([]);
        assert!(CanonicalObservationV1::decode(&zero_delayed.encode()).is_err());
    }

    fn marker(cause: DivergenceCauseV4) -> DivergenceMarkerV4 {
        let fingerprint = cause == DivergenceCauseV4::FeedL1IdentityMismatch;
        let candidate = if cause == DivergenceCauseV4::ExistingAuthorityInvalidatedBySafeReorg {
            10
        } else {
            12
        };
        let (expected, observed) =
            if cause == DivergenceCauseV4::ImpossibleDurablePredecessorContradiction {
                (B256::repeat_byte(11), B256::repeat_byte(13))
            } else {
                (B256::repeat_byte(12), B256::repeat_byte(13))
            };
        DivergenceMarkerV4 {
            cause,
            journal_operation_generation: 4,
            authority_chain_position: 3,
            context_id: PRODUCTION_CONTEXT_ID,
            context_digest: PRODUCTION_CONTEXT_DIGEST,
            j_sequence: 13,
            j_l2_block_number: 13,
            j_l2_block_hash: B256::repeat_byte(1),
            v_sequence: 11,
            v_l2_block_number: 11,
            v_l2_block_hash: B256::repeat_byte(2),
            candidate_sequence: candidate,
            candidate_l2_block_number: candidate,
            expected_fingerprint: if fingerprint {
                B256::repeat_byte(3)
            } else {
                B256::ZERO
            },
            observed_fingerprint: if fingerprint {
                B256::repeat_byte(4)
            } else {
                B256::ZERO
            },
            safe_l1_number: 20,
            safe_l1_hash: B256::repeat_byte(5),
            containing_l1_number: 19,
            containing_l1_hash: B256::repeat_byte(6),
            posting_transaction_hash: B256::repeat_byte(7),
            posting_transaction_index: 2,
            delivery_log_index: 3,
            batch_sequence: 4,
            terminal_message_ordinal: 1,
            decoded_message_count: 2,
            cause_authority_id: B256::repeat_byte(11),
            expected_value: expected,
            observed_value: observed,
        }
    }

    #[test]
    fn every_v4_cause_roundtrips_and_cross_cause_fields_reject() {
        for cause in [
            DivergenceCauseV4::FeedL1IdentityMismatch,
            DivergenceCauseV4::ExistingAuthorityInvalidatedBySafeReorg,
            DivergenceCauseV4::SequencerAccumulatorMismatch,
            DivergenceCauseV4::DelayedAccumulatorMismatch,
            DivergenceCauseV4::CompactObservationMismatch,
            DivergenceCauseV4::ImpossibleDurablePredecessorContradiction,
        ] {
            let marker = marker(cause);
            let encoded = marker.encode().unwrap();
            assert_eq!(DivergenceMarkerV4::decode(&encoded).unwrap(), marker);
            let mut malformed = encoded;
            malformed[36] = 1;
            let checksum = framed_hash(DIVERGENCE_DOMAIN, &malformed[..480]);
            malformed[480..].copy_from_slice(checksum.as_slice());
            assert!(DivergenceMarkerV4::decode(&malformed).is_err());
            let mut malformed = encoded;
            malformed[511] ^= 1;
            assert!(DivergenceMarkerV4::decode(&malformed).is_err());
            let mut malformed = encoded;
            malformed[184] = 1;
            let checksum = framed_hash(DIVERGENCE_DOMAIN, &malformed[..480]);
            malformed[480..].copy_from_slice(checksum.as_slice());
            if cause == DivergenceCauseV4::FeedL1IdentityMismatch {
                let expected = malformed[184..216].to_vec();
                malformed[216..248].copy_from_slice(&expected);
                let checksum = framed_hash(DIVERGENCE_DOMAIN, &malformed[..480]);
                malformed[480..].copy_from_slice(checksum.as_slice());
            }
            assert!(DivergenceMarkerV4::decode(&malformed).is_err());
        }
        assert_eq!(
            B256::from_slice(&Sha256::digest(
                marker(DivergenceCauseV4::FeedL1IdentityMismatch)
                    .encode()
                    .unwrap()
            )),
            b256!("cf6c5a966a498eaac66cee30a34087b2196a541859a3561a2a07bbfae0884616")
        );
        let mut cross_cause = marker(DivergenceCauseV4::FeedL1IdentityMismatch)
            .encode()
            .unwrap();
        put_u16(
            &mut cross_cause[10..12],
            DivergenceCauseV4::ExistingAuthorityInvalidatedBySafeReorg as u16,
        );
        let checksum = framed_hash(DIVERGENCE_DOMAIN, &cross_cause[..480]);
        cross_cause[480..].copy_from_slice(checksum.as_slice());
        assert!(DivergenceMarkerV4::decode(&cross_cause).is_err());
        assert!(DivergenceMarkerV4::decode(br#"{"version":3}"#).is_err());
    }
}
