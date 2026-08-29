//! Frozen Robinhood full-snapshot trust and completion evidence.

use std::{io::Read, path::Path};

use alloy_primitives::{B256, keccak256};
use arb_reth_engine::JournalDirectory;
use eyre::{WrapErr as _, ensure, eyre};
use sha2::{Digest as _, Sha256};

pub(crate) const SNAPSHOT_COMPLETION_FILE: &str = "arb-snapshot-completion-v1.bin";
pub(crate) const SNAPSHOT_COMPLETION_TEMP: &str = "arb-snapshot-completion-v1.bin.tmp";

const DESCRIPTOR_LEN: usize = 501;
const DESCRIPTOR_SHA256: B256 = B256::new([
    0x18, 0x4f, 0x79, 0x68, 0x65, 0xbf, 0xce, 0xbb, 0x48, 0x00, 0x99, 0x89, 0xe5, 0x67, 0x70, 0xd6,
    0xe2, 0xda, 0x4b, 0x7f, 0x5e, 0x44, 0x38, 0xad, 0xf7, 0x26, 0xbf, 0x15, 0x1e, 0x75, 0xee, 0x14,
]);
const CHAIN_ID: u64 = 4_663;
const CHAIN_INFO_SHA256: B256 = B256::new([
    0xcf, 0x6c, 0x0a, 0xa2, 0xbc, 0x52, 0x0a, 0x28, 0xfe, 0x89, 0x83, 0xf7, 0x83, 0x67, 0x6b, 0xc4,
    0x3d, 0xe9, 0x4c, 0xc2, 0x5a, 0x57, 0xa1, 0xcd, 0xc9, 0xb1, 0xf0, 0xaf, 0xc5, 0x20, 0x8f, 0x0a,
]);
const GENESIS_SHA256: B256 = B256::new([
    0x35, 0x3e, 0x6f, 0x64, 0x41, 0xb4, 0x76, 0x95, 0xb4, 0x1c, 0xee, 0x0c, 0x36, 0x45, 0xcd, 0xe8,
    0xdd, 0x74, 0x92, 0xd2, 0xf7, 0xf5, 0x74, 0xbf, 0xb6, 0xaa, 0x43, 0x71, 0xe4, 0x1b, 0xb6, 0xba,
]);
const STREAM_SIZE: u64 = 449_373_850_334;
const STREAM_SHA256: B256 = B256::new([
    0x80, 0x7b, 0x4d, 0x71, 0xba, 0xee, 0xb9, 0x13, 0x82, 0x6d, 0x82, 0x3a, 0x76, 0xfa, 0xa0, 0x05,
    0x6a, 0x6e, 0xa0, 0xa7, 0x9f, 0xc8, 0x08, 0x34, 0x6f, 0xeb, 0x2d, 0xfe, 0xcd, 0xc8, 0xd3, 0x9f,
]);
const HEAD_NUMBER: u64 = 31_805_144;
const HEAD_HASH: B256 = B256::new([
    0xcc, 0x8b, 0x40, 0x72, 0x11, 0xb6, 0x9d, 0xba, 0xc3, 0xe1, 0x6d, 0xc0, 0x83, 0xa9, 0x80, 0xdb,
    0x25, 0xda, 0x71, 0x33, 0xde, 0x71, 0x4d, 0x5f, 0x69, 0xb7, 0xf3, 0xd0, 0x68, 0x27, 0x89, 0x90,
]);
const HEAD_STATE_ROOT: B256 = B256::new([
    0x2f, 0xfa, 0xe1, 0x1c, 0xe6, 0x86, 0xdd, 0x86, 0x12, 0x71, 0xbf, 0x27, 0x28, 0xc1, 0x15, 0xcd,
    0xb7, 0x11, 0x88, 0x7c, 0xc6, 0xb6, 0xa6, 0x24, 0x12, 0x7b, 0xb6, 0x07, 0xe4, 0x3c, 0xe9, 0xb1,
]);

const COMPLETION_MAGIC: &[u8; 16] = b"ARBSNAPSHOTV1\0\0\0";
const COMPLETION_VERSION: u16 = 1;
const COMPLETION_LEN: usize = 288;

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustDescriptor {
    version: u64,
    chain_id: u64,
    chain_info_sha256: String,
    genesis_sha256: String,
    stream_size: u64,
    stream_sha256: String,
    head_number: u64,
    head_hash: String,
    head_state_root: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ApprovedSnapshotTrust {
    pub descriptor_sha256: B256,
    pub chain_id: u64,
    pub chain_info_sha256: B256,
    pub genesis_sha256: B256,
    pub stream_size: u64,
    pub stream_sha256: B256,
    pub head_number: u64,
    pub head_hash: B256,
    pub head_state_root: B256,
}

impl ApprovedSnapshotTrust {
    const fn frozen() -> Self {
        Self {
            descriptor_sha256: DESCRIPTOR_SHA256,
            chain_id: CHAIN_ID,
            chain_info_sha256: CHAIN_INFO_SHA256,
            genesis_sha256: GENESIS_SHA256,
            stream_size: STREAM_SIZE,
            stream_sha256: STREAM_SHA256,
            head_number: HEAD_NUMBER,
            head_hash: HEAD_HASH,
            head_state_root: HEAD_STATE_ROOT,
        }
    }
}

pub(crate) fn load_approved_descriptor(path: &Path) -> eyre::Result<ApprovedSnapshotTrust> {
    let bytes = std::fs::read(path)
        .wrap_err_with(|| format!("read snapshot trust descriptor {}", path.display()))?;
    ensure!(
        bytes.len() == DESCRIPTOR_LEN,
        "snapshot trust descriptor length is {}, expected {DESCRIPTOR_LEN}",
        bytes.len()
    );
    let digest = sha256_bytes(&bytes);
    ensure!(
        digest == DESCRIPTOR_SHA256,
        "snapshot trust descriptor is not compile-time allowlisted"
    );
    let descriptor: TrustDescriptor = serde_json::from_slice(&bytes)?;
    let frozen = ApprovedSnapshotTrust::frozen();
    ensure!(
        descriptor.version == 1,
        "snapshot trust descriptor version is not 1"
    );
    ensure!(
        descriptor.chain_id == frozen.chain_id,
        "snapshot trust chain id changed"
    );
    ensure!(
        descriptor.stream_size == frozen.stream_size,
        "snapshot trust stream size changed"
    );
    ensure!(
        descriptor.head_number == frozen.head_number,
        "snapshot trust head number changed"
    );
    ensure!(
        parse_hex(&descriptor.chain_info_sha256)? == frozen.chain_info_sha256,
        "snapshot trust chain-info digest changed"
    );
    ensure!(
        parse_hex(&descriptor.genesis_sha256)? == frozen.genesis_sha256,
        "snapshot trust genesis digest changed"
    );
    ensure!(
        parse_hex(&descriptor.stream_sha256)? == frozen.stream_sha256,
        "snapshot trust stream digest changed"
    );
    ensure!(
        parse_hex(&descriptor.head_hash)? == frozen.head_hash,
        "snapshot trust head hash changed"
    );
    ensure!(
        parse_hex(&descriptor.head_state_root)? == frozen.head_state_root,
        "snapshot trust state root changed"
    );
    Ok(frozen)
}

pub(crate) fn verify_snapshot_metadata(
    trust: ApprovedSnapshotTrust,
    chain_info: &[u8],
    genesis: &[u8],
) -> eyre::Result<()> {
    ensure!(
        sha256_bytes(chain_info) == trust.chain_info_sha256,
        "chain-info SHA-256 does not match frozen trust descriptor"
    );
    ensure!(
        sha256_bytes(genesis) == trust.genesis_sha256,
        "genesis JSON SHA-256 does not match frozen trust descriptor"
    );
    Ok(())
}

pub(crate) fn verify_snapshot_stream_digest(
    trust: ApprovedSnapshotTrust,
    length: u64,
    digest: B256,
) -> eyre::Result<()> {
    ensure!(
        length == trust.stream_size,
        "full snapshot length {length} does not match frozen {}",
        trust.stream_size
    );
    ensure!(
        digest == trust.stream_sha256,
        "full snapshot SHA-256 does not match frozen trust descriptor"
    );
    Ok(())
}

pub(crate) struct SnapshotDigestReader<R> {
    inner: R,
    hasher: Sha256,
    length: u64,
}

impl<R> SnapshotDigestReader<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            length: 0,
        }
    }

    pub(crate) fn finish(self) -> (u64, B256) {
        (self.length, B256::from_slice(&self.hasher.finalize()))
    }
}

impl<R: Read> Read for SnapshotDigestReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.length = self
            .length
            .checked_add(read as u64)
            .ok_or_else(|| std::io::Error::other("snapshot stream length overflow"))?;
        self.hasher.update(&buffer[..read]);
        Ok(read)
    }
}

fn sha256_bytes(bytes: &[u8]) -> B256 {
    B256::from_slice(&Sha256::digest(bytes))
}

fn parse_hex(value: &str) -> eyre::Result<B256> {
    value
        .parse::<B256>()
        .map_err(|error| eyre!("invalid descriptor digest {value:?}: {error}"))
}

pub(crate) fn encode_completion(trust: ApprovedSnapshotTrust) -> [u8; COMPLETION_LEN] {
    let mut out = [0u8; COMPLETION_LEN];
    out[..16].copy_from_slice(COMPLETION_MAGIC);
    out[16..18].copy_from_slice(&COMPLETION_VERSION.to_be_bytes());
    out[18..26].copy_from_slice(&trust.chain_id.to_be_bytes());
    out[26..58].copy_from_slice(trust.descriptor_sha256.as_slice());
    out[58..66].copy_from_slice(&trust.head_number.to_be_bytes());
    out[66..98].copy_from_slice(trust.head_hash.as_slice());
    out[98..130].copy_from_slice(trust.head_state_root.as_slice());
    out[130..162].copy_from_slice(trust.stream_sha256.as_slice());
    out[162..194].copy_from_slice(trust.chain_info_sha256.as_slice());
    out[194..226].copy_from_slice(trust.genesis_sha256.as_slice());
    let checksum = keccak256(&out[..256]);
    out[256..].copy_from_slice(checksum.as_slice());
    out
}

pub(crate) fn decode_completion(bytes: &[u8]) -> eyre::Result<ApprovedSnapshotTrust> {
    ensure!(
        bytes.len() == COMPLETION_LEN,
        "snapshot completion length is not 288"
    );
    ensure!(
        &bytes[..16] == COMPLETION_MAGIC,
        "snapshot completion magic mismatch"
    );
    ensure!(
        u16::from_be_bytes(bytes[16..18].try_into().unwrap()) == COMPLETION_VERSION,
        "snapshot completion version mismatch"
    );
    ensure!(
        bytes[226..256].iter().all(|byte| *byte == 0),
        "snapshot completion reserved bytes are nonzero"
    );
    ensure!(
        keccak256(&bytes[..256]).as_slice() == &bytes[256..],
        "snapshot completion checksum mismatch"
    );
    let decoded = ApprovedSnapshotTrust {
        descriptor_sha256: B256::from_slice(&bytes[26..58]),
        chain_id: u64::from_be_bytes(bytes[18..26].try_into().unwrap()),
        chain_info_sha256: B256::from_slice(&bytes[162..194]),
        genesis_sha256: B256::from_slice(&bytes[194..226]),
        stream_size: STREAM_SIZE,
        stream_sha256: B256::from_slice(&bytes[130..162]),
        head_number: u64::from_be_bytes(bytes[58..66].try_into().unwrap()),
        head_hash: B256::from_slice(&bytes[66..98]),
        head_state_root: B256::from_slice(&bytes[98..130]),
    };
    ensure!(
        decoded == ApprovedSnapshotTrust::frozen(),
        "snapshot completion is not the frozen Robinhood authority"
    );
    Ok(decoded)
}

pub(crate) fn write_completion(datadir: &Path, trust: ApprovedSnapshotTrust) -> eyre::Result<()> {
    let directory = JournalDirectory::open(datadir)?;
    ensure!(
        !directory.entry_exists(SNAPSHOT_COMPLETION_FILE)?
            && !directory.entry_exists(SNAPSHOT_COMPLETION_TEMP)?,
        "snapshot completion artifact already exists"
    );
    let bytes = encode_completion(trust);
    directory.write_entry_atomic(
        SNAPSHOT_COMPLETION_TEMP,
        SNAPSHOT_COMPLETION_FILE,
        &bytes,
        false,
    )?;
    ensure!(
        read_completion(&directory)? == trust,
        "renamed snapshot completion changed"
    );
    Ok(())
}

pub(crate) fn read_completion(directory: &JournalDirectory) -> eyre::Result<ApprovedSnapshotTrust> {
    decode_completion(&directory.read_entry(SNAPSHOT_COMPLETION_FILE, COMPLETION_LEN)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const APPROVED_DESCRIPTOR_BYTES: &[u8; DESCRIPTOR_LEN] = br#"{"version":1,"chain_id":4663,"chain_info_sha256":"cf6c0aa2bc520a28fe8983f783676bc43de94cc25a57a1cdc9b1f0afc5208f0a","genesis_sha256":"353e6f6441b47695b41cee0c3645cde8dd7492d2f7f574bfb6aa4371e41bb6ba","stream_size":449373850334,"stream_sha256":"807b4d71baeeb913826d823a76faa0056a6ea0a79fc808346feb2dfecdc8d39f","head_number":31805144,"head_hash":"0xcc8b407211b69dbac3e16dc083a980db25da7133de714d5f69b7f3d068278990","head_state_root":"0x2ffae11ce686dd861271bf2728c115cdb711887cc6b6a624127bb607e43ce9b1"}"#;

    #[test]
    fn completion_codec_is_fixed_big_endian_and_mutation_resistant() {
        let trust = ApprovedSnapshotTrust::frozen();
        let bytes = encode_completion(trust);
        assert_eq!(
            alloy_primitives::hex::encode(bytes),
            "415242534e415053484f54563100000000010000000000001237184f796865bfcebb48009989e56770d6e2da4b7f5e4438adf726bf151e75ee140000000001e54ed8cc8b407211b69dbac3e16dc083a980db25da7133de714d5f69b7f3d0682789902ffae11ce686dd861271bf2728c115cdb711887cc6b6a624127bb607e43ce9b1807b4d71baeeb913826d823a76faa0056a6ea0a79fc808346feb2dfecdc8d39fcf6c0aa2bc520a28fe8983f783676bc43de94cc25a57a1cdc9b1f0afc5208f0a353e6f6441b47695b41cee0c3645cde8dd7492d2f7f574bfb6aa4371e41bb6ba00000000000000000000000000000000000000000000000000000000000008bee9f4e3439cad4beba866a3782a0f9d20cd25d9567e13f3e5d56a09268a99"
        );
        assert_eq!(bytes.len(), 288);
        assert_eq!(&bytes[18..26], &CHAIN_ID.to_be_bytes());
        assert_eq!(&bytes[58..66], &HEAD_NUMBER.to_be_bytes());
        assert_eq!(decode_completion(&bytes).unwrap(), trust);
        for offset in [0usize, 16, 18, 26, 58, 66, 98, 130, 162, 194, 226, 256, 287] {
            let mut changed = bytes;
            changed[offset] ^= 1;
            assert!(
                decode_completion(&changed).is_err(),
                "mutation at {offset} accepted"
            );
        }
    }

    #[test]
    fn packet_descriptor_is_the_only_allowlisted_descriptor() {
        let dir = tempfile::tempdir().unwrap();
        let descriptor = dir.path().join("approved-descriptor.json");
        std::fs::write(&descriptor, APPROVED_DESCRIPTOR_BYTES).unwrap();
        assert_eq!(
            load_approved_descriptor(&descriptor).unwrap(),
            ApprovedSnapshotTrust::frozen()
        );
        let self_issued = dir.path().join("descriptor.json");
        std::fs::write(&self_issued, b"{}").unwrap();
        assert!(load_approved_descriptor(&self_issued).is_err());
    }

    #[test]
    fn import_reader_hashes_the_consumed_stream_once() {
        let bytes = b"one forward pass over the snapshot";
        let mut reader = SnapshotDigestReader::new(std::io::Cursor::new(bytes));
        let mut consumed = Vec::new();
        reader.read_to_end(&mut consumed).unwrap();
        let (length, digest) = reader.finish();
        assert_eq!(consumed, bytes);
        assert_eq!(length, bytes.len() as u64);
        assert_eq!(digest, B256::from_slice(&Sha256::digest(bytes)));
    }
}
