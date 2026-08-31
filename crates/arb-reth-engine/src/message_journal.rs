//! Compact Phase-B storage journal.
//!
//! Version 3 freezes only authenticated storage envelopes. Production B1 has no canonical-context
//! registry entries, no bootstrap-certificate allowlist, and no authority producer. A single
//! worker continues to own execution appends; future authority and recovery callers remain absent.

use std::{
    collections::{BTreeMap, VecDeque},
    ffi::{CString, OsStr},
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    },
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use alloy_eips::BlockNumHash;
use alloy_primitives::{Address, B256};
use eyre::{WrapErr as _, ensure, eyre};
use sha2::{Digest as _, Sha256};
use tokio::sync::Notify;

use crate::{ArbEngineInput, ArbEngineInputSource, ArbMessageEnrichment, ArbMessageFingerprint};

pub const MESSAGE_JOURNAL_PREFIX: &str = "arb-message-journal-v3-g";
pub const MESSAGE_JOURNAL_FAMILY_PREFIX: &str = "arb-message-journal";
pub const DIVERGENCE_MARKER_FILE: &str = "arb-message-divergence.json";
pub const LIFECYCLE_FILE: &str = "arb-node-lifecycle-v1.bin";

pub const JOURNAL_WORK_ITEM_CAPACITY: usize = 1_024;
pub const JOURNAL_RECORD_LIABILITY_CAPACITY: usize = 4_096;
pub const JOURNAL_OUTSTANDING_BYTE_CAPACITY: usize = 64 * 1024 * 1024;
pub const PROTECTED_EXECUTION_WORK_FLOOR: usize = 1;
pub const PROTECTED_EXECUTION_RECORD_FLOOR: usize = 1;
pub const MAX_UNJOURNALED_SEQUENCE_DISTANCE: u64 = 1_024;
pub const MAX_SUPPORTED_PERSISTENCE_THRESHOLD: u64 = 512;
pub const AUTHORITY_MAX_RECORDS: usize = 256;
pub const MAINTENANCE_WORK_ITEMS: usize = 1;
pub const MAINTENANCE_MAX_WAIT: Duration = Duration::from_secs(30);
pub const JOURNAL_COMPACT_MIN_IDENTITIES: usize = 100_000;
pub const JOURNAL_COMPACT_DELTA_TRIGGER: usize = 10_000;
pub const JOURNAL_AUTHORITY_COMPACT_TRIGGER: u64 = 128;
pub const JOURNAL_COMPACT_FILE_TRIGGER: u64 = 40 * 1024 * 1024;
pub const JOURNAL_HARD_FILE_LIMIT: u64 = 48 * 1024 * 1024;
pub const JOURNAL_HARD_IDENTITY_LIMIT: usize = 110_000;
pub const JOURNAL_STREAM_SCRATCH: usize = 1024 * 1024;

pub const HEADER_LEN: usize = 256;
pub const FRAME_STORAGE_OVERHEAD: usize = 136;
pub const IDENTITY_LEN: usize = 192;
pub const LOCATOR_LEN: usize = 256;
pub const AUTHORITY_RECORD_LEN: usize = 512;
pub const GRID_RECORD_LEN: usize = 560;
pub const SNAPSHOT_PREFIX_LEN: usize = 512;
pub const MAX_GRID_RECORDS: usize = 128;
pub const MAX_PAYLOAD_LEN: usize = SNAPSHOT_PREFIX_LEN
    + JOURNAL_HARD_IDENTITY_LIMIT * IDENTITY_LEN
    + AUTHORITY_RECORD_LEN
    + MAX_GRID_RECORDS * GRID_RECORD_LEN;
pub const MAX_COMPACTED_FILE_LEN: usize = HEADER_LEN + FRAME_STORAGE_OVERHEAD + MAX_PAYLOAD_LEN;
pub const EXECUTED_STORAGE_LEN: usize = FRAME_STORAGE_OVERHEAD + IDENTITY_LEN;
pub const MAX_AUTHORITY_FRAME_LEN: usize =
    FRAME_STORAGE_OVERHEAD + AUTHORITY_RECORD_LEN + AUTHORITY_MAX_RECORDS * IDENTITY_LEN;
pub const EXACT_MAX_COMPACT_PAYLOAD: usize = 21_192_704;
pub const EXACT_MAX_COMPACT_FILE: usize = 21_193_096;
pub const EXACT_MAX_ENCODED_LIABILITY: usize = 44_204_800;
pub const EXACT_LIABILITY_HEADROOM: usize = 22_904_064;

const EXECUTED_LIABILITY_BYTES: usize = EXECUTED_STORAGE_LEN * 2;
const JOURNAL_MAGIC: &[u8; 16] = b"ARBJOURNALV3\0\0\0\0";
const FRAME_MAGIC: u64 = 0x4152_424a_4652_4d33;
const COMMIT_MAGIC: u64 = 0x4152_424a_434d_5433;
const LOCATOR_MAGIC: &[u8; 8] = b"ARBLOC3\0";
const AUTHORITY_MAGIC: &[u8; 8] = b"ARBAUTH3";
const SNAPSHOT_MAGIC: &[u8; 8] = b"ARBSNAP3";
const SCHEMA_VERSION: u16 = 3;

const DOMAIN_HEADER: &str = "arb-reth-journal-v3-header";
const DOMAIN_FRAME_PREFIX: &str = "arb-reth-journal-v3-frame-prefix";
const DOMAIN_FRAME_COMMIT: &str = "arb-reth-journal-v3-frame-commit";
const DOMAIN_FILE_ROOT: &str = "arb-reth-journal-v3-file-root";
const DOMAIN_STORAGE_CONTEXT: &str = "arb-reth-journal-v3-storage-context";
const DOMAIN_CANONICAL_CONTEXT: &str = "arb-reth-journal-v3-canonical-context";
const DOMAIN_IDENTITIES: &str = "arb-reth-journal-v3-identities";
#[cfg(test)]
const DOMAIN_EVIDENCE: &str = "arb-reth-journal-v3-evidence";
const DOMAIN_AUTHORITY_ID: &str = "arb-reth-journal-v3-authority-id";
const DOMAIN_AUTHORITY_CHAIN: &str = "arb-reth-journal-v3-authority-chain";
const DOMAIN_BOOTSTRAP_CERTIFICATE: &str = "arb-reth-journal-v3-bootstrap-certificate";
const DOMAIN_GRID: &str = "arb-reth-journal-v3-grid";
const DOMAIN_REMOVED_IDENTITIES: &str = "arb-reth-journal-v3-removed-identities";

#[cfg(debug_assertions)]
static AUTHORITY_HOT_PATH_PROHIBITION: AtomicBool = AtomicBool::new(false);

const O_WRONLY: i32 = 0o1;
const O_RDWR: i32 = 0o2;
const O_CREAT: i32 = 0o100;
const O_EXCL: i32 = 0o200;
const O_APPEND: i32 = 0o2000;
const O_DIRECTORY: i32 = 0o200000;
const O_NOFOLLOW: i32 = 0o400000;
const O_CLOEXEC: i32 = 0o2000000;
const RENAME_NOREPLACE: u32 = 1;
#[cfg(target_arch = "x86_64")]
const SYS_GETDENTS64: i64 = 217;
#[cfg(target_arch = "aarch64")]
const SYS_GETDENTS64: i64 = 61;

unsafe extern "C" {
    fn openat(dirfd: i32, pathname: *const i8, flags: i32, mode: u32) -> i32;
    fn renameat(olddirfd: i32, oldpath: *const i8, newdirfd: i32, newpath: *const i8) -> i32;
    fn renameat2(
        olddirfd: i32,
        oldpath: *const i8,
        newdirfd: i32,
        newpath: *const i8,
        flags: u32,
    ) -> i32;
    fn unlinkat(dirfd: i32, pathname: *const i8, flags: i32) -> i32;
    fn fsync(fd: i32) -> i32;
    fn lseek(fd: i32, offset: i64, whence: i32) -> i64;
    fn syscall(number: i64, ...) -> i64;
}

#[doc(hidden)]
pub fn assert_authority_operation_allowed(operation: &str) {
    #[cfg(debug_assertions)]
    assert!(
        !AUTHORITY_HOT_PATH_PROHIBITION.load(Ordering::Acquire),
        "prohibited authority operation on Feed hot path: {operation}"
    );
    #[cfg(not(debug_assertions))]
    let _ = operation;
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub struct AuthorityHotPathGuard;

#[cfg(debug_assertions)]
impl AuthorityHotPathGuard {
    pub fn activate() -> Self {
        assert!(
            !AUTHORITY_HOT_PATH_PROHIBITION.swap(true, Ordering::AcqRel),
            "authority hot-path prohibition is already active"
        );
        Self
    }
}

#[cfg(debug_assertions)]
impl Drop for AuthorityHotPathGuard {
    fn drop(&mut self) {
        assert!(
            AUTHORITY_HOT_PATH_PROHIBITION.swap(false, Ordering::AcqRel),
            "authority hot-path prohibition was not active"
        );
    }
}

/// Pinned, immutable open-file-description for journal authority I/O.
#[derive(Clone, Debug)]
pub struct JournalDirectory {
    path: PathBuf,
    parent: Arc<File>,
    enumeration: Arc<Mutex<()>>,
}

impl JournalDirectory {
    pub fn open(path: &Path) -> eyre::Result<Self> {
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
            .open(path)
            .wrap_err_with(|| format!("open pinned journal datadir {}", path.display()))?;
        ensure!(
            parent.metadata()?.is_dir(),
            "journal datadir is not a directory"
        );
        Ok(Self {
            path: path.to_path_buf(),
            parent: Arc::new(parent),
            enumeration: Arc::new(Mutex::new(())),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn parent_file(&self) -> Arc<File> {
        self.parent.clone()
    }

    pub fn entry_path(&self, name: &str) -> eyre::Result<PathBuf> {
        validate_fixed_name(name)?;
        Ok(self.path.join(name))
    }

    pub fn entry_names(&self) -> eyre::Result<Vec<String>> {
        assert_authority_operation_allowed("getdents64");
        let _enumeration = self
            .enumeration
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let parent = self.parent.as_raw_fd();
        if unsafe { lseek(parent, 0, 0) } < 0 {
            return Err(std::io::Error::last_os_error())
                .wrap_err("rewind pinned authority datadir");
        }
        let mut names = Vec::new();
        let mut buffer = [0u8; 32 * 1024];
        loop {
            let read =
                unsafe { syscall(SYS_GETDENTS64, parent, buffer.as_mut_ptr(), buffer.len()) };
            if read < 0 {
                return Err(std::io::Error::last_os_error())
                    .wrap_err("enumerate pinned authority datadir");
            }
            if read == 0 {
                break;
            }
            let read = usize::try_from(read).expect("positive getdents64 result fits usize");
            let mut offset = 0usize;
            while offset < read {
                ensure!(read - offset >= 19, "truncated getdents64 record");
                let record_len =
                    u16::from_ne_bytes(buffer[offset + 16..offset + 18].try_into().unwrap())
                        as usize;
                ensure!(
                    record_len >= 20 && record_len <= read - offset,
                    "invalid getdents64 record length"
                );
                let name_field = &buffer[offset + 19..offset + record_len];
                let name_len = name_field
                    .iter()
                    .position(|byte| *byte == 0)
                    .ok_or_else(|| eyre!("unterminated getdents64 name"))?;
                let name = std::str::from_utf8(&name_field[..name_len])
                    .map_err(|_| eyre!("non-UTF8 authority entry"))?;
                if !matches!(name, "." | "..") {
                    names.push(name.to_owned());
                }
                offset += record_len;
            }
        }
        names.sort_unstable();
        Ok(names)
    }

    pub fn entry_exists(&self, name: &str) -> eyre::Result<bool> {
        match self.open_existing(name, false, false) {
            Ok(file) => {
                drop(file);
                Ok(true)
            }
            Err(error) if error.raw_os_error() == Some(2) => Ok(false),
            Err(error) => Err(error).wrap_err_with(|| format!("open authority entry {name}")),
        }
    }

    pub fn read_entry(&self, name: &str, maximum: usize) -> eyre::Result<Vec<u8>> {
        let mut file = self.open_existing(name, false, false)?;
        let length = usize::try_from(file.metadata()?.len())?;
        ensure!(
            length <= maximum,
            "authority entry {name} exceeds {maximum} bytes"
        );
        let mut bytes = vec![0u8; length];
        file.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    pub fn create_entry(&self, name: &str, bytes: &[u8]) -> eyre::Result<()> {
        let mut file = self.create_new(name, false)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        self.sync_parent()
    }

    pub fn write_entry_atomic(
        &self,
        temp_name: &str,
        final_name: &str,
        bytes: &[u8],
        replace: bool,
    ) -> eyre::Result<()> {
        let mut file = self.create_new(temp_name, false)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        ensure!(
            self.read_entry(temp_name, bytes.len())? == bytes,
            "atomic authority temp reread mismatch"
        );
        if replace {
            validate_fixed_name(temp_name)?;
            validate_fixed_name(final_name)?;
            let from = CString::new(temp_name).expect("validated name has no NUL");
            let to = CString::new(final_name).expect("validated name has no NUL");
            if unsafe {
                renameat(
                    self.parent.as_raw_fd(),
                    from.as_ptr(),
                    self.parent.as_raw_fd(),
                    to.as_ptr(),
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error()).wrap_err("replace authority entry");
            }
        } else {
            self.rename_noreplace(temp_name, final_name)?;
        }
        self.sync_parent()
    }

    pub fn remove_entry(&self, name: &str) -> eyre::Result<()> {
        assert_authority_operation_allowed("unlinkat");
        validate_fixed_name(name)?;
        let name = CString::new(name).expect("validated name has no NUL");
        if unsafe { unlinkat(self.parent.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error()).wrap_err("unlink authority entry");
        }
        self.sync_parent()
    }

    fn open_existing(&self, name: &str, write: bool, append: bool) -> std::io::Result<File> {
        assert_authority_operation_allowed("openat-existing");
        validate_fixed_name_io(name)?;
        let name = CString::new(name).expect("validated name has no NUL");
        let access = if write { O_RDWR } else { 0 };
        let flags = access | O_CLOEXEC | O_NOFOLLOW | if append { O_APPEND } else { 0 };
        let fd = unsafe { openat(self.parent.as_raw_fd(), name.as_ptr(), flags, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(std::io::Error::other(
                "authority entry is not a singly-linked regular file",
            ));
        }
        Ok(file)
    }

    fn create_new(&self, name: &str, read: bool) -> eyre::Result<File> {
        assert_authority_operation_allowed("openat-create");
        validate_fixed_name(name)?;
        let name = CString::new(name).expect("validated name has no NUL");
        let access = if read { O_RDWR } else { O_WRONLY };
        let fd = unsafe {
            openat(
                self.parent.as_raw_fd(),
                name.as_ptr(),
                access | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).wrap_err("create authority entry");
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn rename_noreplace(&self, from: &str, to: &str) -> eyre::Result<()> {
        assert_authority_operation_allowed("renameat2");
        validate_fixed_name(from)?;
        validate_fixed_name(to)?;
        let from = CString::new(from).expect("validated name has no NUL");
        let to = CString::new(to).expect("validated name has no NUL");
        if unsafe {
            renameat2(
                self.parent.as_raw_fd(),
                from.as_ptr(),
                self.parent.as_raw_fd(),
                to.as_ptr(),
                RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error()).wrap_err("rename authority entry");
        }
        Ok(())
    }

    fn sync_parent(&self) -> eyre::Result<()> {
        assert_authority_operation_allowed("parent-fsync");
        if unsafe { fsync(self.parent.as_raw_fd()) } != 0 {
            return Err(std::io::Error::last_os_error()).wrap_err("sync authority datadir");
        }
        Ok(())
    }
}

fn validate_fixed_name(name: &str) -> eyre::Result<()> {
    ensure!(
        Path::new(name)
            .components()
            .eq([Component::Normal(OsStr::new(name))]),
        "authority entry name is not fixed"
    );
    ensure!(
        !name.as_bytes().contains(&0),
        "authority entry name contains NUL"
    );
    Ok(())
}

fn validate_fixed_name_io(name: &str) -> std::io::Result<()> {
    validate_fixed_name(name).map_err(std::io::Error::other)
}

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
    u16::from_be_bytes(bytes.try_into().expect("validated fixed field"))
}

fn get_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().expect("validated fixed field"))
}

fn get_u64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().expect("validated fixed field"))
}

fn framed_hasher(domain: &str, payload_len: usize) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(
        u16::try_from(domain.len())
            .expect("frozen domain length fits u16")
            .to_be_bytes(),
    );
    hasher.update(domain.as_bytes());
    hasher.update(
        u64::try_from(payload_len)
            .expect("payload length fits u64")
            .to_be_bytes(),
    );
    hasher
}

fn domain_hash(domain: &str, payload: &[u8]) -> B256 {
    let mut hasher = framed_hasher(domain, payload.len());
    hasher.update(payload);
    B256::from_slice(&hasher.finalize())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageJournalAnchor {
    pub sequence: u64,
    pub block_number: u64,
    pub block_hash: B256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageContextV3 {
    pub l2_chain_id: u64,
    pub l2_genesis_number: u64,
    pub l2_genesis_hash: B256,
    pub sequencer_inbox: Address,
    pub bridge: Address,
    pub deployment_block: u64,
    pub anchor: MessageJournalAnchor,
}

impl StorageContextV3 {
    pub fn digest(self) -> B256 {
        let mut payload = [0u8; 144];
        put_u64(&mut payload[0..8], self.l2_chain_id);
        put_u64(&mut payload[8..16], self.l2_genesis_number);
        payload[16..48].copy_from_slice(self.l2_genesis_hash.as_slice());
        payload[48..68].copy_from_slice(self.sequencer_inbox.as_slice());
        payload[68..88].copy_from_slice(self.bridge.as_slice());
        put_u64(&mut payload[88..96], self.deployment_block);
        put_u64(&mut payload[96..104], self.anchor.sequence);
        put_u64(&mut payload[104..112], self.anchor.block_number);
        payload[112..144].copy_from_slice(self.anchor.block_hash.as_slice());
        domain_hash(DOMAIN_STORAGE_CONTEXT, &payload)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageJournalEntry {
    pub sequence: u64,
    pub block_number: u64,
    pub block_hash: B256,
    pub parent_hash: B256,
    pub delayed_messages_read: u64,
    pub fingerprint: ArbMessageFingerprint,
    pub source: ArbEngineInputSource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalHeader {
    pub lineage_generation: u64,
    pub snapshot_through_operation_generation: u64,
    pub predecessor_file_root: B256,
    pub anchor: MessageJournalAnchor,
    pub storage_context_digest: B256,
}

pub fn encode_header(header: JournalHeader) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[..16].copy_from_slice(JOURNAL_MAGIC);
    put_u16(&mut out[16..18], SCHEMA_VERSION);
    put_u16(&mut out[18..20], HEADER_LEN as u16);
    put_u64(&mut out[20..28], header.lineage_generation);
    put_u64(
        &mut out[28..36],
        header.snapshot_through_operation_generation,
    );
    out[36..68].copy_from_slice(header.predecessor_file_root.as_slice());
    put_u64(&mut out[68..76], header.anchor.sequence);
    put_u64(&mut out[76..84], header.anchor.block_number);
    out[84..116].copy_from_slice(header.anchor.block_hash.as_slice());
    out[116..148].copy_from_slice(header.storage_context_digest.as_slice());
    let digest = domain_hash(DOMAIN_HEADER, &out[..224]);
    out[224..256].copy_from_slice(digest.as_slice());
    out
}

pub fn decode_header(bytes: &[u8]) -> eyre::Result<JournalHeader> {
    ensure!(
        bytes.len() == HEADER_LEN,
        "journal header length is not {HEADER_LEN}"
    );
    ensure!(
        &bytes[..16] == JOURNAL_MAGIC,
        "invalid journal header magic"
    );
    ensure!(
        get_u16(&bytes[16..18]) == SCHEMA_VERSION,
        "unsupported journal schema"
    );
    ensure!(
        get_u16(&bytes[18..20]) as usize == HEADER_LEN,
        "invalid header length field"
    );
    ensure!(
        bytes[148..224].iter().all(|byte| *byte == 0),
        "nonzero header reserved bytes"
    );
    ensure!(
        domain_hash(DOMAIN_HEADER, &bytes[..224]).as_slice() == &bytes[224..256],
        "invalid journal header digest"
    );
    let header = JournalHeader {
        lineage_generation: get_u64(&bytes[20..28]),
        snapshot_through_operation_generation: get_u64(&bytes[28..36]),
        predecessor_file_root: B256::from_slice(&bytes[36..68]),
        anchor: MessageJournalAnchor {
            sequence: get_u64(&bytes[68..76]),
            block_number: get_u64(&bytes[76..84]),
            block_hash: B256::from_slice(&bytes[84..116]),
        },
        storage_context_digest: B256::from_slice(&bytes[116..148]),
    };
    if header.lineage_generation == 0 {
        ensure!(
            header.snapshot_through_operation_generation == 0
                && header.predecessor_file_root == B256::ZERO,
            "lineage zero has predecessor authority"
        );
    } else {
        ensure!(
            header.predecessor_file_root != B256::ZERO,
            "later lineage has zero predecessor root"
        );
    }
    Ok(header)
}

pub fn encode_identity(entry: MessageJournalEntry) -> [u8; IDENTITY_LEN] {
    let mut out = [0u8; IDENTITY_LEN];
    put_u64(&mut out[0..8], entry.sequence);
    put_u64(&mut out[8..16], entry.block_number);
    out[16..48].copy_from_slice(entry.block_hash.as_slice());
    out[48..80].copy_from_slice(entry.parent_hash.as_slice());
    put_u64(&mut out[80..88], entry.delayed_messages_read);
    out[88..120].copy_from_slice(entry.fingerprint.core.as_slice());
    if let Some(cost) = entry.fingerprint.enrichment.legacy_batch_gas_cost {
        out[120] = 1;
        put_u64(&mut out[121..129], cost);
    }
    if let Some((length, nonzeros)) = entry.fingerprint.enrichment.batch_data_stats {
        out[129] = 1;
        put_u64(&mut out[130..138], length);
        put_u64(&mut out[138..146], nonzeros);
    }
    out[146] = match entry.source {
        ArbEngineInputSource::Feed => 0,
        ArbEngineInputSource::L1 => 1,
    };
    out
}

pub fn decode_identity(bytes: &[u8]) -> eyre::Result<MessageJournalEntry> {
    ensure!(
        bytes.len() == IDENTITY_LEN,
        "identity length is not {IDENTITY_LEN}"
    );
    ensure!(matches!(bytes[120], 0 | 1), "invalid legacy-cost presence");
    ensure!(matches!(bytes[129], 0 | 1), "invalid batch-stats presence");
    ensure!(matches!(bytes[146], 0 | 1), "invalid identity source");
    ensure!(
        bytes[147..].iter().all(|byte| *byte == 0),
        "nonzero identity epoch/reserved bytes"
    );
    ensure!(
        bytes[120] == 1 || bytes[121..129].iter().all(|byte| *byte == 0),
        "absent legacy cost is nonzero"
    );
    ensure!(
        bytes[129] == 1 || bytes[130..146].iter().all(|byte| *byte == 0),
        "absent batch stats are nonzero"
    );
    let batch_stats =
        (bytes[129] == 1).then(|| (get_u64(&bytes[130..138]), get_u64(&bytes[138..146])));
    if let Some((length, nonzeros)) = batch_stats {
        ensure!(nonzeros <= length, "batch nonzeros exceed length");
    }
    Ok(MessageJournalEntry {
        sequence: get_u64(&bytes[0..8]),
        block_number: get_u64(&bytes[8..16]),
        block_hash: B256::from_slice(&bytes[16..48]),
        parent_hash: B256::from_slice(&bytes[48..80]),
        delayed_messages_read: get_u64(&bytes[80..88]),
        fingerprint: ArbMessageFingerprint {
            core: B256::from_slice(&bytes[88..120]),
            enrichment: ArbMessageEnrichment {
                legacy_batch_gas_cost: (bytes[120] == 1).then(|| get_u64(&bytes[121..129])),
                batch_data_stats: batch_stats,
            },
        },
        source: if bytes[146] == 0 {
            ArbEngineInputSource::Feed
        } else {
            ArbEngineInputSource::L1
        },
    })
}

fn collection_digest(domain: &str, encoded: impl Iterator<Item = Vec<u8>>, count: usize) -> B256 {
    let chunks: Vec<Vec<u8>> = encoded.collect();
    let payload_len = 2 + chunks.iter().map(Vec::len).sum::<usize>();
    let mut hasher = framed_hasher(domain, payload_len);
    hasher.update(
        u16::try_from(count)
            .expect("frozen collection cap fits u16")
            .to_be_bytes(),
    );
    for chunk in chunks {
        hasher.update(chunk);
    }
    B256::from_slice(&hasher.finalize())
}

fn identities_digest(entries: &[MessageJournalEntry]) -> B256 {
    collection_digest(
        DOMAIN_IDENTITIES,
        entries.iter().map(|entry| encode_identity(*entry).to_vec()),
        entries.len(),
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalContextV1 {
    pub context_id: u16,
    pub l1_chain_id: u64,
    pub l1_genesis_hash: B256,
    pub l2_chain_id: u64,
    pub l2_genesis_number: u64,
    pub l2_genesis_hash: B256,
    pub sequencer_inbox: Address,
    pub bridge: Address,
    pub deployment_block: u64,
    pub beacon_genesis_validators_root: B256,
    pub beacon_genesis_time: u64,
    pub seconds_per_slot: u32,
    pub slots_per_epoch: u32,
    pub fork_schedule: Vec<(u64, [u8; 4])>,
    pub kzg_trusted_setup_digest: B256,
}

impl CanonicalContextV1 {
    pub fn encode(&self) -> eyre::Result<Vec<u8>> {
        ensure!(self.context_id != 0, "zero canonical context id");
        ensure!(
            self.fork_schedule.len() <= 16,
            "canonical fork schedule exceeds 16"
        );
        ensure!(
            self.seconds_per_slot != 0 && self.slots_per_epoch != 0,
            "zero beacon geometry"
        );
        let mut out = Vec::with_capacity(230 + self.fork_schedule.len() * 12);
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&self.context_id.to_be_bytes());
        out.extend_from_slice(&self.l1_chain_id.to_be_bytes());
        out.extend_from_slice(self.l1_genesis_hash.as_slice());
        out.extend_from_slice(&self.l2_chain_id.to_be_bytes());
        out.extend_from_slice(&self.l2_genesis_number.to_be_bytes());
        out.extend_from_slice(self.l2_genesis_hash.as_slice());
        out.extend_from_slice(self.sequencer_inbox.as_slice());
        out.extend_from_slice(self.bridge.as_slice());
        out.extend_from_slice(&self.deployment_block.to_be_bytes());
        out.extend_from_slice(self.beacon_genesis_validators_root.as_slice());
        out.extend_from_slice(&self.beacon_genesis_time.to_be_bytes());
        out.extend_from_slice(&self.seconds_per_slot.to_be_bytes());
        out.extend_from_slice(&self.slots_per_epoch.to_be_bytes());
        out.extend_from_slice(&(self.fork_schedule.len() as u16).to_be_bytes());
        for (epoch, version) in &self.fork_schedule {
            out.extend_from_slice(&epoch.to_be_bytes());
            out.extend_from_slice(version);
        }
        out.extend_from_slice(self.kzg_trusted_setup_digest.as_slice());
        out.extend_from_slice(&1u16.to_be_bytes());
        Ok(out)
    }

    pub fn digest(&self) -> eyre::Result<B256> {
        Ok(domain_hash(DOMAIN_CANONICAL_CONTEXT, &self.encode()?))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceLocatorV1 {
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
    pub terminal_delayed_count: u64,
    pub terminal_sequence: u64,
    pub terminal_l2_block_number: u64,
    pub terminal_l2_block_hash: B256,
}

pub fn encode_locator(locator: EvidenceLocatorV1) -> [u8; LOCATOR_LEN] {
    let mut out = [0u8; LOCATOR_LEN];
    out[..8].copy_from_slice(LOCATOR_MAGIC);
    put_u16(&mut out[8..10], 1);
    put_u16(&mut out[10..12], 1);
    put_u16(&mut out[12..14], locator.context_id);
    out[16..48].copy_from_slice(locator.context_digest.as_slice());
    put_u64(&mut out[48..56], locator.safe_l1_number);
    out[56..88].copy_from_slice(locator.safe_l1_hash.as_slice());
    put_u64(&mut out[88..96], locator.containing_l1_number);
    out[96..128].copy_from_slice(locator.containing_l1_hash.as_slice());
    out[128..160].copy_from_slice(locator.posting_transaction_hash.as_slice());
    put_u32(&mut out[160..164], locator.posting_transaction_index);
    put_u32(&mut out[164..168], locator.delivery_log_index);
    put_u64(&mut out[168..176], locator.batch_sequence);
    put_u32(&mut out[176..180], locator.terminal_message_ordinal);
    put_u32(&mut out[180..184], locator.decoded_message_count);
    put_u64(&mut out[184..192], locator.terminal_delayed_count);
    put_u64(&mut out[192..200], locator.terminal_sequence);
    put_u64(&mut out[200..208], locator.terminal_l2_block_number);
    out[208..240].copy_from_slice(locator.terminal_l2_block_hash.as_slice());
    out
}

pub fn decode_locator(bytes: &[u8]) -> eyre::Result<EvidenceLocatorV1> {
    ensure!(
        bytes.len() == LOCATOR_LEN,
        "locator length is not {LOCATOR_LEN}"
    );
    ensure!(&bytes[..8] == LOCATOR_MAGIC, "invalid locator magic");
    ensure!(get_u16(&bytes[8..10]) == 1, "unsupported locator version");
    ensure!(get_u16(&bytes[10..12]) == 1, "unsupported evidence schema");
    ensure!(
        bytes[14..16].iter().all(|byte| *byte == 0),
        "nonzero locator flags"
    );
    ensure!(
        bytes[240..].iter().all(|byte| *byte == 0),
        "nonzero locator reserved bytes"
    );
    let locator = EvidenceLocatorV1 {
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
        terminal_delayed_count: get_u64(&bytes[184..192]),
        terminal_sequence: get_u64(&bytes[192..200]),
        terminal_l2_block_number: get_u64(&bytes[200..208]),
        terminal_l2_block_hash: B256::from_slice(&bytes[208..240]),
    };
    ensure!(locator.context_id != 0, "zero locator context id");
    ensure!(
        locator.context_digest != B256::ZERO
            && locator.safe_l1_hash != B256::ZERO
            && locator.containing_l1_hash != B256::ZERO
            && locator.posting_transaction_hash != B256::ZERO,
        "zero locator commitment"
    );
    ensure!(
        locator.containing_l1_number <= locator.safe_l1_number,
        "containing L1 above safe L1"
    );
    ensure!(
        locator.decoded_message_count != 0
            && locator.terminal_message_ordinal < locator.decoded_message_count,
        "invalid locator message ordinal"
    );
    Ok(locator)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AuthorityKind {
    Promotion = 1,
    Bootstrap = 2,
}

impl TryFrom<u8> for AuthorityKind {
    type Error = eyre::Report;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Promotion),
            2 => Ok(Self::Bootstrap),
            _ => Err(eyre!("unknown authority kind {value}")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityRecordV3 {
    pub kind: AuthorityKind,
    pub operation_generation: u64,
    pub authority_chain_position: u64,
    pub predecessor_authority_id: B256,
    pub start_sequence: u64,
    pub end_sequence: u64,
    pub record_count: u16,
    pub feed_transition_count: u16,
    pub feed_transition_bitmap: [u8; 32],
    pub promoted_identities_digest: B256,
    pub evidence_digest: B256,
    pub locator: EvidenceLocatorV1,
    pub predecessor_authority_chain_digest: B256,
    pub authority_id: B256,
}

pub fn encode_authority_record(record: AuthorityRecordV3) -> [u8; AUTHORITY_RECORD_LEN] {
    let mut out = [0u8; AUTHORITY_RECORD_LEN];
    out[..8].copy_from_slice(AUTHORITY_MAGIC);
    put_u16(&mut out[8..10], 3);
    out[10] = record.kind as u8;
    put_u32(&mut out[12..16], AUTHORITY_RECORD_LEN as u32);
    put_u64(&mut out[16..24], record.operation_generation);
    put_u64(&mut out[24..32], record.authority_chain_position);
    out[32..64].copy_from_slice(record.predecessor_authority_id.as_slice());
    put_u64(&mut out[64..72], record.start_sequence);
    put_u64(&mut out[72..80], record.end_sequence);
    put_u16(&mut out[80..82], record.record_count);
    put_u16(&mut out[82..84], record.feed_transition_count);
    out[84..116].copy_from_slice(&record.feed_transition_bitmap);
    out[116..148].copy_from_slice(record.promoted_identities_digest.as_slice());
    out[148..180].copy_from_slice(record.evidence_digest.as_slice());
    out[180..436].copy_from_slice(&encode_locator(record.locator));
    out[436..468].copy_from_slice(record.predecessor_authority_chain_digest.as_slice());
    let authority_id = domain_hash(DOMAIN_AUTHORITY_ID, &out[..468]);
    out[468..500].copy_from_slice(authority_id.as_slice());
    out
}

pub fn decode_authority_record(bytes: &[u8]) -> eyre::Result<AuthorityRecordV3> {
    ensure!(
        bytes.len() == AUTHORITY_RECORD_LEN,
        "authority record length mismatch"
    );
    ensure!(&bytes[..8] == AUTHORITY_MAGIC, "invalid authority magic");
    ensure!(get_u16(&bytes[8..10]) == 3, "unsupported authority version");
    let kind = AuthorityKind::try_from(bytes[10])?;
    ensure!(bytes[11] == 0, "nonzero authority flags");
    ensure!(
        get_u32(&bytes[12..16]) as usize == AUTHORITY_RECORD_LEN,
        "invalid authority length field"
    );
    ensure!(
        bytes[500..].iter().all(|byte| *byte == 0),
        "nonzero authority reserved bytes"
    );
    let expected_id = domain_hash(DOMAIN_AUTHORITY_ID, &bytes[..468]);
    ensure!(
        expected_id.as_slice() == &bytes[468..500],
        "invalid authority id"
    );
    let record = AuthorityRecordV3 {
        kind,
        operation_generation: get_u64(&bytes[16..24]),
        authority_chain_position: get_u64(&bytes[24..32]),
        predecessor_authority_id: B256::from_slice(&bytes[32..64]),
        start_sequence: get_u64(&bytes[64..72]),
        end_sequence: get_u64(&bytes[72..80]),
        record_count: get_u16(&bytes[80..82]),
        feed_transition_count: get_u16(&bytes[82..84]),
        feed_transition_bitmap: bytes[84..116].try_into().unwrap(),
        promoted_identities_digest: B256::from_slice(&bytes[116..148]),
        evidence_digest: B256::from_slice(&bytes[148..180]),
        locator: decode_locator(&bytes[180..436])?,
        predecessor_authority_chain_digest: B256::from_slice(&bytes[436..468]),
        authority_id: B256::from_slice(&bytes[468..500]),
    };
    Ok(record)
}

fn authority_chain_digest(record: AuthorityRecordV3) -> B256 {
    let mut payload = [0u8; 72];
    payload[..32].copy_from_slice(record.predecessor_authority_chain_digest.as_slice());
    put_u64(&mut payload[32..40], record.authority_chain_position);
    payload[40..72].copy_from_slice(record.authority_id.as_slice());
    domain_hash(DOMAIN_AUTHORITY_CHAIN, &payload)
}

fn bootstrap_certificate_digest(record: AuthorityRecordV3) -> B256 {
    domain_hash(
        DOMAIN_BOOTSTRAP_CERTIFICATE,
        &encode_authority_record(record),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedGridRecordV3 {
    pub authority: AuthorityRecordV3,
    pub original_lineage_generation: u64,
    pub original_frame_commit_digest: B256,
}

pub fn encode_grid_record(record: RetainedGridRecordV3) -> [u8; GRID_RECORD_LEN] {
    let mut out = [0u8; GRID_RECORD_LEN];
    out[..512].copy_from_slice(&encode_authority_record(record.authority));
    put_u64(&mut out[512..520], record.original_lineage_generation);
    out[520..552].copy_from_slice(record.original_frame_commit_digest.as_slice());
    out
}

pub fn decode_grid_record(bytes: &[u8]) -> eyre::Result<RetainedGridRecordV3> {
    ensure!(
        bytes.len() == GRID_RECORD_LEN,
        "grid record length mismatch"
    );
    ensure!(
        bytes[552..].iter().all(|byte| *byte == 0),
        "nonzero grid reserved bytes"
    );
    let authority = decode_authority_record(&bytes[..512])?;
    ensure!(
        authority.kind == AuthorityKind::Promotion,
        "grid record is not a promotion"
    );
    Ok(RetainedGridRecordV3 {
        authority,
        original_lineage_generation: get_u64(&bytes[512..520]),
        original_frame_commit_digest: B256::from_slice(&bytes[520..552]),
    })
}

fn grid_digest(records: &[RetainedGridRecordV3]) -> B256 {
    collection_digest(
        DOMAIN_GRID,
        records
            .iter()
            .map(|record| encode_grid_record(*record).to_vec()),
        records.len(),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum SnapshotStateKind {
    Ordinary = 0,
    RecoveryTruncation = 1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SnapshotState {
    kind: SnapshotStateKind,
    entries: Vec<MessageJournalEntry>,
    bootstrap: Option<AuthorityRecordV3>,
    v: Option<MessageJournalAnchor>,
    authority_operation_count: u64,
    latest_authority_id: B256,
    latest_authority_chain_digest: B256,
    predecessor_final_commit_digest: B256,
    grid: Vec<RetainedGridRecordV3>,
    source_v: Option<u64>,
    source_j: u64,
    source_latest_authority_id: B256,
    truncation_target_authority_id: B256,
    truncation_plan_digest: B256,
    removed_identity_count: u64,
    removed_identities_digest: B256,
    source_authority_chain_digest: B256,
    source_authority_operation_count: u64,
}

fn snapshot_watermark(
    anchor: MessageJournalAnchor,
    entries: &[MessageJournalEntry],
) -> MessageJournalAnchor {
    entries.last().map_or(anchor, |entry| MessageJournalAnchor {
        sequence: entry.sequence,
        block_number: entry.block_number,
        block_hash: entry.block_hash,
    })
}

fn snapshot_payload_len(state: &SnapshotState) -> eyre::Result<usize> {
    ensure!(
        state.entries.len() <= JOURNAL_HARD_IDENTITY_LIMIT,
        "snapshot identity limit exceeded"
    );
    ensure!(
        state.grid.len() <= MAX_GRID_RECORDS,
        "snapshot grid cap exceeded"
    );
    SNAPSHOT_PREFIX_LEN
        .checked_add(
            state
                .entries
                .len()
                .checked_mul(IDENTITY_LEN)
                .ok_or_else(|| eyre!("snapshot identity bytes overflow"))?,
        )
        .and_then(|length| {
            length.checked_add(usize::from(state.bootstrap.is_some()) * AUTHORITY_RECORD_LEN)
        })
        .and_then(|length| length.checked_add(state.grid.len() * GRID_RECORD_LEN))
        .ok_or_else(|| eyre!("snapshot payload length overflow"))
}

fn encode_snapshot_prefix(
    anchor: MessageJournalAnchor,
    state: &SnapshotState,
) -> eyre::Result<[u8; SNAPSHOT_PREFIX_LEN]> {
    snapshot_payload_len(state)?;
    let mut prefix = [0u8; SNAPSHOT_PREFIX_LEN];
    prefix[..8].copy_from_slice(SNAPSHOT_MAGIC);
    put_u16(&mut prefix[8..10], 3);
    prefix[10] = state.kind as u8;
    put_u32(&mut prefix[12..16], SNAPSHOT_PREFIX_LEN as u32);
    put_u32(&mut prefix[16..20], u32::try_from(state.entries.len())?);
    prefix[20] = u8::from(state.bootstrap.is_some());
    prefix[21] = u8::from(state.v.is_some());
    put_u16(&mut prefix[22..24], u16::try_from(state.grid.len())?);
    put_u64(&mut prefix[24..32], state.authority_operation_count);
    let j = snapshot_watermark(anchor, &state.entries);
    put_u64(&mut prefix[32..40], j.sequence);
    put_u64(&mut prefix[40..48], j.block_number);
    prefix[48..80].copy_from_slice(j.block_hash.as_slice());
    if let Some(v) = state.v {
        put_u64(&mut prefix[80..88], v.sequence);
        put_u64(&mut prefix[88..96], v.block_number);
        prefix[96..128].copy_from_slice(v.block_hash.as_slice());
    }
    prefix[128..160].copy_from_slice(state.latest_authority_id.as_slice());
    prefix[160..192].copy_from_slice(state.latest_authority_chain_digest.as_slice());
    prefix[192..224].copy_from_slice(state.predecessor_final_commit_digest.as_slice());
    prefix[224..256].copy_from_slice(grid_digest(&state.grid).as_slice());
    if let Some(bootstrap) = state.bootstrap {
        prefix[256..288].copy_from_slice(bootstrap_certificate_digest(bootstrap).as_slice());
    }
    if state.kind == SnapshotStateKind::RecoveryTruncation {
        prefix[288] = u8::from(state.source_v.is_some());
        put_u64(&mut prefix[296..304], state.source_j);
        put_u64(&mut prefix[304..312], state.source_v.unwrap_or(0));
        prefix[312..344].copy_from_slice(state.source_latest_authority_id.as_slice());
        prefix[344..376].copy_from_slice(state.truncation_target_authority_id.as_slice());
        prefix[376..408].copy_from_slice(state.truncation_plan_digest.as_slice());
        put_u64(&mut prefix[408..416], state.removed_identity_count);
        prefix[416..448].copy_from_slice(state.removed_identities_digest.as_slice());
        prefix[448..480].copy_from_slice(state.source_authority_chain_digest.as_slice());
        put_u64(
            &mut prefix[480..488],
            state.source_authority_operation_count,
        );
    }
    Ok(prefix)
}

#[cfg(test)]
fn encode_snapshot_payload(
    anchor: MessageJournalAnchor,
    state: &SnapshotState,
) -> eyre::Result<Vec<u8>> {
    let capacity = snapshot_payload_len(state)?;
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(&encode_snapshot_prefix(anchor, state)?);
    for entry in &state.entries {
        out.extend_from_slice(&encode_identity(*entry));
    }
    if let Some(bootstrap) = state.bootstrap {
        out.extend_from_slice(&encode_authority_record(bootstrap));
    }
    for record in &state.grid {
        out.extend_from_slice(&encode_grid_record(*record));
    }
    Ok(out)
}

#[derive(Clone, Copy)]
struct AuthorityPolicy<'a> {
    contexts: &'a [CanonicalContextV1],
    bootstrap_certificates: &'a [B256],
}

const PRODUCTION_POLICY: AuthorityPolicy<'static> = AuthorityPolicy {
    contexts: &[],
    bootstrap_certificates: &[],
};

fn validate_locator_context(
    locator: EvidenceLocatorV1,
    policy: AuthorityPolicy<'_>,
) -> eyre::Result<()> {
    let context = policy
        .contexts
        .iter()
        .find(|context| context.context_id == locator.context_id)
        .ok_or_else(|| eyre!("unknown canonical context id {}", locator.context_id))?;
    ensure!(
        context.digest()? == locator.context_digest,
        "canonical context digest mismatch"
    );
    Ok(())
}

fn bitmap_bit(bitmap: &[u8; 32], index: usize) -> bool {
    bitmap[index / 8] & (1 << (7 - index % 8)) != 0
}

fn validate_bitmap(record: AuthorityRecordV3) -> eyre::Result<()> {
    let count = usize::from(record.record_count);
    ensure!(
        count <= AUTHORITY_MAX_RECORDS,
        "authority count exceeds 256"
    );
    let mut transitions = 0usize;
    for index in 0..AUTHORITY_MAX_RECORDS {
        if bitmap_bit(&record.feed_transition_bitmap, index) {
            ensure!(index < count, "authority bitmap has a bit above count");
            transitions += 1;
        }
    }
    ensure!(
        transitions == usize::from(record.feed_transition_count),
        "authority transition popcount mismatch"
    );
    Ok(())
}

fn validate_bootstrap(
    record: AuthorityRecordV3,
    anchor: MessageJournalAnchor,
    policy: AuthorityPolicy<'_>,
) -> eyre::Result<()> {
    validate_bitmap(record)?;
    validate_locator_context(record.locator, policy)?;
    ensure!(
        record.kind == AuthorityKind::Bootstrap,
        "certificate is not bootstrap"
    );
    ensure!(
        record.operation_generation == 0
            && record.authority_chain_position == 1
            && record.predecessor_authority_id == B256::ZERO
            && record.start_sequence == anchor.sequence
            && record.end_sequence == anchor.sequence
            && record.record_count == 0
            && record.feed_transition_count == 0
            && record.feed_transition_bitmap == [0u8; 32]
            && record.promoted_identities_digest == identities_digest(&[])
            && record.evidence_digest != B256::ZERO
            && record.predecessor_authority_chain_digest == B256::ZERO,
        "invalid bootstrap authority fields"
    );
    ensure!(
        record.locator.terminal_sequence == anchor.sequence
            && record.locator.terminal_l2_block_number == anchor.block_number
            && record.locator.terminal_l2_block_hash == anchor.block_hash,
        "bootstrap locator does not terminate at anchor"
    );
    ensure!(
        policy
            .bootstrap_certificates
            .contains(&bootstrap_certificate_digest(record)),
        "bootstrap certificate is not allowlisted"
    );
    Ok(())
}

fn validate_identity_chain(
    anchor: MessageJournalAnchor,
    entries: &[MessageJournalEntry],
    genesis_number: u64,
) -> eyre::Result<()> {
    let mut previous = anchor;
    for entry in entries {
        ensure!(
            entry.sequence
                == previous
                    .sequence
                    .checked_add(1)
                    .ok_or_else(|| eyre!("identity sequence overflow"))?,
            "journal sequence is not contiguous"
        );
        ensure!(
            entry.block_number
                == previous
                    .block_number
                    .checked_add(1)
                    .ok_or_else(|| eyre!("identity block overflow"))?,
            "journal block number is not contiguous"
        );
        ensure!(
            entry.block_number
                == genesis_number
                    .checked_add(entry.sequence)
                    .ok_or_else(|| eyre!("genesis mapping overflow"))?,
            "journal genesis mapping mismatch"
        );
        ensure!(
            entry.parent_hash == previous.block_hash,
            "journal parent mismatch"
        );
        previous = MessageJournalAnchor {
            sequence: entry.sequence,
            block_number: entry.block_number,
            block_hash: entry.block_hash,
        };
    }
    Ok(())
}

fn identity_at(
    anchor: MessageJournalAnchor,
    entries: &[MessageJournalEntry],
    sequence: u64,
) -> Option<MessageJournalAnchor> {
    if sequence == anchor.sequence {
        return Some(anchor);
    }
    let offset = usize::try_from(sequence.checked_sub(anchor.sequence)?.checked_sub(1)?).ok()?;
    entries.get(offset).map(|entry| MessageJournalAnchor {
        sequence: entry.sequence,
        block_number: entry.block_number,
        block_hash: entry.block_hash,
    })
}

fn bootstrap_endpoint(state: &SnapshotState) -> Option<u64> {
    state.bootstrap.map(|record| record.end_sequence)
}

fn positive_grid_endpoint(bootstrap: u64, endpoint: u64) -> bool {
    endpoint > bootstrap && (endpoint - bootstrap).is_multiple_of(256)
}

fn retained_grid_range(bootstrap: u64, v: u64) -> eyre::Result<Option<(u64, u64)>> {
    let distance = v
        .checked_sub(bootstrap)
        .ok_or_else(|| eyre!("V precedes bootstrap"))?;
    let latest_offset = (distance / 256)
        .checked_mul(256)
        .ok_or_else(|| eyre!("latest grid offset overflow"))?;
    let latest = bootstrap
        .checked_add(latest_offset)
        .ok_or_else(|| eyre!("latest grid endpoint overflow"))?;
    if latest == bootstrap {
        return Ok(None);
    }
    let lower = bootstrap.max(v.saturating_sub(8192));
    let first_positive = bootstrap
        .checked_add(256)
        .ok_or_else(|| eyre!("first positive grid endpoint overflow"))?;
    let first = if lower <= first_positive {
        first_positive
    } else {
        let strict_predecessor_distance = lower
            .checked_sub(bootstrap)
            .and_then(|distance| distance.checked_sub(1))
            .ok_or_else(|| eyre!("grid predecessor distance underflow"))?;
        let first_offset = (strict_predecessor_distance / 256)
            .checked_mul(256)
            .ok_or_else(|| eyre!("first grid offset overflow"))?;
        bootstrap
            .checked_add(first_offset)
            .ok_or_else(|| eyre!("first grid endpoint overflow"))?
    };
    Ok(Some((first, latest)))
}

fn retain_ordinary_grid(state: &mut SnapshotState) -> eyre::Result<()> {
    let Some(bootstrap) = bootstrap_endpoint(state) else {
        ensure!(state.grid.is_empty(), "grid exists without bootstrap");
        return Ok(());
    };
    let Some(v) = state.v.map(|v| v.sequence) else {
        ensure!(state.grid.is_empty(), "grid exists without V");
        return Ok(());
    };
    let Some((first, latest)) = retained_grid_range(bootstrap, v)? else {
        state.grid.clear();
        return Ok(());
    };
    state
        .grid
        .retain(|record| (first..=latest).contains(&record.authority.end_sequence));
    ensure!(state.grid.len() <= 34, "ordinary positive grid exceeds 34");
    Ok(())
}

fn validate_grid(
    state: &SnapshotState,
    ordinary: bool,
    source: Option<&SnapshotState>,
) -> eyre::Result<()> {
    ensure!(
        state.grid.len() <= MAX_GRID_RECORDS,
        "grid parser cap exceeded"
    );
    let bootstrap = bootstrap_endpoint(state).ok_or_else(|| eyre!("grid/V has no bootstrap"))?;
    let mut previous = None;
    for record in &state.grid {
        ensure!(
            positive_grid_endpoint(bootstrap, record.authority.end_sequence),
            "irregular grid endpoint"
        );
        ensure!(
            previous.is_none_or(|value| value < record.authority.end_sequence),
            "grid is not strictly ordered"
        );
        ensure!(
            record.original_frame_commit_digest != B256::ZERO,
            "zero original grid commit"
        );
        previous = Some(record.authority.end_sequence);
    }
    if ordinary {
        let v = state
            .v
            .ok_or_else(|| eyre!("ordinary grid has no V"))?
            .sequence;
        let expected = retained_grid_range(bootstrap, v)?;
        match expected {
            None => ensure!(state.grid.is_empty(), "ordinary grid should be empty"),
            Some((first, latest)) => {
                let expected_count = usize::try_from((latest - first) / 256 + 1)?;
                ensure!(
                    state.grid.len() == expected_count,
                    "ordinary grid count mismatch"
                );
                for (index, record) in state.grid.iter().enumerate() {
                    let expected_endpoint = (index as u64)
                        .checked_mul(256)
                        .and_then(|offset| first.checked_add(offset))
                        .ok_or_else(|| eyre!("ordinary grid endpoint overflow"))?;
                    ensure!(
                        record.authority.end_sequence == expected_endpoint,
                        "ordinary grid endpoint mismatch"
                    );
                }
            }
        }
        ensure!(state.grid.len() <= 34, "ordinary grid exceeds 34 positives");
    } else if let Some(source) = source {
        let target = state
            .v
            .ok_or_else(|| eyre!("recovery grid has no target V"))?
            .sequence;
        let expected: Vec<_> = source
            .grid
            .iter()
            .copied()
            .filter(|record| record.authority.end_sequence <= target)
            .collect();
        ensure!(
            state.grid == expected,
            "recovery grid is not exact source subset"
        );
    }
    Ok(())
}

fn validate_snapshot_state(
    header: JournalHeader,
    state: &SnapshotState,
    policy: AuthorityPolicy<'_>,
    predecessor: Option<&MessageJournalInspection>,
) -> eyre::Result<()> {
    let genesis_number = header
        .anchor
        .block_number
        .checked_sub(header.anchor.sequence)
        .ok_or_else(|| eyre!("journal anchor precedes L2 genesis mapping"))?;
    validate_identity_chain(header.anchor, &state.entries, genesis_number)?;
    let j = snapshot_watermark(header.anchor, &state.entries);
    if let Some(v) = state.v {
        ensure!(v.sequence <= j.sequence, "V is above J");
        ensure!(
            identity_at(header.anchor, &state.entries, v.sequence) == Some(v),
            "V identity mismatch"
        );
        ensure!(
            state.bootstrap.is_some()
                && state.authority_operation_count != 0
                && state.latest_authority_id != B256::ZERO
                && state.latest_authority_chain_digest != B256::ZERO,
            "present V has incomplete authority summary"
        );
    } else {
        ensure!(
            state.bootstrap.is_none()
                && state.authority_operation_count == 0
                && state.latest_authority_id == B256::ZERO
                && state.latest_authority_chain_digest == B256::ZERO
                && state.grid.is_empty(),
            "absent V has authority state"
        );
    }
    if let Some(bootstrap) = state.bootstrap {
        validate_bootstrap(bootstrap, header.anchor, policy)?;
        ensure!(state.v.is_some(), "bootstrap exists without V");
        if header.lineage_generation == 0 {
            ensure!(
                state.v == Some(header.anchor)
                    && state.authority_operation_count == 1
                    && state.latest_authority_id == bootstrap.authority_id
                    && state.latest_authority_chain_digest == authority_chain_digest(bootstrap)
                    && state.grid.is_empty(),
                "lineage-zero bootstrap summary mismatch"
            );
        }
    }
    match state.kind {
        SnapshotStateKind::Ordinary => {
            ensure!(
                state.source_v.is_none()
                    && state.source_j == 0
                    && state.source_latest_authority_id == B256::ZERO
                    && state.truncation_target_authority_id == B256::ZERO
                    && state.truncation_plan_digest == B256::ZERO
                    && state.removed_identity_count == 0
                    && state.removed_identities_digest == B256::ZERO
                    && state.source_authority_chain_digest == B256::ZERO
                    && state.source_authority_operation_count == 0,
                "ordinary snapshot has recovery fields"
            );
            if state.v.is_some() {
                validate_grid(state, true, None)?;
            }
        }
        SnapshotStateKind::RecoveryTruncation => {
            ensure!(
                state.truncation_plan_digest != B256::ZERO,
                "zero truncation plan digest"
            );
            ensure!(
                j == state.v.expect("recovery requires V"),
                "recovery J/V mismatch"
            );
            let Some(predecessor) = predecessor else {
                return Ok(());
            };
            ensure!(
                state.source_j == predecessor.watermark.sequence,
                "recovery source J mismatch"
            );
            ensure!(
                state.source_v == predecessor.v.map(|v| v.sequence),
                "recovery source V mismatch"
            );
            ensure!(
                state.source_latest_authority_id == predecessor.latest_authority_id
                    && state.source_authority_chain_digest
                        == predecessor.latest_authority_chain_digest
                    && state.source_authority_operation_count
                        == predecessor.authority_operation_count,
                "recovery source summary mismatch"
            );
            ensure!(
                j.sequence < predecessor.watermark.sequence,
                "recovery target is not below source J"
            );
            let bootstrap = state.bootstrap.expect("present V requires bootstrap");
            let (target_id, target_chain, target_count) = if j.sequence == bootstrap.end_sequence {
                (bootstrap.authority_id, authority_chain_digest(bootstrap), 1)
            } else {
                let target = predecessor
                    .retained_grid
                    .iter()
                    .find(|record| record.authority.end_sequence == j.sequence)
                    .ok_or_else(|| eyre!("recovery target is not bootstrap or retained grid"))?;
                (
                    target.authority.authority_id,
                    authority_chain_digest(target.authority),
                    target.authority.authority_chain_position,
                )
            };
            ensure!(
                state.latest_authority_id == target_id
                    && state.truncation_target_authority_id == target_id
                    && state.latest_authority_chain_digest == target_chain
                    && state.authority_operation_count == target_count,
                "recovery target prefix summary mismatch"
            );
            ensure!(
                state.entries.len() <= predecessor.entries.len(),
                "recovery retained identity count exceeds source"
            );
            let removed = &predecessor.entries[state.entries.len()..];
            ensure!(
                state.removed_identity_count == removed.len() as u64
                    && state.removed_identities_digest == removed_identities_digest(removed),
                "removed identity commitment mismatch"
            );
            validate_grid(state, false, Some(&predecessor.state))?;
        }
    }
    Ok(())
}

#[cfg(test)]
fn decode_snapshot_payload(payload: &[u8], header: JournalHeader) -> eyre::Result<SnapshotState> {
    ensure!(
        payload.len() >= SNAPSHOT_PREFIX_LEN,
        "snapshot prefix is truncated"
    );
    let prefix = &payload[..SNAPSHOT_PREFIX_LEN];
    ensure!(&prefix[..8] == SNAPSHOT_MAGIC, "invalid snapshot magic");
    ensure!(get_u16(&prefix[8..10]) == 3, "unsupported snapshot version");
    let kind = match prefix[10] {
        0 => SnapshotStateKind::Ordinary,
        1 => SnapshotStateKind::RecoveryTruncation,
        value => return Err(eyre!("unknown snapshot state kind {value}")),
    };
    ensure!(prefix[11] == 0, "nonzero snapshot flags");
    ensure!(
        get_u32(&prefix[12..16]) as usize == SNAPSHOT_PREFIX_LEN,
        "snapshot prefix length mismatch"
    );
    ensure!(matches!(prefix[20], 0 | 1), "invalid bootstrap presence");
    ensure!(matches!(prefix[21], 0 | 1), "invalid V presence");
    ensure!(matches!(prefix[288], 0 | 1), "invalid source-V presence");
    ensure!(
        prefix[289..296].iter().all(|byte| *byte == 0),
        "nonzero recovery reserved bytes"
    );
    ensure!(
        prefix[488..].iter().all(|byte| *byte == 0),
        "nonzero snapshot reserved bytes"
    );
    let identity_count = get_u32(&prefix[16..20]) as usize;
    let bootstrap_present = prefix[20] == 1;
    let grid_count = get_u16(&prefix[22..24]) as usize;
    ensure!(
        identity_count <= JOURNAL_HARD_IDENTITY_LIMIT,
        "snapshot identity cap exceeded"
    );
    ensure!(grid_count <= MAX_GRID_RECORDS, "snapshot grid cap exceeded");
    let expected_len = SNAPSHOT_PREFIX_LEN
        + identity_count * IDENTITY_LEN
        + usize::from(bootstrap_present) * AUTHORITY_RECORD_LEN
        + grid_count * GRID_RECORD_LEN;
    ensure!(
        payload.len() == expected_len,
        "snapshot count/length mismatch"
    );
    let mut offset = SNAPSHOT_PREFIX_LEN;
    let mut entries = Vec::with_capacity(identity_count);
    for _ in 0..identity_count {
        entries.push(decode_identity(&payload[offset..offset + IDENTITY_LEN])?);
        offset += IDENTITY_LEN;
    }
    let bootstrap = if bootstrap_present {
        let record = decode_authority_record(&payload[offset..offset + AUTHORITY_RECORD_LEN])?;
        offset += AUTHORITY_RECORD_LEN;
        Some(record)
    } else {
        None
    };
    let mut grid = Vec::with_capacity(grid_count);
    for _ in 0..grid_count {
        grid.push(decode_grid_record(
            &payload[offset..offset + GRID_RECORD_LEN],
        )?);
        offset += GRID_RECORD_LEN;
    }
    ensure!(
        grid_digest(&grid).as_slice() == &prefix[224..256],
        "snapshot grid digest mismatch"
    );
    let v = (prefix[21] == 1).then(|| MessageJournalAnchor {
        sequence: get_u64(&prefix[80..88]),
        block_number: get_u64(&prefix[88..96]),
        block_hash: B256::from_slice(&prefix[96..128]),
    });
    if v.is_none() {
        ensure!(
            prefix[80..128].iter().all(|byte| *byte == 0),
            "absent V fields are nonzero"
        );
    }
    if let Some(bootstrap) = bootstrap {
        ensure!(
            bootstrap_certificate_digest(bootstrap).as_slice() == &prefix[256..288],
            "bootstrap certificate digest mismatch"
        );
    } else {
        ensure!(
            prefix[256..288].iter().all(|byte| *byte == 0),
            "absent bootstrap digest is nonzero"
        );
    }
    let state = SnapshotState {
        kind,
        entries,
        bootstrap,
        v,
        authority_operation_count: get_u64(&prefix[24..32]),
        latest_authority_id: B256::from_slice(&prefix[128..160]),
        latest_authority_chain_digest: B256::from_slice(&prefix[160..192]),
        predecessor_final_commit_digest: B256::from_slice(&prefix[192..224]),
        grid,
        source_v: (prefix[288] == 1).then(|| get_u64(&prefix[304..312])),
        source_j: get_u64(&prefix[296..304]),
        source_latest_authority_id: B256::from_slice(&prefix[312..344]),
        truncation_target_authority_id: B256::from_slice(&prefix[344..376]),
        truncation_plan_digest: B256::from_slice(&prefix[376..408]),
        removed_identity_count: get_u64(&prefix[408..416]),
        removed_identities_digest: B256::from_slice(&prefix[416..448]),
        source_authority_chain_digest: B256::from_slice(&prefix[448..480]),
        source_authority_operation_count: get_u64(&prefix[480..488]),
    };
    let expected_j = snapshot_watermark(header.anchor, &state.entries);
    ensure!(
        (
            get_u64(&prefix[32..40]),
            get_u64(&prefix[40..48]),
            B256::from_slice(&prefix[48..80])
        ) == (
            expected_j.sequence,
            expected_j.block_number,
            expected_j.block_hash
        ),
        "snapshot J summary mismatch"
    );
    Ok(state)
}

fn removed_identities_digest(entries: &[MessageJournalEntry]) -> B256 {
    let payload_len = 8 + entries.len() * IDENTITY_LEN;
    let mut hasher = framed_hasher(DOMAIN_REMOVED_IDENTITIES, payload_len);
    hasher.update((entries.len() as u64).to_be_bytes());
    for entry in entries {
        hasher.update(encode_identity(*entry));
    }
    B256::from_slice(&hasher.finalize())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum FrameKind {
    Executed = 0x11,
    Authority = 0x12,
    Snapshot = 0x13,
    RecoveryTruncationSnapshot = 0x14,
}

impl TryFrom<u8> for FrameKind {
    type Error = eyre::Report;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x11 => Ok(Self::Executed),
            0x12 => Ok(Self::Authority),
            0x13 => Ok(Self::Snapshot),
            0x14 => Ok(Self::RecoveryTruncationSnapshot),
            _ => Err(eyre!("unknown journal frame kind {value:#x}")),
        }
    }
}

fn validate_payload_domain(kind: FrameKind, payload_len: usize) -> eyre::Result<()> {
    match kind {
        FrameKind::Executed => ensure!(
            payload_len == IDENTITY_LEN,
            "EXECUTED_V3 payload length mismatch"
        ),
        FrameKind::Authority => ensure!(
            (AUTHORITY_RECORD_LEN + IDENTITY_LEN
                ..=AUTHORITY_RECORD_LEN + AUTHORITY_MAX_RECORDS * IDENTITY_LEN)
                .contains(&payload_len)
                && (payload_len - AUTHORITY_RECORD_LEN).is_multiple_of(IDENTITY_LEN),
            "AUTHORITY_V3 payload length mismatch"
        ),
        FrameKind::Snapshot | FrameKind::RecoveryTruncationSnapshot => ensure!(
            (SNAPSHOT_PREFIX_LEN..=MAX_PAYLOAD_LEN).contains(&payload_len),
            "snapshot payload length mismatch"
        ),
    }
    Ok(())
}

fn encode_frame(
    kind: FrameKind,
    operation_generation: u64,
    previous_commit_digest: B256,
    payload: &[u8],
) -> eyre::Result<Vec<u8>> {
    let prelude = encode_frame_prelude(
        kind,
        operation_generation,
        previous_commit_digest,
        payload.len(),
    )?;
    let mut out = vec![0u8; FRAME_STORAGE_OVERHEAD + payload.len()];
    out[..96].copy_from_slice(&prelude);
    out[96..96 + payload.len()].copy_from_slice(payload);
    let commit_magic_start = 96 + payload.len();
    put_u64(
        &mut out[commit_magic_start..commit_magic_start + 8],
        COMMIT_MAGIC,
    );
    let commit = domain_hash(DOMAIN_FRAME_COMMIT, &out[..commit_magic_start + 8]);
    out[commit_magic_start + 8..].copy_from_slice(commit.as_slice());
    Ok(out)
}

fn encode_frame_prelude(
    kind: FrameKind,
    operation_generation: u64,
    previous_commit_digest: B256,
    payload_len: usize,
) -> eyre::Result<[u8; 96]> {
    validate_payload_domain(kind, payload_len)?;
    let mut out = [0u8; 96];
    put_u32(&mut out[0..4], u32::try_from(132 + payload_len)?);
    put_u32(&mut out[4..8], u32::try_from(payload_len)?);
    let prefix_digest = domain_hash(DOMAIN_FRAME_PREFIX, &out[..8]);
    out[8..40].copy_from_slice(prefix_digest.as_slice());
    put_u64(&mut out[40..48], FRAME_MAGIC);
    put_u16(&mut out[48..50], SCHEMA_VERSION);
    out[50] = kind as u8;
    put_u64(&mut out[52..60], operation_generation);
    out[60..92].copy_from_slice(previous_commit_digest.as_slice());
    put_u32(&mut out[92..96], u32::try_from(payload_len)?);
    Ok(out)
}

#[derive(Debug)]
struct DecodedFrame {
    kind: FrameKind,
    operation_generation: u64,
    previous_commit_digest: B256,
    payload: Vec<u8>,
    commit_digest: B256,
}

fn decode_complete_frame(bytes: &[u8]) -> eyre::Result<DecodedFrame> {
    ensure!(bytes.len() >= FRAME_STORAGE_OVERHEAD, "frame is too short");
    ensure!(
        domain_hash(DOMAIN_FRAME_PREFIX, &bytes[..8]).as_slice() == &bytes[8..40],
        "invalid frame prefix digest"
    );
    let payload_len = get_u32(&bytes[4..8]) as usize;
    ensure!(
        payload_len <= MAX_PAYLOAD_LEN,
        "frame payload exceeds global cap"
    );
    ensure!(
        get_u32(&bytes[0..4]) as usize == 132 + payload_len,
        "invalid total frame length"
    );
    ensure!(
        bytes.len() == FRAME_STORAGE_OVERHEAD + payload_len,
        "frame storage length mismatch"
    );
    ensure!(
        get_u64(&bytes[40..48]) == FRAME_MAGIC,
        "invalid frame magic"
    );
    ensure!(
        get_u16(&bytes[48..50]) == SCHEMA_VERSION,
        "unsupported frame schema"
    );
    let kind = FrameKind::try_from(bytes[50])?;
    ensure!(bytes[51] == 0, "nonzero frame flags");
    validate_payload_domain(kind, payload_len)?;
    ensure!(
        get_u32(&bytes[92..96]) as usize == payload_len,
        "inner payload length mismatch"
    );
    let commit_magic_start = 96 + payload_len;
    ensure!(
        get_u64(&bytes[commit_magic_start..commit_magic_start + 8]) == COMMIT_MAGIC,
        "invalid commit magic"
    );
    ensure!(
        domain_hash(DOMAIN_FRAME_COMMIT, &bytes[..commit_magic_start + 8]).as_slice()
            == &bytes[commit_magic_start + 8..],
        "invalid frame commit digest"
    );
    Ok(DecodedFrame {
        kind,
        operation_generation: get_u64(&bytes[52..60]),
        previous_commit_digest: B256::from_slice(&bytes[60..92]),
        payload: bytes[96..96 + payload_len].to_vec(),
        commit_digest: B256::from_slice(&bytes[commit_magic_start + 8..]),
    })
}

fn validate_partial_frame(
    bytes: &[u8],
    expected_generation: u64,
    expected_previous_digest: B256,
) -> eyre::Result<bool> {
    if bytes.is_empty() {
        return Ok(false);
    }
    ensure!(bytes.len() >= 40, "unverifiable 1..39-byte journal tail");
    ensure!(
        domain_hash(DOMAIN_FRAME_PREFIX, &bytes[..8]).as_slice() == &bytes[8..40],
        "invalid short-tail prefix"
    );
    let payload_len = get_u32(&bytes[4..8]) as usize;
    ensure!(
        payload_len <= MAX_PAYLOAD_LEN,
        "short-tail payload exceeds cap"
    );
    ensure!(
        get_u32(&bytes[0..4]) as usize == 132 + payload_len,
        "invalid short-tail total length"
    );
    if bytes.len() >= 48 {
        ensure!(
            get_u64(&bytes[40..48]) == FRAME_MAGIC,
            "invalid short-tail magic"
        );
    }
    if bytes.len() >= 50 {
        ensure!(
            get_u16(&bytes[48..50]) == SCHEMA_VERSION,
            "invalid short-tail schema"
        );
    }
    if bytes.len() >= 51 {
        validate_payload_domain(FrameKind::try_from(bytes[50])?, payload_len)?;
    }
    if bytes.len() >= 52 {
        ensure!(bytes[51] == 0, "nonzero short-tail flags");
    }
    if bytes.len() >= 60 {
        ensure!(
            get_u64(&bytes[52..60]) == expected_generation,
            "short-tail generation mismatch"
        );
    }
    if bytes.len() >= 92 {
        ensure!(
            B256::from_slice(&bytes[60..92]) == expected_previous_digest,
            "short-tail predecessor mismatch"
        );
    }
    if bytes.len() >= 96 {
        ensure!(
            get_u32(&bytes[92..96]) as usize == payload_len,
            "short-tail inner length mismatch"
        );
    }
    ensure!(
        bytes.len() < FRAME_STORAGE_OVERHEAD + payload_len,
        "partial validator received complete frame"
    );
    Ok(true)
}

fn apply_authority_frame(
    state: &mut SnapshotState,
    frame: &DecodedFrame,
    policy: AuthorityPolicy<'_>,
    lineage_generation: u64,
) -> eyre::Result<()> {
    ensure!(
        state.bootstrap.is_some() && state.v.is_some(),
        "authority cannot publish while V=None"
    );
    let record = decode_authority_record(&frame.payload[..AUTHORITY_RECORD_LEN])?;
    ensure!(
        record.kind == AuthorityKind::Promotion,
        "appended bootstrap authority is forbidden"
    );
    validate_locator_context(record.locator, policy)?;
    validate_bitmap(record)?;
    ensure!(
        record.evidence_digest != B256::ZERO,
        "zero authority evidence digest"
    );
    ensure!(
        record.operation_generation == frame.operation_generation,
        "authority/frame generation mismatch"
    );
    let count = usize::from(record.record_count);
    ensure!(
        (1..=AUTHORITY_MAX_RECORDS).contains(&count),
        "promotion count outside 1..=256"
    );
    ensure!(
        frame.payload.len() == AUTHORITY_RECORD_LEN + count * IDENTITY_LEN,
        "authority count/length mismatch"
    );
    let old_v = state.v.expect("checked");
    let expected_start = old_v
        .sequence
        .checked_add(1)
        .ok_or_else(|| eyre!("V overflow"))?;
    ensure!(
        record.start_sequence == expected_start,
        "promotion does not start at V+1"
    );
    ensure!(
        record
            .end_sequence
            .checked_sub(record.start_sequence)
            .and_then(|n| n.checked_add(1))
            == Some(count as u64),
        "promotion range/count mismatch"
    );
    ensure!(
        record.authority_chain_position
            == state
                .authority_operation_count
                .checked_add(1)
                .ok_or_else(|| eyre!("authority position overflow"))?
            && record.predecessor_authority_id == state.latest_authority_id
            && record.predecessor_authority_chain_digest == state.latest_authority_chain_digest,
        "authority predecessor summary mismatch"
    );
    let bootstrap = bootstrap_endpoint(state).expect("checked");
    let distance = record
        .start_sequence
        .checked_sub(bootstrap)
        .ok_or_else(|| eyre!("promotion starts before bootstrap"))?;
    let first_grid_offset = distance
        .div_ceil(256)
        .checked_mul(256)
        .ok_or_else(|| eyre!("promotion grid offset overflow"))?;
    let first_grid = bootstrap
        .checked_add(first_grid_offset)
        .ok_or_else(|| eyre!("promotion grid endpoint overflow"))?;
    ensure!(
        first_grid >= record.end_sequence,
        "authority record crosses a grid boundary"
    );
    let mut promoted = Vec::with_capacity(count);
    for index in 0..count {
        let offset = AUTHORITY_RECORD_LEN + index * IDENTITY_LEN;
        let authority_identity = decode_identity(&frame.payload[offset..offset + IDENTITY_LEN])?;
        ensure!(
            authority_identity.source == ArbEngineInputSource::L1,
            "authority identity is not L1"
        );
        ensure!(
            authority_identity.sequence == record.start_sequence + index as u64,
            "authority range gap"
        );
        let retained_index = state
            .entries
            .iter()
            .position(|entry| entry.sequence == authority_identity.sequence)
            .ok_or_else(|| eyre!("authority sequence is not retained"))?;
        let retained = &mut state.entries[retained_index];
        let transitioned = retained.source == ArbEngineInputSource::Feed;
        ensure!(
            bitmap_bit(&record.feed_transition_bitmap, index) == transitioned,
            "authority bitmap/source conflict"
        );
        let mut expected = *retained;
        expected.source = ArbEngineInputSource::L1;
        ensure!(
            authority_identity == expected,
            "authority identity conflicts with retained identity"
        );
        retained.source = ArbEngineInputSource::L1;
        promoted.push(authority_identity);
    }
    ensure!(
        record.promoted_identities_digest == identities_digest(&promoted),
        "promoted identities digest mismatch"
    );
    let terminal = promoted.last().expect("nonempty");
    ensure!(
        record.locator.terminal_sequence == terminal.sequence
            && record.locator.terminal_l2_block_number == terminal.block_number
            && record.locator.terminal_l2_block_hash == terminal.block_hash
            && record.locator.terminal_delayed_count == terminal.delayed_messages_read,
        "authority locator terminal mismatch"
    );
    state.v = Some(MessageJournalAnchor {
        sequence: terminal.sequence,
        block_number: terminal.block_number,
        block_hash: terminal.block_hash,
    });
    state.authority_operation_count = record.authority_chain_position;
    state.latest_authority_id = record.authority_id;
    state.latest_authority_chain_digest = authority_chain_digest(record);
    if positive_grid_endpoint(bootstrap, record.end_sequence) {
        state.grid.push(RetainedGridRecordV3 {
            authority: record,
            original_lineage_generation: lineage_generation,
            original_frame_commit_digest: frame.commit_digest,
        });
    }
    retain_ordinary_grid(state)
}

fn decode_frame_prelude(bytes: &[u8; 96]) -> eyre::Result<(FrameKind, usize, u64, B256)> {
    ensure!(
        domain_hash(DOMAIN_FRAME_PREFIX, &bytes[..8]).as_slice() == &bytes[8..40],
        "invalid frame prefix digest"
    );
    let payload_len = get_u32(&bytes[4..8]) as usize;
    ensure!(
        payload_len <= MAX_PAYLOAD_LEN,
        "frame payload exceeds global cap"
    );
    ensure!(
        get_u32(&bytes[0..4]) as usize == 132 + payload_len,
        "invalid total frame length"
    );
    ensure!(
        get_u64(&bytes[40..48]) == FRAME_MAGIC,
        "invalid frame magic"
    );
    ensure!(
        get_u16(&bytes[48..50]) == SCHEMA_VERSION,
        "unsupported frame schema"
    );
    let kind = FrameKind::try_from(bytes[50])?;
    ensure!(bytes[51] == 0, "nonzero frame flags");
    validate_payload_domain(kind, payload_len)?;
    ensure!(
        get_u32(&bytes[92..96]) as usize == payload_len,
        "inner payload length mismatch"
    );
    Ok((
        kind,
        payload_len,
        get_u64(&bytes[52..60]),
        B256::from_slice(&bytes[60..92]),
    ))
}

fn read_snapshot_frame(
    file: &mut File,
    prelude: [u8; 96],
    header: JournalHeader,
) -> eyre::Result<(SnapshotState, B256)> {
    let (kind, payload_len, _, _) = decode_frame_prelude(&prelude)?;
    ensure!(
        matches!(
            kind,
            FrameKind::Snapshot | FrameKind::RecoveryTruncationSnapshot
        ),
        "streaming parser received a non-snapshot frame"
    );
    let mut commit = framed_hasher(DOMAIN_FRAME_COMMIT, 104 + payload_len);
    commit.update(prelude);
    let mut prefix = [0u8; SNAPSHOT_PREFIX_LEN];
    file.read_exact(&mut prefix)?;
    commit.update(prefix);
    ensure!(&prefix[..8] == SNAPSHOT_MAGIC, "invalid snapshot magic");
    ensure!(get_u16(&prefix[8..10]) == 3, "unsupported snapshot version");
    let state_kind = match prefix[10] {
        0 => SnapshotStateKind::Ordinary,
        1 => SnapshotStateKind::RecoveryTruncation,
        value => return Err(eyre!("unknown snapshot state kind {value}")),
    };
    ensure!(
        (kind == FrameKind::Snapshot && state_kind == SnapshotStateKind::Ordinary)
            || (kind == FrameKind::RecoveryTruncationSnapshot
                && state_kind == SnapshotStateKind::RecoveryTruncation),
        "snapshot frame/state kind mismatch"
    );
    ensure!(prefix[11] == 0, "nonzero snapshot flags");
    ensure!(
        get_u32(&prefix[12..16]) as usize == SNAPSHOT_PREFIX_LEN,
        "snapshot prefix length mismatch"
    );
    ensure!(matches!(prefix[20], 0 | 1), "invalid bootstrap presence");
    ensure!(matches!(prefix[21], 0 | 1), "invalid V presence");
    ensure!(matches!(prefix[288], 0 | 1), "invalid source-V presence");
    ensure!(
        prefix[289..296].iter().all(|byte| *byte == 0),
        "nonzero recovery reserved bytes"
    );
    ensure!(
        prefix[488..].iter().all(|byte| *byte == 0),
        "nonzero snapshot reserved bytes"
    );
    let identity_count = get_u32(&prefix[16..20]) as usize;
    let bootstrap_present = prefix[20] == 1;
    let grid_count = get_u16(&prefix[22..24]) as usize;
    ensure!(
        identity_count <= JOURNAL_HARD_IDENTITY_LIMIT,
        "snapshot identity cap exceeded"
    );
    ensure!(grid_count <= MAX_GRID_RECORDS, "snapshot grid cap exceeded");
    ensure!(
        payload_len
            == SNAPSHOT_PREFIX_LEN
                + identity_count * IDENTITY_LEN
                + usize::from(bootstrap_present) * AUTHORITY_RECORD_LEN
                + grid_count * GRID_RECORD_LEN,
        "snapshot count/length mismatch"
    );
    let mut identity = [0u8; IDENTITY_LEN];
    let mut entries = Vec::with_capacity(identity_count);
    for _ in 0..identity_count {
        file.read_exact(&mut identity)?;
        commit.update(identity);
        entries.push(decode_identity(&identity)?);
    }
    let bootstrap = if bootstrap_present {
        let mut bytes = [0u8; AUTHORITY_RECORD_LEN];
        file.read_exact(&mut bytes)?;
        commit.update(bytes);
        Some(decode_authority_record(&bytes)?)
    } else {
        None
    };
    let mut grid = Vec::with_capacity(grid_count);
    for _ in 0..grid_count {
        let mut bytes = [0u8; GRID_RECORD_LEN];
        file.read_exact(&mut bytes)?;
        commit.update(bytes);
        grid.push(decode_grid_record(&bytes)?);
    }
    let mut commit_magic = [0u8; 8];
    file.read_exact(&mut commit_magic)?;
    ensure!(
        get_u64(&commit_magic) == COMMIT_MAGIC,
        "invalid frame commit magic"
    );
    commit.update(commit_magic);
    let expected_commit = B256::from_slice(&commit.finalize());
    let mut commit_digest = [0u8; 32];
    file.read_exact(&mut commit_digest)?;
    ensure!(
        expected_commit == B256::from(commit_digest),
        "invalid frame commit digest"
    );
    ensure!(
        grid_digest(&grid).as_slice() == &prefix[224..256],
        "snapshot grid digest mismatch"
    );
    let v = (prefix[21] == 1).then(|| MessageJournalAnchor {
        sequence: get_u64(&prefix[80..88]),
        block_number: get_u64(&prefix[88..96]),
        block_hash: B256::from_slice(&prefix[96..128]),
    });
    if v.is_none() {
        ensure!(
            prefix[80..128].iter().all(|byte| *byte == 0),
            "absent V fields are nonzero"
        );
    }
    if let Some(bootstrap) = bootstrap {
        ensure!(
            bootstrap_certificate_digest(bootstrap).as_slice() == &prefix[256..288],
            "bootstrap certificate digest mismatch"
        );
    } else {
        ensure!(
            prefix[256..288].iter().all(|byte| *byte == 0),
            "absent bootstrap digest is nonzero"
        );
    }
    let state = SnapshotState {
        kind: state_kind,
        entries,
        bootstrap,
        v,
        authority_operation_count: get_u64(&prefix[24..32]),
        latest_authority_id: B256::from_slice(&prefix[128..160]),
        latest_authority_chain_digest: B256::from_slice(&prefix[160..192]),
        predecessor_final_commit_digest: B256::from_slice(&prefix[192..224]),
        grid,
        source_v: (prefix[288] == 1).then(|| get_u64(&prefix[304..312])),
        source_j: get_u64(&prefix[296..304]),
        source_latest_authority_id: B256::from_slice(&prefix[312..344]),
        truncation_target_authority_id: B256::from_slice(&prefix[344..376]),
        truncation_plan_digest: B256::from_slice(&prefix[376..408]),
        removed_identity_count: get_u64(&prefix[408..416]),
        removed_identities_digest: B256::from_slice(&prefix[416..448]),
        source_authority_chain_digest: B256::from_slice(&prefix[448..480]),
        source_authority_operation_count: get_u64(&prefix[480..488]),
    };
    let expected_j = snapshot_watermark(header.anchor, &state.entries);
    ensure!(
        (
            get_u64(&prefix[32..40]),
            get_u64(&prefix[40..48]),
            B256::from_slice(&prefix[48..80])
        ) == (
            expected_j.sequence,
            expected_j.block_number,
            expected_j.block_hash
        ),
        "snapshot J summary mismatch"
    );
    Ok((state, expected_commit))
}

fn exact_journal_name(generation: u64, suffix: &str) -> String {
    format!("{MESSAGE_JOURNAL_PREFIX}{generation:020}.{suffix}")
}

fn parse_journal_name(name: &str) -> eyre::Result<Option<(u64, bool)>> {
    if !name.starts_with(MESSAGE_JOURNAL_FAMILY_PREFIX) {
        return Ok(None);
    }
    ensure!(
        name.starts_with(MESSAGE_JOURNAL_PREFIX),
        "unsupported v1/v2 or malformed journal artifact {name}"
    );
    let tail = &name[MESSAGE_JOURNAL_PREFIX.len()..];
    ensure!(
        tail.len() == 24,
        "malformed v3 journal generation in {name}"
    );
    let digits = &tail[..20];
    ensure!(
        digits.bytes().all(|byte| byte.is_ascii_digit()),
        "nondecimal v3 journal generation in {name}"
    );
    let generation = digits.parse::<u64>()?;
    let temp = match &tail[20..] {
        ".log" => false,
        ".tmp" => true,
        _ => return Err(eyre!("unknown v3 journal suffix in {name}")),
    };
    Ok(Some((generation, temp)))
}

fn hash_complete_file(
    directory: &JournalDirectory,
    file_name: &str,
    length: u64,
) -> eyre::Result<B256> {
    let length_usize = usize::try_from(length)?;
    let mut hasher = framed_hasher(DOMAIN_FILE_ROOT, length_usize);
    let mut file = directory.open_existing(file_name, false, false)?;
    let mut scratch = vec![0u8; JOURNAL_STREAM_SCRATCH];
    let mut remaining = length;
    while remaining != 0 {
        let count = usize::try_from(remaining.min(scratch.len() as u64))?;
        file.read_exact(&mut scratch[..count])?;
        hasher.update(&scratch[..count]);
        remaining -= count as u64;
    }
    Ok(B256::from_slice(&hasher.finalize()))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageJournalInspection {
    pub path: PathBuf,
    pub header: JournalHeader,
    pub entries: Vec<MessageJournalEntry>,
    pub watermark: MessageJournalAnchor,
    pub v: Option<MessageJournalAnchor>,
    pub authority_operation_count: u64,
    pub latest_authority_id: B256,
    pub latest_authority_chain_digest: B256,
    pub retained_grid: Vec<RetainedGridRecordV3>,
    pub last_operation_generation: u64,
    pub last_commit_digest: B256,
    pub file_root: B256,
    pub complete_byte_offset: u64,
    pub has_authenticated_short_tail: bool,
    pub recovery_truncation: bool,
    compacted_authority_operation_count: u64,
    state: SnapshotState,
}

impl MessageJournalInspection {
    pub fn anchor(&self) -> MessageJournalAnchor {
        self.header.anchor
    }

    pub fn entry(&self, sequence: u64) -> Option<MessageJournalEntry> {
        let offset = usize::try_from(
            sequence
                .checked_sub(self.header.anchor.sequence)?
                .checked_sub(1)?,
        )
        .ok()?;
        self.entries.get(offset).copied()
    }

    pub fn identity(&self, sequence: u64) -> Option<MessageJournalAnchor> {
        identity_at(self.header.anchor, &self.entries, sequence)
    }
}

#[derive(Debug)]
struct StreamedLineageState {
    header: JournalHeader,
    state: SnapshotState,
    watermark: MessageJournalAnchor,
    identity_count: usize,
    last_operation_generation: u64,
    last_commit_digest: B256,
    file_root: B256,
    complete_byte_offset: u64,
}

fn validate_streamed_snapshot_summary(
    header: JournalHeader,
    state: &SnapshotState,
    identity_count: usize,
    watermark: MessageJournalAnchor,
    v_identity: Option<MessageJournalAnchor>,
    policy: AuthorityPolicy<'_>,
) -> eyre::Result<()> {
    ensure!(
        state.kind == SnapshotStateKind::Ordinary,
        "retained predecessor snapshot is not ordinary"
    );
    if let Some(v) = state.v {
        ensure!(v.sequence <= watermark.sequence, "V is above J");
        ensure!(v_identity == Some(v), "V identity mismatch");
        ensure!(
            state.bootstrap.is_some()
                && state.authority_operation_count != 0
                && state.latest_authority_id != B256::ZERO
                && state.latest_authority_chain_digest != B256::ZERO,
            "present V has incomplete authority summary"
        );
    } else {
        ensure!(
            state.bootstrap.is_none()
                && state.authority_operation_count == 0
                && state.latest_authority_id == B256::ZERO
                && state.latest_authority_chain_digest == B256::ZERO
                && state.grid.is_empty(),
            "absent V has authority state"
        );
    }
    if let Some(bootstrap) = state.bootstrap {
        validate_bootstrap(bootstrap, header.anchor, policy)?;
        ensure!(state.v.is_some(), "bootstrap exists without V");
        if header.lineage_generation == 0 {
            ensure!(
                state.v == Some(header.anchor)
                    && state.authority_operation_count == 1
                    && state.latest_authority_id == bootstrap.authority_id
                    && state.latest_authority_chain_digest == authority_chain_digest(bootstrap)
                    && state.grid.is_empty(),
                "lineage-zero bootstrap summary mismatch"
            );
        }
    }
    ensure!(
        state.source_v.is_none()
            && state.source_j == 0
            && state.source_latest_authority_id == B256::ZERO
            && state.truncation_target_authority_id == B256::ZERO
            && state.truncation_plan_digest == B256::ZERO
            && state.removed_identity_count == 0
            && state.removed_identities_digest == B256::ZERO
            && state.source_authority_chain_digest == B256::ZERO
            && state.source_authority_operation_count == 0,
        "ordinary snapshot has recovery fields"
    );
    if state.v.is_some() {
        validate_grid(state, true, None)?;
    }
    if header.lineage_generation == 0 {
        ensure!(
            identity_count == 0 && state.predecessor_final_commit_digest == B256::ZERO,
            "lineage zero is not canonical"
        );
    }
    Ok(())
}

fn read_snapshot_frame_summary(
    file: &mut File,
    prelude: [u8; 96],
    header: JournalHeader,
    policy: AuthorityPolicy<'_>,
) -> eyre::Result<(SnapshotState, usize, MessageJournalAnchor, B256)> {
    let (kind, payload_len, _, _) = decode_frame_prelude(&prelude)?;
    ensure!(
        matches!(
            kind,
            FrameKind::Snapshot | FrameKind::RecoveryTruncationSnapshot
        ),
        "streaming parser received a non-snapshot frame"
    );
    let mut commit = framed_hasher(DOMAIN_FRAME_COMMIT, 104 + payload_len);
    commit.update(prelude);
    let mut prefix = [0u8; SNAPSHOT_PREFIX_LEN];
    file.read_exact(&mut prefix)?;
    commit.update(prefix);
    ensure!(&prefix[..8] == SNAPSHOT_MAGIC, "invalid snapshot magic");
    ensure!(get_u16(&prefix[8..10]) == 3, "unsupported snapshot version");
    let state_kind = match prefix[10] {
        0 => SnapshotStateKind::Ordinary,
        1 => SnapshotStateKind::RecoveryTruncation,
        value => return Err(eyre!("unknown snapshot state kind {value}")),
    };
    ensure!(
        (kind == FrameKind::Snapshot && state_kind == SnapshotStateKind::Ordinary)
            || (kind == FrameKind::RecoveryTruncationSnapshot
                && state_kind == SnapshotStateKind::RecoveryTruncation),
        "snapshot frame/state kind mismatch"
    );
    ensure!(prefix[11] == 0, "nonzero snapshot flags");
    ensure!(
        get_u32(&prefix[12..16]) as usize == SNAPSHOT_PREFIX_LEN,
        "snapshot prefix length mismatch"
    );
    ensure!(matches!(prefix[20], 0 | 1), "invalid bootstrap presence");
    ensure!(matches!(prefix[21], 0 | 1), "invalid V presence");
    ensure!(matches!(prefix[288], 0 | 1), "invalid source-V presence");
    ensure!(
        prefix[289..296].iter().all(|byte| *byte == 0),
        "nonzero recovery reserved bytes"
    );
    ensure!(
        prefix[488..].iter().all(|byte| *byte == 0),
        "nonzero snapshot reserved bytes"
    );
    let identity_count = get_u32(&prefix[16..20]) as usize;
    let bootstrap_present = prefix[20] == 1;
    let grid_count = get_u16(&prefix[22..24]) as usize;
    ensure!(
        identity_count <= JOURNAL_HARD_IDENTITY_LIMIT,
        "snapshot identity cap exceeded"
    );
    ensure!(grid_count <= MAX_GRID_RECORDS, "snapshot grid cap exceeded");
    ensure!(
        payload_len
            == SNAPSHOT_PREFIX_LEN
                + identity_count * IDENTITY_LEN
                + usize::from(bootstrap_present) * AUTHORITY_RECORD_LEN
                + grid_count * GRID_RECORD_LEN,
        "snapshot count/length mismatch"
    );
    let genesis_number = header
        .anchor
        .block_number
        .checked_sub(header.anchor.sequence)
        .ok_or_else(|| eyre!("journal anchor precedes L2 genesis mapping"))?;
    let v = (prefix[21] == 1).then(|| MessageJournalAnchor {
        sequence: get_u64(&prefix[80..88]),
        block_number: get_u64(&prefix[88..96]),
        block_hash: B256::from_slice(&prefix[96..128]),
    });
    if v.is_none() {
        ensure!(
            prefix[80..128].iter().all(|byte| *byte == 0),
            "absent V fields are nonzero"
        );
    }
    let mut previous = header.anchor;
    let mut v_identity = (v == Some(header.anchor)).then_some(header.anchor);
    let mut identity = [0u8; IDENTITY_LEN];
    for _ in 0..identity_count {
        file.read_exact(&mut identity)?;
        commit.update(identity);
        let decoded = decode_identity(&identity)?;
        validate_identity_chain(previous, &[decoded], genesis_number)?;
        previous = MessageJournalAnchor {
            sequence: decoded.sequence,
            block_number: decoded.block_number,
            block_hash: decoded.block_hash,
        };
        if v.is_some_and(|value| value.sequence == decoded.sequence) {
            v_identity = Some(previous);
        }
    }
    let bootstrap = if bootstrap_present {
        let mut bytes = [0u8; AUTHORITY_RECORD_LEN];
        file.read_exact(&mut bytes)?;
        commit.update(bytes);
        Some(decode_authority_record(&bytes)?)
    } else {
        None
    };
    let mut grid = Vec::with_capacity(grid_count);
    for _ in 0..grid_count {
        let mut bytes = [0u8; GRID_RECORD_LEN];
        file.read_exact(&mut bytes)?;
        commit.update(bytes);
        grid.push(decode_grid_record(&bytes)?);
    }
    let mut commit_magic = [0u8; 8];
    file.read_exact(&mut commit_magic)?;
    ensure!(
        get_u64(&commit_magic) == COMMIT_MAGIC,
        "invalid frame commit magic"
    );
    commit.update(commit_magic);
    let expected_commit = B256::from_slice(&commit.finalize());
    let mut commit_digest = [0u8; 32];
    file.read_exact(&mut commit_digest)?;
    ensure!(
        expected_commit == B256::from(commit_digest),
        "invalid frame commit digest"
    );
    ensure!(
        grid_digest(&grid).as_slice() == &prefix[224..256],
        "snapshot grid digest mismatch"
    );
    if let Some(bootstrap) = bootstrap {
        ensure!(
            bootstrap_certificate_digest(bootstrap).as_slice() == &prefix[256..288],
            "bootstrap certificate digest mismatch"
        );
    } else {
        ensure!(
            prefix[256..288].iter().all(|byte| *byte == 0),
            "absent bootstrap digest is nonzero"
        );
    }
    ensure!(
        (
            get_u64(&prefix[32..40]),
            get_u64(&prefix[40..48]),
            B256::from_slice(&prefix[48..80])
        ) == (
            previous.sequence,
            previous.block_number,
            previous.block_hash
        ),
        "snapshot J summary mismatch"
    );
    let state = SnapshotState {
        kind: state_kind,
        entries: Vec::new(),
        bootstrap,
        v,
        authority_operation_count: get_u64(&prefix[24..32]),
        latest_authority_id: B256::from_slice(&prefix[128..160]),
        latest_authority_chain_digest: B256::from_slice(&prefix[160..192]),
        predecessor_final_commit_digest: B256::from_slice(&prefix[192..224]),
        grid,
        source_v: (prefix[288] == 1).then(|| get_u64(&prefix[304..312])),
        source_j: get_u64(&prefix[296..304]),
        source_latest_authority_id: B256::from_slice(&prefix[312..344]),
        truncation_target_authority_id: B256::from_slice(&prefix[344..376]),
        truncation_plan_digest: B256::from_slice(&prefix[376..408]),
        removed_identity_count: get_u64(&prefix[408..416]),
        removed_identities_digest: B256::from_slice(&prefix[416..448]),
        source_authority_chain_digest: B256::from_slice(&prefix[448..480]),
        source_authority_operation_count: get_u64(&prefix[480..488]),
    };
    validate_streamed_snapshot_summary(
        header,
        &state,
        identity_count,
        previous,
        v_identity,
        policy,
    )?;
    Ok((state, identity_count, previous, expected_commit))
}

fn discard_exact(file: &mut File, mut length: usize) -> eyre::Result<()> {
    let mut scratch = [0u8; 8 * 1024];
    while length != 0 {
        let count = length.min(scratch.len());
        file.read_exact(&mut scratch[..count])?;
        length -= count;
    }
    Ok(())
}

fn stream_logical_identities(
    directory: &JournalDirectory,
    file_name: &str,
    end_offset: u64,
    promoted_through: Option<u64>,
    mut visit: impl FnMut(usize, MessageJournalEntry) -> eyre::Result<()>,
) -> eyre::Result<usize> {
    let mut file = directory.open_existing(file_name, false, false)?;
    let mut header = [0u8; HEADER_LEN];
    file.read_exact(&mut header)?;
    decode_header(&header)?;
    let mut index = 0usize;
    loop {
        let frame_start = file.stream_position()?;
        if frame_start >= end_offset {
            break;
        }
        let mut prelude = [0u8; 96];
        file.read_exact(&mut prelude)?;
        let (kind, payload_len, _, _) = decode_frame_prelude(&prelude)?;
        match kind {
            FrameKind::Snapshot | FrameKind::RecoveryTruncationSnapshot => {
                let mut prefix = [0u8; SNAPSHOT_PREFIX_LEN];
                file.read_exact(&mut prefix)?;
                let identity_count = get_u32(&prefix[16..20]) as usize;
                let trailing_payload = payload_len
                    .checked_sub(SNAPSHOT_PREFIX_LEN + identity_count * IDENTITY_LEN)
                    .ok_or_else(|| eyre!("snapshot identity count exceeds payload"))?;
                let mut bytes = [0u8; IDENTITY_LEN];
                for _ in 0..identity_count {
                    file.read_exact(&mut bytes)?;
                    let mut identity = decode_identity(&bytes)?;
                    if promoted_through.is_some_and(|v| identity.sequence <= v) {
                        identity.source = ArbEngineInputSource::L1;
                    }
                    visit(index, identity)?;
                    index += 1;
                }
                discard_exact(&mut file, trailing_payload + 40)?;
            }
            FrameKind::Executed => {
                ensure!(
                    payload_len == IDENTITY_LEN,
                    "executed payload length changed"
                );
                let mut bytes = [0u8; IDENTITY_LEN];
                file.read_exact(&mut bytes)?;
                let mut identity = decode_identity(&bytes)?;
                if promoted_through.is_some_and(|v| identity.sequence <= v) {
                    identity.source = ArbEngineInputSource::L1;
                }
                visit(index, identity)?;
                index += 1;
                discard_exact(&mut file, 40)?;
            }
            FrameKind::Authority => discard_exact(&mut file, payload_len + 40)?,
        }
    }
    Ok(index)
}

fn apply_streamed_authority_frame(
    directory: &JournalDirectory,
    file_name: &str,
    frame_start: u64,
    state: &mut StreamedLineageState,
    frame: &DecodedFrame,
    policy: AuthorityPolicy<'_>,
) -> eyre::Result<()> {
    ensure!(
        state.state.bootstrap.is_some() && state.state.v.is_some(),
        "authority cannot publish while V=None"
    );
    let record = decode_authority_record(&frame.payload[..AUTHORITY_RECORD_LEN])?;
    ensure!(
        record.kind == AuthorityKind::Promotion,
        "appended bootstrap authority is forbidden"
    );
    validate_locator_context(record.locator, policy)?;
    validate_bitmap(record)?;
    ensure!(
        record.evidence_digest != B256::ZERO,
        "zero authority evidence digest"
    );
    ensure!(
        record.operation_generation == frame.operation_generation,
        "authority/frame generation mismatch"
    );
    let count = usize::from(record.record_count);
    ensure!(
        (1..=AUTHORITY_MAX_RECORDS).contains(&count),
        "promotion count outside 1..=256"
    );
    ensure!(
        frame.payload.len() == AUTHORITY_RECORD_LEN + count * IDENTITY_LEN,
        "authority count/length mismatch"
    );
    let old_v = state.state.v.expect("checked");
    ensure!(
        record.start_sequence
            == old_v
                .sequence
                .checked_add(1)
                .ok_or_else(|| eyre!("V overflow"))?,
        "promotion does not start at V+1"
    );
    ensure!(
        record
            .end_sequence
            .checked_sub(record.start_sequence)
            .and_then(|distance| distance.checked_add(1))
            == Some(count as u64),
        "promotion range/count mismatch"
    );
    ensure!(
        record.authority_chain_position
            == state
                .state
                .authority_operation_count
                .checked_add(1)
                .ok_or_else(|| eyre!("authority position overflow"))?
            && record.predecessor_authority_id == state.state.latest_authority_id
            && record.predecessor_authority_chain_digest
                == state.state.latest_authority_chain_digest,
        "authority predecessor summary mismatch"
    );
    let bootstrap = bootstrap_endpoint(&state.state).expect("checked");
    let distance = record
        .start_sequence
        .checked_sub(bootstrap)
        .ok_or_else(|| eyre!("promotion starts before bootstrap"))?;
    let first_grid_offset = distance
        .div_ceil(256)
        .checked_mul(256)
        .ok_or_else(|| eyre!("promotion grid offset overflow"))?;
    let first_grid = bootstrap
        .checked_add(first_grid_offset)
        .ok_or_else(|| eyre!("promotion grid endpoint overflow"))?;
    ensure!(
        first_grid >= record.end_sequence,
        "authority record crosses a grid boundary"
    );
    let mut promoted_digest = framed_hasher(DOMAIN_IDENTITIES, 2 + count * IDENTITY_LEN);
    promoted_digest.update(u16::try_from(count)?.to_be_bytes());
    let mut found = 0usize;
    stream_logical_identities(
        directory,
        file_name,
        frame_start,
        Some(old_v.sequence),
        |_, retained| {
            if !(record.start_sequence..=record.end_sequence).contains(&retained.sequence) {
                return Ok(());
            }
            ensure!(found < count, "authority retained range exceeds count");
            let offset = AUTHORITY_RECORD_LEN + found * IDENTITY_LEN;
            let authority_identity =
                decode_identity(&frame.payload[offset..offset + IDENTITY_LEN])?;
            ensure!(
                authority_identity.source == ArbEngineInputSource::L1,
                "authority identity is not L1"
            );
            ensure!(
                authority_identity.sequence == record.start_sequence + found as u64,
                "authority range gap"
            );
            let transitioned = retained.source == ArbEngineInputSource::Feed;
            ensure!(
                bitmap_bit(&record.feed_transition_bitmap, found) == transitioned,
                "authority bitmap/source conflict"
            );
            let mut expected = retained;
            expected.source = ArbEngineInputSource::L1;
            ensure!(
                authority_identity == expected,
                "authority identity conflicts with retained identity"
            );
            promoted_digest.update(encode_identity(authority_identity));
            found += 1;
            Ok(())
        },
    )?;
    ensure!(found == count, "authority range is not retained");
    ensure!(
        B256::from_slice(&promoted_digest.finalize()) == record.promoted_identities_digest,
        "promoted identities digest mismatch"
    );
    let terminal_offset = AUTHORITY_RECORD_LEN + (count - 1) * IDENTITY_LEN;
    let terminal =
        decode_identity(&frame.payload[terminal_offset..terminal_offset + IDENTITY_LEN])?;
    ensure!(
        record.locator.terminal_sequence == terminal.sequence
            && record.locator.terminal_l2_block_number == terminal.block_number
            && record.locator.terminal_l2_block_hash == terminal.block_hash
            && record.locator.terminal_delayed_count == terminal.delayed_messages_read,
        "authority locator terminal mismatch"
    );
    state.state.v = Some(MessageJournalAnchor {
        sequence: terminal.sequence,
        block_number: terminal.block_number,
        block_hash: terminal.block_hash,
    });
    state.state.authority_operation_count = record.authority_chain_position;
    state.state.latest_authority_id = record.authority_id;
    state.state.latest_authority_chain_digest = authority_chain_digest(record);
    if positive_grid_endpoint(bootstrap, record.end_sequence) {
        state.state.grid.push(RetainedGridRecordV3 {
            authority: record,
            original_lineage_generation: state.header.lineage_generation,
            original_frame_commit_digest: frame.commit_digest,
        });
    }
    retain_ordinary_grid(&mut state.state)?;
    Ok(())
}

fn inspect_streamed_predecessor(
    directory: &JournalDirectory,
    file_name: &str,
    expected_context: StorageContextV3,
    policy: AuthorityPolicy<'_>,
) -> eyre::Result<StreamedLineageState> {
    let (name_generation, temp) = parse_journal_name(file_name)?
        .ok_or_else(|| eyre!("predecessor is not a v3 journal artifact"))?;
    ensure!(!temp, "selected predecessor is temporary");
    let mut file = directory.open_existing(file_name, false, false)?;
    let length = file.metadata()?.len();
    ensure!(
        length <= JOURNAL_HARD_FILE_LIMIT,
        "selected predecessor exceeds 48 MiB hard limit"
    );
    let mut header_bytes = [0u8; HEADER_LEN];
    file.read_exact(&mut header_bytes)?;
    let header = decode_header(&header_bytes)?;
    ensure!(
        name_generation == header.lineage_generation,
        "journal name/header generation mismatch"
    );
    ensure!(
        header.anchor == expected_context.anchor
            && header.storage_context_digest == expected_context.digest(),
        "predecessor storage context mismatch"
    );
    let mut streamed: Option<StreamedLineageState> = None;
    loop {
        let frame_start = file.stream_position()?;
        let remaining = length - frame_start;
        ensure!(remaining != 0, "predecessor lineage has no snapshot");
        ensure!(
            remaining >= FRAME_STORAGE_OVERHEAD as u64,
            "predecessor has a short tail"
        );
        let mut prelude = [0u8; 96];
        file.read_exact(&mut prelude)?;
        let (kind, payload_len, generation, previous_digest) = decode_frame_prelude(&prelude)?;
        let declared = FRAME_STORAGE_OVERHEAD
            .checked_add(payload_len)
            .ok_or_else(|| eyre!("frame length overflow"))?;
        ensure!(remaining >= declared as u64, "predecessor has a short tail");
        if let Some(state) = streamed.as_mut() {
            ensure!(
                !matches!(
                    kind,
                    FrameKind::Snapshot | FrameKind::RecoveryTruncationSnapshot
                ),
                "snapshot appears after first frame"
            );
            ensure!(
                generation
                    == state
                        .last_operation_generation
                        .checked_add(1)
                        .ok_or_else(|| eyre!("operation generation wrap"))?,
                "operation generation gap"
            );
            ensure!(
                previous_digest == state.last_commit_digest,
                "frame predecessor commit mismatch"
            );
            let mut bytes = vec![0u8; declared];
            bytes[..96].copy_from_slice(&prelude);
            file.read_exact(&mut bytes[96..])?;
            let frame = decode_complete_frame(&bytes)?;
            match kind {
                FrameKind::Executed => {
                    let entry = decode_identity(&frame.payload)?;
                    let genesis_number = header
                        .anchor
                        .block_number
                        .checked_sub(header.anchor.sequence)
                        .ok_or_else(|| eyre!("journal anchor precedes L2 genesis mapping"))?;
                    validate_identity_chain(state.watermark, &[entry], genesis_number)?;
                    ensure!(
                        state.identity_count < JOURNAL_HARD_IDENTITY_LIMIT,
                        "identity hard limit exceeded"
                    );
                    state.identity_count += 1;
                    state.watermark = MessageJournalAnchor {
                        sequence: entry.sequence,
                        block_number: entry.block_number,
                        block_hash: entry.block_hash,
                    };
                }
                FrameKind::Authority => apply_streamed_authority_frame(
                    directory,
                    file_name,
                    frame_start,
                    state,
                    &frame,
                    policy,
                )?,
                FrameKind::Snapshot | FrameKind::RecoveryTruncationSnapshot => unreachable!(),
            }
            state.last_operation_generation = generation;
            state.last_commit_digest = frame.commit_digest;
        } else {
            ensure!(
                matches!(
                    kind,
                    FrameKind::Snapshot | FrameKind::RecoveryTruncationSnapshot
                ),
                "lineage does not start with snapshot"
            );
            ensure!(
                generation == header.snapshot_through_operation_generation,
                "snapshot/header generation mismatch"
            );
            if header.lineage_generation == 0 {
                ensure!(
                    kind == FrameKind::Snapshot && generation == 0 && previous_digest == B256::ZERO,
                    "invalid lineage-zero snapshot chain"
                );
            }
            let (state, identity_count, watermark, commit) =
                read_snapshot_frame_summary(&mut file, prelude, header, policy)?;
            if header.lineage_generation != 0 {
                ensure!(
                    previous_digest == state.predecessor_final_commit_digest,
                    "standalone retained predecessor commit mismatch"
                );
            }
            streamed = Some(StreamedLineageState {
                header,
                state,
                watermark,
                identity_count,
                last_operation_generation: generation,
                last_commit_digest: commit,
                file_root: B256::ZERO,
                complete_byte_offset: length,
            });
        }
        if file.stream_position()? == length {
            break;
        }
    }
    let mut streamed = streamed.expect("snapshot required");
    streamed.file_root = hash_complete_file(directory, file_name, length)?;
    Ok(streamed)
}

fn validate_streamed_predecessor(
    directory: &JournalDirectory,
    file_name: &str,
    expected_context: StorageContextV3,
    policy: AuthorityPolicy<'_>,
    successor: &MessageJournalInspection,
) -> eyre::Result<()> {
    let predecessor = inspect_streamed_predecessor(directory, file_name, expected_context, policy)?;
    ensure!(
        successor.header.lineage_generation
            == predecessor
                .header
                .lineage_generation
                .checked_add(1)
                .ok_or_else(|| eyre!("lineage generation wrap"))?,
        "lineage generation gap"
    );
    ensure!(
        successor.header.predecessor_file_root == predecessor.file_root,
        "predecessor file-root mismatch"
    );
    ensure!(
        successor.header.anchor == predecessor.header.anchor,
        "compaction changed anchor"
    );
    ensure!(
        successor.state.predecessor_final_commit_digest == predecessor.last_commit_digest,
        "snapshot predecessor commit mismatch"
    );
    match successor.state.kind {
        SnapshotStateKind::Ordinary => {
            ensure!(
                successor.header.snapshot_through_operation_generation
                    == predecessor.last_operation_generation
                    && successor.entries.len() == predecessor.identity_count
                    && successor.state.bootstrap == predecessor.state.bootstrap
                    && successor.v == predecessor.state.v
                    && successor.authority_operation_count
                        == predecessor.state.authority_operation_count
                    && successor.latest_authority_id == predecessor.state.latest_authority_id
                    && successor.latest_authority_chain_digest
                        == predecessor.state.latest_authority_chain_digest
                    && successor.retained_grid == predecessor.state.grid,
                "ordinary compaction changed predecessor state"
            );
            let count = stream_logical_identities(
                directory,
                file_name,
                predecessor.complete_byte_offset,
                predecessor.state.v.map(|v| v.sequence),
                |index, identity| {
                    ensure!(
                        successor.entries.get(index) == Some(&identity),
                        "ordinary compaction changed predecessor identity"
                    );
                    Ok(())
                },
            )?;
            ensure!(
                count == predecessor.identity_count,
                "predecessor identity count changed"
            );
        }
        SnapshotStateKind::RecoveryTruncation => {
            ensure!(
                successor.header.snapshot_through_operation_generation
                    == predecessor
                        .last_operation_generation
                        .checked_add(1)
                        .ok_or_else(|| eyre!("operation generation wrap"))?
                    && successor.state.source_j == predecessor.watermark.sequence
                    && successor.state.source_v == predecessor.state.v.map(|v| v.sequence)
                    && successor.state.source_latest_authority_id
                        == predecessor.state.latest_authority_id
                    && successor.state.source_authority_chain_digest
                        == predecessor.state.latest_authority_chain_digest
                    && successor.state.source_authority_operation_count
                        == predecessor.state.authority_operation_count,
                "recovery source summary mismatch"
            );
            let j = successor.watermark;
            ensure!(
                j == successor.v.expect("recovery requires V"),
                "recovery J/V mismatch"
            );
            ensure!(
                j.sequence < predecessor.watermark.sequence,
                "recovery target is not below source J"
            );
            let bootstrap = successor
                .state
                .bootstrap
                .expect("present V requires bootstrap");
            let (target_id, target_chain, target_count) = if j.sequence == bootstrap.end_sequence {
                (bootstrap.authority_id, authority_chain_digest(bootstrap), 1)
            } else {
                let target = predecessor
                    .state
                    .grid
                    .iter()
                    .find(|record| record.authority.end_sequence == j.sequence)
                    .ok_or_else(|| eyre!("recovery target is not bootstrap or retained grid"))?;
                (
                    target.authority.authority_id,
                    authority_chain_digest(target.authority),
                    target.authority.authority_chain_position,
                )
            };
            ensure!(
                successor.latest_authority_id == target_id
                    && successor.state.truncation_target_authority_id == target_id
                    && successor.latest_authority_chain_digest == target_chain
                    && successor.authority_operation_count == target_count,
                "recovery target prefix summary mismatch"
            );
            ensure!(
                successor.entries.len() <= predecessor.identity_count,
                "recovery retained identity count exceeds source"
            );
            let removed_count = predecessor.identity_count - successor.entries.len();
            ensure!(
                successor.state.removed_identity_count == removed_count as u64,
                "removed identity count mismatch"
            );
            let mut removed =
                framed_hasher(DOMAIN_REMOVED_IDENTITIES, 8 + removed_count * IDENTITY_LEN);
            removed.update((removed_count as u64).to_be_bytes());
            let count = stream_logical_identities(
                directory,
                file_name,
                predecessor.complete_byte_offset,
                predecessor.state.v.map(|v| v.sequence),
                |index, identity| {
                    if let Some(expected) = successor.entries.get(index) {
                        ensure!(*expected == identity, "recovery retained identity mismatch");
                    } else {
                        removed.update(encode_identity(identity));
                    }
                    Ok(())
                },
            )?;
            ensure!(
                count == predecessor.identity_count,
                "predecessor identity count changed"
            );
            ensure!(
                B256::from_slice(&removed.finalize()) == successor.state.removed_identities_digest,
                "removed identity commitment mismatch"
            );
            let expected_grid: Vec<_> = predecessor
                .state
                .grid
                .iter()
                .copied()
                .filter(|record| record.authority.end_sequence <= j.sequence)
                .collect();
            ensure!(
                successor.retained_grid == expected_grid,
                "recovery grid is not exact source subset"
            );
        }
    }
    Ok(())
}

fn inspect_file(
    directory: &JournalDirectory,
    file_name: &str,
    expected_context: StorageContextV3,
    policy: AuthorityPolicy<'_>,
) -> eyre::Result<MessageJournalInspection> {
    let path = directory.entry_path(file_name)?;
    let (name_generation, _) = parse_journal_name(file_name)?
        .ok_or_else(|| eyre!("selected file is not a v3 journal artifact"))?;
    let mut file = directory.open_existing(file_name, false, false)?;
    let length = file.metadata()?.len();
    ensure!(
        length <= JOURNAL_HARD_FILE_LIMIT,
        "selected journal exceeds 48 MiB hard limit"
    );
    let mut header_bytes = [0u8; HEADER_LEN];
    file.read_exact(&mut header_bytes)?;
    let header = decode_header(&header_bytes)?;
    ensure!(
        name_generation == header.lineage_generation,
        "journal name/header generation mismatch"
    );
    ensure!(
        header.anchor == expected_context.anchor,
        "journal anchor/storage context mismatch"
    );
    ensure!(
        header.storage_context_digest == expected_context.digest(),
        "journal storage-context digest mismatch"
    );
    let mut complete_offset = HEADER_LEN as u64;
    let mut last_generation = None;
    let mut last_digest = B256::ZERO;
    let mut state = None;
    let mut snapshot_authority_operation_count = None;
    let mut short_tail = false;
    loop {
        let frame_start = file.stream_position()?;
        let remaining = length - frame_start;
        if remaining == 0 {
            break;
        }
        if remaining < 40 {
            let mut tail = vec![0u8; remaining as usize];
            file.read_exact(&mut tail)?;
            validate_partial_frame(
                &tail,
                last_generation
                    .and_then(|value: u64| value.checked_add(1))
                    .unwrap_or(0),
                last_digest,
            )?;
            unreachable!("1..39 byte tails reject")
        }
        let mut prefix = [0u8; 40];
        file.read_exact(&mut prefix)?;
        let payload_len = get_u32(&prefix[4..8]) as usize;
        let declared = FRAME_STORAGE_OVERHEAD
            .checked_add(payload_len)
            .ok_or_else(|| eyre!("frame length overflow"))?;
        if remaining < declared as u64 {
            let inspect_len = usize::try_from(remaining.min(96))?;
            let mut tail = [0u8; 96];
            tail[..40].copy_from_slice(&prefix);
            file.read_exact(&mut tail[40..inspect_len])?;
            let expected_generation = last_generation
                .and_then(|value: u64| value.checked_add(1))
                .unwrap_or(header.snapshot_through_operation_generation);
            validate_partial_frame(&tail[..inspect_len], expected_generation, last_digest)?;
            short_tail = true;
            break;
        }
        let mut prelude = [0u8; 96];
        prelude[..40].copy_from_slice(&prefix);
        file.read_exact(&mut prelude[40..])?;
        let (kind, decoded_payload_len, generation, previous_digest) =
            decode_frame_prelude(&prelude)?;
        ensure!(
            decoded_payload_len == payload_len,
            "frame prefix changed during read"
        );
        let first = state.is_none();
        if first {
            ensure!(
                matches!(
                    kind,
                    FrameKind::Snapshot | FrameKind::RecoveryTruncationSnapshot
                ),
                "lineage does not start with snapshot"
            );
            ensure!(
                generation == header.snapshot_through_operation_generation,
                "snapshot/header generation mismatch"
            );
            if header.lineage_generation == 0 {
                ensure!(
                    kind == FrameKind::Snapshot && generation == 0 && previous_digest == B256::ZERO,
                    "invalid lineage-zero snapshot chain"
                );
            }
        } else {
            ensure!(
                !matches!(
                    kind,
                    FrameKind::Snapshot | FrameKind::RecoveryTruncationSnapshot
                ),
                "snapshot appears after first frame"
            );
            ensure!(
                generation
                    == last_generation
                        .and_then(|value: u64| value.checked_add(1))
                        .ok_or_else(|| eyre!("operation generation wrap"))?,
                "operation generation gap"
            );
            ensure!(
                previous_digest == last_digest,
                "frame predecessor commit mismatch"
            );
        }
        let commit_digest;
        if matches!(
            kind,
            FrameKind::Snapshot | FrameKind::RecoveryTruncationSnapshot
        ) {
            let (snapshot, commit) = read_snapshot_frame(&mut file, prelude, header)?;
            validate_snapshot_state(header, &snapshot, policy, None)?;
            snapshot_authority_operation_count = Some(snapshot.authority_operation_count);
            if header.lineage_generation == 0 {
                ensure!(
                    snapshot.entries.is_empty()
                        && snapshot.predecessor_final_commit_digest == B256::ZERO
                        && snapshot.kind == SnapshotStateKind::Ordinary,
                    "lineage zero is not canonical"
                );
            }
            if header.lineage_generation != 0 {
                ensure!(
                    previous_digest == snapshot.predecessor_final_commit_digest,
                    "standalone retained predecessor commit mismatch"
                );
            }
            state = Some(snapshot);
            commit_digest = commit;
        } else {
            let mut bytes = vec![0u8; declared];
            bytes[..96].copy_from_slice(&prelude);
            file.read_exact(&mut bytes[96..])?;
            let frame = decode_complete_frame(&bytes)?;
            let state = state.as_mut().expect("non-first frame");
            match frame.kind {
                FrameKind::Executed => {
                    let entry = decode_identity(&frame.payload)?;
                    let previous = snapshot_watermark(header.anchor, &state.entries);
                    let genesis_number = header
                        .anchor
                        .block_number
                        .checked_sub(header.anchor.sequence)
                        .ok_or_else(|| eyre!("journal anchor precedes L2 genesis mapping"))?;
                    validate_identity_chain(previous, &[entry], genesis_number)?;
                    ensure!(
                        state.entries.len() < JOURNAL_HARD_IDENTITY_LIMIT,
                        "identity hard limit exceeded"
                    );
                    state.entries.push(entry);
                }
                FrameKind::Authority => {
                    apply_authority_frame(state, &frame, policy, header.lineage_generation)?;
                }
                FrameKind::Snapshot | FrameKind::RecoveryTruncationSnapshot => unreachable!(),
            }
            commit_digest = frame.commit_digest;
        }
        complete_offset += declared as u64;
        last_generation = Some(generation);
        last_digest = commit_digest;
    }
    let mut state = state.ok_or_else(|| eyre!("journal lineage has no snapshot"))?;
    let compacted_authority_operation_count =
        snapshot_authority_operation_count.expect("snapshot exists");
    let watermark = snapshot_watermark(header.anchor, &state.entries);
    let file_root = if short_tail {
        B256::ZERO
    } else {
        hash_complete_file(directory, file_name, complete_offset)?
    };
    let entries = std::mem::take(&mut state.entries);
    Ok(MessageJournalInspection {
        path,
        header,
        entries,
        watermark,
        v: state.v,
        authority_operation_count: state.authority_operation_count,
        latest_authority_id: state.latest_authority_id,
        latest_authority_chain_digest: state.latest_authority_chain_digest,
        retained_grid: state.grid.clone(),
        last_operation_generation: last_generation.expect("snapshot exists"),
        last_commit_digest: last_digest,
        file_root,
        complete_byte_offset: complete_offset,
        has_authenticated_short_tail: short_tail,
        recovery_truncation: state.kind == SnapshotStateKind::RecoveryTruncation,
        compacted_authority_operation_count,
        state,
    })
}

type JournalFinalArtifacts = BTreeMap<u64, String>;
type JournalTempArtifacts = Vec<(u64, String)>;

fn collect_journal_artifacts(
    directory: &JournalDirectory,
) -> eyre::Result<(JournalFinalArtifacts, JournalTempArtifacts)> {
    let mut finals = BTreeMap::new();
    let mut temps = Vec::new();
    for name in directory.entry_names()? {
        if let Some((generation, temp)) = parse_journal_name(&name)? {
            if temp {
                temps.push((generation, name));
            } else {
                ensure!(
                    finals.insert(generation, name).is_none(),
                    "duplicate journal generation"
                );
            }
        }
    }
    Ok((finals, temps))
}

/// Read the authenticated header of the highest final lineage so a stopped caller can derive the
/// expected storage-context preimage from trusted chain/deployment data plus its immutable anchor.
/// Full lineage selection and predecessor validation still occur in [`inspect_message_journal`].
pub fn inspect_selected_journal_header(
    directory: &JournalDirectory,
) -> eyre::Result<JournalHeader> {
    let (finals, _) = collect_journal_artifacts(directory)?;
    let (&generation, name) = finals
        .last_key_value()
        .ok_or_else(|| eyre!("v3 message journal is missing"))?;
    let mut file = directory.open_existing(name, false, false)?;
    let mut bytes = [0u8; HEADER_LEN];
    file.read_exact(&mut bytes)?;
    let header = decode_header(&bytes)?;
    ensure!(
        header.lineage_generation == generation,
        "journal name/header generation mismatch"
    );
    Ok(header)
}

fn inspect_final_lineages(
    directory: &JournalDirectory,
    finals: &BTreeMap<u64, String>,
    expected_context: StorageContextV3,
    policy: AuthorityPolicy<'_>,
) -> eyre::Result<MessageJournalInspection> {
    let (&highest, _) = finals
        .last_key_value()
        .ok_or_else(|| eyre!("v3 message journal is missing"))?;
    if highest == 0 {
        return inspect_file(directory, finals.get(&0).unwrap(), expected_context, policy);
    }
    let predecessor_generation = highest - 1;
    let predecessor_name = finals
        .get(&predecessor_generation)
        .ok_or_else(|| eyre!("selected journal immediate predecessor is missing"))?;
    let selected = inspect_file(
        directory,
        finals.get(&highest).unwrap(),
        expected_context,
        policy,
    )?;
    validate_streamed_predecessor(
        directory,
        predecessor_name,
        expected_context,
        policy,
        &selected,
    )?;
    Ok(selected)
}

/// Read-only stopped classifier. The boolean is true for an authenticated short tail or a complete
/// next temp; callers must remain stopped until a dedicated repair process resolves it.
pub fn inspect_stopped_message_journal(
    directory: &JournalDirectory,
    expected_context: StorageContextV3,
) -> eyre::Result<(MessageJournalInspection, bool)> {
    inspect_stopped_with_policy(directory, expected_context, PRODUCTION_POLICY)
}

fn inspect_stopped_with_policy(
    directory: &JournalDirectory,
    expected_context: StorageContextV3,
    policy: AuthorityPolicy<'_>,
) -> eyre::Result<(MessageJournalInspection, bool)> {
    let (finals, temps) = collect_journal_artifacts(directory)?;
    let selected = inspect_final_lineages(directory, &finals, expected_context, policy)?;
    if temps.is_empty() {
        let repair = selected.has_authenticated_short_tail;
        return Ok((selected, repair));
    }
    ensure!(
        !selected.has_authenticated_short_tail,
        "temp and selected short tail coexist"
    );
    ensure!(temps.len() == 1, "multiple journal temp artifacts");
    let (generation, name) = &temps[0];
    ensure!(
        *generation
            == selected
                .header
                .lineage_generation
                .checked_add(1)
                .ok_or_else(|| eyre!("lineage generation wrap"))?,
        "journal temp is not exact next lineage"
    );
    let candidate = inspect_file(directory, name, expected_context, policy)?;
    ensure!(
        !candidate.has_authenticated_short_tail,
        "journal temp is incomplete"
    );
    let selected_name = selected
        .path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| eyre!("selected journal has no fixed name"))?;
    validate_streamed_predecessor(
        directory,
        selected_name,
        expected_context,
        policy,
        &candidate,
    )?;
    Ok((selected, true))
}

#[derive(Debug)]
pub struct B3RecoveryMarkerRequired;

impl std::fmt::Display for B3RecoveryMarkerRequired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("B3RecoveryMarkerRequired")
    }
}

impl std::error::Error for B3RecoveryMarkerRequired {}

pub fn inspect_message_journal(
    directory: &JournalDirectory,
    expected_context: StorageContextV3,
) -> eyre::Result<MessageJournalInspection> {
    inspect_message_with_policy(directory, expected_context, PRODUCTION_POLICY)
}

fn inspect_message_with_policy(
    directory: &JournalDirectory,
    expected_context: StorageContextV3,
    policy: AuthorityPolicy<'_>,
) -> eyre::Result<MessageJournalInspection> {
    let (inspection, repair_required) =
        inspect_stopped_with_policy(directory, expected_context, policy)?;
    ensure!(
        !repair_required,
        "journal transition requires stopped recovery"
    );
    if inspection.recovery_truncation {
        return Err(B3RecoveryMarkerRequired.into());
    }
    Ok(inspection)
}

pub fn repair_stopped_message_journal(
    directory: &JournalDirectory,
    expected_context: StorageContextV3,
) -> eyre::Result<MessageJournalInspection> {
    let (selected, repair_required) = inspect_stopped_message_journal(directory, expected_context)?;
    ensure!(
        repair_required,
        "stopped journal has no recoverable transition"
    );
    let (_, temps) = collect_journal_artifacts(directory)?;
    if temps.is_empty() {
        let name = selected
            .path
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| eyre!("selected journal has no fixed name"))?;
        let file = directory.open_existing(name, true, false)?;
        file.set_len(selected.complete_byte_offset)?;
        file.sync_data()?;
    } else {
        let (generation, temp) = &temps[0];
        directory.rename_noreplace(temp, &exact_journal_name(*generation, "log"))?;
        directory.sync_parent()?;
    }
    inspect_message_journal(directory, expected_context)
}

fn empty_snapshot_state() -> SnapshotState {
    SnapshotState {
        kind: SnapshotStateKind::Ordinary,
        entries: Vec::new(),
        bootstrap: None,
        v: None,
        authority_operation_count: 0,
        latest_authority_id: B256::ZERO,
        latest_authority_chain_digest: B256::ZERO,
        predecessor_final_commit_digest: B256::ZERO,
        grid: Vec::new(),
        source_v: None,
        source_j: 0,
        source_latest_authority_id: B256::ZERO,
        truncation_target_authority_id: B256::ZERO,
        truncation_plan_digest: B256::ZERO,
        removed_identity_count: 0,
        removed_identities_digest: B256::ZERO,
        source_authority_chain_digest: B256::ZERO,
        source_authority_operation_count: 0,
    }
}

pub fn initialize_journal_v3(
    directory: &JournalDirectory,
    context: StorageContextV3,
) -> eyre::Result<MessageJournalInspection> {
    for name in directory.entry_names()? {
        if name.starts_with(MESSAGE_JOURNAL_FAMILY_PREFIX) {
            return Err(eyre!("message-journal artifact already exists"));
        }
    }
    let header = JournalHeader {
        lineage_generation: 0,
        snapshot_through_operation_generation: 0,
        predecessor_file_root: B256::ZERO,
        anchor: context.anchor,
        storage_context_digest: context.digest(),
    };
    let state = empty_snapshot_state();
    ensure!(
        HEADER_LEN + FRAME_STORAGE_OVERHEAD + snapshot_payload_len(&state)? == 904,
        "lineage zero is not exactly 904 bytes"
    );
    let temp_name = exact_journal_name(0, "tmp");
    let final_name = exact_journal_name(0, "log");
    write_lineage_temp(
        directory,
        &temp_name,
        header,
        FrameKind::Snapshot,
        0,
        B256::ZERO,
        &state,
        "initialization",
    )?;
    let candidate = inspect_file(directory, &temp_name, context, PRODUCTION_POLICY)?;
    ensure!(
        candidate.complete_byte_offset == 904,
        "lineage-zero temp length changed"
    );
    journal_crashpoint("initialization_after_temp_reread");
    drop(candidate);
    directory.rename_noreplace(&temp_name, &final_name)?;
    journal_crashpoint("initialization_after_rename");
    directory.sync_parent()?;
    journal_crashpoint("initialization_after_parent_sync");
    let inspection = inspect_message_journal(directory, context)?;
    journal_crashpoint("initialization_after_selection");
    Ok(inspection)
}

pub fn divergence_marker_path(directory: &JournalDirectory) -> PathBuf {
    directory.path().join(DIVERGENCE_MARKER_FILE)
}

pub(crate) fn write_divergence_marker_at(
    directory: &JournalDirectory,
    tip: BlockNumHash,
    next_sequence: u64,
    input: &ArbEngineInput,
    error: &str,
) -> eyre::Result<()> {
    if directory.entry_exists(DIVERGENCE_MARKER_FILE)? {
        return Ok(());
    }
    let value = serde_json::json!({
        "version": 3,
        "detected_unix_seconds": SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        "tip_block_number": tip.number,
        "tip_block_hash": tip.hash,
        "next_sequence": next_sequence,
        "incoming_source": input.source(),
        "incoming_message": input.message(),
        "error": error,
    });
    let mut file = directory.create_new(DIVERGENCE_MARKER_FILE, false)?;
    serde_json::to_writer_pretty(&mut file, &value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    directory.sync_parent()
}

pub fn clear_divergence_marker_at(directory: &JournalDirectory) -> eyre::Result<()> {
    if directory.entry_exists(DIVERGENCE_MARKER_FILE)? {
        directory.remove_entry(DIVERGENCE_MARKER_FILE)?;
    }
    Ok(())
}

#[derive(Debug, Default)]
struct AdmissionState {
    work: usize,
    records: usize,
    bytes: usize,
}

#[derive(Debug)]
struct Admission {
    state: Mutex<AdmissionState>,
    closed: AtomicBool,
    journaled_sequence: AtomicU64,
    retained_identities: AtomicU64,
    notify: Notify,
}

impl Admission {
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    fn retire(&self, work: usize, records: usize, bytes: usize) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.work -= work;
        state.records -= records;
        state.bytes -= bytes;
        drop(state);
        self.notify.notify_waiters();
    }

    fn try_reserve_maintenance(self: &Arc<Self>, bytes: usize) -> Option<MaintenanceReservation> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let available = state.work + MAINTENANCE_WORK_ITEMS
            <= JOURNAL_WORK_ITEM_CAPACITY - PROTECTED_EXECUTION_WORK_FLOOR
            && state.records
                <= JOURNAL_RECORD_LIABILITY_CAPACITY - PROTECTED_EXECUTION_RECORD_FLOOR
            && state
                .bytes
                .checked_add(bytes)
                .is_some_and(|total| total <= JOURNAL_OUTSTANDING_BYTE_CAPACITY);
        if !available {
            return None;
        }
        state.work += MAINTENANCE_WORK_ITEMS;
        state.bytes += bytes;
        drop(state);
        Some(MaintenanceReservation {
            admission: self.clone(),
            bytes,
        })
    }

    /// Mechanically reserve a future authority frame without publishing authority.
    ///
    /// Production B1 deliberately has no caller or enqueue variant for this reservation. Keeping
    /// the exact shared-capacity transition here makes the frozen storage accounting executable
    /// and available to the later separately authorized producer without weakening B1's empty
    /// registry and caller set.
    #[allow(dead_code)]
    fn try_reserve_authority_storage(
        self: &Arc<Self>,
        records: usize,
    ) -> eyre::Result<Option<AuthorityStorageReservation>> {
        let bytes = authority_storage_charge(records)?;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let available = !self.closed.load(Ordering::Acquire)
            && state.work < JOURNAL_WORK_ITEM_CAPACITY - PROTECTED_EXECUTION_WORK_FLOOR
            && state.records.checked_add(records).is_some_and(|total| {
                total <= JOURNAL_RECORD_LIABILITY_CAPACITY - PROTECTED_EXECUTION_RECORD_FLOOR
            })
            && state
                .bytes
                .checked_add(bytes)
                .is_some_and(|total| total <= JOURNAL_OUTSTANDING_BYTE_CAPACITY);
        if !available {
            return Ok(None);
        }
        state.work += 1;
        state.records += records;
        state.bytes += bytes;
        drop(state);
        Ok(Some(AuthorityStorageReservation {
            admission: self.clone(),
            records,
            bytes,
        }))
    }
}

fn authority_storage_charge(records: usize) -> eyre::Result<usize> {
    ensure!(
        (1..=AUTHORITY_MAX_RECORDS).contains(&records),
        "authority reservation count outside 1..=256"
    );
    (FRAME_STORAGE_OVERHEAD + AUTHORITY_RECORD_LEN)
        .checked_add(
            records
                .checked_mul(IDENTITY_LEN)
                .ok_or_else(|| eyre!("authority identity length overflow"))?,
        )
        .and_then(|frame| frame.checked_mul(2))
        .ok_or_else(|| eyre!("authority storage charge overflow"))
}

pub struct ExecutionReservation {
    admission: Arc<Admission>,
    bytes: usize,
    retired: bool,
}

impl ExecutionReservation {
    fn retire(&mut self) {
        if !self.retired {
            self.admission.retire(1, 1, self.bytes);
            self.retired = true;
        }
    }
}

impl Drop for ExecutionReservation {
    fn drop(&mut self) {
        self.retire();
    }
}

struct MaintenanceReservation {
    admission: Arc<Admission>,
    bytes: usize,
}

impl Drop for MaintenanceReservation {
    fn drop(&mut self) {
        self.admission.retire(MAINTENANCE_WORK_ITEMS, 0, self.bytes);
    }
}

#[allow(dead_code)]
struct AuthorityStorageReservation {
    admission: Arc<Admission>,
    records: usize,
    bytes: usize,
}

impl Drop for AuthorityStorageReservation {
    fn drop(&mut self) {
        self.admission.retire(1, self.records, self.bytes);
    }
}

#[derive(Debug)]
struct PersistenceState {
    frontier: BlockNumHash,
    exact: BTreeMap<u64, B256>,
    fatal: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct PersistenceObserver {
    state: Arc<Mutex<PersistenceState>>,
    wake: crossbeam_channel::Sender<()>,
    admission: Arc<Admission>,
}

impl PersistenceObserver {
    pub(crate) fn failed(&self, error: impl Into<String>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.fatal = Some(error.into());
        self.admission.close();
        drop(state);
        let _ = self.wake.try_send(());
    }

    pub(crate) fn saved(&self, captured: &[BlockNumHash], result: BlockNumHash) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let update = (|| -> eyre::Result<()> {
            let expected = captured
                .last()
                .copied()
                .ok_or_else(|| eyre!("persistence acknowledgement has no captured identity"))?;
            ensure!(
                result == expected,
                "persistence result does not match captured top"
            );
            ensure!(
                result.number >= state.frontier.number,
                "persisted frontier regressed"
            );
            if result.number == state.frontier.number {
                ensure!(
                    result.hash == state.frontier.hash,
                    "same-height persisted hash conflict"
                );
            }
            let mut expected_number = state.frontier.number;
            for identity in captured {
                if identity.number <= state.frontier.number {
                    if identity.number == state.frontier.number {
                        ensure!(
                            identity.hash == state.frontier.hash,
                            "captured frontier conflict"
                        );
                    }
                    continue;
                }
                expected_number = expected_number
                    .checked_add(1)
                    .ok_or_else(|| eyre!("persisted number overflow"))?;
                ensure!(
                    identity.number == expected_number,
                    "captured persistence gap"
                );
                if let Some(existing) = state.exact.insert(identity.number, identity.hash) {
                    ensure!(existing == identity.hash, "captured same-height conflict");
                }
            }
            state.frontier = result;
            Ok(())
        })();
        if let Err(error) = update {
            state.fatal = Some(format!("{error:#}"));
            self.admission.close();
        }
        drop(state);
        let _ = self.wake.try_send(());
    }

    pub(crate) fn removed(&self, result: BlockNumHash) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if result != state.frontier {
            state.fatal = Some("RemoveBlocksAbove changed exact D".into());
            self.admission.close();
        }
        drop(state);
        let _ = self.wake.try_send(());
    }
}

#[cfg(test)]
pub(crate) fn test_persistence_observer() -> PersistenceObserver {
    let (wake, _receiver) = crossbeam_channel::bounded(1);
    let admission = Arc::new(Admission {
        state: Mutex::new(AdmissionState::default()),
        closed: AtomicBool::new(false),
        journaled_sequence: AtomicU64::new(0),
        retained_identities: AtomicU64::new(0),
        notify: Notify::new(),
    });
    PersistenceObserver {
        state: Arc::new(Mutex::new(PersistenceState {
            frontier: BlockNumHash::default(),
            exact: BTreeMap::new(),
            fatal: None,
        })),
        wake,
        admission,
    }
}

enum Work {
    Executed(MessageJournalEntry, ExecutionReservation),
    Drain(crossbeam_channel::Sender<eyre::Result<MessageJournalAnchor>>),
}

enum Control {
    Stop(crossbeam_channel::Sender<eyre::Result<()>>),
}

#[derive(Clone)]
pub struct JournalClient {
    work: crossbeam_channel::Sender<Work>,
    control: crossbeam_channel::Sender<Control>,
    admission: Arc<Admission>,
    fatal: Arc<Mutex<Option<String>>>,
}

impl JournalClient {
    pub async fn reserve_execution(&self, sequence: u64) -> eyre::Result<ExecutionReservation> {
        loop {
            let notified = self.admission.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            ensure!(
                !self.admission.closed.load(Ordering::Acquire),
                "journal admission is closed"
            );
            let journaled = self.admission.journaled_sequence.load(Ordering::Acquire);
            let distance = sequence
                .checked_sub(journaled)
                .ok_or_else(|| eyre!("execution sequence is behind J"))?;
            let reserved = {
                let mut state = self
                    .admission
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let reserved = distance <= MAX_UNJOURNALED_SEQUENCE_DISTANCE
                    && state.work < JOURNAL_WORK_ITEM_CAPACITY
                    && state.records < JOURNAL_RECORD_LIABILITY_CAPACITY
                    && state.bytes + EXECUTED_LIABILITY_BYTES <= JOURNAL_OUTSTANDING_BYTE_CAPACITY
                    && self.admission.retained_identities.load(Ordering::Acquire)
                        + (state.records as u64)
                        < JOURNAL_HARD_IDENTITY_LIMIT as u64;
                if reserved {
                    state.work += 1;
                    state.records += 1;
                    state.bytes += EXECUTED_LIABILITY_BYTES;
                }
                reserved
            };
            if reserved {
                return Ok(ExecutionReservation {
                    admission: self.admission.clone(),
                    bytes: EXECUTED_LIABILITY_BYTES,
                    retired: false,
                });
            }
            notified.await;
        }
    }

    pub fn enqueue_executed(
        &self,
        entry: MessageJournalEntry,
        reservation: ExecutionReservation,
    ) -> eyre::Result<()> {
        self.work
            .try_send(Work::Executed(entry, reservation))
            .map_err(|error| eyre!("reserved journal enqueue failed: {error}"))
    }

    pub fn drain(&self) -> eyre::Result<MessageJournalAnchor> {
        assert_authority_operation_allowed("journal-worker-acknowledgement-wait");
        let (send, receive) = crossbeam_channel::bounded(1);
        self.work
            .send(Work::Drain(send))
            .map_err(|_| eyre!("journal worker is stopped"))?;
        let watermark = receive
            .recv()
            .map_err(|_| eyre!("journal drain response dropped"))??;
        if let Some(error) = self
            .fatal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        {
            return Err(eyre!(error));
        }
        Ok(watermark)
    }

    pub fn drain_until(
        &self,
        deadline: tokio::time::Instant,
    ) -> eyre::Result<MessageJournalAnchor> {
        let (send, receive) = crossbeam_channel::bounded(1);
        self.work
            .send_timeout(Work::Drain(send), remaining_until(deadline)?)
            .map_err(|error| eyre!("journal drain enqueue missed deadline: {error}"))?;
        let watermark = receive
            .recv_timeout(remaining_until(deadline)?)
            .map_err(|error| eyre!("journal drain missed deadline: {error}"))??;
        if let Some(error) = self
            .fatal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        {
            return Err(eyre!(error));
        }
        Ok(watermark)
    }
}

fn remaining_until(deadline: tokio::time::Instant) -> eyre::Result<Duration> {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    ensure!(!remaining.is_zero(), "terminal deadline expired");
    Ok(remaining)
}

fn join_until(
    worker: JoinHandle<()>,
    deadline: tokio::time::Instant,
    name: &str,
) -> eyre::Result<()> {
    while !worker.is_finished() {
        std::thread::sleep(remaining_until(deadline)?.min(Duration::from_millis(1)));
    }
    worker.join().map_err(|_| eyre!("{name} panicked"))
}

pub struct JournalRuntime {
    pub client: JournalClient,
    pub(crate) persistence: PersistenceObserver,
    worker: Option<JoinHandle<()>>,
}

impl JournalRuntime {
    pub fn open(
        directory: JournalDirectory,
        context: StorageContextV3,
        initial_d: BlockNumHash,
    ) -> eyre::Result<Self> {
        let inspection = inspect_message_journal(&directory, context)?;
        ensure!(
            (
                inspection.watermark.block_number,
                inspection.watermark.block_hash
            ) == (initial_d.number, initial_d.hash),
            "journal J does not equal startup D"
        );
        let (work_send, work_receive) = crossbeam_channel::bounded(JOURNAL_WORK_ITEM_CAPACITY);
        let (control_send, control_receive) = crossbeam_channel::bounded(1);
        let (wake_send, wake_receive) = crossbeam_channel::bounded(1);
        let admission = Arc::new(Admission {
            state: Mutex::new(AdmissionState::default()),
            closed: AtomicBool::new(false),
            journaled_sequence: AtomicU64::new(inspection.watermark.sequence),
            retained_identities: AtomicU64::new(inspection.entries.len() as u64),
            notify: Notify::new(),
        });
        let persistence_state = Arc::new(Mutex::new(PersistenceState {
            frontier: initial_d,
            exact: BTreeMap::new(),
            fatal: None,
        }));
        let fatal = Arc::new(Mutex::new(None));
        let client = JournalClient {
            work: work_send,
            control: control_send,
            admission: admission.clone(),
            fatal: fatal.clone(),
        };
        let persistence = PersistenceObserver {
            state: persistence_state.clone(),
            wake: wake_send,
            admission: admission.clone(),
        };
        let worker = std::thread::Builder::new()
            .name("arb-journal-v3".into())
            .spawn(move || {
                run_worker(
                    directory,
                    context,
                    inspection,
                    work_receive,
                    control_receive,
                    wake_receive,
                    admission,
                    persistence_state,
                    fatal,
                )
            })?;
        Ok(Self {
            client,
            persistence,
            worker: Some(worker),
        })
    }

    fn stop(&mut self) -> eyre::Result<()> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        let (send, receive) = crossbeam_channel::bounded(1);
        if self.client.control.send(Control::Stop(send)).is_err() {
            worker
                .join()
                .map_err(|_| eyre!("journal worker panicked"))?;
            return Err(eyre!("journal worker stopped before shutdown"));
        }
        let result = receive
            .recv()
            .map_err(|_| eyre!("journal stop response dropped"));
        worker
            .join()
            .map_err(|_| eyre!("journal worker panicked"))?;
        result?
    }

    pub fn shutdown(mut self) -> eyre::Result<()> {
        self.stop()
    }

    pub fn shutdown_until(mut self, deadline: tokio::time::Instant) -> eyre::Result<()> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        let (send, receive) = crossbeam_channel::bounded(1);
        self.client
            .control
            .send_timeout(Control::Stop(send), remaining_until(deadline)?)
            .map_err(|error| eyre!("journal stop enqueue missed deadline: {error}"))?;
        let result = receive
            .recv_timeout(remaining_until(deadline)?)
            .map_err(|error| eyre!("journal stop missed deadline: {error}"));
        join_until(worker, deadline, "journal worker")?;
        result?
    }
}

fn set_fatal(
    admission: &Arc<Admission>,
    fatal: &Mutex<Option<String>>,
    message: impl Into<String>,
) {
    *fatal
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(message.into());
    admission.close();
}

#[derive(Debug)]
enum JournalIoFailure {
    Known(std::io::Error),
    AmbiguousAfterSuccess(std::io::Error),
}

fn journal_io_classified<T>(
    point: &str,
    operation: impl FnOnce() -> std::io::Result<T>,
) -> Result<T, JournalIoFailure> {
    let injected = journal_io_fault(point);
    if let Some(("before", errno)) = injected {
        return Err(JournalIoFailure::Known(std::io::Error::from_raw_os_error(
            errno,
        )));
    }
    let result = operation().map_err(JournalIoFailure::Known)?;
    if let Some(("after", errno)) = injected {
        return Err(JournalIoFailure::AmbiguousAfterSuccess(
            std::io::Error::from_raw_os_error(errno),
        ));
    }
    Ok(result)
}

fn journal_io_fault(point: &str) -> Option<(&'static str, i32)> {
    let configured = std::env::var("ARB_RETH_JOURNAL_IO_FAULT").ok()?;
    let (timing, errno) = {
        let value = configured.as_str();
        let mut fields = value.split(':');
        let configured_point = fields.next()?;
        let timing = fields.next()?;
        let errno = fields.next()?.parse::<i32>().ok()?;
        if fields.next().is_some() || configured_point != point {
            return None;
        }
        let timing = match timing {
            "before" => "before",
            "after" => "after",
            "short" => "short",
            _ => return None,
        };
        (timing, errno)
    };
    Some((timing, errno))
}

fn journal_write_all(point: &str, file: &mut File, bytes: &[u8]) -> Result<(), JournalIoFailure> {
    if let Some(("short", errno)) = journal_io_fault(point) {
        file.write_all(&bytes[..bytes.len() / 2])
            .map_err(JournalIoFailure::Known)?;
        return Err(JournalIoFailure::Known(std::io::Error::from_raw_os_error(
            errno,
        )));
    }
    journal_io_classified(point, || file.write_all(bytes))
}

fn journal_result<T>(point: &str, operation: impl FnOnce() -> eyre::Result<T>) -> eyre::Result<T> {
    if let Some(("before", errno)) = journal_io_fault(point) {
        return Err(std::io::Error::from_raw_os_error(errno).into());
    }
    let result = operation()?;
    if let Some(("after", errno)) = journal_io_fault(point) {
        return Err(std::io::Error::from_raw_os_error(errno).into());
    }
    Ok(result)
}

fn journal_crashpoint(point: &str) {
    if std::env::var_os("ARB_RETH_JOURNAL_CRASHPOINT").as_deref() == Some(OsStr::new(point)) {
        unsafe extern "C" {
            fn _exit(status: i32) -> !;
        }
        // SAFETY: this test seam intentionally simulates sudden process loss.
        unsafe { _exit(86) }
    }
}

fn rollback_known_append(file: &File, offset: u64, error: std::io::Error) -> eyre::Report {
    if let Err(rollback) = file.set_len(offset).and_then(|()| file.sync_data()) {
        return eyre!("known append failure {error}; fail-closed rollback failed: {rollback}");
    }
    error.into()
}

fn append_entry(
    directory: &JournalDirectory,
    context: StorageContextV3,
    inspection: &mut MessageJournalInspection,
    entry: MessageJournalEntry,
) -> eyre::Result<()> {
    ensure!(
        inspection.entries.len() < JOURNAL_HARD_IDENTITY_LIMIT,
        "journal identity hard limit reached"
    );
    validate_identity_chain(inspection.watermark, &[entry], context.l2_genesis_number)?;
    let generation = inspection
        .last_operation_generation
        .checked_add(1)
        .ok_or_else(|| eyre!("operation generation wrap"))?;
    let frame = encode_frame(
        FrameKind::Executed,
        generation,
        inspection.last_commit_digest,
        &encode_identity(entry),
    )?;
    ensure!(
        inspection
            .complete_byte_offset
            .checked_add(frame.len() as u64)
            .is_some_and(|length| length <= JOURNAL_HARD_FILE_LIMIT),
        "journal selected-file hard limit reached"
    );
    let name = inspection
        .path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| eyre!("selected journal has no fixed name"))?;
    let mut file = directory.open_existing(name, true, true)?;
    let offset = file.metadata()?.len();
    journal_crashpoint("append_before_write");
    let mut ambiguous = None;
    match journal_write_all("append_write", &mut file, &frame) {
        Ok(()) => {}
        Err(JournalIoFailure::Known(error)) => {
            return Err(rollback_known_append(&file, offset, error));
        }
        Err(JournalIoFailure::AmbiguousAfterSuccess(error)) => ambiguous = Some(error),
    }
    journal_crashpoint("append_after_write");
    journal_crashpoint("append_before_flush");
    match journal_io_classified("append_flush", || file.flush()) {
        Ok(()) => {}
        Err(JournalIoFailure::Known(error)) => {
            return Err(rollback_known_append(&file, offset, error));
        }
        Err(JournalIoFailure::AmbiguousAfterSuccess(error)) => {
            ambiguous.get_or_insert(error);
        }
    }
    journal_crashpoint("append_after_flush");
    journal_crashpoint("append_before_sync");
    match journal_io_classified("append_sync", || file.sync_data()) {
        Ok(()) => {}
        Err(JournalIoFailure::Known(error)) => {
            return Err(rollback_known_append(&file, offset, error));
        }
        Err(JournalIoFailure::AmbiguousAfterSuccess(error)) => {
            ambiguous.get_or_insert(error);
        }
    }
    journal_crashpoint("append_after_sync");
    let mut reread = vec![0u8; frame.len()];
    file.seek(SeekFrom::Start(offset))?;
    journal_crashpoint("append_before_reread");
    let reread_ambiguous =
        match journal_io_classified("append_reread", || file.read_exact(&mut reread)) {
            Ok(()) => false,
            Err(JournalIoFailure::Known(error)) => {
                return Err(rollback_known_append(&file, offset, error));
            }
            Err(JournalIoFailure::AmbiguousAfterSuccess(error)) => {
                ambiguous.get_or_insert(error);
                true
            }
        };
    if reread_ambiguous {
        reread.fill(0);
    }
    journal_crashpoint("append_after_reread");
    if reread != frame {
        // A reread syscall can itself report failure after filling the buffer. Reopen through the
        // pinned directory and classify the exact on-disk bytes before deciding authority.
        let mut reopened = directory.open_existing(name, false, false)?;
        reopened.seek(SeekFrom::Start(offset))?;
        if let Err(error) = reopened.read_exact(&mut reread) {
            return Err(ambiguous
                .map(eyre::Report::new)
                .unwrap_or_else(|| eyre::Report::new(error)));
        }
        if reread != frame {
            return Err(ambiguous
                .map(eyre::Report::new)
                .unwrap_or_else(|| eyre!("journal append reread mismatch")));
        }
    }
    let decoded = decode_complete_frame(&reread)?;
    ensure!(
        decoded.operation_generation == generation
            && decoded.previous_commit_digest == inspection.last_commit_digest,
        "journal append authority changed on reread"
    );
    // A complete valid frame wins after an ambiguous syscall failure.
    drop(ambiguous);
    journal_crashpoint("append_before_ack");
    inspection.entries.push(entry);
    inspection.watermark = MessageJournalAnchor {
        sequence: entry.sequence,
        block_number: entry.block_number,
        block_hash: entry.block_hash,
    };
    inspection.last_operation_generation = generation;
    inspection.last_commit_digest = decoded.commit_digest;
    inspection.complete_byte_offset = offset + frame.len() as u64;
    inspection.file_root = B256::ZERO;
    Ok(())
}

fn snapshot_state_for_compaction(
    inspection: &mut MessageJournalInspection,
) -> eyre::Result<SnapshotState> {
    let mut state = inspection.state.clone();
    state.kind = SnapshotStateKind::Ordinary;
    state.entries = std::mem::take(&mut inspection.entries);
    state.v = inspection.v;
    state.authority_operation_count = inspection.authority_operation_count;
    state.latest_authority_id = inspection.latest_authority_id;
    state.latest_authority_chain_digest = inspection.latest_authority_chain_digest;
    state.predecessor_final_commit_digest = inspection.last_commit_digest;
    state.grid = inspection.retained_grid.clone();
    state.source_v = None;
    state.source_j = 0;
    state.source_latest_authority_id = B256::ZERO;
    state.truncation_target_authority_id = B256::ZERO;
    state.truncation_plan_digest = B256::ZERO;
    state.removed_identity_count = 0;
    state.removed_identities_digest = B256::ZERO;
    state.source_authority_chain_digest = B256::ZERO;
    state.source_authority_operation_count = 0;
    retain_ordinary_grid(&mut state)?;
    Ok(state)
}

struct SnapshotLineageWriter<'a> {
    file: &'a mut File,
    short_remaining: Option<(usize, i32)>,
}

impl SnapshotLineageWriter<'_> {
    fn write_chunk(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let Some((remaining, errno)) = self.short_remaining else {
            return self.file.write_all(bytes);
        };
        let count = remaining.min(bytes.len());
        self.file.write_all(&bytes[..count])?;
        self.short_remaining = Some((remaining - count, errno));
        if count != bytes.len() || remaining == count {
            return Err(std::io::Error::from_raw_os_error(errno));
        }
        Ok(())
    }
}

fn write_snapshot_lineage(
    file: &mut File,
    header: JournalHeader,
    kind: FrameKind,
    operation_generation: u64,
    previous_commit_digest: B256,
    state: &SnapshotState,
    short: Option<(usize, i32)>,
) -> std::io::Result<()> {
    let payload_len = snapshot_payload_len(state).map_err(std::io::Error::other)?;
    let prefix = encode_snapshot_prefix(header.anchor, state).map_err(std::io::Error::other)?;
    let prelude = encode_frame_prelude(
        kind,
        operation_generation,
        previous_commit_digest,
        payload_len,
    )
    .map_err(std::io::Error::other)?;
    let mut writer = SnapshotLineageWriter {
        file,
        short_remaining: short,
    };
    writer.write_chunk(&encode_header(header))?;
    writer.write_chunk(&prelude)?;
    let mut commit = framed_hasher(DOMAIN_FRAME_COMMIT, 104 + payload_len);
    commit.update(prelude);
    writer.write_chunk(&prefix)?;
    commit.update(prefix);
    for entry in &state.entries {
        let bytes = encode_identity(*entry);
        writer.write_chunk(&bytes)?;
        commit.update(bytes);
    }
    if let Some(bootstrap) = state.bootstrap {
        let bytes = encode_authority_record(bootstrap);
        writer.write_chunk(&bytes)?;
        commit.update(bytes);
    }
    for record in &state.grid {
        let bytes = encode_grid_record(*record);
        writer.write_chunk(&bytes)?;
        commit.update(bytes);
    }
    let commit_magic = COMMIT_MAGIC.to_be_bytes();
    writer.write_chunk(&commit_magic)?;
    commit.update(commit_magic);
    writer.write_chunk(&commit.finalize())
}

fn discard_known_temp(
    directory: &JournalDirectory,
    temp_name: &str,
    file: File,
    error: std::io::Error,
) -> eyre::Report {
    let invalidate = file.set_len(0).and_then(|()| file.sync_all());
    drop(file);
    if let Err(cleanup) = invalidate {
        return eyre!("known temp failure {error}; invalidation failed: {cleanup}");
    }
    if let Err(cleanup) = directory.remove_entry(temp_name) {
        return eyre!("known temp failure {error}; removal failed: {cleanup:#}");
    }
    error.into()
}

#[allow(clippy::too_many_arguments)]
fn write_lineage_temp(
    directory: &JournalDirectory,
    temp_name: &str,
    header: JournalHeader,
    kind: FrameKind,
    operation_generation: u64,
    previous_commit_digest: B256,
    state: &SnapshotState,
    operation: &str,
) -> eyre::Result<()> {
    let payload_len = snapshot_payload_len(state)?;
    let total_len = HEADER_LEN
        .checked_add(FRAME_STORAGE_OVERHEAD)
        .and_then(|length| payload_len.checked_add(length))
        .ok_or_else(|| eyre!("snapshot lineage length overflow"))?;
    ensure!(
        total_len <= EXACT_MAX_COMPACT_FILE,
        "compacted file exceeds frozen maximum"
    );
    let mut file = directory.create_new(temp_name, false)?;
    journal_crashpoint(&format!("{operation}_before_temp_write"));
    let write_point = format!("{operation}_write");
    let write_fault = journal_io_fault(&write_point);
    if let Some(("before", errno)) = write_fault {
        return Err(discard_known_temp(
            directory,
            temp_name,
            file,
            std::io::Error::from_raw_os_error(errno),
        ));
    }
    let short = write_fault
        .and_then(|(timing, errno)| (timing == "short").then_some((total_len / 2, errno)));
    let mut ambiguous = None;
    match write_snapshot_lineage(
        &mut file,
        header,
        kind,
        operation_generation,
        previous_commit_digest,
        state,
        short,
    ) {
        Ok(()) if matches!(write_fault, Some(("short", _))) => {
            return Err(eyre!("short lineage write unexpectedly completed"));
        }
        Ok(()) if let Some(("after", errno)) = write_fault => {
            ambiguous = Some(std::io::Error::from_raw_os_error(errno));
        }
        Ok(()) => {}
        Err(error) => return Err(discard_known_temp(directory, temp_name, file, error)),
    }
    journal_crashpoint(&format!("{operation}_after_temp_write"));
    journal_crashpoint(&format!("{operation}_before_temp_flush"));
    match journal_io_classified(&format!("{operation}_flush"), || file.flush()) {
        Ok(()) => {}
        Err(JournalIoFailure::Known(error)) => {
            return Err(discard_known_temp(directory, temp_name, file, error));
        }
        Err(JournalIoFailure::AmbiguousAfterSuccess(error)) => {
            ambiguous.get_or_insert(error);
        }
    }
    journal_crashpoint(&format!("{operation}_after_temp_flush"));
    journal_crashpoint(&format!("{operation}_before_temp_sync"));
    match journal_io_classified(&format!("{operation}_sync"), || file.sync_all()) {
        Ok(()) => {}
        Err(JournalIoFailure::Known(error)) => {
            return Err(discard_known_temp(directory, temp_name, file, error));
        }
        Err(JournalIoFailure::AmbiguousAfterSuccess(error)) => {
            ambiguous.get_or_insert(error);
        }
    }
    journal_crashpoint(&format!("{operation}_after_temp_sync"));
    drop(file);
    // The caller immediately streams and validates the complete temp. A complete valid temp wins
    // after an ambiguous syscall error; an incomplete or invalid temp returns that structural
    // failure instead of being treated as absent.
    let _ = ambiguous;
    Ok(())
}

fn compact_lineage(
    directory: &JournalDirectory,
    context: StorageContextV3,
    inspection: &mut MessageJournalInspection,
    policy: AuthorityPolicy<'_>,
) -> eyre::Result<()> {
    ensure!(
        !inspection.has_authenticated_short_tail,
        "cannot compact a short tail"
    );
    let old_generation = inspection.header.lineage_generation;
    let next_generation = old_generation
        .checked_add(1)
        .ok_or_else(|| eyre!("lineage generation wrap"))?;
    let old_name = inspection
        .path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| eyre!("selected journal has no fixed name"))?
        .to_owned();
    let predecessor_root =
        hash_complete_file(directory, &old_name, inspection.complete_byte_offset)?;
    inspection.file_root = predecessor_root;
    let mut snapshot = snapshot_state_for_compaction(inspection)?;
    let header = JournalHeader {
        lineage_generation: next_generation,
        snapshot_through_operation_generation: inspection.last_operation_generation,
        predecessor_file_root: predecessor_root,
        anchor: context.anchor,
        storage_context_digest: context.digest(),
    };
    let temp_name = exact_journal_name(next_generation, "tmp");
    let final_name = exact_journal_name(next_generation, "log");
    ensure!(
        !directory.entry_exists(&temp_name)? && !directory.entry_exists(&final_name)?,
        "next lineage artifact already exists"
    );
    journal_crashpoint("compaction_before_seal");
    let write_result = write_lineage_temp(
        directory,
        &temp_name,
        header,
        FrameKind::Snapshot,
        inspection.last_operation_generation,
        inspection.last_commit_digest,
        &snapshot,
        "compaction",
    );
    if let Err(error) = write_result {
        inspection.entries = std::mem::take(&mut snapshot.entries);
        return Err(error);
    }
    drop(snapshot);
    journal_crashpoint("compaction_before_temp_reread");
    let candidate = journal_result("compaction_validate", || {
        let candidate = inspect_file(directory, &temp_name, context, policy)?;
        validate_streamed_predecessor(directory, &old_name, context, policy, &candidate)?;
        Ok(candidate)
    })?;
    journal_crashpoint("compaction_after_temp_reread");
    drop(candidate);
    journal_crashpoint("compaction_before_rename");
    journal_result("compaction_rename", || {
        directory.rename_noreplace(&temp_name, &final_name)
    })?;
    journal_crashpoint("compaction_after_rename");
    journal_crashpoint("compaction_before_parent_sync");
    journal_result("compaction_parent_sync", || directory.sync_parent())?;
    journal_crashpoint("compaction_after_parent_sync");
    journal_crashpoint("compaction_before_selection");
    let selected = journal_result("compaction_select", || {
        let selected = inspect_file(directory, &final_name, context, policy)?;
        validate_streamed_predecessor(directory, &old_name, context, policy, &selected)?;
        Ok(selected)
    })?;
    journal_crashpoint("compaction_after_selection");
    *inspection = selected;
    journal_crashpoint("compaction_after_append_switch");
    journal_crashpoint("compaction_before_cleanup");
    for generation in 0..old_generation {
        let name = exact_journal_name(generation, "log");
        if directory.entry_exists(&name).unwrap_or(false)
            && let Err(error) = directory.remove_entry(&name)
        {
            tracing::warn!(target: "arb-reth::journal", %error, "old lineage cleanup deferred");
            break;
        }
    }
    journal_crashpoint("compaction_after_cleanup");
    Ok(())
}

fn compaction_due(inspection: &MessageJournalInspection) -> bool {
    let retained = inspection.entries.len();
    (retained >= JOURNAL_COMPACT_MIN_IDENTITIES
        && (retained - JOURNAL_COMPACT_MIN_IDENTITIES)
            .is_multiple_of(JOURNAL_COMPACT_DELTA_TRIGGER))
        || inspection
            .authority_operation_count
            .saturating_sub(inspection.compacted_authority_operation_count)
            >= JOURNAL_AUTHORITY_COMPACT_TRIGGER
        || inspection.complete_byte_offset >= JOURNAL_COMPACT_FILE_TRIGGER
        || force_compaction_for_test()
}

#[cfg(test)]
fn force_compaction_for_test() -> bool {
    std::env::var_os("ARB_RETH_JOURNAL_FORCE_COMPACTION").is_some()
}

#[cfg(not(test))]
const fn force_compaction_for_test() -> bool {
    false
}

struct PendingMaintenance {
    charged_bytes: usize,
    deadline: Instant,
}

fn try_pending_compaction(
    directory: &JournalDirectory,
    context: StorageContextV3,
    inspection: &mut MessageJournalInspection,
    admission: &Arc<Admission>,
    maintenance: &mut Option<PendingMaintenance>,
) -> eyre::Result<()> {
    let Some(pending) = maintenance.as_ref() else {
        return Ok(());
    };
    if let Some(reservation) = admission.try_reserve_maintenance(pending.charged_bytes) {
        compact_lineage(directory, context, inspection, PRODUCTION_POLICY)?;
        drop(reservation);
        *maintenance = None;
    } else {
        ensure!(
            Instant::now() < pending.deadline,
            "journal maintenance unavailable for 30 seconds"
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn process_pending(
    directory: &JournalDirectory,
    context: StorageContextV3,
    inspection: &mut MessageJournalInspection,
    pending: &mut VecDeque<(MessageJournalEntry, ExecutionReservation)>,
    persistence: &Mutex<PersistenceState>,
    admission: &Arc<Admission>,
    maintenance: &mut Option<PendingMaintenance>,
) -> eyre::Result<()> {
    try_pending_compaction(directory, context, inspection, admission, maintenance)?;
    while let Some((entry, _)) = pending.front() {
        let mut state = persistence
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(error) = &state.fatal {
            return Err(eyre!(error.clone()));
        }
        let Some(hash) = state.exact.remove(&entry.block_number) else {
            break;
        };
        ensure!(
            hash == entry.block_hash,
            "persisted hash does not match queued identity"
        );
        drop(state);
        let (entry, reservation) = pending.pop_front().expect("checked");
        append_entry(directory, context, inspection, entry)?;
        admission
            .journaled_sequence
            .store(entry.sequence, Ordering::Release);
        journal_crashpoint("append_after_ack");
        let retained = admission.retained_identities.fetch_add(1, Ordering::AcqRel) + 1;
        drop(reservation);
        if compaction_due(inspection) {
            ensure!(
                maintenance.is_none(),
                "compaction due while maintenance pending"
            );
            let compacted_len = HEADER_LEN
                + FRAME_STORAGE_OVERHEAD
                + SNAPSHOT_PREFIX_LEN
                + inspection.entries.len() * IDENTITY_LEN
                + usize::from(inspection.state.bootstrap.is_some()) * AUTHORITY_RECORD_LEN
                + inspection.retained_grid.len() * GRID_RECORD_LEN;
            let charged = compacted_len
                .checked_mul(2)
                .and_then(|bytes| bytes.checked_add(JOURNAL_STREAM_SCRATCH))
                .ok_or_else(|| eyre!("maintenance charge overflow"))?;
            *maintenance = Some(PendingMaintenance {
                charged_bytes: charged,
                deadline: Instant::now() + MAINTENANCE_MAX_WAIT,
            });
        }
        try_pending_compaction(directory, context, inspection, admission, maintenance)?;
        if retained as usize == JOURNAL_HARD_IDENTITY_LIMIT {
            admission.close();
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_worker(
    directory: JournalDirectory,
    context: StorageContextV3,
    mut inspection: MessageJournalInspection,
    work_receive: crossbeam_channel::Receiver<Work>,
    control_receive: crossbeam_channel::Receiver<Control>,
    wake_receive: crossbeam_channel::Receiver<()>,
    admission: Arc<Admission>,
    persistence: Arc<Mutex<PersistenceState>>,
    fatal: Arc<Mutex<Option<String>>>,
) {
    let mut pending = VecDeque::new();
    let mut maintenance = None;
    loop {
        let timer = maintenance
            .as_ref()
            .map(|pending: &PendingMaintenance| {
                crossbeam_channel::after(pending.deadline.saturating_duration_since(Instant::now()))
            })
            .unwrap_or_else(crossbeam_channel::never);
        crossbeam_channel::select! {
            recv(timer) -> _ => {
                if let Err(error) = try_pending_compaction(
                    &directory, context, &mut inspection, &admission, &mut maintenance,
                ) {
                    set_fatal(&admission, &fatal, format!("{error:#}"));
                }
            }
            recv(wake_receive) -> _ => {
                if let Err(error) = process_pending(
                    &directory, context, &mut inspection, &mut pending, &persistence,
                    &admission, &mut maintenance,
                ) {
                    set_fatal(&admission, &fatal, format!("{error:#}"));
                }
            }
            recv(control_receive) -> control => match control {
                Ok(Control::Stop(response)) => {
                    let result = process_pending(
                        &directory, context, &mut inspection, &mut pending, &persistence,
                        &admission, &mut maintenance,
                    ).and_then(|()| {
                        ensure!(pending.is_empty(), "journal stop has pending identities");
                        ensure!(maintenance.is_none(), "journal stop has pending maintenance");
                        Ok(())
                    });
                    admission.close();
                    let _ = response.send(result);
                    break;
                }
                Err(_) => break,
            },
            recv(work_receive) -> work => match work {
                Ok(Work::Executed(entry, reservation)) => {
                    if admission.closed.load(Ordering::Acquire) {
                        drop(reservation);
                        continue;
                    }
                    pending.push_back((entry, reservation));
                    if let Err(error) = process_pending(
                        &directory, context, &mut inspection, &mut pending, &persistence,
                        &admission, &mut maintenance,
                    ) {
                        set_fatal(&admission, &fatal, format!("{error:#}"));
                    }
                }
                Ok(Work::Drain(response)) => {
                    let result = process_pending(
                        &directory, context, &mut inspection, &mut pending, &persistence,
                        &admission, &mut maintenance,
                    ).and_then(|()| {
                        ensure!(pending.is_empty(), "journal drain has identities not covered by D");
                        ensure!(maintenance.is_none(), "journal drain has pending maintenance");
                        Ok(inspection.watermark)
                    });
                    let _ = response.send(result);
                }
                Err(_) => break,
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryTargetV3 {
    Bootstrap { authority_id: B256 },
    Grid { authority_id: B256 },
}

pub fn create_recovery_truncation_lineage(
    directory: &JournalDirectory,
    context: StorageContextV3,
    selected_source_root: B256,
    target: RecoveryTargetV3,
    truncation_plan_digest: B256,
) -> eyre::Result<MessageJournalInspection> {
    create_recovery_truncation_with_policy(
        directory,
        context,
        selected_source_root,
        target,
        truncation_plan_digest,
        PRODUCTION_POLICY,
    )
}

fn create_recovery_truncation_with_policy(
    directory: &JournalDirectory,
    context: StorageContextV3,
    selected_source_root: B256,
    target: RecoveryTargetV3,
    truncation_plan_digest: B256,
    policy: AuthorityPolicy<'_>,
) -> eyre::Result<MessageJournalInspection> {
    ensure!(
        truncation_plan_digest != B256::ZERO,
        "zero truncation plan digest"
    );
    let (mut source, repair_required) = inspect_stopped_with_policy(directory, context, policy)?;
    ensure!(!repair_required, "recovery source has temp or short tail");
    ensure!(
        !source.recovery_truncation,
        "recovery source is already a truncation lineage"
    );
    ensure!(
        source.file_root == selected_source_root,
        "selected recovery source root mismatch"
    );
    let bootstrap = source
        .state
        .bootstrap
        .ok_or_else(|| eyre!("recovery source has no bootstrap authority"))?;
    let (target_anchor, target_id, target_chain, target_count, retained_grid) = match target {
        RecoveryTargetV3::Bootstrap { authority_id } => {
            ensure!(
                authority_id == bootstrap.authority_id,
                "bootstrap recovery target is stale"
            );
            (
                context.anchor,
                bootstrap.authority_id,
                authority_chain_digest(bootstrap),
                1,
                Vec::new(),
            )
        }
        RecoveryTargetV3::Grid { authority_id } => {
            let record = source
                .retained_grid
                .iter()
                .find(|record| record.authority.authority_id == authority_id)
                .copied()
                .ok_or_else(|| eyre!("grid recovery target is not retained"))?;
            let target_anchor = source
                .identity(record.authority.end_sequence)
                .ok_or_else(|| eyre!("grid recovery target identity is absent"))?;
            let retained_grid = source
                .retained_grid
                .iter()
                .copied()
                .filter(|candidate| candidate.authority.end_sequence <= target_anchor.sequence)
                .collect();
            (
                target_anchor,
                record.authority.authority_id,
                authority_chain_digest(record.authority),
                record.authority.authority_chain_position,
                retained_grid,
            )
        }
    };
    ensure!(
        source
            .v
            .is_some_and(|v| target_anchor.sequence <= v.sequence),
        "recovery target is above V"
    );
    ensure!(
        target_anchor.sequence < source.watermark.sequence,
        "recovery target is not below J"
    );
    let keep_count = usize::try_from(
        target_anchor
            .sequence
            .checked_sub(context.anchor.sequence)
            .ok_or_else(|| eyre!("recovery target precedes anchor"))?,
    )?;
    ensure!(
        keep_count <= source.entries.len(),
        "recovery target identity count overflow"
    );
    let removed_identity_count = source.entries.len() - keep_count;
    let removed_identities_digest = removed_identities_digest(&source.entries[keep_count..]);
    source.entries.truncate(keep_count);
    let state = SnapshotState {
        kind: SnapshotStateKind::RecoveryTruncation,
        entries: std::mem::take(&mut source.entries),
        bootstrap: Some(bootstrap),
        v: Some(target_anchor),
        authority_operation_count: target_count,
        latest_authority_id: target_id,
        latest_authority_chain_digest: target_chain,
        predecessor_final_commit_digest: source.last_commit_digest,
        grid: retained_grid,
        source_v: source.v.map(|v| v.sequence),
        source_j: source.watermark.sequence,
        source_latest_authority_id: source.latest_authority_id,
        truncation_target_authority_id: target_id,
        truncation_plan_digest,
        removed_identity_count: removed_identity_count as u64,
        removed_identities_digest,
        source_authority_chain_digest: source.latest_authority_chain_digest,
        source_authority_operation_count: source.authority_operation_count,
    };
    let next_generation = source
        .header
        .lineage_generation
        .checked_add(1)
        .ok_or_else(|| eyre!("lineage generation wrap"))?;
    let next_operation = source
        .last_operation_generation
        .checked_add(1)
        .ok_or_else(|| eyre!("operation generation wrap"))?;
    let header = JournalHeader {
        lineage_generation: next_generation,
        snapshot_through_operation_generation: next_operation,
        predecessor_file_root: source.file_root,
        anchor: context.anchor,
        storage_context_digest: context.digest(),
    };
    let temp_name = exact_journal_name(next_generation, "tmp");
    let final_name = exact_journal_name(next_generation, "log");
    ensure!(
        !directory.entry_exists(&temp_name)? && !directory.entry_exists(&final_name)?,
        "recovery target lineage exists"
    );
    journal_crashpoint("truncation_before_seal");
    let write_result = write_lineage_temp(
        directory,
        &temp_name,
        header,
        FrameKind::RecoveryTruncationSnapshot,
        next_operation,
        source.last_commit_digest,
        &state,
        "truncation",
    );
    write_result?;
    drop(state);
    let source_name = source
        .path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| eyre!("selected source has no fixed name"))?;
    journal_crashpoint("truncation_before_temp_reread");
    let candidate = journal_result("truncation_validate", || {
        let candidate = inspect_file(directory, &temp_name, context, policy)?;
        validate_streamed_predecessor(directory, source_name, context, policy, &candidate)?;
        Ok(candidate)
    })?;
    journal_crashpoint("truncation_after_temp_reread");
    ensure!(
        candidate.watermark == target_anchor && candidate.v == Some(target_anchor),
        "recovery candidate target mismatch"
    );
    drop(candidate);
    journal_crashpoint("truncation_before_rename");
    journal_result("truncation_rename", || {
        directory.rename_noreplace(&temp_name, &final_name)
    })?;
    journal_crashpoint("truncation_after_rename");
    journal_crashpoint("truncation_before_parent_sync");
    journal_result("truncation_parent_sync", || directory.sync_parent())?;
    journal_crashpoint("truncation_after_parent_sync");
    journal_crashpoint("truncation_before_selection");
    let selected = journal_result("truncation_select", || {
        let selected = inspect_file(directory, &final_name, context, policy)?;
        validate_streamed_predecessor(directory, source_name, context, policy, &selected)?;
        Ok(selected)
    })?;
    journal_crashpoint("truncation_after_selection");
    ensure!(
        directory.entry_exists(
            source
                .path
                .file_name()
                .and_then(OsStr::to_str)
                .expect("selected source has fixed name")
        )?,
        "recovery changed or removed source lineage"
    );
    Ok(selected)
}

/// Checkout-local benchmark adapter over the complete production execution-journal path.
#[doc(hidden)]
pub struct JournalBenchmarkAdapter {
    runtime: Option<JournalRuntime>,
    pressure: Vec<ExecutionReservation>,
    maximum_pressure: bool,
    first_sequence: u64,
}

fn benchmark_context() -> StorageContextV3 {
    StorageContextV3 {
        l2_chain_id: 1,
        l2_genesis_number: 0,
        l2_genesis_hash: B256::repeat_byte(0x11),
        sequencer_inbox: Address::repeat_byte(0x22),
        bridge: Address::repeat_byte(0x33),
        deployment_block: 1,
        anchor: MessageJournalAnchor {
            sequence: 0,
            block_number: 0,
            block_hash: B256::ZERO,
        },
    }
}

impl JournalBenchmarkAdapter {
    pub async fn new(maximum_pressure: bool, directory: JournalDirectory) -> eyre::Result<Self> {
        let context = benchmark_context();
        initialize_journal_v3(&directory, context)?;
        let runtime = JournalRuntime::open(
            directory,
            context,
            BlockNumHash {
                number: 0,
                hash: B256::ZERO,
            },
        )?;
        let mut adapter = Self {
            runtime: Some(runtime),
            pressure: Vec::new(),
            maximum_pressure,
            first_sequence: 1,
        };
        adapter.rebalance_pressure(1).await?;
        Ok(adapter)
    }

    pub const fn first_sequence(&self) -> u64 {
        self.first_sequence
    }

    pub async fn reserve_and_enqueue(&self, entry: MessageJournalEntry) -> eyre::Result<()> {
        let client = &self.runtime.as_ref().expect("benchmark runtime").client;
        let reservation = client.reserve_execution(entry.sequence).await?;
        client.enqueue_executed(entry, reservation)
    }

    pub async fn persist_and_drain(&mut self, entry: MessageJournalEntry) -> eyre::Result<()> {
        let runtime = self.runtime.as_ref().expect("benchmark runtime");
        let next_retained = runtime
            .client
            .admission
            .retained_identities
            .load(Ordering::Acquire)
            .checked_add(1)
            .ok_or_else(|| eyre!("benchmark retained identity overflow"))?;
        if next_retained as usize >= JOURNAL_COMPACT_MIN_IDENTITIES
            && (next_retained as usize - JOURNAL_COMPACT_MIN_IDENTITIES)
                .is_multiple_of(JOURNAL_COMPACT_DELTA_TRIGGER)
        {
            self.pressure.pop();
        }
        let identity = BlockNumHash {
            number: entry.block_number,
            hash: entry.block_hash,
        };
        runtime.persistence.saved(&[identity], identity);
        let journaled = runtime.client.drain()?;
        ensure!(
            journaled.sequence == entry.sequence
                && journaled.block_number == entry.block_number
                && journaled.block_hash == entry.block_hash,
            "benchmark worker did not publish exact persisted identity"
        );
        self.rebalance_pressure(entry.sequence + 1).await
    }

    async fn rebalance_pressure(&mut self, next_sequence: u64) -> eyre::Result<()> {
        let desired = if self.maximum_pressure {
            let retained = self
                .runtime
                .as_ref()
                .expect("benchmark runtime")
                .client
                .admission
                .retained_identities
                .load(Ordering::Acquire);
            let identity_room = (JOURNAL_HARD_IDENTITY_LIMIT as u64)
                .saturating_sub(retained)
                .saturating_sub(1);
            (JOURNAL_WORK_ITEM_CAPACITY - PROTECTED_EXECUTION_WORK_FLOOR)
                .min(usize::try_from(identity_room)?)
        } else {
            0
        };
        self.pressure.truncate(desired);
        while self.pressure.len() < desired {
            let reservation = self
                .runtime
                .as_ref()
                .expect("benchmark runtime")
                .client
                .reserve_execution(next_sequence)
                .await?;
            self.pressure.push(reservation);
        }
        Ok(())
    }
}

impl Drop for JournalBenchmarkAdapter {
    fn drop(&mut self) {
        self.pressure.clear();
        if let Some(runtime) = self.runtime.take()
            && let Err(error) = runtime.shutdown()
        {
            tracing::error!(target: "arb-reth::journal", %error, "benchmark journal shutdown failed");
        }
    }
}

pub fn validate_runtime_capacity(
    memory_block_buffer_target: u64,
    persistence_threshold: u64,
    persistence_backpressure_threshold: u64,
) -> eyre::Result<()> {
    ensure!(
        memory_block_buffer_target <= persistence_threshold,
        "memory buffer exceeds persistence threshold"
    );
    ensure!(
        persistence_threshold <= MAX_SUPPORTED_PERSISTENCE_THRESHOLD,
        "persistence threshold exceeds 512"
    );
    ensure!(
        persistence_threshold < persistence_backpressure_threshold,
        "backpressure must exceed threshold"
    );
    ensure!(
        persistence_backpressure_threshold <= JOURNAL_WORK_ITEM_CAPACITY as u64,
        "backpressure exceeds work capacity"
    );
    ensure!(
        JOURNAL_WORK_ITEM_CAPACITY as u64 > persistence_threshold,
        "work capacity cannot cross persistence threshold"
    );
    ensure!(
        JOURNAL_RECORD_LIABILITY_CAPACITY as u64 > persistence_threshold,
        "record capacity cannot cross persistence threshold"
    );
    ensure!(
        MAX_PAYLOAD_LEN == EXACT_MAX_COMPACT_PAYLOAD,
        "maximum compact payload equation changed"
    );
    ensure!(
        MAX_COMPACTED_FILE_LEN == EXACT_MAX_COMPACT_FILE,
        "maximum compact file equation changed"
    );
    let compact_pair = EXACT_MAX_COMPACT_FILE * 2;
    let authority_pair = MAX_AUTHORITY_FRAME_LEN * 2;
    let execution_pairs = 1_022 * EXECUTED_LIABILITY_BYTES;
    let total = compact_pair + authority_pair + execution_pairs + JOURNAL_STREAM_SCRATCH;
    ensure!(
        total == EXACT_MAX_ENCODED_LIABILITY,
        "encoded-liability equation changed"
    );
    ensure!(
        JOURNAL_OUTSTANDING_BYTE_CAPACITY - total == EXACT_LIABILITY_HEADROOM,
        "liability headroom changed"
    );
    ensure!(
        1_022 + 1 + MAINTENANCE_WORK_ITEMS == JOURNAL_WORK_ITEM_CAPACITY,
        "work proof changed"
    );
    ensure!(
        1_022 + AUTHORITY_MAX_RECORDS <= JOURNAL_RECORD_LIABILITY_CAPACITY,
        "record proof changed"
    );
    ensure!(
        PROTECTED_EXECUTION_WORK_FLOOR == 1 && PROTECTED_EXECUTION_RECORD_FLOOR == 1,
        "execution floors changed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use std::process::{Command, ExitStatus, Stdio};

    fn context() -> StorageContextV3 {
        StorageContextV3 {
            l2_chain_id: 42_161,
            l2_genesis_number: 90,
            l2_genesis_hash: B256::repeat_byte(0x10),
            sequencer_inbox: Address::repeat_byte(0x20),
            bridge: Address::repeat_byte(0x30),
            deployment_block: 40,
            anchor: MessageJournalAnchor {
                sequence: 10,
                block_number: 100,
                block_hash: B256::repeat_byte(0x40),
            },
        }
    }

    fn canonical_context() -> CanonicalContextV1 {
        CanonicalContextV1 {
            context_id: 7,
            l1_chain_id: 1,
            l1_genesis_hash: B256::repeat_byte(0x50),
            l2_chain_id: context().l2_chain_id,
            l2_genesis_number: context().l2_genesis_number,
            l2_genesis_hash: context().l2_genesis_hash,
            sequencer_inbox: context().sequencer_inbox,
            bridge: context().bridge,
            deployment_block: context().deployment_block,
            beacon_genesis_validators_root: B256::repeat_byte(0x60),
            beacon_genesis_time: 1_606_824_023,
            seconds_per_slot: 12,
            slots_per_epoch: 32,
            fork_schedule: vec![(0, [0, 0, 0, 1]), (100, [0, 0, 0, 2])],
            kzg_trusted_setup_digest: B256::repeat_byte(0x70),
        }
    }

    fn evidence_digest(seed: u8) -> B256 {
        let mut payload = vec![0, 1];
        payload.extend_from_slice(&[seed; 32]);
        domain_hash(DOMAIN_EVIDENCE, &payload)
    }

    fn locator(terminal: MessageJournalAnchor, delayed: u64) -> EvidenceLocatorV1 {
        EvidenceLocatorV1 {
            context_id: canonical_context().context_id,
            context_digest: canonical_context().digest().unwrap(),
            safe_l1_number: 1_000,
            safe_l1_hash: B256::repeat_byte(0x81),
            containing_l1_number: 999,
            containing_l1_hash: B256::repeat_byte(0x82),
            posting_transaction_hash: B256::repeat_byte(0x83),
            posting_transaction_index: 4,
            delivery_log_index: 5,
            batch_sequence: 6,
            terminal_message_ordinal: 7,
            decoded_message_count: 8,
            terminal_delayed_count: delayed,
            terminal_sequence: terminal.sequence,
            terminal_l2_block_number: terminal.block_number,
            terminal_l2_block_hash: terminal.block_hash,
        }
    }

    fn seal_record(mut record: AuthorityRecordV3) -> AuthorityRecordV3 {
        record.authority_id = B256::ZERO;
        decode_authority_record(&encode_authority_record(record)).unwrap()
    }

    fn bootstrap() -> AuthorityRecordV3 {
        let anchor = context().anchor;
        seal_record(AuthorityRecordV3 {
            kind: AuthorityKind::Bootstrap,
            operation_generation: 0,
            authority_chain_position: 1,
            predecessor_authority_id: B256::ZERO,
            start_sequence: anchor.sequence,
            end_sequence: anchor.sequence,
            record_count: 0,
            feed_transition_count: 0,
            feed_transition_bitmap: [0; 32],
            promoted_identities_digest: identities_digest(&[]),
            evidence_digest: evidence_digest(1),
            locator: locator(anchor, 0),
            predecessor_authority_chain_digest: B256::ZERO,
            authority_id: B256::ZERO,
        })
    }

    fn policy<'a>(
        contexts: &'a [CanonicalContextV1],
        certificates: &'a [B256],
    ) -> AuthorityPolicy<'a> {
        AuthorityPolicy {
            contexts,
            bootstrap_certificates: certificates,
        }
    }

    fn entry(previous: MessageJournalAnchor, source: ArbEngineInputSource) -> MessageJournalEntry {
        let sequence = previous.sequence + 1;
        MessageJournalEntry {
            sequence,
            block_number: previous.block_number + 1,
            block_hash: B256::from(U256::from(sequence).to_be_bytes::<32>()),
            parent_hash: previous.block_hash,
            delayed_messages_read: sequence / 3,
            fingerprint: ArbMessageFingerprint {
                core: B256::from(U256::from(sequence + 1_000).to_be_bytes::<32>()),
                enrichment: ArbMessageEnrichment {
                    legacy_batch_gas_cost: sequence.is_multiple_of(2).then_some(sequence * 10),
                    batch_data_stats: sequence
                        .is_multiple_of(3)
                        .then_some((sequence + 5, sequence)),
                },
            },
            source,
        }
    }

    fn entries(count: usize) -> Vec<MessageJournalEntry> {
        let mut previous = context().anchor;
        (0..count)
            .map(|index| {
                let next = entry(
                    previous,
                    if index.is_multiple_of(3) {
                        ArbEngineInputSource::L1
                    } else {
                        ArbEngineInputSource::Feed
                    },
                );
                previous = MessageJournalAnchor {
                    sequence: next.sequence,
                    block_number: next.block_number,
                    block_hash: next.block_hash,
                };
                next
            })
            .collect()
    }

    fn bootstrap_state(retained: Vec<MessageJournalEntry>) -> SnapshotState {
        let bootstrap = bootstrap();
        SnapshotState {
            kind: SnapshotStateKind::Ordinary,
            entries: retained,
            bootstrap: Some(bootstrap),
            v: Some(context().anchor),
            authority_operation_count: 1,
            latest_authority_id: bootstrap.authority_id,
            latest_authority_chain_digest: authority_chain_digest(bootstrap),
            predecessor_final_commit_digest: B256::ZERO,
            grid: Vec::new(),
            source_v: None,
            source_j: 0,
            source_latest_authority_id: B256::ZERO,
            truncation_target_authority_id: B256::ZERO,
            truncation_plan_digest: B256::ZERO,
            removed_identity_count: 0,
            removed_identities_digest: B256::ZERO,
            source_authority_chain_digest: B256::ZERO,
            source_authority_operation_count: 0,
        }
    }

    fn promotion_frame(
        state: &SnapshotState,
        start: u64,
        count: usize,
        operation_generation: u64,
        previous_commit_digest: B256,
    ) -> (AuthorityRecordV3, Vec<u8>) {
        let start_index = usize::try_from(start - context().anchor.sequence - 1).unwrap();
        let mut promoted = state.entries[start_index..start_index + count].to_vec();
        let mut bitmap = [0u8; 32];
        let mut transitions = 0u16;
        for (index, identity) in promoted.iter_mut().enumerate() {
            if identity.source == ArbEngineInputSource::Feed {
                bitmap[index / 8] |= 1 << (7 - index % 8);
                transitions += 1;
            }
            identity.source = ArbEngineInputSource::L1;
        }
        let terminal = promoted.last().unwrap();
        let terminal_anchor = MessageJournalAnchor {
            sequence: terminal.sequence,
            block_number: terminal.block_number,
            block_hash: terminal.block_hash,
        };
        let record = seal_record(AuthorityRecordV3 {
            kind: AuthorityKind::Promotion,
            operation_generation,
            authority_chain_position: state.authority_operation_count + 1,
            predecessor_authority_id: state.latest_authority_id,
            start_sequence: start,
            end_sequence: terminal.sequence,
            record_count: count as u16,
            feed_transition_count: transitions,
            feed_transition_bitmap: bitmap,
            promoted_identities_digest: identities_digest(&promoted),
            evidence_digest: evidence_digest(2),
            locator: locator(terminal_anchor, terminal.delayed_messages_read),
            predecessor_authority_chain_digest: state.latest_authority_chain_digest,
            authority_id: B256::ZERO,
        });
        let mut payload = encode_authority_record(record).to_vec();
        for identity in promoted {
            payload.extend_from_slice(&encode_identity(identity));
        }
        (
            record,
            encode_frame(
                FrameKind::Authority,
                operation_generation,
                previous_commit_digest,
                &payload,
            )
            .unwrap(),
        )
    }

    fn initialize_with_bootstrap(
        directory: &JournalDirectory,
        retained: Vec<MessageJournalEntry>,
        policy: AuthorityPolicy<'_>,
    ) -> MessageJournalInspection {
        let state = bootstrap_state(retained);
        let header = JournalHeader {
            lineage_generation: 0,
            snapshot_through_operation_generation: 0,
            predecessor_file_root: B256::ZERO,
            anchor: context().anchor,
            storage_context_digest: context().digest(),
        };
        let payload = encode_snapshot_payload(context().anchor, &state).unwrap();
        let frame = encode_frame(FrameKind::Snapshot, 0, B256::ZERO, &payload).unwrap();
        let mut file = directory
            .create_new(&exact_journal_name(0, "log"), false)
            .unwrap();
        file.write_all(&encode_header(header)).unwrap();
        file.write_all(&frame).unwrap();
        file.sync_all().unwrap();
        drop(file);
        directory.sync_parent().unwrap();
        inspect_stopped_with_policy(directory, context(), policy)
            .unwrap()
            .0
    }

    fn initialize_promoted_source(
        directory: &JournalDirectory,
        policy: AuthorityPolicy<'_>,
    ) -> (MessageJournalInspection, AuthorityRecordV3) {
        let mut source = initialize_with_bootstrap(directory, Vec::new(), policy);
        let name = exact_journal_name(0, "log");
        let mut file = directory.open_existing(&name, true, true).unwrap();
        let retained = entries(300);
        for identity in &retained {
            let generation = source.last_operation_generation + 1;
            let frame = encode_frame(
                FrameKind::Executed,
                generation,
                source.last_commit_digest,
                &encode_identity(*identity),
            )
            .unwrap();
            file.write_all(&frame).unwrap();
            source.last_operation_generation = generation;
            source.last_commit_digest = decode_complete_frame(&frame).unwrap().commit_digest;
        }
        let state = bootstrap_state(retained);
        let (promotion, frame) = promotion_frame(
            &state,
            11,
            256,
            source.last_operation_generation + 1,
            source.last_commit_digest,
        );
        file.write_all(&frame).unwrap();
        file.sync_all().unwrap();
        drop(file);
        (
            inspect_stopped_with_policy(directory, context(), policy)
                .unwrap()
                .0,
            promotion,
        )
    }

    fn run_journal_subprocess(
        path: &Path,
        action: &str,
        injection_name: &str,
        injection: &str,
        expect_error: bool,
    ) -> ExitStatus {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg("--exact")
            .arg("message_journal::tests::journal_subprocess_worker")
            .arg("--nocapture")
            .env("ITE106B1_JOURNAL_CHILD", action)
            .env("ITE106B1_JOURNAL_PATH", path)
            .env(injection_name, injection)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if expect_error {
            command.env("ITE106B1_EXPECT_ERROR", "1");
        }
        command.status().unwrap()
    }

    fn prepare_compaction_source(directory: &JournalDirectory) {
        let mut inspection = initialize_journal_v3(directory, context()).unwrap();
        append_entry(
            directory,
            context(),
            &mut inspection,
            entry(context().anchor, ArbEngineInputSource::Feed),
        )
        .unwrap();
        compact_lineage(directory, context(), &mut inspection, PRODUCTION_POLICY).unwrap();
        assert_eq!(inspection.header.lineage_generation, 1);
    }

    #[test]
    fn journal_subprocess_worker() {
        let Some(action) = std::env::var_os("ITE106B1_JOURNAL_CHILD") else {
            return;
        };
        let path = PathBuf::from(std::env::var_os("ITE106B1_JOURNAL_PATH").unwrap());
        let directory = JournalDirectory::open(&path).unwrap();
        let result = match action.to_str().unwrap() {
            "append" => {
                let mut inspection = inspect_message_journal(&directory, context()).unwrap();
                let next = entry(inspection.watermark, ArbEngineInputSource::Feed);
                append_entry(&directory, context(), &mut inspection, next).map(|()| {
                    journal_crashpoint("append_after_ack");
                })
            }
            "compaction" => {
                let mut inspection = inspect_message_journal(&directory, context()).unwrap();
                compact_lineage(&directory, context(), &mut inspection, PRODUCTION_POLICY)
            }
            "truncation" => {
                let contexts = [canonical_context()];
                let certificates = [bootstrap_certificate_digest(bootstrap())];
                let policy = policy(&contexts, &certificates);
                let source = inspect_message_with_policy(&directory, context(), policy).unwrap();
                let target = source.retained_grid[0].authority.authority_id;
                create_recovery_truncation_with_policy(
                    &directory,
                    context(),
                    source.file_root,
                    RecoveryTargetV3::Grid {
                        authority_id: target,
                    },
                    B256::repeat_byte(0xaa),
                    policy,
                )
                .map(|_| ())
            }
            other => panic!("unknown subprocess action {other}"),
        };
        if std::env::var_os("ITE106B1_EXPECT_ERROR").is_some() {
            assert!(result.is_err(), "fault unexpectedly succeeded");
        } else {
            result.unwrap();
        }
    }

    #[test]
    fn append_crash_and_fault_matrix_fresh_reopen() {
        let crashpoints = [
            ("append_before_write", false),
            ("append_after_write", true),
            ("append_before_flush", true),
            ("append_after_flush", true),
            ("append_before_sync", true),
            ("append_after_sync", true),
            ("append_before_reread", true),
            ("append_after_reread", true),
            ("append_before_ack", true),
            ("append_after_ack", true),
        ];
        for (point, committed) in crashpoints {
            let dir = tempfile::tempdir().unwrap();
            let directory = JournalDirectory::open(dir.path()).unwrap();
            initialize_journal_v3(&directory, context()).unwrap();
            drop(directory);
            let status = run_journal_subprocess(
                dir.path(),
                "append",
                "ARB_RETH_JOURNAL_CRASHPOINT",
                point,
                false,
            );
            assert_eq!(status.code(), Some(86), "crashpoint {point}");
            let reopened = JournalDirectory::open(dir.path()).unwrap();
            let inspection = inspect_message_journal(&reopened, context()).unwrap();
            assert_eq!(
                inspection.watermark.sequence,
                if committed { 11 } else { 10 },
                "crashpoint {point}"
            );
        }

        let complete_faults = [
            "append_write:after:5",
            "append_flush:after:5",
            "append_sync:after:5",
            "append_reread:after:5",
        ];
        for fault in complete_faults {
            let dir = tempfile::tempdir().unwrap();
            let directory = JournalDirectory::open(dir.path()).unwrap();
            initialize_journal_v3(&directory, context()).unwrap();
            drop(directory);
            let status = run_journal_subprocess(
                dir.path(),
                "append",
                "ARB_RETH_JOURNAL_IO_FAULT",
                fault,
                false,
            );
            assert!(status.success(), "complete fault {fault}");
            let reopened = JournalDirectory::open(dir.path()).unwrap();
            assert_eq!(
                inspect_message_journal(&reopened, context())
                    .unwrap()
                    .watermark
                    .sequence,
                11,
                "complete fault {fault}"
            );
        }

        for fault in [
            "append_write:before:28",
            "append_write:short:5",
            "append_flush:before:5",
            "append_sync:before:5",
            "append_reread:before:5",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let directory = JournalDirectory::open(dir.path()).unwrap();
            initialize_journal_v3(&directory, context()).unwrap();
            drop(directory);
            let status = run_journal_subprocess(
                dir.path(),
                "append",
                "ARB_RETH_JOURNAL_IO_FAULT",
                fault,
                true,
            );
            assert!(status.success(), "incomplete fault {fault}");
            let reopened = JournalDirectory::open(dir.path()).unwrap();
            let (inspection, repair) =
                inspect_stopped_message_journal(&reopened, context()).unwrap();
            assert_eq!(
                inspection.watermark.sequence, 10,
                "incomplete fault {fault}"
            );
            assert!(!repair, "known fault left a recoverable tail: {fault}");
        }
    }

    #[test]
    fn compaction_crash_and_fault_matrix_fresh_reopen() {
        #[derive(Clone, Copy, Debug)]
        enum Outcome {
            Old,
            InvalidTemp,
            CompleteTemp,
            New,
        }
        let crashpoints = [
            ("compaction_before_seal", Outcome::Old),
            ("compaction_before_temp_write", Outcome::InvalidTemp),
            ("compaction_after_temp_write", Outcome::CompleteTemp),
            ("compaction_before_temp_flush", Outcome::CompleteTemp),
            ("compaction_after_temp_flush", Outcome::CompleteTemp),
            ("compaction_before_temp_sync", Outcome::CompleteTemp),
            ("compaction_after_temp_sync", Outcome::CompleteTemp),
            ("compaction_before_temp_reread", Outcome::CompleteTemp),
            ("compaction_after_temp_reread", Outcome::CompleteTemp),
            ("compaction_before_rename", Outcome::CompleteTemp),
            ("compaction_after_rename", Outcome::New),
            ("compaction_before_parent_sync", Outcome::New),
            ("compaction_after_parent_sync", Outcome::New),
            ("compaction_before_selection", Outcome::New),
            ("compaction_after_selection", Outcome::New),
            ("compaction_after_append_switch", Outcome::New),
            ("compaction_before_cleanup", Outcome::New),
            ("compaction_after_cleanup", Outcome::New),
        ];
        for (point, outcome) in crashpoints {
            let dir = tempfile::tempdir().unwrap();
            let directory = JournalDirectory::open(dir.path()).unwrap();
            prepare_compaction_source(&directory);
            drop(directory);
            let status = run_journal_subprocess(
                dir.path(),
                "compaction",
                "ARB_RETH_JOURNAL_CRASHPOINT",
                point,
                false,
            );
            assert_eq!(status.code(), Some(86), "crashpoint {point}");
            let reopened = JournalDirectory::open(dir.path()).unwrap();
            match outcome {
                Outcome::Old => {
                    let (inspection, repair) =
                        inspect_stopped_message_journal(&reopened, context()).unwrap();
                    assert_eq!(
                        inspection.header.lineage_generation, 1,
                        "crashpoint {point}"
                    );
                    assert!(!repair, "crashpoint {point}");
                }
                Outcome::InvalidTemp => {
                    assert!(
                        inspect_stopped_message_journal(&reopened, context()).is_err(),
                        "crashpoint {point}"
                    );
                }
                Outcome::CompleteTemp => {
                    let (inspection, repair) =
                        inspect_stopped_message_journal(&reopened, context()).unwrap();
                    assert_eq!(
                        inspection.header.lineage_generation, 1,
                        "crashpoint {point}"
                    );
                    assert!(repair, "crashpoint {point}");
                }
                Outcome::New => {
                    let inspection = inspect_message_journal(&reopened, context()).unwrap();
                    assert_eq!(
                        inspection.header.lineage_generation, 2,
                        "crashpoint {point}"
                    );
                    assert_eq!(inspection.watermark.sequence, 11, "crashpoint {point}");
                }
            }
        }

        let faults = [
            ("compaction_write:before:28", true, Outcome::Old),
            ("compaction_write:short:5", true, Outcome::Old),
            ("compaction_write:after:5", false, Outcome::New),
            ("compaction_flush:before:5", true, Outcome::Old),
            ("compaction_flush:after:5", false, Outcome::New),
            ("compaction_sync:before:5", true, Outcome::Old),
            ("compaction_sync:after:5", false, Outcome::New),
            ("compaction_validate:before:5", true, Outcome::CompleteTemp),
            ("compaction_validate:after:5", true, Outcome::CompleteTemp),
            ("compaction_rename:before:5", true, Outcome::CompleteTemp),
            ("compaction_rename:after:5", true, Outcome::New),
            ("compaction_parent_sync:before:5", true, Outcome::New),
            ("compaction_parent_sync:after:5", true, Outcome::New),
            ("compaction_select:before:5", true, Outcome::New),
            ("compaction_select:after:5", true, Outcome::New),
        ];
        for (fault, expect_error, outcome) in faults {
            let dir = tempfile::tempdir().unwrap();
            let directory = JournalDirectory::open(dir.path()).unwrap();
            prepare_compaction_source(&directory);
            drop(directory);
            let status = run_journal_subprocess(
                dir.path(),
                "compaction",
                "ARB_RETH_JOURNAL_IO_FAULT",
                fault,
                expect_error,
            );
            assert!(status.success(), "fault {fault}");
            let reopened = JournalDirectory::open(dir.path()).unwrap();
            match outcome {
                Outcome::InvalidTemp => {
                    assert!(
                        inspect_stopped_message_journal(&reopened, context()).is_err(),
                        "fault {fault}"
                    );
                }
                Outcome::CompleteTemp => {
                    assert!(
                        inspect_stopped_message_journal(&reopened, context())
                            .unwrap()
                            .1,
                        "fault {fault}"
                    );
                }
                Outcome::New => {
                    assert_eq!(
                        inspect_message_journal(&reopened, context())
                            .unwrap()
                            .header
                            .lineage_generation,
                        2,
                        "fault {fault}"
                    );
                }
                Outcome::Old => {
                    let (inspection, repair) =
                        inspect_stopped_message_journal(&reopened, context()).unwrap();
                    assert_eq!(inspection.header.lineage_generation, 1, "fault {fault}");
                    assert!(!repair, "fault {fault}");
                }
            }
        }
    }

    #[test]
    fn truncation_crash_and_fault_matrix_preserves_source() {
        #[derive(Clone, Copy, Debug)]
        enum Outcome {
            Old,
            InvalidTemp,
            CompleteTemp,
            New,
        }
        fn prepare(directory: &JournalDirectory) -> (AuthorityPolicy<'static>, String, Vec<u8>) {
            static CONTEXTS: std::sync::OnceLock<[CanonicalContextV1; 1]> =
                std::sync::OnceLock::new();
            static CERTIFICATES: std::sync::OnceLock<[B256; 1]> = std::sync::OnceLock::new();
            let contexts = CONTEXTS.get_or_init(|| [canonical_context()]);
            let certificates =
                CERTIFICATES.get_or_init(|| [bootstrap_certificate_digest(bootstrap())]);
            let policy = policy(contexts, certificates);
            let (source, _) = initialize_promoted_source(directory, policy);
            let source_name = source
                .path
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            let source_bytes = std::fs::read(&source.path).unwrap();
            (policy, source_name, source_bytes)
        }
        fn verify(
            directory: &JournalDirectory,
            policy: AuthorityPolicy<'_>,
            outcome: Outcome,
            scenario: &str,
        ) {
            match outcome {
                Outcome::Old => {
                    let (inspection, repair) =
                        inspect_stopped_with_policy(directory, context(), policy).unwrap();
                    assert_eq!(inspection.header.lineage_generation, 0, "{scenario}");
                    assert!(!inspection.recovery_truncation, "{scenario}");
                    assert!(!repair, "{scenario}");
                }
                Outcome::InvalidTemp => {
                    assert!(
                        inspect_stopped_with_policy(directory, context(), policy).is_err(),
                        "{scenario}"
                    );
                }
                Outcome::CompleteTemp => {
                    let (inspection, repair) =
                        inspect_stopped_with_policy(directory, context(), policy).unwrap();
                    assert_eq!(inspection.header.lineage_generation, 0, "{scenario}");
                    assert!(!inspection.recovery_truncation, "{scenario}");
                    assert!(repair, "{scenario}");
                }
                Outcome::New => {
                    let (inspection, repair) =
                        inspect_stopped_with_policy(directory, context(), policy).unwrap();
                    assert_eq!(inspection.header.lineage_generation, 1, "{scenario}");
                    assert!(inspection.recovery_truncation, "{scenario}");
                    assert!(!repair, "{scenario}");
                    assert!(
                        inspect_message_with_policy(directory, context(), policy)
                            .unwrap_err()
                            .downcast_ref::<B3RecoveryMarkerRequired>()
                            .is_some(),
                        "{scenario}"
                    );
                }
            }
        }

        let crashpoints = [
            ("truncation_before_seal", Outcome::Old),
            ("truncation_before_temp_write", Outcome::InvalidTemp),
            ("truncation_after_temp_write", Outcome::CompleteTemp),
            ("truncation_before_temp_flush", Outcome::CompleteTemp),
            ("truncation_after_temp_flush", Outcome::CompleteTemp),
            ("truncation_before_temp_sync", Outcome::CompleteTemp),
            ("truncation_after_temp_sync", Outcome::CompleteTemp),
            ("truncation_before_temp_reread", Outcome::CompleteTemp),
            ("truncation_after_temp_reread", Outcome::CompleteTemp),
            ("truncation_before_rename", Outcome::CompleteTemp),
            ("truncation_after_rename", Outcome::New),
            ("truncation_before_parent_sync", Outcome::New),
            ("truncation_after_parent_sync", Outcome::New),
            ("truncation_before_selection", Outcome::New),
            ("truncation_after_selection", Outcome::New),
        ];
        for (point, outcome) in crashpoints {
            let dir = tempfile::tempdir().unwrap();
            let directory = JournalDirectory::open(dir.path()).unwrap();
            let (policy, source_name, source_bytes) = prepare(&directory);
            drop(directory);
            let status = run_journal_subprocess(
                dir.path(),
                "truncation",
                "ARB_RETH_JOURNAL_CRASHPOINT",
                point,
                false,
            );
            assert_eq!(status.code(), Some(86), "crashpoint {point}");
            let reopened = JournalDirectory::open(dir.path()).unwrap();
            assert_eq!(
                std::fs::read(dir.path().join(&source_name)).unwrap(),
                source_bytes,
                "crashpoint {point}"
            );
            verify(&reopened, policy, outcome, point);
        }

        let faults = [
            ("truncation_write:before:28", true, Outcome::Old),
            ("truncation_write:short:5", true, Outcome::Old),
            ("truncation_write:after:5", false, Outcome::New),
            ("truncation_flush:before:5", true, Outcome::Old),
            ("truncation_flush:after:5", false, Outcome::New),
            ("truncation_sync:before:5", true, Outcome::Old),
            ("truncation_sync:after:5", false, Outcome::New),
            ("truncation_validate:before:5", true, Outcome::CompleteTemp),
            ("truncation_validate:after:5", true, Outcome::CompleteTemp),
            ("truncation_rename:before:5", true, Outcome::CompleteTemp),
            ("truncation_rename:after:5", true, Outcome::New),
            ("truncation_parent_sync:before:5", true, Outcome::New),
            ("truncation_parent_sync:after:5", true, Outcome::New),
            ("truncation_select:before:5", true, Outcome::New),
            ("truncation_select:after:5", true, Outcome::New),
        ];
        for (fault, expect_error, outcome) in faults {
            let dir = tempfile::tempdir().unwrap();
            let directory = JournalDirectory::open(dir.path()).unwrap();
            let (policy, source_name, source_bytes) = prepare(&directory);
            drop(directory);
            let status = run_journal_subprocess(
                dir.path(),
                "truncation",
                "ARB_RETH_JOURNAL_IO_FAULT",
                fault,
                expect_error,
            );
            assert!(status.success(), "fault {fault}");
            let reopened = JournalDirectory::open(dir.path()).unwrap();
            assert_eq!(
                std::fs::read(dir.path().join(&source_name)).unwrap(),
                source_bytes,
                "fault {fault}"
            );
            verify(&reopened, policy, outcome, fault);
        }
    }

    #[test]
    fn frozen_golden_vectors_and_independent_roundtrips() {
        let header = JournalHeader {
            lineage_generation: 3,
            snapshot_through_operation_generation: 9,
            predecessor_file_root: B256::repeat_byte(0x91),
            anchor: context().anchor,
            storage_context_digest: context().digest(),
        };
        let identity = entries(1)[0];
        let locator = locator(context().anchor, 0);
        let bootstrap = bootstrap();
        let promotion_state = bootstrap_state(entries(1));
        let (promotion, authority_frame) = promotion_frame(&promotion_state, 11, 1, 1, B256::ZERO);
        let grid = RetainedGridRecordV3 {
            authority: promotion,
            original_lineage_generation: 4,
            original_frame_commit_digest: B256::repeat_byte(0x92),
        };
        let ordinary =
            encode_snapshot_payload(context().anchor, &bootstrap_state(entries(2))).unwrap();
        let mut recovery_state = empty_snapshot_state();
        recovery_state.kind = SnapshotStateKind::RecoveryTruncation;
        recovery_state.source_v = Some(10);
        recovery_state.source_j = 11;
        recovery_state.source_latest_authority_id = B256::repeat_byte(2);
        recovery_state.truncation_target_authority_id = B256::repeat_byte(3);
        recovery_state.truncation_plan_digest = B256::repeat_byte(4);
        recovery_state.removed_identity_count = 1;
        recovery_state.removed_identities_digest = B256::repeat_byte(5);
        recovery_state.source_authority_chain_digest = B256::repeat_byte(6);
        recovery_state.source_authority_operation_count = 7;
        let recovery = encode_snapshot_payload(context().anchor, &recovery_state).unwrap();
        let frames = [
            (
                "FRAME_EXECUTED",
                encode_frame(
                    FrameKind::Executed,
                    1,
                    B256::ZERO,
                    &encode_identity(identity),
                )
                .unwrap(),
            ),
            ("FRAME_AUTHORITY", authority_frame),
            (
                "FRAME_SNAPSHOT",
                encode_frame(FrameKind::Snapshot, 0, B256::ZERO, &ordinary).unwrap(),
            ),
            (
                "FRAME_RECOVERY",
                encode_frame(
                    FrameKind::RecoveryTruncationSnapshot,
                    1,
                    B256::repeat_byte(1),
                    &recovery,
                )
                .unwrap(),
            ),
        ];
        let mut vectors = vec![
            (
                "HEADER",
                encode_header(header).to_vec(),
                alloy_primitives::b256!(
                    "943871e2f6a9b0f172b900fcac46e0849d00881575e40621112abd61352ee98f"
                ),
            ),
            (
                "IDENTITY",
                encode_identity(identity).to_vec(),
                alloy_primitives::b256!(
                    "a76ca746ba8aae1d0e6947e327f7480b08faa8b21151811713fb991499bdec75"
                ),
            ),
            (
                "LOCATOR",
                encode_locator(locator).to_vec(),
                alloy_primitives::b256!(
                    "e9195f4c5bf5b80897915bc7a75323b019eccb22304a3513b6da39036707e7a7"
                ),
            ),
            (
                "BOOTSTRAP",
                encode_authority_record(bootstrap).to_vec(),
                alloy_primitives::b256!(
                    "3a9b703a1db141bc60c796d351a19a46bdcad848a564ee993b6a9ac341aca19e"
                ),
            ),
            (
                "PROMOTION",
                encode_authority_record(promotion).to_vec(),
                alloy_primitives::b256!(
                    "b19040e883f349c191ebe63c8208b7817fa08dd9f186ecc18647ed6cd15f5654"
                ),
            ),
            (
                "GRID",
                encode_grid_record(grid).to_vec(),
                alloy_primitives::b256!(
                    "acce626330b259b79141751350106810a1b452b5a789d34bc439cf8e83027432"
                ),
            ),
            (
                "SNAPSHOT_ORDINARY",
                ordinary,
                alloy_primitives::b256!(
                    "c3a60086d6b0d2063f9ce897cc0365c09c968e803c506a12579ce974e54cc1de"
                ),
            ),
            (
                "SNAPSHOT_RECOVERY",
                recovery,
                alloy_primitives::b256!(
                    "f087f39dc32dbdff884bc9dd01b483faf24b36fe334d31d0cca4ba03a836f590"
                ),
            ),
        ];
        for ((name, bytes), expected) in frames.into_iter().zip([
            alloy_primitives::b256!(
                "5fe5304b6a6317d1a6cf3d93a56e4440d6f4a6fab25d3062015a1f26755970d9"
            ),
            alloy_primitives::b256!(
                "6d0b41e3ddf8644a03c1dce35f68f875dbc843637a47c0244c3204901c2460e8"
            ),
            alloy_primitives::b256!(
                "f00ad6c26fb7ed98757a7c7f13c2d2abe11db9288ec4dc4621318772cc9bed94"
            ),
            alloy_primitives::b256!(
                "b15213082a4128ed67e19743e76f236a7caaa48b0f86d5732e3b9f919b62c386"
            ),
        ]) {
            vectors.push((name, bytes, expected));
        }
        let golden = include_str!("../tests/fixtures/ite106b1-golden-vectors.txt");
        assert_eq!(golden.lines().count(), vectors.len());
        for (name, bytes, expected_hash) in vectors {
            let prefix = format!("GOLDEN_{name}=");
            let expected_bytes = golden
                .lines()
                .find_map(|line| line.strip_prefix(&prefix))
                .map(alloy_primitives::hex::decode)
                .transpose()
                .unwrap()
                .unwrap_or_else(|| panic!("missing golden {name}"));
            assert_eq!(bytes, expected_bytes, "full golden hex {name}");
            assert_eq!(
                B256::from_slice(&Sha256::digest(&bytes)),
                expected_hash,
                "golden {name}"
            );
            let reencoded = match name {
                "HEADER" => encode_header(decode_header(&bytes).unwrap()).to_vec(),
                "IDENTITY" => encode_identity(decode_identity(&bytes).unwrap()).to_vec(),
                "LOCATOR" => encode_locator(decode_locator(&bytes).unwrap()).to_vec(),
                "BOOTSTRAP" | "PROMOTION" => {
                    encode_authority_record(decode_authority_record(&bytes).unwrap()).to_vec()
                }
                "GRID" => encode_grid_record(decode_grid_record(&bytes).unwrap()).to_vec(),
                "SNAPSHOT_ORDINARY" | "SNAPSHOT_RECOVERY" => encode_snapshot_payload(
                    context().anchor,
                    &decode_snapshot_payload(&bytes, header).unwrap(),
                )
                .unwrap(),
                _ => {
                    let decoded = decode_complete_frame(&bytes).unwrap();
                    encode_frame(
                        decoded.kind,
                        decoded.operation_generation,
                        decoded.previous_commit_digest,
                        &decoded.payload,
                    )
                    .unwrap()
                }
            };
            assert_eq!(reencoded, bytes, "golden {name} independent roundtrip");
        }
    }

    #[test]
    fn frozen_codecs_roundtrip_and_reject_mutations() {
        let header = JournalHeader {
            lineage_generation: 3,
            snapshot_through_operation_generation: 9,
            predecessor_file_root: B256::repeat_byte(0x91),
            anchor: context().anchor,
            storage_context_digest: context().digest(),
        };
        let header_bytes = encode_header(header);
        assert_eq!(decode_header(&header_bytes).unwrap(), header);
        for offset in 0..HEADER_LEN {
            let mut changed = header_bytes;
            changed[offset] ^= 1;
            assert!(decode_header(&changed).is_err(), "header mutation {offset}");
        }

        let identity = entries(1)[0];
        let identity_bytes = encode_identity(identity);
        assert_eq!(decode_identity(&identity_bytes).unwrap(), identity);
        for offset in 147..IDENTITY_LEN {
            let mut changed = identity_bytes;
            changed[offset] = 1;
            assert!(
                decode_identity(&changed).is_err(),
                "identity reserved mutation {offset}"
            );
        }
        for offset in [120, 129, 146] {
            let mut changed = identity_bytes;
            changed[offset] = 2;
            assert!(
                decode_identity(&changed).is_err(),
                "identity flag mutation {offset}"
            );
        }
        for offset in (121..129).chain(130..146) {
            let mut changed = identity_bytes;
            changed[offset] = 1;
            assert!(
                decode_identity(&changed).is_err(),
                "absent identity enrichment mutation {offset}"
            );
        }

        let locator = locator(context().anchor, 0);
        let locator_bytes = encode_locator(locator);
        assert_eq!(decode_locator(&locator_bytes).unwrap(), locator);
        for offset in [0, 8, 10, 14, 15] {
            let mut changed = locator_bytes;
            changed[offset] ^= 1;
            assert!(
                decode_locator(&changed).is_err(),
                "locator structural mutation {offset}"
            );
        }
        for offset in 240..LOCATOR_LEN {
            let mut changed = locator_bytes;
            changed[offset] = 1;
            assert!(
                decode_locator(&changed).is_err(),
                "locator reserved mutation {offset}"
            );
        }

        let bootstrap = bootstrap();
        let authority_bytes = encode_authority_record(bootstrap);
        assert_eq!(
            decode_authority_record(&authority_bytes).unwrap(),
            bootstrap
        );
        for offset in 0..AUTHORITY_RECORD_LEN {
            let mut changed = authority_bytes;
            changed[offset] ^= 1;
            assert!(
                decode_authority_record(&changed).is_err(),
                "authority mutation {offset}"
            );
        }

        let grid = RetainedGridRecordV3 {
            authority: seal_record(AuthorityRecordV3 {
                kind: AuthorityKind::Promotion,
                ..bootstrap
            }),
            original_lineage_generation: 4,
            original_frame_commit_digest: B256::repeat_byte(0x92),
        };
        let grid_bytes = encode_grid_record(grid);
        assert_eq!(decode_grid_record(&grid_bytes).unwrap(), grid);
        for offset in 552..GRID_RECORD_LEN {
            let mut changed = grid_bytes;
            changed[offset] = 1;
            assert!(
                decode_grid_record(&changed).is_err(),
                "grid reserved mutation {offset}"
            );
        }

        assert_eq!(header_bytes.len(), HEADER_LEN);
        assert_eq!(identity_bytes.len(), IDENTITY_LEN);
        assert_eq!(locator_bytes.len(), LOCATOR_LEN);
        assert_eq!(authority_bytes.len(), AUTHORITY_RECORD_LEN);
        assert_eq!(grid_bytes.len(), GRID_RECORD_LEN);
    }

    #[test]
    fn frame_kinds_have_exact_envelopes_and_reject_corruption() {
        let identity = entries(1)[0];
        let ordinary = encode_snapshot_payload(context().anchor, &empty_snapshot_state()).unwrap();
        let mut recovery = empty_snapshot_state();
        recovery.kind = SnapshotStateKind::RecoveryTruncation;
        let recovery = encode_snapshot_payload(context().anchor, &recovery).unwrap();
        let state = bootstrap_state(entries(1));
        let (_, authority) = promotion_frame(&state, 11, 1, 1, B256::ZERO);
        let vectors = [
            encode_frame(
                FrameKind::Executed,
                1,
                B256::ZERO,
                &encode_identity(identity),
            )
            .unwrap(),
            authority,
            encode_frame(FrameKind::Snapshot, 0, B256::ZERO, &ordinary).unwrap(),
            encode_frame(
                FrameKind::RecoveryTruncationSnapshot,
                1,
                B256::repeat_byte(1),
                &recovery,
            )
            .unwrap(),
        ];
        for bytes in vectors {
            let decoded = decode_complete_frame(&bytes).unwrap();
            assert_eq!(
                encode_frame(
                    decoded.kind,
                    decoded.operation_generation,
                    decoded.previous_commit_digest,
                    &decoded.payload,
                )
                .unwrap(),
                bytes
            );
            for offset in 0..bytes.len() {
                let mut changed = bytes.clone();
                changed[offset] ^= 1;
                assert!(
                    decode_complete_frame(&changed).is_err(),
                    "frame mutation {offset}"
                );
            }
        }
    }

    #[test]
    fn lineage_zero_is_exact_storage_only_and_context_bound() {
        assert!(PRODUCTION_POLICY.contexts.is_empty());
        assert!(PRODUCTION_POLICY.bootstrap_certificates.is_empty());
        let dir = tempfile::tempdir().unwrap();
        let directory = JournalDirectory::open(dir.path()).unwrap();
        let inspection = initialize_journal_v3(&directory, context()).unwrap();
        assert_eq!(inspection.complete_byte_offset, 904);
        assert_eq!(inspection.v, None);
        assert_eq!(inspection.watermark, context().anchor);
        assert!(inspection.entries.is_empty());
        assert!(inspection.retained_grid.is_empty());
        let mut mismatch = context();
        mismatch.bridge = Address::repeat_byte(0xff);
        assert!(inspect_message_journal(&directory, mismatch).is_err());
        assert!(initialize_journal_v3(&directory, context()).is_err());

        let old = tempfile::tempdir().unwrap();
        std::fs::write(
            old.path()
                .join("arb-message-journal-v2-g00000000000000000000.log"),
            [],
        )
        .unwrap();
        let old = JournalDirectory::open(old.path()).unwrap();
        assert!(initialize_journal_v3(&old, context()).is_err());
        assert!(inspect_message_journal(&old, context()).is_err());
    }

    #[test]
    fn core_inspection_binds_final_and_temp_names_to_authenticated_generation() {
        let zero_final = tempfile::tempdir().unwrap();
        let directory = JournalDirectory::open(zero_final.path()).unwrap();
        initialize_journal_v3(&directory, context()).unwrap();
        directory
            .rename_noreplace(&exact_journal_name(0, "log"), &exact_journal_name(1, "log"))
            .unwrap();
        assert!(
            inspect_file(
                &directory,
                &exact_journal_name(1, "log"),
                context(),
                PRODUCTION_POLICY,
            )
            .unwrap_err()
            .to_string()
            .contains("name/header generation mismatch")
        );

        let zero_temp = tempfile::tempdir().unwrap();
        let directory = JournalDirectory::open(zero_temp.path()).unwrap();
        initialize_journal_v3(&directory, context()).unwrap();
        std::fs::copy(
            zero_temp.path().join(exact_journal_name(0, "log")),
            zero_temp.path().join(exact_journal_name(1, "tmp")),
        )
        .unwrap();
        assert!(
            inspect_file(
                &directory,
                &exact_journal_name(1, "tmp"),
                context(),
                PRODUCTION_POLICY,
            )
            .is_err()
        );
        assert!(inspect_stopped_with_policy(&directory, context(), PRODUCTION_POLICY).is_err());

        let public_final = tempfile::tempdir().unwrap();
        let directory = JournalDirectory::open(public_final.path()).unwrap();
        let inspection = initialize_journal_v3(&directory, context()).unwrap();
        let mut header = inspection.header;
        header.lineage_generation = 1;
        header.predecessor_file_root = B256::repeat_byte(1);
        let mut file = directory
            .open_existing(&exact_journal_name(0, "log"), true, false)
            .unwrap();
        file.write_all(&encode_header(header)).unwrap();
        file.sync_all().unwrap();
        drop(file);
        for result in [
            inspect_message_with_policy(&directory, context(), PRODUCTION_POLICY).map(|_| ()),
            inspect_stopped_with_policy(&directory, context(), PRODUCTION_POLICY).map(|_| ()),
        ] {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("name/header generation mismatch")
            );
        }

        let later_final = tempfile::tempdir().unwrap();
        let directory = JournalDirectory::open(later_final.path()).unwrap();
        prepare_compaction_source(&directory);
        directory
            .rename_noreplace(&exact_journal_name(1, "log"), &exact_journal_name(2, "log"))
            .unwrap();
        assert!(
            inspect_file(
                &directory,
                &exact_journal_name(2, "log"),
                context(),
                PRODUCTION_POLICY,
            )
            .is_err()
        );
    }

    #[test]
    fn snapshot_codec_roundtrips_ordinary_and_recovery_prefixes() {
        let header = JournalHeader {
            lineage_generation: 1,
            snapshot_through_operation_generation: 2,
            predecessor_file_root: B256::repeat_byte(1),
            anchor: context().anchor,
            storage_context_digest: context().digest(),
        };
        let ordinary = empty_snapshot_state();
        let encoded = encode_snapshot_payload(context().anchor, &ordinary).unwrap();
        assert_eq!(decode_snapshot_payload(&encoded, header).unwrap(), ordinary);
        for offset in [0, 8, 11, 12, 16, 20, 22, 224, 289, 488, 511] {
            let mut changed = encoded.clone();
            changed[offset] ^= 1;
            assert!(
                decode_snapshot_payload(&changed, header).is_err(),
                "snapshot mutation {offset}"
            );
        }

        let mut recovery = empty_snapshot_state();
        recovery.kind = SnapshotStateKind::RecoveryTruncation;
        recovery.source_v = Some(10);
        recovery.source_j = 11;
        recovery.source_latest_authority_id = B256::repeat_byte(2);
        recovery.truncation_target_authority_id = B256::repeat_byte(3);
        recovery.truncation_plan_digest = B256::repeat_byte(4);
        recovery.removed_identity_count = 1;
        recovery.removed_identities_digest = B256::repeat_byte(5);
        recovery.source_authority_chain_digest = B256::repeat_byte(6);
        recovery.source_authority_operation_count = 7;
        let encoded = encode_snapshot_payload(context().anchor, &recovery).unwrap();
        assert_eq!(decode_snapshot_payload(&encoded, header).unwrap(), recovery);
    }

    #[test]
    fn bootstrap_promotion_bitmap_grid_and_boundaries_are_exact() {
        let contexts = [canonical_context()];
        let certificates = [bootstrap_certificate_digest(bootstrap())];
        let policy = policy(&contexts, &certificates);
        validate_bootstrap(bootstrap(), context().anchor, policy).unwrap();
        assert!(validate_bootstrap(bootstrap(), context().anchor, PRODUCTION_POLICY).is_err());

        let mut one = bootstrap_state(entries(3));
        let (first_l1, frame) = promotion_frame(&one, 11, 1, 1, B256::ZERO);
        assert_eq!(first_l1.feed_transition_count, 0);
        assert_eq!(first_l1.feed_transition_bitmap, [0; 32]);
        let first_frame = decode_complete_frame(&frame).unwrap();
        apply_authority_frame(&mut one, &first_frame, policy, 0).unwrap();
        assert_eq!(one.v.unwrap().sequence, 11);
        let (_, duplicate) = promotion_frame(&one, 11, 1, 2, first_frame.commit_digest);
        assert!(
            apply_authority_frame(
                &mut one,
                &decode_complete_frame(&duplicate).unwrap(),
                policy,
                0,
            )
            .is_err()
        );

        let mixed_state = bootstrap_state(entries(3));
        let (mixed, mixed_frame) = promotion_frame(&mixed_state, 11, 3, 1, B256::ZERO);
        assert_eq!(mixed.feed_transition_count, 2);
        assert_eq!(mixed.feed_transition_bitmap[0], 0b0110_0000);
        let mut conflict = mixed;
        conflict.feed_transition_bitmap[0] ^= 0b1000_0000;
        conflict = seal_record(conflict);
        let decoded = decode_complete_frame(&mixed_frame).unwrap();
        let mut conflict_payload = encode_authority_record(conflict).to_vec();
        conflict_payload.extend_from_slice(&decoded.payload[AUTHORITY_RECORD_LEN..]);
        let conflict_frame =
            encode_frame(FrameKind::Authority, 1, B256::ZERO, &conflict_payload).unwrap();
        assert!(
            apply_authority_frame(
                &mut mixed_state.clone(),
                &decode_complete_frame(&conflict_frame).unwrap(),
                policy,
                0,
            )
            .is_err()
        );

        let mut duplicate_payload = decoded.payload.clone();
        let first_identity = decode_identity(
            &duplicate_payload[AUTHORITY_RECORD_LEN..AUTHORITY_RECORD_LEN + IDENTITY_LEN],
        )
        .unwrap();
        duplicate_payload
            [AUTHORITY_RECORD_LEN + IDENTITY_LEN..AUTHORITY_RECORD_LEN + 2 * IDENTITY_LEN]
            .copy_from_slice(&encode_identity(first_identity));
        let duplicate_frame =
            encode_frame(FrameKind::Authority, 1, B256::ZERO, &duplicate_payload).unwrap();
        assert!(
            apply_authority_frame(
                &mut mixed_state.clone(),
                &decode_complete_frame(&duplicate_frame).unwrap(),
                policy,
                0,
            )
            .is_err()
        );

        let (_, gap) = promotion_frame(&mixed_state, 12, 1, 1, B256::ZERO);
        assert!(
            apply_authority_frame(
                &mut mixed_state.clone(),
                &decode_complete_frame(&gap).unwrap(),
                policy,
                0,
            )
            .is_err()
        );
        let mut appended_bootstrap_payload = encode_authority_record(bootstrap()).to_vec();
        appended_bootstrap_payload.extend_from_slice(&encode_identity(entries(1)[0]));
        let appended_bootstrap = encode_frame(
            FrameKind::Authority,
            1,
            B256::ZERO,
            &appended_bootstrap_payload,
        )
        .unwrap();
        assert!(
            apply_authority_frame(
                &mut mixed_state.clone(),
                &decode_complete_frame(&appended_bootstrap).unwrap(),
                policy,
                0,
            )
            .is_err()
        );

        let mut state = bootstrap_state(entries(300));
        let (record, bytes) = promotion_frame(&state, 11, 256, 1, B256::ZERO);
        let frame = decode_complete_frame(&bytes).unwrap();
        apply_authority_frame(&mut state, &frame, policy, 0).unwrap();
        assert_eq!(state.v.unwrap().sequence, 266);
        assert_eq!(state.authority_operation_count, 2);
        assert_eq!(state.latest_authority_id, record.authority_id);
        assert_eq!(state.grid.len(), 1);
        assert_eq!(state.grid[0].authority.end_sequence, 266);

        let mut before_grid = bootstrap_state(entries(300));
        let (_, frame) = promotion_frame(&before_grid, 11, 255, 1, B256::ZERO);
        apply_authority_frame(
            &mut before_grid,
            &decode_complete_frame(&frame).unwrap(),
            policy,
            0,
        )
        .unwrap();
        assert_eq!(before_grid.v.unwrap().sequence, 265);
        assert!(before_grid.grid.is_empty());
        let mut crossing_state = bootstrap_state(entries(300));
        let (_, first) = promotion_frame(&crossing_state, 11, 89, 1, B256::ZERO);
        let first = decode_complete_frame(&first).unwrap();
        apply_authority_frame(&mut crossing_state, &first, policy, 0).unwrap();
        let (_, crossing) = promotion_frame(&crossing_state, 100, 200, 2, first.commit_digest);
        assert!(
            apply_authority_frame(
                &mut crossing_state,
                &decode_complete_frame(&crossing).unwrap(),
                policy,
                0,
            )
            .is_err()
        );
        assert!(validate_payload_domain(FrameKind::Authority, AUTHORITY_RECORD_LEN).is_err());
        assert!(
            validate_payload_domain(
                FrameKind::Authority,
                AUTHORITY_RECORD_LEN + 257 * IDENTITY_LEN,
            )
            .is_err()
        );
    }

    #[test]
    fn authority_and_snapshot_semantic_field_mutations_fail_closed() {
        let contexts = [canonical_context()];
        let certificates = [bootstrap_certificate_digest(bootstrap())];
        let policy = policy(&contexts, &certificates);
        let base = bootstrap();
        let mut authority_mutations = Vec::new();
        macro_rules! changed_authority {
            ($field:ident, $value:expr) => {{
                let mut changed = base;
                changed.$field = $value;
                authority_mutations.push(seal_record(changed));
            }};
        }
        changed_authority!(kind, AuthorityKind::Promotion);
        changed_authority!(operation_generation, 1);
        changed_authority!(authority_chain_position, 2);
        changed_authority!(predecessor_authority_id, B256::repeat_byte(1));
        changed_authority!(start_sequence, base.start_sequence + 1);
        changed_authority!(end_sequence, base.end_sequence + 1);
        changed_authority!(record_count, 1);
        changed_authority!(feed_transition_count, 1);
        changed_authority!(feed_transition_bitmap, [1; 32]);
        changed_authority!(promoted_identities_digest, B256::repeat_byte(2));
        changed_authority!(evidence_digest, B256::ZERO);
        changed_authority!(predecessor_authority_chain_digest, B256::repeat_byte(3));

        for mutate in 0..6 {
            let mut changed = base;
            match mutate {
                0 => changed.locator.context_id += 1,
                1 => changed.locator.context_digest = B256::repeat_byte(4),
                2 => changed.locator.terminal_delayed_count += 1,
                3 => changed.locator.terminal_sequence += 1,
                4 => changed.locator.terminal_l2_block_number += 1,
                5 => changed.locator.terminal_l2_block_hash = B256::repeat_byte(5),
                _ => unreachable!(),
            }
            authority_mutations.push(seal_record(changed));
        }
        for (index, changed) in authority_mutations.into_iter().enumerate() {
            assert!(
                validate_bootstrap(changed, context().anchor, policy).is_err(),
                "bootstrap semantic mutation {index}"
            );
        }

        let locator = locator(context().anchor, 0);
        let mut invalid_locators = Vec::new();
        let mut changed = locator;
        changed.context_id = 0;
        invalid_locators.push(changed);
        let mut changed = locator;
        changed.safe_l1_hash = B256::ZERO;
        invalid_locators.push(changed);
        let mut changed = locator;
        changed.containing_l1_hash = B256::ZERO;
        invalid_locators.push(changed);
        let mut changed = locator;
        changed.posting_transaction_hash = B256::ZERO;
        invalid_locators.push(changed);
        let mut changed = locator;
        changed.containing_l1_number = changed.safe_l1_number + 1;
        invalid_locators.push(changed);
        let mut changed = locator;
        changed.decoded_message_count = 0;
        invalid_locators.push(changed);
        let mut changed = locator;
        changed.terminal_message_ordinal = changed.decoded_message_count;
        invalid_locators.push(changed);
        for (index, changed) in invalid_locators.into_iter().enumerate() {
            assert!(
                decode_locator(&encode_locator(changed)).is_err(),
                "locator semantic mutation {index}"
            );
        }

        let header = JournalHeader {
            lineage_generation: 1,
            snapshot_through_operation_generation: 1,
            predecessor_file_root: B256::repeat_byte(9),
            anchor: context().anchor,
            storage_context_digest: context().digest(),
        };
        let base = empty_snapshot_state();
        let mut snapshot_mutations = Vec::new();
        let mut changed = base.clone();
        changed.v = Some(context().anchor);
        snapshot_mutations.push(changed);
        let mut changed = base.clone();
        changed.bootstrap = Some(bootstrap());
        snapshot_mutations.push(changed);
        let mut changed = base.clone();
        changed.authority_operation_count = 1;
        snapshot_mutations.push(changed);
        let mut changed = base.clone();
        changed.latest_authority_id = B256::repeat_byte(1);
        snapshot_mutations.push(changed);
        let mut changed = base.clone();
        changed.latest_authority_chain_digest = B256::repeat_byte(2);
        snapshot_mutations.push(changed);
        let mut changed = base.clone();
        changed.source_v = Some(1);
        snapshot_mutations.push(changed);
        let mut changed = base.clone();
        changed.source_j = 1;
        snapshot_mutations.push(changed);
        let mut changed = base.clone();
        changed.source_latest_authority_id = B256::repeat_byte(3);
        snapshot_mutations.push(changed);
        let mut changed = base.clone();
        changed.truncation_target_authority_id = B256::repeat_byte(4);
        snapshot_mutations.push(changed);
        let mut changed = base.clone();
        changed.truncation_plan_digest = B256::repeat_byte(5);
        snapshot_mutations.push(changed);
        let mut changed = base.clone();
        changed.removed_identity_count = 1;
        snapshot_mutations.push(changed);
        let mut changed = base.clone();
        changed.removed_identities_digest = B256::repeat_byte(6);
        snapshot_mutations.push(changed);
        let mut changed = base.clone();
        changed.source_authority_chain_digest = B256::repeat_byte(7);
        snapshot_mutations.push(changed);
        let mut changed = base;
        changed.source_authority_operation_count = 1;
        snapshot_mutations.push(changed);
        for (index, changed) in snapshot_mutations.iter().enumerate() {
            assert!(
                validate_snapshot_state(header, changed, policy, None).is_err(),
                "snapshot semantic mutation {index}"
            );
        }
    }

    #[test]
    fn off_grid_v_and_repeated_compaction_preserve_exact_state() {
        let contexts = [canonical_context()];
        let certificates = [bootstrap_certificate_digest(bootstrap())];
        let policy = policy(&contexts, &certificates);
        let dir = tempfile::tempdir().unwrap();
        let directory = JournalDirectory::open(dir.path()).unwrap();
        let mut source = initialize_with_bootstrap(&directory, Vec::new(), policy);
        let retained = entries(300);
        let name = exact_journal_name(0, "log");
        let mut file = directory.open_existing(&name, true, true).unwrap();
        for identity in &retained {
            let generation = source.last_operation_generation + 1;
            let frame = encode_frame(
                FrameKind::Executed,
                generation,
                source.last_commit_digest,
                &encode_identity(*identity),
            )
            .unwrap();
            file.write_all(&frame).unwrap();
            source.last_operation_generation = generation;
            source.last_commit_digest = decode_complete_frame(&frame).unwrap().commit_digest;
        }
        let state = bootstrap_state(retained);
        let (promotion, frame) = promotion_frame(
            &state,
            11,
            100,
            source.last_operation_generation + 1,
            source.last_commit_digest,
        );
        file.write_all(&frame).unwrap();
        file.sync_all().unwrap();
        drop(file);
        source = inspect_message_with_policy(&directory, context(), policy).unwrap();
        assert_eq!(source.v.unwrap().sequence, 110);
        assert!(source.retained_grid.is_empty());
        assert_eq!(source.latest_authority_id, promotion.authority_id);
        let expected_entries = source.entries.clone();
        let expected_j = source.watermark;
        let expected_v = source.v;
        let expected_bootstrap = source.state.bootstrap;
        let expected_latest = (
            source.latest_authority_id,
            source.latest_authority_chain_digest,
            source.authority_operation_count,
        );
        for generation in 1..=3 {
            compact_lineage(&directory, context(), &mut source, policy).unwrap();
            assert_eq!(source.header.lineage_generation, generation);
            assert_eq!(source.entries, expected_entries);
            assert_eq!(source.watermark, expected_j);
            assert_eq!(source.v, expected_v);
            assert_eq!(source.state.bootstrap, expected_bootstrap);
            assert_eq!(
                (
                    source.latest_authority_id,
                    source.latest_authority_chain_digest,
                    source.authority_operation_count,
                ),
                expected_latest
            );
            assert!(source.retained_grid.is_empty());
        }
    }

    #[test]
    fn grid_window_and_capacity_equations_are_frozen() {
        assert_eq!(retained_grid_range(10, 10).unwrap(), None);
        assert_eq!(retained_grid_range(10, 265).unwrap(), None);
        assert_eq!(retained_grid_range(10, 266).unwrap(), Some((266, 266)));
        assert_eq!(retained_grid_range(10, 8_202).unwrap(), Some((266, 8_202)));
        assert_eq!(retained_grid_range(10, 8_458).unwrap(), Some((266, 8_458)));
        assert_eq!(retained_grid_range(10, 8_459).unwrap(), Some((266, 8_458)));
        let (first, latest) = retained_grid_range(10, 8_714).unwrap().unwrap();
        assert_eq!((latest - first) / 256 + 1, 34);
        assert_eq!(first, 266, "exact 8192-window predecessor changed");
        assert_eq!(latest, 8_714);
        assert_eq!(34 + 1, 35, "positive grid plus bootstrap cap changed");
        assert!(retained_grid_range(11, 10).is_err());
        assert_eq!(retained_grid_range(u64::MAX, u64::MAX).unwrap(), None);
        assert_eq!(retained_grid_range(u64::MAX - 255, u64::MAX).unwrap(), None);
        assert_eq!(
            retained_grid_range(u64::MAX - 256, u64::MAX).unwrap(),
            Some((u64::MAX, u64::MAX))
        );
        assert_eq!(
            retained_grid_range(u64::MAX - 512, u64::MAX).unwrap(),
            Some((u64::MAX - 256, u64::MAX))
        );
        let (first, latest) = retained_grid_range(10, 100_000).unwrap().unwrap();
        assert!((latest - first) / 256 < 34);

        let overflow_anchor = MessageJournalAnchor {
            sequence: u64::MAX,
            block_number: u64::MAX,
            block_hash: B256::repeat_byte(1),
        };
        assert!(
            validate_identity_chain(
                overflow_anchor,
                &[MessageJournalEntry {
                    sequence: 0,
                    block_number: 0,
                    block_hash: B256::repeat_byte(2),
                    parent_hash: overflow_anchor.block_hash,
                    delayed_messages_read: 0,
                    fingerprint: ArbMessageFingerprint {
                        core: B256::ZERO,
                        enrichment: ArbMessageEnrichment {
                            legacy_batch_gas_cost: None,
                            batch_data_stats: None,
                        },
                    },
                    source: ArbEngineInputSource::Feed,
                }],
                0,
            )
            .is_err()
        );

        assert_eq!(
            SNAPSHOT_PREFIX_LEN
                + JOURNAL_HARD_IDENTITY_LIMIT * IDENTITY_LEN
                + AUTHORITY_RECORD_LEN
                + MAX_GRID_RECORDS * GRID_RECORD_LEN,
            EXACT_MAX_COMPACT_PAYLOAD
        );
        assert_eq!(
            HEADER_LEN + FRAME_STORAGE_OVERHEAD + EXACT_MAX_COMPACT_PAYLOAD,
            EXACT_MAX_COMPACT_FILE
        );
        assert_eq!(
            EXACT_MAX_COMPACT_FILE * 2
                + MAX_AUTHORITY_FRAME_LEN * 2
                + 1_022 * EXECUTED_LIABILITY_BYTES
                + JOURNAL_STREAM_SCRATCH,
            EXACT_MAX_ENCODED_LIABILITY
        );
        assert_eq!(
            JOURNAL_OUTSTANDING_BYTE_CAPACITY - EXACT_MAX_ENCODED_LIABILITY,
            EXACT_LIABILITY_HEADROOM
        );
        assert!(authority_storage_charge(0).is_err());
        assert!(authority_storage_charge(AUTHORITY_MAX_RECORDS + 1).is_err());
        for records in [1usize, AUTHORITY_MAX_RECORDS] {
            let frame_len = FRAME_STORAGE_OVERHEAD + AUTHORITY_RECORD_LEN + records * IDENTITY_LEN;
            let charge = authority_storage_charge(records).unwrap();
            assert_eq!(
                charge,
                if records == AUTHORITY_MAX_RECORDS {
                    MAX_AUTHORITY_FRAME_LEN * 2
                } else {
                    (FRAME_STORAGE_OVERHEAD + AUTHORITY_RECORD_LEN + IDENTITY_LEN) * 2
                }
            );
            assert_eq!(charge, frame_len * 2);
            let admission = Arc::new(Admission {
                state: Mutex::new(AdmissionState {
                    work: JOURNAL_WORK_ITEM_CAPACITY - PROTECTED_EXECUTION_WORK_FLOOR - 1,
                    records: JOURNAL_RECORD_LIABILITY_CAPACITY
                        - PROTECTED_EXECUTION_RECORD_FLOOR
                        - records,
                    bytes: JOURNAL_OUTSTANDING_BYTE_CAPACITY - charge,
                }),
                closed: AtomicBool::new(false),
                journaled_sequence: AtomicU64::new(0),
                retained_identities: AtomicU64::new(0),
                notify: Notify::new(),
            });
            let reservation = admission
                .try_reserve_authority_storage(records)
                .unwrap()
                .expect("exact authority reservation boundary");
            let state = admission
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert_eq!(
                (state.work, state.records, state.bytes),
                (
                    JOURNAL_WORK_ITEM_CAPACITY - PROTECTED_EXECUTION_WORK_FLOOR,
                    JOURNAL_RECORD_LIABILITY_CAPACITY - PROTECTED_EXECUTION_RECORD_FLOOR,
                    JOURNAL_OUTSTANDING_BYTE_CAPACITY,
                )
            );
            drop(state);
            drop(reservation);

            for (blocked, closed) in [
                (AdmissionState::default(), true),
                (
                    AdmissionState {
                        work: JOURNAL_WORK_ITEM_CAPACITY - PROTECTED_EXECUTION_WORK_FLOOR,
                        records: 0,
                        bytes: 0,
                    },
                    false,
                ),
                (
                    AdmissionState {
                        work: 0,
                        records: JOURNAL_RECORD_LIABILITY_CAPACITY
                            - PROTECTED_EXECUTION_RECORD_FLOOR
                            - records
                            + 1,
                        bytes: 0,
                    },
                    false,
                ),
                (
                    AdmissionState {
                        work: 0,
                        records: 0,
                        bytes: JOURNAL_OUTSTANDING_BYTE_CAPACITY - charge + 1,
                    },
                    false,
                ),
            ] {
                let before = (blocked.work, blocked.records, blocked.bytes);
                let admission = Arc::new(Admission {
                    state: Mutex::new(blocked),
                    closed: AtomicBool::new(closed),
                    journaled_sequence: AtomicU64::new(0),
                    retained_identities: AtomicU64::new(0),
                    notify: Notify::new(),
                });
                assert!(
                    admission
                        .try_reserve_authority_storage(records)
                        .unwrap()
                        .is_none()
                );
                let state = admission
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                assert_eq!((state.work, state.records, state.bytes), before);
            }
        }
        validate_runtime_capacity(256, 256, 512).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let directory = JournalDirectory::open(dir.path()).unwrap();
        let mut operation_wrap = initialize_journal_v3(&directory, context()).unwrap();
        let original = std::fs::read(&operation_wrap.path).unwrap();
        operation_wrap.last_operation_generation = u64::MAX;
        assert!(
            append_entry(&directory, context(), &mut operation_wrap, entries(1)[0],)
                .unwrap_err()
                .to_string()
                .contains("operation generation wrap")
        );
        assert_eq!(std::fs::read(&operation_wrap.path).unwrap(), original);

        operation_wrap.header.lineage_generation = u64::MAX;
        assert!(
            compact_lineage(
                &directory,
                context(),
                &mut operation_wrap,
                PRODUCTION_POLICY
            )
            .unwrap_err()
            .to_string()
            .contains("lineage generation wrap")
        );
        assert_eq!(std::fs::read(&operation_wrap.path).unwrap(), original);
    }

    #[test]
    fn physical_tail_lengths_and_conflicting_artifacts_fail_closed() {
        for length in 1..=39 {
            assert!(validate_partial_frame(&vec![0; length], 0, B256::ZERO).is_err());
        }
        let complete = encode_frame(
            FrameKind::Executed,
            1,
            B256::repeat_byte(1),
            &encode_identity(entries(1)[0]),
        )
        .unwrap();
        for length in 40..=96 {
            assert!(validate_partial_frame(&complete[..length], 1, B256::repeat_byte(1)).unwrap());
        }

        let dir = tempfile::tempdir().unwrap();
        let directory = JournalDirectory::open(dir.path()).unwrap();
        initialize_journal_v3(&directory, context()).unwrap();
        std::fs::write(
            dir.path().join(exact_journal_name(1, "tmp")),
            vec![0; HEADER_LEN],
        )
        .unwrap();
        assert!(inspect_stopped_message_journal(&directory, context()).is_err());
        std::fs::write(
            dir.path().join(exact_journal_name(2, "tmp")),
            vec![0; HEADER_LEN],
        )
        .unwrap();
        assert!(inspect_stopped_message_journal(&directory, context()).is_err());
    }

    #[test]
    fn recovery_truncation_uses_authenticated_grid_and_preserves_source() {
        let contexts = [canonical_context()];
        let certificates = [bootstrap_certificate_digest(bootstrap())];
        let policy = policy(&contexts, &certificates);
        let dir = tempfile::tempdir().unwrap();
        let directory = JournalDirectory::open(dir.path()).unwrap();
        let mut source = initialize_with_bootstrap(&directory, Vec::new(), policy);
        let name = exact_journal_name(0, "log");
        let mut file = directory.open_existing(&name, true, true).unwrap();
        let retained = entries(300);
        for identity in &retained {
            let generation = source.last_operation_generation + 1;
            let frame = encode_frame(
                FrameKind::Executed,
                generation,
                source.last_commit_digest,
                &encode_identity(*identity),
            )
            .unwrap();
            file.write_all(&frame).unwrap();
            source.last_operation_generation = generation;
            source.last_commit_digest = decode_complete_frame(&frame).unwrap().commit_digest;
        }
        let mut state = bootstrap_state(retained);
        let (promotion, frame) = promotion_frame(
            &state,
            11,
            256,
            source.last_operation_generation + 1,
            source.last_commit_digest,
        );
        apply_authority_frame(
            &mut state,
            &decode_complete_frame(&frame).unwrap(),
            policy,
            0,
        )
        .unwrap();
        file.write_all(&frame).unwrap();
        file.sync_all().unwrap();
        drop(file);

        let source = inspect_stopped_with_policy(&directory, context(), policy)
            .unwrap()
            .0;
        let source_name = source.path.file_name().unwrap().to_owned();
        let source_bytes = std::fs::read(&source.path).unwrap();
        let selected = create_recovery_truncation_with_policy(
            &directory,
            context(),
            source.file_root,
            RecoveryTargetV3::Grid {
                authority_id: promotion.authority_id,
            },
            B256::repeat_byte(0xaa),
            policy,
        )
        .unwrap();
        assert_eq!(selected.watermark.sequence, 266);
        assert_eq!(selected.v, Some(selected.watermark));
        assert_eq!(selected.authority_operation_count, 2);
        assert!(selected.recovery_truncation);
        assert_eq!(selected.retained_grid.len(), 1);
        assert_eq!(
            std::fs::read(dir.path().join(source_name)).unwrap(),
            source_bytes
        );
        assert!(
            inspect_message_with_policy(&directory, context(), policy)
                .unwrap_err()
                .downcast_ref::<B3RecoveryMarkerRequired>()
                .is_some()
        );
        assert!(
            create_recovery_truncation_with_policy(
                &directory,
                context(),
                selected.file_root,
                RecoveryTargetV3::Bootstrap {
                    authority_id: bootstrap().authority_id,
                },
                B256::repeat_byte(0xbb),
                policy,
            )
            .unwrap_err()
            .to_string()
            .contains("already a truncation lineage")
        );
    }

    #[test]
    fn recovery_rejects_a_historic_grid_record_omitted_by_its_source() {
        let contexts = [canonical_context()];
        let certificates = [bootstrap_certificate_digest(bootstrap())];
        let policy = policy(&contexts, &certificates);
        let dir = tempfile::tempdir().unwrap();
        let directory = JournalDirectory::open(dir.path()).unwrap();
        let mut source = initialize_with_bootstrap(&directory, Vec::new(), policy);
        let retained = entries(9_000);
        let mut logical = bootstrap_state(retained.clone());
        let source_name = exact_journal_name(0, "log");
        let mut file = directory.open_existing(&source_name, true, true).unwrap();
        for identity in retained {
            let generation = source.last_operation_generation + 1;
            let frame = encode_frame(
                FrameKind::Executed,
                generation,
                source.last_commit_digest,
                &encode_identity(identity),
            )
            .unwrap();
            file.write_all(&frame).unwrap();
            source.last_operation_generation = generation;
            source.last_commit_digest = decode_complete_frame(&frame).unwrap().commit_digest;
        }
        let mut omitted = None;
        for batch in 0..35u64 {
            let generation = source.last_operation_generation + 1;
            let (_, frame) = promotion_frame(
                &logical,
                11 + batch * 256,
                256,
                generation,
                source.last_commit_digest,
            );
            let decoded = decode_complete_frame(&frame).unwrap();
            apply_authority_frame(&mut logical, &decoded, policy, 0).unwrap();
            if batch == 0 {
                omitted = logical.grid.first().copied();
            }
            file.write_all(&frame).unwrap();
            source.last_operation_generation = generation;
            source.last_commit_digest = decoded.commit_digest;
        }
        file.sync_all().unwrap();
        drop(file);

        source = inspect_message_with_policy(&directory, context(), policy).unwrap();
        let omitted = omitted.expect("first positive grid record");
        assert_eq!(omitted.authority.end_sequence, 266);
        assert_eq!(source.retained_grid.len(), 34);
        assert!(source.retained_grid.iter().all(|record| record != &omitted));
        let target = source.retained_grid[0];
        let mut selected = create_recovery_truncation_with_policy(
            &directory,
            context(),
            source.file_root,
            RecoveryTargetV3::Grid {
                authority_id: target.authority.authority_id,
            },
            B256::repeat_byte(0xcc),
            policy,
        )
        .unwrap();
        validate_streamed_predecessor(&directory, &source_name, context(), policy, &selected)
            .unwrap();

        selected.retained_grid.insert(0, omitted);
        selected.state.grid.insert(0, omitted);
        assert!(
            validate_streamed_predecessor(&directory, &source_name, context(), policy, &selected,)
                .unwrap_err()
                .to_string()
                .contains("exact source subset")
        );
    }

    #[test]
    fn recovery_truncation_rejects_stale_nonretained_equal_j_and_zero_plan() {
        let contexts = [canonical_context()];
        let certificates = [bootstrap_certificate_digest(bootstrap())];
        let policy = policy(&contexts, &certificates);

        let promoted = tempfile::tempdir().unwrap();
        let promoted_directory = JournalDirectory::open(promoted.path()).unwrap();
        let (source, promotion) = initialize_promoted_source(&promoted_directory, policy);
        assert!(
            create_recovery_truncation_with_policy(
                &promoted_directory,
                context(),
                B256::repeat_byte(0xf1),
                RecoveryTargetV3::Grid {
                    authority_id: promotion.authority_id,
                },
                B256::repeat_byte(1),
                policy,
            )
            .is_err()
        );
        assert!(
            create_recovery_truncation_with_policy(
                &promoted_directory,
                context(),
                source.file_root,
                RecoveryTargetV3::Grid {
                    authority_id: B256::repeat_byte(0xf2),
                },
                B256::repeat_byte(1),
                policy,
            )
            .is_err()
        );
        assert!(
            create_recovery_truncation_with_policy(
                &promoted_directory,
                context(),
                source.file_root,
                RecoveryTargetV3::Grid {
                    authority_id: promotion.authority_id,
                },
                B256::ZERO,
                policy,
            )
            .is_err()
        );

        let bootstrap_target = tempfile::tempdir().unwrap();
        let bootstrap_directory = JournalDirectory::open(bootstrap_target.path()).unwrap();
        let mut bootstrap_source =
            initialize_with_bootstrap(&bootstrap_directory, Vec::new(), policy);
        let name = exact_journal_name(0, "log");
        let mut file = bootstrap_directory
            .open_existing(&name, true, true)
            .unwrap();
        for identity in entries(2) {
            let generation = bootstrap_source.last_operation_generation + 1;
            let frame = encode_frame(
                FrameKind::Executed,
                generation,
                bootstrap_source.last_commit_digest,
                &encode_identity(identity),
            )
            .unwrap();
            file.write_all(&frame).unwrap();
            bootstrap_source.last_operation_generation = generation;
            bootstrap_source.last_commit_digest =
                decode_complete_frame(&frame).unwrap().commit_digest;
        }
        file.sync_all().unwrap();
        drop(file);
        bootstrap_source =
            inspect_message_with_policy(&bootstrap_directory, context(), policy).unwrap();
        let selected = create_recovery_truncation_with_policy(
            &bootstrap_directory,
            context(),
            bootstrap_source.file_root,
            RecoveryTargetV3::Bootstrap {
                authority_id: bootstrap().authority_id,
            },
            B256::repeat_byte(2),
            policy,
        )
        .unwrap();
        assert_eq!(selected.header.lineage_generation, 1);
        assert_eq!(selected.watermark, context().anchor);
        assert_eq!(selected.v, Some(context().anchor));
        assert!(selected.entries.is_empty());
        assert!(selected.retained_grid.is_empty());

        let equal_j = tempfile::tempdir().unwrap();
        let equal_j_directory = JournalDirectory::open(equal_j.path()).unwrap();
        let mut equal_j_source = initialize_with_bootstrap(&equal_j_directory, Vec::new(), policy);
        let retained = entries(256);
        let name = exact_journal_name(0, "log");
        let mut file = equal_j_directory.open_existing(&name, true, true).unwrap();
        for identity in &retained {
            let generation = equal_j_source.last_operation_generation + 1;
            let frame = encode_frame(
                FrameKind::Executed,
                generation,
                equal_j_source.last_commit_digest,
                &encode_identity(*identity),
            )
            .unwrap();
            file.write_all(&frame).unwrap();
            equal_j_source.last_operation_generation = generation;
            equal_j_source.last_commit_digest =
                decode_complete_frame(&frame).unwrap().commit_digest;
        }
        let state = bootstrap_state(retained);
        let (at_j, frame) = promotion_frame(
            &state,
            11,
            256,
            equal_j_source.last_operation_generation + 1,
            equal_j_source.last_commit_digest,
        );
        file.write_all(&frame).unwrap();
        file.sync_all().unwrap();
        drop(file);
        equal_j_source =
            inspect_message_with_policy(&equal_j_directory, context(), policy).unwrap();
        assert_eq!(equal_j_source.v, Some(equal_j_source.watermark));
        assert!(
            create_recovery_truncation_with_policy(
                &equal_j_directory,
                context(),
                equal_j_source.file_root,
                RecoveryTargetV3::Grid {
                    authority_id: at_j.authority_id,
                },
                B256::repeat_byte(3),
                policy,
            )
            .is_err()
        );
    }
}
