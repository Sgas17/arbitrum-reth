//! Transactional phase-A message journal.
//!
//! The authority format is deliberately independent of serde and native layouts. A single worker
//! owns the selected lineage. Producers reserve bounded liability before execution and enqueue one
//! immutable identity after canonical-memory settlement. The worker appends only after the
//! persistence proxy has reported the exact committed `(number, hash)` identity.

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
use alloy_primitives::{B256, Keccak256, keccak256};
use eyre::{WrapErr as _, ensure, eyre};
use tokio::sync::Notify;

use crate::{ArbEngineInput, ArbEngineInputSource, ArbMessageEnrichment, ArbMessageFingerprint};

pub const MESSAGE_JOURNAL_PREFIX: &str = "arb-message-journal-v2-g";
pub const MESSAGE_JOURNAL_V1_FILE: &str = "arb-message-journal.ndjson";
pub const DIVERGENCE_MARKER_FILE: &str = "arb-message-divergence.json";
pub const LIFECYCLE_FILE: &str = "arb-node-lifecycle-v1.bin";

pub const JOURNAL_WORK_ITEM_CAPACITY: usize = 1_024;
pub const JOURNAL_RECORD_LIABILITY_CAPACITY: usize = 4_096;
pub const JOURNAL_OUTSTANDING_BYTE_CAPACITY: usize = 64 * 1024 * 1024;
pub const PROTECTED_EXECUTION_WORK_FLOOR: usize = 1;
pub const PROTECTED_EXECUTION_RECORD_FLOOR: usize = 1;
pub const MAX_UNJOURNALED_SEQUENCE_DISTANCE: u64 = 1_024;
pub const MAX_SUPPORTED_PERSISTENCE_THRESHOLD: u64 = 512;
pub const PROMOTION_MAX_RECORDS: usize = 256;
pub const PROMOTION_MAX_ENCODED_BYTES: usize = 1024 * 1024;
pub const MAINTENANCE_WORK_ITEMS: usize = 1;
pub const MAINTENANCE_MAX_WAIT: Duration = Duration::from_secs(30);
pub const JOURNAL_COMPACT_MIN_IDENTITIES: usize = 100_000;
pub const JOURNAL_COMPACT_DELTA_TRIGGER: usize = 10_000;
pub const JOURNAL_HARD_IDENTITY_LIMIT: usize = 110_000;
pub const JOURNAL_STREAM_SCRATCH: usize = 1024 * 1024;

const HEADER_LEN: usize = 160;
const FRAME_PREFIX_LEN: usize = 40;
const FRAME_OVERHEAD_AFTER_LENGTH: usize = 132;
const FRAME_STORAGE_OVERHEAD: usize = 136;
const IDENTITY_LEN: usize = 192;
const CHECKPOINT_LEN: usize = 272;
const SNAPSHOT_FIXED_LEN: usize = 36;
const MAX_PAYLOAD_LEN: usize = SNAPSHOT_FIXED_LEN + JOURNAL_HARD_IDENTITY_LIMIT * IDENTITY_LEN;
const EXECUTED_STORAGE_LEN: usize = FRAME_STORAGE_OVERHEAD + IDENTITY_LEN;
const EXECUTED_LIABILITY_BYTES: usize = EXECUTED_STORAGE_LEN * 2;
const MAX_COMPACTED_FILE_LEN: usize = HEADER_LEN + FRAME_STORAGE_OVERHEAD + MAX_PAYLOAD_LEN;
const MAX_APPEND_LINEAGE_LEN: u64 = (HEADER_LEN + FRAME_STORAGE_OVERHEAD + SNAPSHOT_FIXED_LEN)
    as u64
    + JOURNAL_HARD_IDENTITY_LIMIT as u64 * EXECUTED_STORAGE_LEN as u64;

const JOURNAL_MAGIC: &[u8; 16] = b"ARBJOURNALV2\0\0\0\0";
const FRAME_MAGIC: u64 = 0x4152_424a_4652_414d;
const COMMIT_MAGIC: u64 = 0x4152_424a_434f_4d54;
const SCHEMA_VERSION: u16 = 2;

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
    fn renameat2(
        olddirfd: i32,
        oldpath: *const i8,
        newdirfd: i32,
        newpath: *const i8,
        flags: u32,
    ) -> i32;
    fn renameat(olddirfd: i32, oldpath: *const i8, newdirfd: i32, newpath: *const i8) -> i32;
    fn unlinkat(dirfd: i32, pathname: *const i8, flags: i32) -> i32;
    fn fsync(fd: i32) -> i32;
    fn lseek(fd: i32, offset: i64, whence: i32) -> i64;
    fn syscall(number: i64, ...) -> i64;
}

/// Debug-only tripwire used by the Feed-to-first-event mutation-resistant integration test.
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

/// Activates the authority-operation tripwire for one isolated debug test process.
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

/// One immutable open-file-description for every Phase-A authority entry in a datadir.
///
/// Production constructs this before lifecycle/journal classification and shares clones for the
/// process lifetime. Entry opens, creates, renames, and removals are all fixed-name `*at` calls
/// relative to this descriptor; the display path is never used for authority I/O.
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
                ensure!(
                    read - offset >= 19,
                    "getdents64 returned a truncated directory record"
                );
                let record_len =
                    u16::from_ne_bytes(buffer[offset + 16..offset + 18].try_into().unwrap())
                        as usize;
                ensure!(
                    record_len >= 20 && record_len <= read - offset,
                    "getdents64 returned an invalid directory record length"
                );
                let name_field = &buffer[offset + 19..offset + record_len];
                let name_len = name_field
                    .iter()
                    .position(|byte| *byte == 0)
                    .ok_or_else(|| eyre!("getdents64 record has no terminated name"))?;
                let name = std::str::from_utf8(&name_field[..name_len])
                    .map_err(|_| eyre!("non-UTF8 entry in authority datadir"))?;
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
        let flags =
            (if read { O_RDWR } else { O_WRONLY }) | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW;
        let fd = unsafe { openat(self.parent.as_raw_fd(), name.as_ptr(), flags, 0o600) };
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
            return Err(std::io::Error::last_os_error())
                .wrap_err("rename authority entry without replacement");
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageJournalAnchor {
    pub sequence: u64,
    pub block_number: u64,
    pub block_hash: B256,
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PromotionCheckpoint {
    pub observation_generation: u64,
    pub chain_id: u64,
    pub safe_l1_number: u64,
    pub safe_l1_hash: B256,
    pub safe_l1_parent_hash: B256,
    pub batch_sequence: u64,
    pub batch_before_acc: B256,
    pub batch_after_acc: B256,
    pub delayed_count: u64,
    pub delayed_acc: B256,
    pub start_sequence: u64,
    pub end_sequence: u64,
    pub end_l2_block_number: u64,
    pub end_l2_block_hash: B256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageJournalInspection {
    pub path: PathBuf,
    pub header: JournalHeader,
    pub entries: Vec<MessageJournalEntry>,
    pub watermark: MessageJournalAnchor,
    pub last_operation_generation: u64,
    pub last_commit_digest: B256,
    pub file_root: B256,
    pub complete_byte_offset: u64,
    pub has_authenticated_short_tail: bool,
}

#[derive(Clone, Copy)]
struct LineageSummary {
    header: JournalHeader,
    last_commit_digest: B256,
    file_root: B256,
    entry_count: usize,
    entry_digest: B256,
    watermark: MessageJournalAnchor,
}

impl LineageSummary {
    fn from_inspection(inspection: &MessageJournalInspection) -> Self {
        Self {
            header: inspection.header,
            last_commit_digest: inspection.last_commit_digest,
            file_root: inspection.file_root,
            entry_count: inspection.entries.len(),
            entry_digest: identity_digest(&inspection.entries),
            watermark: inspection.watermark,
        }
    }
}

impl MessageJournalInspection {
    pub fn anchor(&self) -> MessageJournalAnchor {
        self.header.anchor
    }

    pub fn entry(&self, sequence: u64) -> Option<MessageJournalEntry> {
        let offset = sequence
            .checked_sub(self.header.anchor.sequence)?
            .checked_sub(1)?;
        self.entries.get(usize::try_from(offset).ok()?).copied()
    }

    pub fn identity(&self, sequence: u64) -> Option<MessageJournalAnchor> {
        if sequence == self.header.anchor.sequence {
            return Some(self.header.anchor);
        }
        self.entry(sequence).map(|entry| MessageJournalAnchor {
            sequence,
            block_number: entry.block_number,
            block_hash: entry.block_hash,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum FrameKind {
    Executed = 1,
    PromoteWithCheckpoint = 2,
    Snapshot = 3,
}

impl TryFrom<u8> for FrameKind {
    type Error = eyre::Report;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Executed),
            2 => Ok(Self::PromoteWithCheckpoint),
            3 => Ok(Self::Snapshot),
            _ => Err(eyre!("unknown journal frame kind {value}")),
        }
    }
}

#[derive(Debug)]
struct DecodedFrame {
    kind: FrameKind,
    operation_generation: u64,
    previous_commit_digest: B256,
    payload: Vec<u8>,
    commit_digest: B256,
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
    let digest = keccak256(&out[..128]);
    out[128..].copy_from_slice(digest.as_slice());
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
        "invalid journal header length field"
    );
    ensure!(
        bytes[116..128].iter().all(|byte| *byte == 0),
        "nonzero journal header reserved bytes"
    );
    ensure!(
        keccak256(&bytes[..128]).as_slice() == &bytes[128..160],
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
    };
    if header.lineage_generation == 0 {
        ensure!(
            header.snapshot_through_operation_generation == 0
                && header.predecessor_file_root == B256::ZERO,
            "lineage zero has nonzero predecessor authority"
        );
    } else {
        ensure!(
            header.predecessor_file_root != B256::ZERO,
            "nonzero lineage has zero predecessor root"
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
    if let Some(value) = entry.fingerprint.enrichment.legacy_batch_gas_cost {
        out[120] = 1;
        put_u64(&mut out[121..129], value);
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
    // mode_epoch and safety_epoch are explicit zero in phase A; reserved bytes remain zero.
    out
}

pub fn decode_identity(bytes: &[u8]) -> eyre::Result<MessageJournalEntry> {
    ensure!(
        bytes.len() == IDENTITY_LEN,
        "identity length is not {IDENTITY_LEN}"
    );
    ensure!(
        matches!(bytes[120], 0 | 1),
        "invalid legacy-cost presence flag"
    );
    ensure!(
        matches!(bytes[129], 0 | 1),
        "invalid batch-stats presence flag"
    );
    ensure!(matches!(bytes[146], 0 | 1), "invalid identity source");
    ensure!(
        get_u64(&bytes[147..155]) == 0,
        "phase-A mode epoch is nonzero"
    );
    ensure!(
        get_u64(&bytes[155..163]) == 0,
        "phase-A safety epoch is nonzero"
    );
    ensure!(
        bytes[163..].iter().all(|byte| *byte == 0),
        "nonzero identity reserved bytes"
    );
    let legacy = get_u64(&bytes[121..129]);
    ensure!(
        bytes[120] == 1 || legacy == 0,
        "absent legacy cost is nonzero"
    );
    let stats = (get_u64(&bytes[130..138]), get_u64(&bytes[138..146]));
    ensure!(
        bytes[129] == 1 || stats == (0, 0),
        "absent batch stats are nonzero"
    );
    Ok(MessageJournalEntry {
        sequence: get_u64(&bytes[0..8]),
        block_number: get_u64(&bytes[8..16]),
        block_hash: B256::from_slice(&bytes[16..48]),
        parent_hash: B256::from_slice(&bytes[48..80]),
        delayed_messages_read: get_u64(&bytes[80..88]),
        fingerprint: ArbMessageFingerprint {
            core: B256::from_slice(&bytes[88..120]),
            enrichment: ArbMessageEnrichment {
                legacy_batch_gas_cost: (bytes[120] == 1).then_some(legacy),
                batch_data_stats: (bytes[129] == 1).then_some(stats),
            },
        },
        source: if bytes[146] == 0 {
            ArbEngineInputSource::Feed
        } else {
            ArbEngineInputSource::L1
        },
    })
}

fn identity_digest(entries: &[MessageJournalEntry]) -> B256 {
    let mut digest = Keccak256::new();
    for entry in entries.iter().copied() {
        digest.update(encode_identity(entry));
    }
    digest.finalize()
}

fn validate_payload_domain(kind: FrameKind, payload_len: usize) -> eyre::Result<()> {
    match kind {
        FrameKind::Executed => ensure!(
            payload_len == IDENTITY_LEN,
            "EXECUTED payload length is not 192"
        ),
        FrameKind::PromoteWithCheckpoint => ensure!(
            (CHECKPOINT_LEN + 2 + IDENTITY_LEN
                ..=CHECKPOINT_LEN + 2 + PROMOTION_MAX_RECORDS * IDENTITY_LEN)
                .contains(&payload_len)
                && (payload_len - CHECKPOINT_LEN - 2).is_multiple_of(IDENTITY_LEN),
            "PROMOTE_WITH_CHECKPOINT payload length is outside its exact domain"
        ),
        FrameKind::Snapshot => ensure!(
            (SNAPSHOT_FIXED_LEN..=MAX_PAYLOAD_LEN).contains(&payload_len)
                && (payload_len - SNAPSHOT_FIXED_LEN).is_multiple_of(IDENTITY_LEN),
            "SNAPSHOT payload length is outside its exact domain"
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
    let storage_len = FRAME_STORAGE_OVERHEAD
        .checked_add(payload.len())
        .ok_or_else(|| eyre!("frame storage length overflow"))?;
    let mut out = vec![0u8; storage_len];
    out[..96].copy_from_slice(&prelude);
    out[96..96 + payload.len()].copy_from_slice(payload);
    let commit_magic_start = 96 + payload.len();
    put_u64(
        &mut out[commit_magic_start..commit_magic_start + 8],
        COMMIT_MAGIC,
    );
    let commit_digest = keccak256(&out[..commit_magic_start + 8]);
    out[commit_magic_start + 8..].copy_from_slice(commit_digest.as_slice());
    Ok(out)
}

fn encode_frame_prelude(
    kind: FrameKind,
    operation_generation: u64,
    previous_commit_digest: B256,
    payload_len: usize,
) -> eyre::Result<[u8; 96]> {
    validate_payload_domain(kind, payload_len)?;
    let total_frame_length = FRAME_OVERHEAD_AFTER_LENGTH
        .checked_add(payload_len)
        .ok_or_else(|| eyre!("frame length overflow"))?;
    let total_frame_length = u32::try_from(total_frame_length)?;
    let payload_length = u32::try_from(payload_len)?;
    let mut out = [0u8; 96];
    put_u32(&mut out[0..4], total_frame_length);
    put_u32(&mut out[4..8], payload_length);
    let prefix_digest = keccak256(&out[..8]);
    out[8..40].copy_from_slice(prefix_digest.as_slice());
    put_u64(&mut out[40..48], FRAME_MAGIC);
    put_u16(&mut out[48..50], SCHEMA_VERSION);
    out[50] = kind as u8;
    out[51] = 0;
    put_u64(&mut out[52..60], operation_generation);
    out[60..92].copy_from_slice(previous_commit_digest.as_slice());
    put_u32(&mut out[92..96], payload_length);
    Ok(out)
}

fn decode_complete_frame(bytes: &[u8]) -> eyre::Result<DecodedFrame> {
    ensure!(
        bytes.len() >= FRAME_STORAGE_OVERHEAD,
        "complete frame is too short"
    );
    ensure!(
        keccak256(&bytes[..8]).as_slice() == &bytes[8..40],
        "invalid frame prefix digest"
    );
    let payload_len = get_u32(&bytes[4..8]) as usize;
    ensure!(
        payload_len <= MAX_PAYLOAD_LEN,
        "frame payload exceeds global maximum"
    );
    ensure!(
        get_u32(&bytes[0..4]) as usize == FRAME_OVERHEAD_AFTER_LENGTH + payload_len,
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
        "invalid frame commit magic"
    );
    ensure!(
        keccak256(&bytes[..commit_magic_start + 8]).as_slice() == &bytes[commit_magic_start + 8..],
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

fn decode_frame_prelude(bytes: &[u8; 96]) -> eyre::Result<(FrameKind, usize, u64, B256)> {
    ensure!(
        keccak256(&bytes[..8]).as_slice() == &bytes[8..40],
        "invalid frame prefix digest"
    );
    let payload_len = get_u32(&bytes[4..8]) as usize;
    ensure!(
        payload_len <= MAX_PAYLOAD_LEN,
        "frame payload exceeds global maximum"
    );
    ensure!(
        get_u32(&bytes[0..4]) as usize == FRAME_OVERHEAD_AFTER_LENGTH + payload_len,
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

fn validate_partial_frame(
    bytes: &[u8],
    expected_generation: u64,
    expected_previous_digest: B256,
) -> eyre::Result<bool> {
    if bytes.is_empty() {
        return Ok(false);
    }
    ensure!(
        bytes.len() >= FRAME_PREFIX_LEN,
        "unverifiable 1..39-byte journal tail"
    );
    ensure!(
        keccak256(&bytes[..8]).as_slice() == &bytes[8..40],
        "invalid short-tail prefix digest"
    );
    let payload_len = get_u32(&bytes[4..8]) as usize;
    ensure!(
        payload_len <= MAX_PAYLOAD_LEN,
        "short-tail payload exceeds global maximum"
    );
    ensure!(
        get_u32(&bytes[0..4]) as usize == FRAME_OVERHEAD_AFTER_LENGTH + payload_len,
        "invalid short-tail total length"
    );
    if bytes.len() >= 48 {
        ensure!(
            get_u64(&bytes[40..48]) == FRAME_MAGIC,
            "invalid short-tail frame magic"
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
            "invalid short-tail operation generation"
        );
    }
    if bytes.len() >= 92 {
        ensure!(
            B256::from_slice(&bytes[60..92]) == expected_previous_digest,
            "invalid short-tail predecessor digest"
        );
    }
    if bytes.len() >= 96 {
        ensure!(
            get_u32(&bytes[92..96]) as usize == payload_len,
            "short-tail inner length mismatch"
        );
    }
    let declared = FRAME_STORAGE_OVERHEAD
        .checked_add(payload_len)
        .ok_or_else(|| eyre!("short-tail declared length overflow"))?;
    ensure!(
        bytes.len() < declared,
        "partial-frame validator received a complete frame"
    );
    Ok(true)
}

fn encode_snapshot_payload(
    entries: &[MessageJournalEntry],
    summarized: B256,
) -> eyre::Result<Vec<u8>> {
    ensure!(
        entries.len() <= JOURNAL_HARD_IDENTITY_LIMIT,
        "snapshot identity limit exceeded"
    );
    let mut payload = vec![0u8; 4 + entries.len() * IDENTITY_LEN + 32];
    put_u32(&mut payload[..4], u32::try_from(entries.len())?);
    for (index, entry) in entries.iter().copied().enumerate() {
        let start = 4 + index * IDENTITY_LEN;
        payload[start..start + IDENTITY_LEN].copy_from_slice(&encode_identity(entry));
    }
    let end = payload.len();
    payload[end - 32..].copy_from_slice(summarized.as_slice());
    Ok(payload)
}

pub fn encode_promotion_payload(
    checkpoint: PromotionCheckpoint,
    entries: &[MessageJournalEntry],
) -> eyre::Result<Vec<u8>> {
    ensure!(
        (1..=PROMOTION_MAX_RECORDS).contains(&entries.len()),
        "promotion record count outside 1..=256"
    );
    ensure!(
        checkpoint
            .end_sequence
            .checked_sub(checkpoint.start_sequence)
            .and_then(|count| count.checked_add(1))
            == Some(entries.len() as u64),
        "promotion sequence range/count mismatch"
    );
    let mut payload = vec![0u8; CHECKPOINT_LEN + 2 + entries.len() * IDENTITY_LEN];
    put_u64(&mut payload[0..8], checkpoint.observation_generation);
    put_u64(&mut payload[8..16], checkpoint.chain_id);
    put_u64(&mut payload[16..24], checkpoint.safe_l1_number);
    payload[24..56].copy_from_slice(checkpoint.safe_l1_hash.as_slice());
    payload[56..88].copy_from_slice(checkpoint.safe_l1_parent_hash.as_slice());
    put_u64(&mut payload[88..96], checkpoint.batch_sequence);
    payload[96..128].copy_from_slice(checkpoint.batch_before_acc.as_slice());
    payload[128..160].copy_from_slice(checkpoint.batch_after_acc.as_slice());
    put_u64(&mut payload[160..168], checkpoint.delayed_count);
    payload[168..200].copy_from_slice(checkpoint.delayed_acc.as_slice());
    put_u64(&mut payload[200..208], checkpoint.start_sequence);
    put_u64(&mut payload[208..216], checkpoint.end_sequence);
    put_u64(&mut payload[216..224], checkpoint.end_l2_block_number);
    payload[224..256].copy_from_slice(checkpoint.end_l2_block_hash.as_slice());
    put_u16(
        &mut payload[CHECKPOINT_LEN..CHECKPOINT_LEN + 2],
        entries.len() as u16,
    );
    for (index, entry) in entries.iter().copied().enumerate() {
        let start = CHECKPOINT_LEN + 2 + index * IDENTITY_LEN;
        payload[start..start + IDENTITY_LEN].copy_from_slice(&encode_identity(entry));
    }
    Ok(payload)
}

fn decode_promotion_checkpoint(payload: &[u8]) -> eyre::Result<PromotionCheckpoint> {
    ensure!(
        payload.len() >= CHECKPOINT_LEN,
        "promotion checkpoint is truncated"
    );
    ensure!(
        payload[256..272].iter().all(|byte| *byte == 0),
        "promotion checkpoint reserved bytes are nonzero"
    );
    Ok(PromotionCheckpoint {
        observation_generation: get_u64(&payload[0..8]),
        chain_id: get_u64(&payload[8..16]),
        safe_l1_number: get_u64(&payload[16..24]),
        safe_l1_hash: B256::from_slice(&payload[24..56]),
        safe_l1_parent_hash: B256::from_slice(&payload[56..88]),
        batch_sequence: get_u64(&payload[88..96]),
        batch_before_acc: B256::from_slice(&payload[96..128]),
        batch_after_acc: B256::from_slice(&payload[128..160]),
        delayed_count: get_u64(&payload[160..168]),
        delayed_acc: B256::from_slice(&payload[168..200]),
        start_sequence: get_u64(&payload[200..208]),
        end_sequence: get_u64(&payload[208..216]),
        end_l2_block_number: get_u64(&payload[216..224]),
        end_l2_block_hash: B256::from_slice(&payload[224..256]),
    })
}

fn validate_entry(
    entry: MessageJournalEntry,
    previous: MessageJournalAnchor,
    genesis_block: u64,
) -> eyre::Result<MessageJournalAnchor> {
    let expected_sequence = previous
        .sequence
        .checked_add(1)
        .ok_or_else(|| eyre!("journal sequence overflow"))?;
    let expected_block = previous
        .block_number
        .checked_add(1)
        .ok_or_else(|| eyre!("journal block overflow"))?;
    ensure!(
        entry.sequence == expected_sequence,
        "journal sequence is not contiguous"
    );
    ensure!(
        entry.block_number == expected_block,
        "journal block number is not contiguous"
    );
    ensure!(
        entry.block_number
            == genesis_block
                .checked_add(entry.sequence)
                .ok_or_else(|| eyre!("genesis mapping overflow"))?,
        "journal genesis mapping mismatch"
    );
    ensure!(
        entry.parent_hash == previous.block_hash,
        "journal identity parent mismatch"
    );
    Ok(MessageJournalAnchor {
        sequence: entry.sequence,
        block_number: entry.block_number,
        block_hash: entry.block_hash,
    })
}

#[allow(clippy::too_many_arguments)]
fn apply_frame(
    frame: &DecodedFrame,
    header: JournalHeader,
    genesis_block: u64,
    entries: &mut Vec<MessageJournalEntry>,
    watermark: &mut MessageJournalAnchor,
    previous_generation: Option<u64>,
    previous_digest: B256,
    first_frame: bool,
    predecessor_verified: bool,
) -> eyre::Result<()> {
    validate_frame_chain(
        frame.kind,
        frame.operation_generation,
        frame.previous_commit_digest,
        header,
        previous_generation,
        previous_digest,
        first_frame,
        predecessor_verified,
    )?;

    match frame.kind {
        FrameKind::Executed => {
            ensure!(
                !first_frame,
                "lineage starts with EXECUTED instead of SNAPSHOT"
            );
            let entry = decode_identity(&frame.payload)?;
            *watermark = validate_entry(entry, *watermark, genesis_block)?;
            entries.push(entry);
        }
        FrameKind::PromoteWithCheckpoint => {
            validate_promotion_payload(&frame.payload, entries)?;
        }
        FrameKind::Snapshot => {
            ensure!(first_frame, "SNAPSHOT is not the first lineage frame");
            let count = get_u32(&frame.payload[..4]) as usize;
            ensure!(
                frame.payload.len() == SNAPSHOT_FIXED_LEN + count * IDENTITY_LEN,
                "SNAPSHOT count/length mismatch"
            );
            let summarized = B256::from_slice(&frame.payload[frame.payload.len() - 32..]);
            validate_snapshot_summary(
                count,
                summarized,
                frame.previous_commit_digest,
                header,
                previous_digest,
                predecessor_verified,
            )?;
            for index in 0..count {
                let start = 4 + index * IDENTITY_LEN;
                let entry = decode_identity(&frame.payload[start..start + IDENTITY_LEN])?;
                *watermark = validate_entry(entry, *watermark, genesis_block)?;
                entries.push(entry);
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_frame_chain(
    kind: FrameKind,
    operation_generation: u64,
    previous_commit_digest: B256,
    header: JournalHeader,
    previous_generation: Option<u64>,
    previous_digest: B256,
    first_frame: bool,
    predecessor_verified: bool,
) -> eyre::Result<()> {
    if first_frame && header.lineage_generation == 0 {
        ensure!(
            kind == FrameKind::Snapshot,
            "lineage zero does not start with SNAPSHOT"
        );
        ensure!(
            operation_generation == 0,
            "lineage-zero snapshot generation is not zero"
        );
        ensure!(
            previous_commit_digest == B256::ZERO,
            "lineage-zero snapshot predecessor digest is nonzero"
        );
    } else if first_frame {
        ensure!(
            kind == FrameKind::Snapshot,
            "compaction lineage does not start with SNAPSHOT"
        );
        ensure!(
            operation_generation == header.snapshot_through_operation_generation,
            "compaction snapshot generation mismatch"
        );
        if predecessor_verified {
            ensure!(
                previous_commit_digest == previous_digest,
                "compaction snapshot predecessor digest mismatch"
            );
        }
    } else {
        ensure!(
            operation_generation
                == previous_generation
                    .and_then(|value| value.checked_add(1))
                    .ok_or_else(|| eyre!("operation generation overflow"))?,
            "operation generation gap"
        );
        ensure!(
            previous_commit_digest == previous_digest,
            "previous commit digest mismatch"
        );
    }
    Ok(())
}

fn validate_snapshot_summary(
    count: usize,
    summarized: B256,
    frame_previous_digest: B256,
    header: JournalHeader,
    previous_digest: B256,
    predecessor_verified: bool,
) -> eyre::Result<()> {
    if header.lineage_generation == 0 {
        ensure!(
            count == 0 && summarized == B256::ZERO,
            "lineage-zero SNAPSHOT is not empty"
        );
    } else {
        ensure!(
            summarized == frame_previous_digest,
            "compaction summary digest does not match the frame predecessor",
        );
        if predecessor_verified {
            ensure!(
                summarized == previous_digest,
                "compaction summary digest mismatch"
            );
        }
    }
    Ok(())
}

fn validate_promotion_payload(
    payload: &[u8],
    entries: &mut [MessageJournalEntry],
) -> eyre::Result<()> {
    ensure!(
        payload.len() >= CHECKPOINT_LEN + 2 + IDENTITY_LEN,
        "promotion payload too short"
    );
    let checkpoint = decode_promotion_checkpoint(payload)?;
    let count = get_u16(&payload[CHECKPOINT_LEN..CHECKPOINT_LEN + 2]) as usize;
    ensure!(
        (1..=PROMOTION_MAX_RECORDS).contains(&count),
        "promotion record count outside 1..=256"
    );
    ensure!(
        payload.len() == CHECKPOINT_LEN + 2 + count * IDENTITY_LEN,
        "promotion count/length mismatch"
    );
    let start_sequence = checkpoint.start_sequence;
    let end_sequence = checkpoint.end_sequence;
    ensure!(
        end_sequence
            .checked_sub(start_sequence)
            .and_then(|n| n.checked_add(1))
            == Some(count as u64),
        "promotion sequence range/count mismatch"
    );
    let mut final_entry = None;
    for index in 0..count {
        let start = CHECKPOINT_LEN + 2 + index * IDENTITY_LEN;
        let entry = decode_identity(&payload[start..start + IDENTITY_LEN])?;
        ensure!(
            entry.source == ArbEngineInputSource::L1,
            "promotion identity is not L1 authority"
        );
        ensure!(
            entry.sequence == start_sequence + index as u64,
            "promotion records are not contiguous"
        );
        let existing = entries
            .iter_mut()
            .find(|existing| existing.sequence == entry.sequence)
            .ok_or_else(|| eyre!("promotion sequence {} is not retained", entry.sequence))?;
        ensure!(
            existing.block_number == entry.block_number
                && existing.block_hash == entry.block_hash
                && existing.parent_hash == entry.parent_hash
                && existing.delayed_messages_read == entry.delayed_messages_read
                && existing.fingerprint == entry.fingerprint,
            "promotion identity conflicts with retained sequence {}",
            entry.sequence,
        );
        ensure!(
            existing.source == ArbEngineInputSource::Feed,
            "promotion source transition is not Feed to L1 at sequence {}",
            entry.sequence,
        );
        existing.source = ArbEngineInputSource::L1;
        final_entry = Some(entry);
    }
    let final_entry = final_entry.expect("count is nonzero");
    ensure!(
        final_entry.sequence == end_sequence,
        "promotion final sequence mismatch"
    );
    ensure!(
        final_entry.block_number == checkpoint.end_l2_block_number,
        "promotion final block mismatch"
    );
    ensure!(
        final_entry.block_hash == checkpoint.end_l2_block_hash,
        "promotion final hash mismatch"
    );
    Ok(())
}

fn exact_journal_name(generation: u64, suffix: &str) -> String {
    format!("{MESSAGE_JOURNAL_PREFIX}{generation:020}.{suffix}")
}

fn parse_journal_name(name: &str) -> eyre::Result<Option<(u64, bool)>> {
    if !name.starts_with("arb-message-journal") {
        return Ok(None);
    }
    ensure!(
        name.starts_with(MESSAGE_JOURNAL_PREFIX),
        "unsupported or malformed message-journal artifact {name}"
    );
    let tail = &name[MESSAGE_JOURNAL_PREFIX.len()..];
    ensure!(
        tail.len() == 24,
        "malformed v2 journal generation in {name}"
    );
    let generation = &tail[..20];
    ensure!(
        generation.bytes().all(|byte| byte.is_ascii_digit()),
        "nondecimal v2 journal generation in {name}"
    );
    let generation = generation.parse::<u64>()?;
    let is_temp = match &tail[20..] {
        ".log" => false,
        ".tmp" => true,
        _ => return Err(eyre!("unknown v2 journal suffix in {name}")),
    };
    Ok(Some((generation, is_temp)))
}

fn read_exact_or_eof(file: &mut File, bytes: &mut [u8]) -> std::io::Result<usize> {
    let mut read = 0;
    while read < bytes.len() {
        match file.read(&mut bytes[read..])? {
            0 => break,
            count => read += count,
        }
    }
    Ok(read)
}

#[allow(clippy::too_many_arguments)]
fn inspect_streamed_snapshot(
    file: &mut File,
    prelude: &[u8; 96],
    header: JournalHeader,
    genesis_block: u64,
    entries: &mut Vec<MessageJournalEntry>,
    watermark: &mut MessageJournalAnchor,
    previous_generation: Option<u64>,
    previous_digest: B256,
    first_frame: bool,
    predecessor_verified: bool,
    root: &mut Keccak256,
) -> eyre::Result<(u64, B256)> {
    let (kind, payload_len, operation_generation, frame_previous_digest) =
        decode_frame_prelude(prelude)?;
    ensure!(
        kind == FrameKind::Snapshot,
        "only SNAPSHOT may exceed streaming scratch"
    );
    validate_frame_chain(
        kind,
        operation_generation,
        frame_previous_digest,
        header,
        previous_generation,
        previous_digest,
        first_frame,
        predecessor_verified,
    )?;

    let mut commit = Keccak256::new();
    commit.update(prelude);
    root.update(prelude);

    let mut count_bytes = [0u8; 4];
    file.read_exact(&mut count_bytes)?;
    commit.update(count_bytes);
    root.update(count_bytes);
    let count = get_u32(&count_bytes) as usize;
    ensure!(
        payload_len
            == SNAPSHOT_FIXED_LEN
                + count
                    .checked_mul(IDENTITY_LEN)
                    .ok_or_else(|| eyre!("SNAPSHOT count overflow"))?,
        "SNAPSHOT count/length mismatch"
    );
    let mut identity = [0u8; IDENTITY_LEN];
    for _ in 0..count {
        file.read_exact(&mut identity)?;
        commit.update(identity);
        root.update(identity);
        let entry = decode_identity(&identity)?;
        *watermark = validate_entry(entry, *watermark, genesis_block)?;
        entries.push(entry);
    }
    let mut summarized = [0u8; 32];
    file.read_exact(&mut summarized)?;
    commit.update(summarized);
    root.update(summarized);
    validate_snapshot_summary(
        count,
        B256::from(summarized),
        frame_previous_digest,
        header,
        previous_digest,
        predecessor_verified,
    )?;

    let mut commit_magic = [0u8; 8];
    file.read_exact(&mut commit_magic)?;
    ensure!(
        get_u64(&commit_magic) == COMMIT_MAGIC,
        "invalid frame commit magic"
    );
    commit.update(commit_magic);
    root.update(commit_magic);
    let expected_digest = commit.finalize();
    let mut digest = [0u8; 32];
    file.read_exact(&mut digest)?;
    root.update(digest);
    ensure!(
        expected_digest.as_slice() == digest,
        "invalid frame commit digest"
    );
    Ok((operation_generation, B256::from(digest)))
}

fn inspect_file(
    directory: &JournalDirectory,
    file_name: &str,
    genesis_block: u64,
    predecessor: Option<LineageSummary>,
) -> eyre::Result<MessageJournalInspection> {
    let path = directory.entry_path(file_name)?;
    let mut file = directory
        .open_existing(file_name, false, false)
        .wrap_err_with(|| format!("open journal {}", path.display()))?;
    let length = file.metadata()?.len();
    ensure!(
        length <= MAX_APPEND_LINEAGE_LEN,
        "journal exceeds absolute phase-A size bound"
    );
    let mut header_bytes = [0u8; HEADER_LEN];
    file.read_exact(&mut header_bytes)?;
    let header = decode_header(&header_bytes)?;
    ensure!(
        header.anchor.block_number
            == genesis_block
                .checked_add(header.anchor.sequence)
                .ok_or_else(|| eyre!("anchor mapping overflow"))?,
        "journal anchor/genesis mapping mismatch"
    );

    let predecessor_digest =
        predecessor.map_or(B256::ZERO, |inspection| inspection.last_commit_digest);
    if let Some(predecessor) = predecessor {
        ensure!(
            header.lineage_generation
                == predecessor
                    .header
                    .lineage_generation
                    .checked_add(1)
                    .ok_or_else(|| eyre!("journal lineage generation wrap"))?,
            "journal lineage generation gap"
        );
        ensure!(
            header.predecessor_file_root == predecessor.file_root,
            "journal predecessor root mismatch"
        );
        ensure!(
            header.anchor == predecessor.header.anchor,
            "phase-A compaction changed the anchor"
        );
    }
    let mut root = Keccak256::new();
    root.update(header_bytes);
    let mut complete_offset = HEADER_LEN as u64;
    let mut entries = Vec::new();
    let mut watermark = header.anchor;
    let mut last_generation: Option<u64> = None;
    let mut last_digest = predecessor_digest;
    let mut first_frame = true;
    let mut short_tail = false;
    loop {
        let expected_generation = if first_frame {
            header.snapshot_through_operation_generation
        } else {
            last_generation
                .expect("non-first frame has a generation")
                .checked_add(1)
                .ok_or_else(|| eyre!("operation generation wrap"))?
        };
        let frame_start = file.stream_position()?;
        let remaining = length.saturating_sub(frame_start);
        if remaining == 0 {
            break;
        }
        if remaining < FRAME_PREFIX_LEN as u64 {
            let mut tail = vec![0u8; remaining as usize];
            file.read_exact(&mut tail)?;
            validate_partial_frame(&tail, expected_generation, last_digest)?;
            unreachable!("tails shorter than 40 are rejected")
        }
        let mut prefix = [0u8; FRAME_PREFIX_LEN];
        file.read_exact(&mut prefix)?;
        validate_partial_frame(&prefix, expected_generation, last_digest)?;
        let payload_len = get_u32(&prefix[4..8]) as usize;
        let declared = FRAME_STORAGE_OVERHEAD
            .checked_add(payload_len)
            .ok_or_else(|| eyre!("declared frame storage length overflow"))?;
        if remaining < declared as u64 {
            let inspected = usize::try_from(remaining.min(96))?;
            let mut tail = [0u8; 96];
            tail[..FRAME_PREFIX_LEN].copy_from_slice(&prefix);
            read_exact_or_eof(&mut file, &mut tail[FRAME_PREFIX_LEN..inspected])?;
            ensure!(
                validate_partial_frame(&tail[..inspected], expected_generation, last_digest,)?,
                "expected authenticated short tail"
            );
            short_tail = true;
            break;
        }
        if declared > JOURNAL_STREAM_SCRATCH {
            let mut prelude = [0u8; 96];
            prelude[..FRAME_PREFIX_LEN].copy_from_slice(&prefix);
            file.read_exact(&mut prelude[FRAME_PREFIX_LEN..])?;
            let (operation_generation, commit_digest) = inspect_streamed_snapshot(
                &mut file,
                &prelude,
                header,
                genesis_block,
                &mut entries,
                &mut watermark,
                last_generation,
                last_digest,
                first_frame,
                predecessor.is_some(),
                &mut root,
            )?;
            complete_offset = complete_offset
                .checked_add(declared as u64)
                .ok_or_else(|| eyre!("journal offset overflow"))?;
            last_generation = Some(operation_generation);
            last_digest = commit_digest;
            first_frame = false;
            continue;
        }
        let mut frame_bytes = vec![0u8; declared];
        frame_bytes[..FRAME_PREFIX_LEN].copy_from_slice(&prefix);
        file.read_exact(&mut frame_bytes[FRAME_PREFIX_LEN..])?;
        let frame = decode_complete_frame(&frame_bytes)?;
        apply_frame(
            &frame,
            header,
            genesis_block,
            &mut entries,
            &mut watermark,
            last_generation,
            last_digest,
            first_frame,
            predecessor.is_some(),
        )?;
        root.update(&frame_bytes);
        complete_offset = complete_offset
            .checked_add(declared as u64)
            .ok_or_else(|| eyre!("journal offset overflow"))?;
        last_generation = Some(frame.operation_generation);
        last_digest = frame.commit_digest;
        first_frame = false;
    }
    ensure!(!first_frame, "journal lineage has no SNAPSHOT frame");
    let file_root = root.finalize();
    Ok(MessageJournalInspection {
        path,
        header,
        entries,
        watermark,
        last_operation_generation: last_generation.expect("at least one frame"),
        last_commit_digest: last_digest,
        file_root,
        complete_byte_offset: complete_offset,
        has_authenticated_short_tail: short_tail,
    })
}

pub fn inspect_message_journal(
    directory: &JournalDirectory,
    genesis_block: u64,
) -> eyre::Result<MessageJournalInspection> {
    let (inspection, recovery_required) =
        inspect_stopped_message_journal(directory, genesis_block)?;
    ensure!(
        !recovery_required,
        "journal transition requires disposable stopped recovery"
    );
    Ok(inspection)
}

#[allow(clippy::type_complexity)]
fn collect_journal_artifacts(
    directory: &JournalDirectory,
) -> eyre::Result<(BTreeMap<u64, String>, Vec<(u64, String)>)> {
    let mut finals = BTreeMap::<u64, String>::new();
    let mut temps = Vec::new();
    for name in directory.entry_names()? {
        if let Some((generation, temp)) = parse_journal_name(&name)? {
            let file = directory.open_existing(&name, false, false)?;
            ensure!(
                file.metadata()?.is_file(),
                "journal authority artifact is not a regular file"
            );
            drop(file);
            if temp {
                temps.push((generation, name));
            } else {
                ensure!(
                    finals.insert(generation, name).is_none(),
                    "duplicate journal lineage generation"
                );
            }
        }
    }
    Ok((finals, temps))
}

fn inspect_final_lineages(
    directory: &JournalDirectory,
    finals: &BTreeMap<u64, String>,
    genesis_block: u64,
) -> eyre::Result<MessageJournalInspection> {
    let (&highest, _) = finals
        .last_key_value()
        .ok_or_else(|| eyre!("v2 message journal is missing"))?;
    ensure!(
        highest == 0 || finals.contains_key(&(highest - 1)),
        "selected journal predecessor is missing"
    );
    let mut previous_generation: Option<u64> = None;
    let mut previous_summary = None;
    let mut selected = None;
    for (&generation, path) in finals {
        if let Some(previous) = previous_generation {
            ensure!(
                generation
                    == previous
                        .checked_add(1)
                        .ok_or_else(|| eyre!("journal cleanup lineage generation wrap"))?,
                "journal cleanup debris has a lineage gap"
            );
        }
        let inspection = inspect_file(directory, path, genesis_block, previous_summary)?;
        ensure!(
            inspection.header.lineage_generation == generation,
            "journal filename/header generation mismatch"
        );
        if let Some(predecessor) = previous_summary {
            ensure!(
                inspection.entries.len() >= predecessor.entry_count
                    && identity_digest(&inspection.entries[..predecessor.entry_count])
                        == predecessor.entry_digest,
                "compaction lineage changes predecessor authority"
            );
            ensure!(
                predecessor.entry_count == 0
                    || inspection.entries[predecessor.entry_count - 1].sequence
                        == predecessor.watermark.sequence,
                "compaction predecessor watermark is not retained"
            );
        }
        previous_generation = Some(generation);
        previous_summary = Some(LineageSummary::from_inspection(&inspection));
        if generation == highest {
            selected = Some(inspection);
        }
    }
    Ok(selected.expect("highest was inspected"))
}

/// Read-only stopped classifier. `true` means a complete frozen transition or authenticated short
/// tail must be repaired by a disposable process before ordinary startup can continue.
pub fn inspect_stopped_message_journal(
    directory: &JournalDirectory,
    genesis_block: u64,
) -> eyre::Result<(MessageJournalInspection, bool)> {
    let (finals, temps) = collect_journal_artifacts(directory)?;
    let mut selected = inspect_final_lineages(directory, &finals, genesis_block)?;
    if temps.is_empty() {
        let recovery_required = selected.has_authenticated_short_tail;
        return Ok((selected, recovery_required));
    }
    ensure!(
        !selected.has_authenticated_short_tail,
        "journal temp and selected short tail coexist"
    );
    ensure!(temps.len() == 1, "multiple journal temp artifacts");
    let (generation, path) = &temps[0];
    ensure!(
        *generation
            == selected
                .header
                .lineage_generation
                .checked_add(1)
                .ok_or_else(|| eyre!("journal lineage generation wrap"))?,
        "journal temp is not the exact next lineage"
    );
    let predecessor = LineageSummary::from_inspection(&selected);
    let selected_entry_count = selected.entries.len();
    let selected_entry_digest = identity_digest(&selected.entries);
    drop(std::mem::take(&mut selected.entries));
    let candidate = inspect_file(directory, path, genesis_block, Some(predecessor))?;
    ensure!(
        !candidate.has_authenticated_short_tail,
        "journal temp is incomplete"
    );
    ensure!(
        candidate.entries.len() == selected_entry_count
            && identity_digest(&candidate.entries) == selected_entry_digest
            && candidate.watermark == selected.watermark
            && candidate.last_operation_generation == selected.last_operation_generation,
        "journal temp does not preserve the selected authority"
    );
    selected.entries = candidate.entries;
    Ok((selected, true))
}

/// Finish exactly the transition accepted by [`inspect_stopped_message_journal`].
pub fn recover_stopped_message_journal(
    directory: &JournalDirectory,
    genesis_block: u64,
) -> eyre::Result<MessageJournalInspection> {
    let (selected, recovery_required) = inspect_stopped_message_journal(directory, genesis_block)?;
    ensure!(
        recovery_required,
        "stopped journal has no recoverable transition"
    );
    let (_, temps) = collect_journal_artifacts(directory)?;
    if temps.is_empty() {
        let file_name = selected
            .path
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| eyre!("selected journal has no fixed UTF-8 name"))?;
        let file = directory.open_existing(file_name, true, false)?;
        file.set_len(selected.complete_byte_offset)?;
        file.sync_data()?;
    } else {
        let (generation, temp) = &temps[0];
        let final_name = exact_journal_name(*generation, "log");
        directory.rename_noreplace(temp, &final_name)?;
        directory.sync_parent()?;
    }
    inspect_message_journal(directory, genesis_block)
}

pub fn initialize_journal_v2(
    directory: &JournalDirectory,
    anchor: MessageJournalAnchor,
) -> eyre::Result<MessageJournalInspection> {
    for name in directory.entry_names()? {
        if name.starts_with("arb-message-journal") {
            return Err(eyre!("message-journal artifact already exists"));
        }
    }
    let header = JournalHeader {
        lineage_generation: 0,
        snapshot_through_operation_generation: 0,
        predecessor_file_root: B256::ZERO,
        anchor,
    };
    let payload = encode_snapshot_payload(&[], B256::ZERO)?;
    let frame = encode_frame(FrameKind::Snapshot, 0, B256::ZERO, &payload)?;
    let name = exact_journal_name(0, "log");
    let mut file = directory.create_new(&name, false)?;
    file.write_all(&encode_header(header))?;
    file.write_all(&frame)?;
    file.sync_all()?;
    directory.sync_parent()?;
    let inspection = inspect_message_journal(directory, anchor.block_number - anchor.sequence)?;
    ensure!(
        inspection.complete_byte_offset == 332,
        "lineage-zero journal is not exactly 332 bytes"
    );
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
        "version": 2,
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
    directory.sync_parent()?;
    Ok(())
}

pub fn clear_divergence_marker_at(directory: &JournalDirectory) -> eyre::Result<()> {
    if directory.entry_exists(DIVERGENCE_MARKER_FILE)? {
        directory.remove_entry(DIVERGENCE_MARKER_FILE)?;
    }
    Ok(())
}

pub fn truncate_authenticated_short_tail(
    directory: &JournalDirectory,
    genesis_block: u64,
) -> eyre::Result<()> {
    let (inspection, recovery_required) =
        inspect_stopped_message_journal(directory, genesis_block)?;
    let (_, temps) = collect_journal_artifacts(directory)?;
    ensure!(
        recovery_required && temps.is_empty() && inspection.has_authenticated_short_tail,
        "selected journal has no authenticated short tail"
    );
    let reopened = recover_stopped_message_journal(directory, genesis_block)?;
    ensure!(
        !reopened.has_authenticated_short_tail,
        "short-tail truncation did not produce a complete lineage"
    );
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

struct MaintenanceReservation {
    admission: Arc<Admission>,
    bytes: usize,
}

impl Drop for MaintenanceReservation {
    fn drop(&mut self) {
        self.admission.retire(MAINTENANCE_WORK_ITEMS, 0, self.bytes);
    }
}

impl Drop for ExecutionReservation {
    fn drop(&mut self) {
        self.retire();
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
                .ok_or_else(|| eyre!("persistence acknowledgment has no captured identities"))?;
            ensure!(
                result == expected,
                "persistence result {result:?} does not match captured top {expected:?}"
            );
            ensure!(
                result.number >= state.frontier.number,
                "persisted frontier regressed from {} to {}",
                state.frontier.number,
                result.number
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
                            "captured identity conflicts at persisted frontier"
                        );
                    }
                    continue;
                }
                expected_number = expected_number
                    .checked_add(1)
                    .ok_or_else(|| eyre!("persisted number overflow"))?;
                ensure!(
                    identity.number == expected_number,
                    "captured persistence identities are not contiguous"
                );
                if let Some(existing) = state.exact.insert(identity.number, identity.hash) {
                    ensure!(
                        existing == identity.hash,
                        "captured same-height persistence conflict"
                    );
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
            state.fatal = Some(format!(
                "RemoveBlocksAbove changed exact D from {:?} to {:?}",
                state.frontier, result
            ));
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
            frontier: BlockNumHash {
                number: 0,
                hash: B256::ZERO,
            },
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
                        < (JOURNAL_HARD_IDENTITY_LIMIT as u64);
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
        let (tx, rx) = crossbeam_channel::bounded(1);
        self.work
            .send(Work::Drain(tx))
            .map_err(|_| eyre!("journal worker is stopped"))?;
        let watermark = rx
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
        assert_authority_operation_allowed("journal-worker-acknowledgement-wait");
        let (tx, rx) = crossbeam_channel::bounded(1);
        self.work
            .send_timeout(Work::Drain(tx), remaining_until(deadline)?)
            .map_err(|error| eyre!("journal drain enqueue missed terminal deadline: {error}"))?;
        let watermark = rx
            .recv_timeout(remaining_until(deadline)?)
            .map_err(|error| eyre!("journal drain missed terminal deadline: {error}"))??;
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

/// Checkout-local benchmark adapter over the complete production journal runtime.
///
/// Persistence acknowledgement and worker drain happen outside the measured reserve/enqueue
/// interval, but every accepted benchmark identity traverses the real worker append, sync, reread,
/// acknowledgment, compaction, and admission-retirement path.
#[doc(hidden)]
pub struct JournalBenchmarkAdapter {
    runtime: Option<JournalRuntime>,
    pressure: Vec<ExecutionReservation>,
    maximum_pressure: bool,
    first_sequence: u64,
}

impl JournalBenchmarkAdapter {
    pub async fn new(maximum_pressure: bool, directory: JournalDirectory) -> eyre::Result<Self> {
        let anchor = MessageJournalAnchor {
            sequence: 0,
            block_number: 0,
            block_hash: B256::ZERO,
        };
        initialize_journal_v2(&directory, anchor)?;
        let runtime = JournalRuntime::open(
            directory,
            0,
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
        let client = &self
            .runtime
            .as_ref()
            .expect("benchmark adapter is running")
            .client;
        let reservation = client.reserve_execution(entry.sequence).await?;
        client.enqueue_executed(entry, reservation)
    }

    pub async fn persist_and_drain(&mut self, entry: MessageJournalEntry) -> eyre::Result<()> {
        let runtime = self.runtime.as_ref().expect("benchmark adapter is running");
        let next_retained = runtime
            .client
            .admission
            .retained_identities
            .load(Ordering::Acquire)
            .checked_add(1)
            .ok_or_else(|| eyre!("benchmark retained identity overflow"))?;
        if compaction_due(usize::try_from(next_retained)?) {
            // Production maintenance must preserve the execution floor. Release one synthetic
            // pressure liability before D wakes the worker so compaction can reserve its slot.
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
            "benchmark worker did not publish the exact persisted identity"
        );
        self.rebalance_pressure(
            entry
                .sequence
                .checked_add(1)
                .ok_or_else(|| eyre!("benchmark sequence overflow"))?,
        )
        .await
    }

    async fn rebalance_pressure(&mut self, next_sequence: u64) -> eyre::Result<()> {
        let desired = if self.maximum_pressure {
            let retained = self
                .runtime
                .as_ref()
                .expect("benchmark adapter is running")
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
                .expect("benchmark adapter is running")
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
        let remaining = remaining_until(deadline)
            .wrap_err_with(|| format!("terminal deadline expired waiting for {name}"))?;
        std::thread::sleep(remaining.min(Duration::from_millis(1)));
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
        genesis_block: u64,
        initial_d: BlockNumHash,
    ) -> eyre::Result<Self> {
        let inspection = inspect_message_journal(&directory, genesis_block)?;
        ensure!(
            !inspection.has_authenticated_short_tail,
            "journal has an authenticated short tail requiring stopped recovery"
        );
        ensure!(
            (
                inspection.watermark.block_number,
                inspection.watermark.block_hash
            ) == (initial_d.number, initial_d.hash),
            "journal J does not equal startup D"
        );
        let file_name = inspection
            .path
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| eyre!("journal has no fixed UTF-8 name"))?;
        let root = hash_complete_file(&directory, file_name, inspection.complete_byte_offset)?;
        // Work and controls have independent bounded transports: all execution descriptors are
        // covered by the exact admission bound, while drain/stop cannot consume a reserved slot.
        let (work_tx, work_rx) = crossbeam_channel::bounded(JOURNAL_WORK_ITEM_CAPACITY);
        let (control_tx, control_rx) = crossbeam_channel::bounded(1);
        // Persistence wakeups are level-triggered through shared state, so one coalesced wake is
        // sufficient and cannot accumulate an unbounded notification backlog.
        let (wake_tx, wake_rx) = crossbeam_channel::bounded(1);
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
            work: work_tx,
            control: control_tx,
            admission: admission.clone(),
            fatal: fatal.clone(),
        };
        let persistence = PersistenceObserver {
            state: persistence_state.clone(),
            wake: wake_tx,
            admission: admission.clone(),
        };
        let worker = std::thread::Builder::new()
            .name("arb-journal-v2".into())
            .spawn(move || {
                run_worker(
                    directory,
                    inspection,
                    genesis_block,
                    work_rx,
                    control_rx,
                    wake_rx,
                    admission,
                    persistence_state,
                    fatal,
                    root,
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
        let (tx, rx) = crossbeam_channel::bounded(1);
        if self.client.control.send(Control::Stop(tx)).is_err() {
            worker
                .join()
                .map_err(|_| eyre!("journal worker panicked"))?;
            return Err(eyre!("journal worker stopped before shutdown"));
        }
        let result = rx
            .recv()
            .map_err(|_| eyre!("journal stop response dropped"));
        let joined = worker.join().map_err(|_| eyre!("journal worker panicked"));
        joined?;
        result?
    }

    pub fn shutdown(mut self) -> eyre::Result<()> {
        self.stop()
    }

    pub fn shutdown_until(mut self, deadline: tokio::time::Instant) -> eyre::Result<()> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        let (tx, rx) = crossbeam_channel::bounded(1);
        self.client
            .control
            .send_timeout(Control::Stop(tx), remaining_until(deadline)?)
            .map_err(|error| eyre!("journal stop enqueue missed terminal deadline: {error}"))?;
        let result = rx
            .recv_timeout(remaining_until(deadline)?)
            .map_err(|error| eyre!("journal stop missed terminal deadline: {error}"));
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

fn journal_io<T>(
    point: &str,
    operation: impl FnOnce() -> std::io::Result<T>,
) -> std::io::Result<T> {
    let configured = std::env::var("ARB_RETH_JOURNAL_IO_FAULT").ok();
    let injected = configured.as_deref().and_then(|value| {
        let mut fields = value.split(':');
        let configured_point = fields.next()?;
        let timing = fields.next()?;
        let errno = fields.next()?.parse::<i32>().ok()?;
        (fields.next().is_none() && configured_point == point).then_some((timing, errno))
    });
    if let Some(("before", errno)) = injected {
        return Err(std::io::Error::from_raw_os_error(errno));
    }
    let result = operation()?;
    if let Some(("after", errno)) = injected {
        return Err(std::io::Error::from_raw_os_error(errno));
    }
    Ok(result)
}

fn journal_crashpoint(point: &str) {
    if std::env::var_os("ARB_RETH_JOURNAL_CRASHPOINT").as_deref()
        == Some(std::ffi::OsStr::new(point))
    {
        unsafe extern "C" {
            fn _exit(status: i32) -> !;
        }
        // SAFETY: this production test seam intentionally simulates sudden process loss.
        unsafe { _exit(86) }
    }
}

fn hash_complete_file(
    directory: &JournalDirectory,
    file_name: &str,
    length: u64,
) -> eyre::Result<Keccak256> {
    let mut root = Keccak256::new();
    let mut reader = directory.open_existing(file_name, false, false)?;
    let mut scratch = vec![0u8; JOURNAL_STREAM_SCRATCH];
    let mut remaining = length;
    while remaining > 0 {
        let read_len = usize::try_from(remaining.min(scratch.len() as u64))?;
        reader.read_exact(&mut scratch[..read_len])?;
        root.update(&scratch[..read_len]);
        remaining -= read_len as u64;
    }
    Ok(root)
}

fn append_entry(
    directory: &JournalDirectory,
    inspection: &mut MessageJournalInspection,
    genesis_block: u64,
    entry: MessageJournalEntry,
    root: &mut Keccak256,
) -> eyre::Result<()> {
    validate_entry(entry, inspection.watermark, genesis_block)?;
    ensure!(
        inspection.entries.len() < JOURNAL_HARD_IDENTITY_LIMIT,
        "phase-A journal identity hard limit reached"
    );
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
    let file_name = inspection
        .path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| eyre!("selected journal has no fixed UTF-8 name"))?;
    let mut file = directory.open_existing(file_name, true, true)?;
    let offset = file.metadata()?.len();
    journal_crashpoint("append_before_write");
    let mut ambiguous_error = journal_io("append_write", || file.write_all(&frame)).err();
    journal_crashpoint("append_after_write");
    if let Err(error) = journal_io("append_flush", || file.flush()) {
        ambiguous_error.get_or_insert(error);
    }
    journal_crashpoint("append_after_flush");
    if let Err(error) = journal_io("append_sync", || file.sync_data()) {
        ambiguous_error.get_or_insert(error);
    }
    journal_crashpoint("append_after_sync");
    let mut reread = vec![0u8; frame.len()];
    file.seek(SeekFrom::Start(offset))?;
    if let Err(error) = journal_io("append_reread", || file.read_exact(&mut reread)) {
        ambiguous_error.get_or_insert(error);
    }
    journal_crashpoint("append_after_reread");
    if reread != frame {
        return Err(ambiguous_error
            .map(eyre::Report::new)
            .unwrap_or_else(|| eyre!("journal append reread mismatch")));
    }
    let decoded = decode_complete_frame(&reread)?;
    ensure!(
        decoded.operation_generation == generation,
        "journal append generation changed on reread"
    );
    if let Some(error) = ambiguous_error {
        return Err(error.into());
    }
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
    root.update(&reread);
    inspection.file_root = root.clone().finalize();
    Ok(())
}

fn compact_lineage(
    directory: &JournalDirectory,
    genesis_block: u64,
    inspection: &mut MessageJournalInspection,
    root: &mut Keccak256,
) -> eyre::Result<()> {
    journal_crashpoint("compaction_before_seal");
    let old_lineage = inspection.header.lineage_generation;
    let next_lineage = inspection
        .header
        .lineage_generation
        .checked_add(1)
        .ok_or_else(|| eyre!("journal lineage generation wrap"))?;
    let header = JournalHeader {
        lineage_generation: next_lineage,
        snapshot_through_operation_generation: inspection.last_operation_generation,
        predecessor_file_root: inspection.file_root,
        anchor: inspection.header.anchor,
    };
    let payload_len = SNAPSHOT_FIXED_LEN
        .checked_add(
            inspection
                .entries
                .len()
                .checked_mul(IDENTITY_LEN)
                .ok_or_else(|| eyre!("compaction payload length overflow"))?,
        )
        .ok_or_else(|| eyre!("compaction payload length overflow"))?;
    let prelude = encode_frame_prelude(
        FrameKind::Snapshot,
        inspection.last_operation_generation,
        inspection.last_commit_digest,
        payload_len,
    )?;
    journal_crashpoint("compaction_after_seal");
    let temp_name = exact_journal_name(next_lineage, "tmp");
    let final_name = exact_journal_name(next_lineage, "log");
    ensure!(
        !directory.entry_exists(&final_name)?,
        "next journal lineage final already exists"
    );
    let mut file = directory.create_new(&temp_name, false)?;
    journal_io("compaction_write", || {
        file.write_all(&encode_header(header))
    })?;
    let mut commit = Keccak256::new();
    file.write_all(&prelude)?;
    commit.update(prelude);
    let count = u32::try_from(inspection.entries.len())?.to_be_bytes();
    file.write_all(&count)?;
    commit.update(count);
    for entry in inspection.entries.iter().copied() {
        let encoded = encode_identity(entry);
        file.write_all(&encoded)?;
        commit.update(encoded);
    }
    file.write_all(inspection.last_commit_digest.as_slice())?;
    commit.update(inspection.last_commit_digest.as_slice());
    let commit_magic = COMMIT_MAGIC.to_be_bytes();
    file.write_all(&commit_magic)?;
    commit.update(commit_magic);
    let commit_digest = commit.finalize();
    file.write_all(commit_digest.as_slice())?;
    journal_crashpoint("compaction_after_temp_write");
    journal_io("compaction_flush", || file.flush())?;
    journal_crashpoint("compaction_after_temp_flush");
    journal_io("compaction_sync", || file.sync_all())?;
    journal_crashpoint("compaction_after_temp_sync");
    drop(file);

    let predecessor = LineageSummary::from_inspection(inspection);
    let expected_entry_count = inspection.entries.len();
    let expected_entry_digest = identity_digest(&inspection.entries);
    let expected_watermark = inspection.watermark;
    drop(std::mem::take(&mut inspection.entries));
    let candidate = inspect_file(directory, &temp_name, genesis_block, Some(predecessor))?;
    journal_crashpoint("compaction_after_temp_reread");
    ensure!(
        candidate.entries.len() == expected_entry_count
            && identity_digest(&candidate.entries) == expected_entry_digest,
        "compaction changed retained identities"
    );
    ensure!(
        candidate.watermark == expected_watermark,
        "compaction changed J"
    );
    let candidate_summary = LineageSummary::from_inspection(&candidate);
    let candidate_generation = candidate.last_operation_generation;
    let candidate_offset = candidate.complete_byte_offset;
    let candidate_short_tail = candidate.has_authenticated_short_tail;
    drop(candidate);
    directory.rename_noreplace(&temp_name, &final_name)?;
    journal_crashpoint("compaction_after_rename");
    directory.sync_parent()?;
    journal_crashpoint("compaction_after_parent_sync");
    let selected = inspect_file(directory, &final_name, genesis_block, Some(predecessor))?;
    journal_crashpoint("compaction_after_selection");
    ensure!(
        selected.header == candidate_summary.header
            && selected.entries.len() == candidate_summary.entry_count
            && identity_digest(&selected.entries) == candidate_summary.entry_digest
            && selected.watermark == candidate_summary.watermark
            && selected.last_operation_generation == candidate_generation
            && selected.last_commit_digest == candidate_summary.last_commit_digest
            && selected.file_root == candidate_summary.file_root
            && selected.complete_byte_offset == candidate_offset
            && selected.has_authenticated_short_tail == candidate_short_tail,
        "renamed compacted lineage changed after validation",
    );
    *root = hash_complete_file(directory, &final_name, selected.complete_byte_offset)?;
    *inspection = selected;
    journal_crashpoint("compaction_after_append_switch");
    cleanup_old_lineages(directory, old_lineage);
    journal_crashpoint("compaction_after_cleanup");
    Ok(())
}

fn compaction_due(retained: usize) -> bool {
    (retained >= JOURNAL_COMPACT_MIN_IDENTITIES
        && (retained - JOURNAL_COMPACT_MIN_IDENTITIES)
            .is_multiple_of(JOURNAL_COMPACT_DELTA_TRIGGER))
        || force_compaction_for_test()
}

struct PendingMaintenance {
    charged_bytes: usize,
    deadline: Instant,
}

fn try_pending_compaction(
    directory: &JournalDirectory,
    inspection: &mut MessageJournalInspection,
    genesis_block: u64,
    admission: &Arc<Admission>,
    root: &mut Keccak256,
    maintenance: &mut Option<PendingMaintenance>,
) -> eyre::Result<()> {
    let Some(pending) = maintenance.as_ref() else {
        return Ok(());
    };
    if let Some(reservation) = admission.try_reserve_maintenance(pending.charged_bytes) {
        compact_lineage(directory, genesis_block, inspection, root)?;
        drop(reservation);
        *maintenance = None;
    } else {
        ensure!(
            Instant::now() < pending.deadline,
            "journal maintenance capacity remained unavailable for 30 seconds"
        );
    }
    Ok(())
}

#[cfg(test)]
fn force_compaction_for_test() -> bool {
    std::env::var_os("ARB_RETH_JOURNAL_FORCE_COMPACTION").is_some()
}

#[cfg(not(test))]
const fn force_compaction_for_test() -> bool {
    false
}

fn cleanup_old_lineages(directory: &JournalDirectory, predecessor_lineage: u64) {
    for generation in 0..predecessor_lineage {
        let name = exact_journal_name(generation, "log");
        if !directory.entry_exists(&name).unwrap_or(false) {
            continue;
        }
        let result = directory.remove_entry(&name);
        if let Err(error) = result {
            tracing::warn!(
                target: "arb-reth::journal",
                %error,
                path = %directory.path().join(&name).display(),
                "old journal-lineage cleanup deferred",
            );
            break;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn process_pending(
    directory: &JournalDirectory,
    inspection: &mut MessageJournalInspection,
    genesis_block: u64,
    pending: &mut VecDeque<(MessageJournalEntry, ExecutionReservation)>,
    persistence: &Mutex<PersistenceState>,
    admission: &Arc<Admission>,
    root: &mut Keccak256,
    maintenance: &mut Option<PendingMaintenance>,
) -> eyre::Result<()> {
    try_pending_compaction(
        directory,
        inspection,
        genesis_block,
        admission,
        root,
        maintenance,
    )?;
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
            "exact persisted hash does not match queued executed identity"
        );
        drop(state);
        let (entry, reservation) = pending.pop_front().expect("checked above");
        append_entry(directory, inspection, genesis_block, entry, root)?;
        admission
            .journaled_sequence
            .store(entry.sequence, Ordering::Release);
        journal_crashpoint("append_after_ack");
        let retained = admission.retained_identities.fetch_add(1, Ordering::AcqRel) + 1;
        drop(reservation);
        if compaction_due(retained as usize) {
            ensure!(
                maintenance.is_none(),
                "journal compaction became due while prior maintenance was pending"
            );
            let compacted_len = HEADER_LEN
                .checked_add(FRAME_STORAGE_OVERHEAD)
                .and_then(|length| length.checked_add(SNAPSHOT_FIXED_LEN))
                .and_then(|length| {
                    length.checked_add(inspection.entries.len().checked_mul(IDENTITY_LEN)?)
                })
                .ok_or_else(|| eyre!("compaction maintenance length overflow"))?;
            let charged = compacted_len
                .checked_mul(2)
                .ok_or_else(|| eyre!("compaction maintenance charge overflow"))?;
            *maintenance = Some(PendingMaintenance {
                charged_bytes: charged,
                deadline: Instant::now() + MAINTENANCE_MAX_WAIT,
            });
        }
        try_pending_compaction(
            directory,
            inspection,
            genesis_block,
            admission,
            root,
            maintenance,
        )?;
        if retained as usize == JOURNAL_HARD_IDENTITY_LIMIT {
            admission.close();
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_worker(
    directory: JournalDirectory,
    mut inspection: MessageJournalInspection,
    genesis_block: u64,
    work_rx: crossbeam_channel::Receiver<Work>,
    control_rx: crossbeam_channel::Receiver<Control>,
    wake_rx: crossbeam_channel::Receiver<()>,
    admission: Arc<Admission>,
    persistence: Arc<Mutex<PersistenceState>>,
    fatal: Arc<Mutex<Option<String>>>,
    mut root: Keccak256,
) {
    let mut pending = VecDeque::new();
    let mut maintenance = None;
    loop {
        let maintenance_timer = maintenance
            .as_ref()
            .map(|pending: &PendingMaintenance| {
                crossbeam_channel::after(pending.deadline.saturating_duration_since(Instant::now()))
            })
            .unwrap_or_else(crossbeam_channel::never);
        crossbeam_channel::select! {
            recv(maintenance_timer) -> _ => {
                if let Err(error) = try_pending_compaction(
                    &directory,
                    &mut inspection,
                    genesis_block,
                    &admission,
                    &mut root,
                    &mut maintenance,
                ) {
                    set_fatal(&admission, &fatal, format!("{error:#}"));
                }
            }
            recv(wake_rx) -> _ => {
                if let Err(error) = process_pending(
                    &directory,
                    &mut inspection,
                    genesis_block,
                    &mut pending,
                    &persistence,
                    &admission,
                    &mut root,
                    &mut maintenance,
                ) {
                    set_fatal(&admission, &fatal, format!("{error:#}"));
                }
            }
            recv(control_rx) -> control => match control {
                Ok(Control::Stop(response)) => {
                    let result = process_pending(
                        &directory,
                        &mut inspection,
                        genesis_block,
                        &mut pending,
                        &persistence,
                        &admission,
                        &mut root,
                        &mut maintenance,
                    )
                    .and_then(|()| {
                        ensure!(pending.is_empty(), "journal stop has pending identities");
                        ensure!(maintenance.is_none(), "journal stop has pending maintenance");
                        Ok(())
                    });
                    admission.close();
                    let _ = response.send(result);
                    break
                }
                Err(_) => break,
            },
            recv(work_rx) -> work => match work {
                Ok(Work::Executed(entry, reservation)) => {
                    if admission.closed.load(Ordering::Acquire) {
                        drop(reservation);
                        continue
                    }
                    pending.push_back((entry, reservation));
                    if let Err(error) = process_pending(
                        &directory,
                        &mut inspection,
                        genesis_block,
                        &mut pending,
                        &persistence,
                        &admission,
                        &mut root,
                        &mut maintenance,
                    ) {
                        set_fatal(&admission, &fatal, format!("{error:#}"));
                    }
                }
                Ok(Work::Drain(response)) => {
                    let result = process_pending(
                        &directory,
                        &mut inspection,
                        genesis_block,
                        &mut pending,
                        &persistence,
                        &admission,
                        &mut root,
                        &mut maintenance,
                    )
                    .and_then(|()| {
                        ensure!(pending.is_empty(), "journal drain has identities not covered by exact D");
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

pub fn validate_runtime_capacity(
    memory_block_buffer_target: u64,
    persistence_threshold: u64,
    persistence_backpressure_threshold: u64,
) -> eyre::Result<()> {
    ensure!(
        memory_block_buffer_target <= persistence_threshold,
        "memory block buffer target exceeds persistence threshold"
    );
    ensure!(
        persistence_threshold <= MAX_SUPPORTED_PERSISTENCE_THRESHOLD,
        "persistence threshold exceeds 512"
    );
    ensure!(
        persistence_threshold < persistence_backpressure_threshold,
        "persistence backpressure must exceed threshold"
    );
    ensure!(
        persistence_backpressure_threshold <= JOURNAL_WORK_ITEM_CAPACITY as u64,
        "persistence backpressure exceeds journal work capacity"
    );
    ensure!(
        JOURNAL_WORK_ITEM_CAPACITY as u64 > persistence_threshold,
        "execution work capacity cannot cross persistence threshold"
    );
    ensure!(
        JOURNAL_RECORD_LIABILITY_CAPACITY as u64 > persistence_threshold,
        "execution record capacity cannot cross persistence threshold"
    );
    let compact_twice = MAX_COMPACTED_FILE_LEN
        .checked_mul(2)
        .ok_or_else(|| eyre!("capacity arithmetic overflow"))?;
    let promotion_twice = PROMOTION_MAX_ENCODED_BYTES * 2;
    let executions = 1_022usize
        .checked_mul(EXECUTED_LIABILITY_BYTES)
        .ok_or_else(|| eyre!("capacity arithmetic overflow"))?;
    ensure!(
        compact_twice + promotion_twice + executions <= JOURNAL_OUTSTANDING_BYTE_CAPACITY,
        "frozen simultaneous journal byte capacity is infeasible"
    );
    ensure!(
        1_022 + 1 + MAINTENANCE_WORK_ITEMS == JOURNAL_WORK_ITEM_CAPACITY,
        "frozen work capacity proof changed"
    );
    ensure!(
        1_022 + PROMOTION_MAX_RECORDS <= JOURNAL_RECORD_LIABILITY_CAPACITY,
        "frozen record capacity proof changed"
    );
    ensure!(
        PROTECTED_EXECUTION_WORK_FLOOR == 1 && PROTECTED_EXECUTION_RECORD_FLOOR == 1,
        "protected execution floors changed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropping_journal_runtime_cannot_request_stop_or_join() {
        let (work, _work_rx) = crossbeam_channel::bounded(1);
        let (control, control_rx) = crossbeam_channel::bounded(1);
        let admission = Arc::new(Admission {
            state: Mutex::new(AdmissionState::default()),
            closed: AtomicBool::new(false),
            journaled_sequence: AtomicU64::new(0),
            retained_identities: AtomicU64::new(0),
            notify: Notify::new(),
        });
        let fatal = Arc::new(Mutex::new(None));
        let client = JournalClient {
            work,
            control,
            admission: admission.clone(),
            fatal,
        };
        let (wake, _wake_rx) = crossbeam_channel::bounded(1);
        let persistence = PersistenceObserver {
            state: Arc::new(Mutex::new(PersistenceState {
                frontier: BlockNumHash::default(),
                exact: BTreeMap::new(),
                fatal: None,
            })),
            wake,
            admission,
        };
        let (observed_tx, observed_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            observed_tx
                .send(matches!(control_rx.recv(), Ok(Control::Stop(_))))
                .unwrap();
        });

        drop(JournalRuntime {
            client,
            persistence,
            worker: Some(worker),
        });
        assert!(
            !observed_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap(),
            "journal runtime destruction must not send Stop"
        );
    }

    fn anchor() -> MessageJournalAnchor {
        MessageJournalAnchor {
            sequence: 10,
            block_number: 110,
            block_hash: B256::repeat_byte(0x10),
        }
    }

    fn entry(sequence: u64, source: ArbEngineInputSource) -> MessageJournalEntry {
        MessageJournalEntry {
            sequence,
            block_number: sequence + 100,
            block_hash: B256::with_last_byte(sequence as u8),
            parent_hash: if sequence == 11 {
                anchor().block_hash
            } else {
                B256::with_last_byte(sequence as u8 - 1)
            },
            delayed_messages_read: 7,
            fingerprint: ArbMessageFingerprint {
                core: B256::repeat_byte(sequence as u8),
                enrichment: ArbMessageEnrichment {
                    legacy_batch_gas_cost: Some(9),
                    batch_data_stats: Some((11, 8)),
                },
            },
            source,
        }
    }

    #[test]
    fn golden_header_and_identity_round_trip() {
        let header = JournalHeader {
            lineage_generation: 0,
            snapshot_through_operation_generation: 0,
            predecessor_file_root: B256::ZERO,
            anchor: anchor(),
        };
        let encoded = encode_header(header);
        assert_eq!(
            alloy_primitives::hex::encode(encoded),
            "4152424a4f55524e414c563200000000000200a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000006e1010101010101010101010101010101010101010101010101010101010101010000000000000000000000000a4580d44eb8e69ec838dcfb26ee20f6ca54a3d619ecbe49ea7799a8b260c2a0f"
        );
        assert_eq!(decode_header(&encoded).unwrap(), header);
        assert_eq!(&encoded[..20], b"ARBJOURNALV2\0\0\0\0\0\x02\0\xa0",);
        let identity = encode_identity(entry(11, ArbEngineInputSource::Feed));
        assert_eq!(
            decode_identity(&identity).unwrap(),
            entry(11, ArbEngineInputSource::Feed)
        );
        assert_eq!(
            &identity[..16],
            &[0, 0, 0, 0, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 111]
        );
    }

    #[test]
    fn all_frame_kinds_round_trip_and_mutations_reject() {
        let executed = encode_frame(
            FrameKind::Executed,
            1,
            B256::repeat_byte(1),
            &encode_identity(entry(11, ArbEngineInputSource::Feed)),
        )
        .unwrap();
        assert_eq!(
            alloy_primitives::hex::encode(&executed),
            "00000144000000c00c3c4952c52368e3077ed53253671061eb91418916106bcab6e80b19d02a9a6f4152424a4652414d0002010000000000000000010101010101010101010101010101010101010101010101010101010101010101000000c0000000000000000b000000000000006f000000000000000000000000000000000000000000000000000000000000000b101010101010101010101010101010101010101010101010101010101010101000000000000000070b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b01000000000000000901000000000000000b0000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004152424a434f4d54aa99d407e1fa914554d173baa1aa34b4e103351b7cba40a5eb1020dc32ec41ab"
        );
        assert_eq!(
            decode_complete_frame(&executed).unwrap().kind,
            FrameKind::Executed
        );
        let mut snapshot_payload = encode_snapshot_payload(
            &[entry(11, ArbEngineInputSource::Feed)],
            B256::repeat_byte(2),
        )
        .unwrap();
        let snapshot = encode_frame(
            FrameKind::Snapshot,
            1,
            B256::repeat_byte(2),
            &snapshot_payload,
        )
        .unwrap();
        assert_eq!(
            alloy_primitives::hex::encode(&snapshot),
            "00000168000000e4608b96de1d9c662d234dd2b54f22fcba3fb44fd5781f5d066bc07338c25263064152424a4652414d0002030000000000000000010202020202020202020202020202020202020202020202020202020202020202000000e400000001000000000000000b000000000000006f000000000000000000000000000000000000000000000000000000000000000b101010101010101010101010101010101010101010101010101010101010101000000000000000070b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b01000000000000000901000000000000000b00000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002020202020202020202020202020202020202020202020202020202020202024152424a434f4d54932fdd5b55676b4816ad488eecff19acefe0ce9b4dc62d7f665e3f34ee14ec7c"
        );
        assert_eq!(
            decode_complete_frame(&snapshot).unwrap().kind,
            FrameKind::Snapshot
        );
        let checkpoint = PromotionCheckpoint {
            observation_generation: 7,
            chain_id: 4_663,
            safe_l1_number: 19,
            safe_l1_hash: B256::repeat_byte(0x19),
            safe_l1_parent_hash: B256::repeat_byte(0x18),
            batch_sequence: 4,
            batch_before_acc: B256::repeat_byte(0x20),
            batch_after_acc: B256::repeat_byte(0x21),
            delayed_count: 3,
            delayed_acc: B256::repeat_byte(0x22),
            start_sequence: 11,
            end_sequence: 11,
            end_l2_block_number: 111,
            end_l2_block_hash: entry(11, ArbEngineInputSource::L1).block_hash,
        };
        let promotion_payload =
            encode_promotion_payload(checkpoint, &[entry(11, ArbEngineInputSource::L1)]).unwrap();
        assert_eq!(
            decode_promotion_checkpoint(&promotion_payload).unwrap(),
            checkpoint
        );
        let promotion = encode_frame(
            FrameKind::PromoteWithCheckpoint,
            2,
            B256::repeat_byte(3),
            &promotion_payload,
        )
        .unwrap();
        assert_eq!(
            alloy_primitives::hex::encode(&promotion),
            "00000256000001d2d298e186ebe341a70ac2fdc991fb6b149bc3d2425e28b6b55c7142cbbaed2dbf4152424a4652414d0002020000000000000000020303030303030303030303030303030303030303030303030303030303030303000001d20000000000000007000000000000123700000000000000131919191919191919191919191919191919191919191919191919191919191919181818181818181818181818181818181818181818181818181818181818181800000000000000042020202020202020202020202020202020202020202020202020202020202020212121212121212121212121212121212121212121212121212121212121212100000000000000032222222222222222222222222222222222222222222222222222222222222222000000000000000b000000000000000b000000000000006f000000000000000000000000000000000000000000000000000000000000000b000000000000000000000000000000000001000000000000000b000000000000006f000000000000000000000000000000000000000000000000000000000000000b101010101010101010101010101010101010101010101010101010101010101000000000000000070b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b01000000000000000901000000000000000b0000000000000008010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004152424a434f4d54fec0eba4a99f03d7983a5fb0b8d5170faaddd16a360d8adc77f417c795165d48"
        );
        assert_eq!(
            decode_complete_frame(&promotion).unwrap().kind,
            FrameKind::PromoteWithCheckpoint
        );
        let mut retained = vec![entry(11, ArbEngineInputSource::Feed)];
        validate_promotion_payload(&promotion_payload, &mut retained).unwrap();
        assert_eq!(retained[0].source, ArbEngineInputSource::L1);
        for index in [0, 4, 8, 40, 48, 50, 51, 52, 60, 92, executed.len() - 1] {
            let mut changed = executed.clone();
            changed[index] ^= 1;
            assert!(
                decode_complete_frame(&changed).is_err(),
                "mutation {index} accepted"
            );
        }
        snapshot_payload[0] ^= 1;
    }

    #[test]
    fn incremental_short_tail_domain_is_exact() {
        let frame = encode_frame(
            FrameKind::Executed,
            1,
            B256::ZERO,
            &encode_identity(entry(11, ArbEngineInputSource::Feed)),
        )
        .unwrap();
        for length in 0..=96 {
            let result = validate_partial_frame(&frame[..length], 1, B256::ZERO);
            if length == 0 || length >= 40 {
                assert!(
                    result.is_ok(),
                    "valid prefix length {length} rejected: {result:?}"
                );
            } else {
                assert!(result.is_err(), "unverifiable length {length} accepted");
            }
        }
        let mut impossible = frame[..96].to_vec();
        put_u32(&mut impossible[4..8], 193);
        put_u32(&mut impossible[0..4], 325);
        let digest = keccak256(&impossible[..8]);
        impossible[8..40].copy_from_slice(digest.as_slice());
        assert!(validate_partial_frame(&impossible[..51], 1, B256::ZERO).is_err());

        for kind in [
            FrameKind::Executed,
            FrameKind::PromoteWithCheckpoint,
            FrameKind::Snapshot,
        ] {
            for physical_len in 51..=96 {
                let mut invalid = frame[..physical_len].to_vec();
                invalid[50] = kind as u8;
                put_u32(&mut invalid[4..8], 1);
                put_u32(&mut invalid[0..4], FRAME_OVERHEAD_AFTER_LENGTH as u32 + 1);
                let digest = keccak256(&invalid[..8]);
                invalid[8..40].copy_from_slice(digest.as_slice());
                assert!(
                    validate_partial_frame(&invalid, 1, B256::ZERO).is_err(),
                    "impossible {kind:?} length accepted at physical length {physical_len}"
                );
            }
        }
        for physical_len in 60..=96 {
            let mut invalid = frame[..physical_len].to_vec();
            invalid[59] ^= 1;
            assert!(
                validate_partial_frame(&invalid, 1, B256::ZERO).is_err(),
                "wrong generation accepted at physical length {physical_len}"
            );
        }
        for physical_len in 92..=96 {
            let mut invalid = frame[..physical_len].to_vec();
            invalid[91] ^= 1;
            assert!(
                validate_partial_frame(&invalid, 1, B256::ZERO).is_err(),
                "wrong predecessor accepted at physical length {physical_len}"
            );
        }
    }

    #[test]
    fn lineage_zero_is_exactly_332_bytes_and_v1_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let directory = JournalDirectory::open(dir.path()).unwrap();
        let inspection = initialize_journal_v2(&directory, anchor()).unwrap();
        assert_eq!(inspection.complete_byte_offset, 332);
        assert_eq!(inspection.watermark, anchor());
        std::fs::write(dir.path().join(MESSAGE_JOURNAL_V1_FILE), b"old").unwrap();
        assert!(inspect_message_journal(&directory, 100).is_err());
    }

    #[tokio::test]
    async fn benchmark_adapter_uses_the_production_worker_and_exact_d() {
        let dir = tempfile::tempdir().unwrap();
        let directory = JournalDirectory::open(dir.path()).unwrap();
        let mut adapter = JournalBenchmarkAdapter::new(true, directory.clone())
            .await
            .unwrap();
        let entry = MessageJournalEntry {
            sequence: 1,
            block_number: 1,
            block_hash: B256::repeat_byte(1),
            parent_hash: B256::ZERO,
            delayed_messages_read: 0,
            fingerprint: ArbMessageFingerprint {
                core: B256::repeat_byte(2),
                enrichment: ArbMessageEnrichment {
                    legacy_batch_gas_cost: None,
                    batch_data_stats: None,
                },
            },
            source: ArbEngineInputSource::Feed,
        };
        adapter.reserve_and_enqueue(entry).await.unwrap();
        adapter.persist_and_drain(entry).await.unwrap();
        drop(adapter);

        let inspection = inspect_message_journal(&directory, 0).unwrap();
        assert_eq!(inspection.entries, vec![entry]);
        assert_eq!(inspection.watermark.sequence, 1);
    }

    #[test]
    fn authenticated_short_tail_is_read_only_until_explicit_repair() {
        let dir = tempfile::tempdir().unwrap();
        let directory = JournalDirectory::open(dir.path()).unwrap();
        let inspection = initialize_journal_v2(&directory, anchor()).unwrap();
        let frame = encode_frame(
            FrameKind::Executed,
            1,
            inspection.last_commit_digest,
            &encode_identity(entry(11, ArbEngineInputSource::Feed)),
        )
        .unwrap();
        let mut file = OpenOptions::new()
            .append(true)
            .open(&inspection.path)
            .unwrap();
        file.write_all(&frame[..40]).unwrap();
        file.sync_data().unwrap();
        let before = std::fs::metadata(&inspection.path).unwrap().len();
        assert!(inspect_message_journal(&directory, 100).is_err());
        let (stopped, recovery_required) =
            inspect_stopped_message_journal(&directory, 100).unwrap();
        assert!(
            recovery_required && stopped.has_authenticated_short_tail,
            "stopped classifier did not freeze the authenticated short tail"
        );
        assert_eq!(std::fs::metadata(&inspection.path).unwrap().len(), before);
        truncate_authenticated_short_tail(&directory, 100).unwrap();
        assert_eq!(std::fs::metadata(&inspection.path).unwrap().len(), 332);
    }

    #[test]
    fn complete_next_temp_finishes_only_through_stopped_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let directory = JournalDirectory::open(dir.path()).unwrap();
        let selected = initialize_journal_v2(&directory, anchor()).unwrap();
        let header = JournalHeader {
            lineage_generation: 1,
            snapshot_through_operation_generation: selected.last_operation_generation,
            predecessor_file_root: selected.file_root,
            anchor: selected.header.anchor,
        };
        let payload =
            encode_snapshot_payload(&selected.entries, selected.last_commit_digest).unwrap();
        let frame = encode_frame(
            FrameKind::Snapshot,
            selected.last_operation_generation,
            selected.last_commit_digest,
            &payload,
        )
        .unwrap();
        let temp = dir.path().join(exact_journal_name(1, "tmp"));
        let mut file = File::create(&temp).unwrap();
        file.write_all(&encode_header(header)).unwrap();
        file.write_all(&frame).unwrap();
        file.sync_all().unwrap();

        let (still_selected, recovery_required) =
            inspect_stopped_message_journal(&directory, 100).unwrap();
        assert!(recovery_required);
        assert_eq!(still_selected.header.lineage_generation, 0);
        assert!(inspect_message_journal(&directory, 100).is_err());
        let recovered = recover_stopped_message_journal(&directory, 100).unwrap();
        assert_eq!(recovered.header.lineage_generation, 1);
        assert!(!temp.exists());
        assert!(dir.path().join(exact_journal_name(1, "log")).exists());
    }

    #[tokio::test]
    async fn exact_d_hash_gates_j_and_wrong_hash_closes() {
        let dir = tempfile::tempdir().unwrap();
        let directory = JournalDirectory::open(dir.path()).unwrap();
        initialize_journal_v2(&directory, anchor()).unwrap();
        let runtime = JournalRuntime::open(
            directory,
            100,
            BlockNumHash {
                number: 110,
                hash: anchor().block_hash,
            },
        )
        .unwrap();
        let reservation = runtime.client.reserve_execution(11).await.unwrap();
        runtime
            .client
            .enqueue_executed(entry(11, ArbEngineInputSource::Feed), reservation)
            .unwrap();
        runtime.persistence.saved(
            &[BlockNumHash {
                number: 111,
                hash: B256::repeat_byte(0xff),
            }],
            BlockNumHash {
                number: 111,
                hash: B256::repeat_byte(0xff),
            },
        );
        assert!(runtime.client.drain().is_err());
    }

    #[tokio::test]
    async fn exact_d_evidence_retires_when_j_consumes_it() {
        let dir = tempfile::tempdir().unwrap();
        let directory = JournalDirectory::open(dir.path()).unwrap();
        initialize_journal_v2(&directory, anchor()).unwrap();
        let runtime = JournalRuntime::open(
            directory,
            100,
            BlockNumHash {
                number: anchor().block_number,
                hash: anchor().block_hash,
            },
        )
        .unwrap();
        let next = entry(11, ArbEngineInputSource::Feed);
        let reservation = runtime
            .client
            .reserve_execution(next.sequence)
            .await
            .unwrap();
        runtime.client.enqueue_executed(next, reservation).unwrap();
        let persisted = BlockNumHash {
            number: next.block_number,
            hash: next.block_hash,
        };
        runtime.persistence.saved(&[persisted], persisted);
        assert_eq!(runtime.client.drain().unwrap().sequence, next.sequence);
        assert!(
            runtime
                .persistence
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .exact
                .is_empty(),
            "exact D evidence outlived its journal liability"
        );
    }

    #[tokio::test]
    async fn append_fault_and_crash_subprocess_matrix() {
        const CHILD_DATADIR: &str = "ARB_RETH_JOURNAL_TEST_DATADIR";
        const CHILD_EXPECT: &str = "ARB_RETH_JOURNAL_TEST_EXPECT";
        if let Some(datadir) = std::env::var_os(CHILD_DATADIR) {
            let directory = JournalDirectory::open(std::path::Path::new(&datadir)).unwrap();
            let runtime = JournalRuntime::open(
                directory,
                100,
                BlockNumHash {
                    number: anchor().block_number,
                    hash: anchor().block_hash,
                },
            )
            .unwrap();
            let next = entry(11, ArbEngineInputSource::Feed);
            let reservation = runtime
                .client
                .reserve_execution(11)
                .await
                .expect("reserve child execution");
            runtime.client.enqueue_executed(next, reservation).unwrap();
            runtime.persistence.saved(
                &[BlockNumHash {
                    number: next.block_number,
                    hash: next.block_hash,
                }],
                BlockNumHash {
                    number: next.block_number,
                    hash: next.block_hash,
                },
            );
            let result = runtime.client.drain();
            match std::env::var(CHILD_EXPECT).as_deref() {
                Ok("commit") => assert_eq!(result.unwrap().sequence, 11),
                Ok("reject") => {
                    assert!(result.is_err());
                    assert!(
                        runtime.client.reserve_execution(12).await.is_err(),
                        "fatal journal I/O must close admission"
                    );
                }
                other => panic!("unknown child expectation {other:?}"),
            }
            return;
        }

        let executable = std::env::current_exe().unwrap();
        let cases = [
            ("fault", "append_write:before:28", "reject", 10),
            ("fault", "append_write:before:5", "reject", 10),
            ("fault", "append_write:after:5", "reject", 11),
            ("fault", "append_flush:before:5", "reject", 11),
            ("fault", "append_flush:after:5", "reject", 11),
            ("fault", "append_sync:before:5", "reject", 11),
            ("fault", "append_sync:after:5", "reject", 11),
            ("fault", "append_reread:before:5", "reject", 11),
            ("fault", "append_reread:after:5", "reject", 11),
            ("crash", "append_before_write", "", 10),
            ("crash", "append_after_write", "", 11),
            ("crash", "append_after_flush", "", 11),
            ("crash", "append_after_sync", "", 11),
            ("crash", "append_after_reread", "", 11),
            ("crash", "append_before_ack", "", 11),
            ("crash", "append_after_ack", "", 11),
        ];
        for (kind, point, expectation, expected_sequence) in cases {
            let dir = tempfile::tempdir().unwrap();
            let directory = JournalDirectory::open(dir.path()).unwrap();
            initialize_journal_v2(&directory, anchor()).unwrap();
            drop(directory);
            let mut command = std::process::Command::new(&executable);
            command
                .args([
                    "--exact",
                    "message_journal::tests::append_fault_and_crash_subprocess_matrix",
                    "--nocapture",
                ])
                .env(CHILD_DATADIR, dir.path());
            if kind == "fault" {
                command
                    .env("ARB_RETH_JOURNAL_IO_FAULT", point)
                    .env(CHILD_EXPECT, expectation);
            } else {
                command.env("ARB_RETH_JOURNAL_CRASHPOINT", point);
            }
            let status = command.status().unwrap();
            if kind == "fault" {
                assert!(status.success(), "fault case {point} failed: {status}");
            } else {
                assert_eq!(status.code(), Some(86), "crashpoint {point} did not fire");
            }
            let directory = JournalDirectory::open(dir.path()).unwrap();
            let inspection = inspect_message_journal(&directory, 100).unwrap();
            assert_eq!(
                inspection.watermark.sequence, expected_sequence,
                "case {point} selected the wrong durable authority"
            );
        }
    }

    #[tokio::test]
    async fn compaction_fault_and_crash_subprocess_matrix() {
        const CHILD_DATADIR: &str = "ARB_RETH_COMPACTION_TEST_DATADIR";
        if let Some(datadir) = std::env::var_os(CHILD_DATADIR) {
            let directory = JournalDirectory::open(std::path::Path::new(&datadir)).unwrap();
            let runtime = JournalRuntime::open(
                directory,
                100,
                BlockNumHash {
                    number: anchor().block_number,
                    hash: anchor().block_hash,
                },
            )
            .unwrap();
            let next = entry(11, ArbEngineInputSource::Feed);
            let reservation = runtime.client.reserve_execution(11).await.unwrap();
            runtime.client.enqueue_executed(next, reservation).unwrap();
            runtime.persistence.saved(
                &[BlockNumHash {
                    number: next.block_number,
                    hash: next.block_hash,
                }],
                BlockNumHash {
                    number: next.block_number,
                    hash: next.block_hash,
                },
            );
            assert!(runtime.client.drain().is_err());
            assert!(runtime.client.reserve_execution(12).await.is_err());
            return;
        }

        let executable = std::env::current_exe().unwrap();
        let cases = [
            ("fault", "compaction_write:before:28", "invalid_temp"),
            ("fault", "compaction_write:before:5", "invalid_temp"),
            ("fault", "compaction_flush:before:5", "complete_temp"),
            ("fault", "compaction_flush:after:5", "complete_temp"),
            ("fault", "compaction_sync:before:5", "complete_temp"),
            ("fault", "compaction_sync:after:5", "complete_temp"),
            ("crash", "compaction_before_seal", "ordinary_old"),
            ("crash", "compaction_after_seal", "ordinary_old"),
            ("crash", "compaction_after_temp_write", "complete_temp"),
            ("crash", "compaction_after_temp_flush", "complete_temp"),
            ("crash", "compaction_after_temp_sync", "complete_temp"),
            ("crash", "compaction_after_temp_reread", "complete_temp"),
            ("crash", "compaction_after_rename", "ordinary_new"),
            ("crash", "compaction_after_parent_sync", "ordinary_new"),
            ("crash", "compaction_after_selection", "ordinary_new"),
            ("crash", "compaction_after_append_switch", "ordinary_new"),
            ("crash", "compaction_after_cleanup", "ordinary_new"),
        ];
        for (kind, point, classification) in cases {
            let dir = tempfile::tempdir().unwrap();
            let directory = JournalDirectory::open(dir.path()).unwrap();
            initialize_journal_v2(&directory, anchor()).unwrap();
            drop(directory);
            let mut command = std::process::Command::new(&executable);
            command
                .args([
                    "--exact",
                    "message_journal::tests::compaction_fault_and_crash_subprocess_matrix",
                    "--nocapture",
                ])
                .env(CHILD_DATADIR, dir.path())
                .env("ARB_RETH_JOURNAL_FORCE_COMPACTION", "1");
            if kind == "fault" {
                command.env("ARB_RETH_JOURNAL_IO_FAULT", point);
            } else {
                command.env("ARB_RETH_JOURNAL_CRASHPOINT", point);
            }
            let status = command.status().unwrap();
            if kind == "fault" {
                assert!(status.success(), "fault case {point} failed: {status}");
            } else {
                assert_eq!(status.code(), Some(86), "crashpoint {point} did not fire");
            }

            let directory = JournalDirectory::open(dir.path()).unwrap();
            let predecessor = inspect_file(&directory, &exact_journal_name(0, "log"), 100, None)
                .expect("predecessor authority always survives compaction");
            assert_eq!(predecessor.watermark.sequence, 11);
            match classification {
                "ordinary_old" => assert_eq!(
                    inspect_message_journal(&directory, 100)
                        .unwrap()
                        .header
                        .lineage_generation,
                    0
                ),
                "invalid_temp" => {
                    assert!(inspect_message_journal(&directory, 100).is_err());
                    assert!(inspect_stopped_message_journal(&directory, 100).is_err());
                }
                "complete_temp" => {
                    let (selected, recovery_required) =
                        inspect_stopped_message_journal(&directory, 100).unwrap();
                    assert_eq!(selected.header.lineage_generation, 0);
                    assert!(recovery_required);
                    assert_eq!(
                        recover_stopped_message_journal(&directory, 100)
                            .unwrap()
                            .header
                            .lineage_generation,
                        1
                    );
                }
                "ordinary_new" => assert_eq!(
                    inspect_message_journal(&directory, 100)
                        .unwrap()
                        .header
                        .lineage_generation,
                    1
                ),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn append_heavy_streaming_boundaries_and_maximum_compaction() {
        fn large_entry(sequence: u64, parent_hash: B256) -> MessageJournalEntry {
            MessageJournalEntry {
                sequence,
                block_number: sequence + 100,
                block_hash: keccak256(sequence.to_be_bytes()),
                parent_hash,
                delayed_messages_read: sequence / 7,
                fingerprint: ArbMessageFingerprint {
                    core: keccak256((sequence ^ 0xfeed_beef).to_be_bytes()),
                    enrichment: ArbMessageEnrichment {
                        legacy_batch_gas_cost: Some(sequence),
                        batch_data_stats: Some((sequence + 1, sequence + 2)),
                    },
                },
                source: ArbEngineInputSource::Feed,
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let directory = JournalDirectory::open(dir.path()).unwrap();
        let initialized = initialize_journal_v2(&directory, anchor()).unwrap();
        let selected_name = exact_journal_name(0, "log");
        let file = directory.open_existing(&selected_name, true, true).unwrap();
        let mut writer = std::io::BufWriter::with_capacity(JOURNAL_STREAM_SCRATCH, file);
        let mut previous_digest = initialized.last_commit_digest;
        let mut parent_hash = anchor().block_hash;
        for index in 1..=JOURNAL_HARD_IDENTITY_LIMIT as u64 {
            let identity = large_entry(anchor().sequence + index, parent_hash);
            let frame = encode_frame(
                FrameKind::Executed,
                index,
                previous_digest,
                &encode_identity(identity),
            )
            .unwrap();
            previous_digest = decode_complete_frame(&frame).unwrap().commit_digest;
            writer.write_all(&frame).unwrap();
            parent_hash = identity.block_hash;
        }
        writer.flush().unwrap();
        writer.get_ref().sync_all().unwrap();
        drop(writer);

        let mut maximum = inspect_message_journal(&directory, 100).unwrap();
        assert_eq!(maximum.complete_byte_offset, MAX_APPEND_LINEAGE_LEN);
        assert_eq!(maximum.entries.len(), JOURNAL_HARD_IDENTITY_LIMIT);
        assert_eq!(JOURNAL_STREAM_SCRATCH, 1024 * 1024);

        let mut selected = directory.open_existing(&selected_name, true, true).unwrap();
        selected.write_all(&[0]).unwrap();
        selected.sync_all().unwrap();
        assert_eq!(selected.metadata().unwrap().len(), 36_080_333);
        assert!(inspect_message_journal(&directory, 100).is_err());
        selected.set_len(MAX_APPEND_LINEAGE_LEN).unwrap();
        selected.sync_all().unwrap();
        drop(selected);
        maximum = inspect_message_journal(&directory, 100).unwrap();

        let middle = tempfile::tempdir().unwrap();
        let middle_directory = JournalDirectory::open(middle.path()).unwrap();
        std::fs::copy(
            dir.path().join(&selected_name),
            middle.path().join(&selected_name),
        )
        .unwrap();
        let middle_file = middle_directory
            .open_existing(&selected_name, true, false)
            .unwrap();
        middle_file.set_len(21_120_333).unwrap();
        middle_file.sync_all().unwrap();
        drop(middle_file);
        let (middle_inspection, recovery_required) =
            inspect_stopped_message_journal(&middle_directory, 100).unwrap();
        assert!(recovery_required && middle_inspection.has_authenticated_short_tail);
        assert_eq!(middle_inspection.complete_byte_offset, 21_120_252);

        let mut root = hash_complete_file(&directory, &selected_name, MAX_APPEND_LINEAGE_LEN)
            .expect("stream maximum predecessor root");
        compact_lineage(&directory, 100, &mut maximum, &mut root).unwrap();
        assert_eq!(maximum.header.lineage_generation, 1);
        assert_eq!(maximum.entries.len(), JOURNAL_HARD_IDENTITY_LIMIT);
        assert_eq!(maximum.complete_byte_offset, MAX_COMPACTED_FILE_LEN as u64);
        assert!(directory.entry_exists(&selected_name).unwrap());
        assert_eq!(
            inspect_message_journal(&directory, 100).unwrap().watermark,
            maximum.watermark
        );
    }

    #[test]
    fn capacity_proof_covers_all_supported_boundaries() {
        for threshold in 0..=MAX_SUPPORTED_PERSISTENCE_THRESHOLD {
            let backpressure = (threshold + 1).max(1);
            assert!(validate_runtime_capacity(0, threshold, backpressure).is_ok());
        }
        assert!(validate_runtime_capacity(513, 513, 514).is_err());
        assert!(validate_runtime_capacity(0, 2, 2).is_err());
        assert_eq!(MAX_COMPACTED_FILE_LEN, 21_120_332);
        assert_eq!(MAX_APPEND_LINEAGE_LEN, 36_080_332);
    }

    #[test]
    fn maintenance_wait_preserves_the_execution_floor_until_capacity_retires() {
        assert_eq!(MAINTENANCE_MAX_WAIT, Duration::from_secs(30));
        let admission = Arc::new(Admission {
            state: Mutex::new(AdmissionState {
                work: JOURNAL_WORK_ITEM_CAPACITY - PROTECTED_EXECUTION_WORK_FLOOR,
                records: JOURNAL_WORK_ITEM_CAPACITY - PROTECTED_EXECUTION_RECORD_FLOOR,
                bytes: (JOURNAL_WORK_ITEM_CAPACITY - PROTECTED_EXECUTION_WORK_FLOOR)
                    * EXECUTED_LIABILITY_BYTES,
            }),
            closed: AtomicBool::new(false),
            journaled_sequence: AtomicU64::new(0),
            retained_identities: AtomicU64::new(0),
            notify: Notify::new(),
        });
        assert!(
            admission
                .try_reserve_maintenance(MAX_COMPACTED_FILE_LEN * 2)
                .is_none(),
            "maintenance consumed the protected execution floor"
        );
        admission.retire(1, 1, EXECUTED_LIABILITY_BYTES);
        let maintenance = admission
            .try_reserve_maintenance(MAX_COMPACTED_FILE_LEN * 2)
            .expect("one retired execution makes bounded maintenance feasible");
        drop(maintenance);
        let state = admission
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(state.work, JOURNAL_WORK_ITEM_CAPACITY - 2);
        assert_eq!(state.records, JOURNAL_WORK_ITEM_CAPACITY - 2);
    }
}
