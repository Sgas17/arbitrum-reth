//! Preallocated A/B node-lifecycle authority.
//!
//! The file is bound to its pinned parent directory, immutable journal anchor, inode, filesystem,
//! and physical slot geometry. Ordinary startup never creates or reopens it.

use std::{
    ffi::CString,
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd, RawFd},
    sync::Arc,
};

use alloy_primitives::{B256, keccak256};
use arb_reth_engine::{JournalDirectory, LIFECYCLE_FILE, MessageJournalAnchor};
use eyre::{WrapErr as _, ensure, eyre};

#[cfg(test)]
use std::cell::RefCell;

const FILE_LEN: u64 = 8192;
const SLOT_LEN: usize = 4096;
const SLOT_BODY_LEN: usize = 4064;
const MAGIC: &[u8; 16] = b"ARBLIFECYCLEV1\0\0";
const VERSION: u16 = 1;
const ROLE_NODE: u8 = 1;
const EXT4_SUPER_MAGIC: u64 = 0xef53;
const XFS_SUPER_MAGIC: u64 = 0x5846_5342;
const FS_IOC_FIEMAP: libc::c_ulong = 0xc020_660b;
const FIEMAP_FLAG_SYNC: u32 = 0x1;
const FIEMAP_EXTENT_LAST: u32 = 0x1;
const REJECTED_EXTENT_FLAGS: u32 = 0x2 | 0x4 | 0x8 | 0x100 | 0x200 | 0x2000;

#[cfg(test)]
std::thread_local! {
    static LIFECYCLE_OPEN_FLAGS: RefCell<Vec<i32>> = const { RefCell::new(Vec::new()) };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LifecycleState {
    Initializing = 0,
    Clean = 1,
    RunningUnclean = 2,
}

impl TryFrom<u8> for LifecycleState {
    type Error = eyre::Report;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Initializing),
            1 => Ok(Self::Clean),
            2 => Ok(Self::RunningUnclean),
            _ => Err(eyre!("unknown lifecycle state {value}")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleSlot {
    pub state: LifecycleState,
    pub generation: u64,
    pub setup_binding: B256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TerminalState {
    Preparing,
    CleanCommitStarted,
    CleanCommitFinished,
}

enum CleanAuthority {
    Target,
    Prior,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FiemapExtent {
    logical: u64,
    physical: u64,
    length: u64,
    reserved64: [u64; 2],
    flags: u32,
    reserved: [u32; 3],
}

#[repr(C)]
struct FiemapQuery<const N: usize> {
    start: u64,
    length: u64,
    flags: u32,
    mapped_extents: u32,
    extent_count: u32,
    reserved: u32,
    extents: [FiemapExtent; N],
}

impl<const N: usize> Default for FiemapQuery<N> {
    fn default() -> Self {
        Self {
            start: 0,
            length: FILE_LEN,
            flags: FIEMAP_FLAG_SYNC,
            mapped_extents: 0,
            extent_count: N as u32,
            reserved: 0,
            extents: [FiemapExtent::default(); N],
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Geometry {
    parent_dev: u64,
    parent_ino: u64,
    file_dev: u64,
    file_ino: u64,
    fs_type: u64,
    frsize: u64,
    bsize: u64,
    slot_a_physical: u64,
    slot_b_physical: u64,
}

/// Pinned lifecycle authority. Both descriptors stay open for this value's lifetime.
pub struct LifecycleGuard {
    parent: Arc<File>,
    file: File,
    anchor: MessageJournalAnchor,
    binding: B256,
    selected: LifecycleSlot,
    selected_index: usize,
    terminal_state: TerminalState,
}

impl LifecycleGuard {
    /// One-shot setup, used only after the v2 journal was exclusively created and revalidated.
    pub fn initialize(
        directory: &JournalDirectory,
        anchor: MessageJournalAnchor,
    ) -> eyre::Result<Self> {
        let parent = directory.parent_file();
        let file = open_lifecycle_at(parent.as_raw_fd(), true)?;
        set_len(file.as_raw_fd(), FILE_LEN)?;
        pwrite_all(file.as_raw_fd(), 0, &[0u8; FILE_LEN as usize])?;
        lifecycle_failpoint("provisional_full_written");
        file.sync_all().wrap_err("allocate lifecycle file")?;
        lifecycle_failpoint("provisional_synced");

        let geometry = prove_geometry_and_entry(&parent, &file)?;
        lifecycle_failpoint("provisional_entry_proved");
        let binding = setup_binding(geometry, anchor);
        let initializing_a = LifecycleSlot {
            state: LifecycleState::Initializing,
            generation: 1,
            setup_binding: binding,
        };
        write_slot(&file, 0, initializing_a, "a_initializing")?;
        file.sync_data().wrap_err("sync lifecycle slot A")?;
        lifecycle_failpoint("a_initializing_synced");
        prove_after_write(&parent, &file, anchor, binding)?;
        lifecycle_failpoint("a_initializing_entry_proved");

        let initializing_b = LifecycleSlot {
            state: LifecycleState::Initializing,
            generation: 0,
            setup_binding: binding,
        };
        write_slot(&file, 1, initializing_b, "b_initializing")?;
        file.sync_data()
            .wrap_err("sync lifecycle slot B initializing")?;
        lifecycle_failpoint("b_initializing_synced");
        validate_slots(&file, binding)?;
        lifecycle_failpoint("b_initializing_reread");
        fsync_fd(parent.as_raw_fd()).wrap_err("sync lifecycle parent")?;
        lifecycle_failpoint("b_initializing_parent_synced");
        prove_after_write(&parent, &file, anchor, binding)?;
        lifecycle_failpoint("b_initializing_entry_proved");

        let clean_b = LifecycleSlot {
            state: LifecycleState::Clean,
            generation: 2,
            setup_binding: binding,
        };
        write_slot(&file, 1, clean_b, "b_clean")?;
        file.sync_data().wrap_err("sync lifecycle setup commit")?;
        lifecycle_failpoint("b_clean_synced");
        let (selected_index, selected) = validate_slots(&file, binding)?;
        lifecycle_failpoint("b_clean_reread");
        ensure!(
            selected_index == 1 && selected == clean_b,
            "lifecycle setup did not select CLEAN/2"
        );
        prove_after_write(&parent, &file, anchor, binding)?;
        lifecycle_failpoint("b_clean_entry_proved");
        Ok(Self {
            parent,
            file,
            anchor,
            binding,
            selected,
            selected_index,
            terminal_state: TerminalState::Preparing,
        })
    }

    /// Open and pin an existing authority file. This path never creates or truncates.
    pub fn open_existing(
        directory: &JournalDirectory,
        anchor: MessageJournalAnchor,
    ) -> eyre::Result<Self> {
        let parent = directory.parent_file();
        let file = open_lifecycle_at(parent.as_raw_fd(), false)?;
        let geometry = prove_geometry_and_entry(&parent, &file)?;
        let binding = setup_binding(geometry, anchor);
        let (selected_index, selected) = validate_slots(&file, binding)?;
        Ok(Self {
            parent,
            file,
            anchor,
            binding,
            selected,
            selected_index,
            terminal_state: TerminalState::Preparing,
        })
    }

    pub const fn selected(&self) -> LifecycleSlot {
        self.selected
    }

    /// CLEAN startup transition. RUNNING evidence must first pass the stopped classifier.
    pub fn mark_running(&mut self) -> eyre::Result<()> {
        ensure!(
            self.selected.state == LifecycleState::Clean,
            "lifecycle is not CLEAN"
        );
        self.transition(LifecycleState::RunningUnclean)
    }

    /// Reassert RUNNING after successful stopped classification of prior RUNNING evidence.
    pub fn reassert_running(&mut self) -> eyre::Result<()> {
        ensure!(
            self.selected.state == LifecycleState::RunningUnclean,
            "lifecycle is not RUNNING"
        );
        self.transition(LifecycleState::RunningUnclean)
    }

    /// Test-only direct transition used by codec/crash fixtures that do not own a terminal clock.
    #[cfg(test)]
    pub fn mark_clean(&mut self) -> eyre::Result<()> {
        let (target_index, target) = self.preflight_clean_commit()?;
        self.terminal_state = TerminalState::CleanCommitStarted;
        self.commit_transition(LifecycleState::Clean, target_index, target)
    }

    /// Atomically pass the final strict deadline preflight, then commit CLEAN without cancellation.
    pub fn mark_clean_until(&mut self, deadline: tokio::time::Instant) -> eyre::Result<()> {
        let (target_index, target) = self.preflight_clean_commit()?;
        self.begin_clean_commit(tokio::time::Instant::now(), deadline)?;
        self.commit_transition(LifecycleState::Clean, target_index, target)
    }

    fn preflight_clean_commit(&self) -> eyre::Result<(usize, LifecycleSlot)> {
        ensure!(
            self.selected.state == LifecycleState::RunningUnclean,
            "lifecycle is not RUNNING"
        );
        ensure!(
            self.terminal_state == TerminalState::Preparing,
            "terminal lifecycle owner is not PREPARING"
        );
        let (selected_index, selected) = validate_slots(&self.file, self.binding)?;
        ensure!(
            selected_index == self.selected_index && selected == self.selected,
            "final lifecycle preflight no longer selects the pinned RUNNING authority"
        );
        prove_after_write(&self.parent, &self.file, self.anchor, self.binding)
            .wrap_err("final lifecycle geometry/binding/entry preflight")?;
        self.prepare_transition(LifecycleState::Clean)
    }

    fn begin_clean_commit(
        &mut self,
        now: tokio::time::Instant,
        deadline: tokio::time::Instant,
    ) -> eyre::Result<()> {
        ensure!(
            self.terminal_state == TerminalState::Preparing,
            "terminal lifecycle owner is not PREPARING"
        );
        ensure!(now < deadline, "terminal deadline expired before CLEAN");
        self.terminal_state = TerminalState::CleanCommitStarted;
        lifecycle_failpoint("clean_commit_started");
        Ok(())
    }

    fn transition(&mut self, state: LifecycleState) -> eyre::Result<()> {
        let (target_index, target) = self.prepare_transition(state)?;
        self.commit_transition(state, target_index, target)
    }

    fn prepare_transition(&self, state: LifecycleState) -> eyre::Result<(usize, LifecycleSlot)> {
        let generation = self
            .selected
            .generation
            .checked_add(1)
            .ok_or_else(|| eyre!("lifecycle generation wrap"))?;
        let target_index = 1 - self.selected_index;
        let target = LifecycleSlot {
            state,
            generation,
            setup_binding: self.binding,
        };
        Ok((target_index, target))
    }

    fn commit_transition(
        &mut self,
        state: LifecycleState,
        target_index: usize,
        target: LifecycleSlot,
    ) -> eyre::Result<()> {
        let failpoint_prefix = match state {
            LifecycleState::Initializing => "transition_initializing",
            LifecycleState::Clean => "transition_clean",
            LifecycleState::RunningUnclean => "transition_running",
        };
        let result = (|| {
            write_slot(&self.file, target_index, target, failpoint_prefix)?;
            lifecycle_io(&format!("{failpoint_prefix}_sync"), || {
                self.file.sync_data().wrap_err("sync lifecycle transition")
            })?;
            lifecycle_failpoint(&format!("{failpoint_prefix}_synced"));
            let (selected_index, selected) =
                lifecycle_io(&format!("{failpoint_prefix}_reread"), || {
                    validate_slots(&self.file, self.binding)
                })?;
            lifecycle_failpoint(&format!("{failpoint_prefix}_reread"));
            ensure!(
                selected_index == target_index && selected == target,
                "lifecycle transition did not commit exactly"
            );
            lifecycle_io(&format!("{failpoint_prefix}_proof"), || {
                prove_after_write(&self.parent, &self.file, self.anchor, self.binding)
            })?;
            lifecycle_failpoint(&format!("{failpoint_prefix}_entry_proved"));
            Ok((selected_index, selected))
        })();
        match result {
            Ok((selected_index, selected)) => {
                self.selected_index = selected_index;
                self.selected = selected;
                if state == LifecycleState::Clean {
                    self.terminal_state = TerminalState::CleanCommitFinished;
                }
                Ok(())
            }
            Err(error)
                if state == LifecycleState::Clean
                    && self.terminal_state == TerminalState::CleanCommitStarted =>
            {
                self.resolve_clean_commit_error(target_index, target, error)
            }
            Err(error) => Err(error),
        }
    }

    fn resolve_clean_commit_error(
        &mut self,
        target_index: usize,
        target: LifecycleSlot,
        original: eyre::Report,
    ) -> eyre::Result<()> {
        match self.classify_clean_authority(&self.file, target_index, target) {
            Ok(CleanAuthority::Target) => {
                self.selected_index = target_index;
                self.selected = target;
                self.terminal_state = TerminalState::CleanCommitFinished;
                Ok(())
            }
            Ok(CleanAuthority::Prior) => Err(eyre!(
                "CLEAN commit failed and structural reread selected the prior RUNNING authority: {original:#}"
            )),
            Err(same_fd_error) => {
                let reopened = open_lifecycle_at(self.parent.as_raw_fd(), false);
                match reopened.and_then(|file| {
                    let authority = self.classify_clean_authority(&file, target_index, target)?;
                    Ok((file, authority))
                }) {
                    Ok((file, CleanAuthority::Target)) => {
                        self.file = file;
                        self.selected_index = target_index;
                        self.selected = target;
                        self.terminal_state = TerminalState::CleanCommitFinished;
                        Ok(())
                    }
                    Ok((file, CleanAuthority::Prior)) => {
                        self.file = file;
                        Err(eyre!(
                            "CLEAN commit failed and fresh structural reopen selected the prior RUNNING authority: {original:#}"
                        ))
                    }
                    Err(reopen_error) => Err(eyre!(
                        "lifecycle authority unknown after CLEAN commit error; original={original:#}; same-fd classification={same_fd_error:#}; fresh reopen={reopen_error:#}"
                    )),
                }
            }
        }
    }

    fn classify_clean_authority(
        &self,
        file: &File,
        target_index: usize,
        target: LifecycleSlot,
    ) -> eyre::Result<CleanAuthority> {
        let (selected_index, selected) = validate_slots(file, self.binding)?;
        prove_after_write(&self.parent, file, self.anchor, self.binding)?;
        if selected_index == target_index && selected == target {
            return Ok(CleanAuthority::Target);
        }
        if selected_index == self.selected_index && selected == self.selected {
            return Ok(CleanAuthority::Prior);
        }
        Err(eyre!(
            "CLEAN commit error selected unexpected lifecycle authority {selected:?} in slot {selected_index}"
        ))
    }
}

/// Inspect an existing lifecycle authority without acquiring a writable file description.
///
/// B1 startup uses this dedicated seam for stopped classification and drops the descriptor before
/// returning its permanent storage-only closure.
pub fn inspect_existing_read_only(
    directory: &JournalDirectory,
    anchor: MessageJournalAnchor,
) -> eyre::Result<LifecycleSlot> {
    let parent = directory.parent_file();
    let file = open_lifecycle_read_only_at(parent.as_raw_fd())?;
    let geometry = prove_geometry_and_entry(&parent, &file)?;
    let binding = setup_binding(geometry, anchor);
    let (_, selected) = validate_slots(&file, binding)?;
    prove_after_write(&parent, &file, anchor, binding)?;
    Ok(selected)
}

pub fn encode_slot(slot: LifecycleSlot) -> [u8; SLOT_LEN] {
    let mut out = [0u8; SLOT_LEN];
    out[..16].copy_from_slice(MAGIC);
    out[16..18].copy_from_slice(&VERSION.to_be_bytes());
    out[18] = ROLE_NODE;
    out[19] = slot.state as u8;
    out[20..28].copy_from_slice(&slot.generation.to_be_bytes());
    out[44..76].copy_from_slice(slot.setup_binding.as_slice());
    let checksum = keccak256(&out[..SLOT_BODY_LEN]);
    out[SLOT_BODY_LEN..].copy_from_slice(checksum.as_slice());
    out
}

pub fn decode_slot(bytes: &[u8]) -> eyre::Result<LifecycleSlot> {
    ensure!(bytes.len() == SLOT_LEN, "lifecycle slot length is not 4096");
    ensure!(&bytes[..16] == MAGIC, "lifecycle magic mismatch");
    ensure!(
        u16::from_be_bytes(bytes[16..18].try_into().unwrap()) == VERSION,
        "lifecycle version mismatch"
    );
    ensure!(bytes[18] == ROLE_NODE, "lifecycle role is not NODE");
    ensure!(
        bytes[28..44].iter().all(|byte| *byte == 0),
        "lifecycle nonce is nonzero"
    );
    ensure!(
        bytes[76..SLOT_BODY_LEN].iter().all(|byte| *byte == 0),
        "lifecycle reserved bytes are nonzero"
    );
    ensure!(
        keccak256(&bytes[..SLOT_BODY_LEN]).as_slice() == &bytes[SLOT_BODY_LEN..],
        "lifecycle checksum mismatch"
    );
    Ok(LifecycleSlot {
        state: LifecycleState::try_from(bytes[19])?,
        generation: u64::from_be_bytes(bytes[20..28].try_into().unwrap()),
        setup_binding: B256::from_slice(&bytes[44..76]),
    })
}

fn journal_context(anchor: MessageJournalAnchor) -> B256 {
    let mut input = Vec::with_capacity(32 + 8 + 8 + 32);
    input.extend_from_slice(b"arb-lifecycle-journal-context-v1");
    input.extend_from_slice(&anchor.sequence.to_be_bytes());
    input.extend_from_slice(&anchor.block_number.to_be_bytes());
    input.extend_from_slice(anchor.block_hash.as_slice());
    keccak256(input)
}

fn setup_binding(geometry: Geometry, anchor: MessageJournalAnchor) -> B256 {
    let mut input = Vec::with_capacity(192);
    input.extend_from_slice(b"arb-lifecycle-setup-binding-v1");
    input.extend_from_slice(&geometry.parent_dev.to_be_bytes());
    input.extend_from_slice(&geometry.parent_ino.to_be_bytes());
    input.extend_from_slice(journal_context(anchor).as_slice());
    input.extend_from_slice(&geometry.file_dev.to_be_bytes());
    input.extend_from_slice(&geometry.file_ino.to_be_bytes());
    input.extend_from_slice(&geometry.fs_type.to_be_bytes());
    input.extend_from_slice(&geometry.frsize.to_be_bytes());
    input.extend_from_slice(&geometry.bsize.to_be_bytes());
    input.extend_from_slice(&FILE_LEN.to_be_bytes());
    input.extend_from_slice(&geometry.slot_a_physical.to_be_bytes());
    input.extend_from_slice(&geometry.slot_b_physical.to_be_bytes());
    keccak256(input)
}

fn open_lifecycle_at(parent: RawFd, create: bool) -> eyre::Result<File> {
    arb_reth_engine::assert_authority_operation_allowed("lifecycle-openat");
    let name = CString::new(LIFECYCLE_FILE).expect("fixed lifecycle name has no NUL");
    let mut flags = libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    if create {
        flags |= libc::O_CREAT | libc::O_EXCL;
    }
    #[cfg(test)]
    LIFECYCLE_OPEN_FLAGS.with(|observed| observed.borrow_mut().push(flags));
    let fd = unsafe { libc::openat(parent, name.as_ptr(), flags, 0o600) };
    if fd < 0 {
        return Err(io::Error::last_os_error()).wrap_err(if create {
            "exclusively create lifecycle authority"
        } else {
            "open existing lifecycle authority"
        });
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_lifecycle_read_only_at(parent: RawFd) -> eyre::Result<File> {
    arb_reth_engine::assert_authority_operation_allowed("lifecycle-openat-read-only");
    let name = CString::new(LIFECYCLE_FILE).expect("fixed lifecycle name has no NUL");
    let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    #[cfg(test)]
    LIFECYCLE_OPEN_FLAGS.with(|observed| observed.borrow_mut().push(flags));
    let fd = unsafe { libc::openat(parent, name.as_ptr(), flags, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error()).wrap_err("open existing lifecycle read-only");
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn set_len(fd: RawFd, length: u64) -> eyre::Result<()> {
    arb_reth_engine::assert_authority_operation_allowed("lifecycle-ftruncate");
    let length =
        libc::off_t::try_from(length).map_err(|_| eyre!("lifecycle length conversion overflow"))?;
    if unsafe { libc::ftruncate(fd, length) } != 0 {
        return Err(io::Error::last_os_error()).wrap_err("set lifecycle length");
    }
    Ok(())
}

fn fsync_fd(fd: RawFd) -> io::Result<()> {
    arb_reth_engine::assert_authority_operation_allowed("lifecycle-parent-fsync");
    if unsafe { libc::fsync(fd) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn pwrite_all(fd: RawFd, offset: u64, mut bytes: &[u8]) -> eyre::Result<()> {
    arb_reth_engine::assert_authority_operation_allowed("lifecycle-pwrite");
    let mut position = offset;
    while !bytes.is_empty() {
        let written = unsafe {
            libc::pwrite(
                fd,
                bytes.as_ptr().cast(),
                bytes.len(),
                libc::off_t::try_from(position).map_err(|_| eyre!("lifecycle offset overflow"))?,
            )
        };
        if written < 0 {
            return Err(io::Error::last_os_error()).wrap_err("write lifecycle authority");
        }
        ensure!(written != 0, "zero-byte lifecycle write");
        let written = usize::try_from(written).expect("positive ssize_t fits usize");
        position += written as u64;
        bytes = &bytes[written..];
    }
    Ok(())
}

fn pread_exact(fd: RawFd, offset: u64, mut bytes: &mut [u8]) -> eyre::Result<()> {
    arb_reth_engine::assert_authority_operation_allowed("lifecycle-pread");
    let mut position = offset;
    while !bytes.is_empty() {
        let read = unsafe {
            libc::pread(
                fd,
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                libc::off_t::try_from(position).map_err(|_| eyre!("lifecycle offset overflow"))?,
            )
        };
        if read < 0 {
            return Err(io::Error::last_os_error()).wrap_err("read lifecycle authority");
        }
        ensure!(read != 0, "short lifecycle read");
        let read = usize::try_from(read).expect("positive ssize_t fits usize");
        position += read as u64;
        bytes = &mut bytes[read..];
    }
    Ok(())
}

fn write_slot(
    file: &File,
    index: usize,
    slot: LifecycleSlot,
    failpoint_prefix: &str,
) -> eyre::Result<()> {
    ensure!(index < 2, "invalid lifecycle slot index");
    let bytes = encode_slot(slot);
    let offset = (index * SLOT_LEN) as u64;
    lifecycle_io(&format!("{failpoint_prefix}_body"), || {
        pwrite_all(file.as_raw_fd(), offset, &bytes[..SLOT_BODY_LEN])
    })?;
    lifecycle_failpoint(&format!("{failpoint_prefix}_body_written"));
    lifecycle_io(&format!("{failpoint_prefix}_checksum"), || {
        pwrite_all(
            file.as_raw_fd(),
            offset + SLOT_BODY_LEN as u64,
            &bytes[SLOT_BODY_LEN..],
        )
    })?;
    lifecycle_failpoint(&format!("{failpoint_prefix}_checksum_written"));
    lifecycle_io(&format!("{failpoint_prefix}_full"), || {
        pwrite_all(file.as_raw_fd(), offset, &bytes)
    })?;
    lifecycle_failpoint(&format!("{failpoint_prefix}_full_written"));
    Ok(())
}

fn lifecycle_io<T>(point: &str, operation: impl FnOnce() -> eyre::Result<T>) -> eyre::Result<T> {
    let configured = std::env::var("ARB_RETH_LIFECYCLE_IO_FAULT").ok();
    let timing = configured.as_deref().and_then(|value| {
        let (configured_point, timing) = value.split_once(':')?;
        (configured_point == point && matches!(timing, "before" | "after")).then_some(timing)
    });
    if timing == Some("before") {
        return Err(eyre!("injected lifecycle I/O failure before {point}"));
    }
    let result = operation()?;
    if std::env::var_os("ARB_RETH_LIFECYCLE_IO_PAUSE").as_deref()
        == Some(std::ffi::OsStr::new(point))
    {
        let ready = std::env::var_os("ARB_RETH_LIFECYCLE_IO_READY")
            .ok_or_else(|| eyre!("lifecycle I/O pause requires a ready-file path"))?;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(ready)
            .wrap_err("publish lifecycle I/O pause boundary")?
            .sync_all()
            .wrap_err("sync lifecycle I/O pause boundary")?;
        loop {
            std::thread::park();
        }
    }
    if timing == Some("after") {
        return Err(eyre!("injected lifecycle I/O failure after {point}"));
    }
    Ok(result)
}

fn read_slots(file: &File) -> eyre::Result<[[u8; SLOT_LEN]; 2]> {
    static READS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    if std::env::var_os("ARB_RETH_LIFECYCLE_READ_FAULT_AFTER_SECOND").is_some()
        && READS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) >= 2
    {
        return Err(io::Error::from_raw_os_error(libc::EIO))
            .wrap_err("injected lifecycle authority read failure");
    }
    let mut slots = [[0u8; SLOT_LEN]; 2];
    pread_exact(file.as_raw_fd(), 0, &mut slots[0])?;
    pread_exact(file.as_raw_fd(), SLOT_LEN as u64, &mut slots[1])?;
    Ok(slots)
}

fn validate_slots(file: &File, expected_binding: B256) -> eyre::Result<(usize, LifecycleSlot)> {
    let raw = read_slots(file)?;
    let mut valid = Vec::with_capacity(2);
    for (index, bytes) in raw.iter().enumerate() {
        if keccak256(&bytes[..SLOT_BODY_LEN]).as_slice() != &bytes[SLOT_BODY_LEN..] {
            continue;
        }
        let slot = decode_slot(bytes).map_err(|error| {
            eyre!("checksum-valid lifecycle slot {index} has invalid authority fields: {error:#}")
        })?;
        ensure!(
            slot.setup_binding == expected_binding,
            "lifecycle setup binding mismatch"
        );
        valid.push((index, slot));
    }
    ensure!(!valid.is_empty(), "both lifecycle slots are invalid");
    if valid.len() == 2 {
        ensure!(
            valid[0].1.generation != valid[1].1.generation,
            "equal lifecycle generations"
        );
    }
    Ok(*valid
        .iter()
        .max_by_key(|(_, slot)| slot.generation)
        .expect("nonempty"))
}

fn stat_fd(fd: RawFd) -> eyre::Result<libc::stat> {
    arb_reth_engine::assert_authority_operation_allowed("lifecycle-fstat");
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error()).wrap_err("fstat lifecycle authority");
    }
    Ok(unsafe { stat.assume_init() })
}

fn prove_geometry_and_entry(parent: &File, file: &File) -> eyre::Result<Geometry> {
    arb_reth_engine::assert_authority_operation_allowed("lifecycle-context-proof");
    let parent_stat = stat_fd(parent.as_raw_fd())?;
    let file_stat = stat_fd(file.as_raw_fd())?;
    ensure!(
        (file_stat.st_mode & libc::S_IFMT) == libc::S_IFREG,
        "lifecycle is not a regular file"
    );
    ensure!(file_stat.st_nlink == 1, "lifecycle link count is not one");
    ensure!(
        file_stat.st_size == FILE_LEN as libc::off_t,
        "lifecycle size is not 8192"
    );

    let name = CString::new(LIFECYCLE_FILE).expect("fixed lifecycle name has no NUL");
    let mut entry = std::mem::MaybeUninit::<libc::stat>::zeroed();
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            entry.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error()).wrap_err("prove lifecycle directory entry");
    }
    let entry = unsafe { entry.assume_init() };
    ensure!(
        entry.st_dev == file_stat.st_dev && entry.st_ino == file_stat.st_ino,
        "lifecycle entry/file identity mismatch"
    );
    ensure!(
        (entry.st_mode & libc::S_IFMT) == libc::S_IFREG && entry.st_nlink == 1,
        "lifecycle entry type/link mismatch"
    );

    let mut statfs = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    if unsafe { libc::fstatfs(file.as_raw_fd(), statfs.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error()).wrap_err("fstatfs lifecycle authority");
    }
    let statfs = unsafe { statfs.assume_init() };
    let fs_type = u64::try_from(statfs.f_type).map_err(|_| eyre!("negative filesystem type"))?;
    ensure!(
        matches!(fs_type, EXT4_SUPER_MAGIC | XFS_SUPER_MAGIC),
        "lifecycle filesystem is not ext4/xfs"
    );

    let mut statvfs = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
    if unsafe { libc::fstatvfs(file.as_raw_fd(), statvfs.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error()).wrap_err("fstatvfs lifecycle authority");
    }
    let statvfs = unsafe { statvfs.assume_init() };
    let frsize = statvfs.f_frsize;
    let bsize = statvfs.f_bsize;
    ensure!(
        frsize == SLOT_LEN as u64 && bsize == SLOT_LEN as u64,
        "lifecycle filesystem blocks are not 4096 bytes"
    );

    let (slot_a_physical, slot_b_physical) = fiemap_slots(file.as_raw_fd())?;
    Ok(Geometry {
        parent_dev: parent_stat.st_dev,
        parent_ino: parent_stat.st_ino,
        file_dev: file_stat.st_dev,
        file_ino: file_stat.st_ino,
        fs_type,
        frsize,
        bsize,
        slot_a_physical,
        slot_b_physical,
    })
}

fn fiemap_slots(fd: RawFd) -> eyre::Result<(u64, u64)> {
    let mut query = FiemapQuery::<16>::default();
    if unsafe { libc::ioctl(fd, FS_IOC_FIEMAP, &mut query) } != 0 {
        return Err(io::Error::last_os_error()).wrap_err("FIEMAP lifecycle authority");
    }
    let count =
        usize::try_from(query.mapped_extents).map_err(|_| eyre!("FIEMAP extent count overflow"))?;
    ensure!(
        count > 0 && count <= query.extents.len(),
        "FIEMAP returned invalid extent count"
    );
    let extents = &query.extents[..count];
    ensure!(
        extents
            .last()
            .is_some_and(|extent| extent.flags & FIEMAP_EXTENT_LAST != 0),
        "FIEMAP result is incomplete"
    );
    let mut logical_cursor = 0u64;
    for extent in extents {
        ensure!(
            extent.length > 0 && extent.flags & REJECTED_EXTENT_FLAGS == 0,
            "FIEMAP extent is unsupported"
        );
        if logical_cursor < FILE_LEN {
            ensure!(
                extent.logical == logical_cursor,
                "FIEMAP has a hole or overlap before logical offset {logical_cursor}"
            );
            logical_cursor = extent
                .logical
                .checked_add(extent.length)
                .ok_or_else(|| eyre!("FIEMAP logical range overflow"))?;
        }
    }
    ensure!(
        logical_cursor >= FILE_LEN,
        "FIEMAP does not cover the lifecycle authority"
    );
    let physical_at = |logical: u64| -> eyre::Result<u64> {
        let extent = extents
            .iter()
            .find(|extent| {
                logical >= extent.logical && logical < extent.logical.saturating_add(extent.length)
            })
            .ok_or_else(|| eyre!("FIEMAP hole at logical offset {logical}"))?;
        extent
            .physical
            .checked_add(logical - extent.logical)
            .ok_or_else(|| eyre!("FIEMAP physical offset overflow"))
    };
    let a = physical_at(0)?;
    let a_end = physical_at((SLOT_LEN - 1) as u64)?;
    let b = physical_at(SLOT_LEN as u64)?;
    let b_end = physical_at((2 * SLOT_LEN - 1) as u64)?;
    ensure!(
        a % SLOT_LEN as u64 == 0 && b % SLOT_LEN as u64 == 0,
        "lifecycle slots are not physically aligned"
    );
    ensure!(
        a_end == a + SLOT_LEN as u64 - 1 && b_end == b + SLOT_LEN as u64 - 1,
        "lifecycle slot range is not contiguous"
    );
    let a_range = a..a + SLOT_LEN as u64;
    let b_range = b..b + SLOT_LEN as u64;
    ensure!(
        a_range.end <= b_range.start || b_range.end <= a_range.start,
        "lifecycle physical slots overlap"
    );
    Ok((a, b))
}

fn prove_after_write(
    parent: &File,
    file: &File,
    anchor: MessageJournalAnchor,
    binding: B256,
) -> eyre::Result<()> {
    let geometry = prove_geometry_and_entry(parent, file)?;
    ensure!(
        setup_binding(geometry, anchor) == binding,
        "lifecycle binding changed after write"
    );
    Ok(())
}

fn lifecycle_failpoint(name: &str) {
    if std::env::var_os("ARB_RETH_LIFECYCLE_FAILPOINT").as_deref()
        == Some(std::ffi::OsStr::new(name))
    {
        unsafe extern "C" {
            fn _exit(status: i32) -> !;
        }
        // SAFETY: this test seam intentionally simulates sudden process loss.
        unsafe { _exit(86) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor() -> MessageJournalAnchor {
        MessageJournalAnchor {
            sequence: 0,
            block_number: 100,
            block_hash: B256::repeat_byte(0x42),
        }
    }

    #[test]
    fn lifecycle_slot_codec_rejects_every_authority_class_mutation() {
        let slot_a = LifecycleSlot {
            state: LifecycleState::Initializing,
            generation: 1,
            setup_binding: B256::repeat_byte(0xa5),
        };
        let slot_b = LifecycleSlot {
            state: LifecycleState::Clean,
            generation: 2,
            setup_binding: B256::repeat_byte(0xa5),
        };
        let bytes_a = encode_slot(slot_a);
        let bytes = encode_slot(slot_b);
        for (encoded, prefix, checksum) in [
            (
                &bytes_a,
                "4152424c4946454359434c455631000000010100000000000000000100000000000000000000000000000000a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
                "b3876796b9cd786396270f3bd7b0194938170dd4d721b63f585a3a4cc5c7eaf0",
            ),
            (
                &bytes,
                "4152424c4946454359434c455631000000010101000000000000000200000000000000000000000000000000a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
                "a756012d0dd7e87a35998a3a6dc39c5ab9c2fe9778b0e358d97c8feffafd03b9",
            ),
        ] {
            assert_eq!(alloy_primitives::hex::encode(&encoded[..76]), prefix);
            assert!(encoded[76..SLOT_BODY_LEN].iter().all(|byte| *byte == 0));
            assert_eq!(
                alloy_primitives::hex::encode(&encoded[SLOT_BODY_LEN..]),
                checksum
            );
        }
        assert_eq!(decode_slot(&bytes_a).unwrap(), slot_a);
        assert_eq!(decode_slot(&bytes).unwrap(), slot_b);
        assert_eq!(&bytes[20..28], &slot_b.generation.to_be_bytes());
        for offset in [0usize, 16, 18, 19, 28, 44, 76, 4064, 4095] {
            let mut changed = bytes;
            changed[offset] ^= 1;
            assert!(
                decode_slot(&changed).is_err(),
                "mutation at {offset} accepted"
            );
        }
    }

    #[test]
    fn lifecycle_real_filesystem_setup_startup_and_transitions() {
        let dir = tempfile::tempdir().unwrap();
        let directory = JournalDirectory::open(dir.path()).unwrap();
        let setup = LifecycleGuard::initialize(&directory, anchor()).unwrap();
        assert_eq!(setup.selected().state, LifecycleState::Clean);
        assert!(LifecycleGuard::initialize(&directory, anchor()).is_err());
        drop(setup);

        let mut guard = LifecycleGuard::open_existing(&directory, anchor()).unwrap();
        guard.mark_running().unwrap();
        assert_eq!(guard.selected().state, LifecycleState::RunningUnclean);
        guard.mark_clean().unwrap();
        assert_eq!(guard.selected().state, LifecycleState::Clean);
    }

    #[tokio::test]
    async fn expired_terminal_deadline_leaves_running_authoritative() {
        let dir = tempfile::tempdir().unwrap();
        let directory = JournalDirectory::open(dir.path()).unwrap();
        let mut guard = LifecycleGuard::initialize(&directory, anchor()).unwrap();
        guard.mark_running().unwrap();
        let running = guard.selected();

        let error = guard
            .mark_clean_until(tokio::time::Instant::now())
            .expect_err("an expired deadline cannot publish CLEAN");
        assert!(error.to_string().contains("deadline expired before CLEAN"));
        assert_eq!(guard.selected(), running);
        drop(guard);

        let reopened = LifecycleGuard::open_existing(&directory, anchor()).unwrap();
        assert_eq!(reopened.selected(), running);
        assert_eq!(reopened.selected().state, LifecycleState::RunningUnclean);
    }

    #[test]
    fn exact_deadline_equality_cannot_start_clean_commit() {
        let dir = tempfile::tempdir().unwrap();
        let directory = JournalDirectory::open(dir.path()).unwrap();
        let mut guard = LifecycleGuard::initialize(&directory, anchor()).unwrap();
        guard.mark_running().unwrap();
        let running = guard.selected();
        let deadline = tokio::time::Instant::now();

        guard.preflight_clean_commit().unwrap();
        let error = guard
            .begin_clean_commit(deadline, deadline)
            .expect_err("now == deadline must fail the strict preflight");
        assert!(error.to_string().contains("deadline expired before CLEAN"));
        assert_eq!(guard.terminal_state, TerminalState::Preparing);
        assert_eq!(guard.selected(), running);
        drop(guard);

        assert_eq!(
            LifecycleGuard::open_existing(&directory, anchor())
                .unwrap()
                .selected(),
            running
        );
    }

    #[test]
    fn owner_panic_immediately_after_clean_linearization_leaves_structural_running() {
        let dir = tempfile::tempdir().unwrap();
        let directory = JournalDirectory::open(dir.path()).unwrap();
        let mut guard = LifecycleGuard::initialize(&directory, anchor()).unwrap();
        guard.mark_running().unwrap();
        let running = guard.selected();

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            guard.preflight_clean_commit().unwrap();
            let now = tokio::time::Instant::now();
            guard
                .begin_clean_commit(
                    now,
                    now.checked_add(std::time::Duration::from_secs(1)).unwrap(),
                )
                .unwrap();
            panic!("injected owner panic after CLEAN_COMMIT_STARTED");
        }));
        assert!(panic.is_err());
        assert_eq!(guard.terminal_state, TerminalState::CleanCommitStarted);
        drop(guard);

        assert_eq!(
            LifecycleGuard::open_existing(&directory, anchor())
                .unwrap()
                .selected(),
            running
        );
    }

    #[test]
    fn clean_commit_ambiguous_io_uses_only_structural_authority() {
        const CHILD_DATADIR: &str = "ARB_RETH_LIFECYCLE_IO_TEST_DATADIR";
        const CHILD_EXPECT: &str = "ARB_RETH_LIFECYCLE_IO_TEST_EXPECT";
        if let Some(datadir) = std::env::var_os(CHILD_DATADIR) {
            let directory = JournalDirectory::open(std::path::Path::new(&datadir)).unwrap();
            let mut guard = LifecycleGuard::open_existing(&directory, anchor()).unwrap();
            let result = guard.mark_clean_until(
                tokio::time::Instant::now()
                    .checked_add(std::time::Duration::from_secs(5))
                    .unwrap(),
            );
            let selected = LifecycleGuard::open_existing(&directory, anchor())
                .unwrap()
                .selected()
                .state;
            match std::env::var(CHILD_EXPECT).as_deref() {
                Ok("running") => {
                    assert!(result.is_err());
                    assert_eq!(selected, LifecycleState::RunningUnclean);
                }
                Ok("clean") => {
                    result.expect("complete structurally valid CLEAN must win");
                    assert_eq!(selected, LifecycleState::Clean);
                }
                other => panic!("unknown lifecycle I/O expectation {other:?}"),
            }
            return;
        }

        let cases = [
            ("transition_clean_body:before", "running"),
            ("transition_clean_body:after", "running"),
            ("transition_clean_checksum:before", "running"),
            ("transition_clean_checksum:after", "clean"),
            ("transition_clean_full:before", "clean"),
            ("transition_clean_full:after", "clean"),
            ("transition_clean_sync:before", "clean"),
            ("transition_clean_sync:after", "clean"),
            ("transition_clean_reread:before", "clean"),
            ("transition_clean_reread:after", "clean"),
            ("transition_clean_proof:before", "clean"),
            ("transition_clean_proof:after", "clean"),
        ];
        for (fault, expected) in cases {
            let dir = tempfile::tempdir().unwrap();
            let directory = JournalDirectory::open(dir.path()).unwrap();
            let mut guard = LifecycleGuard::initialize(&directory, anchor()).unwrap();
            guard.mark_running().unwrap();
            drop(guard);
            drop(directory);

            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "lifecycle::tests::clean_commit_ambiguous_io_uses_only_structural_authority",
                    "--nocapture",
                ])
                .env(CHILD_DATADIR, dir.path())
                .env(CHILD_EXPECT, expected)
                .env("ARB_RETH_LIFECYCLE_IO_FAULT", fault)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "fault {fault} failed\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
    }

    #[test]
    fn force_kill_at_clean_io_boundaries_reopens_structural_authority() {
        const CHILD_DATADIR: &str = "ARB_RETH_LIFECYCLE_KILL_TEST_DATADIR";
        if let Some(datadir) = std::env::var_os(CHILD_DATADIR) {
            let directory = JournalDirectory::open(std::path::Path::new(&datadir)).unwrap();
            let mut guard = LifecycleGuard::open_existing(&directory, anchor()).unwrap();
            guard
                .mark_clean_until(
                    tokio::time::Instant::now()
                        .checked_add(std::time::Duration::from_secs(30))
                        .unwrap(),
                )
                .unwrap();
            panic!("force-kill child unexpectedly passed its pause boundary");
        }

        let cases = [
            ("transition_clean_body", LifecycleState::RunningUnclean),
            ("transition_clean_checksum", LifecycleState::Clean),
            ("transition_clean_full", LifecycleState::Clean),
            ("transition_clean_sync", LifecycleState::Clean),
            ("transition_clean_reread", LifecycleState::Clean),
            ("transition_clean_proof", LifecycleState::Clean),
        ];
        for (point, expected) in cases {
            let dir = tempfile::tempdir().unwrap();
            let directory = JournalDirectory::open(dir.path()).unwrap();
            let mut guard = LifecycleGuard::initialize(&directory, anchor()).unwrap();
            guard.mark_running().unwrap();
            drop(guard);
            drop(directory);
            let ready = dir.path().join("kill-ready");

            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "lifecycle::tests::force_kill_at_clean_io_boundaries_reopens_structural_authority",
                    "--nocapture",
                ])
                .env(CHILD_DATADIR, dir.path())
                .env("ARB_RETH_LIFECYCLE_IO_PAUSE", point)
                .env("ARB_RETH_LIFECYCLE_IO_READY", &ready)
                .spawn()
                .unwrap();
            let wait_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !ready.exists() {
                assert!(
                    std::time::Instant::now() < wait_deadline,
                    "child did not reach force-kill boundary {point}"
                );
                if let Some(status) = child.try_wait().unwrap() {
                    panic!("child exited at force-kill boundary {point}: {status}");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            child.kill().unwrap();
            let status = child.wait().unwrap();
            assert!(
                !status.success(),
                "force-killed child unexpectedly succeeded"
            );

            let directory = JournalDirectory::open(dir.path()).unwrap();
            assert_eq!(
                LifecycleGuard::open_existing(&directory, anchor())
                    .unwrap()
                    .selected()
                    .state,
                expected,
                "force-kill boundary {point} selected the wrong authority"
            );
        }
    }

    #[test]
    fn unreadable_and_reopen_failed_clean_media_reports_authority_unknown() {
        const CHILD_DATADIR: &str = "ARB_RETH_LIFECYCLE_UNKNOWN_TEST_DATADIR";
        if let Some(datadir) = std::env::var_os(CHILD_DATADIR) {
            let path = std::path::Path::new(&datadir);
            let directory = JournalDirectory::open(path).unwrap();
            let mut guard = LifecycleGuard::open_existing(&directory, anchor()).unwrap();
            let error = guard
                .mark_clean_until(
                    tokio::time::Instant::now()
                        .checked_add(std::time::Duration::from_secs(1))
                        .unwrap(),
                )
                .expect_err("unreadable fd plus failed reopen cannot decide authority");
            assert!(
                error.to_string().contains("lifecycle authority unknown"),
                "unexpected error: {error:#}"
            );
            assert_eq!(guard.terminal_state, TerminalState::CleanCommitStarted);
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let directory = JournalDirectory::open(dir.path()).unwrap();
        let mut guard = LifecycleGuard::initialize(&directory, anchor()).unwrap();
        guard.mark_running().unwrap();
        drop(guard);
        drop(directory);

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "lifecycle::tests::unreadable_and_reopen_failed_clean_media_reports_authority_unknown",
                "--nocapture",
            ])
            .env(CHILD_DATADIR, dir.path())
            // Open and the final preflight consume two successful reads. Fail the transition's
            // reread plus both same-fd and fresh-reopen classification to exercise the
            // authority-unknown ambiguous-I/O path.
            .env("ARB_RETH_LIFECYCLE_READ_FAULT_AFTER_SECOND", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "authority-unknown child failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    #[test]
    fn lifecycle_open_modes_are_exact_and_existing_fd_is_reused() {
        let dir = tempfile::tempdir().unwrap();
        let directory = JournalDirectory::open(dir.path()).unwrap();
        LIFECYCLE_OPEN_FLAGS.with(|observed| observed.borrow_mut().clear());
        let setup = LifecycleGuard::initialize(&directory, anchor()).unwrap();
        assert_eq!(
            LIFECYCLE_OPEN_FLAGS.with(|observed| observed.borrow().clone()),
            vec![libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_CREAT | libc::O_EXCL]
        );
        drop(setup);

        LIFECYCLE_OPEN_FLAGS.with(|observed| observed.borrow_mut().clear());
        let mut guard = LifecycleGuard::open_existing(&directory, anchor()).unwrap();
        guard.mark_running().unwrap();
        guard.mark_clean().unwrap();
        assert_eq!(
            LIFECYCLE_OPEN_FLAGS.with(|observed| observed.borrow().clone()),
            vec![libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW],
            "ordinary startup or a transition reopened the lifecycle path"
        );
        drop(guard);

        LIFECYCLE_OPEN_FLAGS.with(|observed| observed.borrow_mut().clear());
        assert_eq!(
            inspect_existing_read_only(&directory, anchor())
                .unwrap()
                .state,
            LifecycleState::Clean
        );
        assert_eq!(
            LIFECYCLE_OPEN_FLAGS.with(|observed| observed.borrow().clone()),
            vec![libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW],
            "B1 classification acquired a writable lifecycle descriptor"
        );
    }

    #[test]
    fn lifecycle_entry_identity_is_reproved_after_transition() {
        let restored = tempfile::tempdir().unwrap();
        let restored_directory = JournalDirectory::open(restored.path()).unwrap();
        let mut restored_guard = LifecycleGuard::initialize(&restored_directory, anchor()).unwrap();
        let fixed = restored.path().join(LIFECYCLE_FILE);
        let moved = restored.path().join("moved-lifecycle");
        std::fs::rename(&fixed, &moved).unwrap();
        std::fs::rename(&moved, &fixed).unwrap();
        restored_guard.mark_running().unwrap();

        let substituted = tempfile::tempdir().unwrap();
        let substituted_directory = JournalDirectory::open(substituted.path()).unwrap();
        let mut substituted_guard =
            LifecycleGuard::initialize(&substituted_directory, anchor()).unwrap();
        let fixed = substituted.path().join(LIFECYCLE_FILE);
        let pinned = substituted.path().join("pinned-lifecycle");
        std::fs::rename(&fixed, &pinned).unwrap();
        std::fs::copy(&pinned, &fixed).unwrap();
        assert!(substituted_guard.mark_running().is_err());
    }

    #[test]
    fn final_clean_preflight_rejects_substitution_before_linearization() {
        let dir = tempfile::tempdir().unwrap();
        let directory = JournalDirectory::open(dir.path()).unwrap();
        let mut guard = LifecycleGuard::initialize(&directory, anchor()).unwrap();
        guard.mark_running().unwrap();
        let running = guard.selected();
        let fixed = dir.path().join(LIFECYCLE_FILE);
        let pinned = dir.path().join("pinned-running-lifecycle");
        std::fs::rename(&fixed, &pinned).unwrap();
        std::fs::copy(&pinned, &fixed).unwrap();

        let error = guard
            .mark_clean_until(
                tokio::time::Instant::now()
                    .checked_add(std::time::Duration::from_secs(1))
                    .unwrap(),
            )
            .expect_err("substituted fixed entry must fail before CLEAN linearization");
        assert!(
            error
                .to_string()
                .contains("final lifecycle geometry/binding/entry preflight"),
            "unexpected error: {error:#}"
        );
        assert_eq!(guard.terminal_state, TerminalState::Preparing);
        assert_eq!(guard.selected(), running);

        std::fs::remove_file(&fixed).unwrap();
        std::fs::rename(&pinned, &fixed).unwrap();
        assert_eq!(
            LifecycleGuard::open_existing(&directory, anchor())
                .unwrap()
                .selected(),
            running,
            "failed preflight must write no CLEAN authority"
        );
    }

    #[test]
    fn generation_wrap_rejects_before_clean_linearization() {
        let dir = tempfile::tempdir().unwrap();
        let directory = JournalDirectory::open(dir.path()).unwrap();
        let mut guard = LifecycleGuard::initialize(&directory, anchor()).unwrap();
        guard.mark_running().unwrap();
        let max_running = LifecycleSlot {
            state: LifecycleState::RunningUnclean,
            generation: u64::MAX,
            setup_binding: guard.binding,
        };
        let max_index = 1 - guard.selected_index;
        pwrite_all(
            guard.file.as_raw_fd(),
            (max_index * SLOT_LEN) as u64,
            &encode_slot(max_running),
        )
        .unwrap();
        guard.file.sync_data().unwrap();
        drop(guard);

        let mut guard = LifecycleGuard::open_existing(&directory, anchor()).unwrap();
        assert_eq!(guard.selected(), max_running);
        let error = guard
            .mark_clean_until(
                tokio::time::Instant::now()
                    .checked_add(std::time::Duration::from_secs(1))
                    .unwrap(),
            )
            .expect_err("generation wrap must fail before CLEAN linearization");
        assert!(error.to_string().contains("lifecycle generation wrap"));
        assert_eq!(guard.terminal_state, TerminalState::Preparing);
        assert_eq!(guard.selected(), max_running);
        drop(guard);

        assert_eq!(
            LifecycleGuard::open_existing(&directory, anchor())
                .unwrap()
                .selected(),
            max_running,
            "generation wrap must not attempt a CLEAN slot write"
        );
    }

    #[test]
    fn lifecycle_slot_selection_conflict_invalid_and_wrap_rules() {
        let dir = tempfile::tempdir().unwrap();
        let directory = JournalDirectory::open(dir.path()).unwrap();
        let mut guard = LifecycleGuard::initialize(&directory, anchor()).unwrap();
        let binding = guard.binding;

        let equal = LifecycleSlot {
            state: LifecycleState::Clean,
            generation: 7,
            setup_binding: binding,
        };
        pwrite_all(guard.file.as_raw_fd(), 0, &encode_slot(equal)).unwrap();
        pwrite_all(guard.file.as_raw_fd(), SLOT_LEN as u64, &encode_slot(equal)).unwrap();
        assert!(validate_slots(&guard.file, binding).is_err());

        let wrong_binding = LifecycleSlot {
            generation: 8,
            setup_binding: B256::repeat_byte(0xee),
            ..equal
        };
        pwrite_all(
            guard.file.as_raw_fd(),
            SLOT_LEN as u64,
            &encode_slot(wrong_binding),
        )
        .unwrap();
        assert!(validate_slots(&guard.file, binding).is_err());

        pwrite_all(guard.file.as_raw_fd(), 0, &[0u8; SLOT_LEN]).unwrap();
        assert_eq!(
            validate_slots(&guard.file, B256::repeat_byte(0xee))
                .unwrap()
                .0,
            1
        );
        pwrite_all(guard.file.as_raw_fd(), SLOT_LEN as u64, &[0u8; SLOT_LEN]).unwrap();
        assert!(validate_slots(&guard.file, binding).is_err());

        guard.selected = LifecycleSlot {
            state: LifecycleState::Clean,
            generation: u64::MAX,
            setup_binding: binding,
        };
        assert!(guard.mark_running().is_err());
    }

    #[test]
    fn lifecycle_transition_crash_matrix() {
        const CHILD_DATADIR: &str = "ARB_RETH_LIFECYCLE_TRANSITION_TEST_DATADIR";
        const CHILD_ACTION: &str = "ARB_RETH_LIFECYCLE_TRANSITION_TEST_ACTION";
        if let Some(datadir) = std::env::var_os(CHILD_DATADIR) {
            let directory = JournalDirectory::open(std::path::Path::new(&datadir)).unwrap();
            let mut guard = LifecycleGuard::open_existing(&directory, anchor()).unwrap();
            match std::env::var(CHILD_ACTION).as_deref() {
                Ok("running") => guard.mark_running().unwrap(),
                Ok("clean") => guard.mark_clean().unwrap(),
                other => panic!("unknown lifecycle transition child action {other:?}"),
            }
            return;
        }

        let mut cases = Vec::new();
        for (action, prior, target) in [
            (
                "running",
                LifecycleState::Clean,
                LifecycleState::RunningUnclean,
            ),
            (
                "clean",
                LifecycleState::RunningUnclean,
                LifecycleState::Clean,
            ),
        ] {
            let prefix = if action == "running" {
                "transition_running"
            } else {
                "transition_clean"
            };
            for suffix in [
                "body_written",
                "checksum_written",
                "full_written",
                "synced",
                "reread",
                "entry_proved",
            ] {
                let expected = if suffix == "body_written" {
                    prior
                } else {
                    target
                };
                cases.push((action, format!("{prefix}_{suffix}"), expected));
            }
        }

        let executable = std::env::current_exe().unwrap();
        for (action, point, expected) in cases {
            let dir = tempfile::tempdir().unwrap();
            let directory = JournalDirectory::open(dir.path()).unwrap();
            let mut guard = LifecycleGuard::initialize(&directory, anchor()).unwrap();
            if action == "clean" {
                guard.mark_running().unwrap();
            }
            drop(guard);
            drop(directory);

            let status = std::process::Command::new(&executable)
                .args([
                    "--exact",
                    "lifecycle::tests::lifecycle_transition_crash_matrix",
                    "--nocapture",
                ])
                .env(CHILD_DATADIR, dir.path())
                .env(CHILD_ACTION, action)
                .env("ARB_RETH_LIFECYCLE_FAILPOINT", &point)
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(86), "failpoint {point} did not crash");
            let directory = JournalDirectory::open(dir.path()).unwrap();
            assert_eq!(
                LifecycleGuard::open_existing(&directory, anchor())
                    .unwrap()
                    .selected()
                    .state,
                expected,
                "failpoint {point} selected the wrong state"
            );
        }
    }

    #[test]
    fn copied_bytes_and_changed_context_reject() {
        let first = tempfile::tempdir().unwrap();
        let first_directory = JournalDirectory::open(first.path()).unwrap();
        LifecycleGuard::initialize(&first_directory, anchor()).unwrap();
        assert!(
            LifecycleGuard::open_existing(
                &first_directory,
                MessageJournalAnchor {
                    block_hash: B256::repeat_byte(0x43),
                    ..anchor()
                }
            )
            .is_err()
        );

        let second = tempfile::tempdir().unwrap();
        std::fs::copy(
            first.path().join(LIFECYCLE_FILE),
            second.path().join(LIFECYCLE_FILE),
        )
        .unwrap();
        let second_directory = JournalDirectory::open(second.path()).unwrap();
        assert!(LifecycleGuard::open_existing(&second_directory, anchor()).is_err());
    }

    #[test]
    fn lifecycle_init_failpoint_child() {
        const CHILD_DATADIR: &str = "ARB_RETH_LIFECYCLE_TEST_DATADIR";
        if let Some(datadir) = std::env::var_os(CHILD_DATADIR) {
            let directory = JournalDirectory::open(std::path::Path::new(&datadir)).unwrap();
            LifecycleGuard::initialize(&directory, anchor()).unwrap();
            return;
        }

        let points = [
            ("provisional_full_written", None),
            ("provisional_synced", None),
            ("provisional_entry_proved", None),
            ("a_initializing_body_written", None),
            (
                "a_initializing_checksum_written",
                Some(LifecycleState::Initializing),
            ),
            (
                "a_initializing_full_written",
                Some(LifecycleState::Initializing),
            ),
            ("a_initializing_synced", Some(LifecycleState::Initializing)),
            (
                "a_initializing_entry_proved",
                Some(LifecycleState::Initializing),
            ),
            (
                "b_initializing_body_written",
                Some(LifecycleState::Initializing),
            ),
            (
                "b_initializing_checksum_written",
                Some(LifecycleState::Initializing),
            ),
            (
                "b_initializing_full_written",
                Some(LifecycleState::Initializing),
            ),
            ("b_initializing_synced", Some(LifecycleState::Initializing)),
            ("b_initializing_reread", Some(LifecycleState::Initializing)),
            (
                "b_initializing_parent_synced",
                Some(LifecycleState::Initializing),
            ),
            (
                "b_initializing_entry_proved",
                Some(LifecycleState::Initializing),
            ),
            ("b_clean_body_written", Some(LifecycleState::Initializing)),
            ("b_clean_checksum_written", Some(LifecycleState::Clean)),
            ("b_clean_full_written", Some(LifecycleState::Clean)),
            ("b_clean_synced", Some(LifecycleState::Clean)),
            ("b_clean_reread", Some(LifecycleState::Clean)),
            ("b_clean_entry_proved", Some(LifecycleState::Clean)),
        ];
        let executable = std::env::current_exe().unwrap();
        for (point, expected) in points {
            let dir = tempfile::tempdir().unwrap();
            let status = std::process::Command::new(&executable)
                .args([
                    "--exact",
                    "lifecycle::tests::lifecycle_init_failpoint_child",
                    "--nocapture",
                ])
                .env(CHILD_DATADIR, dir.path())
                .env("ARB_RETH_LIFECYCLE_FAILPOINT", point)
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(86), "failpoint {point} did not crash");

            let directory = JournalDirectory::open(dir.path()).unwrap();
            let reopened = LifecycleGuard::open_existing(&directory, anchor());
            match expected {
                Some(state) => assert_eq!(
                    reopened.unwrap().selected().state,
                    state,
                    "failpoint {point} selected the wrong authority state"
                ),
                None => assert!(
                    reopened.is_err(),
                    "failpoint {point} unexpectedly authorized startup"
                ),
            }
        }
    }
}
