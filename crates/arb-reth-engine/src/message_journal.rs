//! Durable identities for feed-executed and L1-verified messages.
//!
//! The Reth block database cannot reconstruct the original `MessageWithMetadata`, so overlap
//! verification needs a small sidecar. The file is append-only NDJSON: a trusted anchor followed by
//! contiguous applied-message records and optional same-sequence L1-promotion records. Complete
//! corrupt lines are fatal; an incomplete final line from a crash is truncated on open.

use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{BufRead as _, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use alloy_primitives::B256;
use eyre::{WrapErr as _, ensure, eyre};
use serde::{Deserialize, Serialize};

use crate::{ArbEngineInput, ArbEngineInputSource, ArbMessageFingerprint};

pub const MESSAGE_JOURNAL_FILE: &str = "arb-message-journal.ndjson";
pub const DIVERGENCE_MARKER_FILE: &str = "arb-message-divergence.json";
const JOURNAL_VERSION: u64 = 1;
const JOURNAL_RETAIN_MESSAGES: usize = 100_000;
const JOURNAL_COMPACT_TRIGGER: usize = 110_000;

/// Complete journal identity at an anchor or applied message.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageJournalAnchor {
    pub sequence: u64,
    pub block_number: u64,
    pub block_hash: B256,
}

/// Full durable identity for one applied Arbitrum message.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageJournalEntry {
    pub sequence: u64,
    pub block_number: u64,
    pub block_hash: B256,
    pub parent_hash: B256,
    pub delayed_messages_read: u64,
    pub fingerprint: ArbMessageFingerprint,
    pub source: ArbEngineInputSource,
}

/// Result of validating a journal without opening it for writes or repairing its crash tail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageJournalInspection {
    pub anchor: MessageJournalAnchor,
    pub entries: Vec<MessageJournalEntry>,
    pub watermark: MessageJournalAnchor,
    pub complete_byte_offset: u64,
    pub has_incomplete_tail: bool,
}

impl MessageJournalInspection {
    /// Returns the complete identity at `sequence`, including the anchor identity.
    pub fn identity(&self, sequence: u64) -> Option<MessageJournalAnchor> {
        if sequence == self.anchor.sequence {
            return Some(self.anchor);
        }
        self.entry(sequence).map(|entry| MessageJournalAnchor {
            sequence: entry.sequence,
            block_number: entry.block_number,
            block_hash: entry.block_hash,
        })
    }

    /// Returns the retained full message identity at `sequence`.
    pub fn entry(&self, sequence: u64) -> Option<MessageJournalEntry> {
        self.entries
            .iter()
            .find(|entry| entry.sequence == sequence)
            .copied()
    }

    fn sequence_for_target(&self, block_number: u64, block_hash: B256) -> eyre::Result<u64> {
        if block_number == self.anchor.block_number && block_hash == self.anchor.block_hash {
            return Ok(self.anchor.sequence);
        }
        self.entries
            .iter()
            .find(|entry| entry.block_number == block_number && entry.block_hash == block_hash)
            .map(|entry| entry.sequence)
            .ok_or_else(|| {
                eyre!(
                    "journal has no identity for recovery target block {block_number} ({block_hash:#x}); retained identities span blocks {} through {}",
                    self.anchor.block_number,
                    self.watermark.block_number,
                )
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "record", rename_all = "snake_case")]
enum DiskRecord {
    Header {
        version: u64,
        anchor: MessageJournalAnchor,
    },
    Message {
        version: u64,
        entry: MessageJournalEntry,
    },
}

#[derive(Debug, Serialize)]
struct DivergenceMarker<'a> {
    version: u64,
    detected_unix_seconds: u64,
    tip_block_number: u64,
    tip_block_hash: B256,
    next_sequence: u64,
    incoming_source: ArbEngineInputSource,
    incoming_message: &'a arbitrum_alloy_sequencer::sequencer::feed::BroadcastFeedMessage,
    error: &'a str,
}

pub(crate) struct MessageJournal {
    path: PathBuf,
    anchor: MessageJournalAnchor,
    entries: BTreeMap<u64, MessageJournalEntry>,
    append_operations: usize,
}

impl MessageJournal {
    pub(crate) fn path_in(datadir: &Path) -> PathBuf {
        datadir.join(MESSAGE_JOURNAL_FILE)
    }

    pub(crate) fn divergence_path_in(datadir: &Path) -> PathBuf {
        datadir.join(DIVERGENCE_MARKER_FILE)
    }

    pub(crate) fn unresolved_divergence_path(&self) -> PathBuf {
        self.path.with_file_name(DIVERGENCE_MARKER_FILE)
    }

    pub(crate) fn recovery_marker_exists(&self) -> bool {
        self.path
            .with_file_name("arb-message-recovery.json")
            .exists()
    }

    pub(crate) fn write_divergence_marker(
        &self,
        tip_block_number: u64,
        tip_block_hash: B256,
        next_sequence: u64,
        input: &ArbEngineInput,
        error: &str,
    ) -> eyre::Result<()> {
        let path = self.unresolved_divergence_path();
        if path.exists() {
            return Ok(());
        }
        let marker = DivergenceMarker {
            version: JOURNAL_VERSION,
            detected_unix_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            tip_block_number,
            tip_block_hash,
            next_sequence,
            incoming_source: input.source(),
            incoming_message: input.message(),
            error,
        };
        // Create the final path first: even a torn marker blocks startup after power loss.
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer_pretty(&mut writer, &marker)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        sync_parent(&path)?;
        Ok(())
    }

    pub(crate) fn create(path: PathBuf, anchor: MessageJournalAnchor) -> eyre::Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .wrap_err_with(|| format!("create message journal {}", path.display()))?;
        let mut writer = BufWriter::new(file);
        write_record(
            &mut writer,
            &DiskRecord::Header {
                version: JOURNAL_VERSION,
                anchor,
            },
        )?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        sync_parent(&path)?;
        Ok(Self {
            path,
            anchor,
            entries: BTreeMap::new(),
            append_operations: 0,
        })
    }

    pub(crate) fn open(path: PathBuf) -> eyre::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .wrap_err_with(|| format!("open message journal {}", path.display()))?;
        let mut reader = BufReader::new(file.try_clone()?);
        let mut line = Vec::new();
        let mut complete_offset = 0u64;
        let mut records = Vec::new();
        loop {
            line.clear();
            let read = reader.read_until(b'\n', &mut line)?;
            if read == 0 {
                break;
            }
            if !line.ends_with(b"\n") {
                file.set_len(complete_offset)?;
                file.sync_data()?;
                break;
            }
            complete_offset += read as u64;
            let record = serde_json::from_slice::<DiskRecord>(&line).wrap_err_with(|| {
                format!("invalid complete message-journal record ending at byte {complete_offset}")
            })?;
            records.push(record);
        }

        let Some(DiskRecord::Header { version, anchor }) = records.first().copied() else {
            return Err(eyre!("message journal is missing its header record"));
        };
        ensure!(
            version == JOURNAL_VERSION,
            "unsupported message journal version {version}"
        );

        let mut entries = BTreeMap::new();
        let mut watermark = anchor.sequence;
        for record in records.into_iter().skip(1) {
            let DiskRecord::Message { version, entry } = record else {
                return Err(eyre!("message journal contains a second header"));
            };
            ensure!(
                version == JOURNAL_VERSION,
                "unsupported message journal version {version}"
            );
            if let Some(existing) = entries.get(&entry.sequence).copied() {
                validate_promotion(existing, entry)?;
            } else {
                ensure!(
                    entry.sequence == watermark + 1,
                    "message journal sequence gap: expected {}, got {}",
                    watermark + 1,
                    entry.sequence
                );
                watermark = entry.sequence;
            }
            entries.insert(entry.sequence, entry);
        }

        Ok(Self {
            path,
            anchor,
            entries,
            append_operations: 0,
        })
    }

    pub(crate) const fn anchor(&self) -> MessageJournalAnchor {
        self.anchor
    }

    pub(crate) fn watermark(&self) -> MessageJournalAnchor {
        self.entries
            .last_key_value()
            .map(|(_, entry)| MessageJournalAnchor {
                sequence: entry.sequence,
                block_number: entry.block_number,
                block_hash: entry.block_hash,
            })
            .unwrap_or(self.anchor)
    }

    pub(crate) fn entry(&self, sequence: u64) -> Option<MessageJournalEntry> {
        self.entries.get(&sequence).copied()
    }

    /// Return the journal-durable maximal contiguous L1-authoritative prefix.
    pub(crate) fn l1_verified_tip(&self) -> MessageJournalAnchor {
        let mut tip = self.anchor;
        for entry in self.entries.values() {
            let Some(expected) = tip.sequence.checked_add(1) else {
                break;
            };
            if entry.sequence != expected || entry.source != ArbEngineInputSource::L1 {
                break;
            }
            tip = MessageJournalAnchor {
                sequence: entry.sequence,
                block_number: entry.block_number,
                block_hash: entry.block_hash,
            };
        }
        tip
    }

    pub(crate) const fn append_operations(&self) -> usize {
        self.append_operations
    }

    /// Append applied entries or L1 promotions and fsync them as one durability batch.
    pub(crate) fn append_durable(
        &mut self,
        new_entries: &[MessageJournalEntry],
    ) -> eyre::Result<()> {
        if new_entries.is_empty() {
            return Ok(());
        }

        let mut updates = BTreeMap::new();
        let mut watermark = self.watermark().sequence;
        for &entry in new_entries {
            let existing = updates
                .get(&entry.sequence)
                .copied()
                .or_else(|| self.entries.get(&entry.sequence).copied());
            if let Some(existing) = existing {
                validate_promotion(existing, entry)?;
            } else {
                ensure!(
                    entry.sequence == watermark + 1,
                    "message journal sequence gap: expected {}, got {}",
                    watermark + 1,
                    entry.sequence
                );
                watermark = entry.sequence;
            }
            updates.insert(entry.sequence, entry);
        }

        let file = OpenOptions::new().append(true).open(&self.path)?;
        let mut writer = BufWriter::new(file);
        for &entry in new_entries {
            write_record(
                &mut writer,
                &DiskRecord::Message {
                    version: JOURNAL_VERSION,
                    entry,
                },
            )?;
        }
        writer.flush()?;
        writer.get_ref().sync_data()?;
        self.entries.extend(updates);
        self.append_operations += 1;
        if self.entries.len() >= JOURNAL_COMPACT_TRIGGER {
            self.compact_verified_prefix(JOURNAL_RETAIN_MESSAGES)?;
        }
        Ok(())
    }

    fn sequence_for_target(&self, block_number: u64, block_hash: B256) -> eyre::Result<u64> {
        if block_number == self.anchor.block_number && block_hash == self.anchor.block_hash {
            return Ok(self.anchor.sequence);
        }
        self.entries
            .values()
            .find(|entry| entry.block_number == block_number && entry.block_hash == block_hash)
            .map(|entry| entry.sequence)
            .ok_or_else(|| {
                let watermark = self.watermark();
                eyre!(
                    "journal has no identity for rewind target block {block_number} ({block_hash:#x}); choose a retained identity between anchor block {} and watermark block {}, or snapshot re-import",
                    self.anchor.block_number,
                    watermark.block_number,
                )
            })
    }

    pub(crate) fn truncate_to(&mut self, block_number: u64, block_hash: B256) -> eyre::Result<()> {
        let sequence = self.sequence_for_target(block_number, block_hash)?;
        let retained = self.entries.split_off(&sequence.saturating_add(1));
        drop(retained);
        self.rewrite(self.anchor, self.entries.clone(), "truncate")?;
        Ok(())
    }

    fn compact_verified_prefix(&mut self, retain: usize) -> eyre::Result<()> {
        let drop_count = self.entries.len().saturating_sub(retain);
        if drop_count == 0
            || self
                .entries
                .values()
                .take(drop_count)
                .any(|entry| entry.source != ArbEngineInputSource::L1)
        {
            return Ok(());
        }

        let new_anchor_entry = self
            .entries
            .values()
            .nth(drop_count - 1)
            .copied()
            .ok_or_else(|| eyre!("journal compaction anchor is missing"))?;
        let new_anchor = MessageJournalAnchor {
            sequence: new_anchor_entry.sequence,
            block_number: new_anchor_entry.block_number,
            block_hash: new_anchor_entry.block_hash,
        };
        let remaining = self.entries.split_off(&(new_anchor.sequence + 1));
        self.rewrite(new_anchor, remaining, "compact")?;
        Ok(())
    }

    fn rewrite(
        &mut self,
        anchor: MessageJournalAnchor,
        entries: BTreeMap<u64, MessageJournalEntry>,
        operation: &str,
    ) -> eyre::Result<()> {
        let temp_path = self.path.with_extension(format!("ndjson.{operation}.tmp"));
        if temp_path.exists() {
            std::fs::remove_file(&temp_path)?;
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .wrap_err_with(|| format!("create journal rewrite file {}", temp_path.display()))?;
        let mut writer = BufWriter::new(file);
        write_record(
            &mut writer,
            &DiskRecord::Header {
                version: JOURNAL_VERSION,
                anchor,
            },
        )?;
        for &entry in entries.values() {
            write_record(
                &mut writer,
                &DiskRecord::Message {
                    version: JOURNAL_VERSION,
                    entry,
                },
            )?;
        }
        writer.flush()?;
        writer.get_ref().sync_all()?;
        std::fs::rename(&temp_path, &self.path)?;
        sync_parent(&self.path)?;
        self.anchor = anchor;
        self.entries = entries;
        Ok(())
    }
}

/// Return the message-journal path within `datadir`.
pub fn message_journal_path(datadir: &Path) -> PathBuf {
    MessageJournal::path_in(datadir)
}

/// Return the startup-blocking divergence-marker path within `datadir`.
pub fn divergence_marker_path(datadir: &Path) -> PathBuf {
    MessageJournal::divergence_path_in(datadir)
}

/// Inspect and fully validate the complete journal prefix without mutating any artifact.
///
/// A final record without a newline is reported as an incomplete crash tail and deliberately left
/// byte-for-byte unchanged. Corruption in any complete record is fatal.
pub fn inspect_message_journal(
    datadir: &Path,
    genesis_block: u64,
) -> eyre::Result<MessageJournalInspection> {
    let path = MessageJournal::path_in(datadir);
    let file = File::open(&path)
        .wrap_err_with(|| format!("open message journal read-only {}", path.display()))?;
    let file_len = file.metadata()?.len();
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    let mut complete_byte_offset = 0u64;
    let mut records = Vec::new();
    let mut has_incomplete_tail = false;
    loop {
        line.clear();
        let read = reader.read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }
        if !line.ends_with(b"\n") {
            has_incomplete_tail = true;
            break;
        }
        complete_byte_offset += read as u64;
        records.push(
            serde_json::from_slice::<DiskRecord>(&line).wrap_err_with(|| {
                format!(
                    "invalid complete message-journal record ending at byte {complete_byte_offset}"
                )
            })?,
        );
    }
    ensure!(
        complete_byte_offset <= file_len,
        "message-journal complete offset exceeds file length"
    );

    let Some(DiskRecord::Header { version, anchor }) = records.first().copied() else {
        return Err(eyre!("message journal is missing its header record"));
    };
    ensure!(
        version == JOURNAL_VERSION,
        "unsupported message journal version {version}"
    );
    ensure_journal_mapping(anchor.sequence, anchor.block_number, genesis_block)?;

    let mut entries = BTreeMap::new();
    let mut previous = anchor;
    for record in records.into_iter().skip(1) {
        let DiskRecord::Message { version, entry } = record else {
            return Err(eyre!("message journal contains a second header"));
        };
        ensure!(
            version == JOURNAL_VERSION,
            "unsupported message journal version {version}"
        );
        ensure_journal_mapping(entry.sequence, entry.block_number, genesis_block)?;
        if let Some(existing) = entries.get(&entry.sequence).copied() {
            validate_promotion(existing, entry)?;
        } else {
            let expected_sequence = previous
                .sequence
                .checked_add(1)
                .ok_or_else(|| eyre!("message journal sequence overflow"))?;
            let expected_block = previous
                .block_number
                .checked_add(1)
                .ok_or_else(|| eyre!("message journal block-number overflow"))?;
            ensure!(
                entry.sequence == expected_sequence,
                "message journal sequence gap: expected {expected_sequence}, got {}",
                entry.sequence
            );
            ensure!(
                entry.block_number == expected_block,
                "message journal block gap: expected {expected_block}, got {}",
                entry.block_number
            );
            ensure!(
                entry.parent_hash == previous.block_hash,
                "message journal parent mismatch at sequence {}: expected {:#x}, got {:#x}",
                entry.sequence,
                previous.block_hash,
                entry.parent_hash
            );
            previous = MessageJournalAnchor {
                sequence: entry.sequence,
                block_number: entry.block_number,
                block_hash: entry.block_hash,
            };
        }
        entries.insert(entry.sequence, entry);
    }

    let entries = entries.into_values().collect::<Vec<_>>();
    let watermark = entries
        .last()
        .map(|entry| MessageJournalAnchor {
            sequence: entry.sequence,
            block_number: entry.block_number,
            block_hash: entry.block_hash,
        })
        .unwrap_or(anchor);
    Ok(MessageJournalInspection {
        anchor,
        entries,
        watermark,
        complete_byte_offset,
        has_incomplete_tail,
    })
}

/// Durably replace the journal with its exact complete prefix through `block_number`/`block_hash`.
///
/// This is recovery's sole journal-repair operation. It also removes an inspected incomplete tail,
/// but only after the caller has frozen recovery evidence.
pub fn rewrite_journal_to_identity_at(
    datadir: &Path,
    genesis_block: u64,
    block_number: u64,
    block_hash: B256,
) -> eyre::Result<MessageJournalInspection> {
    let inspection = inspect_message_journal(datadir, genesis_block)?;
    let target_sequence = inspection.sequence_for_target(block_number, block_hash)?;
    let entries = inspection
        .entries
        .iter()
        .copied()
        .filter(|entry| entry.sequence <= target_sequence)
        .map(|entry| (entry.sequence, entry))
        .collect();
    let path = MessageJournal::path_in(datadir);
    let mut journal = MessageJournal {
        path,
        anchor: inspection.anchor,
        entries,
        append_operations: 0,
    };
    let entries = journal.entries.clone();
    journal.rewrite(inspection.anchor, entries, "recovery")?;
    inspect_message_journal(datadir, genesis_block)
}

fn ensure_journal_mapping(
    sequence: u64,
    block_number: u64,
    genesis_block: u64,
) -> eyre::Result<()> {
    let expected = genesis_block
        .checked_add(sequence)
        .ok_or_else(|| eyre!("journal genesis/sequence mapping overflows u64"))?;
    ensure!(
        block_number == expected,
        "incoherent message journal mapping: genesis block {genesis_block} + sequence {sequence} = {expected}, got block {block_number}"
    );
    Ok(())
}

/// Validate that an existing journal can be truncated to this canonical block identity.
pub fn validate_journal_target_at(
    datadir: &Path,
    block_number: u64,
    block_hash: B256,
) -> eyre::Result<()> {
    let path = MessageJournal::path_in(datadir);
    if !path.exists() {
        return Ok(());
    }
    MessageJournal::open(path)?.sequence_for_target(block_number, block_hash)?;
    Ok(())
}

/// Truncate the durable message journal to a canonical rewind target while the node is stopped.
pub fn truncate_journal_at(
    datadir: &Path,
    block_number: u64,
    block_hash: B256,
) -> eyre::Result<()> {
    let path = MessageJournal::path_in(datadir);
    if !path.exists() {
        return Ok(());
    }
    let mut journal = MessageJournal::open(path)?;
    journal.truncate_to(block_number, block_hash)
}

/// Clear the startup-blocking divergence marker after database and sidecar recovery succeeds.
pub fn clear_divergence_marker_at(datadir: &Path) -> eyre::Result<()> {
    let path = MessageJournal::divergence_path_in(datadir);
    if path.exists() {
        std::fs::remove_file(&path)?;
        sync_parent(&path)?;
    }
    Ok(())
}

fn validate_promotion(
    existing: MessageJournalEntry,
    incoming: MessageJournalEntry,
) -> eyre::Result<()> {
    ensure!(
        existing.sequence == incoming.sequence
            && existing.block_number == incoming.block_number
            && existing.block_hash == incoming.block_hash
            && existing.parent_hash == incoming.parent_hash
            && existing.delayed_messages_read == incoming.delayed_messages_read
            && existing
                .fingerprint
                .semantically_matches(incoming.fingerprint),
        "message journal rewrite disagrees with sequence {}",
        existing.sequence
    );
    ensure!(
        existing.source == incoming.source
            || (existing.source == ArbEngineInputSource::Feed
                && incoming.source == ArbEngineInputSource::L1),
        "invalid message journal authority transition at sequence {}: {:?} to {:?}",
        existing.sequence,
        existing.source,
        incoming.source
    );
    Ok(())
}

fn write_record(writer: &mut impl Write, record: &DiskRecord) -> eyre::Result<()> {
    serde_json::to_writer(&mut *writer, record)?;
    writer.write_all(b"\n")?;
    Ok(())
}

fn sync_parent(path: &Path) -> eyre::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| eyre!("journal path has no parent"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArbMessageEnrichment, ArbMessageFingerprint};

    fn anchor() -> MessageJournalAnchor {
        MessageJournalAnchor {
            sequence: 10,
            block_number: 110,
            block_hash: B256::with_last_byte(10),
        }
    }

    fn entry(sequence: u64, source: ArbEngineInputSource) -> MessageJournalEntry {
        MessageJournalEntry {
            sequence,
            block_number: sequence + 100,
            block_hash: B256::with_last_byte(sequence as u8),
            parent_hash: B256::with_last_byte(sequence.saturating_sub(1) as u8),
            delayed_messages_read: 7,
            fingerprint: ArbMessageFingerprint {
                core: B256::repeat_byte(sequence as u8),
                enrichment: ArbMessageEnrichment {
                    legacy_batch_gas_cost: None,
                    batch_data_stats: None,
                },
            },
            source,
        }
    }

    #[test]
    fn creates_appends_promotes_and_reopens() -> eyre::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = MessageJournal::path_in(dir.path());
        let mut journal = MessageJournal::create(path.clone(), anchor())?;
        journal.append_durable(&[
            entry(11, ArbEngineInputSource::Feed),
            entry(12, ArbEngineInputSource::Feed),
        ])?;
        journal.append_durable(&[entry(11, ArbEngineInputSource::L1)])?;

        let reopened = MessageJournal::open(path)?;
        assert_eq!(reopened.anchor(), anchor());
        assert_eq!(reopened.watermark().sequence, 12);
        assert_eq!(reopened.entry(11).unwrap().source, ArbEngineInputSource::L1);
        Ok(())
    }

    #[test]
    fn truncates_incomplete_crash_tail() -> eyre::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = MessageJournal::path_in(dir.path());
        drop(MessageJournal::create(path.clone(), anchor())?);
        let good_len = std::fs::metadata(&path)?.len();
        let mut file = OpenOptions::new().append(true).open(&path)?;
        file.write_all(b"{\"record\":\"message\"")?;
        file.sync_all()?;

        let reopened = MessageJournal::open(path.clone())?;
        assert_eq!(reopened.watermark(), anchor());
        assert_eq!(std::fs::metadata(path)?.len(), good_len);
        Ok(())
    }

    #[test]
    fn read_only_inspection_reports_but_does_not_repair_incomplete_tail() -> eyre::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = MessageJournal::path_in(dir.path());
        let mut journal = MessageJournal::create(path.clone(), anchor())?;
        journal.append_durable(&[entry(11, ArbEngineInputSource::L1)])?;
        let complete_len = std::fs::metadata(&path)?.len();
        let mut file = OpenOptions::new().append(true).open(&path)?;
        file.write_all(b"{\"record\":\"message\"")?;
        file.sync_all()?;
        let torn_len = std::fs::metadata(&path)?.len();

        let inspection = inspect_message_journal(dir.path(), 100)?;
        assert!(inspection.has_incomplete_tail);
        assert_eq!(inspection.complete_byte_offset, complete_len);
        assert_eq!(inspection.watermark.sequence, 11);
        assert_eq!(std::fs::metadata(&path)?.len(), torn_len);

        let repaired = rewrite_journal_to_identity_at(
            dir.path(),
            100,
            inspection.watermark.block_number,
            inspection.watermark.block_hash,
        )?;
        assert!(!repaired.has_incomplete_tail);
        assert_eq!(std::fs::metadata(path)?.len(), complete_len);
        Ok(())
    }

    #[test]
    fn read_only_inspection_rejects_incoherent_mapping_without_writing() -> eyre::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = MessageJournal::path_in(dir.path());
        drop(MessageJournal::create(path.clone(), anchor())?);
        let before = std::fs::read(&path)?;

        assert!(inspect_message_journal(dir.path(), 101).is_err());
        assert_eq!(std::fs::read(path)?, before);
        Ok(())
    }

    #[test]
    fn truncates_to_a_known_canonical_entry() -> eyre::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = MessageJournal::path_in(dir.path());
        let mut journal = MessageJournal::create(path.clone(), anchor())?;
        journal.append_durable(&[
            entry(11, ArbEngineInputSource::L1),
            entry(12, ArbEngineInputSource::Feed),
        ])?;
        let target = entry(11, ArbEngineInputSource::L1);
        journal.truncate_to(target.block_number, target.block_hash)?;

        let reopened = MessageJournal::open(path)?;
        assert_eq!(reopened.watermark().sequence, 11);
        assert!(reopened.entry(12).is_none());
        Ok(())
    }

    #[test]
    fn legacy_rewind_without_a_journal_is_a_noop() -> eyre::Result<()> {
        let dir = tempfile::tempdir()?;
        validate_journal_target_at(dir.path(), 123, B256::repeat_byte(0x44))?;
        truncate_journal_at(dir.path(), 123, B256::repeat_byte(0x44))?;
        Ok(())
    }

    #[test]
    fn writes_one_durable_divergence_marker() -> eyre::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = MessageJournal::path_in(dir.path());
        let journal = MessageJournal::create(path, anchor())?;
        let mut message: arbitrum_alloy_sequencer::sequencer::feed::BroadcastFeedMessage =
            serde_json::from_str(include_str!(
                "../../arb-reth-node/tests/fixtures/deposit_message_only.json"
            ))?;
        message.sequence_number = 11;
        let input = ArbEngineInput::feed(message, Some(B256::repeat_byte(0xaa)));
        journal.write_divergence_marker(110, B256::repeat_byte(0x10), 11, &input, "first")?;
        journal.write_divergence_marker(111, B256::repeat_byte(0x11), 12, &input, "second")?;

        let marker: serde_json::Value = serde_json::from_slice(&std::fs::read(
            MessageJournal::divergence_path_in(dir.path()),
        )?)?;
        assert_eq!(marker["error"], "first");
        assert_eq!(marker["next_sequence"], 11);
        Ok(())
    }

    #[test]
    fn compacts_only_verified_prefix_into_a_new_anchor() -> eyre::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = MessageJournal::path_in(dir.path());
        let mut journal = MessageJournal::create(path.clone(), anchor())?;
        journal.append_durable(&[
            entry(11, ArbEngineInputSource::L1),
            entry(12, ArbEngineInputSource::L1),
            entry(13, ArbEngineInputSource::Feed),
        ])?;
        journal.compact_verified_prefix(1)?;

        let reopened = MessageJournal::open(path)?;
        assert_eq!(reopened.anchor().sequence, 12);
        assert_eq!(reopened.watermark().sequence, 13);
        assert_eq!(
            reopened.entry(13).unwrap().source,
            ArbEngineInputSource::Feed
        );
        Ok(())
    }

    #[test]
    fn coalesces_feed_to_l1_authority_within_one_append_batch() -> eyre::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = MessageJournal::path_in(dir.path());
        let mut journal = MessageJournal::create(path.clone(), anchor())?;
        journal.append_durable(&[
            entry(11, ArbEngineInputSource::Feed),
            entry(11, ArbEngineInputSource::L1),
        ])?;

        let reopened = MessageJournal::open(path)?;
        assert_eq!(reopened.entry(11).unwrap().source, ArbEngineInputSource::L1);
        Ok(())
    }

    #[test]
    fn rejects_gaps_and_conflicting_promotions() -> eyre::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = MessageJournal::path_in(dir.path());
        let mut journal = MessageJournal::create(path, anchor())?;
        assert!(
            journal
                .append_durable(&[entry(12, ArbEngineInputSource::Feed)])
                .is_err()
        );
        journal.append_durable(&[entry(11, ArbEngineInputSource::Feed)])?;
        let mut conflict = entry(11, ArbEngineInputSource::L1);
        conflict.block_hash = B256::repeat_byte(0xff);
        assert!(journal.append_durable(&[conflict]).is_err());
        Ok(())
    }

    #[test]
    fn verified_tip_stops_at_the_first_feed_authority_entry() -> eyre::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = MessageJournal::path_in(dir.path());
        let mut journal = MessageJournal::create(path, anchor())?;
        journal.append_durable(&[
            entry(11, ArbEngineInputSource::L1),
            entry(12, ArbEngineInputSource::Feed),
            entry(13, ArbEngineInputSource::L1),
        ])?;

        assert_eq!(journal.l1_verified_tip().sequence, 11);
        journal.append_durable(&[entry(12, ArbEngineInputSource::L1)])?;
        assert_eq!(journal.l1_verified_tip().sequence, 13);
        Ok(())
    }
}
