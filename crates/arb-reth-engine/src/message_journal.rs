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

pub(crate) const MESSAGE_JOURNAL_FILE: &str = "arb-message-journal.ndjson";
pub(crate) const DIVERGENCE_MARKER_FILE: &str = "arb-message-divergence.json";
const JOURNAL_VERSION: u64 = 1;
const JOURNAL_RETAIN_MESSAGES: usize = 100_000;
const JOURNAL_COMPACT_TRIGGER: usize = 110_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct MessageJournalAnchor {
    pub sequence: u64,
    pub block_number: u64,
    pub block_hash: B256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct MessageJournalEntry {
    pub sequence: u64,
    pub block_number: u64,
    pub block_hash: B256,
    pub parent_hash: B256,
    pub delayed_messages_read: u64,
    pub fingerprint: ArbMessageFingerprint,
    pub source: ArbEngineInputSource,
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
            block_hash: B256::repeat_byte(0x10),
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
