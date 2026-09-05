//! Phase-A stopped-start classifier and authority-artifact inventory.
//!
//! Canonical-L1 verification is intentionally unavailable. This module only allows a clean v2
//! startup shape through to the test-artifact runtime; crash/recovery evidence remains closed.

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

use alloy_consensus::Header;
use alloy_primitives::{Address, B256};
use arbitrum_alloy_consensus::reth::ArbPrimitives;
use eyre::{WrapErr as _, ensure, eyre};
use reth_chainspec::{ChainSpec, EthChainSpec as _};
use reth_config::PruneConfig;
use reth_db::{
    ClientVersion, Database as _, init_db, mdbx::DatabaseArguments, open_db_read_only, tables,
};
use reth_db_api::{cursor::DbCursorRO as _, models::StorageSettings, transaction::DbTx as _};
use reth_node_types::NodeTypesWithDBAdapter;
use reth_provider::{
    BlockExecutionWriter as _, BlockNumReader as _, DatabaseProviderFactory as _,
    HeaderProvider as _, ProviderFactory, StaticFileProviderFactory as _,
    StorageSettingsCache as _,
    providers::{RocksDBProvider, StaticFileProvider},
};
use reth_prune_types::{MINIMUM_UNWIND_SAFE_DISTANCE, PruneCheckpoint, PruneSegment};
use reth_stages_types::StageId;
use reth_static_file_types::StaticFileSegment;
use reth_storage_api::{DBProvider as _, PruneCheckpointReader as _};
use reth_tasks::Runtime;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use arb_reth_engine::{
    DIVERGENCE_MARKER_FILE, JournalDirectory, LIFECYCLE_FILE, MESSAGE_JOURNAL_FAMILY_PREFIX,
    MESSAGE_JOURNAL_PREFIX, MessageJournalAnchor, StorageContextV3, inspect_message_journal,
    inspect_selected_journal_header, production_storage_context, read_divergence_marker_v4,
};

use crate::lifecycle::LifecycleState;

pub(crate) const RECOVERY_MARKER_FILE: &str = "arb-message-recovery.json";
pub(crate) const RECOVERY_WORKER_ENV: &str = "ARB_RETH_INTERNAL_RECOVERY_WORKER";
const SNAPSHOT_COMPLETION_FILE: &str = "arb-snapshot-completion-v1.bin";
const OLD_SNAPSHOT_MANIFEST: &str = "snapshot-import.json";
const RESUME_FILE: &str = "arb-l1-resume.json";
const RECOVERY_VERSION: u64 = 1;
const RECOVERY_FAILPOINT_ENV: &str = "ARB_RETH_RECOVERY_FAILPOINT";
#[cfg(test)]
const RECOVERY_VALIDATE_RECEIPTS_ENV: &str = "ARB_RETH_INTERNAL_RECOVERY_RECEIPTS_PRUNED";
#[cfg(test)]
const RECOVERY_VALIDATE_SENDERS_ENV: &str = "ARB_RETH_INTERNAL_RECOVERY_SENDERS_PRUNED";

type ArbNodeTypesWithDB = NodeTypesWithDBAdapter<crate::ArbNode, reth_db::DatabaseEnv>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ParentChainClassification {
    Unspecified,
    Arbitrum,
    NonArbitrum,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ParentChainClaim {
    pub chain_id: Option<u64>,
    pub classification: ParentChainClassification,
}

#[derive(Clone)]
pub(crate) struct RecoveryConfig {
    pub datadir: PathBuf,
    pub directory: JournalDirectory,
    pub chain_spec: Arc<ChainSpec>,
    pub chain_id: u64,
    pub genesis_block: u64,
    pub sequencer_inbox: Address,
    pub bridge: Address,
    pub deployed_at: u64,
    pub parent_chain_claim: ParentChainClaim,
    pub snapshot_seeded: bool,
    pub prune_config: Option<PruneConfig>,
    pub no_l1_derive: bool,
    pub l1_rpc: Option<String>,
    pub l1_beacon: Option<String>,
    pub l1_start_block: Option<u64>,
    pub l1_start_delayed: Option<u64>,
    pub l1_end_block: Option<u64>,
    pub lifecycle_state: LifecycleState,
}

pub(crate) struct RecoveryPreparation {
    pub gate: RecoveryGate,
    pub runtime: Option<RecoveryRuntime>,
}

/// Kept as an empty launch type until Phase B supplies canonical recovery.
#[derive(Clone)]
pub struct RecoveryRuntime {
    pub(crate) marker: RecoveryMarker,
    storage: RecoveryStorageConfig,
    pub(crate) needs_worker: bool,
}

#[derive(Clone)]
struct RecoveryStorageConfig {
    datadir: PathBuf,
    directory: JournalDirectory,
    chain_spec: Arc<ChainSpec>,
    genesis_block: u64,
    storage_context: StorageContextV3,
    prune_config: Option<PruneConfig>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RecoveryPhase {
    Classified,
    ConsistencyHealed,
    HistoryValidated,
    DbUnwound,
    ReopenedValidated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    tag = "kind",
    content = "value",
    rename_all = "snake_case"
)]
enum ObservedNumber {
    None,
    Number(u64),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum ObservedPruneCheckpoint {
    None,
    Checkpoint {
        block_number: ObservedNumber,
        tx_number: ObservedNumber,
        prune_mode: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ObservedStaticRange {
    start: u64,
    end: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryMarker {
    version: u64,
    phase: RecoveryPhase,
    l2_chain_id: u64,
    l2_genesis_block_number: u64,
    l2_genesis_hash: B256,
    sequencer_inbox: Address,
    bridge: Address,
    deployment_block: u64,
    snapshot_seeded: bool,
    anchor_sequence: u64,
    anchor_block_number: u64,
    anchor_block_hash: B256,
    target_sequence: u64,
    target_block_number: u64,
    target_block_hash: B256,
    target_state_root: B256,
    pub old_db_tip_number: u64,
    old_db_tip_hash: B256,
    old_db_tip_state_root: B256,
    active_unwind_horizon: u64,
    account_history_prune_checkpoint: ObservedPruneCheckpoint,
    storage_history_prune_checkpoint: ObservedPruneCheckpoint,
    account_changeset_ranges: Vec<ObservedStaticRange>,
    storage_changeset_ranges: Vec<ObservedStaticRange>,
}

impl RecoveryMarker {
    const fn anchor(&self) -> MessageJournalAnchor {
        MessageJournalAnchor {
            sequence: self.anchor_sequence,
            block_number: self.anchor_block_number,
            block_hash: self.anchor_block_hash,
        }
    }

    const fn target(&self) -> MessageJournalAnchor {
        MessageJournalAnchor {
            sequence: self.target_sequence,
            block_number: self.target_block_number,
            block_hash: self.target_block_hash,
        }
    }
}

#[derive(Clone)]
pub struct RecoveryGate {
    inner: Arc<RecoveryGateInner>,
}

struct RecoveryGateInner {
    ready: Arc<AtomicBool>,
    sender: watch::Sender<bool>,
    gauge: OnceLock<metrics::Gauge>,
}

impl RecoveryGate {
    pub fn new(ready: bool) -> Self {
        let (sender, _) = watch::channel(ready);
        Self {
            inner: Arc::new(RecoveryGateInner {
                ready: Arc::new(AtomicBool::new(ready)),
                sender,
                gauge: OnceLock::new(),
            }),
        }
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.inner.ready.load(Ordering::Acquire)
    }

    pub(crate) fn register_metric(&self) {
        let gauge = metrics::gauge!("arb_reth_recovery_ready");
        gauge.set(if self.is_ready() { 1.0 } else { 0.0 });
        let _ = self.inner.gauge.set(gauge);
    }

    pub(crate) async fn wait_ready(&self) {
        if self.is_ready() {
            return;
        }
        let mut receiver = self.inner.sender.subscribe();
        while !*receiver.borrow_and_update() {
            if receiver.changed().await.is_err() {
                return;
            }
        }
    }
}

pub(crate) fn is_recovery_worker() -> bool {
    std::env::var_os(RECOVERY_WORKER_ENV).is_some()
}

pub(crate) fn recovery_failpoint(name: &str) {
    if std::env::var(RECOVERY_FAILPOINT_ENV).as_deref() == Ok(name) {
        std::process::abort();
    }
}

pub(crate) fn preflight_before_l1_genesis(datadir: &Path, _genesis_block: u64) -> eyre::Result<()> {
    inspect_artifacts(datadir, InventoryMode::Fresh)?;
    for storage in ["db", "static_files", "rocksdb"] {
        let path = datadir.join(storage);
        if path.is_dir() && std::fs::read_dir(&path)?.next().transpose()?.is_some() {
            return Err(eyre!(
                "fresh L1 genesis target contains existing storage at {}",
                path.display()
            ));
        }
    }
    Ok(())
}

pub(crate) fn preflight_ordinary_authority(
    directory: &JournalDirectory,
    snapshot_completion_expected: bool,
) -> eyre::Result<OrdinaryAuthorityEvidence> {
    inspect_pinned_artifacts(
        directory,
        InventoryMode::Ordinary {
            snapshot_completion_expected,
        },
    )?;
    let divergence = directory.entry_exists(DIVERGENCE_MARKER_FILE)?;
    let recovery = directory.entry_exists(RECOVERY_MARKER_FILE)?;
    if divergence {
        validate_divergence_marker(directory)?;
    }
    if recovery {
        read_marker(directory)?;
    }
    Ok(if divergence {
        OrdinaryAuthorityEvidence::Divergence
    } else if recovery {
        OrdinaryAuthorityEvidence::Recovery
    } else {
        OrdinaryAuthorityEvidence::None
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OrdinaryAuthorityEvidence {
    None,
    Divergence,
    Recovery,
}

fn validate_divergence_marker(directory: &JournalDirectory) -> eyre::Result<()> {
    let marker =
        read_divergence_marker_v4(directory).wrap_err("decode binary divergence marker v4")?;
    let journal = inspect_message_journal(directory, production_storage_context())
        .wrap_err("authenticate divergence-v4 journal")?;
    marker
        .validate_journal_state(&journal)
        .wrap_err("authenticate divergence-v4 durable fields")?;
    Ok(())
}

pub(crate) async fn prepare_recovery(config: RecoveryConfig) -> eyre::Result<RecoveryPreparation> {
    // Touch every frozen launch input so accidental reintroduction cannot silently bypass this
    // single classifier boundary.
    let _ = (
        &config.chain_spec,
        config.chain_id,
        config.genesis_block,
        config.sequencer_inbox,
        config.bridge,
        config.deployed_at,
        config.parent_chain_claim.chain_id,
        config.parent_chain_claim.classification,
        config.snapshot_seeded,
        &config.prune_config,
        config.no_l1_derive,
        &config.l1_rpc,
        &config.l1_beacon,
        config.l1_start_block,
        config.l1_start_delayed,
        config.l1_end_block,
        config.lifecycle_state,
    );
    inspect_pinned_artifacts(
        &config.directory,
        InventoryMode::Ordinary {
            snapshot_completion_expected: config.snapshot_seeded,
        },
    )?;
    let selected_header = inspect_selected_journal_header(&config.directory)?;
    let storage_context = StorageContextV3 {
        l2_chain_id: config.chain_id,
        l2_genesis_number: config.genesis_block,
        l2_genesis_hash: config.chain_spec.genesis_hash(),
        sequencer_inbox: config.sequencer_inbox,
        bridge: config.bridge,
        deployment_block: config.deployed_at,
        anchor: selected_header.anchor,
    };
    let journal = inspect_message_journal(&config.directory, storage_context)?;
    ensure!(
        !journal.has_authenticated_short_tail,
        "authenticated journal tail requires stopped recovery"
    );
    let storage = RecoveryStorageConfig {
        datadir: config.datadir.clone(),
        directory: config.directory.clone(),
        chain_spec: config.chain_spec.clone(),
        genesis_block: config.genesis_block,
        storage_context,
        prune_config: config.prune_config.clone(),
    };

    if config.directory.entry_exists(RECOVERY_MARKER_FILE)? {
        let marker = read_marker(&config.directory)?;
        validate_marker_config(&marker, &config)?;
        validate_marker_against_journal(&marker, &journal)?;
        let runtime = RecoveryRuntime {
            marker,
            storage,
            needs_worker: false,
        };
        if is_recovery_worker()
            && phase_rank(runtime.marker.phase) < phase_rank(RecoveryPhase::DbUnwound)
        {
            repair_db_ahead_suffix(&runtime)?;
            return Ok(RecoveryPreparation {
                gate: RecoveryGate::new(false),
                runtime: Some(RecoveryRuntime {
                    marker: read_marker(&config.directory)?,
                    needs_worker: false,
                    ..runtime
                }),
            });
        }
        let needs_worker = phase_rank(runtime.marker.phase) < phase_rank(RecoveryPhase::DbUnwound);
        return Ok(RecoveryPreparation {
            gate: RecoveryGate::new(false),
            runtime: Some(RecoveryRuntime {
                needs_worker,
                ..runtime
            }),
        });
    }

    let db = inspect_exact_storage_shape(
        &storage.datadir,
        receipts_fully_pruned(storage.prune_config.as_ref()),
        senders_fully_pruned(storage.prune_config.as_ref()),
        storage.genesis_block,
    )?;
    let target = journal.watermark;
    match db.tip_number.cmp(&target.block_number) {
        std::cmp::Ordering::Less => Err(eyre!(
            "journal is ahead of durable DB (J={}, DB={}); snapshot/operator recovery required",
            target.block_number,
            db.tip_number
        )),
        std::cmp::Ordering::Equal => {
            ensure!(
                db.tip_hash == target.block_hash,
                "equal-height DB/J hash mismatch at block {}; snapshot/operator recovery required",
                db.tip_number
            );
            reject_phase_a_equal_frontier(config.lifecycle_state)
        }
        std::cmp::Ordering::Greater => {
            ensure!(
                config.lifecycle_state == LifecycleState::RunningUnclean,
                "CLEAN lifecycle with DB>J is an impossible authority shape"
            );
            let distance = db.tip_number - target.block_number;
            let active_unwind_horizon = active_unwind_horizon(&config).min(1_024);
            ensure!(
                distance <= active_unwind_horizon,
                "DB-ahead distance {distance} exceeds active repair bound {active_unwind_horizon}; snapshot/operator recovery required"
            );
            let target_header =
                read_retained_header(&storage, target.block_number)?.ok_or_else(|| {
                    eyre!(
                        "journal target header is unavailable; snapshot/operator recovery required"
                    )
                })?;
            ensure!(
                target_header.hash() == target.block_hash,
                "journal target hash does not match retained DB identity"
            );
            let evidence = freeze_recovery_evidence(&storage)?;
            let marker = RecoveryMarker {
                version: RECOVERY_VERSION,
                phase: RecoveryPhase::Classified,
                l2_chain_id: config.chain_id,
                l2_genesis_block_number: config.genesis_block,
                l2_genesis_hash: config.chain_spec.genesis_hash(),
                sequencer_inbox: config.sequencer_inbox,
                bridge: config.bridge,
                deployment_block: config.deployed_at,
                snapshot_seeded: config.snapshot_seeded,
                anchor_sequence: journal.header.anchor.sequence,
                anchor_block_number: journal.header.anchor.block_number,
                anchor_block_hash: journal.header.anchor.block_hash,
                target_sequence: target.sequence,
                target_block_number: target.block_number,
                target_block_hash: target.block_hash,
                target_state_root: target_header.state_root,
                old_db_tip_number: db.tip_number,
                old_db_tip_hash: db.tip_hash,
                old_db_tip_state_root: db.tip_state_root,
                active_unwind_horizon,
                account_history_prune_checkpoint: evidence.account_history_prune_checkpoint,
                storage_history_prune_checkpoint: evidence.storage_history_prune_checkpoint,
                account_changeset_ranges: evidence.account_changeset_ranges,
                storage_changeset_ranges: evidence.storage_changeset_ranges,
            };
            write_marker(&config.directory, &marker, true)?;
            recovery_failpoint("initial_marker_fsynced");
            Ok(RecoveryPreparation {
                gate: RecoveryGate::new(false),
                runtime: Some(RecoveryRuntime {
                    marker,
                    storage,
                    needs_worker: true,
                }),
            })
        }
    }
}

fn reject_phase_a_equal_frontier(
    lifecycle_state: LifecycleState,
) -> eyre::Result<RecoveryPreparation> {
    match lifecycle_state {
        LifecycleState::Clean => Err(eyre!(
            "storage is consistent at DB==J but phase A remains phase-incomplete/closed before ordinary writer or service open"
        )),
        LifecycleState::Initializing => Err(eyre!(
            "selected lifecycle state is INITIALIZING; snapshot/operator recovery required"
        )),
        LifecycleState::RunningUnclean => Err(eyre!(
            "crash evidence is storage-consistent at DB==J but phase A cannot establish canonical recovery; snapshot/operator recovery required"
        )),
    }
}

pub(crate) fn finalize_recovery_and_release(
    runtime: &RecoveryRuntime,
    _gate: &RecoveryGate,
) -> eyre::Result<()> {
    #[cfg(not(test))]
    {
        let _ = (runtime, _gate);
        Err(eyre!(
            "RecoveryEvidencePhaseUnavailable: B1 has no production recovery validation dispatch"
        ))
    }
    #[cfg(test)]
    {
        let mut marker = read_marker(&runtime.storage.directory)?;
        ensure!(
            marker.phase == RecoveryPhase::DbUnwound,
            "recovery worker did not durably record repair completion"
        );
        ensure!(
            runtime.needs_worker || marker == runtime.marker,
            "recovery marker changed unexpectedly"
        );
        run_reopened_validation_subprocess(&runtime.storage)?;
        ensure!(
            read_marker(&runtime.storage.directory)? == marker,
            "recovery marker changed during fresh-process validation"
        );
        marker.phase = RecoveryPhase::ReopenedValidated;
        write_marker(&runtime.storage.directory, &marker, false)?;
        recovery_failpoint("reopened_storage_validated");
        Err(eyre!(
            "DB>J repair reached exact J and released its writer, but phase A remains recovery-closed; snapshot/operator recovery required"
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExactStorageIdentity {
    tip_number: u64,
    tip_hash: B256,
    tip_state_root: B256,
}

fn read_marker(directory: &JournalDirectory) -> eyre::Result<RecoveryMarker> {
    const MAX_RECOVERY_MARKER_LEN: usize = 1024 * 1024;
    let bytes = directory.read_entry(RECOVERY_MARKER_FILE, MAX_RECOVERY_MARKER_LEN)?;
    ensure!(
        bytes.len() <= MAX_RECOVERY_MARKER_LEN,
        "recovery marker exceeds 1-MiB bound"
    );
    let marker: RecoveryMarker =
        serde_json::from_slice(&bytes).wrap_err("decode recovery marker")?;
    ensure!(
        marker.version == RECOVERY_VERSION,
        "unsupported recovery marker version"
    );
    ensure!(
        marker
            .target_sequence
            .checked_sub(marker.anchor_sequence)
            .and_then(|distance| marker.anchor_block_number.checked_add(distance))
            == Some(marker.target_block_number)
            && marker.target_block_number >= marker.anchor_block_number
            && marker.target_sequence >= marker.anchor_sequence
            && marker.old_db_tip_number > marker.target_block_number
            && marker.old_db_tip_number - marker.target_block_number
                <= marker.active_unwind_horizon,
        "recovery marker has invalid authority ordering"
    );
    for ranges in [
        &marker.account_changeset_ranges,
        &marker.storage_changeset_ranges,
    ] {
        ensure!(
            ranges.iter().all(|range| range.start <= range.end)
                && ranges.windows(2).all(|pair| pair[0].end < pair[1].start),
            "recovery marker contains invalid static-file ranges"
        );
    }
    Ok(marker)
}

fn validate_marker_config(marker: &RecoveryMarker, config: &RecoveryConfig) -> eyre::Result<()> {
    ensure!(
        marker.l2_chain_id == config.chain_id
            && marker.l2_genesis_block_number == config.genesis_block
            && marker.l2_genesis_hash == config.chain_spec.genesis_hash(),
        "recovery marker L2 chain/genesis identity changed"
    );
    ensure!(
        marker.sequencer_inbox == config.sequencer_inbox
            && marker.bridge == config.bridge
            && marker.deployment_block == config.deployed_at,
        "recovery marker rollup deployment identity changed"
    );
    ensure!(
        marker.snapshot_seeded == config.snapshot_seeded,
        "recovery marker snapshot mode changed"
    );
    ensure!(
        marker.active_unwind_horizon == active_unwind_horizon(config).min(1_024),
        "recovery marker active unwind horizon changed"
    );
    let current_tip = current_storage_tip_read_only(&config.datadir)?;
    ensure!(
        current_tip == marker.old_db_tip_number || current_tip == marker.target_block_number,
        "recovery storage tip {current_tip} is neither the frozen old tip nor exact J"
    );
    validate_frozen_static_evidence(marker, &config.datadir, config.genesis_block, current_tip)
}

const fn phase_rank(phase: RecoveryPhase) -> u8 {
    match phase {
        RecoveryPhase::Classified => 0,
        RecoveryPhase::ConsistencyHealed => 1,
        RecoveryPhase::HistoryValidated => 2,
        RecoveryPhase::DbUnwound => 3,
        RecoveryPhase::ReopenedValidated => 4,
    }
}

fn active_unwind_horizon(config: &RecoveryConfig) -> u64 {
    config
        .prune_config
        .as_ref()
        .map(|config| config.minimum_pruning_distance)
        .unwrap_or(MINIMUM_UNWIND_SAFE_DISTANCE)
}

fn current_storage_tip_read_only(datadir: &Path) -> eyre::Result<u64> {
    let db = open_db_read_only(
        datadir.join("db"),
        DatabaseArguments::new(ClientVersion::default()),
    )?;
    let tx = db.tx()?;
    tx.cursor_read::<tables::CanonicalHeaders>()?
        .last()?
        .map(|(number, _)| number)
        .into_iter()
        .chain(
            tx.get::<tables::StageCheckpoints>(StageId::Execution.to_string())?
                .map(|checkpoint| checkpoint.block_number),
        )
        .max()
        .ok_or_else(|| eyre!("recovery marker exists but stopped storage has no durable tip"))
}

fn receipts_fully_pruned(config: Option<&PruneConfig>) -> bool {
    config
        .and_then(|config| config.segments.receipts.as_ref())
        .is_some_and(|mode| mode.is_full())
}

fn senders_fully_pruned(config: Option<&PruneConfig>) -> bool {
    config
        .and_then(|config| config.segments.sender_recovery.as_ref())
        .is_some_and(|mode| mode.is_full())
}

fn observed_prune_checkpoint(checkpoint: Option<PruneCheckpoint>) -> ObservedPruneCheckpoint {
    let Some(checkpoint) = checkpoint else {
        return ObservedPruneCheckpoint::None;
    };
    ObservedPruneCheckpoint::Checkpoint {
        block_number: checkpoint
            .block_number
            .map(ObservedNumber::Number)
            .unwrap_or(ObservedNumber::None),
        tx_number: checkpoint
            .tx_number
            .map(ObservedNumber::Number)
            .unwrap_or(ObservedNumber::None),
        prune_mode: format!("{:?}", checkpoint.prune_mode),
    }
}

struct FrozenRecoveryEvidence {
    account_history_prune_checkpoint: ObservedPruneCheckpoint,
    storage_history_prune_checkpoint: ObservedPruneCheckpoint,
    account_changeset_ranges: Vec<ObservedStaticRange>,
    storage_changeset_ranges: Vec<ObservedStaticRange>,
}

fn freeze_recovery_evidence(
    storage: &RecoveryStorageConfig,
) -> eyre::Result<FrozenRecoveryEvidence> {
    let db = open_db_read_only(
        storage.datadir.join("db"),
        DatabaseArguments::new(ClientVersion::default()),
    )?;
    let tx = db.tx()?;
    let static_path = storage.datadir.join("static_files");
    let static_files = StaticFileProvider::<ArbPrimitives>::read_only(&static_path)?;
    let evidence = FrozenRecoveryEvidence {
        account_history_prune_checkpoint: observed_prune_checkpoint(
            tx.get::<tables::PruneCheckpoints>(PruneSegment::AccountHistory)?,
        ),
        storage_history_prune_checkpoint: observed_prune_checkpoint(
            tx.get::<tables::PruneCheckpoints>(PruneSegment::StorageHistory)?,
        ),
        account_changeset_ranges: observed_static_ranges(
            &static_path,
            &static_files,
            StaticFileSegment::AccountChangeSets,
        )?,
        storage_changeset_ranges: observed_static_ranges(
            &static_path,
            &static_files,
            StaticFileSegment::StorageChangeSets,
        )?,
    };
    tx.commit()?;
    Ok(evidence)
}

fn observed_static_ranges(
    path: &Path,
    provider: &StaticFileProvider<ArbPrimitives>,
    segment: StaticFileSegment,
) -> eyre::Result<Vec<ObservedStaticRange>> {
    let mut ranges = Vec::new();
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if file_name.contains('.') {
            continue;
        }
        let Some((parsed, _)) = StaticFileSegment::parse_filename(&file_name) else {
            continue;
        };
        if parsed != segment {
            continue;
        }
        let jar = provider
            .get_segment_provider_for_path(&entry.path())?
            .ok_or_else(|| eyre!("static-file path has no readable segment header"))?;
        if let Some(range) = jar.user_header().block_range() {
            ranges.push(ObservedStaticRange {
                start: range.start(),
                end: range.end(),
            });
        }
    }
    ranges.sort_by_key(|range| (range.start, range.end));
    Ok(ranges)
}

fn ranges_through(ranges: &[ObservedStaticRange], tip: u64) -> Vec<ObservedStaticRange> {
    ranges
        .iter()
        .filter_map(|range| {
            (range.start <= tip).then_some(ObservedStaticRange {
                start: range.start,
                end: range.end.min(tip),
            })
        })
        .collect()
}

fn validate_frozen_static_evidence(
    marker: &RecoveryMarker,
    datadir: &Path,
    _genesis_block: u64,
    current_tip: u64,
) -> eyre::Result<()> {
    let static_path = datadir.join("static_files");
    let static_files = StaticFileProvider::<ArbPrimitives>::read_only(&static_path)?;
    for (name, segment, frozen) in [
        (
            "account",
            StaticFileSegment::AccountChangeSets,
            &marker.account_changeset_ranges,
        ),
        (
            "storage",
            StaticFileSegment::StorageChangeSets,
            &marker.storage_changeset_ranges,
        ),
    ] {
        let actual = observed_static_ranges(&static_path, &static_files, segment)?;
        let comparison_tip = current_tip.min(marker.old_db_tip_number);
        ensure!(
            ranges_through(&actual, comparison_tip) == ranges_through(frozen, comparison_tip),
            "{name} changeset static-file ranges no longer match frozen evidence through block {comparison_tip}"
        );
        ensure!(
            actual.iter().all(|range| range.start <= range.end)
                && actual
                    .windows(2)
                    .all(|pair| pair[0].end.checked_add(1) == Some(pair[1].start)),
            "{name} changeset static-file successor is overlapping or gapped"
        );
    }
    Ok(())
}

fn validate_static_ranges(
    path: &Path,
    provider: &StaticFileProvider<ArbPrimitives>,
    segment: StaticFileSegment,
    tip: u64,
    genesis_block: u64,
    pruned_through: Option<u64>,
) -> eyre::Result<Vec<ObservedStaticRange>> {
    ensure!(
        provider.get_highest_static_file_block(segment) == Some(tip),
        "{segment:?} static-file tip is not the exact durable tip {tip}"
    );
    let ranges = observed_static_ranges(path, provider, segment)?;
    ensure!(
        !ranges.is_empty()
            && ranges.iter().all(|range| range.start <= range.end)
            && ranges
                .windows(2)
                .all(|pair| pair[0].end.checked_add(1) == Some(pair[1].start))
            && ranges.last().is_some_and(|range| range.end == tip),
        "{segment:?} static-file ranges are missing, gapped, overlapping, or do not end at {tip}"
    );
    let first = ranges[0].start;
    let unpruned_start = first == genesis_block
        || (matches!(
            segment,
            StaticFileSegment::AccountChangeSets | StaticFileSegment::StorageChangeSets
        ) && genesis_block.checked_add(1) == Some(first));
    ensure!(
        first >= genesis_block
            && (unpruned_start
                || pruned_through.is_some_and(|block| block >= first.saturating_sub(1))),
        "{segment:?} static-file lower bound {first} is not explained by genesis {genesis_block} or its prune checkpoint {pruned_through:?}"
    );
    Ok(ranges)
}

fn validate_transaction_sender_ranges<TX>(
    tx: &TX,
    path: &Path,
    provider: &StaticFileProvider<ArbPrimitives>,
    tip: u64,
    genesis_block: u64,
    senders_fully_pruned: bool,
) -> eyre::Result<()>
where
    TX: reth_db_api::transaction::DbTx,
{
    let checkpoint = tx.get::<tables::PruneCheckpoints>(PruneSegment::SenderRecovery)?;
    if checkpoint.is_some_and(|checkpoint| checkpoint.prune_mode.is_full()) {
        ensure!(
            senders_fully_pruned,
            "persisted fully pruned sender-recovery checkpoint contradicts the active prune configuration"
        );
        let checkpoint = checkpoint.expect("checked above");
        ensure!(
            checkpoint.block_number == Some(tip),
            "fully pruned sender-recovery checkpoint block {:?} is not the exact durable tip {tip}",
            checkpoint.block_number
        );
        let tip_body_indices = tx
            .get::<tables::BlockBodyIndices>(tip)?
            .ok_or_else(|| eyre!("MDBX body indices are missing at durable tip {tip}"))?;
        let expected_checkpoint_tx = tip_body_indices.next_tx_num().checked_sub(1);
        match checkpoint.tx_number {
            Some(checkpoint_tx) => ensure!(
                Some(checkpoint_tx) == expected_checkpoint_tx,
                "fully pruned sender-recovery transaction checkpoint {checkpoint_tx} differs from body-index frontier {expected_checkpoint_tx:?} at block {tip}"
            ),
            None => {
                let final_range =
                    provider.find_fixed_range(StaticFileSegment::TransactionSenders, tip);
                let first_block = final_range.start().max(genesis_block);
                let first_body_indices = tx
                    .get::<tables::BlockBodyIndices>(first_block)?
                    .ok_or_else(|| {
                        eyre!(
                            "MDBX body indices are missing at fully pruned sender jar lower bound {first_block}"
                        )
                    })?;
                ensure!(
                    first_body_indices.first_tx_num() == tip_body_indices.next_tx_num(),
                    "fully pruned sender-recovery checkpoint is missing its transaction frontier for a final deleted jar containing transactions"
                );
            }
        }
        let prefix = format!(
            "static_file_{}_",
            StaticFileSegment::TransactionSenders.as_str()
        );
        ensure!(
            provider
                .get_highest_static_file_block(StaticFileSegment::TransactionSenders)
                .is_none()
                && provider
                    .get_highest_static_file_tx(StaticFileSegment::TransactionSenders)
                    .is_none(),
            "fully pruned sender-recovery checkpoint has stale transaction-sender static files"
        );
        for entry in std::fs::read_dir(path)? {
            ensure!(
                !entry?.file_name().to_string_lossy().starts_with(&prefix),
                "fully pruned sender-recovery checkpoint has stale transaction-sender static-file artifacts"
            );
        }
        return Ok(());
    }

    let pruned_through = checkpoint.and_then(|checkpoint| checkpoint.block_number);
    let ranges = validate_static_ranges(
        path,
        provider,
        StaticFileSegment::TransactionSenders,
        tip,
        genesis_block,
        pruned_through,
    )?;
    let first_block = ranges[0].start;
    let expected_first_block = match pruned_through {
        Some(block) => block
            .checked_add(1)
            .ok_or_else(|| eyre!("sender-recovery checkpoint block overflows its destination"))?,
        None => genesis_block,
    };
    ensure!(
        first_block == expected_first_block,
        "transaction-sender static-file lower block bound {first_block} differs from the persisted sender-recovery destination {expected_first_block}"
    );

    if let Some(checkpoint) = checkpoint {
        let checkpoint_block = checkpoint
            .block_number
            .ok_or_else(|| eyre!("sender-recovery checkpoint has no block destination"))?;
        let checkpoint_body_indices = tx
            .get::<tables::BlockBodyIndices>(checkpoint_block)?
            .ok_or_else(|| {
                eyre!("MDBX body indices are missing at sender checkpoint {checkpoint_block}")
            })?;
        let expected_checkpoint_tx = checkpoint_body_indices.next_tx_num().checked_sub(1);
        match checkpoint.tx_number {
            Some(checkpoint_tx) => ensure!(
                Some(checkpoint_tx) == expected_checkpoint_tx,
                "sender-recovery transaction checkpoint {checkpoint_tx} differs from body-index frontier {expected_checkpoint_tx:?} at block {checkpoint_block}"
            ),
            None => {
                let checkpoint_range = provider
                    .find_fixed_range(StaticFileSegment::TransactionSenders, checkpoint_block);
                ensure!(
                    checkpoint_range.end() == checkpoint_block,
                    "sender-recovery checkpoint without a transaction frontier does not end a complete static-file jar"
                );
                let first_block = checkpoint_range.start().max(genesis_block);
                let first_body_indices = tx
                    .get::<tables::BlockBodyIndices>(first_block)?
                    .ok_or_else(|| {
                        eyre!(
                            "MDBX body indices are missing at pruned sender jar lower bound {first_block}"
                        )
                    })?;
                ensure!(
                    first_body_indices.first_tx_num() == checkpoint_body_indices.next_tx_num(),
                    "sender-recovery checkpoint is missing its transaction frontier for a deleted jar containing transactions"
                );
            }
        }
    }

    let mut sender_jars = Vec::new();
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some((segment, _)) = StaticFileSegment::parse_filename(&name) else {
            continue;
        };
        if segment != StaticFileSegment::TransactionSenders || name.contains('.') {
            continue;
        }
        let jar = provider
            .get_segment_provider_for_path(&entry.path())?
            .ok_or_else(|| {
                eyre!("transaction-sender static-file has no readable segment header")
            })?;
        const OFFSET_SIZE_BYTES: u64 = 8;
        let offsets_path = jar.offsets_path();
        let actual_offsets_file_size = std::fs::metadata(&offsets_path)
            .wrap_err_with(|| {
                format!(
                    "failed to read transaction-sender offset-file metadata at {}",
                    offsets_path.display()
                )
            })?
            .len();
        ensure!(
            actual_offsets_file_size > 0,
            "transaction-sender offset file {} is empty",
            offsets_path.display()
        );
        let reader = jar.open_data_reader().wrap_err_with(|| {
            format!(
                "failed to open transaction-sender NippyJar reader at {}",
                jar.data_path().display()
            )
        })?;
        ensure!(
            u64::from(reader.offset_size()) == OFFSET_SIZE_BYTES,
            "transaction-sender NippyJar {} uses {}-byte offsets instead of {OFFSET_SIZE_BYTES}",
            jar.data_path().display(),
            reader.offset_size()
        );
        let rows = u64::try_from(jar.rows())
            .map_err(|_| eyre!("transaction-sender NippyJar row count does not fit u64"))?;
        let columns = u64::try_from(jar.columns())
            .map_err(|_| eyre!("transaction-sender NippyJar column count does not fit u64"))?;
        let expected_offsets_file_size = rows
            .checked_mul(columns)
            .and_then(|offsets| offsets.checked_mul(OFFSET_SIZE_BYTES))
            .and_then(|bytes| bytes.checked_add(1 + OFFSET_SIZE_BYTES))
            .ok_or_else(|| eyre!("transaction-sender NippyJar offset-file length overflows"))?;
        ensure!(
            actual_offsets_file_size == expected_offsets_file_size,
            "transaction-sender offset file {} has length {actual_offsets_file_size}, expected committed length {expected_offsets_file_size}",
            offsets_path.display()
        );
        let committed_data_size = reader.reverse_offset(0).wrap_err_with(|| {
            format!(
                "failed to read the committed transaction-sender data length from {}",
                offsets_path.display()
            )
        })?;
        let actual_data_size = std::fs::metadata(jar.data_path())
            .wrap_err_with(|| {
                format!(
                    "failed to read transaction-sender data-file metadata at {}",
                    jar.data_path().display()
                )
            })?
            .len();
        ensure!(
            committed_data_size == actual_data_size,
            "transaction-sender data file {} has length {actual_data_size}, expected committed length {committed_data_size}",
            jar.data_path().display()
        );
        let block_range = jar
            .user_header()
            .block_range()
            .ok_or_else(|| eyre!("transaction-sender static-file has no retained block range"))?;
        let tx_range = jar
            .user_header()
            .tx_range()
            .map(|range| {
                ensure!(
                    range.start() <= range.end(),
                    "transaction-sender static-file has an invalid transaction range"
                );
                Ok::<_, eyre::Report>((range.start(), range.end()))
            })
            .transpose()?;
        sender_jars.push((
            ObservedStaticRange {
                start: block_range.start(),
                end: block_range.end(),
            },
            tx_range,
            jar.rows(),
        ));
    }
    sender_jars.sort_by_key(|(range, _, _)| (range.start, range.end));
    ensure!(
        sender_jars
            .iter()
            .map(|(range, _, _)| *range)
            .eq(ranges.iter().copied()),
        "transaction-sender static-file headers differ from the validated block ranges"
    );
    for (block_range, actual_tx_range, actual_rows) in sender_jars {
        let first_tx = tx
            .get::<tables::BlockBodyIndices>(block_range.start)?
            .ok_or_else(|| {
                eyre!(
                    "MDBX body indices are missing at sender jar lower bound {}",
                    block_range.start
                )
            })?
            .first_tx_num();
        let next_tx = tx
            .get::<tables::BlockBodyIndices>(block_range.end)?
            .ok_or_else(|| {
                eyre!(
                    "MDBX body indices are missing at sender jar upper bound {}",
                    block_range.end
                )
            })?
            .next_tx_num();
        let expected_tx_range = (first_tx < next_tx).then(|| (first_tx, next_tx.saturating_sub(1)));
        ensure!(
            actual_tx_range == expected_tx_range,
            "transaction-sender static-file block range {}..={} has transaction bounds {actual_tx_range:?}, expected {expected_tx_range:?} from MDBX body indices",
            block_range.start,
            block_range.end
        );
        let expected_rows = match expected_tx_range {
            Some((start, end)) => usize::try_from(
                end.checked_sub(start)
                    .and_then(|rows| rows.checked_add(1))
                    .ok_or_else(|| eyre!("transaction-sender row range overflows"))?,
            )
            .map_err(|_| eyre!("transaction-sender row range does not fit the host row count"))?,
            None => 0,
        };
        ensure!(
            actual_rows == expected_rows,
            "transaction-sender static-file block range {}..={} has {actual_rows} physical rows, expected {expected_rows}",
            block_range.start,
            block_range.end
        );
    }
    Ok(())
}

fn write_marker(
    directory: &JournalDirectory,
    marker: &RecoveryMarker,
    create: bool,
) -> eyre::Result<()> {
    let mut bytes = serde_json::to_vec_pretty(marker)?;
    bytes.push(b'\n');
    directory.write_entry_atomic(
        &format!("{RECOVERY_MARKER_FILE}.tmp"),
        RECOVERY_MARKER_FILE,
        &bytes,
        !create,
    )?;
    ensure!(
        read_marker(directory)? == *marker,
        "recovery marker reread mismatch"
    );
    Ok(())
}

fn validate_marker_against_journal(
    marker: &RecoveryMarker,
    journal: &arb_reth_engine::MessageJournalInspection,
) -> eyre::Result<()> {
    ensure!(
        marker.anchor() == journal.header.anchor,
        "recovery marker journal anchor mismatch"
    );
    ensure!(
        marker.target() == journal.watermark,
        "recovery marker target no longer equals J"
    );
    Ok(())
}

fn retained_header<TX>(
    tx: &TX,
    static_files: &StaticFileProvider<ArbPrimitives>,
    block_number: u64,
) -> eyre::Result<Option<reth_primitives_traits::SealedHeader<Header>>>
where
    TX: reth_db_api::transaction::DbTx,
{
    if let Some(header) = static_files.sealed_header(block_number)? {
        return Ok(Some(header));
    }
    let Some(header) = tx.get::<tables::Headers<Header>>(block_number)? else {
        return Ok(None);
    };
    let hash = tx
        .get::<tables::CanonicalHeaders>(block_number)?
        .ok_or_else(|| eyre!("MDBX header {block_number} has no canonical hash"))?;
    Ok(Some(reth_primitives_traits::SealedHeader::new(
        header, hash,
    )))
}

fn read_retained_header(
    storage: &RecoveryStorageConfig,
    number: u64,
) -> eyre::Result<Option<reth_primitives_traits::SealedHeader<Header>>> {
    let db = open_db_read_only(
        storage.datadir.join("db"),
        DatabaseArguments::new(ClientVersion::default()),
    )?;
    let tx = db.tx()?;
    let static_files =
        StaticFileProvider::<ArbPrimitives>::read_only(storage.datadir.join("static_files"))?;
    retained_header(&tx, &static_files, number)
}

fn inspect_exact_storage_shape(
    datadir: &Path,
    receipts_fully_pruned: bool,
    senders_fully_pruned: bool,
    genesis_block: u64,
) -> eyre::Result<ExactStorageIdentity> {
    let db = open_db_read_only(
        datadir.join("db"),
        DatabaseArguments::new(ClientVersion::default()),
    )?;
    let tx = db.tx()?;
    let static_files =
        StaticFileProvider::<ArbPrimitives>::read_only(datadir.join("static_files"))?;
    inspect_exact_storage_shape_with(
        &tx,
        &static_files,
        datadir,
        receipts_fully_pruned,
        senders_fully_pruned,
        genesis_block,
    )
}

fn inspect_exact_storage_shape_with<TX>(
    tx: &TX,
    static_files: &StaticFileProvider<ArbPrimitives>,
    datadir: &Path,
    receipts_fully_pruned: bool,
    senders_fully_pruned: bool,
    genesis_block: u64,
) -> eyre::Result<ExactStorageIdentity>
where
    TX: reth_db_api::transaction::DbTx,
{
    let canonical_tip = tx.cursor_read::<tables::CanonicalHeaders>()?.last()?;
    let tip_number = tx
        .get::<tables::StageCheckpoints>(StageId::Execution.to_string())?
        .map(|checkpoint| checkpoint.block_number)
        .ok_or_else(|| eyre!("stopped storage has no MDBX execution checkpoint"))?;
    ensure!(
        canonical_tip.is_none_or(|(number, _)| number == tip_number),
        "retained MDBX canonical bound {canonical_tip:?} differs from execution checkpoint {tip_number}"
    );
    let expected_body_rows = tip_number
        .checked_sub(genesis_block)
        .and_then(|rows| rows.checked_add(1))
        .ok_or_else(|| {
            eyre!(
                "MDBX body-index range {genesis_block}..={tip_number} is not a valid canonical range"
            )
        })?;
    let expected_body_rows = usize::try_from(expected_body_rows)
        .map_err(|_| eyre!("MDBX body-index range does not fit the host entry-count type"))?;
    let mut body_indices = tx.cursor_read::<tables::BlockBodyIndices>()?;
    let first_body_block = body_indices.first()?.map(|(block, _)| block);
    let last_body_block = body_indices.last()?.map(|(block, _)| block);
    let body_rows = tx.entries::<tables::BlockBodyIndices>()?;
    ensure!(
        first_body_block == Some(genesis_block)
            && last_body_block == Some(tip_number)
            && body_rows == expected_body_rows,
        "MDBX body-index keys ({first_body_block:?}, {last_body_block:?}, {body_rows} rows) are not the complete canonical range {genesis_block}..={tip_number}"
    );
    for stage in StageId::ALL {
        let checkpoint = tx
            .get::<tables::StageCheckpoints>(stage.to_string())?
            .map(|checkpoint| checkpoint.block_number);
        ensure!(
            checkpoint == Some(tip_number),
            "MDBX stage {stage} checkpoint {checkpoint:?} is not the exact durable tip {tip_number}"
        );
    }
    for (name, key) in [
        ("safe", tables::ChainStateKey::LastSafeBlock),
        ("finalized", tables::ChainStateKey::LastFinalizedBlock),
    ] {
        ensure!(
            tx.get::<tables::ChainState>(key)?
                .is_none_or(|number| number <= tip_number),
            "MDBX {name} block is ahead of the durable tip {tip_number}"
        );
    }
    let settings = tx
        .get::<tables::Metadata>("storage_settings".to_string())?
        .and_then(|bytes| serde_json::from_slice::<StorageSettings>(&bytes).ok());
    ensure!(
        settings == Some(StorageSettings::v2()),
        "exact storage classification requires persisted Reth storage-v2"
    );

    let static_path = datadir.join("static_files");
    for (segment, prune_segment) in [
        (StaticFileSegment::Headers, None),
        (StaticFileSegment::Transactions, Some(PruneSegment::Bodies)),
        (
            StaticFileSegment::AccountChangeSets,
            Some(PruneSegment::AccountHistory),
        ),
        (
            StaticFileSegment::StorageChangeSets,
            Some(PruneSegment::StorageHistory),
        ),
    ] {
        let pruned_through = prune_segment
            .map(|segment| tx.get::<tables::PruneCheckpoints>(segment))
            .transpose()?
            .flatten()
            .and_then(|checkpoint| checkpoint.block_number);
        validate_static_ranges(
            &static_path,
            static_files,
            segment,
            tip_number,
            genesis_block,
            pruned_through,
        )?;
    }
    validate_transaction_sender_ranges(
        tx,
        &static_path,
        static_files,
        tip_number,
        genesis_block,
        senders_fully_pruned,
    )?;
    if receipts_fully_pruned {
        ensure!(
            static_files.get_highest_static_file_block(StaticFileSegment::Receipts).is_none()
                && observed_static_ranges(
                    &static_path,
                    static_files,
                    StaticFileSegment::Receipts,
                )?
                .is_empty(),
            "fully pruned receipts configuration has stale or orphaned receipt static files"
        );
    } else {
        let receipts_pruned_through = tx
            .get::<tables::PruneCheckpoints>(PruneSegment::Receipts)?
            .and_then(|checkpoint| checkpoint.block_number);
        validate_static_ranges(
            &static_path,
            static_files,
            StaticFileSegment::Receipts,
            tip_number,
            genesis_block,
            receipts_pruned_through,
        )?;
    }

    let body_indices = tx
        .get::<tables::BlockBodyIndices>(tip_number)?
        .ok_or_else(|| eyre!("MDBX body indices are missing at durable tip {tip_number}"))?;
    let next_tx = body_indices.next_tx_num();
    let static_tx = static_files.get_highest_static_file_tx(StaticFileSegment::Transactions);
    ensure!(
        (next_tx == 0 && static_tx.is_none())
            || (next_tx > 0 && static_tx == Some(next_tx.saturating_sub(1))),
        "transaction static-file bound {static_tx:?} differs from MDBX next transaction {next_tx}"
    );

    let rocks = open_rocks_read_only(&datadir.join("rocksdb"))?;
    let lookup_prune = tx.get::<tables::PruneCheckpoints>(PruneSegment::TransactionLookup)?;
    let retained_tx_start = lookup_prune
        .and_then(|checkpoint| checkpoint.tx_number)
        .map_or(0, |number| number.saturating_add(1));
    let mut transaction_numbers = std::collections::BTreeSet::new();
    for entry in rocks.iter::<tables::TransactionHashNumbers>()? {
        let (_, number) = entry?;
        ensure!(
            number >= retained_tx_start && number < next_tx,
            "RocksDB transaction lookup number {number} is outside retained range {retained_tx_start}..{next_tx}"
        );
        ensure!(
            transaction_numbers.insert(number),
            "RocksDB transaction lookup contains duplicate transaction number {number}"
        );
    }
    ensure!(
        transaction_numbers.first().copied()
            == (retained_tx_start < next_tx).then_some(retained_tx_start)
            && transaction_numbers.last().copied() == next_tx.checked_sub(1),
        "RocksDB transaction lookup bounds ({:?}, {:?}) do not match retained transaction frontier {retained_tx_start}..{next_tx}",
        transaction_numbers.first(),
        transaction_numbers.last()
    );

    for (name, segment, highest_changed_block) in [
        (
            "account",
            StaticFileSegment::AccountChangeSets,
            static_segment_highest_changed_block(
                &static_path,
                static_files,
                StaticFileSegment::AccountChangeSets,
            )?,
        ),
        (
            "storage",
            StaticFileSegment::StorageChangeSets,
            static_segment_highest_changed_block(
                &static_path,
                static_files,
                StaticFileSegment::StorageChangeSets,
            )?,
        ),
    ] {
        let max_history_block = match segment {
            StaticFileSegment::AccountChangeSets => {
                let mut max_block = None;
                for entry in rocks.iter::<tables::AccountsHistory>()? {
                    let (key, blocks) = entry?;
                    ensure!(
                        key.highest_block_number == u64::MAX
                            || key.highest_block_number <= tip_number,
                        "RocksDB account history shard is ahead of durable tip {tip_number}"
                    );
                    if let Some(block) = blocks.max() {
                        ensure!(
                            block <= tip_number,
                            "RocksDB account history is ahead of durable tip {tip_number}"
                        );
                        max_block = max_block.max(Some(block));
                    }
                }
                max_block
            }
            StaticFileSegment::StorageChangeSets => {
                let mut max_block = None;
                for entry in rocks.iter::<tables::StoragesHistory>()? {
                    let (key, blocks) = entry?;
                    ensure!(
                        key.sharded_key.highest_block_number == u64::MAX
                            || key.sharded_key.highest_block_number <= tip_number,
                        "RocksDB storage history shard is ahead of durable tip {tip_number}"
                    );
                    if let Some(block) = blocks.max() {
                        ensure!(
                            block <= tip_number,
                            "RocksDB storage history is ahead of durable tip {tip_number}"
                        );
                        max_block = max_block.max(Some(block));
                    }
                }
                max_block
            }
            _ => unreachable!(),
        };
        ensure!(
            max_history_block == highest_changed_block,
            "RocksDB {name} history bound {max_history_block:?} differs from the static changeset bound {highest_changed_block:?}"
        );
    }

    let tip_header = retained_header(tx, static_files, tip_number)?
        .ok_or_else(|| eyre!("durable tip header {tip_number} is missing"))?;
    if let Some((_, canonical_hash)) = canonical_tip {
        ensure!(
            tip_header.hash() == canonical_hash,
            "retained tip header hash differs from MDBX canonical hash"
        );
    }
    Ok(ExactStorageIdentity {
        tip_number,
        tip_hash: tip_header.hash(),
        tip_state_root: tip_header.state_root,
    })
}

fn static_segment_highest_changed_block(
    path: &Path,
    provider: &StaticFileProvider<ArbPrimitives>,
    segment: StaticFileSegment,
) -> eyre::Result<Option<u64>> {
    let mut jars = Vec::new();
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some((parsed, _)) = StaticFileSegment::parse_filename(&name) else {
            continue;
        };
        if parsed == segment && !name.contains('.') {
            let jar = provider
                .get_segment_provider_for_path(&entry.path())?
                .ok_or_else(|| eyre!("static-file path has no readable segment header"))?;
            if jar.rows() > 0 {
                let range = jar
                    .user_header()
                    .block_range()
                    .ok_or_else(|| eyre!("changeset static-file with rows has no block range"))?;
                jars.push((range.start(), range.end(), jar));
            }
        }
    }
    jars.sort_by_key(|(start, end, _)| (*start, *end));
    for (start, end, jar) in jars.into_iter().rev() {
        for block in (start..=end).rev() {
            let count = jar
                .read_changeset_offset(block)?
                .ok_or_else(|| eyre!("changeset offset metadata is missing at block {block}"))?
                .num_changes();
            if count > 0 {
                return Ok(Some(block));
            }
        }
    }
    Ok(None)
}

fn open_rocks_read_only(path: &Path) -> eyre::Result<RocksDBProvider> {
    ensure!(
        path.is_dir(),
        "RocksDB directory is missing at {}",
        path.display()
    );
    let current = std::fs::read_to_string(path.join("CURRENT"))?;
    let manifest = current.trim();
    ensure!(
        !manifest.is_empty() && !manifest.contains('/') && path.join(manifest).is_file(),
        "RocksDB CURRENT references invalid metadata"
    );
    RocksDBProvider::builder(path)
        .with_default_tables()
        .with_read_only(true)
        .build()
        .map_err(|error| eyre!("open RocksDB read-only: {error}"))
}

fn open_recovery_factory(
    storage: &RecoveryStorageConfig,
) -> eyre::Result<ProviderFactory<ArbNodeTypesWithDB>> {
    let db = init_db(
        storage.datadir.join("db"),
        DatabaseArguments::new(ClientVersion::default()),
    )?;
    let static_files = StaticFileProvider::read_write(storage.datadir.join("static_files"))?;
    let rocksdb = RocksDBProvider::builder(storage.datadir.join("rocksdb"))
        .with_default_tables()
        .build()
        .map_err(|error| eyre!("open RocksDB for stopped repair: {error}"))?;
    let factory = ProviderFactory::new(
        db,
        storage.chain_spec.clone(),
        static_files,
        rocksdb,
        Runtime::test(),
    )?
    .with_prune_modes(
        storage
            .prune_config
            .as_ref()
            .map(|config| config.segments.clone())
            .unwrap_or_default(),
    );
    factory.set_storage_settings_cache(StorageSettings::v2());
    Ok(factory)
}

fn update_recovery_phase(
    directory: &JournalDirectory,
    marker: &mut RecoveryMarker,
    phase: RecoveryPhase,
) -> eyre::Result<()> {
    if phase_rank(phase) > phase_rank(marker.phase) {
        marker.phase = phase;
        write_marker(directory, marker, false)?;
    }
    let boundary = match phase {
        RecoveryPhase::Classified => "phase_classified_revalidated",
        RecoveryPhase::ConsistencyHealed => "phase_consistency_healed_revalidated",
        RecoveryPhase::HistoryValidated => "phase_history_validated_revalidated",
        RecoveryPhase::DbUnwound => "phase_db_unwound_revalidated",
        RecoveryPhase::ReopenedValidated => "phase_reopened_validated_revalidated",
    };
    recovery_failpoint(boundary);
    Ok(())
}

fn validate_old_tip_header(
    factory: &ProviderFactory<ArbNodeTypesWithDB>,
    marker: &RecoveryMarker,
) -> eyre::Result<()> {
    let header = factory
        .provider()?
        .sealed_header(marker.old_db_tip_number)?
        .ok_or_else(|| eyre!("frozen old DB tip header is missing"))?;
    ensure!(
        header.hash() == marker.old_db_tip_hash
            && header.state_root == marker.old_db_tip_state_root,
        "frozen old DB tip hash/state root changed before unwind"
    );
    Ok(())
}

fn validate_prune_observations(
    factory: &ProviderFactory<ArbNodeTypesWithDB>,
    marker: &RecoveryMarker,
) -> eyre::Result<()> {
    let provider = factory.provider()?;
    let account = provider.get_prune_checkpoint(PruneSegment::AccountHistory)?;
    let storage = provider.get_prune_checkpoint(PruneSegment::StorageHistory)?;
    ensure!(
        observed_prune_checkpoint(account) == marker.account_history_prune_checkpoint
            && observed_prune_checkpoint(storage) == marker.storage_history_prune_checkpoint,
        "account/storage prune checkpoints changed after recovery classification"
    );
    let first = marker.target_block_number.saturating_add(1);
    for (name, checkpoint) in [("account", account), ("storage", storage)] {
        ensure!(
            !checkpoint
                .and_then(|checkpoint| checkpoint.block_number)
                .is_some_and(|block| block >= first),
            "{name} history is pruned through the requested unwind range at block {first}; snapshot/operator recovery required"
        );
    }
    Ok(())
}

fn validate_changeset_segment_coverage(
    name: &str,
    target: u64,
    tip: u64,
    mut inspect: impl FnMut(u64) -> eyre::Result<(u64, u64, Option<u64>)>,
) -> eyre::Result<()> {
    for block in target.saturating_add(1)..=tip {
        let (start, end, num_changes) = inspect(block)?;
        ensure!(
            (start..=end).contains(&block),
            "{name} changeset jar range does not cover block {block}"
        );
        ensure!(
            num_changes.is_some(),
            "{name} changeset offset metadata is missing at block {block}; snapshot/operator recovery required"
        );
    }
    Ok(())
}

fn validate_changeset_coverage(
    factory: &ProviderFactory<ArbNodeTypesWithDB>,
    target: u64,
    tip: u64,
) -> eyre::Result<()> {
    let static_files = factory.static_file_provider();
    for (name, segment) in [
        ("account", StaticFileSegment::AccountChangeSets),
        ("storage", StaticFileSegment::StorageChangeSets),
    ] {
        validate_changeset_segment_coverage(name, target, tip, |block| {
            let jar = static_files
                .get_segment_provider_for_block(segment, block, None)
                .map_err(|error| {
                    eyre!(
                        "{name} changeset static-file gap at block {block}: {error}; snapshot/operator recovery required"
                    )
                })?;
            let range = jar
                .user_header()
                .block_range()
                .ok_or_else(|| eyre!("{name} changeset jar at block {block} has no block range"))?;
            let num_changes = jar
                .read_changeset_offset(block)?
                .map(|offset| offset.num_changes());
            Ok((range.start(), range.end(), num_changes))
        })?;
    }
    Ok(())
}

fn repair_db_ahead_suffix(runtime: &RecoveryRuntime) -> eyre::Result<()> {
    ensure!(
        is_recovery_worker(),
        "DB>J mutation is restricted to the disposable worker"
    );
    let mut marker = runtime.marker.clone();
    ensure!(
        phase_rank(marker.phase) < phase_rank(RecoveryPhase::DbUnwound),
        "recovery marker is already repaired"
    );
    validate_frozen_static_evidence(
        &marker,
        &runtime.storage.datadir,
        runtime.storage.genesis_block,
        marker.old_db_tip_number,
    )?;
    let factory = open_recovery_factory(&runtime.storage)?;
    let (rocksdb_unwind, static_unwind) = factory.check_consistency()?;
    recovery_failpoint("consistency_heal_completed");
    ensure!(
        rocksdb_unwind.is_none() && static_unwind.is_none(),
        "stopped stores require an unsupported consistency unwind ({rocksdb_unwind:?}, {static_unwind:?})"
    );
    drop(factory);
    update_recovery_phase(
        &runtime.storage.directory,
        &mut marker,
        RecoveryPhase::ConsistencyHealed,
    )?;

    let factory = open_recovery_factory(&runtime.storage)?;
    let provider = factory.provider()?;
    let current_tip = provider.last_block_number()?;
    let target = provider
        .sealed_header(marker.target_block_number)?
        .ok_or_else(|| eyre!("frozen journal target header disappeared"))?;
    ensure!(
        target.hash() == marker.target_block_hash && target.state_root == marker.target_state_root,
        "frozen journal target hash/state root changed"
    );
    drop(provider);
    validate_prune_observations(&factory, &marker)?;
    if current_tip == marker.old_db_tip_number {
        validate_old_tip_header(&factory, &marker)?;
        validate_changeset_coverage(&factory, marker.target_block_number, current_tip)?;
    } else {
        ensure!(
            current_tip == marker.target_block_number
                && phase_rank(runtime.marker.phase) >= phase_rank(RecoveryPhase::HistoryValidated),
            "stopped storage tip {current_tip} contradicts frozen recovery phase {:?}",
            runtime.marker.phase
        );
    }
    update_recovery_phase(
        &runtime.storage.directory,
        &mut marker,
        RecoveryPhase::HistoryValidated,
    )?;
    recovery_failpoint("history_validated_before_unwind");
    if current_tip > marker.target_block_number {
        let provider = factory.database_provider_rw()?;
        provider.remove_block_and_execution_above(marker.target_block_number)?;
        provider
            .commit()
            .map_err(|error| eyre!("commit stopped DB>J unwind: {error}"))?;
        recovery_failpoint("aggregate_unwind_committed");
    }
    drop(factory);
    validate_repaired_storage(&runtime.storage, &marker)?;
    update_recovery_phase(
        &runtime.storage.directory,
        &mut marker,
        RecoveryPhase::DbUnwound,
    )?;
    Ok(())
}

fn validate_repaired_storage(
    storage: &RecoveryStorageConfig,
    marker: &RecoveryMarker,
) -> eyre::Result<()> {
    let tip = inspect_exact_storage_shape(
        &storage.datadir,
        receipts_fully_pruned(storage.prune_config.as_ref()),
        senders_fully_pruned(storage.prune_config.as_ref()),
        storage.genesis_block,
    )?;
    ensure!(
        tip == (ExactStorageIdentity {
            tip_number: marker.target_block_number,
            tip_hash: marker.target_block_hash,
            tip_state_root: marker.target_state_root,
        }),
        "freshly reopened stopped storage does not equal exact J"
    );
    validate_frozen_static_evidence(
        marker,
        &storage.datadir,
        storage.genesis_block,
        marker.target_block_number,
    )?;
    let journal = inspect_message_journal(&storage.directory, storage.storage_context)?;
    validate_marker_against_journal(marker, &journal)?;
    Ok(())
}

#[cfg(test)]
fn run_reopened_validation_subprocess(storage: &RecoveryStorageConfig) -> eyre::Result<()> {
    let mut command = std::process::Command::new(std::env::current_exe()?);
    command
        .args([
            "--exact",
            "recovery::tests::process_fixture_helper",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ITE106A_RECOVERY_ACTION", "final-validate")
        .env("ITE106A_RECOVERY_DATADIR", &storage.datadir);
    command.env(
        RECOVERY_VALIDATE_RECEIPTS_ENV,
        if receipts_fully_pruned(storage.prune_config.as_ref()) {
            "1"
        } else {
            "0"
        },
    );
    command.env(
        RECOVERY_VALIDATE_SENDERS_ENV,
        if senders_fully_pruned(storage.prune_config.as_ref()) {
            "1"
        } else {
            "0"
        },
    );
    let output = command.output()?;
    ensure!(
        output.status.success(),
        "reopened recovery validation subprocess failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

fn validate_reopened_finalization(
    datadir: &Path,
    receipts_fully_pruned: bool,
    senders_fully_pruned: bool,
) -> eyre::Result<()> {
    let directory = JournalDirectory::open(datadir)?;
    let marker = read_marker(&directory)?;
    ensure!(
        marker.phase == RecoveryPhase::DbUnwound,
        "fresh-process validation requires a durably unwound marker"
    );
    let exact = inspect_exact_storage_shape(
        datadir,
        receipts_fully_pruned,
        senders_fully_pruned,
        marker.l2_genesis_block_number,
    )
    .wrap_err("reopened recovery storage is not exactly consistent")?;
    ensure!(
        exact
            == (ExactStorageIdentity {
                tip_number: marker.target_block_number,
                tip_hash: marker.target_block_hash,
                tip_state_root: marker.target_state_root,
            }),
        "fresh-process stopped storage does not equal exact J"
    );
    validate_frozen_static_evidence(
        &marker,
        datadir,
        marker.l2_genesis_block_number,
        exact.tip_number,
    )?;
    let journal = inspect_message_journal(
        &directory,
        StorageContextV3 {
            l2_chain_id: marker.l2_chain_id,
            l2_genesis_number: marker.l2_genesis_block_number,
            l2_genesis_hash: marker.l2_genesis_hash,
            sequencer_inbox: marker.sequencer_inbox,
            bridge: marker.bridge,
            deployment_block: marker.deployment_block,
            anchor: marker.anchor(),
        },
    )?;
    validate_marker_against_journal(&marker, &journal)?;
    ensure!(
        read_marker(&directory)? == marker,
        "recovery marker changed during fresh-process proof"
    );
    Ok(())
}

#[derive(Clone, Copy)]
enum InventoryMode {
    Fresh,
    Ordinary { snapshot_completion_expected: bool },
}

fn inspect_artifacts(datadir: &Path, mode: InventoryMode) -> eyre::Result<()> {
    if !datadir.exists() {
        return Ok(());
    }
    let mut names = Vec::new();
    for entry in std::fs::read_dir(datadir)? {
        names.push(
            entry?
                .file_name()
                .into_string()
                .map_err(|_| eyre!("non-UTF8 authority sibling in datadir"))?,
        );
    }
    inspect_artifact_names(names, mode)
}

fn inspect_pinned_artifacts(directory: &JournalDirectory, mode: InventoryMode) -> eyre::Result<()> {
    inspect_artifact_names(directory.entry_names()?, mode)
}

fn inspect_artifact_names(names: Vec<String>, mode: InventoryMode) -> eyre::Result<()> {
    let mut journal_finals = 0usize;
    let mut lifecycle = false;
    for name in names {
        let authority_family = name.starts_with(MESSAGE_JOURNAL_FAMILY_PREFIX)
            || name.starts_with(LIFECYCLE_FILE)
            || name.starts_with(SNAPSHOT_COMPLETION_FILE)
            || name.starts_with(OLD_SNAPSHOT_MANIFEST)
            || name.starts_with(DIVERGENCE_MARKER_FILE)
            || name.starts_with(RECOVERY_MARKER_FILE)
            || name.starts_with(RESUME_FILE);
        if !authority_family {
            continue;
        }
        if matches!(mode, InventoryMode::Fresh) {
            return Err(eyre!("fresh target contains authority artifact {name}"));
        }
        if name == RESUME_FILE || name.starts_with(&format!("{RESUME_FILE}.")) {
            return Err(eyre!("resume artifact rejects phase-A startup: {name}"));
        }
        if name == OLD_SNAPSHOT_MANIFEST || name.starts_with(&format!("{OLD_SNAPSHOT_MANIFEST}.")) {
            return Err(eyre!(
                "old snapshot manifest rejects phase-A startup: {name}"
            ));
        }
        if name == DIVERGENCE_MARKER_FILE {
            continue;
        }
        if name.starts_with(DIVERGENCE_MARKER_FILE) {
            return Err(eyre!("unsupported divergence-marker sibling {name}"));
        }
        if name == RECOVERY_MARKER_FILE {
            continue;
        }
        if name.starts_with(RECOVERY_MARKER_FILE) {
            return Err(eyre!("unsupported recovery-marker sibling {name}"));
        }
        if name == LIFECYCLE_FILE {
            ensure!(!lifecycle, "duplicate lifecycle authority");
            lifecycle = true;
            continue;
        }
        if name.starts_with(LIFECYCLE_FILE) {
            return Err(eyre!("unsupported lifecycle sibling {name}"));
        }
        if name == SNAPSHOT_COMPLETION_FILE {
            ensure!(
                matches!(
                    mode,
                    InventoryMode::Ordinary {
                        snapshot_completion_expected: true
                    }
                ),
                "snapshot completion exists without an approved snapshot launch"
            );
            continue;
        }
        if name.starts_with(SNAPSHOT_COMPLETION_FILE) {
            return Err(eyre!("unsupported snapshot-completion sibling {name}"));
        }
        if let Some(generation) = exact_journal_final(&name) {
            let _ = generation;
            journal_finals += 1;
            continue;
        }
        return Err(eyre!(
            "unsupported, malformed, or temporary journal sibling {name}"
        ));
    }
    if matches!(mode, InventoryMode::Ordinary { .. }) {
        ensure!(journal_finals > 0, "missing v3 journal lineage");
        ensure!(lifecycle, "missing lifecycle authority");
    }
    Ok(())
}

fn exact_journal_final(name: &str) -> Option<u64> {
    let suffix = name.strip_prefix(MESSAGE_JOURNAL_PREFIX)?;
    let digits = suffix.strip_suffix(".log")?;
    (digits.len() == 20 && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| digits.parse().ok())
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_db_j_never_releases_the_phase_a_service_gate() {
        for state in [
            LifecycleState::Clean,
            LifecycleState::Initializing,
            LifecycleState::RunningUnclean,
        ] {
            assert!(
                reject_phase_a_equal_frontier(state).is_err(),
                "DB==J with {state:?} must stop before constructing a service-ready recovery gate"
            );
        }
    }

    #[test]
    fn process_fixture_helper() {
        if std::env::var_os("ITE106A_RECOVERY_ACTION").as_deref()
            != Some(std::ffi::OsStr::new("final-validate"))
        {
            return;
        }
        let datadir =
            std::env::var_os("ITE106A_RECOVERY_DATADIR").expect("recovery fixture datadir");
        let receipts_fully_pruned = std::env::var_os(RECOVERY_VALIDATE_RECEIPTS_ENV).as_deref()
            == Some(std::ffi::OsStr::new("1"));
        let senders_fully_pruned = std::env::var_os(RECOVERY_VALIDATE_SENDERS_ENV).as_deref()
            == Some(std::ffi::OsStr::new("1"));
        validate_reopened_finalization(
            Path::new(&datadir),
            receipts_fully_pruned,
            senders_fully_pruned,
        )
        .unwrap();
    }

    #[test]
    fn changeset_coverage_rejects_gap_and_missing_offsets() {
        assert!(
            validate_changeset_segment_coverage("account", 10, 12, |block| {
                Ok((11, 12, Some(block)))
            })
            .is_ok()
        );
        assert!(
            validate_changeset_segment_coverage("account", 10, 12, |block| {
                Ok((block + 1, block + 1, Some(0)))
            })
            .is_err()
        );
        assert!(
            validate_changeset_segment_coverage("storage", 10, 12, |_| Ok((11, 12, None))).is_err()
        );
    }

    #[test]
    fn frozen_ranges_compare_only_the_still_durable_prefix() {
        let frozen = vec![
            ObservedStaticRange { start: 1, end: 4 },
            ObservedStaticRange { start: 5, end: 8 },
        ];
        assert_eq!(
            ranges_through(&frozen, 6),
            vec![
                ObservedStaticRange { start: 1, end: 4 },
                ObservedStaticRange { start: 5, end: 6 },
            ]
        );
    }

    #[test]
    fn exact_v3_name_and_four_inventory_guards() {
        assert_eq!(
            exact_journal_final("arb-message-journal-v3-g00000000000000000042.log"),
            Some(42)
        );
        for invalid in [
            "arb-message-journal-v3-g42.log",
            "arb-message-journal-v3-g00000000000000000042.tmp",
            "arb-message-journal-v3-g0000000000000000004x.log",
            "arb-message-journal-v2-g00000000000000000042.log",
        ] {
            assert_eq!(exact_journal_final(invalid), None);
        }

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(RESUME_FILE), b"{}").unwrap();
        assert!(
            inspect_artifacts(
                dir.path(),
                InventoryMode::Ordinary {
                    snapshot_completion_expected: false,
                },
            )
            .is_err()
        );
        assert!(inspect_artifacts(dir.path(), InventoryMode::Fresh).is_err());

        assert!(
            inspect_artifact_names(
                vec![
                    DIVERGENCE_MARKER_FILE.to_owned(),
                    format!("{RECOVERY_MARKER_FILE}.tmp"),
                ],
                InventoryMode::Ordinary {
                    snapshot_completion_expected: false,
                },
            )
            .unwrap_err()
            .to_string()
            .contains("unsupported recovery-marker sibling")
        );

        // Fresh, ordinary, divergence, and recovery inventories use exact names only. Marker body
        // validation is a separate mandatory preflight after the complete sibling set is accepted.
        assert!(inspect_artifact_names(Vec::new(), InventoryMode::Fresh).is_ok());
        let ordinary = vec![
            "arb-message-journal-v3-g00000000000000000000.log".to_owned(),
            LIFECYCLE_FILE.to_owned(),
        ];
        for marker in [DIVERGENCE_MARKER_FILE, RECOVERY_MARKER_FILE] {
            let mut inventory = ordinary.clone();
            inventory.push(marker.to_owned());
            assert!(
                inspect_artifact_names(
                    inventory,
                    InventoryMode::Ordinary {
                        snapshot_completion_expected: false,
                    },
                )
                .is_ok()
            );
        }
        let mut with_completion = ordinary.clone();
        with_completion.push(SNAPSHOT_COMPLETION_FILE.to_owned());
        assert!(
            inspect_artifact_names(
                with_completion.clone(),
                InventoryMode::Ordinary {
                    snapshot_completion_expected: false,
                },
            )
            .is_err()
        );
        assert!(
            inspect_artifact_names(
                with_completion,
                InventoryMode::Ordinary {
                    snapshot_completion_expected: true,
                },
            )
            .is_ok()
        );
    }

    #[test]
    fn both_marker_bodies_validate_before_divergence_precedence() {
        let dir = tempfile::tempdir().unwrap();
        let directory = JournalDirectory::open(dir.path()).unwrap();
        let context = production_storage_context();
        let journal =
            arb_reth_engine::initialize_approved_snapshot_journal_v3(&directory, context).unwrap();
        std::fs::write(dir.path().join(LIFECYCLE_FILE), []).unwrap();
        let observation = arb_reth_engine::decode_production_bootstrap_observation();
        let bootstrap = arb_reth_engine::production_bootstrap_authority();
        let divergence = arb_reth_engine::DivergenceMarkerV4 {
            cause: arb_reth_engine::DivergenceCauseV4::ExistingAuthorityInvalidatedBySafeReorg,
            journal_operation_generation: journal.last_operation_generation,
            authority_chain_position: journal.authority_operation_count,
            context_id: observation.context_id,
            context_digest: observation.context_digest,
            j_sequence: journal.watermark.sequence,
            j_l2_block_number: journal.watermark.block_number,
            j_l2_block_hash: journal.watermark.block_hash,
            v_sequence: journal.v.unwrap().sequence,
            v_l2_block_number: journal.v.unwrap().block_number,
            v_l2_block_hash: journal.v.unwrap().block_hash,
            candidate_sequence: bootstrap.start_sequence,
            candidate_l2_block_number: bootstrap.start_sequence,
            expected_fingerprint: B256::ZERO,
            observed_fingerprint: B256::ZERO,
            safe_l1_number: observation.safe_l1_number,
            safe_l1_hash: observation.safe_l1_hash,
            containing_l1_number: observation.containing_l1_number,
            containing_l1_hash: observation.containing_l1_hash,
            posting_transaction_hash: observation.posting_transaction_hash,
            posting_transaction_index: observation.posting_transaction_index,
            delivery_log_index: observation.delivery_log_index,
            batch_sequence: observation.batch_sequence,
            terminal_message_ordinal: observation.terminal_message_ordinal,
            decoded_message_count: observation.decoded_message_count,
            cause_authority_id: bootstrap.authority_id,
            expected_value: bootstrap.evidence_digest,
            observed_value: B256::repeat_byte(0xff),
        };
        std::fs::write(
            dir.path().join(DIVERGENCE_MARKER_FILE),
            divergence.encode().unwrap(),
        )
        .unwrap();
        let recovery = RecoveryMarker {
            version: RECOVERY_VERSION,
            phase: RecoveryPhase::Classified,
            l2_chain_id: 1,
            l2_genesis_block_number: 0,
            l2_genesis_hash: B256::repeat_byte(2),
            sequencer_inbox: Address::repeat_byte(3),
            bridge: Address::repeat_byte(4),
            deployment_block: 0,
            snapshot_seeded: false,
            anchor_sequence: 0,
            anchor_block_number: 0,
            anchor_block_hash: B256::repeat_byte(5),
            target_sequence: 1,
            target_block_number: 1,
            target_block_hash: B256::repeat_byte(6),
            target_state_root: B256::repeat_byte(7),
            old_db_tip_number: 2,
            old_db_tip_hash: B256::repeat_byte(8),
            old_db_tip_state_root: B256::repeat_byte(9),
            active_unwind_horizon: 1,
            account_history_prune_checkpoint: ObservedPruneCheckpoint::None,
            storage_history_prune_checkpoint: ObservedPruneCheckpoint::None,
            account_changeset_ranges: Vec::new(),
            storage_changeset_ranges: Vec::new(),
        };
        std::fs::write(
            dir.path().join(RECOVERY_MARKER_FILE),
            serde_json::to_vec(&recovery).unwrap(),
        )
        .unwrap();
        assert_eq!(
            preflight_ordinary_authority(&directory, false).unwrap(),
            OrdinaryAuthorityEvidence::Divergence
        );
        let divergence_error = crate::commands::node::require_no_phase_a_evidence(
            preflight_ordinary_authority(&directory, false).unwrap(),
        )
        .unwrap_err();
        assert!(
            divergence_error
                .downcast_ref::<crate::commands::node::DivergenceEvidencePhaseUnavailable>()
                .is_some()
        );

        std::fs::remove_file(dir.path().join(DIVERGENCE_MARKER_FILE)).unwrap();
        let recovery_error = crate::commands::node::require_no_phase_a_evidence(
            preflight_ordinary_authority(&directory, false).unwrap(),
        )
        .unwrap_err();
        assert!(
            recovery_error
                .downcast_ref::<crate::commands::node::RecoveryEvidencePhaseUnavailable>()
                .is_some()
        );
        std::fs::write(
            dir.path().join(DIVERGENCE_MARKER_FILE),
            divergence.encode().unwrap(),
        )
        .unwrap();

        std::fs::write(dir.path().join(RECOVERY_MARKER_FILE), b"{").unwrap();
        assert!(preflight_ordinary_authority(&directory, false).is_err());
        std::fs::write(
            dir.path().join(RECOVERY_MARKER_FILE),
            serde_json::to_vec(&recovery).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.path().join(DIVERGENCE_MARKER_FILE), b"{").unwrap();
        assert!(preflight_ordinary_authority(&directory, false).is_err());
    }
}
