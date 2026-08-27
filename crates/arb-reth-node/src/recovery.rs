//! Bounded stopped-storage recovery for a durable DB suffix ahead of the message journal.

use std::{
    fs::{File, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use alloy_consensus::Header;
use alloy_primitives::{Address, B256};
use alloy_provider::{Provider as _, ProviderBuilder};
use arb_reth_engine::{
    MessageJournalAnchor, MessageJournalEntry, divergence_marker_path, inspect_message_journal,
    message_journal_path, rewrite_journal_to_identity_at,
};
use arb_reth_sync::{L1ResumeCheckpoint, inspect_resume_log_strict, rewrite_resume_checkpoint_at};
use arbitrum_alloy_consensus::reth::ArbPrimitives;
use eyre::{WrapErr as _, ensure, eyre};
use reth_chainspec::{ChainSpec, EthChainSpec as _};
use reth_config::PruneConfig;
use reth_db::{
    ClientVersion, Database as _, Tables, init_db, mdbx::DatabaseArguments, open_db_read_only,
    tables,
};
use reth_db_api::{cursor::DbCursorRO as _, models::StorageSettings, transaction::DbTx as _};
use reth_node_types::NodeTypesWithDBAdapter;
use reth_provider::{
    BlockExecutionWriter as _, BlockNumReader, DatabaseProviderFactory as _, HeaderProvider as _,
    ProviderFactory, StaticFileProviderFactory as _, StorageSettingsCache as _,
    providers::{RocksDBProvider, StaticFileProvider},
};
use reth_prune_types::{MINIMUM_UNWIND_SAFE_DISTANCE, PruneCheckpoint, PruneSegment};
use reth_stages_types::StageId;
use reth_static_file_types::StaticFileSegment;
use reth_storage_api::{DBProvider as _, PruneCheckpointReader as _};
use reth_tasks::Runtime;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::ArbNode;

type ArbNodeTypesWithDB = NodeTypesWithDBAdapter<ArbNode, reth_db::DatabaseEnv>;

pub(crate) const RECOVERY_MARKER_FILE: &str = "arb-message-recovery.json";
const RECOVERY_VERSION: u64 = 1;
const RECOVERY_FAILPOINT_ENV: &str = "ARB_RETH_RECOVERY_FAILPOINT";
pub(crate) const RECOVERY_WORKER_ENV: &str = "ARB_RETH_INTERNAL_RECOVERY_WORKER";
const RECOVERY_VALIDATE_DATADIR_ENV: &str = "ARB_RETH_INTERNAL_RECOVERY_VALIDATE_DATADIR";
const RECOVERY_VALIDATE_RECEIPTS_ENV: &str = "ARB_RETH_INTERNAL_RECOVERY_RECEIPTS_PRUNED";
const RECOVERY_VALIDATE_SENDERS_ENV: &str = "ARB_RETH_INTERNAL_RECOVERY_SENDERS_PRUNED";

/// The classification supplied by chaininfo, kept explicit rather than optional in the marker.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ParentChainClassification {
    Unspecified,
    Arbitrum,
    NonArbitrum,
}

/// CLI and chain identities that must remain stable for the whole recovery transaction.
#[derive(Clone)]
pub(crate) struct RecoveryConfig {
    pub datadir: PathBuf,
    pub chain_spec: Arc<ChainSpec>,
    pub chain_id: u64,
    pub genesis_block: u64,
    pub sequencer_inbox: Address,
    pub bridge: Address,
    pub deployed_at: u64,
    pub parent_chain_claim: ParentChainClaim,
    pub snapshot_seeded: bool,
    pub prune_config: Option<PruneConfig>,
    pub no_fsync: bool,
    pub no_l1_derive: bool,
    pub l1_rpc: Option<String>,
    pub l1_beacon: Option<String>,
    pub l1_start_block: Option<u64>,
    pub l1_start_delayed: Option<u64>,
    pub l1_end_block: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ParentChainClaim {
    pub chain_id: Option<u64>,
    pub classification: ParentChainClassification,
}

/// Result supplied to normal node wiring after stopped-storage classification/repair.
pub(crate) struct RecoveryPreparation {
    pub gate: RecoveryGate,
    pub runtime: Option<RecoveryRuntime>,
}

#[derive(Clone)]
pub struct RecoveryRuntime {
    pub(crate) marker: RecoveryMarker,
    storage: RecoveryStorageConfig,
}

#[derive(Clone)]
struct RecoveryStorageConfig {
    datadir: PathBuf,
    chain_spec: Arc<ChainSpec>,
    genesis_block: u64,
    snapshot_seeded: bool,
    prune_config: Option<PruneConfig>,
}

impl RecoveryStorageConfig {
    fn from_config(config: &RecoveryConfig) -> Self {
        Self {
            datadir: config.datadir.clone(),
            chain_spec: config.chain_spec.clone(),
            genesis_block: config.genesis_block,
            snapshot_seeded: config.snapshot_seeded,
            prune_config: config.prune_config.clone(),
        }
    }
}

/// One production readiness state shared by internal orchestration and Prometheus exposition.
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

    pub(crate) fn readiness_atomic(&self) -> Arc<AtomicBool> {
        self.inner.ready.clone()
    }

    /// Register after the process recorder is installed. The handle mirrors the same atomic state.
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

    /// Publish readiness only after the recovery marker's parent-directory fsync completed.
    pub(crate) fn release(&self) {
        self.inner.ready.store(true, Ordering::Release);
        if let Some(gauge) = self.inner.gauge.get() {
            gauge.set(1.0);
        }
        recovery_failpoint("ready_stored_before_services_released");
        self.inner.sender.send_replace(true);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RecoveryPhase {
    Classified,
    LayoutNormalized,
    ConsistencyHealed,
    HistoryValidated,
    DbUnwound,
    JournalRewritten,
    ResumeRewritten,
    OfflineValidated,
    Rederiving,
    Finalizing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SnapshotLayout {
    NonSnapshot,
    SnapshotLegacy,
    SnapshotAligned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub(crate) enum RecoveryTarget {
    Anchor {
        sequence: u64,
        block_number: u64,
        block_hash: B256,
        state_root: B256,
    },
    Message {
        sequence: u64,
        block_number: u64,
        block_hash: B256,
        state_root: B256,
        entry: MessageJournalEntry,
    },
}

impl RecoveryTarget {
    pub(crate) const fn sequence(self) -> u64 {
        match self {
            Self::Anchor { sequence, .. } | Self::Message { sequence, .. } => sequence,
        }
    }

    pub(crate) const fn block_number(self) -> u64 {
        match self {
            Self::Anchor { block_number, .. } | Self::Message { block_number, .. } => block_number,
        }
    }

    pub(crate) const fn block_hash(self) -> B256 {
        match self {
            Self::Anchor { block_hash, .. } | Self::Message { block_hash, .. } => block_hash,
        }
    }

    pub(crate) const fn state_root(self) -> B256 {
        match self {
            Self::Anchor { state_root, .. } | Self::Message { state_root, .. } => state_root,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    tag = "kind",
    content = "checkpoint",
    rename_all = "snake_case"
)]
pub(crate) enum FrozenResumeCheckpoint {
    None,
    Checkpoint(L1ResumeCheckpoint),
}

impl FrozenResumeCheckpoint {
    pub(crate) const fn checkpoint(self) -> Option<L1ResumeCheckpoint> {
        match self {
            Self::None => None,
            Self::Checkpoint(checkpoint) => Some(checkpoint),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum ObservedPruneCheckpoint {
    None,
    Checkpoint {
        block_number: ObservedNumber,
        tx_number: ObservedNumber,
        prune_mode: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservedStaticRange {
    start: u64,
    end: u64,
}

/// Closed durable evidence for one recovery transaction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryMarker {
    version: u64,
    phase: RecoveryPhase,
    l2_chain_id: u64,
    l2_genesis_block_number: u64,
    l2_genesis_hash: B256,
    parent_execution_chain_id: u64,
    parent_execution_genesis_hash: B256,
    parent_chain_is_arbitrum: ParentChainClassification,
    sequencer_inbox: Address,
    bridge: Address,
    deployment_block: u64,
    journal_anchor: MessageJournalAnchor,
    pub target: RecoveryTarget,
    pub old_db_tip_number: u64,
    pub old_db_tip_hash: B256,
    pub old_db_tip_state_root: B256,
    pub resume_checkpoint: FrozenResumeCheckpoint,
    active_unwind_horizon: u64,
    account_history_prune_checkpoint: ObservedPruneCheckpoint,
    storage_history_prune_checkpoint: ObservedPruneCheckpoint,
    account_changeset_ranges: Vec<ObservedStaticRange>,
    storage_changeset_ranges: Vec<ObservedStaticRange>,
    snapshot_layout: SnapshotLayout,
}

struct RecoveryCandidate {
    journal_anchor: MessageJournalAnchor,
    target: RecoveryTarget,
    old_db_tip_number: u64,
    old_db_tip_hash: B256,
    old_db_tip_state_root: B256,
    resume_checkpoint: FrozenResumeCheckpoint,
    active_unwind_horizon: u64,
    account_history_prune_checkpoint: ObservedPruneCheckpoint,
    storage_history_prune_checkpoint: ObservedPruneCheckpoint,
    account_changeset_ranges: Vec<ObservedStaticRange>,
    storage_changeset_ranges: Vec<ObservedStaticRange>,
    snapshot_layout: SnapshotLayout,
}

enum ReadOnlyClassification {
    Normal,
    Existing(RecoveryMarker),
    Candidate(RecoveryCandidate),
}

#[derive(Clone, Copy)]
struct ParentIdentity {
    chain_id: u64,
    genesis_hash: B256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExactStorageIdentity {
    tip_number: u64,
    tip_hash: B256,
    tip_state_root: B256,
}

/// Inspect local quarantine and stopped storage before an L1-backed genesis request is possible.
/// A DB-ahead or existing recovery transaction needs a locally supplied chain specification;
/// parent RPC data must never become the first authority consulted for those shapes.
pub(crate) fn preflight_before_l1_genesis(datadir: &Path, genesis_block: u64) -> eyre::Result<()> {
    if divergence_marker_path(datadir).exists() {
        return Err(eyre!(
            "unresolved arb-message-divergence.json has precedence over L1-backed genesis; no parent endpoint was contacted"
        ));
    }
    if recovery_marker_path(datadir).exists() {
        read_marker(datadir)?;
        return Err(eyre!(
            "recovery marker requires a locally supplied chain specification; refusing L1-backed genesis before recovery classification"
        ));
    }
    if !datadir.join("db").exists() {
        validate_fresh_sidecars(datadir)?;
        return Ok(());
    }

    let db = open_db_read_only(
        datadir.join("db"),
        DatabaseArguments::new(ClientVersion::default()),
    )?;
    let tx = db.tx()?;
    let has_tip = tx
        .cursor_read::<tables::CanonicalHeaders>()?
        .last()?
        .is_some()
        || tx
            .get::<tables::StageCheckpoints>(StageId::Execution.to_string())?
            .is_some();
    if !has_tip {
        validate_empty_mdbx(&tx)?;
        validate_fresh_sidecars(datadir)?;
        return Ok(());
    }
    drop(tx);
    drop(db);

    // Prune arguments depend on the chain spec that may be derived from L1. Admit either locally
    // self-consistent sender layout here; classification compares it to the resolved active mode.
    let exact = inspect_exact_storage_shape(datadir, false, true, genesis_block)
        .wrap_err("stopped storage is not an exact recognized shape; refusing L1-backed genesis")?;
    let journal_path = message_journal_path(datadir);
    if !journal_path.exists() {
        ensure!(
            exact.tip_number == genesis_block,
            "message journal is missing at non-genesis stopped-storage tip {}; refusing parent endpoint access",
            exact.tip_number
        );
        return Ok(());
    }
    let journal = inspect_message_journal(datadir, genesis_block)?;
    ensure!(
        !journal.has_incomplete_tail
            && journal.watermark.block_number == exact.tip_number
            && journal.watermark.block_hash == exact.tip_hash,
        "stopped DB/journal is not at exact parity; recovery requires a locally supplied chain specification before any parent endpoint access"
    );
    Ok(())
}

/// Classify before normal Reth construction, freeze evidence, and complete offline repair.
pub(crate) async fn prepare_recovery(config: RecoveryConfig) -> eyre::Result<RecoveryPreparation> {
    let classification = classify_read_only(&config)?;
    let (existing, candidate) = match classification {
        ReadOnlyClassification::Normal => {
            let gate = RecoveryGate::new(true);
            return Ok(RecoveryPreparation {
                gate,
                runtime: None,
            });
        }
        ReadOnlyClassification::Existing(marker) => (Some(marker), None),
        ReadOnlyClassification::Candidate(candidate) => (None, Some(candidate)),
    };

    validate_recovery_cli(&config)?;
    if let Some(marker) = existing.as_ref() {
        validate_marker_config(marker, &config)?;
    }
    let l1_rpc = config.l1_rpc.as_deref().expect("validated recovery L1 RPC");
    let parent = if existing.is_some() {
        observe_parent_with_retry(l1_rpc).await?
    } else {
        observe_parent(l1_rpc).await?
    };

    let mut marker = match (existing, candidate) {
        (Some(marker), None) => {
            validate_parent(&marker, parent)?;
            marker
        }
        (None, Some(candidate)) => {
            if let Some(expected) = config.parent_chain_claim.chain_id {
                ensure!(
                    parent.chain_id == expected,
                    "configured parent chain id {expected} does not match observed parent execution chain id {}",
                    parent.chain_id
                );
            }
            let marker = marker_from_candidate(&config, candidate, parent);
            write_marker(&config.datadir, &marker)?;
            recovery_failpoint("initial_marker_fsynced");
            marker
        }
        _ => unreachable!(),
    };

    let gate = RecoveryGate::new(false);
    complete_offline_repair(&config, &mut marker)?;
    Ok(RecoveryPreparation {
        gate: gate.clone(),
        runtime: Some(RecoveryRuntime {
            marker,
            storage: RecoveryStorageConfig::from_config(&config),
        }),
    })
}

fn marker_from_candidate(
    config: &RecoveryConfig,
    candidate: RecoveryCandidate,
    parent: ParentIdentity,
) -> RecoveryMarker {
    RecoveryMarker {
        version: RECOVERY_VERSION,
        phase: RecoveryPhase::Classified,
        l2_chain_id: config.chain_id,
        l2_genesis_block_number: config.genesis_block,
        l2_genesis_hash: config.chain_spec.genesis_hash(),
        parent_execution_chain_id: parent.chain_id,
        parent_execution_genesis_hash: parent.genesis_hash,
        parent_chain_is_arbitrum: config.parent_chain_claim.classification,
        sequencer_inbox: config.sequencer_inbox,
        bridge: config.bridge,
        deployment_block: config.deployed_at,
        journal_anchor: candidate.journal_anchor,
        target: candidate.target,
        old_db_tip_number: candidate.old_db_tip_number,
        old_db_tip_hash: candidate.old_db_tip_hash,
        old_db_tip_state_root: candidate.old_db_tip_state_root,
        resume_checkpoint: candidate.resume_checkpoint,
        active_unwind_horizon: candidate.active_unwind_horizon,
        account_history_prune_checkpoint: candidate.account_history_prune_checkpoint,
        storage_history_prune_checkpoint: candidate.storage_history_prune_checkpoint,
        account_changeset_ranges: candidate.account_changeset_ranges,
        storage_changeset_ranges: candidate.storage_changeset_ranges,
        snapshot_layout: candidate.snapshot_layout,
    }
}

fn classify_read_only(config: &RecoveryConfig) -> eyre::Result<ReadOnlyClassification> {
    let recovery_path = recovery_marker_path(&config.datadir);
    if divergence_marker_path(&config.datadir).exists() {
        return Err(eyre!(
            "unresolved arb-message-divergence.json has precedence over automatic recovery; explicit operator rewind is required"
        ));
    }
    if recovery_path.exists() {
        return Ok(ReadOnlyClassification::Existing(read_marker(
            &config.datadir,
        )?));
    }

    let db_path = config.datadir.join("db");
    if !db_path.exists() {
        validate_fresh_sidecars(&config.datadir)?;
        return Ok(ReadOnlyClassification::Normal);
    }
    let db = open_db_read_only(&db_path, DatabaseArguments::new(ClientVersion::default()))?;
    let tx = db.tx()?;
    let mdbx_tip = tx.cursor_read::<tables::CanonicalHeaders>()?.last()?;
    let execution_tip = tx
        .get::<tables::StageCheckpoints>(StageId::Execution.to_string())?
        .map(|checkpoint| checkpoint.block_number);
    let Some(db_tip_number) = mdbx_tip
        .map(|(number, _)| number)
        .into_iter()
        .chain(execution_tip)
        .max()
    else {
        validate_empty_mdbx(&tx)?;
        validate_fresh_sidecars(&config.datadir)?;
        return Ok(ReadOnlyClassification::Normal);
    };
    let static_files_path = config.datadir.join("static_files");
    let static_files: StaticFileProvider<ArbPrimitives> =
        StaticFileProvider::read_only(&static_files_path)?;
    let old_tip_header = retained_header(&tx, &static_files, db_tip_number)?
        .ok_or_else(|| eyre!("durable DB tip header {db_tip_number} is missing"))?;
    let db_tip_hash = old_tip_header.hash();
    let genesis_header = retained_header(&tx, &static_files, config.genesis_block)?
        .ok_or_else(|| eyre!("configured L2 genesis header is missing from the retained DB"))?;
    ensure!(
        genesis_header.hash() == config.chain_spec.genesis_hash(),
        "configured L2 genesis hash does not match the retained DB"
    );

    let settings = tx
        .get::<tables::Metadata>("storage_settings".to_string())?
        .and_then(|bytes| serde_json::from_slice::<StorageSettings>(&bytes).ok());
    ensure!(
        settings == Some(StorageSettings::v2()),
        "automatic recovery requires a persisted Reth storage-v2 datadir"
    );
    inspect_rocks_bounds(&config.datadir.join("rocksdb"))?;

    let journal_path = message_journal_path(&config.datadir);
    if !journal_path.exists() {
        if db_tip_number == config.genesis_block {
            let exact = inspect_exact_storage_shape_with(
                &tx,
                &static_files,
                &config.datadir,
                receipts_fully_pruned(config.prune_config.as_ref()),
                senders_fully_pruned(config.prune_config.as_ref()),
                config.genesis_block,
            )
            .wrap_err(
                "genesis stopped-storage cross-store mismatch; refusing normal mutating Reth startup",
            )?;
            ensure!(
                exact.tip_number == db_tip_number && exact.tip_hash == db_tip_hash,
                "exact genesis stopped-storage identity changed during read-only classification"
            );
            return Ok(ReadOnlyClassification::Normal);
        }
        return Err(eyre!(
            "message journal is missing at non-genesis DB tip {db_tip_number}; automatic recovery cannot manufacture a trusted anchor"
        ));
    }
    let journal = inspect_message_journal(&config.datadir, config.genesis_block)?;
    ensure!(
        !journal.has_incomplete_tail || db_tip_number > journal.watermark.block_number,
        "incomplete journal tail at non-DB-ahead startup is not automatically repairable"
    );

    match db_tip_number.cmp(&journal.watermark.block_number) {
        std::cmp::Ordering::Less => {
            return Err(eyre!(
                "journal is ahead of the durable DB (journal block {}, DB block {db_tip_number}); refusing automatic recovery",
                journal.watermark.block_number
            ));
        }
        std::cmp::Ordering::Equal => {
            ensure!(
                db_tip_hash == journal.watermark.block_hash,
                "equal-height DB/journal hash mismatch at block {db_tip_number}"
            );
            ensure!(
                !journal.has_incomplete_tail,
                "incomplete journal tail requires quarantine"
            );
            let exact = inspect_exact_storage_shape_with(
                &tx,
                &static_files,
                &config.datadir,
                receipts_fully_pruned(config.prune_config.as_ref()),
                senders_fully_pruned(config.prune_config.as_ref()),
                config.genesis_block,
            )
            .wrap_err("non-DB-ahead cross-store mismatch; refusing normal mutating Reth startup")?;
            ensure!(
                exact.tip_number == db_tip_number && exact.tip_hash == db_tip_hash,
                "exact stopped-storage identity changed during read-only classification"
            );
            return Ok(ReadOnlyClassification::Normal);
        }
        std::cmp::Ordering::Greater => {}
    }

    ensure!(
        !config.no_fsync,
        "automatic recovery is forbidden with --no-fsync; restart with fsync enabled"
    );
    let suffix = db_tip_number - journal.watermark.block_number;
    let horizon = active_unwind_horizon(config);
    ensure!(
        suffix > 0 && suffix <= horizon,
        "DB-ahead suffix is {suffix} blocks, outside active unwind horizon {horizon}; snapshot re-import is required"
    );

    let target_header = retained_header(&tx, &static_files, journal.watermark.block_number)?
        .ok_or_else(|| eyre!("journal recovery target header is missing"))?;
    ensure!(
        target_header.hash() == journal.watermark.block_hash,
        "journal recovery target hash does not match retained DB header"
    );
    ensure!(
        old_tip_header.hash() == db_tip_hash,
        "old DB tip hash/header mismatch"
    );

    let target = match journal.entry(journal.watermark.sequence) {
        Some(entry) => RecoveryTarget::Message {
            sequence: journal.watermark.sequence,
            block_number: journal.watermark.block_number,
            block_hash: journal.watermark.block_hash,
            state_root: target_header.state_root,
            entry,
        },
        None => {
            ensure!(
                journal.watermark == journal.anchor,
                "journal target entry is missing"
            );
            RecoveryTarget::Anchor {
                sequence: journal.anchor.sequence,
                block_number: journal.anchor.block_number,
                block_hash: journal.anchor.block_hash,
                state_root: target_header.state_root,
            }
        }
    };

    let account_prune = observed_prune_checkpoint(
        tx.get::<tables::PruneCheckpoints>(PruneSegment::AccountHistory)?,
    );
    let storage_prune = observed_prune_checkpoint(
        tx.get::<tables::PruneCheckpoints>(PruneSegment::StorageHistory)?,
    );
    let account_ranges = observed_static_ranges(
        &static_files_path,
        &static_files,
        StaticFileSegment::AccountChangeSets,
    )?;
    let storage_ranges = observed_static_ranges(
        &static_files_path,
        &static_files,
        StaticFileSegment::StorageChangeSets,
    )?;
    let snapshot_layout = classify_snapshot_layout(
        &static_files_path,
        config.genesis_block,
        config.snapshot_seeded,
    )?;
    let resume_checkpoint = inspect_resume_log_strict(&config.datadir)?
        .and_then(|log| log.resume_for(journal.watermark.block_number))
        .map(FrozenResumeCheckpoint::Checkpoint)
        .unwrap_or(FrozenResumeCheckpoint::None);
    tx.commit()?;

    Ok(ReadOnlyClassification::Candidate(RecoveryCandidate {
        journal_anchor: journal.anchor,
        target,
        old_db_tip_number: db_tip_number,
        old_db_tip_hash: db_tip_hash,
        old_db_tip_state_root: old_tip_header.state_root,
        resume_checkpoint,
        active_unwind_horizon: horizon,
        account_history_prune_checkpoint: account_prune,
        storage_history_prune_checkpoint: storage_prune,
        account_changeset_ranges: account_ranges,
        storage_changeset_ranges: storage_ranges,
        snapshot_layout,
    }))
}

fn validate_empty_mdbx<TX>(tx: &TX) -> eyre::Result<()>
where
    TX: reth_db_api::transaction::DbTx,
{
    for stage in StageId::ALL {
        ensure!(
            tx.get::<tables::StageCheckpoints>(stage.to_string())?
                .is_none(),
            "stopped MDBX has {stage} progress without an execution/canonical tip"
        );
    }
    ensure!(
        tx.cursor_read::<tables::CanonicalHeaders>()?
            .first()?
            .is_none()
            && tx
                .cursor_read::<tables::Headers<Header>>()?
                .first()?
                .is_none()
            && tx
                .cursor_read::<tables::BlockBodyIndices>()?
                .first()?
                .is_none(),
        "stopped MDBX has block data without an execution/canonical tip"
    );
    for table in Tables::ALL {
        if matches!(table, Tables::VersionHistory | Tables::Metadata) {
            continue;
        }
        let entries =
            reth_db_api::tables_to_generic!(*table, |GenericTable| tx.entries::<GenericTable>())?;
        ensure!(
            entries == 0,
            "stopped MDBX table {table} has {entries} orphan rows without a durable tip"
        );
    }
    let mut metadata = tx.cursor_read::<tables::Metadata>()?;
    while let Some((key, value)) = metadata.next()? {
        ensure!(
            key == "storage_settings"
                && serde_json::from_slice::<StorageSettings>(&value).ok()
                    == Some(StorageSettings::v2()),
            "stopped MDBX contains unrecognized no-tip metadata {key}"
        );
    }
    Ok(())
}

fn validate_fresh_sidecars(datadir: &Path) -> eyre::Result<()> {
    ensure!(
        !message_journal_path(datadir).exists(),
        "message journal exists without a durable MDBX tip"
    );
    ensure!(
        inspect_resume_log_strict(datadir)?.is_none(),
        "L1 resume log exists without a durable MDBX tip"
    );
    for name in ["static_files", "rocksdb"] {
        let path = datadir.join(name);
        if path.exists() {
            ensure!(
                path.is_dir(),
                "stopped storage path is not a directory: {}",
                path.display()
            );
            ensure!(
                std::fs::read_dir(&path)?.next().is_none(),
                "{name} contains artifacts without a durable MDBX tip"
            );
        }
    }
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

fn open_rocks_read_only(path: &Path) -> eyre::Result<RocksDBProvider> {
    ensure!(
        path.is_dir(),
        "RocksDB directory is missing at {}",
        path.display()
    );
    ensure!(
        path.join("CURRENT").is_file(),
        "RocksDB CURRENT metadata is missing"
    );
    let current = std::fs::read_to_string(path.join("CURRENT"))?;
    let manifest = current.trim();
    ensure!(
        !manifest.is_empty() && !manifest.contains('/') && path.join(manifest).is_file(),
        "RocksDB CURRENT references an invalid or missing manifest"
    );
    RocksDBProvider::builder(path)
        .with_default_tables()
        .with_read_only(true)
        .build()
        .map_err(|error| eyre!("open RocksDB read-only during recovery classification: {error}"))
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
            // Pinned Full deletion records transaction bounds only from the jars present in that
            // pass. `None` is therefore valid after an earlier non-Full pass removed every
            // transaction-bearing jar and Full later removed an all-empty retained suffix.
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
            // Non-Full storage-v2 pruning derives this field from whole jars deleted in the
            // current pass. `None` is valid only when that complete fixed jar had no transactions;
            // older, transaction-bearing jars may already have been deleted by an earlier pass.
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
        // Match pinned NippyJarChecker::check_consistency without opening a writer: the config is
        // the commit boundary, so physical data or offset tails must exactly match it before
        // normal Reth startup can heal them or finalization can remove the recovery marker.
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

fn validate_recovery_cli(config: &RecoveryConfig) -> eyre::Result<()> {
    ensure!(
        !config.no_fsync,
        "recovery marker is quarantined; restart with fsync enabled"
    );
    ensure!(
        !config.no_l1_derive,
        "recovery requires L1 derivation; remove --no-l1-derive"
    );
    ensure!(config.l1_rpc.is_some(), "recovery requires --l1-rpc");
    ensure!(config.l1_beacon.is_some(), "recovery requires --l1-beacon");
    ensure!(
        config.l1_start_block.is_none(),
        "--l1-start-block is forbidden during recovery"
    );
    ensure!(
        config.l1_start_delayed.is_none(),
        "--l1-start-delayed is forbidden during recovery"
    );
    ensure!(
        config.l1_end_block.is_none(),
        "--l1-end-block is forbidden during recovery"
    );
    Ok(())
}

fn active_unwind_horizon(config: &RecoveryConfig) -> u64 {
    config
        .prune_config
        .as_ref()
        .map(|config| config.minimum_pruning_distance)
        .unwrap_or(MINIMUM_UNWIND_SAFE_DISTANCE)
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

fn current_storage_tip_read_only(config: &RecoveryConfig) -> eyre::Result<u64> {
    let db = open_db_read_only(
        config.datadir.join("db"),
        DatabaseArguments::new(ClientVersion::default()),
    )?;
    let tx = db.tx()?;
    let canonical = tx
        .cursor_read::<tables::CanonicalHeaders>()?
        .last()?
        .map(|(number, _)| number);
    let execution = tx
        .get::<tables::StageCheckpoints>(StageId::Execution.to_string())?
        .map(|checkpoint| checkpoint.block_number);
    canonical
        .into_iter()
        .chain(execution)
        .max()
        .ok_or_else(|| eyre!("recovery marker exists but stopped storage has no durable tip"))
}

fn normalized_snapshot_ranges(
    ranges: &[ObservedStaticRange],
    genesis: u64,
) -> Vec<ObservedStaticRange> {
    let normalized_start = genesis.saturating_add(1);
    ranges
        .iter()
        .filter_map(|range| {
            let start = if range.start == genesis {
                normalized_start
            } else {
                range.start
            };
            (start <= range.end).then_some(ObservedStaticRange {
                start,
                end: range.end,
            })
        })
        .collect()
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
    config: &RecoveryConfig,
) -> eyre::Result<()> {
    let current_tip = current_storage_tip_read_only(config)?;
    validate_frozen_static_evidence_at_tip(
        marker,
        &config.datadir,
        config.genesis_block,
        config.snapshot_seeded,
        current_tip,
    )
}

fn validate_frozen_static_evidence_at_tip(
    marker: &RecoveryMarker,
    datadir: &Path,
    genesis_block: u64,
    configured_snapshot_seeded: bool,
    current_tip: u64,
) -> eyre::Result<()> {
    let snapshot_seeded = marker.snapshot_layout != SnapshotLayout::NonSnapshot;
    ensure!(
        configured_snapshot_seeded == snapshot_seeded,
        "recovery marker snapshot mode conflicts with current launch configuration"
    );
    let actual_layout = if snapshot_seeded {
        classify_snapshot_layout(&datadir.join("static_files"), genesis_block, true)?
    } else {
        SnapshotLayout::NonSnapshot
    };
    ensure!(
        actual_layout == marker.snapshot_layout
            || (marker.snapshot_layout == SnapshotLayout::SnapshotLegacy
                && actual_layout == SnapshotLayout::SnapshotAligned),
        "snapshot layout no longer matches frozen recovery evidence or its normalized successor"
    );

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
        let normalized;
        let expected = if marker.snapshot_layout == SnapshotLayout::SnapshotLegacy
            && actual_layout == SnapshotLayout::SnapshotAligned
        {
            normalized = normalized_snapshot_ranges(frozen, genesis_block);
            &normalized
        } else {
            frozen
        };
        let comparison_tip = current_tip.min(marker.old_db_tip_number);
        ensure!(
            ranges_through(&actual, comparison_tip) == ranges_through(expected, comparison_tip),
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

fn validate_marker_config(marker: &RecoveryMarker, config: &RecoveryConfig) -> eyre::Result<()> {
    ensure!(
        marker.version == RECOVERY_VERSION,
        "unsupported recovery marker version {}",
        marker.version
    );
    ensure!(
        marker.l2_chain_id == config.chain_id
            && marker.l2_genesis_block_number == config.genesis_block
            && marker.l2_genesis_hash == config.chain_spec.genesis_hash(),
        "recovery marker L2 chain/genesis identity conflicts with current configuration"
    );
    ensure!(
        marker.sequencer_inbox == config.sequencer_inbox
            && marker.bridge == config.bridge
            && marker.deployment_block == config.deployed_at,
        "recovery marker rollup deployment conflicts with current configuration"
    );
    ensure!(
        marker.parent_chain_is_arbitrum == config.parent_chain_claim.classification,
        "recovery marker parent-chain classification conflicts with chaininfo"
    );
    if let Some(expected) = config.parent_chain_claim.chain_id {
        ensure!(
            marker.parent_execution_chain_id == expected,
            "recovery marker parent chain id conflicts with chaininfo"
        );
    }
    ensure!(
        marker.active_unwind_horizon == active_unwind_horizon(config),
        "active unwind horizon changed from frozen value {} to {}",
        marker.active_unwind_horizon,
        active_unwind_horizon(config)
    );
    validate_frozen_static_evidence(marker, config)?;
    let inspection = inspect_message_journal(&config.datadir, config.genesis_block)?;
    ensure!(
        inspection.anchor == marker.journal_anchor,
        "recovery marker journal anchor changed"
    );
    let target = marker.target;
    ensure!(
        inspection.identity(target.sequence())
            == Some(MessageJournalAnchor {
                sequence: target.sequence(),
                block_number: target.block_number(),
                block_hash: target.block_hash(),
            }),
        "recovery marker target is not the frozen retained journal identity"
    );
    if let RecoveryTarget::Message { entry, .. } = target {
        ensure!(
            inspection.entry(entry.sequence) == Some(entry),
            "recovery target message changed"
        );
    }
    Ok(())
}

async fn observe_parent(l1_rpc: &str) -> eyre::Result<ParentIdentity> {
    let url = l1_rpc
        .parse()
        .map_err(|_| eyre!("invalid --l1-rpc URL during recovery"))?;
    let provider = ProviderBuilder::new().connect_http(url);
    let chain_id = provider.get_chain_id().await.map_err(|_| {
        eyre!("parent execution endpoint unavailable while recovery is quarantined")
    })?;
    let genesis = provider
        .get_block_by_number(alloy_eips::BlockNumberOrTag::Number(0))
        .await
        .map_err(|_| eyre!("parent execution endpoint unavailable while reading genesis"))?
        .ok_or_else(|| eyre!("parent execution endpoint returned no genesis block"))?;
    Ok(ParentIdentity {
        chain_id,
        genesis_hash: genesis.header.hash,
    })
}

async fn observe_parent_with_retry(l1_rpc: &str) -> eyre::Result<ParentIdentity> {
    let parsed = l1_rpc
        .parse::<url::Url>()
        .map_err(|_| eyre!("invalid --l1-rpc URL during recovery"))?;
    ensure!(
        matches!(parsed.scheme(), "http" | "https"),
        "recovery parent execution endpoint must use http or https"
    );
    let mut delay = Duration::from_secs(1);
    loop {
        match observe_parent(l1_rpc).await {
            Ok(identity) => return Ok(identity),
            Err(error) => {
                reth_tracing::tracing::warn!(
                    target: "arb-reth::recovery",
                    %error,
                    retry_seconds = delay.as_secs(),
                    "parent execution endpoint unavailable; recovery remains quarantined",
                );
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(30));
            }
        }
    }
}

fn validate_parent(marker: &RecoveryMarker, parent: ParentIdentity) -> eyre::Result<()> {
    ensure!(
        marker.parent_execution_chain_id == parent.chain_id
            && marker.parent_execution_genesis_hash == parent.genesis_hash,
        "parent execution endpoint identity does not match the frozen recovery marker; recovery remains quarantined"
    );
    Ok(())
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

fn inspect_rocks_bounds(path: &Path) -> eyre::Result<()> {
    let provider = open_rocks_read_only(path)?;
    // Decode both extrema of every storage-v2 RocksDB table. The values are observations only;
    // supported consistency healing remains exclusively post-marker.
    let _transaction_hash_bounds = (
        provider.first::<tables::TransactionHashNumbers>()?,
        provider.last::<tables::TransactionHashNumbers>()?,
    );
    let _account_history_bounds = (
        provider.first::<tables::AccountsHistory>()?,
        provider.last::<tables::AccountsHistory>()?,
    );
    let _storage_history_bounds = (
        provider.first::<tables::StoragesHistory>()?,
        provider.last::<tables::StoragesHistory>()?,
    );
    Ok(())
}

fn classify_snapshot_layout(
    static_files: &Path,
    genesis: u64,
    snapshot_seeded: bool,
) -> eyre::Result<SnapshotLayout> {
    if !snapshot_seeded {
        return Ok(SnapshotLayout::NonSnapshot);
    }
    let mut legacy = false;
    for segment in ["account-change-sets", "storage-change-sets"] {
        for entry in std::fs::read_dir(static_files)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with(&format!("static_file_{segment}_")) || !name.ends_with(".conf") {
                continue;
            }
            let conf = std::fs::read(entry.path())?;
            ensure!(
                conf.len() >= 41,
                "changeset static-file config is truncated"
            );
            let read = |offset: usize| {
                u64::from_le_bytes(conf[offset..offset + 8].try_into().expect("checked config"))
            };
            ensure!(
                read(0) == 1 && conf[24] == 1,
                "unrecognized snapshot changeset header"
            );
            let expected_start = read(8);
            let block_start = read(25);
            if expected_start != block_start {
                ensure!(
                    block_start == genesis,
                    "unrecognized partial snapshot layout"
                );
                legacy = true;
            }
        }
    }
    Ok(if legacy {
        SnapshotLayout::SnapshotLegacy
    } else {
        SnapshotLayout::SnapshotAligned
    })
}

fn recovery_marker_path(datadir: &Path) -> PathBuf {
    datadir.join(RECOVERY_MARKER_FILE)
}

fn read_marker(datadir: &Path) -> eyre::Result<RecoveryMarker> {
    let path = recovery_marker_path(datadir);
    let marker: RecoveryMarker = serde_json::from_slice(&std::fs::read(&path)?)
        .wrap_err_with(|| format!("torn or malformed recovery marker {}", path.display()))?;
    ensure!(
        marker.version == RECOVERY_VERSION,
        "unsupported recovery marker version {}",
        marker.version
    );
    validate_marker_invariants(&marker)?;
    Ok(marker)
}

fn validate_marker_invariants(marker: &RecoveryMarker) -> eyre::Result<()> {
    let target = marker.target;
    ensure!(
        marker
            .l2_genesis_block_number
            .checked_add(marker.journal_anchor.sequence)
            == Some(marker.journal_anchor.block_number),
        "recovery marker journal anchor has incoherent L2 sequence mapping"
    );
    ensure!(
        marker
            .l2_genesis_block_number
            .checked_add(target.sequence())
            == Some(target.block_number()),
        "recovery marker target has incoherent L2 sequence mapping"
    );
    ensure!(
        target.sequence() >= marker.journal_anchor.sequence
            && target.block_number() >= marker.journal_anchor.block_number,
        "recovery marker target precedes its journal anchor"
    );
    if let RecoveryTarget::Message {
        sequence,
        block_number,
        block_hash,
        entry,
        ..
    } = target
    {
        ensure!(
            entry.sequence == sequence
                && entry.block_number == block_number
                && entry.block_hash == block_hash,
            "recovery marker target message contradicts its exact identity"
        );
    }
    let suffix = marker
        .old_db_tip_number
        .checked_sub(target.block_number())
        .ok_or_else(|| eyre!("recovery marker old DB tip is below its target"))?;
    ensure!(
        suffix > 0 && suffix <= marker.active_unwind_horizon,
        "recovery marker suffix {suffix} is outside frozen unwind horizon {}",
        marker.active_unwind_horizon
    );
    if let Some(checkpoint) = marker.resume_checkpoint.checkpoint() {
        ensure!(
            checkpoint.l2_block <= target.block_number(),
            "recovery marker resume checkpoint is above its target"
        );
    }
    for ranges in [
        &marker.account_changeset_ranges,
        &marker.storage_changeset_ranges,
    ] {
        ensure!(
            ranges.iter().all(|range| range.start <= range.end)
                && ranges.windows(2).all(|pair| pair[0].end < pair[1].start),
            "recovery marker contains invalid or overlapping static-file ranges"
        );
    }
    Ok(())
}

fn write_marker(datadir: &Path, marker: &RecoveryMarker) -> eyre::Result<()> {
    let path = recovery_marker_path(datadir);
    let temp = path.with_extension("json.tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temp)?;
    serde_json::to_writer_pretty(&mut file, marker)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    std::fs::rename(&temp, &path)?;
    sync_parent(&path)?;
    Ok(())
}

fn update_phase(
    datadir: &Path,
    marker: &mut RecoveryMarker,
    phase: RecoveryPhase,
) -> eyre::Result<()> {
    if phase_rank(phase) > phase_rank(marker.phase) {
        marker.phase = phase;
        write_marker(datadir, marker)?;
    }
    let boundary = match phase {
        RecoveryPhase::Classified => "phase_classified_revalidated",
        RecoveryPhase::LayoutNormalized => "phase_layout_normalized_revalidated",
        RecoveryPhase::ConsistencyHealed => "phase_consistency_healed_revalidated",
        RecoveryPhase::HistoryValidated => "phase_history_validated_revalidated",
        RecoveryPhase::DbUnwound => "phase_db_unwound_revalidated",
        RecoveryPhase::JournalRewritten => "phase_journal_rewritten_revalidated",
        RecoveryPhase::ResumeRewritten => "phase_resume_rewritten_revalidated",
        RecoveryPhase::OfflineValidated => "phase_offline_validated_revalidated",
        RecoveryPhase::Rederiving => "phase_rederiving_revalidated",
        RecoveryPhase::Finalizing => "phase_finalizing_revalidated",
    };
    recovery_failpoint(boundary);
    Ok(())
}

fn complete_offline_repair(
    config: &RecoveryConfig,
    marker: &mut RecoveryMarker,
) -> eyre::Result<()> {
    let starting_phase = marker.phase;
    let resume_before = inspect_resume_log_strict(&config.datadir)?;
    let selected_before = resume_before
        .as_ref()
        .and_then(|log| log.resume_for(marker.target.block_number()));
    if phase_rank(starting_phase) < phase_rank(RecoveryPhase::Rederiving) {
        ensure!(
            selected_before == marker.resume_checkpoint.checkpoint(),
            "resume artifact no longer selects the marker-frozen checkpoint at the recovery target"
        );
    }
    normalize_snapshot_layout(config, marker)?;
    validate_frozen_static_evidence(marker, config)?;
    update_phase(&config.datadir, marker, RecoveryPhase::LayoutNormalized)?;

    let factory = open_recovery_factory(config)?;
    let (rocksdb_unwind, static_unwind) = factory
        .check_consistency()
        .map_err(|error| eyre!("post-marker storage consistency healing failed: {error}"))?;
    recovery_failpoint("consistency_heal_completed");
    ensure!(
        rocksdb_unwind.is_none() && static_unwind.is_none(),
        "storage consistency requires a deeper pipeline unwind ({rocksdb_unwind:?}, {static_unwind:?}); recovery marker retained, snapshot re-import required"
    );
    drop(factory);
    validate_frozen_static_evidence(marker, config)?;
    update_phase(&config.datadir, marker, RecoveryPhase::ConsistencyHealed)?;

    let factory = open_recovery_factory(config)?;
    let target = marker.target;
    let current_tip = factory.provider()?.last_block_number()?;
    ensure!(
        current_tip >= target.block_number(),
        "durable DB tip {current_tip} is below frozen recovery target {}; snapshot re-import required",
        target.block_number()
    );
    if phase_rank(starting_phase) >= phase_rank(RecoveryPhase::ResumeRewritten) {
        ensure!(
            resume_before.as_ref().is_none_or(|log| log
                .checkpoints
                .iter()
                .all(|checkpoint| checkpoint.l2_block <= current_tip)),
            "recovery resume log is above the current durable DB tip"
        );
    }
    validate_target_header(&factory, target)?;
    validate_prune_observations(&factory, marker)?;

    // The phase records a completed durable boundary, but storage is revalidated independently.
    // A crash after the aggregate commit can leave `history_validated` with storage already at the
    // target; a crash during replay can leave a fresh partial suffix that must be discarded.
    if current_tip == marker.old_db_tip_number {
        validate_old_tip_header(&factory, marker)?;
        validate_changeset_coverage(&factory, target.block_number(), current_tip)?;
    } else if current_tip == target.block_number() {
        ensure!(
            phase_rank(starting_phase) >= phase_rank(RecoveryPhase::HistoryValidated),
            "storage reached the recovery target before durable history validation; snapshot re-import required"
        );
    } else {
        ensure!(
            phase_rank(starting_phase) >= phase_rank(RecoveryPhase::Rederiving),
            "durable DB tip {current_tip} contradicts recovery phase {starting_phase:?}; snapshot re-import required"
        );
        validate_changeset_coverage(&factory, target.block_number(), current_tip)?;
    }
    update_phase(&config.datadir, marker, RecoveryPhase::HistoryValidated)?;
    recovery_failpoint("history_validated_before_unwind");

    if current_tip > target.block_number() {
        commit_storage_v2_unwind(&factory, target.block_number())?;
        recovery_failpoint("aggregate_unwind_committed");
    }
    update_phase(&config.datadir, marker, RecoveryPhase::DbUnwound)?;

    let rewritten = rewrite_journal_to_identity_at(
        &config.datadir,
        config.genesis_block,
        target.block_number(),
        target.block_hash(),
    )?;
    ensure!(
        rewritten.watermark.sequence == target.sequence()
            && rewritten.watermark.block_number == target.block_number()
            && rewritten.watermark.block_hash == target.block_hash()
            && !rewritten.has_incomplete_tail,
        "recovery journal rewrite did not land on the exact frozen target"
    );
    recovery_failpoint("journal_rewritten_before_resume");
    update_phase(&config.datadir, marker, RecoveryPhase::JournalRewritten)?;

    rewrite_resume_checkpoint_at(&config.datadir, marker.resume_checkpoint.checkpoint())?;
    recovery_failpoint("resume_rewritten_before_offline_validation");
    update_phase(&config.datadir, marker, RecoveryPhase::ResumeRewritten)?;

    drop(factory);
    validate_reopened_offline(config, marker)?;
    update_phase(&config.datadir, marker, RecoveryPhase::OfflineValidated)?;
    recovery_failpoint("offline_validated_before_rederivation");
    update_phase(&config.datadir, marker, RecoveryPhase::Rederiving)?;
    Ok(())
}

fn open_recovery_factory(
    config: &RecoveryConfig,
) -> eyre::Result<ProviderFactory<ArbNodeTypesWithDB>> {
    let db = init_db(
        config.datadir.join("db"),
        DatabaseArguments::new(ClientVersion::default()),
    )?;
    let static_files = StaticFileProvider::read_write(config.datadir.join("static_files"))?;
    let rocksdb = RocksDBProvider::builder(config.datadir.join("rocksdb"))
        .with_default_tables()
        .build()
        .map_err(|error| eyre!("RocksDB open error during recovery: {error}"))?;
    let factory: ProviderFactory<ArbNodeTypesWithDB> = ProviderFactory::new(
        db,
        config.chain_spec.clone(),
        static_files,
        rocksdb,
        Runtime::test(),
    )?
    .with_prune_modes(
        config
            .prune_config
            .as_ref()
            .map(|config| config.segments.clone())
            .unwrap_or_default(),
    );
    factory.set_storage_settings_cache(StorageSettings::v2());
    Ok(factory)
}

fn validate_target_header(
    factory: &ProviderFactory<ArbNodeTypesWithDB>,
    target: RecoveryTarget,
) -> eyre::Result<()> {
    let header = factory
        .provider()?
        .sealed_header(target.block_number())?
        .ok_or_else(|| eyre!("frozen recovery target header is missing"))?;
    ensure!(
        header.hash() == target.block_hash() && header.state_root == target.state_root(),
        "frozen recovery target hash/state root no longer matches storage"
    );
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
    let first = marker.target.block_number().saturating_add(1);
    for (name, checkpoint) in [("account", account), ("storage", storage)] {
        validate_prune_bound(
            name,
            checkpoint.and_then(|checkpoint| checkpoint.block_number),
            first,
        )?;
    }
    Ok(())
}

fn validate_prune_bound(name: &str, pruned_through: Option<u64>, first: u64) -> eyre::Result<()> {
    ensure!(
        !pruned_through.is_some_and(|block| block >= first),
        "{name} history is pruned through the requested unwind range at block {first}; snapshot re-import required"
    );
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
            "{name} changeset offset metadata is missing at block {block}; snapshot re-import required"
        );
    }
    Ok(())
}

pub(crate) fn validate_changeset_coverage(
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
                        "{name} changeset static-file gap at block {block}: {error}; snapshot re-import required"
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

fn validate_reopened_offline(config: &RecoveryConfig, marker: &RecoveryMarker) -> eyre::Result<()> {
    let factory = open_recovery_factory(config)?;
    let (rocksdb_unwind, static_unwind) = factory.check_consistency()?;
    ensure!(
        rocksdb_unwind.is_none() && static_unwind.is_none(),
        "reopened storage is inconsistent after offline repair"
    );
    let target = marker.target;
    ensure!(
        factory.provider()?.last_block_number()? == target.block_number(),
        "reopened durable DB tip is not the exact recovery target"
    );
    validate_target_header(&factory, target)?;
    let journal = inspect_message_journal(&config.datadir, config.genesis_block)?;
    ensure!(
        journal.anchor == marker.journal_anchor
            && journal.watermark.sequence == target.sequence()
            && journal.watermark.block_number == target.block_number()
            && journal.watermark.block_hash == target.block_hash()
            && !journal.has_incomplete_tail,
        "reopened journal is not the exact frozen recovery target"
    );
    if let RecoveryTarget::Message { entry, .. } = target {
        ensure!(
            journal.entry(entry.sequence) == Some(entry),
            "reopened target message changed"
        );
    }
    let expected_resume = marker.resume_checkpoint.checkpoint();
    let actual_resume = inspect_resume_log_strict(&config.datadir)?;
    let resume_matches = match (expected_resume, actual_resume) {
        (None, None) => true,
        (Some(expected), Some(log)) => log.checkpoints == [expected],
        _ => false,
    };
    ensure!(
        resume_matches,
        "reopened resume log changed frozen selection"
    );
    validate_prune_observations(&factory, marker)?;
    Ok(())
}

const fn phase_rank(phase: RecoveryPhase) -> u8 {
    match phase {
        RecoveryPhase::Classified => 0,
        RecoveryPhase::LayoutNormalized => 1,
        RecoveryPhase::ConsistencyHealed => 2,
        RecoveryPhase::HistoryValidated => 3,
        RecoveryPhase::DbUnwound => 4,
        RecoveryPhase::JournalRewritten => 5,
        RecoveryPhase::ResumeRewritten => 6,
        RecoveryPhase::OfflineValidated => 7,
        RecoveryPhase::Rederiving => 8,
        RecoveryPhase::Finalizing => 9,
    }
}

fn normalize_snapshot_layout(config: &RecoveryConfig, marker: &RecoveryMarker) -> eyre::Result<()> {
    if marker.snapshot_layout != SnapshotLayout::SnapshotLegacy {
        return Ok(());
    }
    let static_files = config.datadir.join("static_files");
    normalize_snapshot_changeset_layout(&static_files, config.genesis_block)?;
    ensure!(
        classify_snapshot_layout(&static_files, config.genesis_block, true)?
            == SnapshotLayout::SnapshotAligned,
        "snapshot changeset layout did not normalize completely"
    );
    Ok(())
}

/// Crash-safe normalization shared by automatic recovery and explicit manual rewind.
pub(crate) fn normalize_snapshot_changeset_layout(
    static_files: &Path,
    genesis: u64,
) -> eyre::Result<()> {
    let target_start = genesis
        .checked_add(1)
        .ok_or_else(|| eyre!("snapshot genesis block overflows normalization target"))?;
    for segment in ["account-change-sets", "storage-change-sets"] {
        normalize_snapshot_segment(static_files, segment, genesis, target_start)?;
    }
    Ok(())
}

/// The sole storage-v2 suffix-removal primitive used by automatic and manual recovery.
pub(crate) fn commit_storage_v2_unwind(
    factory: &ProviderFactory<ArbNodeTypesWithDB>,
    target: u64,
) -> eyre::Result<()> {
    let provider = factory.database_provider_rw()?;
    provider.remove_block_and_execution_above(target)?;
    provider
        .commit()
        .map_err(|error| eyre!("commit storage-v2 unwind: {error}"))
}

fn normalize_snapshot_segment(
    static_files: &Path,
    segment: &str,
    genesis: u64,
    target_start: u64,
) -> eyre::Result<()> {
    let prefix = format!("static_file_{segment}_");
    let mut bases = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(static_files)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if !name.starts_with(&prefix) {
            continue;
        }
        let base = [".csoff", ".conf", ".off"]
            .into_iter()
            .find_map(|extension| name.strip_suffix(extension))
            .unwrap_or(&name);
        bases.insert(base.to_string());
    }
    ensure!(
        !bases.is_empty(),
        "legacy snapshot {segment} files are missing"
    );

    let mut config_bytes = None;
    for base in &bases {
        let path = static_files.join(format!("{base}.conf"));
        if path.exists() {
            let bytes = std::fs::read(&path)?;
            ensure!(
                bytes.len() >= 41,
                "legacy snapshot {segment} config is truncated"
            );
            if let Some(existing) = &config_bytes {
                ensure!(
                    existing == &bytes,
                    "contradictory partial {segment} config files"
                );
            } else {
                config_bytes = Some(bytes);
            }
        }
    }
    let mut bytes =
        config_bytes.ok_or_else(|| eyre!("legacy snapshot {segment} config is missing"))?;
    let read = |bytes: &[u8], offset: usize| {
        u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .expect("checked config"),
        )
    };
    ensure!(
        read(&bytes, 0) == 1 && bytes[24] == 1,
        "unrecognized legacy {segment} header"
    );
    let expected_start = read(&bytes, 8);
    let block_start = read(&bytes, 25);
    if block_start == genesis && expected_start == genesis {
        return Ok(());
    }
    ensure!(
        (block_start == genesis && expected_start != block_start)
            || (block_start == target_start && expected_start == target_start),
        "unrecognized interrupted legacy {segment} normalization"
    );
    let expected_end = read(&bytes, 16);
    let target_base = format!("static_file_{segment}_{target_start}_{expected_end}");

    for extension in ["", ".conf", ".off", ".csoff"] {
        let destination = static_files.join(format!("{target_base}{extension}"));
        for base in &bases {
            let source = static_files.join(format!("{base}{extension}"));
            if !source.exists() || source == destination {
                continue;
            }
            if destination.exists() {
                ensure!(
                    std::fs::read(&source)? == std::fs::read(&destination)?,
                    "contradictory old/new {segment}{extension} files"
                );
                std::fs::remove_file(&source)?;
            } else {
                std::fs::rename(&source, &destination)?;
            }
            sync_parent(&destination)?;
            recovery_failpoint(&format!("snapshot_{segment}_{extension}_renamed"));
        }
    }

    bytes[8..16].copy_from_slice(&target_start.to_le_bytes());
    bytes[25..33].copy_from_slice(&target_start.to_le_bytes());
    let config_path = static_files.join(format!("{target_base}.conf"));
    let temp = config_path.with_extension("conf.recovery.tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temp)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    std::fs::rename(&temp, &config_path)?;
    sync_parent(&config_path)?;
    recovery_failpoint(&format!("snapshot_{segment}_header_fsynced"));
    Ok(())
}

trait MarkerRemovalFilesystem {
    fn unlink(&mut self, path: &Path) -> eyre::Result<()>;
    fn sync_parent(&mut self, path: &Path) -> eyre::Result<()>;
}

struct ProductionMarkerRemovalFilesystem;

impl MarkerRemovalFilesystem for ProductionMarkerRemovalFilesystem {
    fn unlink(&mut self, path: &Path) -> eyre::Result<()> {
        std::fs::remove_file(path)?;
        Ok(())
    }

    fn sync_parent(&mut self, path: &Path) -> eyre::Result<()> {
        sync_parent(path)
    }
}

fn remove_marker_durable_with(
    datadir: &Path,
    filesystem: &mut impl MarkerRemovalFilesystem,
    after_unlink: impl FnOnce() -> eyre::Result<()>,
) -> eyre::Result<()> {
    let path = recovery_marker_path(datadir);
    filesystem.unlink(&path)?;
    after_unlink()?;
    filesystem.sync_parent(&path)?;
    recovery_failpoint("marker_parent_fsynced_before_ready");
    Ok(())
}

pub(crate) fn remove_marker_durable(datadir: &Path) -> eyre::Result<()> {
    remove_marker_durable_with(datadir, &mut ProductionMarkerRemovalFilesystem, || {
        recovery_failpoint("marker_unlinked_before_parent_fsync");
        Ok(())
    })
}

/// Reopen quiesced storage, prove the exact completion frontier, and durably remove quarantine
/// before gate publication. No live engine/provider handle is accepted at this boundary.
pub(crate) fn finalize_recovery(runtime: &RecoveryRuntime) -> eyre::Result<()> {
    let marker = &runtime.marker;
    let storage = &runtime.storage;
    let datadir = &storage.datadir;
    ensure!(
        read_marker(datadir)? == *marker,
        "durable recovery marker changed before reopened finalization proof"
    );
    ensure!(
        marker.l2_genesis_block_number == storage.genesis_block
            && marker.l2_genesis_hash == storage.chain_spec.genesis_hash(),
        "runtime chain identity changed from the durable recovery marker"
    );
    ensure!(
        marker.active_unwind_horizon
            == storage
                .prune_config
                .as_ref()
                .map(|config| config.minimum_pruning_distance)
                .unwrap_or(MINIMUM_UNWIND_SAFE_DISTANCE),
        "runtime unwind horizon changed from the durable recovery marker"
    );
    ensure!(
        storage.snapshot_seeded == (marker.snapshot_layout != SnapshotLayout::NonSnapshot),
        "runtime snapshot mode changed from the durable recovery marker"
    );
    run_reopened_validation_subprocess(storage)?;
    ensure!(
        read_marker(datadir)? == *marker,
        "durable recovery marker changed during reopened finalization proof"
    );
    recovery_failpoint("reopened_storage_validated_before_finalizing");

    let mut final_marker = marker.clone();
    update_phase(datadir, &mut final_marker, RecoveryPhase::Finalizing)?;
    remove_marker_durable(datadir)?;
    Ok(())
}

pub(crate) fn finalize_recovery_and_release(
    runtime: &RecoveryRuntime,
    gate: &RecoveryGate,
) -> eyre::Result<()> {
    finalize_recovery(runtime)?;
    gate.release();
    Ok(())
}

fn run_reopened_validation_subprocess(storage: &RecoveryStorageConfig) -> eyre::Result<()> {
    let mut command = std::process::Command::new(std::env::current_exe()?);
    #[cfg(test)]
    command
        .args([
            "--exact",
            "recovery::tests::process_fixture_helper",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ITE105_FIXTURE_ACTION", "final-validate")
        .env("ITE105_RECOVERY_DATADIR", &storage.datadir);
    #[cfg(not(test))]
    command.env(RECOVERY_VALIDATE_DATADIR_ENV, &storage.datadir);
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

/// Execute the read-only recovery proof in a fresh process before normal CLI initialization.
#[doc(hidden)]
pub fn run_recovery_validation_child_from_env() -> eyre::Result<bool> {
    let Some(datadir) = std::env::var_os(RECOVERY_VALIDATE_DATADIR_ENV) else {
        return Ok(false);
    };
    let receipts_fully_pruned = std::env::var_os(RECOVERY_VALIDATE_RECEIPTS_ENV).as_deref()
        == Some(std::ffi::OsStr::new("1"));
    let senders_fully_pruned = std::env::var_os(RECOVERY_VALIDATE_SENDERS_ENV).as_deref()
        == Some(std::ffi::OsStr::new("1"));
    validate_reopened_finalization(
        Path::new(&datadir),
        receipts_fully_pruned,
        senders_fully_pruned,
    )?;
    Ok(true)
}

fn validate_reopened_finalization(
    datadir: &Path,
    receipts_fully_pruned: bool,
    senders_fully_pruned: bool,
) -> eyre::Result<()> {
    let marker = read_marker(datadir)?;
    let genesis_block = marker.l2_genesis_block_number;
    let exact = inspect_exact_storage_shape(
        datadir,
        receipts_fully_pruned,
        senders_fully_pruned,
        genesis_block,
    )
    .wrap_err("reopened recovery storage is not exactly consistent")?;
    let current_tip = exact.tip_number;
    validate_frozen_static_evidence_at_tip(
        &marker,
        datadir,
        genesis_block,
        marker.snapshot_layout != SnapshotLayout::NonSnapshot,
        current_tip,
    )?;
    ensure!(
        current_tip >= marker.old_db_tip_number,
        "recovery completion barrier reached with DB tip {current_tip} below old frontier {}",
        marker.old_db_tip_number
    );
    let db = open_db_read_only(
        datadir.join("db"),
        DatabaseArguments::new(ClientVersion::default()),
    )?;
    let tx = db.tx()?;
    let static_files =
        StaticFileProvider::<ArbPrimitives>::read_only(datadir.join("static_files"))?;
    let old_header = retained_header(&tx, &static_files, marker.old_db_tip_number)?
        .ok_or_else(|| eyre!("old recovery frontier header is missing"))?;
    ensure!(
        old_header.hash() == marker.old_db_tip_hash
            && old_header.state_root == marker.old_db_tip_state_root,
        "rederived old frontier hash/state root differs from frozen DB evidence"
    );

    let journal = inspect_message_journal(datadir, genesis_block)?;
    ensure!(
        !journal.has_incomplete_tail,
        "recovery final journal has an incomplete tail"
    );
    ensure!(
        journal.watermark.block_number == current_tip
            && journal.watermark.block_hash == exact.tip_hash
            && exact.tip_state_root
                == retained_header(&tx, &static_files, current_tip)?
                    .ok_or_else(|| eyre!("current durable recovery frontier header is missing"))?
                    .state_root,
        "current durable DB tip and journal watermark are not exactly equal"
    );
    let old_sequence = marker
        .old_db_tip_number
        .checked_sub(genesis_block)
        .ok_or_else(|| eyre!("old recovery frontier is below L2 genesis"))?;
    let old_entry = journal
        .entry(old_sequence)
        .ok_or_else(|| eyre!("journal has no exact entry for the old recovery frontier"))?;
    ensure!(
        old_entry.block_number == marker.old_db_tip_number
            && old_entry.block_hash == marker.old_db_tip_hash,
        "journal old-frontier identity differs from frozen DB evidence"
    );
    let first_recovered = marker.target.sequence().saturating_add(1);
    for sequence in first_recovered..=journal.watermark.sequence {
        let entry = journal
            .entry(sequence)
            .ok_or_else(|| eyre!("recovered journal range has a gap at sequence {sequence}"))?;
        ensure!(
            entry.source == arb_reth_engine::ArbEngineInputSource::L1,
            "non-L1 authority {:?} appears in recovered range at sequence {sequence}",
            entry.source
        );
    }
    let resume = inspect_resume_log_strict(datadir)?;
    let expected_resume = marker.resume_checkpoint.checkpoint();
    ensure!(
        match (expected_resume, resume) {
            (None, None) => true,
            (Some(expected), Some(log)) => log.checkpoints == [expected],
            _ => false,
        },
        "resume log changed from the marker-frozen checkpoint before finalization"
    );
    Ok(())
}

fn sync_parent(path: &Path) -> eyre::Result<()> {
    let parent = path.parent().ok_or_else(|| eyre!("path has no parent"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

pub(crate) fn recovery_failpoint(name: &str) {
    if std::env::var_os(RECOVERY_FAILPOINT_ENV).as_deref() == Some(std::ffi::OsStr::new(name)) {
        unsafe extern "C" {
            fn _exit(status: i32) -> !;
        }
        // SAFETY: this production test failpoint intentionally simulates sudden process loss.
        unsafe { _exit(86) }
    }
}

pub(crate) fn is_recovery_worker() -> bool {
    std::env::var_os(RECOVERY_WORKER_ENV).as_deref() == Some(std::ffi::OsStr::new("1"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use alloy_primitives::{U256, address};
    use arb_revm::arbos_init::ArbosInitConfig;
    use arbitrum_alloy_sequencer::sequencer::feed::BroadcastFeedMessage;
    use reth_db_api::transaction::DbTxMut as _;
    use reth_node_builder::{LaunchNode, NodeBuilder, NodeConfig};
    use reth_provider::RocksDBProviderFactory as _;
    use reth_prune_types::PruneMode;
    use reth_stages_types::StageCheckpoint;
    use reth_storage_api::{PruneCheckpointWriter as _, StageCheckpointWriter as _};
    use reth_tasks::Runtime;

    use crate::{ArbEngineTuning, launcher::ArbLauncher};

    fn test_chain_spec() -> Arc<ChainSpec> {
        let init = ArbosInitConfig {
            initial_arbos_version: 40,
            initial_chain_owner: address!("5E1497dD1f08C87b2d8FE23e9AAB6c1De833D927"),
            chain_id: U256::from(412_346u64),
            genesis_block_number: 0,
            initial_l1_base_fee: U256::from(167u64),
            serialized_chain_config: include_bytes!(
                "../tests/fixtures/testnode_l2_chain_config.json"
            )
            .to_vec(),
            debug_precompiles: true,
        };
        Arc::new(crate::arb_chain_spec(&init).unwrap())
    }

    fn test_config(datadir: &Path) -> RecoveryConfig {
        RecoveryConfig {
            datadir: datadir.to_path_buf(),
            chain_spec: test_chain_spec(),
            chain_id: 412_346,
            genesis_block: 0,
            sequencer_inbox: Address::repeat_byte(0x11),
            bridge: Address::repeat_byte(0x22),
            deployed_at: 100,
            parent_chain_claim: ParentChainClaim {
                chain_id: Some(1),
                classification: ParentChainClassification::NonArbitrum,
            },
            snapshot_seeded: false,
            prune_config: None,
            no_fsync: false,
            no_l1_derive: false,
            l1_rpc: Some("http://127.0.0.1:1".into()),
            l1_beacon: Some("http://127.0.0.1:2".into()),
            l1_start_block: None,
            l1_start_delayed: None,
            l1_end_block: None,
        }
    }

    fn deposit_message(sequence: u64) -> BroadcastFeedMessage {
        let mut message: BroadcastFeedMessage =
            serde_json::from_str(include_str!("../tests/fixtures/deposit_message_only.json"))
                .unwrap();
        message.sequence_number = sequence;
        message
    }

    async fn run_test_node(
        datadir: &Path,
        sequences: impl IntoIterator<Item = u64>,
        gate: RecoveryGate,
        recovery: Option<RecoveryRuntime>,
    ) {
        let chain_spec = test_chain_spec();
        let db = Arc::new(
            init_db(
                datadir.join("db"),
                DatabaseArguments::new(ClientVersion::default()),
            )
            .unwrap(),
        );
        let maybe_path =
            reth_node_core::dirs::MaybePlatformPath::<reth_node_core::dirs::DataDirPath>::from(
                datadir.to_path_buf(),
            );
        let config = NodeConfig::test()
            .with_chain(chain_spec.clone())
            .with_datadir_args(reth_node_core::args::DatadirArgs {
                datadir: maybe_path.clone(),
                ..Default::default()
            });
        let data_dir =
            maybe_path.unwrap_or_chain_default(chain_spec.chain(), config.datadir.clone());
        let (feed_tx, feed_rx) = tokio::sync::mpsc::channel(1);
        let messages = sequences
            .into_iter()
            .map(deposit_message)
            .collect::<Vec<_>>();
        let (l1_tx, l1_rx) = tokio::sync::mpsc::channel(messages.len().max(1));
        for message in messages {
            l1_tx.send(message).await.unwrap();
        }
        drop((feed_tx, l1_tx));
        let handle = ArbLauncher {
            ctx: reth_node_builder::LaunchContext::new(Runtime::test(), data_dir),
            chain_id: 412_346,
            genesis_block: 0,
            tuning: ArbEngineTuning {
                persistence_threshold: 0,
                ..ArbEngineTuning::reth_defaults()
            },
            prune_config: None,
            init_message_journal_at_tip: false,
            l1_verified_tip: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            feed_messages: feed_rx,
            l1_messages: l1_rx,
            feed_latency: None,
            rpc_addr: None,
            tx_log_stream: None,
            recovery_gate: gate,
            recovery,
            driver_test_control: None,
        }
        .launch_node(NodeBuilder::new(config).with_database(db).node(ArbNode))
        .await
        .unwrap();
        handle.wait_for_node_exit().await.unwrap();
    }

    fn free_addr() -> std::net::SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        addr
    }

    async fn scrape_metrics(addr: std::net::SocketAddr) -> String {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8(response).unwrap()
    }

    fn recovery_metric(exposition: &str) -> Option<f64> {
        exposition.lines().find_map(|line| {
            line.strip_prefix("reth_arb_reth_recovery_ready ")
                .and_then(|value| value.parse().ok())
        })
    }

    async fn wait_recovery_metric(addr: std::net::SocketAddr, expected: f64) {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Ok(exposition) =
                    async { Ok::<_, std::io::Error>(scrape_metrics(addr).await) }.await
                    && recovery_metric(&exposition) == Some(expected)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    }

    async fn exercise_production_gate(datadir: &Path) {
        let chain_spec = test_chain_spec();
        let db = Arc::new(
            init_db(
                datadir.join("db"),
                DatabaseArguments::new(ClientVersion::default()),
            )
            .unwrap(),
        );
        let metrics_addr = free_addr();
        let rpc_addr = free_addr();
        let maybe_path =
            reth_node_core::dirs::MaybePlatformPath::<reth_node_core::dirs::DataDirPath>::from(
                datadir.to_path_buf(),
            );
        let config = NodeConfig::test()
            .with_chain(chain_spec.clone())
            .with_metrics(reth_node_core::args::MetricArgs {
                prometheus: Some(metrics_addr),
                ..Default::default()
            })
            .with_datadir_args(reth_node_core::args::DatadirArgs {
                datadir: maybe_path.clone(),
                ..Default::default()
            });
        let data_dir =
            maybe_path.unwrap_or_chain_default(chain_spec.chain(), config.datadir.clone());
        let (feed_tx, feed_rx) = tokio::sync::mpsc::channel(1);
        let (l1_tx, l1_rx) = tokio::sync::mpsc::channel(1);
        let gate = RecoveryGate::new(false);
        let handle = ArbLauncher {
            ctx: reth_node_builder::LaunchContext::new(Runtime::test(), data_dir),
            chain_id: 412_346,
            genesis_block: 0,
            tuning: ArbEngineTuning::reth_defaults(),
            prune_config: None,
            init_message_journal_at_tip: false,
            l1_verified_tip: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            feed_messages: feed_rx,
            l1_messages: l1_rx,
            feed_latency: None,
            rpc_addr: Some(rpc_addr),
            tx_log_stream: None,
            recovery_gate: gate.clone(),
            recovery: None,
            driver_test_control: None,
        }
        .launch_node(NodeBuilder::new(config).with_database(db).node(ArbNode))
        .await
        .unwrap();
        assert!(handle.rpc_handle.is_none());
        wait_recovery_metric(metrics_addr, 0.0).await;
        assert!(tokio::net::TcpStream::connect(rpc_addr).await.is_err());

        gate.release();
        wait_recovery_metric(metrics_addr, 1.0).await;
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if tokio::net::TcpStream::connect(rpc_addr).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();

        drop((feed_tx, l1_tx));
        handle.wait_for_node_exit().await.unwrap();
    }

    async fn seed_db_ahead_in_process(datadir: &Path) {
        run_test_node(datadir, 1..=3, RecoveryGate::new(true), None).await;
        let journal = inspect_message_journal(datadir, 0).unwrap();
        let target = journal.entry(1).unwrap();
        rewrite_journal_to_identity_at(datadir, 0, target.block_number, target.block_hash).unwrap();
    }

    async fn seed_exact(datadir: &Path) {
        const TEST: &str = "recovery::tests::process_fixture_helper";
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
            .env("ITE105_FIXTURE_ACTION", "exact")
            .env("ITE105_RECOVERY_DATADIR", datadir)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "exact-parity seed failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    async fn seed_db_ahead(datadir: &Path) {
        const TEST: &str = "recovery::tests::process_fixture_helper";
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
            .env("ITE105_FIXTURE_ACTION", "seed")
            .env("ITE105_RECOVERY_DATADIR", datadir)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "seed subprocess failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        assert_eq!(
            StaticFileProvider::<ArbPrimitives>::read_only(datadir.join("static_files"))
                .unwrap()
                .get_highest_static_file_block(StaticFileSegment::Headers),
            Some(3)
        );
    }

    fn recover_offline_for_test(datadir: &Path) -> RecoveryRuntime {
        let config = test_config(datadir);
        let mut marker = match classify_read_only(&config).unwrap() {
            ReadOnlyClassification::Existing(marker) => {
                validate_marker_config(&marker, &config).unwrap();
                marker
            }
            ReadOnlyClassification::Candidate(candidate) => {
                let marker = marker_from_candidate(
                    &config,
                    candidate,
                    ParentIdentity {
                        chain_id: 1,
                        genesis_hash: B256::repeat_byte(0x33),
                    },
                );
                write_marker(datadir, &marker).unwrap();
                recovery_failpoint("initial_marker_fsynced");
                marker
            }
            ReadOnlyClassification::Normal => panic!("expected DB-ahead recovery state"),
        };
        complete_offline_repair(&config, &mut marker).unwrap();
        RecoveryRuntime {
            marker,
            storage: RecoveryStorageConfig::from_config(&config),
        }
    }

    fn runtime_from_marker_for_test(datadir: &Path) -> RecoveryRuntime {
        let config = test_config(datadir);
        RecoveryRuntime {
            marker: read_marker(datadir).unwrap(),
            storage: RecoveryStorageConfig::from_config(&config),
        }
    }

    fn fixture_status(
        datadir: &Path,
        action: &str,
        failpoint: Option<&str>,
    ) -> std::process::ExitStatus {
        const TEST: &str = "recovery::tests::process_fixture_helper";
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
            .env("ITE105_FIXTURE_ACTION", action)
            .env("ITE105_RECOVERY_DATADIR", datadir);
        if action == "worker" {
            command.env(RECOVERY_WORKER_ENV, "1");
        }
        if let Some(failpoint) = failpoint {
            command.env(RECOVERY_FAILPOINT_ENV, failpoint);
        }
        command.status().unwrap()
    }

    fn finish_recovery_processes(datadir: &Path) {
        assert!(fixture_status(datadir, "worker", None).success());
        assert!(fixture_status(datadir, "finalize", None).success());
    }

    fn freeze_candidate_for_test(datadir: &Path) -> (RecoveryConfig, RecoveryMarker) {
        let config = test_config(datadir);
        let ReadOnlyClassification::Candidate(candidate) = classify_read_only(&config).unwrap()
        else {
            panic!("expected DB-ahead candidate")
        };
        let marker = marker_from_candidate(
            &config,
            candidate,
            ParentIdentity {
                chain_id: 1,
                genesis_hash: B256::repeat_byte(0x33),
            },
        );
        write_marker(datadir, &marker).unwrap();
        (config, marker)
    }

    fn copy_tree(source: &Path, destination: &Path) {
        std::fs::create_dir_all(destination).unwrap();
        for entry in std::fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let target = destination.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), target).unwrap();
            }
        }
    }

    fn static_segment_artifacts(datadir: &Path, needle: &str) -> Vec<PathBuf> {
        std::fs::read_dir(datadir.join("static_files"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.file_name().unwrap().to_string_lossy().contains(needle))
            .collect()
    }

    fn static_segment_artifact_bytes(datadir: &Path, needle: &str) -> Vec<(PathBuf, Vec<u8>)> {
        let mut paths = static_segment_artifacts(datadir, needle);
        paths.sort();
        paths
            .into_iter()
            .map(|path| {
                let bytes = std::fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect()
    }

    fn mutate_sender_physical_file(datadir: &Path, shape: &str) {
        let data_files = static_segment_artifacts(datadir, "transaction-senders")
            .into_iter()
            .filter(|path| path.extension().is_none())
            .collect::<Vec<_>>();
        assert_eq!(data_files.len(), 1);
        let data_path = &data_files[0];
        let offsets_path = data_path.with_extension("off");
        let config_path = data_path.with_extension("conf");
        let config_before = std::fs::read(&config_path).unwrap();
        match shape {
            "sender_data_missing" => std::fs::remove_file(data_path).unwrap(),
            "sender_data_extra_tail" => OpenOptions::new()
                .append(true)
                .open(data_path)
                .unwrap()
                .write_all(&[0xa5])
                .unwrap(),
            "sender_data_truncated" => {
                let file = OpenOptions::new().write(true).open(data_path).unwrap();
                let len = file.metadata().unwrap().len();
                assert!(len > 0);
                file.set_len(len - 1).unwrap();
            }
            "sender_offsets_missing" => std::fs::remove_file(&offsets_path).unwrap(),
            "sender_offsets_wrong_width" => {
                let mut bytes = std::fs::read(&offsets_path).unwrap();
                assert_eq!(bytes[0], 8);
                bytes[0] = 4;
                std::fs::write(&offsets_path, bytes).unwrap();
            }
            "sender_offsets_extra_tail" => OpenOptions::new()
                .append(true)
                .open(&offsets_path)
                .unwrap()
                .write_all(&[0xa5; 8])
                .unwrap(),
            "sender_offsets_misaligned" => OpenOptions::new()
                .append(true)
                .open(&offsets_path)
                .unwrap()
                .write_all(&[0xa5])
                .unwrap(),
            "sender_offsets_truncated" => {
                let file = OpenOptions::new().write(true).open(&offsets_path).unwrap();
                let len = file.metadata().unwrap().len();
                assert!(len > 1);
                file.set_len(len - 1).unwrap();
            }
            _ => unreachable!(),
        }
        assert_eq!(std::fs::read(config_path).unwrap(), config_before);
    }

    fn mutate_sender_proof_shape(datadir: &Path, shape: &str) {
        match shape {
            "sender_data_missing"
            | "sender_data_extra_tail"
            | "sender_data_truncated"
            | "sender_offsets_missing"
            | "sender_offsets_wrong_width"
            | "sender_offsets_extra_tail"
            | "sender_offsets_misaligned"
            | "sender_offsets_truncated" => mutate_sender_physical_file(datadir, shape),
            "body_index_gap" => {
                let factory = open_recovery_factory(&test_config(datadir)).unwrap();
                let provider = factory.provider_rw().unwrap();
                assert!(
                    provider
                        .tx_ref()
                        .delete::<tables::BlockBodyIndices>(1, None)
                        .unwrap()
                );
                provider.commit().unwrap();
                drop(factory);
            }
            "sender_row_missing" => {
                let factory = open_recovery_factory(&test_config(datadir)).unwrap();
                let static_files = factory.static_file_provider();
                let tip = static_files
                    .get_highest_static_file_block(StaticFileSegment::TransactionSenders)
                    .unwrap();
                let provider = factory.provider_rw().unwrap();
                let mut writer = provider
                    .get_static_file_writer(tip, StaticFileSegment::TransactionSenders)
                    .unwrap();
                let original_header = writer.user_header().clone();
                writer.prune_transaction_senders(1, tip).unwrap();
                writer.commit().unwrap();
                drop(writer);
                let mut writer = provider
                    .get_static_file_writer(tip, StaticFileSegment::TransactionSenders)
                    .unwrap();
                *writer.user_header_mut() = original_header;
                writer.commit().unwrap();
                drop(writer);
                provider.commit().unwrap();
                drop(factory);
            }
            "missing" => {
                for path in static_segment_artifacts(datadir, "transaction-senders") {
                    std::fs::remove_file(path).unwrap();
                }
            }
            "stale" | "ahead" => {
                let config = test_config(datadir);
                let factory = open_recovery_factory(&config).unwrap();
                let static_files = factory.static_file_provider();
                let tip = static_files
                    .get_highest_static_file_block(StaticFileSegment::TransactionSenders)
                    .unwrap();
                let highest_tx = static_files
                    .get_highest_static_file_tx(StaticFileSegment::TransactionSenders)
                    .unwrap();
                let provider = factory.provider_rw().unwrap();
                let mut writer = provider
                    .get_static_file_writer(tip, StaticFileSegment::TransactionSenders)
                    .unwrap();
                if shape == "stale" {
                    let retained_tx = provider
                        .tx_ref()
                        .get::<tables::BlockBodyIndices>(tip - 1)
                        .unwrap()
                        .unwrap()
                        .next_tx_num();
                    writer
                        .prune_transaction_senders(highest_tx + 1 - retained_tx, tip - 1)
                        .unwrap();
                } else {
                    writer.increment_block(tip + 1).unwrap();
                    writer
                        .append_transaction_sender(highest_tx + 1, &Address::repeat_byte(0x44))
                        .unwrap();
                }
                writer.commit().unwrap();
                drop(writer);
                provider.commit().unwrap();
                drop(factory);
            }
            "checkpoint_ahead" => {
                let config = test_config(datadir);
                let factory = open_recovery_factory(&config).unwrap();
                let provider = factory.provider_rw().unwrap();
                provider
                    .save_prune_checkpoint(
                        PruneSegment::SenderRecovery,
                        PruneCheckpoint {
                            block_number: Some(u64::MAX),
                            tx_number: None,
                            prune_mode: PruneMode::Before(1),
                        },
                    )
                    .unwrap();
                provider.commit().unwrap();
                drop(factory);
            }
            "fully_pruned"
            | "fully_pruned_stale"
            | "fully_pruned_config_mismatch"
            | "fully_pruned_missing_block"
            | "fully_pruned_bad_block"
            | "fully_pruned_missing_tx"
            | "fully_pruned_bad_tx" => {
                let config = test_config(datadir);
                let factory = open_recovery_factory(&config).unwrap();
                let static_files = factory.static_file_provider();
                let tip = static_files
                    .get_highest_static_file_block(StaticFileSegment::TransactionSenders)
                    .unwrap();
                let highest_tx =
                    static_files.get_highest_static_file_tx(StaticFileSegment::TransactionSenders);
                let provider = factory.provider_rw().unwrap();
                provider
                    .save_prune_checkpoint(
                        PruneSegment::SenderRecovery,
                        PruneCheckpoint {
                            block_number: match shape {
                                "fully_pruned_missing_block" => None,
                                "fully_pruned_bad_block" => Some(tip - 1),
                                _ => Some(tip),
                            },
                            tx_number: match shape {
                                "fully_pruned_missing_tx" => None,
                                "fully_pruned_bad_tx" => highest_tx.map(|number| number - 1),
                                _ => highest_tx,
                            },
                            prune_mode: PruneMode::Full,
                        },
                    )
                    .unwrap();
                provider.commit().unwrap();
                drop(factory);
                if shape != "fully_pruned_stale" {
                    for path in static_segment_artifacts(datadir, "transaction-senders") {
                        std::fs::remove_file(path).unwrap();
                    }
                }
            }
            _ => unreachable!(),
        }
    }

    fn sender_shape_config(datadir: &Path, shape: &str) -> RecoveryConfig {
        let mut config = test_config(datadir);
        if shape == "configured_full_retained"
            || shape == "fully_pruned"
            || (shape.starts_with("fully_pruned_") && shape != "fully_pruned_config_mismatch")
        {
            let mut prune = PruneConfig::default();
            prune.segments.sender_recovery = Some(PruneMode::Full);
            config.prune_config = Some(prune);
        }
        config
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn process_fixture_helper() {
        let Some(action) = std::env::var_os("ITE105_FIXTURE_ACTION") else {
            return;
        };
        let datadir = PathBuf::from(std::env::var_os("ITE105_RECOVERY_DATADIR").unwrap());
        match action.to_str().unwrap() {
            "exact" => run_test_node(&datadir, 1..=3, RecoveryGate::new(true), None).await,
            "seed" => seed_db_ahead_in_process(&datadir).await,
            "offline" => drop(recover_offline_for_test(&datadir)),
            "worker" => {
                assert!(is_recovery_worker());
                let runtime = recover_offline_for_test(&datadir);
                run_test_node(&datadir, 2..=3, RecoveryGate::new(false), Some(runtime)).await;
            }
            "finalize" => {
                assert!(!is_recovery_worker());
                recovery_failpoint("recovery_worker_exited_before_reopen");
                let runtime = runtime_from_marker_for_test(&datadir);
                finalize_recovery_and_release(&runtime, &RecoveryGate::new(false)).unwrap();
            }
            "final-validate" => validate_reopened_finalization(
                &datadir,
                std::env::var_os(RECOVERY_VALIDATE_RECEIPTS_ENV).as_deref()
                    == Some(std::ffi::OsStr::new("1")),
                std::env::var_os(RECOVERY_VALIDATE_SENDERS_ENV).as_deref()
                    == Some(std::ffi::OsStr::new("1")),
            )
            .unwrap(),
            "gate" => exercise_production_gate(&datadir).await,
            action => panic!("unknown fixture action {action}"),
        }
    }

    fn test_marker() -> RecoveryMarker {
        RecoveryMarker {
            version: RECOVERY_VERSION,
            phase: RecoveryPhase::Classified,
            l2_chain_id: 42_161,
            l2_genesis_block_number: 0,
            l2_genesis_hash: B256::repeat_byte(1),
            parent_execution_chain_id: 1,
            parent_execution_genesis_hash: B256::repeat_byte(2),
            parent_chain_is_arbitrum: ParentChainClassification::Unspecified,
            sequencer_inbox: Address::repeat_byte(3),
            bridge: Address::repeat_byte(4),
            deployment_block: 10,
            journal_anchor: MessageJournalAnchor {
                sequence: 0,
                block_number: 0,
                block_hash: B256::repeat_byte(5),
            },
            target: RecoveryTarget::Anchor {
                sequence: 0,
                block_number: 0,
                block_hash: B256::repeat_byte(5),
                state_root: B256::repeat_byte(6),
            },
            old_db_tip_number: 2,
            old_db_tip_hash: B256::repeat_byte(7),
            old_db_tip_state_root: B256::repeat_byte(8),
            resume_checkpoint: FrozenResumeCheckpoint::None,
            active_unwind_horizon: 10,
            account_history_prune_checkpoint: ObservedPruneCheckpoint::None,
            storage_history_prune_checkpoint: ObservedPruneCheckpoint::None,
            account_changeset_ranges: vec![ObservedStaticRange { start: 1, end: 2 }],
            storage_changeset_ranges: vec![ObservedStaticRange { start: 1, end: 2 }],
            snapshot_layout: SnapshotLayout::NonSnapshot,
        }
    }

    fn write_legacy_segment(static_files: &Path, segment: &str, locations: u8) {
        let old = format!("static_file_{segment}_0_10");
        let new = format!("static_file_{segment}_1_10");
        let mut config = vec![0u8; 41];
        config[0..8].copy_from_slice(&1u64.to_le_bytes());
        config[8..16].copy_from_slice(&500_000u64.to_le_bytes());
        config[16..24].copy_from_slice(&10u64.to_le_bytes());
        config[24] = 1;
        config[25..33].copy_from_slice(&0u64.to_le_bytes());
        config[33..41].copy_from_slice(&10u64.to_le_bytes());
        for (index, extension) in ["", ".conf", ".off", ".csoff"].into_iter().enumerate() {
            let base = if locations & (1 << index) == 0 {
                &old
            } else {
                &new
            };
            let contents = if extension == ".conf" {
                config.as_slice()
            } else {
                b"sidecar"
            };
            std::fs::write(static_files.join(format!("{base}{extension}")), contents).unwrap();
        }
    }

    fn assert_aligned_segment(static_files: &Path, segment: &str) {
        let base = format!("static_file_{segment}_1_10");
        for extension in ["", ".conf", ".off", ".csoff"] {
            assert!(static_files.join(format!("{base}{extension}")).is_file());
        }
        let config = std::fs::read(static_files.join(format!("{base}.conf"))).unwrap();
        let read =
            |offset: usize| u64::from_le_bytes(config[offset..offset + 8].try_into().unwrap());
        assert_eq!(read(8), 1);
        assert_eq!(read(25), 1);
        let legacy_prefix = format!("static_file_{segment}_0_10");
        assert!(std::fs::read_dir(static_files).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(&legacy_prefix)
        }));
    }

    #[tokio::test]
    async fn production_gate_and_gauge_share_one_release_state() {
        let gate = RecoveryGate::new(false);
        let checkpoint_readiness = gate.readiness_atomic();
        gate.register_metric();
        assert!(!gate.is_ready());
        assert!(!checkpoint_readiness.load(Ordering::Acquire));
        let waiter = {
            let gate = gate.clone();
            tokio::spawn(async move { gate.wait_ready().await })
        };
        tokio::task::yield_now().await;
        gate.release();
        waiter.await.unwrap();
        assert!(gate.is_ready());
        assert!(checkpoint_readiness.load(Ordering::Acquire));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn production_prometheus_and_rpc_use_the_same_gate() {
        let dir = tempfile::tempdir().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "recovery::tests::process_fixture_helper",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("ITE105_FIXTURE_ACTION", "gate")
            .env("ITE105_RECOVERY_DATADIR", dir.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "production gate subprocess failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    #[test]
    fn marker_schema_rejects_unknown_fields_and_unsupported_versions() {
        let dir = tempfile::tempdir().unwrap();
        let path = recovery_marker_path(dir.path());
        std::fs::write(&path, b"{\"version\":2}").unwrap();
        assert!(read_marker(dir.path()).is_err());
        std::fs::write(&path, b"{\"version\":1,\"unknown\":true}").unwrap();
        assert!(read_marker(dir.path()).is_err());
    }

    #[test]
    fn marker_round_trip_is_closed_and_ignores_leftover_temp() {
        let dir = tempfile::tempdir().unwrap();
        let marker = test_marker();
        write_marker(dir.path(), &marker).unwrap();
        assert_eq!(read_marker(dir.path()).unwrap(), marker);

        let path = recovery_marker_path(dir.path());
        std::fs::write(path.with_extension("json.tmp"), b"{").unwrap();
        assert_eq!(read_marker(dir.path()).unwrap(), marker);

        let mut value = serde_json::to_value(&marker).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), serde_json::Value::Bool(true));
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(read_marker(dir.path()).is_err());
    }

    #[test]
    fn contradictory_marker_authority_is_rejected() {
        let mut marker = test_marker();
        marker.old_db_tip_number = marker.target.block_number();
        assert!(validate_marker_invariants(&marker).is_err());

        let mut marker = test_marker();
        marker.journal_anchor.block_number = 1;
        assert!(validate_marker_invariants(&marker).is_err());

        let mut marker = test_marker();
        marker.resume_checkpoint = FrozenResumeCheckpoint::Checkpoint(L1ResumeCheckpoint {
            l1_block: 100,
            delayed_count: 1,
            l2_block: 1,
        });
        assert!(validate_marker_invariants(&marker).is_err());
    }

    #[test]
    fn changeset_history_proof_accepts_zero_change_blocks_and_rejects_missing_coverage() {
        let validate_counts = |name: &str, counts: [u64; 3]| {
            validate_changeset_segment_coverage(name, 1, 4, |block| {
                Ok((2, 4, Some(counts[(block - 2) as usize])))
            })
        };
        // Account-only, storage-only, and all-empty blocks all retain readable offsets.
        validate_counts("account", [1, 2, 1]).unwrap();
        validate_counts("storage", [0, 0, 0]).unwrap();
        validate_counts("account", [0, 0, 0]).unwrap();
        validate_counts("storage", [1, 2, 1]).unwrap();
        validate_counts("account", [0, 0, 0]).unwrap();
        validate_counts("storage", [0, 0, 0]).unwrap();

        let missing_segment = validate_changeset_segment_coverage("storage", 1, 4, |block| {
            Err(eyre!("storage changeset static-file gap at block {block}"))
        });
        assert!(missing_segment.is_err());
        let gap = validate_changeset_segment_coverage("account", 1, 4, |block| {
            Ok(if block == 3 {
                (2, 2, Some(0))
            } else {
                (2, 4, Some(0))
            })
        });
        assert!(gap.is_err());
        let truncated_upper = validate_changeset_segment_coverage("storage", 1, 4, |block| {
            Ok((2, 4, (block != 4).then_some(0)))
        });
        assert!(truncated_upper.is_err());

        validate_prune_bound("account", Some(1), 2).unwrap();
        assert!(validate_prune_bound("storage", Some(2), 2).is_err());
    }

    #[test]
    fn recovery_cli_rejects_all_mutable_authority_and_no_fsync() {
        let dir = tempfile::tempdir().unwrap();
        let base = RecoveryConfig {
            datadir: dir.path().to_path_buf(),
            chain_spec: reth_chainspec::MAINNET.clone(),
            chain_id: 1,
            genesis_block: 0,
            sequencer_inbox: Address::ZERO,
            bridge: Address::ZERO,
            deployed_at: 0,
            parent_chain_claim: ParentChainClaim {
                chain_id: None,
                classification: ParentChainClassification::Unspecified,
            },
            snapshot_seeded: false,
            prune_config: None,
            no_fsync: false,
            no_l1_derive: false,
            l1_rpc: Some("http://127.0.0.1:1".into()),
            l1_beacon: Some("http://127.0.0.1:2".into()),
            l1_start_block: None,
            l1_start_delayed: None,
            l1_end_block: None,
        };
        assert!(validate_recovery_cli(&base).is_ok());
        let mutations: [fn(&mut RecoveryConfig); 7] = [
            |config: &mut RecoveryConfig| config.no_fsync = true,
            |config: &mut RecoveryConfig| config.no_l1_derive = true,
            |config: &mut RecoveryConfig| config.l1_rpc = None,
            |config: &mut RecoveryConfig| config.l1_beacon = None,
            |config: &mut RecoveryConfig| config.l1_start_block = Some(1),
            |config: &mut RecoveryConfig| config.l1_start_delayed = Some(1),
            |config: &mut RecoveryConfig| config.l1_end_block = Some(1),
        ];
        for mutate in mutations {
            let mut config = base.clone();
            mutate(&mut config);
            assert!(validate_recovery_cli(&config).is_err());
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn read_only_classification_and_offline_repair_preserve_frozen_identity() {
        let dir = tempfile::tempdir().unwrap();
        seed_db_ahead(dir.path()).await;
        let mut journal_file = OpenOptions::new()
            .append(true)
            .open(message_journal_path(dir.path()))
            .unwrap();
        journal_file.write_all(b"{\"record\":").unwrap();
        journal_file.sync_all().unwrap();
        drop(journal_file);
        let journal_before = std::fs::read(message_journal_path(dir.path())).unwrap();
        let resume_before = inspect_resume_log_strict(dir.path()).unwrap();
        let config = test_config(dir.path());
        let ReadOnlyClassification::Candidate(candidate) = classify_read_only(&config).unwrap()
        else {
            panic!("expected exact DB-ahead candidate");
        };
        assert_eq!(
            std::fs::read(message_journal_path(dir.path())).unwrap(),
            journal_before
        );
        assert_eq!(
            inspect_resume_log_strict(dir.path()).unwrap(),
            resume_before
        );
        assert!(!recovery_marker_path(dir.path()).exists());
        assert_eq!(candidate.target.block_number(), 1);
        assert_eq!(candidate.old_db_tip_number, 3);

        let runtime = recover_offline_for_test(dir.path());
        assert_eq!(runtime.marker.phase, RecoveryPhase::Rederiving);
        validate_reopened_offline(&config, &runtime.marker).unwrap();
        assert!(
            !inspect_message_journal(dir.path(), 0)
                .unwrap()
                .has_incomplete_tail
        );
        assert!(recovery_marker_path(dir.path()).is_file());
        assert!(!divergence_marker_path(dir.path()).exists());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn actual_account_and_storage_artifact_mutations_stop_before_unwind() {
        let template = tempfile::tempdir().unwrap();
        seed_db_ahead(template.path()).await;

        for segment in ["account-change-sets", "storage-change-sets"] {
            for mutation in ["missing_conf", "missing_offset", "truncated_offset", "gap"] {
                let dir = tempfile::tempdir().unwrap();
                copy_tree(template.path(), dir.path());
                let (config, mut marker) = freeze_candidate_for_test(dir.path());
                let marker_before = marker.clone();
                let journal_before = std::fs::read(message_journal_path(dir.path())).unwrap();
                let resume_before = inspect_resume_log_strict(dir.path()).unwrap();
                let artifacts = static_segment_artifacts(dir.path(), segment);
                match mutation {
                    "missing_conf" => {
                        let conf = artifacts
                            .into_iter()
                            .find(|path| path.extension().is_some_and(|ext| ext == "conf"))
                            .unwrap();
                        std::fs::remove_file(conf).unwrap();
                    }
                    "missing_offset" => {
                        let offsets = artifacts
                            .into_iter()
                            .find(|path| path.extension().is_some_and(|ext| ext == "off"))
                            .unwrap();
                        std::fs::remove_file(offsets).unwrap();
                    }
                    "truncated_offset" => {
                        let offsets = artifacts
                            .into_iter()
                            .find(|path| path.extension().is_some_and(|ext| ext == "off"))
                            .unwrap();
                        OpenOptions::new()
                            .write(true)
                            .open(offsets)
                            .unwrap()
                            .set_len(8)
                            .unwrap();
                    }
                    "gap" => {
                        let conf = artifacts
                            .into_iter()
                            .find(|path| path.extension().is_some_and(|ext| ext == "conf"))
                            .unwrap();
                        let mut bytes = std::fs::read(&conf).unwrap();
                        assert!(bytes.len() >= 41);
                        bytes[25..33].copy_from_slice(&2u64.to_le_bytes());
                        std::fs::write(conf, bytes).unwrap();
                    }
                    _ => unreachable!(),
                }

                assert!(
                    complete_offline_repair(&config, &mut marker).is_err(),
                    "{segment} {mutation} artifact mutation reached recovery unwind"
                );
                assert_eq!(current_storage_tip_read_only(&config).unwrap(), 3);
                let persisted = read_marker(dir.path()).unwrap();
                assert!(
                    phase_rank(persisted.phase) < phase_rank(RecoveryPhase::DbUnwound),
                    "{segment} {mutation} advanced past pre-unwind validation"
                );
                let mut expected = marker_before;
                expected.phase = persisted.phase;
                assert_eq!(persisted, expected);
                assert_eq!(
                    std::fs::read(message_journal_path(dir.path())).unwrap(),
                    journal_before
                );
                assert_eq!(
                    inspect_resume_log_strict(dir.path()).unwrap(),
                    resume_before
                );
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn frozen_l2_deployment_and_parent_identities_reject_mutation() {
        let dir = tempfile::tempdir().unwrap();
        seed_db_ahead(dir.path()).await;
        let runtime = recover_offline_for_test(dir.path());
        let marker = runtime.marker;
        let config = test_config(dir.path());
        validate_marker_config(&marker, &config).unwrap();

        let mut changed_l2 = config.clone();
        changed_l2.chain_id += 1;
        assert!(validate_marker_config(&marker, &changed_l2).is_err());
        let mut changed_deployment = config.clone();
        changed_deployment.bridge = Address::repeat_byte(0x99);
        assert!(validate_marker_config(&marker, &changed_deployment).is_err());
        let mut changed_classification = config;
        changed_classification.parent_chain_claim.classification =
            ParentChainClassification::Arbitrum;
        assert!(validate_marker_config(&marker, &changed_classification).is_err());
        let mut changed_horizon = test_config(dir.path());
        let mut prune = PruneConfig::default();
        prune.minimum_pruning_distance = marker.active_unwind_horizon + 1;
        changed_horizon.prune_config = Some(prune);
        assert!(validate_marker_config(&marker, &changed_horizon).is_err());
        let mut changed_snapshot_mode = test_config(dir.path());
        changed_snapshot_mode.snapshot_seeded = true;
        assert!(validate_marker_config(&marker, &changed_snapshot_mode).is_err());

        let mut changed_layout = marker.clone();
        changed_layout.snapshot_layout = SnapshotLayout::SnapshotAligned;
        assert!(validate_marker_config(&changed_layout, &test_config(dir.path())).is_err());
        for account in [true, false] {
            let mut changed_ranges = marker.clone();
            let ranges = if account {
                &mut changed_ranges.account_changeset_ranges
            } else {
                &mut changed_ranges.storage_changeset_ranges
            };
            ranges[0].start = ranges[0].start.saturating_add(1);
            assert!(
                validate_marker_config(&changed_ranges, &test_config(dir.path())).is_err(),
                "{} frozen static ranges accepted mutation",
                if account { "account" } else { "storage" }
            );
        }

        validate_parent(
            &marker,
            ParentIdentity {
                chain_id: marker.parent_execution_chain_id,
                genesis_hash: marker.parent_execution_genesis_hash,
            },
        )
        .unwrap();
        assert!(
            validate_parent(
                &marker,
                ParentIdentity {
                    chain_id: marker.parent_execution_chain_id + 1,
                    genesis_hash: marker.parent_execution_genesis_hash,
                },
            )
            .is_err()
        );
        assert!(
            validate_parent(
                &marker,
                ParentIdentity {
                    chain_id: marker.parent_execution_chain_id,
                    genesis_hash: B256::repeat_byte(0xaa),
                },
            )
            .is_err()
        );

        let marker_before = std::fs::read(recovery_marker_path(dir.path())).unwrap();
        let journal_before = std::fs::read(message_journal_path(dir.path())).unwrap();
        std::fs::write(divergence_marker_path(dir.path()), b"operator evidence").unwrap();
        assert!(classify_read_only(&test_config(dir.path())).is_err());
        assert_eq!(
            std::fs::read(recovery_marker_path(dir.path())).unwrap(),
            marker_before
        );
        assert_eq!(
            std::fs::read(message_journal_path(dir.path())).unwrap(),
            journal_before
        );
        assert_eq!(
            std::fs::read(divergence_marker_path(dir.path())).unwrap(),
            b"operator evidence"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn divergence_precedence_and_no_fsync_do_not_mutate_candidate() {
        let dir = tempfile::tempdir().unwrap();
        seed_db_ahead(dir.path()).await;
        let journal_before = std::fs::read(message_journal_path(dir.path())).unwrap();
        let divergence = divergence_marker_path(dir.path());
        std::fs::write(&divergence, b"operator evidence").unwrap();
        let config = test_config(dir.path());
        assert!(classify_read_only(&config).is_err());
        assert_eq!(std::fs::read(&divergence).unwrap(), b"operator evidence");
        assert_eq!(
            std::fs::read(message_journal_path(dir.path())).unwrap(),
            journal_before
        );
        assert!(!recovery_marker_path(dir.path()).exists());

        std::fs::remove_file(divergence).unwrap();
        let mut no_fsync = config;
        no_fsync.no_fsync = true;
        assert!(classify_read_only(&no_fsync).is_err());
        assert_eq!(
            std::fs::read(message_journal_path(dir.path())).unwrap(),
            journal_before
        );
        assert!(!recovery_marker_path(dir.path()).exists());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn exact_parity_is_normal_and_missing_non_genesis_journal_fails_closed() {
        let template = tempfile::tempdir().unwrap();
        seed_exact(template.path()).await;
        let journal_before = std::fs::read(message_journal_path(template.path())).unwrap();
        let resume_before = inspect_resume_log_strict(template.path()).unwrap();
        let config = test_config(template.path());

        assert!(matches!(
            classify_read_only(&config).unwrap(),
            ReadOnlyClassification::Normal
        ));
        let preparation = prepare_recovery(config).await.unwrap();
        assert!(preparation.gate.is_ready());
        assert!(preparation.runtime.is_none());
        assert_eq!(
            std::fs::read(message_journal_path(template.path())).unwrap(),
            journal_before
        );
        assert_eq!(
            inspect_resume_log_strict(template.path()).unwrap(),
            resume_before
        );
        assert!(!recovery_marker_path(template.path()).exists());

        let missing = tempfile::tempdir().unwrap();
        copy_tree(template.path(), missing.path());
        std::fs::remove_file(message_journal_path(missing.path())).unwrap();
        let error = match classify_read_only(&test_config(missing.path())) {
            Err(error) => error,
            Ok(_) => panic!("missing non-genesis journal must fail closed"),
        };
        assert!(error.to_string().contains("missing at non-genesis"));
        assert!(!message_journal_path(missing.path()).exists());
        assert!(!recovery_marker_path(missing.path()).exists());

        let fully_pruned_receipts = tempfile::tempdir().unwrap();
        copy_tree(template.path(), fully_pruned_receipts.path());
        for path in static_segment_artifacts(fully_pruned_receipts.path(), "receipts") {
            std::fs::remove_file(path).unwrap();
        }
        let mut fully_pruned_config = test_config(fully_pruned_receipts.path());
        let mut prune = PruneConfig::default();
        prune.segments.receipts = Some(PruneMode::Full);
        fully_pruned_config.prune_config = Some(prune);
        assert!(matches!(
            classify_read_only(&fully_pruned_config).unwrap(),
            ReadOnlyClassification::Normal
        ));
        assert!(!recovery_marker_path(fully_pruned_receipts.path()).exists());

        let static_ahead = tempfile::tempdir().unwrap();
        copy_tree(template.path(), static_ahead.path());
        let saved_static = tempfile::tempdir().unwrap();
        copy_tree(
            &static_ahead.path().join("static_files"),
            &saved_static.path().join("static_files"),
        );
        let factory = open_recovery_factory(&test_config(static_ahead.path())).unwrap();
        commit_storage_v2_unwind(&factory, 2).unwrap();
        drop(factory);
        let entry = inspect_message_journal(static_ahead.path(), 0)
            .unwrap()
            .entry(2)
            .unwrap();
        rewrite_journal_to_identity_at(
            static_ahead.path(),
            0,
            entry.block_number,
            entry.block_hash,
        )
        .unwrap();
        std::fs::remove_dir_all(static_ahead.path().join("static_files")).unwrap();
        copy_tree(
            &saved_static.path().join("static_files"),
            &static_ahead.path().join("static_files"),
        );
        let journal_before = std::fs::read(message_journal_path(static_ahead.path())).unwrap();
        let error = match classify_read_only(&test_config(static_ahead.path())) {
            Err(error) => error,
            Ok(_) => panic!("non-DB-ahead static-file suffix must fail closed"),
        };
        assert!(error.to_string().contains("cross-store mismatch"));
        assert_eq!(
            std::fs::read(message_journal_path(static_ahead.path())).unwrap(),
            journal_before
        );
        assert!(!recovery_marker_path(static_ahead.path()).exists());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn normal_classification_rejects_mdbx_static_and_rocks_mismatch_without_healing() {
        let template = tempfile::tempdir().unwrap();
        seed_exact(template.path()).await;

        for shape in [
            "mdbx_checkpoint",
            "static_header_lower_bound",
            "static_receipt_missing",
            "static_receipt_full_stale",
            "static_transaction_missing",
            "rocks_transaction_bound",
            "rocks_account_bound",
            "rocks_storage_bound",
        ] {
            let dir = tempfile::tempdir().unwrap();
            copy_tree(template.path(), dir.path());
            match shape {
                "mdbx_checkpoint" => {
                    let factory = open_recovery_factory(&test_config(dir.path())).unwrap();
                    let provider = factory.provider_rw().unwrap();
                    provider
                        .save_stage_checkpoint(StageId::Headers, StageCheckpoint::new(2))
                        .unwrap();
                    provider.commit().unwrap();
                    drop(factory);
                }
                "static_header_lower_bound" => {
                    let path = static_segment_artifacts(dir.path(), "headers")
                        .into_iter()
                        .find(|path| path.extension().is_some_and(|ext| ext == "conf"))
                        .unwrap();
                    let mut bytes = std::fs::read(&path).unwrap();
                    assert!(bytes.len() >= 41);
                    bytes[8..16].copy_from_slice(&1u64.to_le_bytes());
                    bytes[25..33].copy_from_slice(&1u64.to_le_bytes());
                    std::fs::write(path, bytes).unwrap();
                }
                "static_receipt_missing" => {
                    let path = static_segment_artifacts(dir.path(), "receipts")
                        .into_iter()
                        .find(|path| path.extension().is_some_and(|ext| ext == "conf"))
                        .unwrap();
                    std::fs::remove_file(path).unwrap();
                }
                "static_receipt_full_stale" => {}
                "static_transaction_missing" => {
                    let path = static_segment_artifacts(dir.path(), "transactions")
                        .into_iter()
                        .find(|path| path.extension().is_some_and(|ext| ext == "conf"))
                        .unwrap();
                    std::fs::remove_file(path).unwrap();
                }
                "rocks_transaction_bound" => {
                    let factory = open_recovery_factory(&test_config(dir.path())).unwrap();
                    let rocks = factory.rocksdb_provider();
                    let key = rocks
                        .iter::<tables::TransactionHashNumbers>()
                        .unwrap()
                        .map(|entry| entry.unwrap())
                        .max_by_key(|(_, number)| *number)
                        .unwrap()
                        .0;
                    rocks.delete::<tables::TransactionHashNumbers>(key).unwrap();
                    rocks.flush(&["TransactionHashNumbers"]).unwrap();
                    drop(factory);
                }
                "rocks_account_bound" | "rocks_storage_bound" => {
                    let factory = open_recovery_factory(&test_config(dir.path())).unwrap();
                    let static_files = factory.static_file_provider();
                    let segment = if shape == "rocks_account_bound" {
                        StaticFileSegment::AccountChangeSets
                    } else {
                        StaticFileSegment::StorageChangeSets
                    };
                    assert!(
                        static_segment_highest_changed_block(
                            &dir.path().join("static_files"),
                            &static_files,
                            segment,
                        )
                        .unwrap()
                        .is_some()
                    );
                    let rocks = factory.rocksdb_provider();
                    if shape == "rocks_account_bound" {
                        rocks.clear::<tables::AccountsHistory>().unwrap();
                        rocks.flush(&["AccountsHistory"]).unwrap();
                    } else {
                        rocks.clear::<tables::StoragesHistory>().unwrap();
                        rocks.flush(&["StoragesHistory"]).unwrap();
                    }
                    drop(factory);
                }
                _ => unreachable!(),
            }

            let journal_before = std::fs::read(message_journal_path(dir.path())).unwrap();
            let resume_before = inspect_resume_log_strict(dir.path()).unwrap();
            let mut launch_config = test_config(dir.path());
            if shape == "static_receipt_full_stale" {
                let mut prune = PruneConfig::default();
                prune.segments.receipts = Some(PruneMode::Full);
                launch_config.prune_config = Some(prune);
            }
            assert!(
                prepare_recovery(launch_config).await.is_err(),
                "shape {shape} entered normal startup"
            );
            assert_eq!(
                std::fs::read(message_journal_path(dir.path())).unwrap(),
                journal_before,
                "shape {shape} changed journal"
            );
            assert_eq!(
                inspect_resume_log_strict(dir.path()).unwrap(),
                resume_before,
                "shape {shape} changed resume log"
            );
            assert!(
                !recovery_marker_path(dir.path()).exists(),
                "shape {shape} created recovery marker"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sender_static_shape_is_required_for_normal_and_final_reopened_proofs() {
        let normal_template = tempfile::tempdir().unwrap();
        seed_exact(normal_template.path()).await;
        for shape in [
            "sender_data_missing",
            "sender_data_extra_tail",
            "sender_data_truncated",
            "sender_offsets_missing",
            "sender_offsets_wrong_width",
            "sender_offsets_extra_tail",
            "sender_offsets_misaligned",
            "sender_offsets_truncated",
            "body_index_gap",
            "sender_row_missing",
            "missing",
            "stale",
            "ahead",
            "checkpoint_ahead",
            "fully_pruned_stale",
            "fully_pruned_config_mismatch",
            "fully_pruned_missing_block",
            "fully_pruned_bad_block",
            "fully_pruned_missing_tx",
            "fully_pruned_bad_tx",
        ] {
            let dir = tempfile::tempdir().unwrap();
            copy_tree(normal_template.path(), dir.path());
            mutate_sender_proof_shape(dir.path(), shape);
            let journal_before = std::fs::read(message_journal_path(dir.path())).unwrap();
            let sender_artifacts_before =
                static_segment_artifact_bytes(dir.path(), "transaction-senders");
            assert!(
                prepare_recovery(sender_shape_config(dir.path(), shape))
                    .await
                    .is_err(),
                "sender shape {shape} entered normal mutating startup"
            );
            assert_eq!(
                std::fs::read(message_journal_path(dir.path())).unwrap(),
                journal_before,
                "sender shape {shape} changed journal during classification"
            );
            assert!(
                !recovery_marker_path(dir.path()).exists(),
                "sender shape {shape} created a recovery marker"
            );
            assert_eq!(
                static_segment_artifact_bytes(dir.path(), "transaction-senders"),
                sender_artifacts_before,
                "sender shape {shape} was healed during read-only classification"
            );
        }

        // An active Full configuration does not mean the pruner has already deleted exact
        // retained jars. Pinned Reth checks this segment until it persists a Full checkpoint.
        let normal_full_retained = tempfile::tempdir().unwrap();
        copy_tree(normal_template.path(), normal_full_retained.path());
        let normal_full_retained_config =
            sender_shape_config(normal_full_retained.path(), "configured_full_retained");
        preflight_before_l1_genesis(normal_full_retained.path(), 0).unwrap();
        let normal_preparation = prepare_recovery(normal_full_retained_config).await.unwrap();
        assert!(normal_preparation.gate.is_ready());
        assert!(normal_preparation.runtime.is_none());
        assert!(!recovery_marker_path(normal_full_retained.path()).exists());

        let normal_full = tempfile::tempdir().unwrap();
        copy_tree(normal_template.path(), normal_full.path());
        mutate_sender_proof_shape(normal_full.path(), "fully_pruned");
        let normal_full_config = sender_shape_config(normal_full.path(), "fully_pruned");
        preflight_before_l1_genesis(normal_full.path(), 0).unwrap();
        let normal_preparation = prepare_recovery(normal_full_config).await.unwrap();
        assert!(normal_preparation.gate.is_ready());
        assert!(normal_preparation.runtime.is_none());
        assert!(!recovery_marker_path(normal_full.path()).exists());

        let final_template = tempfile::tempdir().unwrap();
        seed_db_ahead(final_template.path()).await;
        drop(recover_offline_for_test(final_template.path()));
        let status = fixture_status(
            final_template.path(),
            "worker",
            Some("current_frontier_journal_fsynced_before_marker_removal"),
        );
        assert_eq!(status.code(), Some(86));

        for shape in [
            "sender_data_missing",
            "sender_data_extra_tail",
            "sender_data_truncated",
            "sender_offsets_missing",
            "sender_offsets_wrong_width",
            "sender_offsets_extra_tail",
            "sender_offsets_misaligned",
            "sender_offsets_truncated",
            "body_index_gap",
            "sender_row_missing",
            "missing",
            "stale",
            "ahead",
            "checkpoint_ahead",
            "fully_pruned_stale",
            "fully_pruned_config_mismatch",
            "fully_pruned_missing_block",
            "fully_pruned_bad_block",
            "fully_pruned_missing_tx",
            "fully_pruned_bad_tx",
        ] {
            let dir = tempfile::tempdir().unwrap();
            copy_tree(final_template.path(), dir.path());
            mutate_sender_proof_shape(dir.path(), shape);
            let config = sender_shape_config(dir.path(), shape);
            let runtime = RecoveryRuntime {
                marker: read_marker(dir.path()).unwrap(),
                storage: RecoveryStorageConfig::from_config(&config),
            };
            let gate = RecoveryGate::new(false);
            let sender_artifacts_before =
                static_segment_artifact_bytes(dir.path(), "transaction-senders");
            assert!(
                finalize_recovery_and_release(&runtime, &gate).is_err(),
                "sender shape {shape} removed the recovery marker"
            );
            assert!(recovery_marker_path(dir.path()).is_file());
            assert!(!gate.is_ready());
            assert_eq!(
                static_segment_artifact_bytes(dir.path(), "transaction-senders"),
                sender_artifacts_before,
                "sender shape {shape} was healed during final reopened proof"
            );
        }

        let final_full_retained = tempfile::tempdir().unwrap();
        copy_tree(final_template.path(), final_full_retained.path());
        let final_full_retained_config =
            sender_shape_config(final_full_retained.path(), "configured_full_retained");
        let runtime = RecoveryRuntime {
            marker: read_marker(final_full_retained.path()).unwrap(),
            storage: RecoveryStorageConfig::from_config(&final_full_retained_config),
        };
        let gate = RecoveryGate::new(false);
        finalize_recovery_and_release(&runtime, &gate).unwrap();
        assert!(!recovery_marker_path(final_full_retained.path()).exists());
        assert!(gate.is_ready());

        let final_full = tempfile::tempdir().unwrap();
        copy_tree(final_template.path(), final_full.path());
        mutate_sender_proof_shape(final_full.path(), "fully_pruned");
        let final_full_config = sender_shape_config(final_full.path(), "fully_pruned");
        let runtime = RecoveryRuntime {
            marker: read_marker(final_full.path()).unwrap(),
            storage: RecoveryStorageConfig::from_config(&final_full_config),
        };
        let gate = RecoveryGate::new(false);
        finalize_recovery_and_release(&runtime, &gate).unwrap();
        assert!(!recovery_marker_path(final_full.path()).exists());
        assert!(gate.is_ready());
    }

    #[test]
    fn fresh_classification_rejects_orphan_journal_resume_static_and_rocks_artifacts() {
        let clean = tempfile::tempdir().unwrap();
        assert!(matches!(
            classify_read_only(&test_config(clean.path())).unwrap(),
            ReadOnlyClassification::Normal
        ));

        let empty_db = tempfile::tempdir().unwrap();
        drop(
            init_db(
                empty_db.path().join("db"),
                DatabaseArguments::new(ClientVersion::default()),
            )
            .unwrap(),
        );
        assert!(matches!(
            classify_read_only(&test_config(empty_db.path())).unwrap(),
            ReadOnlyClassification::Normal
        ));

        for shape in ["journal", "resume", "static", "rocks"] {
            let dir = tempfile::tempdir().unwrap();
            match shape {
                "journal" => {
                    std::fs::write(message_journal_path(dir.path()), b"orphan").unwrap();
                }
                "resume" => {
                    rewrite_resume_checkpoint_at(
                        dir.path(),
                        Some(L1ResumeCheckpoint {
                            l1_block: 1,
                            delayed_count: 0,
                            l2_block: 0,
                        }),
                    )
                    .unwrap();
                }
                "static" | "rocks" => {
                    let path = dir.path().join(if shape == "static" {
                        "static_files"
                    } else {
                        "rocksdb"
                    });
                    std::fs::create_dir(&path).unwrap();
                    std::fs::write(path.join("orphan"), b"x").unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                classify_read_only(&test_config(dir.path())).is_err(),
                "orphan {shape} artifact entered normal startup"
            );
            assert!(!recovery_marker_path(dir.path()).exists());
        }

        let orphan_mdbx = tempfile::tempdir().unwrap();
        let db = init_db(
            orphan_mdbx.path().join("db"),
            DatabaseArguments::new(ClientVersion::default()),
        )
        .unwrap();
        let tx = db.tx_mut().unwrap();
        tx.put::<tables::PlainAccountState>(
            Address::ZERO,
            reth_primitives_traits::Account::default(),
        )
        .unwrap();
        tx.commit().unwrap();
        drop(db);
        assert!(
            classify_read_only(&test_config(orphan_mdbx.path())).is_err(),
            "orphan no-tip MDBX state entered normal startup"
        );
        assert!(!recovery_marker_path(orphan_mdbx.path()).exists());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn corrupt_mismatched_and_ahead_journals_fail_without_recovery_mutation() {
        let template = tempfile::tempdir().unwrap();
        seed_exact(template.path()).await;

        for shape in [
            "complete_corruption",
            "equal_hash_mismatch",
            "journal_ahead",
            "mapping",
        ] {
            let dir = tempfile::tempdir().unwrap();
            copy_tree(template.path(), dir.path());
            let path = message_journal_path(dir.path());
            let bytes = std::fs::read(&path).unwrap();
            let lines = bytes
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty());
            let mut records = lines
                .map(|line| serde_json::from_slice::<serde_json::Value>(line).unwrap())
                .collect::<Vec<_>>();
            match shape {
                "complete_corruption" => {
                    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
                    file.write_all(b"not-json\n").unwrap();
                    file.sync_all().unwrap();
                }
                "equal_hash_mismatch" => {
                    records.last_mut().unwrap()["entry"]["block_hash"] =
                        serde_json::Value::String(format!("{:#x}", B256::repeat_byte(0xee)));
                    let mut rewritten = records
                        .iter()
                        .map(|record| serde_json::to_string(record).unwrap())
                        .collect::<Vec<_>>()
                        .join("\n")
                        .into_bytes();
                    rewritten.push(b'\n');
                    std::fs::write(&path, rewritten).unwrap();
                }
                "journal_ahead" | "mapping" => {
                    let previous = records.last().unwrap()["entry"].clone();
                    let mut entry = previous.clone();
                    entry["sequence"] = serde_json::Value::from(4);
                    entry["block_number"] =
                        serde_json::Value::from(if shape == "mapping" { 5 } else { 4 });
                    entry["parent_hash"] = previous["block_hash"].clone();
                    entry["block_hash"] =
                        serde_json::Value::String(format!("{:#x}", B256::repeat_byte(0xdd)));
                    let record = serde_json::json!({
                        "record": "message",
                        "version": 1,
                        "entry": entry,
                    });
                    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
                    serde_json::to_writer(&mut file, &record).unwrap();
                    file.write_all(b"\n").unwrap();
                    file.sync_all().unwrap();
                }
                _ => unreachable!(),
            }
            let before = std::fs::read(&path).unwrap();
            assert!(
                classify_read_only(&test_config(dir.path())).is_err(),
                "shape {shape}"
            );
            assert_eq!(std::fs::read(&path).unwrap(), before, "shape {shape}");
            assert!(!recovery_marker_path(dir.path()).exists(), "shape {shape}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn offline_repair_no_drop_process_matrix() {
        const DATADIR_ENV: &str = "ITE105_RECOVERY_DATADIR";
        const TEST: &str = "recovery::tests::process_fixture_helper";

        let template = tempfile::tempdir().unwrap();
        seed_db_ahead(template.path()).await;
        for failpoint in [
            "initial_marker_fsynced",
            "consistency_heal_completed",
            "aggregate_unwind_committed",
            "journal_rewritten_before_resume",
            "resume_rewritten_before_offline_validation",
            "offline_validated_before_rederivation",
        ] {
            let dir = tempfile::tempdir().unwrap();
            copy_tree(template.path(), dir.path());
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
                .env("ITE105_FIXTURE_ACTION", "offline")
                .env(DATADIR_ENV, dir.path())
                .env(RECOVERY_FAILPOINT_ENV, failpoint)
                .status()
                .unwrap();
            assert_eq!(
                status.code(),
                Some(86),
                "failpoint {failpoint} did not _exit"
            );

            let runtime = recover_offline_for_test(dir.path());
            assert_eq!(runtime.marker.phase, RecoveryPhase::Rederiving);
            validate_reopened_offline(&test_config(dir.path()), &runtime.marker).unwrap();
        }

        let checkpoint_dir = tempfile::tempdir().unwrap();
        copy_tree(template.path(), checkpoint_dir.path());
        let checkpoint = L1ResumeCheckpoint {
            l1_block: 100,
            delayed_count: 1,
            l2_block: 1,
        };
        rewrite_resume_checkpoint_at(checkpoint_dir.path(), Some(checkpoint)).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
            .env("ITE105_FIXTURE_ACTION", "offline")
            .env(DATADIR_ENV, checkpoint_dir.path())
            .env(
                RECOVERY_FAILPOINT_ENV,
                "resume_rewritten_before_offline_validation",
            )
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(86));
        let runtime = recover_offline_for_test(checkpoint_dir.path());
        assert_eq!(
            runtime.marker.resume_checkpoint,
            FrozenResumeCheckpoint::Checkpoint(checkpoint)
        );
        validate_reopened_offline(&test_config(checkpoint_dir.path()), &runtime.marker).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn interrupted_cross_store_unwind_shapes_converge_before_sidecars() {
        const TEST: &str = "recovery::tests::process_fixture_helper";
        let template = tempfile::tempdir().unwrap();
        seed_db_ahead(template.path()).await;

        for restore_rocks in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            copy_tree(template.path(), dir.path());
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
                .env("ITE105_FIXTURE_ACTION", "offline")
                .env("ITE105_RECOVERY_DATADIR", dir.path())
                .env(RECOVERY_FAILPOINT_ENV, "aggregate_unwind_committed")
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(86));
            assert_eq!(
                read_marker(dir.path()).unwrap().phase,
                RecoveryPhase::HistoryValidated
            );

            std::fs::remove_dir_all(dir.path().join("static_files")).unwrap();
            copy_tree(
                &template.path().join("static_files"),
                &dir.path().join("static_files"),
            );
            if restore_rocks {
                std::fs::remove_dir_all(dir.path().join("rocksdb")).unwrap();
                copy_tree(
                    &template.path().join("rocksdb"),
                    &dir.path().join("rocksdb"),
                );
            }
            let journal_before = std::fs::read(message_journal_path(dir.path())).unwrap();
            let resume_before = inspect_resume_log_strict(dir.path()).unwrap();

            let runtime = recover_offline_for_test(dir.path());
            assert_eq!(runtime.marker.phase, RecoveryPhase::Rederiving);
            assert_eq!(
                journal_before,
                std::fs::read(message_journal_path(dir.path())).unwrap()
            );
            assert_eq!(
                resume_before,
                inspect_resume_log_strict(dir.path()).unwrap()
            );
            validate_reopened_offline(&test_config(dir.path()), &runtime.marker).unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn late_phase_revalidation_no_drop_never_regresses_and_converges() {
        let template = tempfile::tempdir().unwrap();
        seed_db_ahead(template.path()).await;
        drop(recover_offline_for_test(template.path()));

        for starting_phase in [RecoveryPhase::Rederiving, RecoveryPhase::Finalizing] {
            for failpoint in [
                "phase_layout_normalized_revalidated",
                "phase_consistency_healed_revalidated",
                "phase_history_validated_revalidated",
                "phase_db_unwound_revalidated",
                "phase_journal_rewritten_revalidated",
                "phase_resume_rewritten_revalidated",
                "phase_offline_validated_revalidated",
                "phase_rederiving_revalidated",
                "phase_finalizing_revalidated",
            ] {
                let dir = tempfile::tempdir().unwrap();
                copy_tree(template.path(), dir.path());
                let mut expected = read_marker(dir.path()).unwrap();
                expected.phase = starting_phase;
                write_marker(dir.path(), &expected).unwrap();

                let action = if failpoint == "phase_finalizing_revalidated" {
                    assert!(fixture_status(dir.path(), "worker", None).success());
                    "finalize"
                } else {
                    "worker"
                };
                let status = fixture_status(dir.path(), action, Some(failpoint));
                assert_eq!(
                    status.code(),
                    Some(86),
                    "{starting_phase:?} restart did not _exit at {failpoint}"
                );
                let persisted = read_marker(dir.path()).unwrap();
                assert!(
                    phase_rank(persisted.phase) >= phase_rank(starting_phase),
                    "{starting_phase:?} regressed to {:?} at {failpoint}",
                    persisted.phase
                );
                expected.phase = persisted.phase;
                assert_eq!(persisted, expected);

                finish_recovery_processes(dir.path());
                assert!(!recovery_marker_path(dir.path()).exists());
                assert!(matches!(
                    classify_read_only(&test_config(dir.path())).unwrap(),
                    ReadOnlyClassification::Normal
                ));
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn replay_and_finalization_no_drop_process_matrix() {
        let template = tempfile::tempdir().unwrap();
        seed_db_ahead(template.path()).await;
        for failpoint in [
            "replay_db_persisted_before_journal",
            "recovery_persistence_quiesced",
            "current_frontier_journal_fsynced_before_marker_removal",
            "recovery_writers_released_before_reopen",
            "recovery_worker_quiesced_before_process_exit",
            "recovery_worker_exited_before_reopen",
            "reopened_storage_validated_before_finalizing",
            "marker_unlinked_before_parent_fsync",
            "marker_parent_fsynced_before_ready",
            "ready_stored_before_services_released",
        ] {
            let dir = tempfile::tempdir().unwrap();
            copy_tree(template.path(), dir.path());
            drop(recover_offline_for_test(dir.path()));
            let finalizer_failpoint = matches!(
                failpoint,
                "recovery_worker_exited_before_reopen"
                    | "reopened_storage_validated_before_finalizing"
                    | "marker_unlinked_before_parent_fsync"
                    | "marker_parent_fsynced_before_ready"
                    | "ready_stored_before_services_released"
            );
            if finalizer_failpoint {
                assert!(fixture_status(dir.path(), "worker", None).success());
            }
            let status = fixture_status(
                dir.path(),
                if finalizer_failpoint {
                    "finalize"
                } else {
                    "worker"
                },
                Some(failpoint),
            );
            assert_eq!(
                status.code(),
                Some(86),
                "failpoint {failpoint} did not _exit"
            );
            if failpoint == "replay_db_persisted_before_journal" {
                let db = open_db_read_only(
                    dir.path().join("db"),
                    DatabaseArguments::new(ClientVersion::default()),
                )
                .unwrap();
                let tx = db.tx().unwrap();
                let execution_tip = tx
                    .get::<tables::StageCheckpoints>(StageId::Execution.to_string())
                    .unwrap()
                    .unwrap()
                    .block_number;
                let journal_tip = inspect_message_journal(dir.path(), 0)
                    .unwrap()
                    .watermark
                    .block_number;
                assert!(
                    execution_tip > journal_tip,
                    "failpoint missed DB-ahead window"
                );
                assert!(
                    inspect_resume_log_strict(dir.path())
                        .unwrap()
                        .is_none_or(|log| log
                            .checkpoints
                            .iter()
                            .all(|checkpoint| checkpoint.l2_block <= journal_tip)),
                    "resume checkpoint advanced beyond the durable journal"
                );
            }

            if recovery_marker_path(dir.path()).exists() {
                finish_recovery_processes(dir.path());
            }
            assert!(!recovery_marker_path(dir.path()).exists());
            assert!(matches!(
                classify_read_only(&test_config(dir.path())).unwrap(),
                ReadOnlyClassification::Normal
            ));
            let journal = inspect_message_journal(dir.path(), 0).unwrap();
            assert_eq!(journal.watermark.block_number, 3);
        }

        let checkpoint_dir = tempfile::tempdir().unwrap();
        copy_tree(template.path(), checkpoint_dir.path());
        let checkpoint = L1ResumeCheckpoint {
            l1_block: 100,
            delayed_count: 1,
            l2_block: 1,
        };
        rewrite_resume_checkpoint_at(checkpoint_dir.path(), Some(checkpoint)).unwrap();
        drop(recover_offline_for_test(checkpoint_dir.path()));
        finish_recovery_processes(checkpoint_dir.path());
        assert!(!recovery_marker_path(checkpoint_dir.path()).exists());
        assert_eq!(
            inspect_resume_log_strict(checkpoint_dir.path())
                .unwrap()
                .unwrap()
                .checkpoints,
            [checkpoint]
        );
    }

    #[derive(Default)]
    struct ControlledMarkerRemovalFilesystem {
        unlinked: bool,
        parent_synced: bool,
    }

    impl MarkerRemovalFilesystem for ControlledMarkerRemovalFilesystem {
        fn unlink(&mut self, path: &Path) -> eyre::Result<()> {
            std::fs::remove_file(path)?;
            self.unlinked = true;
            Ok(())
        }

        fn sync_parent(&mut self, path: &Path) -> eyre::Result<()> {
            sync_parent(path)?;
            self.parent_synced = true;
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn marker_unlink_harness_models_both_unsynced_directory_outcomes() {
        let template = tempfile::tempdir().unwrap();
        seed_db_ahead(template.path()).await;
        drop(recover_offline_for_test(template.path()));
        assert!(fixture_status(template.path(), "worker", None).success());

        for marker_entry_survives_crash in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            copy_tree(template.path(), dir.path());
            let mut marker = read_marker(dir.path()).unwrap();
            marker.phase = RecoveryPhase::Finalizing;
            write_marker(dir.path(), &marker).unwrap();

            let mut filesystem = ControlledMarkerRemovalFilesystem::default();
            let result = remove_marker_durable_with(dir.path(), &mut filesystem, || {
                Err(eyre!("simulated crash before parent-directory fsync"))
            });
            assert!(result.is_err());
            assert!(filesystem.unlinked);
            assert!(!filesystem.parent_synced);

            if marker_entry_survives_crash {
                // A filesystem may replay the last durable directory state after an unsynced
                // unlink. Recreate that represented outcome, then use production classification.
                write_marker(dir.path(), &marker).unwrap();
                assert!(matches!(
                    classify_read_only(&test_config(dir.path())).unwrap(),
                    ReadOnlyClassification::Existing(persisted) if persisted == marker
                ));
            } else {
                // Or the unlink may survive. Exact reopened DB/journal parity is then a normal
                // restart, matching the production crash contract after durable repair.
                assert!(matches!(
                    classify_read_only(&test_config(dir.path())).unwrap(),
                    ReadOnlyClassification::Normal
                ));
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn final_barrier_mutations_remain_quarantined() {
        let template = tempfile::tempdir().unwrap();
        seed_db_ahead(template.path()).await;
        drop(recover_offline_for_test(template.path()));
        let status = fixture_status(
            template.path(),
            "worker",
            Some("current_frontier_journal_fsynced_before_marker_removal"),
        );
        assert_eq!(status.code(), Some(86));

        for mutation in [
            "old_hash",
            "feed_authority",
            "frontier_hash",
            "journal_gap",
            "resume_above",
            "resume_below",
            "reopen_static_failure",
            "reopen_rocks_failure",
        ] {
            let dir = tempfile::tempdir().unwrap();
            copy_tree(template.path(), dir.path());
            let mut marker = read_marker(dir.path()).unwrap();
            if mutation == "old_hash" {
                marker.old_db_tip_hash = B256::repeat_byte(0xbb);
                write_marker(dir.path(), &marker).unwrap();
            } else if matches!(mutation, "resume_above" | "resume_below") {
                rewrite_resume_checkpoint_at(
                    dir.path(),
                    Some(L1ResumeCheckpoint {
                        l1_block: 100,
                        delayed_count: 1,
                        l2_block: if mutation == "resume_above" { 4 } else { 2 },
                    }),
                )
                .unwrap();
            } else if mutation == "reopen_static_failure" {
                let path = static_segment_artifacts(dir.path(), "headers")
                    .into_iter()
                    .find(|path| path.extension().is_none())
                    .unwrap();
                std::fs::remove_file(path).unwrap();
            } else if mutation == "reopen_rocks_failure" {
                std::fs::remove_file(dir.path().join("rocksdb").join("CURRENT")).unwrap();
            } else {
                let path = message_journal_path(dir.path());
                let bytes = std::fs::read(&path).unwrap();
                let mut records = bytes
                    .split(|byte| *byte == b'\n')
                    .filter(|line| !line.is_empty())
                    .map(|line| serde_json::from_slice::<serde_json::Value>(line).unwrap())
                    .collect::<Vec<_>>();
                match mutation {
                    "feed_authority" => {
                        records
                            .iter_mut()
                            .find(|record| record["entry"]["sequence"] == 2)
                            .unwrap()["entry"]["source"] = serde_json::Value::String("feed".into());
                    }
                    "frontier_hash" => {
                        records.last_mut().unwrap()["entry"]["block_hash"] =
                            serde_json::Value::String(format!("{:#x}", B256::repeat_byte(0xcc)));
                    }
                    "journal_gap" => {
                        records.retain(|record| record["entry"]["sequence"] != 2);
                    }
                    _ => unreachable!(),
                }
                let mut rewritten = records
                    .iter()
                    .map(|record| serde_json::to_string(record).unwrap())
                    .collect::<Vec<_>>()
                    .join("\n")
                    .into_bytes();
                rewritten.push(b'\n');
                std::fs::write(path, rewritten).unwrap();
            }

            let config = test_config(dir.path());
            let gate = RecoveryGate::new(false);
            let runtime = RecoveryRuntime {
                marker,
                storage: RecoveryStorageConfig::from_config(&config),
            };
            assert!(
                finalize_recovery_and_release(&runtime, &gate).is_err(),
                "mutation {mutation} passed finalization"
            );
            assert!(
                recovery_marker_path(dir.path()).is_file(),
                "mutation {mutation}"
            );
            assert!(!gate.is_ready(), "mutation {mutation}");
        }
    }

    #[test]
    fn snapshot_normalization_accepts_every_partial_old_new_name_set() {
        for locations in 0..16 {
            let dir = tempfile::tempdir().unwrap();
            for segment in ["account-change-sets", "storage-change-sets"] {
                write_legacy_segment(dir.path(), segment, locations);
            }
            normalize_snapshot_changeset_layout(dir.path(), 0).unwrap();
            for segment in ["account-change-sets", "storage-change-sets"] {
                assert_aligned_segment(dir.path(), segment);
            }
        }
    }

    #[test]
    fn snapshot_normalization_no_drop_restart_matrix() {
        const CHILD_ENV: &str = "ITE105_LAYOUT_CHILD_DATADIR";
        const TEST: &str = "recovery::tests::snapshot_normalization_no_drop_restart_matrix";
        if let Some(datadir) = std::env::var_os(CHILD_ENV) {
            normalize_snapshot_changeset_layout(Path::new(&datadir), 0).unwrap();
            return;
        }

        let failpoints = [
            "snapshot_account-change-sets__renamed",
            "snapshot_account-change-sets_.conf_renamed",
            "snapshot_account-change-sets_.off_renamed",
            "snapshot_account-change-sets_.csoff_renamed",
            "snapshot_account-change-sets_header_fsynced",
            "snapshot_storage-change-sets__renamed",
            "snapshot_storage-change-sets_.conf_renamed",
            "snapshot_storage-change-sets_.off_renamed",
            "snapshot_storage-change-sets_.csoff_renamed",
            "snapshot_storage-change-sets_header_fsynced",
        ];
        for failpoint in failpoints {
            let dir = tempfile::tempdir().unwrap();
            for segment in ["account-change-sets", "storage-change-sets"] {
                write_legacy_segment(dir.path(), segment, 0);
            }
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
                .env(CHILD_ENV, dir.path())
                .env(RECOVERY_FAILPOINT_ENV, failpoint)
                .status()
                .unwrap();
            assert_eq!(
                status.code(),
                Some(86),
                "failpoint {failpoint} did not _exit"
            );
            normalize_snapshot_changeset_layout(dir.path(), 0).unwrap();
            for segment in ["account-change-sets", "storage-change-sets"] {
                assert_aligned_segment(dir.path(), segment);
            }
        }
    }
}
