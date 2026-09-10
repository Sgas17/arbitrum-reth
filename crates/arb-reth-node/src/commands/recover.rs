//! `arb-reth recover`: stopped, bounded reconstruction after a trusted-L2 incident.
//!
//! This command intentionally has a narrow CLI and never invokes the ordinary node launcher.

#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use clap::Parser;
use reth_chainspec::ChainSpec;
use reth_db::{ClientVersion, init_db, mdbx::DatabaseArguments};
use reth_node_builder::NodeConfig;
use reth_node_core::{args::DatadirArgs, dirs::MaybePlatformPath};
use reth_node_types::NodeTypesWithDBAdapter;
use reth_provider::{
    BlockExecutionWriter, BlockNumReader, DBProvider, DatabaseProviderFactory, HeaderProvider,
    ProviderFactory,
    providers::{RocksDBProvider, StaticFileProvider},
};
use reth_tasks::Runtime;
use serde::{Deserialize, Serialize};

use crate::trusted_l2::{
    CanonicalL2Client, HeaderObservation, Incident, RecoveryAuthorityError, load_active_incident,
};
use crate::{
    ArbNode, L1ResumeCheckpoint, L1ResumeLog, L1SyncConfig, ResolvedRollupBoot,
    StoppedFiniteConfig, StoppedFiniteRethLaunch, run_stopped_finite,
};
use alloy_primitives::{Address, B256};

type Factory = ProviderFactory<NodeTypesWithDBAdapter<ArbNode, reth_db::DatabaseEnv>>;
const JOURNAL_DIR: &str = "arb-trusted-l2";
const JOURNAL_FILE: &str = "recovery-v2.json";
const RECOVERY_LOCK_FILE: &str = "recovery.lock";

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FaultPoint {
    AfterUnwindCommit,
    AfterResumeDurableSave,
    BeforeResumePhaseSave,
    AfterFiniteCompletion,
}

#[cfg(test)]
thread_local! {
    static RECOVERY_FAULT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn inject_fault(point: FaultPoint) -> eyre::Result<()> {
    if RECOVERY_FAULT.with(|fault| {
        let expected = point as u8 + 1;
        if fault.get() == expected {
            fault.set(0);
            true
        } else {
            false
        }
    }) {
        return Err(eyre::eyre!("injected recovery crash at {point:?}"));
    }
    Ok(())
}

#[derive(Clone, Debug, Parser)]
#[command(
    name = "arb-reth recover",
    about = "Stopped bounded trusted-L2 incident recovery"
)]
pub struct RecoverArgs {
    #[arg(long, value_name = "PATH")]
    datadir: PathBuf,
    #[arg(long, value_name = "URL")]
    canonical_l2_rpc: String,
    #[arg(long, value_name = "URL")]
    l1_rpc: String,
    #[arg(long, value_name = "URL")]
    l1_beacon: String,
    #[arg(long, value_name = "BLOCK")]
    l1_end_block: u64,
    #[arg(long, value_name = "BLOCK")]
    max_recovery_l2_blocks: u64,
    #[arg(long = "snapshot-head", value_name = "PATH", conflicts_with_all = ["chain_info", "genesis_json"])]
    snapshot_head: Option<PathBuf>,
    #[arg(long = "chain-info", value_name = "PATH", requires = "genesis_json")]
    chain_info: Option<PathBuf>,
    #[arg(long = "genesis", value_name = "PATH", requires = "chain_info")]
    genesis_json: Option<PathBuf>,
    /// Required for snapshot-head boot, and must match the incident's effective chain id.
    #[arg(long, value_name = "CHAIN_ID")]
    chain_id: Option<u64>,
    #[arg(long, default_value_t = 6)]
    l1_prefetch: u64,
    #[arg(long, default_value_t = 1_000)]
    l1_getlogs_range: u64,
}

#[derive(Clone)]
struct Boot {
    resolved: ResolvedRollupBoot,
    genesis_hash: B256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Prepared,
    Unwound,
    ResumeTruncated,
    FrontierMatched,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryIdentity {
    chain_id: u64,
    genesis_block: u64,
    genesis_hash: B256,
    sequencer_inbox: Address,
    bridge: Address,
    canonical_l2_rpc: String,
    l1_rpc: String,
    l1_beacon: String,
    l1_end_block: u64,
    max_recovery_l2_blocks: u64,
    l1_prefetch: u64,
    l1_getlogs_range: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryJournal {
    schema_version: u32,
    identity: RecoveryIdentity,
    incident: Incident,
    checkpoint: L1ResumeCheckpoint,
    /// The exact strict resume-log prefix retained by recovery. This is immutable so a restart
    /// after the durable replacement can validate the file without the removed suffix.
    truncated_resume: L1ResumeLog,
    original_tip: u64,
    target: u64,
    frontier: u64,
    phase: Phase,
}

fn journal_path(datadir: &Path) -> PathBuf {
    datadir.join(JOURNAL_DIR).join(JOURNAL_FILE)
}

fn strict_journal(path: &Path) -> eyre::Result<Option<RecoveryJournal>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path)?;
    let journal: RecoveryJournal = serde_json::from_slice(&bytes)?;
    if journal.schema_version != 2 {
        return Err(eyre::eyre!(
            "unsupported recovery journal schema version {} (recovery journals are schema-v2)",
            journal.schema_version
        ));
    }
    Ok(Some(journal))
}

fn unique_temp(dir: &Path, stem: &str) -> PathBuf {
    dir.join(format!(
        ".{stem}-{}-{}.tmp",
        std::process::id(),
        unique_suffix()
    ))
}

fn unique_suffix() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

fn write_journal_temp(temp: &Path, journal: &RecoveryJournal) -> eyre::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(temp)?;
    file.write_all(&serde_json::to_vec(journal)?)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

/// Create the immutable initial journal without replacing a concurrent creator.
fn create_journal(path: &Path, journal: &RecoveryJournal) -> eyre::Result<RecoveryJournal> {
    let dir = path
        .parent()
        .ok_or_else(|| eyre::eyre!("recovery journal has no parent"))?;
    fs::create_dir_all(dir)?;
    let temp = unique_temp(dir, "recovery");
    let result = (|| -> eyre::Result<RecoveryJournal> {
        write_journal_temp(&temp, journal)?;
        match fs::hard_link(&temp, path) {
            Ok(()) => {
                File::open(dir)?.sync_all()?;
                Ok(journal.clone())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = strict_journal(path)?
                    .ok_or_else(|| eyre::eyre!("journal disappeared during creation"))?;
                if existing != *journal {
                    return Err(eyre::eyre!(
                        "concurrent recovery created a different immutable journal"
                    ));
                }
                Ok(existing)
            }
            Err(error) => Err(error.into()),
        }
    })();
    let _ = fs::remove_file(&temp);
    let _ = File::open(dir).and_then(|file| file.sync_all());
    result
}

fn same_immutable_identity(left: &RecoveryJournal, right: &RecoveryJournal) -> bool {
    left.schema_version == right.schema_version
        && left.identity == right.identity
        && left.incident == right.incident
        && left.checkpoint == right.checkpoint
        && left.truncated_resume == right.truncated_resume
        && left.original_tip == right.original_tip
        && left.target == right.target
        && left.frontier == right.frontier
}

fn legal_phase_transition(from: Phase, to: Phase) -> bool {
    from == to
        || matches!(
            (from, to),
            (Phase::Prepared, Phase::Unwound | Phase::Failed)
                | (Phase::Unwound, Phase::ResumeTruncated | Phase::Failed)
                | (
                    Phase::ResumeTruncated,
                    Phase::FrontierMatched | Phase::Failed
                )
        )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DurableTipAction {
    UnwindToTarget,
    AtTarget,
    VerifyFrontier,
}

/// Decide from the durable journal and database tip only.  This is deliberately separate from
/// the destructive action so every restart point has one auditable, fail-closed interpretation.
fn durable_tip_action(journal: &RecoveryJournal, tip: u64) -> eyre::Result<DurableTipAction> {
    match journal.phase {
        Phase::Prepared if tip >= journal.target => Ok(if tip > journal.target {
            DurableTipAction::UnwindToTarget
        } else {
            DurableTipAction::AtTarget
        }),
        Phase::Unwound if tip == journal.target => Ok(DurableTipAction::AtTarget),
        Phase::ResumeTruncated if tip == journal.target => Ok(DurableTipAction::AtTarget),
        Phase::ResumeTruncated if tip > journal.target && tip < journal.frontier => {
            Ok(DurableTipAction::UnwindToTarget)
        }
        Phase::ResumeTruncated if tip == journal.frontier => Ok(DurableTipAction::VerifyFrontier),
        Phase::FrontierMatched if tip == journal.frontier => Ok(DurableTipAction::VerifyFrontier),
        Phase::Failed => Err(eyre::eyre!("recovery journal is terminally failed")),
        _ => Err(eyre::eyre!(
            "database tip {tip} is incompatible with recovery phase {:?} and bounds {}..={}",
            journal.phase,
            journal.target,
            journal.frontier
        )),
    }
}

/// A non-blocking advisory lock held for the entire destructive recovery state machine. Closing
/// the file releases it automatically after a crash; the pathname itself carries no ownership.
struct RecoveryLock(File);

impl RecoveryLock {
    fn acquire(datadir: &Path) -> eyre::Result<Self> {
        let dir = datadir.join(JOURNAL_DIR);
        fs::create_dir_all(&dir)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join(RECOVERY_LOCK_FILE))?;
        #[cfg(unix)]
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == -1 {
            return Err(eyre::eyre!(
                "another recovery process holds the datadir recovery lock: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self(file))
    }
}

impl Drop for RecoveryLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            let _ = libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// Update only the phase of an already-published, identity-verified journal.
fn save_journal(path: &Path, journal: &RecoveryJournal) -> eyre::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| eyre::eyre!("recovery journal has no parent"))?;
    let current = strict_journal(path)?
        .ok_or_else(|| eyre::eyre!("recovery journal disappeared before phase update"))?;
    if !same_immutable_identity(&current, journal) {
        return Err(eyre::eyre!(
            "recovery journal immutable identity changed before phase update"
        ));
    }
    if !legal_phase_transition(current.phase, journal.phase) {
        return Err(eyre::eyre!(
            "illegal recovery journal phase transition {:?} -> {:?}",
            current.phase,
            journal.phase
        ));
    }
    #[cfg(test)]
    inject_fault(FaultPoint::BeforeResumePhaseSave)?;
    let temp = unique_temp(dir, "recovery");
    let result = (|| -> eyre::Result<()> {
        write_journal_temp(&temp, journal)?;
        fs::rename(&temp, path)?;
        File::open(dir)?.sync_all()?;
        Ok(())
    })();
    let _ = fs::remove_file(&temp);
    result
}

fn boot(args: &RecoverArgs, incident: &Incident) -> eyre::Result<Boot> {
    match (&args.snapshot_head, &args.chain_info, &args.genesis_json) {
        (Some(head), None, None) => {
            let chain_id = args.chain_id.ok_or_else(|| eyre::eyre!("--snapshot-head requires explicit --chain-id"))?;
            if chain_id != crate::ARB_ONE_CHAIN_ID {
                return Err(eyre::eyre!(
                    "--snapshot-head recovery only supports Arbitrum One chain id {}",
                    crate::ARB_ONE_CHAIN_ID
                ));
            }
            let (genesis, hash, header) = crate::read_head_header(head)?;
            let spec = crate::arb_chain_spec_with_header(chain_id, header, hash);
            Ok(Boot { resolved: ResolvedRollupBoot { chain_spec: spec, chain_id, genesis_block: genesis, sequencer_inbox: arb_reth_l1::SEQUENCER_INBOX_MAINNET, bridge: arb_reth_l1::BRIDGE_MAINNET }, genesis_hash: hash })
        }
        (None, Some(chain_info), Some(genesis)) => {
            let (spec, init, info) = crate::orbit_chain_from_files(&fs::read(chain_info)?, &fs::read(genesis)?)?;
            let chain_id = init.chain_id.to::<u64>();
            if args.chain_id.is_some_and(|id| id != chain_id) { return Err(eyre::eyre!("--chain-id does not match Orbit boot chain id")); }
            let chain_spec = Arc::new(spec);
            Ok(Boot { genesis_hash: chain_spec.genesis_hash(), resolved: ResolvedRollupBoot { chain_spec, chain_id, genesis_block: init.genesis_block_number, sequencer_inbox: info.rollup.sequencer_inbox, bridge: info.rollup.bridge } })
        }
        _ => Err(eyre::eyre!("provide exactly --snapshot-head with --chain-id, or --chain-info together with --genesis")),
    }.and_then(|boot| {
        if boot.resolved.chain_id != incident.effective_chain_id { Err(eyre::eyre!("boot chain id does not match active incident effective chain id")) } else { Ok(boot) }
    })
}

fn observation(number: u64, header: alloy_consensus::Header) -> HeaderObservation {
    HeaderObservation {
        number,
        hash: header.hash_slow(),
        state_root: header.state_root,
    }
}

fn exact(left: HeaderObservation, right: HeaderObservation) -> bool {
    left == right
}

fn validate_http_url(name: &str, value: &str) -> eyre::Result<()> {
    let url = value.parse::<url::Url>()?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(eyre::eyre!("{name} must use HTTP(S) with a host"));
    }
    Ok(())
}

fn validate_finite_inputs(args: &RecoverArgs, checkpoint: L1ResumeCheckpoint) -> eyre::Result<()> {
    validate_http_url("--l1-rpc", &args.l1_rpc)?;
    validate_http_url("--l1-beacon", &args.l1_beacon)?;
    if args.l1_end_block < checkpoint.l1_block {
        return Err(eyre::eyre!(
            "--l1-end-block is before the selected checkpoint L1 block"
        ));
    }
    Ok(())
}

async fn choose_checkpoint(
    log: &L1ResumeLog,
    incident: &Incident,
    canonical: &CanonicalL2Client,
    local: &StaticFileProvider<arbitrum_alloy_consensus::reth::ArbPrimitives>,
    max_span: u64,
) -> eyre::Result<L1ResumeCheckpoint> {
    for checkpoint in log
        .checkpoints
        .iter()
        .rev()
        .copied()
        .filter(|cp| cp.l2_block < incident.l2_block_number)
    {
        let Some(header) = local.header_by_number(checkpoint.l2_block)? else {
            continue;
        };
        let local = observation(checkpoint.l2_block, header);
        if exact(local, canonical.header(checkpoint.l2_block).await?) {
            let span = incident
                .l2_block_number
                .checked_sub(checkpoint.l2_block)
                .ok_or_else(|| eyre::eyre!("checkpoint is above incident"))?;
            if span > max_span {
                return Err(eyre::eyre!(
                    "selected recovery span {span} exceeds --max-recovery-l2-blocks {max_span}"
                ));
            }
            return Ok(checkpoint);
        }
    }
    Err(eyre::eyre!(
        "no exact canonical resume checkpoint exists below incident frontier"
    ))
}

fn recovery_identity(args: &RecoverArgs, boot: &Boot) -> RecoveryIdentity {
    RecoveryIdentity {
        chain_id: boot.resolved.chain_id,
        genesis_block: boot.resolved.genesis_block,
        genesis_hash: boot.genesis_hash,
        sequencer_inbox: boot.resolved.sequencer_inbox,
        bridge: boot.resolved.bridge,
        canonical_l2_rpc: args.canonical_l2_rpc.clone(),
        l1_rpc: args.l1_rpc.clone(),
        l1_beacon: args.l1_beacon.clone(),
        l1_end_block: args.l1_end_block,
        max_recovery_l2_blocks: args.max_recovery_l2_blocks,
        l1_prefetch: args.l1_prefetch,
        l1_getlogs_range: args.l1_getlogs_range,
    }
}

/// Opening is non-mutating. Consistency healing must happen only after a journal exists.
fn open_factory(datadir: &Path, boot: &Boot) -> eyre::Result<(reth_db::DatabaseEnv, Factory)> {
    for component in ["db", "static_files", "rocksdb"] {
        let path = datadir.join(component);
        if !path.is_dir() {
            return Err(eyre::eyre!(
                "recovery requires existing {} directory {}",
                component,
                path.display()
            ));
        }
    }
    let db = init_db(
        datadir.join("db"),
        DatabaseArguments::new(ClientVersion::default()),
    )?;
    let static_files = StaticFileProvider::read_write(datadir.join("static_files"))?;
    let rocks = RocksDBProvider::builder(datadir.join("rocksdb"))
        .with_default_tables()
        .build()
        .map_err(|error| eyre::eyre!("RocksDB open error: {error}"))?;
    let factory = ProviderFactory::new(
        db.clone(),
        boot.resolved.chain_spec.clone(),
        static_files,
        rocks,
        Runtime::test(),
    )?;
    Ok((db, factory))
}

fn node_config(datadir: &Path, chain: Arc<ChainSpec>) -> NodeConfig<ChainSpec> {
    NodeConfig::test()
        .with_chain(chain)
        .with_datadir_args(DatadirArgs {
            datadir: MaybePlatformPath::from(datadir.to_path_buf()),
            ..Default::default()
        })
}

/// Execute the journal-bound destructive unwind and prove its target after a fresh storage-v2
/// reopen. `None` means the journal already represents a durable frontier that needs canonical
/// verification rather than an unwind.
fn unwind_and_reopen(
    datadir: &Path,
    boot: &Boot,
    path: &Path,
    journal: &mut RecoveryJournal,
) -> eyre::Result<Option<(reth_db::DatabaseEnv, Factory)>> {
    let (db, factory) = open_factory(datadir, boot)?;
    super::rewind::require_storage_v2_consistency(&factory)?;
    let tip = factory.provider()?.last_block_number()?;
    let action = durable_tip_action(journal, tip)?;
    if action == DurableTipAction::VerifyFrontier {
        drop(factory);
        drop(db);
        return Ok(None);
    }
    if action == DurableTipAction::UnwindToTarget {
        let result = (|| -> eyre::Result<()> {
            let rw = factory.database_provider_rw()?;
            rw.remove_block_and_execution_above(journal.target)?;
            rw.commit()?;
            Ok(())
        })();
        if let Err(error) = result {
            return Err(persist_terminal_failure(path, journal, error).unwrap_err());
        }
        #[cfg(test)]
        inject_fault(FaultPoint::AfterUnwindCommit)?;
    }
    drop(factory);
    drop(db);

    let (db, factory) = open_factory(datadir, boot)?;
    super::rewind::require_storage_v2_consistency(&factory)?;
    let reopened_tip = factory.provider()?.last_block_number()?;
    if reopened_tip != journal.target {
        let target = journal.target;
        return Err(persist_terminal_failure(
            path,
            journal,
            eyre::eyre!("unwind reopened at {reopened_tip}, expected {target}"),
        )
        .unwrap_err());
    }
    if journal.phase == Phase::Prepared {
        journal.phase = Phase::Unwound;
        save_journal(path, journal)?;
    }
    Ok(Some((db, factory)))
}

fn is_authority_error(error: &eyre::Report) -> bool {
    error.downcast_ref::<RecoveryAuthorityError>().is_some()
}

async fn verify_durable_frontier(
    datadir: &Path,
    boot: &Boot,
    journal: &RecoveryJournal,
    canonical: &CanonicalL2Client,
) -> eyre::Result<()> {
    let (db, factory) = open_factory(datadir, boot)?;
    let provider = factory.provider()?;
    let tip = provider.last_block_number()?;
    let header = provider
        .header_by_number(journal.frontier)?
        .ok_or_else(|| eyre::eyre!("durable frontier header is missing"))?;
    drop(provider);
    drop(factory);
    drop(db);
    if tip != journal.frontier {
        return Err(eyre::eyre!(
            "durable local tip {tip} does not equal recovery frontier {}",
            journal.frontier
        ));
    }
    if !exact(
        observation(journal.frontier, header),
        canonical.header(journal.frontier).await?,
    ) {
        return Err(eyre::eyre!(
            "durable local frontier does not match canonical authority"
        ));
    }
    Ok(())
}

fn persist_terminal_failure(
    path: &Path,
    journal: &mut RecoveryJournal,
    cause: eyre::Report,
) -> eyre::Result<()> {
    journal.phase = Phase::Failed;
    save_journal(path, journal).map_err(|error| {
        eyre::eyre!("{cause}; additionally failed to durably record recovery failure: {error}")
    })?;
    Err(cause)
}

/// Derive the immutable retained prefix from a strict pre-mutation log.
fn truncated_resume_from(
    log: &L1ResumeLog,
    checkpoint: L1ResumeCheckpoint,
) -> eyre::Result<L1ResumeLog> {
    let mut truncated = log.clone();
    truncated.truncate_to(checkpoint.l2_block);
    if truncated.checkpoints.last().copied() != Some(checkpoint) {
        return Err(eyre::eyre!(
            "strict resume log no longer retains selected checkpoint"
        ));
    }
    Ok(truncated)
}

/// Make the journal-bound resume prefix durable before publishing `ResumeTruncated`.
///
/// A restart after the replacement but before the phase write has only the retained prefix in
/// memory. The immutable journal supplies the expected exact vector, while deriving the current
/// prefix proves that the strict input is either the original compatible log or that prefix.
fn durably_truncate_resume(
    log: &L1ResumeLog,
    resume_path: &Path,
    journal_path: &Path,
    journal: &mut RecoveryJournal,
) -> eyre::Result<()> {
    let expected = &journal.truncated_resume;
    let derived = truncated_resume_from(log, journal.checkpoint)?;
    if &derived != expected {
        return persist_terminal_failure(
            journal_path,
            journal,
            eyre::eyre!("strict resume log does not match journal-bound truncation"),
        );
    }

    match journal.phase {
        Phase::Unwound => {
            if log != expected
                && let Err(error) = expected.save(resume_path)
            {
                return persist_terminal_failure(journal_path, journal, error.into());
            }
            let durable = match L1ResumeLog::load_strict(resume_path).map_err(|error| {
                eyre::eyre!(
                    "strict recovery resume log {}: {error}",
                    resume_path.display()
                )
            }) {
                Ok(durable) => durable,
                Err(error) => return persist_terminal_failure(journal_path, journal, error),
            };
            if durable != *expected {
                return persist_terminal_failure(
                    journal_path,
                    journal,
                    eyre::eyre!("durable resume log does not equal journal-bound truncation"),
                );
            }
            #[cfg(test)]
            inject_fault(FaultPoint::AfterResumeDurableSave)?;
            let mut next = journal.clone();
            next.phase = Phase::ResumeTruncated;
            save_journal(journal_path, &next)?;
            *journal = next;
            Ok(())
        }
        Phase::ResumeTruncated => {
            let durable = L1ResumeLog::load_strict(resume_path).map_err(|error| {
                eyre::eyre!(
                    "strict recovery resume log {}: {error}",
                    resume_path.display()
                )
            });
            match durable {
                Ok(durable) if durable == *expected => Ok(()),
                Ok(_) => persist_terminal_failure(
                    journal_path,
                    journal,
                    eyre::eyre!("durable resume log does not equal journal-bound truncation"),
                ),
                Err(error) => persist_terminal_failure(journal_path, journal, error),
            }
        }
        phase => Err(eyre::eyre!(
            "cannot truncate resume log from recovery phase {phase:?}"
        )),
    }
}

async fn preflight(
    args: &RecoverArgs,
) -> eyre::Result<(Boot, Incident, CanonicalL2Client, L1ResumeLog)> {
    if args.max_recovery_l2_blocks == 0 {
        return Err(eyre::eyre!("--max-recovery-l2-blocks must be nonzero"));
    }
    if args.l1_prefetch == 0 || args.l1_getlogs_range == 0 {
        return Err(eyre::eyre!("L1 recovery bounds must be nonzero"));
    }
    let incident = load_active_incident(&args.datadir)?;
    let boot = boot(args, &incident)?;
    let log_path = L1ResumeLog::path_in(&args.datadir);
    let log = L1ResumeLog::load_strict(&log_path).map_err(|error| {
        eyre::eyre!("strict recovery resume log {}: {error}", log_path.display())
    })?;
    let canonical =
        CanonicalL2Client::connect(&args.canonical_l2_rpc, boot.resolved.chain_id).await?;
    let frontier = canonical.header(incident.l2_block_number).await?;
    if frontier.hash != incident.canonical_hash
        || frontier.state_root != incident.canonical_state_root
    {
        return Err(RecoveryAuthorityError::Mismatch(
            "canonical incident frontier no longer matches active incident authority".into(),
        )
        .into());
    }
    Ok((boot, incident, canonical, log))
}

/// Production recovery always uses the real bounded L1 synchronizer.
pub async fn run(args: RecoverArgs) -> eyre::Result<()> {
    run_inner(args, |reth, boot, finite| {
        run_stopped_finite(reth, boot, finite)
    })
    .await
}

/// Test-only seam: all authority, journal, rewind, and verification behavior remains production
/// code; only the finite L1 producer may be substituted.
#[cfg(test)]
async fn run_with_deps<P, F>(args: RecoverArgs, finite_runner: P) -> eyre::Result<()>
where
    P: FnOnce(StoppedFiniteRethLaunch, ResolvedRollupBoot, StoppedFiniteConfig) -> F,
    F: std::future::Future<Output = eyre::Result<HeaderObservation>>,
{
    run_inner(args, finite_runner).await
}

async fn run_inner<P, F>(args: RecoverArgs, finite_runner: P) -> eyre::Result<()>
where
    P: FnOnce(StoppedFiniteRethLaunch, ResolvedRollupBoot, StoppedFiniteConfig) -> F,
    F: std::future::Future<Output = eyre::Result<HeaderObservation>>,
{
    run_inner_with_before_lock(args, finite_runner, || {}).await
}

async fn run_inner_with_before_lock<P, F, H>(
    args: RecoverArgs,
    finite_runner: P,
    before_lock: H,
) -> eyre::Result<()>
where
    P: FnOnce(StoppedFiniteRethLaunch, ResolvedRollupBoot, StoppedFiniteConfig) -> F,
    F: std::future::Future<Output = eyre::Result<HeaderObservation>>,
    H: FnOnce(),
{
    // Check an existing immutable identity before contacting any caller-supplied authority. This
    // prevents a restart from silently switching canonical or L1 sources after a crash.
    let path = journal_path(&args.datadir);
    let initial_incident = load_active_incident(&args.datadir)?;
    let initial_boot = boot(&args, &initial_incident)?;
    let initial_journal = strict_journal(&path)?;
    if let Some(existing) = &initial_journal
        && (existing.incident != initial_incident
            || existing.identity != recovery_identity(&args, &initial_boot))
    {
        return Err(eyre::eyre!(
            "recovery inputs do not match the immutable journal identity"
        ));
    }
    if initial_journal
        .as_ref()
        .is_some_and(|journal| journal.phase == Phase::Failed)
    {
        return Err(eyre::eyre!(
            "recovery journal is marked failed; inspect it before a new recovery"
        ));
    }
    let (boot, incident, canonical, log) = preflight(&args).await?;
    let resume_path = L1ResumeLog::path_in(&args.datadir);
    let static_read =
        StaticFileProvider::<arbitrum_alloy_consensus::reth::ArbPrimitives>::read_only(
            args.datadir.join("static_files"),
        )?;
    let genesis = static_read
        .header_by_number(boot.resolved.genesis_block)?
        .ok_or_else(|| eyre::eyre!("boot genesis header is missing locally"))?;
    if genesis.hash_slow() != boot.resolved.chain_spec.genesis_hash() {
        return Err(eyre::eyre!(
            "local genesis hash does not match resolved chain boot"
        ));
    }
    let checkpoint = match &initial_journal {
        Some(existing) => existing.checkpoint,
        None => {
            choose_checkpoint(
                &log,
                &incident,
                &canonical,
                &static_read,
                args.max_recovery_l2_blocks,
            )
            .await?
        }
    };
    let local_checkpoint = static_read
        .header_by_number(checkpoint.l2_block)?
        .ok_or_else(|| eyre::eyre!("selected recovery checkpoint header is missing locally"))?;
    if !exact(
        observation(checkpoint.l2_block, local_checkpoint),
        canonical.header(checkpoint.l2_block).await?,
    ) {
        return Err(eyre::eyre!(
            "selected recovery checkpoint no longer matches canonical authority"
        ));
    }
    let span = incident
        .l2_block_number
        .checked_sub(checkpoint.l2_block)
        .filter(|span| *span > 0)
        .ok_or_else(|| {
            eyre::eyre!("selected checkpoint is not strictly below incident frontier")
        })?;
    if span > args.max_recovery_l2_blocks {
        return Err(eyre::eyre!(
            "selected recovery span {span} exceeds --max-recovery-l2-blocks {}",
            args.max_recovery_l2_blocks
        ));
    }
    validate_finite_inputs(&args, checkpoint)?;
    drop(static_read);

    // All caller-controlled authority and bound validation above is non-mutating. Only now may
    // recovery create its advisory-lock pathname. The re-reads below are authoritative: no
    // preflight incident, resume prefix, or checkpoint may cross this mutation boundary stale.
    before_lock();
    let _recovery_lock = RecoveryLock::acquire(&args.datadir)?;
    let locked_incident = load_active_incident(&args.datadir)?;
    if locked_incident != incident {
        return Err(eyre::eyre!(
            "active incident changed before lock acquisition; refusing recovery"
        ));
    }
    let locked_log = L1ResumeLog::load_strict(&resume_path).map_err(|error| {
        eyre::eyre!(
            "strict recovery resume log {} after lock acquisition: {error}",
            resume_path.display()
        )
    })?;
    if locked_log != log {
        return Err(eyre::eyre!(
            "recovery resume log changed before lock acquisition; refusing recovery"
        ));
    }
    let mut journal = strict_journal(&path)?;
    if initial_journal.is_some() && journal.is_none() {
        return Err(eyre::eyre!(
            "recovery journal disappeared before lock acquisition; refusing recovery"
        ));
    }
    if let Some(existing) = &journal {
        if existing.incident != locked_incident {
            return Err(eyre::eyre!(
                "recovery journal names a different active incident; refusing target reselection"
            ));
        }
        if existing.identity != recovery_identity(&args, &boot) {
            return Err(eyre::eyre!(
                "recovery inputs do not match the immutable journal identity"
            ));
        }
        if existing.phase == Phase::Failed {
            return Err(eyre::eyre!(
                "recovery journal is marked failed; inspect it before a new recovery"
            ));
        }
        if existing.checkpoint != checkpoint
            || existing.target != checkpoint.l2_block
            || existing.frontier != locked_incident.l2_block_number
            || existing.truncated_resume != truncated_resume_from(&locked_log, checkpoint)?
        {
            return Err(eyre::eyre!(
                "recovery journal changed before lock acquisition; refusing target reselection"
            ));
        }
    }
    let (db, factory) = open_factory(&args.datadir, &boot)?;
    let tip = factory.provider()?.last_block_number()?;
    // Only the initial incident has the original-tip preflight. Once an immutable journal exists,
    // its phase defines which crash boundary the durable tip is allowed to represent.
    if journal.is_none() && tip < locked_incident.l2_block_number {
        return Err(eyre::eyre!(
            "database tip {tip} is below incident frontier {}; refusing initial recovery",
            locked_incident.l2_block_number
        ));
    }
    if checkpoint.l2_block < boot.resolved.genesis_block {
        return Err(eyre::eyre!("selected checkpoint is below boot genesis"));
    }
    if let Some(existing) = &journal {
        if existing.target != checkpoint.l2_block || existing.frontier != incident.l2_block_number {
            return Err(eyre::eyre!(
                "recovery journal target does not match its checkpoint/frontier"
            ));
        }
    } else {
        let created = RecoveryJournal {
            schema_version: 2,
            identity: recovery_identity(&args, &boot),
            incident: locked_incident,
            checkpoint,
            truncated_resume: truncated_resume_from(&locked_log, checkpoint)?,
            original_tip: tip,
            target: checkpoint.l2_block,
            frontier: locked_incident.l2_block_number,
            phase: Phase::Prepared,
        };
        journal = Some(create_journal(&path, &created)?);
    }
    let mut journal = journal.expect("journal persisted or loaded");
    drop(factory);
    drop(db);
    let Some((db, factory)) = unwind_and_reopen(&args.datadir, &boot, &path, &mut journal)? else {
        // A finite launcher may have committed the frontier before its success phase was saved.
        // Treat that exact durable state as a fresh verification point, never as presumed success.
        if let Err(error) =
            verify_durable_frontier(&args.datadir, &boot, &journal, &canonical).await
        {
            // Canonical RPC transport/protocol failures do not prove a local integrity loss.
            if is_authority_error(&error) {
                return Err(error);
            }
            if journal.phase == Phase::ResumeTruncated {
                return persist_terminal_failure(&path, &mut journal, error);
            }
            return Err(error);
        }
        if journal.phase == Phase::ResumeTruncated {
            journal.phase = Phase::FrontierMatched;
            return save_journal(&path, &journal);
        }
        return Ok(());
    };
    durably_truncate_resume(&locked_log, &resume_path, &path, &mut journal)?;
    drop(factory);
    let mut sync =
        L1SyncConfig::mainnet(args.l1_rpc, checkpoint.l1_block, checkpoint.delayed_count);
    sync.sequencer_inbox = boot.resolved.sequencer_inbox;
    sync.bridge = boot.resolved.bridge;
    sync.l1_beacon = Some(args.l1_beacon);
    sync.end_block = Some(args.l1_end_block);
    sync.prefetch_windows = args.l1_prefetch;
    sync.batch_window = args.l1_getlogs_range;
    sync.delayed_window = args.l1_getlogs_range;
    sync.start_l2_block = checkpoint.l2_block;
    sync.db_tip_l2 = checkpoint.l2_block;
    sync.genesis_block = boot.resolved.genesis_block;
    sync.l2_frontier = Some(journal.frontier);
    let rebuilt = {
        let runtime = Runtime::test();
        let result = finite_runner(
            StoppedFiniteRethLaunch::new(
                node_config(&args.datadir, boot.resolved.chain_spec.clone()),
                db,
                runtime.clone(),
            ),
            boot.resolved.clone(),
            StoppedFiniteConfig {
                checkpoint,
                l1_sync: sync,
                frontier: journal.frontier,
            },
        )
        .await;
        // Stage3C finite completion joins all launch-owned resources before returning, so recovery
        // retains no lifecycle ownership beyond awaiting this result.
        result
    };
    let rebuilt = match rebuilt {
        Ok(header) => header,
        // L1/beacon transport and finite execution failures are retryable with the immutable
        // journal identity. They are not proof that either authority or local state is corrupt.
        Err(error) => return Err(error),
    };
    #[cfg(test)]
    inject_fault(FaultPoint::AfterFiniteCompletion)?;
    let canonical_frontier = match canonical.header(journal.frontier).await {
        Ok(header) => header,
        // A canonical outage is likewise retryable, not a terminal integrity result.
        Err(error) => return Err(error.into()),
    };
    if !exact(rebuilt, canonical_frontier) {
        return persist_terminal_failure(
            &path,
            &mut journal,
            eyre::eyre!("rebuilt frontier does not match canonical hash/state root"),
        );
    }
    // The launcher result is only an in-memory observation. Reopen and compare the actual durable
    // local frontier after all finite tasks have exited before publishing success.
    if let Err(error) = verify_durable_frontier(&args.datadir, &boot, &journal, &canonical).await {
        // A malformed or unavailable canonical RPC is retryable; a successfully observed
        // canonical/local mismatch remains a terminal integrity failure.
        if is_authority_error(&error) {
            return Err(error);
        }
        return persist_terminal_failure(&path, &mut journal, error);
    }
    journal.phase = Phase::FrontierMatched;
    save_journal(&path, &journal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use clap::Parser;
    use std::{
        collections::BTreeMap,
        io::{Read, Write},
        net::{Ipv4Addr, Shutdown, TcpListener},
        sync::{
            Arc, Barrier, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread,
        time::Duration,
    };
    use tempfile::tempdir;

    static RECOVERY_FAULT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn incident() -> Incident {
        Incident {
            schema_version: 1,
            effective_chain_id: 1,
            l2_block_number: 10,
            local_hash: B256::ZERO,
            canonical_hash: B256::ZERO,
            local_state_root: B256::ZERO,
            canonical_state_root: B256::ZERO,
            detected_at_unix_secs: 0,
        }
    }
    fn cp(l2_block: u64) -> L1ResumeCheckpoint {
        L1ResumeCheckpoint {
            l1_block: 1,
            delayed_count: 0,
            l2_block,
        }
    }

    #[test]
    fn journal_is_strict_and_never_deleted() {
        let dir = tempdir().unwrap();
        let path = journal_path(dir.path());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, br#"{"schema_version":1,"extra":true}"#).unwrap();
        assert!(strict_journal(&path).is_err());
        assert!(path.exists());
    }
    #[test]
    fn recover_cli_requires_authority_and_rejects_zero_bound() {
        assert!(RecoverArgs::try_parse_from(["recover"]).is_err());
        let parsed = RecoverArgs::try_parse_from([
            "recover",
            "--datadir",
            "/d",
            "--canonical-l2-rpc",
            "http://l2",
            "--l1-rpc",
            "http://l1",
            "--l1-beacon",
            "http://beacon",
            "--l1-end-block",
            "1",
            "--max-recovery-l2-blocks",
            "0",
            "--snapshot-head",
            "/head",
            "--chain-id",
            "1",
        ])
        .unwrap();
        assert_eq!(parsed.max_recovery_l2_blocks, 0);
    }
    #[test]
    fn strict_incident_rejects_unknown_fields_without_removing_marker() {
        let dir = tempdir().unwrap();
        let marker = dir.path().join("arb-trusted-l2/active.json");
        fs::create_dir_all(marker.parent().unwrap()).unwrap();
        fs::write(&marker, br#"{"schema_version":1,"effective_chain_id":1,"l2_block_number":1,"local_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","canonical_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","local_state_root":"0x0000000000000000000000000000000000000000000000000000000000000000","canonical_state_root":"0x0000000000000000000000000000000000000000000000000000000000000000","detected_at_unix_secs":0,"extra":true}"#).unwrap();
        assert!(load_active_incident(dir.path()).is_err());
        assert!(marker.exists());
    }

    #[test]
    fn strict_resume_rejects_legacy_shape() {
        let dir = tempdir().unwrap();
        let path = L1ResumeLog::path_in(dir.path());
        fs::write(path, br#"{"l1_block":1,"delayed_count":0,"l2_block":1}"#).unwrap();
        assert!(L1ResumeLog::load_strict(&L1ResumeLog::path_in(dir.path())).is_err());
    }
    #[test]
    fn recovery_cli_rejects_ordinary_serving_sources() {
        for flag in ["--feed-url", "--replay-feed", "--http", "--mev-tx-log-ipc"] {
            let mut argv = vec![
                "recover",
                "--datadir",
                "/d",
                "--canonical-l2-rpc",
                "http://l2",
                "--l1-rpc",
                "http://l1",
                "--l1-beacon",
                "http://beacon",
                "--l1-end-block",
                "1",
                "--max-recovery-l2-blocks",
                "1",
                "--snapshot-head",
                "/head",
                "--chain-id",
                "1",
                flag,
            ];
            if matches!(flag, "--feed-url" | "--replay-feed" | "--mev-tx-log-ipc") {
                argv.push("x");
            }
            assert!(
                RecoverArgs::try_parse_from(argv).is_err(),
                "{flag} must not be accepted"
            );
        }
    }

    #[test]
    fn finite_inputs_reject_unbounded_or_invalid_launch_values() {
        let args = RecoverArgs::try_parse_from([
            "recover",
            "--datadir",
            "/d",
            "--canonical-l2-rpc",
            "http://l2",
            "--l1-rpc",
            "ws://l1",
            "--l1-beacon",
            "http://beacon",
            "--l1-end-block",
            "1",
            "--max-recovery-l2-blocks",
            "1",
            "--snapshot-head",
            "/head",
            "--chain-id",
            "1",
        ])
        .unwrap();
        assert!(validate_finite_inputs(&args, cp(1)).is_err());
    }

    fn identity() -> RecoveryIdentity {
        RecoveryIdentity {
            chain_id: 1,
            genesis_block: 0,
            genesis_hash: B256::ZERO,
            sequencer_inbox: Address::ZERO,
            bridge: Address::ZERO,
            canonical_l2_rpc: "http://canonical".into(),
            l1_rpc: "http://l1".into(),
            l1_beacon: "http://beacon".into(),
            l1_end_block: 10,
            max_recovery_l2_blocks: 10,
            l1_prefetch: 1,
            l1_getlogs_range: 1,
        }
    }

    fn journal(phase: Phase) -> RecoveryJournal {
        RecoveryJournal {
            schema_version: 2,
            identity: identity(),
            incident: incident(),
            checkpoint: cp(5),
            truncated_resume: L1ResumeLog {
                checkpoints: vec![cp(2), cp(5)],
            },
            original_tip: 12,
            target: 5,
            frontier: 10,
            phase,
        }
    }

    #[test]
    fn journal_target_is_stable() {
        let j = journal(Phase::Prepared);
        assert_eq!(j.checkpoint.l2_block, j.target);
        assert!(j.target < j.frontier);
    }

    #[test]
    fn initial_journal_creation_never_clobbers_concurrent_target() {
        let dir = tempdir().unwrap();
        let path = journal_path(dir.path());
        let first = journal(Phase::Prepared);
        let mut second = first.clone();
        second.checkpoint = cp(6);
        second.target = 6;
        assert_eq!(create_journal(&path, &first).unwrap(), first);
        assert!(create_journal(&path, &second).is_err());
        assert_eq!(strict_journal(&path).unwrap(), Some(first));
    }

    #[test]
    fn phase_updates_follow_only_the_explicit_transition_table() {
        for from in [
            Phase::Prepared,
            Phase::Unwound,
            Phase::ResumeTruncated,
            Phase::FrontierMatched,
            Phase::Failed,
        ] {
            for to in [
                Phase::Prepared,
                Phase::Unwound,
                Phase::ResumeTruncated,
                Phase::FrontierMatched,
                Phase::Failed,
            ] {
                let dir = tempdir().unwrap();
                let path = journal_path(dir.path());
                let persisted = create_journal(&path, &journal(from)).unwrap();
                let mut candidate = persisted.clone();
                candidate.phase = to;
                assert_eq!(
                    save_journal(&path, &candidate).is_ok(),
                    legal_phase_transition(from, to),
                    "{from:?} -> {to:?}"
                );
            }
        }
        let dir = tempdir().unwrap();
        let path = journal_path(dir.path());
        let mut altered = create_journal(&path, &journal(Phase::Prepared)).unwrap();
        altered.original_tip += 1;
        assert!(save_journal(&path, &altered).is_err());
    }

    #[test]
    fn durable_tip_matrix_covers_each_phase_and_crash_boundary() {
        let cases = [
            (Phase::Prepared, 4, false),
            (Phase::Prepared, 5, true),
            (Phase::Prepared, 7, true),
            (Phase::Prepared, 10, true),
            (Phase::Prepared, 11, true),
            (Phase::Unwound, 4, false),
            (Phase::Unwound, 5, true),
            (Phase::Unwound, 7, false),
            (Phase::Unwound, 10, false),
            (Phase::Unwound, 11, false),
            (Phase::ResumeTruncated, 4, false),
            (Phase::ResumeTruncated, 5, true),
            (Phase::ResumeTruncated, 7, true),
            (Phase::ResumeTruncated, 10, true),
            (Phase::ResumeTruncated, 11, false),
            (Phase::FrontierMatched, 4, false),
            (Phase::FrontierMatched, 5, false),
            (Phase::FrontierMatched, 7, false),
            (Phase::FrontierMatched, 10, true),
            (Phase::FrontierMatched, 11, false),
            (Phase::Failed, 4, false),
            (Phase::Failed, 5, false),
            (Phase::Failed, 7, false),
            (Phase::Failed, 10, false),
            (Phase::Failed, 11, false),
        ];
        for (phase, tip, accepted) in cases {
            assert_eq!(
                durable_tip_action(&journal(phase), tip).is_ok(),
                accepted,
                "{phase:?} tip {tip}"
            );
        }
        assert_eq!(
            durable_tip_action(&journal(Phase::ResumeTruncated), 7).unwrap(),
            DurableTipAction::UnwindToTarget
        );
        assert_eq!(
            durable_tip_action(&journal(Phase::ResumeTruncated), 10).unwrap(),
            DurableTipAction::VerifyFrontier
        );
    }

    #[test]
    fn concurrent_initial_journal_creation_never_clobbers_identity() {
        let dir = tempdir().unwrap();
        let path = journal_path(dir.path());
        let barrier = Arc::new(Barrier::new(2));
        let first = journal(Phase::Prepared);
        let mut second = first.clone();
        second.target = 6;
        second.checkpoint = cp(6);
        let a = {
            let path = path.clone();
            let barrier = barrier.clone();
            let first = first.clone();
            thread::spawn(move || {
                barrier.wait();
                create_journal(&path, &first)
            })
        };
        let b = {
            let path = path.clone();
            let barrier = barrier.clone();
            let second = second.clone();
            thread::spawn(move || {
                barrier.wait();
                create_journal(&path, &second)
            })
        };
        let a = a.join().unwrap();
        let b = b.join().unwrap();
        assert!(a.is_ok() ^ b.is_ok());
        let persisted = strict_journal(&path).unwrap().unwrap();
        assert!(persisted == first || persisted == second);
    }

    #[test]
    fn advisory_lock_is_process_lifetime_and_contended() {
        let dir = tempdir().unwrap();
        let first = RecoveryLock::acquire(dir.path()).unwrap();
        assert!(RecoveryLock::acquire(dir.path()).is_err());
        drop(first);
        assert!(RecoveryLock::acquire(dir.path()).is_ok());
    }

    #[test]
    fn missing_storage_paths_are_rejected_without_creation() {
        let dir = tempdir().unwrap();
        let boot = Boot {
            resolved: ResolvedRollupBoot {
                chain_spec: reth_chainspec::MAINNET.clone(),
                chain_id: 1,
                genesis_block: 0,
                sequencer_inbox: Address::ZERO,
                bridge: Address::ZERO,
            },
            genesis_hash: B256::ZERO,
        };
        assert!(open_factory(dir.path(), &boot).is_err());
        assert!(!dir.path().join("db").exists());
        assert!(!dir.path().join("static_files").exists());
        assert!(!dir.path().join("rocksdb").exists());
    }

    #[test]
    fn journal_identity_rejects_changed_authority_or_bounds_after_crash() {
        let j = journal(Phase::Unwound);
        let mut changed = j.identity.clone();
        changed.l1_end_block += 1;
        assert_ne!(j.identity, changed);
        changed = j.identity.clone();
        changed.sequencer_inbox = Address::from([1; 20]);
        assert_ne!(j.identity, changed);
    }

    fn resume_with_suffix() -> L1ResumeLog {
        L1ResumeLog {
            checkpoints: vec![cp(2), cp(5), cp(9)],
        }
    }

    #[test]
    fn unwound_resume_is_durably_truncated_without_changing_marker() {
        let dir = tempdir().unwrap();
        let marker = dir.path().join("arb-trusted-l2/active.json");
        fs::create_dir_all(marker.parent().unwrap()).unwrap();
        let marker_bytes = b"active incident bytes\n".to_vec();
        fs::write(&marker, &marker_bytes).unwrap();
        let resume_path = L1ResumeLog::path_in(dir.path());
        let resume = resume_with_suffix();
        resume.save(&resume_path).unwrap();
        let path = journal_path(dir.path());
        let mut state = create_journal(&path, &journal(Phase::Unwound)).unwrap();

        durably_truncate_resume(&resume, &resume_path, &path, &mut state).unwrap();

        assert_eq!(
            L1ResumeLog::load_strict(&resume_path).unwrap(),
            state.truncated_resume
        );
        assert_eq!(
            strict_journal(&path).unwrap().unwrap().phase,
            Phase::ResumeTruncated
        );
        assert_eq!(fs::read(marker).unwrap(), marker_bytes);
    }

    #[test]
    fn resume_durable_save_crash_reenters_from_truncated_log() {
        let _fault_guard = RECOVERY_FAULT_TEST_LOCK.lock().unwrap();
        let dir = tempdir().unwrap();
        let resume_path = L1ResumeLog::path_in(dir.path());
        let resume = resume_with_suffix();
        resume.save(&resume_path).unwrap();
        let path = journal_path(dir.path());
        let mut state = create_journal(&path, &journal(Phase::Unwound)).unwrap();

        RECOVERY_FAULT.with(|fault| fault.set(FaultPoint::AfterResumeDurableSave as u8 + 1));
        assert!(durably_truncate_resume(&resume, &resume_path, &path, &mut state).is_err());
        assert_eq!(
            L1ResumeLog::load_strict(&resume_path).unwrap(),
            state.truncated_resume
        );
        assert_eq!(
            strict_journal(&path).unwrap().unwrap().phase,
            Phase::Unwound
        );

        let reloaded = L1ResumeLog::load_strict(&resume_path).unwrap();
        let mut restarted = strict_journal(&path).unwrap().unwrap();
        durably_truncate_resume(&reloaded, &resume_path, &path, &mut restarted).unwrap();
        assert_eq!(restarted.phase, Phase::ResumeTruncated);
        assert_eq!(
            strict_journal(&path).unwrap().unwrap().phase,
            Phase::ResumeTruncated
        );
    }

    #[test]
    fn resume_truncated_requires_exact_durable_file_and_records_integrity_failure() {
        for bad in ["altered", "malformed", "missing"] {
            let dir = tempdir().unwrap();
            let resume_path = L1ResumeLog::path_in(dir.path());
            let path = journal_path(dir.path());
            let mut state = create_journal(&path, &journal(Phase::ResumeTruncated)).unwrap();
            match bad {
                "altered" => L1ResumeLog {
                    checkpoints: vec![cp(2)],
                }
                .save(&resume_path)
                .unwrap(),
                "malformed" => fs::write(&resume_path, b"not json").unwrap(),
                "missing" => {}
                _ => unreachable!(),
            }

            let loaded = state.truncated_resume.clone();
            assert!(durably_truncate_resume(&loaded, &resume_path, &path, &mut state).is_err());
            assert_eq!(
                strict_journal(&path).unwrap().unwrap().phase,
                Phase::Failed,
                "{bad}"
            );
        }

        let dir = tempdir().unwrap();
        let resume_path = L1ResumeLog::path_in(dir.path());
        let path = journal_path(dir.path());
        let mut state = create_journal(&path, &journal(Phase::ResumeTruncated)).unwrap();
        state.truncated_resume.save(&resume_path).unwrap();
        durably_truncate_resume(
            &state.truncated_resume.clone(),
            &resume_path,
            &path,
            &mut state,
        )
        .unwrap();
        assert_eq!(
            strict_journal(&path).unwrap().unwrap().phase,
            Phase::ResumeTruncated
        );
    }

    #[test]
    fn resume_phase_write_failure_is_surfaced_without_phase_regression() {
        let _fault_guard = RECOVERY_FAULT_TEST_LOCK.lock().unwrap();
        let dir = tempdir().unwrap();
        let resume_path = L1ResumeLog::path_in(dir.path());
        let resume = resume_with_suffix();
        resume.save(&resume_path).unwrap();
        let path = journal_path(dir.path());
        let mut state = create_journal(&path, &journal(Phase::Unwound)).unwrap();

        RECOVERY_FAULT.with(|fault| fault.set(FaultPoint::BeforeResumePhaseSave as u8 + 1));
        assert!(durably_truncate_resume(&resume, &resume_path, &path, &mut state).is_err());
        assert_eq!(
            L1ResumeLog::load_strict(&resume_path).unwrap(),
            state.truncated_resume
        );
        assert_eq!(
            strict_journal(&path).unwrap().unwrap().phase,
            Phase::Unwound
        );
    }

    fn fixture_boot(fixture: &crate::finite::test_support::StorageV2Fixture) -> Boot {
        Boot {
            genesis_hash: fixture.boot.chain_spec.genesis_hash(),
            resolved: fixture.boot.clone(),
        }
    }

    fn fixture_journal(phase: Phase, original_tip: u64) -> RecoveryJournal {
        RecoveryJournal {
            schema_version: 2,
            identity: RecoveryIdentity {
                chain_id: 412346,
                genesis_block: 0,
                genesis_hash: B256::ZERO,
                sequencer_inbox: arb_reth_l1::SEQUENCER_INBOX_MAINNET,
                bridge: arb_reth_l1::BRIDGE_MAINNET,
                canonical_l2_rpc: "http://canonical".into(),
                l1_rpc: "http://l1".into(),
                l1_beacon: "http://beacon".into(),
                l1_end_block: 5,
                max_recovery_l2_blocks: 5,
                l1_prefetch: 1,
                l1_getlogs_range: 1,
            },
            incident: Incident {
                schema_version: 1,
                effective_chain_id: 412346,
                l2_block_number: 5,
                local_hash: B256::ZERO,
                canonical_hash: B256::ZERO,
                local_state_root: B256::ZERO,
                canonical_state_root: B256::ZERO,
                detected_at_unix_secs: 0,
            },
            checkpoint: cp(2),
            truncated_resume: L1ResumeLog {
                checkpoints: vec![cp(2)],
            },
            original_tip,
            target: 2,
            frontier: 5,
            phase,
        }
    }

    fn reopened_tip(datadir: &Path, boot: &Boot) -> u64 {
        let (db, factory) = open_factory(datadir, boot).expect("open production factory");
        let provider = factory.provider().expect("open provider");
        let tip = provider.last_block_number().expect("read durable tip");
        drop(provider);
        drop(factory);
        drop(db);
        tip
    }

    fn marker_bytes(datadir: &Path) -> Vec<u8> {
        let path = datadir.join("arb-trusted-l2/active.json");
        let mut bytes = serde_json::to_vec(&Incident {
            schema_version: 1,
            effective_chain_id: 412346,
            l2_block_number: 5,
            local_hash: B256::ZERO,
            canonical_hash: B256::ZERO,
            local_state_root: B256::ZERO,
            canonical_state_root: B256::ZERO,
            detected_at_unix_secs: 0,
        })
        .unwrap();
        bytes.push(b'\n');
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, &bytes).unwrap();
        bytes
    }

    #[derive(Clone)]
    enum RpcReply {
        Header(HeaderObservation),
        Missing,
        Malformed,
        Unavailable,
    }

    #[derive(Clone)]
    enum ChainReply {
        Id(u64),
    }

    struct LoopbackRpc {
        url: String,
        headers: Arc<Mutex<BTreeMap<u64, RpcReply>>>,
        requested_heights: Arc<Mutex<Vec<u64>>>,
        stopped: Arc<AtomicBool>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl LoopbackRpc {
        fn start(chain: ChainReply, headers: BTreeMap<u64, RpcReply>) -> Self {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            listener.set_nonblocking(true).unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let chain = Arc::new(Mutex::new(chain));
            let headers = Arc::new(Mutex::new(headers));
            let requested_heights = Arc::new(Mutex::new(Vec::new()));
            let stopped = Arc::new(AtomicBool::new(false));
            let thread = {
                let chain = chain.clone();
                let headers = headers.clone();
                let requested_heights = requested_heights.clone();
                let stopped = stopped.clone();
                thread::spawn(move || {
                    while !stopped.load(Ordering::Relaxed) {
                        let Ok((mut stream, _)) = listener.accept() else {
                            thread::sleep(Duration::from_millis(2));
                            continue;
                        };
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                        let mut request = Vec::new();
                        let mut chunk = [0_u8; 4096];
                        while let Ok(read) = stream.read(&mut chunk) {
                            if read == 0 {
                                break;
                            }
                            request.extend_from_slice(&chunk[..read]);
                            if let Some(head_end) =
                                request.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                            {
                                let head = String::from_utf8_lossy(&request[..head_end]);
                                let content_length = head
                                    .lines()
                                    .find_map(|line| {
                                        line.strip_prefix("Content-Length: ")
                                            .or_else(|| line.strip_prefix("content-length: "))
                                    })
                                    .and_then(|value| value.parse::<usize>().ok())
                                    .unwrap_or(0);
                                if request.len() >= head_end + 4 + content_length {
                                    break;
                                }
                            }
                        }
                        let body = request
                            .windows(4)
                            .position(|bytes| bytes == b"\r\n\r\n")
                            .map(|index| &request[index + 4..])
                            .unwrap_or_default();
                        let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
                            continue;
                        };
                        let id = value.get("id").cloned().unwrap_or(serde_json::Value::Null);
                        let method = value.get("method").and_then(|method| method.as_str());
                        let reply = match method {
                            Some("eth_chainId") => match chain.lock().unwrap().clone() {
                                ChainReply::Id(id) => Some(serde_json::json!(format!("0x{id:x}"))),
                            },
                            Some("eth_getBlockByNumber") => {
                                let height = value
                                    .get("params")
                                    .and_then(|params| params.get(0))
                                    .and_then(|number| number.as_str())
                                    .and_then(|number| {
                                        u64::from_str_radix(number.trim_start_matches("0x"), 16)
                                            .ok()
                                    });
                                let Some(height) = height else { continue };
                                requested_heights.lock().unwrap().push(height);
                                match headers
                                    .lock()
                                    .unwrap()
                                    .get(&height)
                                    .cloned()
                                    .unwrap_or(RpcReply::Missing)
                                {
                                    RpcReply::Header(header) => Some(serde_json::json!({
                                        "number": format!("0x{:x}", header.number),
                                        "hash": format!("{:#x}", header.hash),
                                        "stateRoot": format!("{:#x}", header.state_root),
                                    })),
                                    RpcReply::Missing => Some(serde_json::Value::Null),
                                    RpcReply::Malformed => {
                                        Some(serde_json::json!({"number": "bad"}))
                                    }
                                    RpcReply::Unavailable => None,
                                }
                            }
                            _ => Some(serde_json::Value::Null),
                        };
                        let Some(result) = reply else {
                            let _ = stream.shutdown(Shutdown::Both);
                            continue;
                        };
                        let body = serde_json::to_vec(
                            &serde_json::json!({"jsonrpc":"2.0", "id":id, "result":result}),
                        )
                        .unwrap();
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(&body);
                    }
                })
            };
            Self {
                url,
                headers,
                requested_heights,
                stopped,
                thread: Some(thread),
            }
        }

        fn set_header(&self, height: u64, reply: RpcReply) {
            self.headers.lock().unwrap().insert(height, reply);
        }
    }

    impl Drop for LoopbackRpc {
        fn drop(&mut self) {
            self.stopped.store(true, Ordering::Relaxed);
            self.thread.take().unwrap().join().unwrap();
        }
    }

    fn local_headers(datadir: &Path, heights: &[u64]) -> BTreeMap<u64, HeaderObservation> {
        let local = StaticFileProvider::<arbitrum_alloy_consensus::reth::ArbPrimitives>::read_only(
            datadir.join("static_files"),
        )
        .unwrap();
        heights
            .iter()
            .filter_map(|height| {
                local
                    .header_by_number(*height)
                    .unwrap()
                    .map(|header| (*height, observation(*height, header)))
            })
            .collect()
    }

    fn snapshot_head(path: &Path) {
        let header = alloy_consensus::Header {
            number: 1,
            ..Default::default()
        };
        let hash = header.hash_slow();
        fs::write(
            path,
            format!(
                "H 1 {hash:#x} {}\n",
                alloy_primitives::hex::encode(alloy_rlp::encode(header))
            ),
        )
        .unwrap();
    }

    fn authority_incident(frontier: HeaderObservation) -> Incident {
        Incident {
            schema_version: 1,
            effective_chain_id: crate::ARB_ONE_CHAIN_ID,
            l2_block_number: frontier.number,
            local_hash: B256::ZERO,
            canonical_hash: frontier.hash,
            local_state_root: B256::ZERO,
            canonical_state_root: frontier.state_root,
            detected_at_unix_secs: 0,
        }
    }

    fn write_strict_preflight_inputs(datadir: &Path, incident: Incident) -> L1ResumeLog {
        let marker = datadir.join("arb-trusted-l2/active.json");
        fs::create_dir_all(marker.parent().unwrap()).unwrap();
        fs::write(&marker, serde_json::to_vec(&incident).unwrap()).unwrap();
        let log = L1ResumeLog {
            checkpoints: vec![cp(1)],
        };
        log.save(&L1ResumeLog::path_in(datadir)).unwrap();
        log
    }

    async fn preflight_error(args: RecoverArgs) -> eyre::Report {
        match preflight(&args).await {
            Ok(_) => panic!("preflight unexpectedly succeeded"),
            Err(error) => error,
        }
    }

    fn preflight_args(datadir: &Path, head: &Path, rpc: String) -> RecoverArgs {
        RecoverArgs {
            datadir: datadir.to_owned(),
            canonical_l2_rpc: rpc,
            l1_rpc: "http://127.0.0.1:8545".into(),
            l1_beacon: "http://127.0.0.1:5052".into(),
            l1_end_block: 1,
            max_recovery_l2_blocks: 1,
            snapshot_head: Some(head.to_owned()),
            chain_info: None,
            genesis_json: None,
            chain_id: Some(crate::ARB_ONE_CHAIN_ID),
            l1_prefetch: 1,
            l1_getlogs_range: 1,
        }
    }

    fn tree_bytes(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        fn visit(root: &Path, path: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for entry in fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let relative = path.strip_prefix(root).unwrap().to_owned();
                if path.is_dir() {
                    out.insert(relative.clone(), Vec::new());
                    visit(root, &path, out);
                } else {
                    out.insert(relative, fs::read(path).unwrap());
                }
            }
        }
        let mut out = BTreeMap::new();
        visit(root, root, &mut out);
        out
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn checkpoint_selection_uses_newest_exact_local_canonical_match() {
        let fixture = crate::finite::test_support::storage_v2_fixture(412346, 2).await;
        let local = local_headers(&fixture.datadir, &[1, 2]);
        let mut canonical = BTreeMap::from([
            (1, RpcReply::Header(local[&1])),
            (
                2,
                RpcReply::Header(HeaderObservation {
                    hash: B256::with_last_byte(9),
                    ..local[&2]
                }),
            ),
        ]);
        canonical.insert(
            4,
            RpcReply::Header(HeaderObservation {
                number: 4,
                hash: B256::with_last_byte(4),
                state_root: B256::with_last_byte(5),
            }),
        );
        let rpc = LoopbackRpc::start(ChainReply::Id(412346), canonical);
        let client = CanonicalL2Client::connect(&rpc.url, 412346).await.unwrap();
        let static_read =
            StaticFileProvider::<arbitrum_alloy_consensus::reth::ArbPrimitives>::read_only(
                fixture.datadir.join("static_files"),
            )
            .unwrap();
        let log = L1ResumeLog {
            checkpoints: vec![cp(1), cp(2), cp(3)],
        };
        let incident = Incident {
            l2_block_number: 4,
            ..incident()
        };

        assert_eq!(
            choose_checkpoint(&log, &incident, &client, &static_read, 3)
                .await
                .unwrap(),
            cp(1)
        );
        assert_eq!(*rpc.requested_heights.lock().unwrap(), vec![2, 1]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn newest_exact_checkpoint_exceeding_span_refuses_without_fallback() {
        let fixture = crate::finite::test_support::storage_v2_fixture(412346, 2).await;
        let local = local_headers(&fixture.datadir, &[1, 2]);
        let rpc = LoopbackRpc::start(
            ChainReply::Id(412346),
            BTreeMap::from([
                (1, RpcReply::Header(local[&1])),
                (2, RpcReply::Header(local[&2])),
            ]),
        );
        let client = CanonicalL2Client::connect(&rpc.url, 412346).await.unwrap();
        let static_read =
            StaticFileProvider::<arbitrum_alloy_consensus::reth::ArbPrimitives>::read_only(
                fixture.datadir.join("static_files"),
            )
            .unwrap();
        let log = L1ResumeLog {
            checkpoints: vec![cp(1), cp(2)],
        };
        let incident = Incident {
            l2_block_number: 4,
            ..incident()
        };

        let error = choose_checkpoint(&log, &incident, &client, &static_read, 1)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("selected recovery span 2 exceeds")
        );
        assert_eq!(*rpc.requested_heights.lock().unwrap(), vec![2]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn authority_failures_remain_typed_and_never_match() {
        let frontier = HeaderObservation {
            number: 1,
            hash: B256::with_last_byte(1),
            state_root: B256::with_last_byte(2),
        };
        let datadir = tempdir().unwrap();
        let head = datadir.path().join("head.stream");
        snapshot_head(&head);
        let incident = authority_incident(frontier);
        write_strict_preflight_inputs(datadir.path(), incident);

        let chain_mismatch = LoopbackRpc::start(ChainReply::Id(1), BTreeMap::new());
        let error = preflight_error(preflight_args(
            datadir.path(),
            &head,
            chain_mismatch.url.clone(),
        ))
        .await;
        assert!(matches!(
            error.downcast_ref::<RecoveryAuthorityError>(),
            Some(RecoveryAuthorityError::Mismatch(_))
        ));

        let frontier_mismatch = LoopbackRpc::start(
            ChainReply::Id(crate::ARB_ONE_CHAIN_ID),
            BTreeMap::from([(
                1,
                RpcReply::Header(HeaderObservation {
                    hash: B256::ZERO,
                    ..frontier
                }),
            )]),
        );
        let error = preflight_error(preflight_args(
            datadir.path(),
            &head,
            frontier_mismatch.url.clone(),
        ))
        .await;
        assert!(matches!(
            error.downcast_ref::<RecoveryAuthorityError>(),
            Some(RecoveryAuthorityError::Mismatch(_))
        ));

        let malformed = LoopbackRpc::start(
            ChainReply::Id(crate::ARB_ONE_CHAIN_ID),
            BTreeMap::from([(1, RpcReply::Malformed)]),
        );
        let error =
            preflight_error(preflight_args(datadir.path(), &head, malformed.url.clone())).await;
        assert!(matches!(
            error.downcast_ref::<RecoveryAuthorityError>(),
            Some(RecoveryAuthorityError::Malformed(_))
        ));

        let unavailable = LoopbackRpc::start(
            ChainReply::Id(crate::ARB_ONE_CHAIN_ID),
            BTreeMap::from([(1, RpcReply::Unavailable)]),
        );
        let error = preflight_error(preflight_args(
            datadir.path(),
            &head,
            unavailable.url.clone(),
        ))
        .await;
        assert!(matches!(
            error.downcast_ref::<RecoveryAuthorityError>(),
            Some(RecoveryAuthorityError::Unavailable(_))
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn preflight_authority_failure_creates_no_recovery_or_storage_artifacts() {
        let datadir = tempdir().unwrap();
        let head = datadir.path().join("head.stream");
        snapshot_head(&head);
        let frontier = HeaderObservation {
            number: 1,
            hash: B256::with_last_byte(1),
            state_root: B256::with_last_byte(2),
        };
        let incident = authority_incident(frontier);
        let log = write_strict_preflight_inputs(datadir.path(), incident);
        let before = tree_bytes(datadir.path());
        let rpc = LoopbackRpc::start(
            ChainReply::Id(crate::ARB_ONE_CHAIN_ID),
            BTreeMap::from([(1, RpcReply::Unavailable)]),
        );

        assert!(
            preflight(&preflight_args(datadir.path(), &head, rpc.url.clone()))
                .await
                .is_err()
        );

        assert_eq!(tree_bytes(datadir.path()), before);
        assert_eq!(
            fs::read(datadir.path().join("arb-trusted-l2/active.json")).unwrap(),
            before[&PathBuf::from("arb-trusted-l2/active.json")]
        );
        assert_eq!(
            L1ResumeLog::load_strict(&L1ResumeLog::path_in(datadir.path())).unwrap(),
            log
        );
        assert!(!journal_path(datadir.path()).exists());
        assert!(
            !datadir
                .path()
                .join(JOURNAL_DIR)
                .join(RECOVERY_LOCK_FILE)
                .exists()
        );
        for path in ["db", "static_files", "rocksdb"] {
            assert!(
                !datadir.path().join(path).exists(),
                "{path} must not be created"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn successful_preflight_returns_strict_inputs_without_mutation() {
        let datadir = tempdir().unwrap();
        let head = datadir.path().join("head.stream");
        snapshot_head(&head);
        let frontier = HeaderObservation {
            number: 1,
            hash: B256::with_last_byte(1),
            state_root: B256::with_last_byte(2),
        };
        let incident = authority_incident(frontier);
        let log = write_strict_preflight_inputs(datadir.path(), incident);
        let before = tree_bytes(datadir.path());
        let rpc = LoopbackRpc::start(
            ChainReply::Id(crate::ARB_ONE_CHAIN_ID),
            BTreeMap::from([(1, RpcReply::Header(frontier))]),
        );

        let (_boot, actual_incident, _canonical, actual_log) =
            preflight(&preflight_args(datadir.path(), &head, rpc.url.clone()))
                .await
                .unwrap();

        assert_eq!(actual_incident, incident);
        assert_eq!(actual_log, log);
        assert_eq!(tree_bytes(datadir.path()), before);
        assert!(!journal_path(datadir.path()).exists());
        assert!(
            !datadir
                .path()
                .join(JOURNAL_DIR)
                .join(RECOVERY_LOCK_FILE)
                .exists()
        );
    }

    async fn run_with_deps_before_lock<P, F, H>(
        args: RecoverArgs,
        finite_runner: P,
        before_lock: H,
    ) -> eyre::Result<()>
    where
        P: FnOnce(StoppedFiniteRethLaunch, ResolvedRollupBoot, StoppedFiniteConfig) -> F,
        F: std::future::Future<Output = eyre::Result<HeaderObservation>>,
        H: FnOnce(),
    {
        run_inner_with_before_lock(args, finite_runner, before_lock).await
    }

    async fn assert_invalid_finite_input_preserves_datadir(args: RecoverArgs) {
        let before = tree_bytes(&args.datadir);
        let calls = Arc::new(AtomicUsize::new(0));
        let runner_calls = calls.clone();
        let _error = run_with_deps(args.clone(), move |_reth, _boot, _finite| {
            runner_calls.fetch_add(1, Ordering::SeqCst);
            async { Err(eyre::eyre!("finite runner must not be called")) }
        })
        .await
        .expect_err("invalid finite inputs must reject recovery");

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(tree_bytes(&args.datadir), before);
        assert!(!journal_path(&args.datadir).exists());
        assert!(
            !args
                .datadir
                .join(JOURNAL_DIR)
                .join(RECOVERY_LOCK_FILE)
                .exists()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_inner_invalid_l1_url_leaves_datadir_byte_identical() {
        let fixture = RecoveryOrchestrationFixture::new().await;
        let mut args = fixture.args.clone();
        args.l1_rpc = "ws://127.0.0.1:8545".into();
        assert_invalid_finite_input_preserves_datadir(args).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_inner_invalid_beacon_url_leaves_datadir_byte_identical() {
        let fixture = RecoveryOrchestrationFixture::new().await;
        let mut args = fixture.args.clone();
        args.l1_beacon = "ws://127.0.0.1:5052".into();
        assert_invalid_finite_input_preserves_datadir(args).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_inner_end_before_checkpoint_leaves_datadir_byte_identical() {
        let fixture = RecoveryOrchestrationFixture::new().await;
        let mut args = fixture.args.clone();
        args.l1_end_block = 0;
        assert_invalid_finite_input_preserves_datadir(args).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_inner_resume_replacement_before_lock_rejects_without_mutation() {
        let fixture = RecoveryOrchestrationFixture::new().await;
        let resume_path = L1ResumeLog::path_in(&fixture.storage.datadir);
        let replacement = L1ResumeLog {
            checkpoints: vec![cp(1)],
        };
        let replacement_bytes = serde_json::to_vec(&replacement).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let runner_calls = calls.clone();

        let _ = run_with_deps_before_lock(
            fixture.args.clone(),
            move |_, _, _| {
                runner_calls.fetch_add(1, Ordering::SeqCst);
                async { Err(eyre::eyre!("finite runner must not be called")) }
            },
            || fs::write(&resume_path, &replacement_bytes).unwrap(),
        )
        .await
        .expect_err("a post-preflight resume replacement must reject recovery");

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            reopened_tip(&fixture.storage.datadir, &fixture_boot(&fixture.storage)),
            5
        );
        assert!(!journal_path(&fixture.storage.datadir).exists());
        assert_eq!(fs::read(&resume_path).unwrap(), replacement_bytes);
        assert_eq!(
            fs::read(fixture.storage.datadir.join("arb-trusted-l2/active.json")).unwrap(),
            fixture.marker
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_inner_incident_replacement_before_lock_rejects_without_mutation() {
        let fixture = RecoveryOrchestrationFixture::new().await;
        let marker_path = fixture.storage.datadir.join("arb-trusted-l2/active.json");
        let mut replacement: Incident = serde_json::from_slice(&fixture.marker).unwrap();
        replacement.local_hash = B256::with_last_byte(0xab);
        let replacement_bytes = serde_json::to_vec(&replacement).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let runner_calls = calls.clone();

        let _ = run_with_deps_before_lock(
            fixture.args.clone(),
            move |_, _, _| {
                runner_calls.fetch_add(1, Ordering::SeqCst);
                async { Err(eyre::eyre!("finite runner must not be called")) }
            },
            || fs::write(&marker_path, &replacement_bytes).unwrap(),
        )
        .await
        .expect_err("a post-preflight incident replacement must reject recovery");

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            reopened_tip(&fixture.storage.datadir, &fixture_boot(&fixture.storage)),
            5
        );
        assert!(!journal_path(&fixture.storage.datadir).exists());
        assert_eq!(fs::read(&marker_path).unwrap(), replacement_bytes);
        assert_eq!(
            L1ResumeLog::load_strict(&L1ResumeLog::path_in(&fixture.storage.datadir)).unwrap(),
            L1ResumeLog {
                checkpoints: vec![cp(2), cp(5)]
            }
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn real_storage_v2_unwind_reopens_at_target_and_records_unwound() {
        let fixture = crate::finite::test_support::storage_v2_fixture(412346, 6).await;
        let boot = fixture_boot(&fixture);
        let marker = marker_bytes(&fixture.datadir);
        let path = journal_path(&fixture.datadir);
        let mut journal = create_journal(&path, &fixture_journal(Phase::Prepared, 6)).unwrap();

        let opened = unwind_and_reopen(&fixture.datadir, &boot, &path, &mut journal)
            .expect("production unwind")
            .expect("target state is not frontier verification");
        drop(opened);

        assert_eq!(reopened_tip(&fixture.datadir, &boot), 2);
        let bytes = fs::read(&path).unwrap();
        assert_eq!(
            serde_json::from_slice::<RecoveryJournal>(&bytes)
                .unwrap()
                .phase,
            Phase::Unwound
        );
        assert_eq!(
            fs::read(fixture.datadir.join("arb-trusted-l2/active.json")).unwrap(),
            marker
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn real_storage_v2_unwind_fault_is_idempotent_without_overshoot() {
        let fixture = crate::finite::test_support::storage_v2_fixture(412346, 6).await;
        let _fault_guard = RECOVERY_FAULT_TEST_LOCK.lock().unwrap();
        let boot = fixture_boot(&fixture);
        let path = journal_path(&fixture.datadir);
        let mut journal = create_journal(&path, &fixture_journal(Phase::Prepared, 6)).unwrap();

        RECOVERY_FAULT.with(|fault| fault.set(FaultPoint::AfterUnwindCommit as u8 + 1));
        assert!(unwind_and_reopen(&fixture.datadir, &boot, &path, &mut journal).is_err());
        assert_eq!(reopened_tip(&fixture.datadir, &boot), 2);
        assert_eq!(
            serde_json::from_slice::<RecoveryJournal>(&fs::read(&path).unwrap())
                .unwrap()
                .phase,
            Phase::Prepared
        );

        let opened = unwind_and_reopen(&fixture.datadir, &boot, &path, &mut journal)
            .expect("idempotent production unwind")
            .expect("target state is not frontier verification");
        drop(opened);
        assert_eq!(reopened_tip(&fixture.datadir, &boot), 2);
        assert_eq!(
            serde_json::from_slice::<RecoveryJournal>(&fs::read(&path).unwrap())
                .unwrap()
                .phase,
            Phase::Unwound
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn real_storage_v2_resume_prefix_rewinds_without_phase_regression() {
        let fixture = crate::finite::test_support::storage_v2_fixture(412346, 4).await;
        let boot = fixture_boot(&fixture);
        let path = journal_path(&fixture.datadir);
        let mut journal =
            create_journal(&path, &fixture_journal(Phase::ResumeTruncated, 6)).unwrap();

        let opened = unwind_and_reopen(&fixture.datadir, &boot, &path, &mut journal)
            .expect("production retry unwind")
            .expect("partial prefix is not frontier verification");
        drop(opened);
        assert_eq!(reopened_tip(&fixture.datadir, &boot), 2);
        assert_eq!(
            serde_json::from_slice::<RecoveryJournal>(&fs::read(&path).unwrap())
                .unwrap()
                .phase,
            Phase::ResumeTruncated
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn real_storage_v2_incompatible_durable_tips_fail_closed() {
        let below = crate::finite::test_support::storage_v2_fixture(412346, 1).await;
        let below_boot = fixture_boot(&below);
        let below_path = journal_path(&below.datadir);
        let mut below_journal =
            create_journal(&below_path, &fixture_journal(Phase::Prepared, 1)).unwrap();
        assert!(
            unwind_and_reopen(&below.datadir, &below_boot, &below_path, &mut below_journal)
                .is_err()
        );
        assert_eq!(reopened_tip(&below.datadir, &below_boot), 1);
        assert_eq!(
            serde_json::from_slice::<RecoveryJournal>(&fs::read(&below_path).unwrap())
                .unwrap()
                .phase,
            Phase::Prepared
        );

        let above = crate::finite::test_support::storage_v2_fixture(412346, 6).await;
        let above_boot = fixture_boot(&above);
        let above_path = journal_path(&above.datadir);
        let mut above_journal =
            create_journal(&above_path, &fixture_journal(Phase::ResumeTruncated, 6)).unwrap();
        assert!(
            unwind_and_reopen(&above.datadir, &above_boot, &above_path, &mut above_journal)
                .is_err()
        );
        assert_eq!(reopened_tip(&above.datadir, &above_boot), 6);
        assert_eq!(
            serde_json::from_slice::<RecoveryJournal>(&fs::read(&above_path).unwrap())
                .unwrap()
                .phase,
            Phase::ResumeTruncated
        );
    }

    struct RecoveryOrchestrationFixture {
        storage: crate::finite::test_support::StorageV2Fixture,
        rpc: LoopbackRpc,
        args: RecoverArgs,
        marker: Vec<u8>,
    }

    impl RecoveryOrchestrationFixture {
        async fn new() -> Self {
            const CHECKPOINT: u64 = 2;
            const FRONTIER: u64 = 5;
            let storage =
                crate::finite::test_support::storage_v2_fixture(crate::ARB_ONE_CHAIN_ID, FRONTIER)
                    .await;
            let headers = local_headers(&storage.datadir, &[CHECKPOINT, FRONTIER]);
            let frontier = headers[&FRONTIER];
            let incident = Incident {
                local_hash: B256::with_last_byte(0xff),
                local_state_root: B256::with_last_byte(0xfe),
                ..authority_incident(frontier)
            };
            let marker = serde_json::to_vec(&incident).unwrap();
            let marker_path = storage.datadir.join("arb-trusted-l2/active.json");
            fs::create_dir_all(marker_path.parent().unwrap()).unwrap();
            fs::write(&marker_path, &marker).unwrap();
            L1ResumeLog {
                checkpoints: vec![cp(CHECKPOINT), cp(FRONTIER)],
            }
            .save(&L1ResumeLog::path_in(&storage.datadir))
            .unwrap();
            let rpc = LoopbackRpc::start(
                ChainReply::Id(crate::ARB_ONE_CHAIN_ID),
                BTreeMap::from([
                    (CHECKPOINT, RpcReply::Header(headers[&CHECKPOINT])),
                    (FRONTIER, RpcReply::Header(frontier)),
                ]),
            );
            let args = RecoverArgs {
                datadir: storage.datadir.clone(),
                canonical_l2_rpc: rpc.url.clone(),
                l1_rpc: "http://127.0.0.1:8545".into(),
                l1_beacon: "http://127.0.0.1:5052".into(),
                l1_end_block: 1,
                max_recovery_l2_blocks: FRONTIER - CHECKPOINT,
                snapshot_head: Some(storage.snapshot_head.clone()),
                chain_info: None,
                genesis_json: None,
                chain_id: Some(crate::ARB_ONE_CHAIN_ID),
                l1_prefetch: 1,
                l1_getlogs_range: 1,
            };
            Self {
                storage,
                rpc,
                args,
                marker,
            }
        }

        fn frontier(&self) -> HeaderObservation {
            local_headers(&self.storage.datadir, &[5])[&5]
        }

        fn assert_durable_frontier(&self) {
            assert_eq!(
                reopened_tip(&self.storage.datadir, &fixture_boot(&self.storage)),
                5
            );
            let static_files =
                StaticFileProvider::<arbitrum_alloy_consensus::reth::ArbPrimitives>::read_only(
                    self.storage.datadir.join("static_files"),
                )
                .unwrap();
            assert!(static_files.header_by_number(6).unwrap().is_none());
            assert_eq!(
                fs::read(self.storage.datadir.join("arb-trusted-l2/active.json")).unwrap(),
                self.marker
            );
        }

        fn assert_phase(&self, phase: Phase) {
            assert_eq!(
                strict_journal(&journal_path(&self.storage.datadir))
                    .unwrap()
                    .unwrap()
                    .phase,
                phase
            );
        }
    }

    async fn real_finite_runner(
        reth: StoppedFiniteRethLaunch,
        boot: ResolvedRollupBoot,
        finite: StoppedFiniteConfig,
        calls: Arc<AtomicUsize>,
    ) -> eyre::Result<HeaderObservation> {
        calls.fetch_add(1, Ordering::SeqCst);
        let message = crate::finite::test_support::valid_deposit_message();
        crate::finite::run_stopped_finite_with_producer(
            reth,
            boot,
            finite,
            move |l1_tx| async move {
                for sequence_number in 3..=6 {
                    let mut message = message.clone();
                    message.sequence_number = sequence_number;
                    l1_tx.send(message).await.expect("finite input receiver");
                }
                Ok(crate::L1SyncCompletion::FrontierReached { frontier: 5 })
            },
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn full_recovery_orchestration_rebuilds_only_through_frontier() {
        const CHECKPOINT: u64 = 2;
        const FRONTIER: u64 = 5;
        let fixture =
            crate::finite::test_support::storage_v2_fixture(crate::ARB_ONE_CHAIN_ID, FRONTIER)
                .await;
        let headers = local_headers(&fixture.datadir, &[CHECKPOINT, FRONTIER]);
        let frontier = headers[&FRONTIER];
        let incident = Incident {
            local_hash: B256::with_last_byte(0xff),
            local_state_root: B256::with_last_byte(0xfe),
            ..authority_incident(frontier)
        };
        let marker = fixture.datadir.join("arb-trusted-l2/active.json");
        let marker_bytes = serde_json::to_vec(&incident).unwrap();
        fs::create_dir_all(marker.parent().unwrap()).unwrap();
        fs::write(&marker, &marker_bytes).unwrap();
        L1ResumeLog {
            checkpoints: vec![cp(CHECKPOINT), cp(FRONTIER)],
        }
        .save(&L1ResumeLog::path_in(&fixture.datadir))
        .unwrap();
        let rpc = LoopbackRpc::start(
            ChainReply::Id(crate::ARB_ONE_CHAIN_ID),
            BTreeMap::from([
                (CHECKPOINT, RpcReply::Header(headers[&CHECKPOINT])),
                (FRONTIER, RpcReply::Header(frontier)),
            ]),
        );
        // The canonical fixture is mutable so post-finite authority transitions can be modeled
        // without changing the transport. Keep the expected frontier installed for this success
        // path.
        rpc.set_header(FRONTIER, RpcReply::Header(frontier));
        let args = RecoverArgs {
            datadir: fixture.datadir.clone(),
            canonical_l2_rpc: rpc.url.clone(),
            l1_rpc: "http://127.0.0.1:8545".into(),
            l1_beacon: "http://127.0.0.1:5052".into(),
            l1_end_block: 1,
            max_recovery_l2_blocks: FRONTIER - CHECKPOINT,
            snapshot_head: Some(fixture.snapshot_head.clone()),
            chain_info: None,
            genesis_json: None,
            chain_id: Some(crate::ARB_ONE_CHAIN_ID),
            l1_prefetch: 1,
            l1_getlogs_range: 1,
        };
        let message = crate::finite::test_support::valid_deposit_message();

        run_with_deps(args, move |reth, boot, finite| async move {
            crate::finite::run_stopped_finite_with_producer(
                reth,
                boot,
                finite,
                move |l1_tx| async move {
                    for sequence_number in CHECKPOINT + 1..=FRONTIER + 1 {
                        let mut message = message.clone();
                        message.sequence_number = sequence_number;
                        l1_tx.send(message).await.expect("finite input receiver");
                    }
                    Ok(crate::L1SyncCompletion::FrontierReached { frontier: FRONTIER })
                },
            )
            .await
        })
        .await
        .expect("full stopped recovery");

        assert_eq!(
            reopened_tip(&fixture.datadir, &fixture_boot(&fixture)),
            FRONTIER
        );
        let static_files =
            StaticFileProvider::<arbitrum_alloy_consensus::reth::ArbPrimitives>::read_only(
                fixture.datadir.join("static_files"),
            )
            .unwrap();
        assert!(
            static_files
                .header_by_number(FRONTIER + 1)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            L1ResumeLog::load_strict(&L1ResumeLog::path_in(&fixture.datadir)).unwrap(),
            L1ResumeLog {
                checkpoints: vec![cp(CHECKPOINT)]
            }
        );
        assert_eq!(fs::read(marker).unwrap(), marker_bytes);
        assert_eq!(
            strict_journal(&journal_path(&fixture.datadir))
                .unwrap()
                .unwrap()
                .phase,
            Phase::FrontierMatched
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn full_recovery_terminalizes_post_finite_canonical_mismatch() {
        let fixture = RecoveryOrchestrationFixture::new().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let headers = fixture.rpc.headers.clone();
        let expected = fixture.frontier();
        let runner_calls = calls.clone();
        let error = run_with_deps(fixture.args.clone(), move |reth, boot, finite| {
            let calls = runner_calls.clone();
            let headers = headers.clone();
            async move {
                let result = real_finite_runner(reth, boot, finite, calls).await;
                headers.lock().unwrap().insert(
                    5,
                    RpcReply::Header(HeaderObservation {
                        hash: B256::with_last_byte(0xaa),
                        state_root: B256::with_last_byte(0xbb),
                        ..expected
                    }),
                );
                result
            }
        })
        .await
        .expect_err("post-finite canonical mismatch must fail recovery");

        assert!(
            error
                .to_string()
                .contains("rebuilt frontier does not match canonical")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        fixture.assert_durable_frontier();
        fixture.assert_phase(Phase::Failed);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn full_recovery_retries_post_finite_canonical_outage_without_rebuild() {
        let fixture = RecoveryOrchestrationFixture::new().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let headers = fixture.rpc.headers.clone();
        let runner_calls = calls.clone();
        let error = run_with_deps(fixture.args.clone(), move |reth, boot, finite| {
            let calls = runner_calls.clone();
            let headers = headers.clone();
            async move {
                let result = real_finite_runner(reth, boot, finite, calls).await;
                headers.lock().unwrap().insert(5, RpcReply::Unavailable);
                result
            }
        })
        .await
        .expect_err("post-finite canonical outage must be retryable");

        assert!(matches!(
            error.downcast_ref::<RecoveryAuthorityError>(),
            Some(RecoveryAuthorityError::Unavailable(_))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        fixture.assert_durable_frontier();
        fixture.assert_phase(Phase::ResumeTruncated);

        fixture
            .rpc
            .set_header(5, RpcReply::Header(fixture.frontier()));
        let forbidden_calls = calls.clone();
        run_with_deps(fixture.args.clone(), move |_, _, _| async move {
            forbidden_calls.fetch_add(1, Ordering::SeqCst);
            Err(eyre::eyre!(
                "finite runner must not run after durable frontier"
            ))
        })
        .await
        .expect("retry must freshly verify the durable frontier without rebuilding");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        fixture.assert_durable_frontier();
        fixture.assert_phase(Phase::FrontierMatched);
    }

    #[allow(clippy::await_holding_lock)] // serializes the thread-local recovery fault injection
    #[tokio::test(flavor = "multi_thread")]
    async fn full_recovery_after_finite_completion_fault_reenters_without_rebuild() {
        let _fault_guard = RECOVERY_FAULT_TEST_LOCK.lock().unwrap();
        let fixture = RecoveryOrchestrationFixture::new().await;
        let calls = Arc::new(AtomicUsize::new(0));
        RECOVERY_FAULT.with(|fault| fault.set(FaultPoint::AfterFiniteCompletion as u8 + 1));
        assert!(
            run_with_deps(fixture.args.clone(), {
                let calls = calls.clone();
                move |reth, boot, finite| real_finite_runner(reth, boot, finite, calls)
            })
            .await
            .is_err()
        );

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        fixture.assert_durable_frontier();
        fixture.assert_phase(Phase::ResumeTruncated);

        let forbidden_calls = calls.clone();
        run_with_deps(fixture.args.clone(), move |_, _, _| async move {
            forbidden_calls.fetch_add(1, Ordering::SeqCst);
            Err(eyre::eyre!(
                "finite runner must not run after injected completion crash"
            ))
        })
        .await
        .expect("reentry must freshly verify the durable frontier");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        fixture.assert_durable_frontier();
        fixture.assert_phase(Phase::FrontierMatched);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn frontier_matched_reentry_freshly_verifies_and_rejects_tampered_authority() {
        let fixture = RecoveryOrchestrationFixture::new().await;
        let calls = Arc::new(AtomicUsize::new(0));
        run_with_deps(fixture.args.clone(), {
            let calls = calls.clone();
            move |reth, boot, finite| real_finite_runner(reth, boot, finite, calls)
        })
        .await
        .expect("initial real recovery");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        fixture.assert_phase(Phase::FrontierMatched);

        fixture.rpc.requested_heights.lock().unwrap().clear();
        let forbidden_calls = calls.clone();
        run_with_deps(fixture.args.clone(), move |_, _, _| async move {
            forbidden_calls.fetch_add(1, Ordering::SeqCst);
            Err(eyre::eyre!(
                "finite runner must not run from FrontierMatched"
            ))
        })
        .await
        .expect("FrontierMatched reentry must freshly verify authority");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(fixture.rpc.requested_heights.lock().unwrap().contains(&5));
        fixture.assert_durable_frontier();

        let expected = fixture.frontier();
        fixture.rpc.set_header(
            5,
            RpcReply::Header(HeaderObservation {
                hash: B256::with_last_byte(0xcc),
                ..expected
            }),
        );
        let forbidden_calls = calls.clone();
        let error = run_with_deps(fixture.args.clone(), move |_, _, _| async move {
            forbidden_calls.fetch_add(1, Ordering::SeqCst);
            Err(eyre::eyre!(
                "finite runner must not run for tampered authority"
            ))
        })
        .await
        .expect_err("tampered incident authority must reject before blind success");

        assert!(matches!(
            error.downcast_ref::<RecoveryAuthorityError>(),
            Some(RecoveryAuthorityError::Mismatch(_))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        fixture.assert_durable_frontier();
        fixture.assert_phase(Phase::FrontierMatched);
    }

    #[test]
    fn snapshot_boot_rejects_non_mainnet_chain_id() {
        let args = RecoverArgs::try_parse_from([
            "recover",
            "--datadir",
            "/d",
            "--canonical-l2-rpc",
            "http://l2",
            "--l1-rpc",
            "http://l1",
            "--l1-beacon",
            "http://beacon",
            "--l1-end-block",
            "1",
            "--max-recovery-l2-blocks",
            "1",
            "--snapshot-head",
            "/missing",
            "--chain-id",
            "421614",
        ])
        .unwrap();
        assert!(boot(&args, &incident()).is_err());
    }
}
