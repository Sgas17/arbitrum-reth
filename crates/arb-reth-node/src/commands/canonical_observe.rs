//! One-shot, stopped canonical-L1 authority observer.

use std::{
    collections::BTreeMap,
    io::{Read as _, Write as _},
    os::{fd::AsRawFd as _, unix::fs::MetadataExt as _},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use alloy_primitives::{B256, Bytes, b256, keccak256};
use arb_reth_engine::{
    ArbEngineInput, AuthorityCandidateV3, AuthorityRecordV3, CanonicalObservationV1,
    CanonicalPayloadKind, DivergenceCauseV4, DivergenceMarkerV4, JournalDirectory, JournalRuntime,
    MessageJournalInspection, StorageContextV3, compare_complete_l1_batch,
    decode_production_bootstrap_observation, fingerprint_commitment, fingerprint_message,
    inspect_message_journal, is_authority_candidate_stale, message_divergence_sequence,
    production_bootstrap_authority, production_canonical_context, production_storage_context,
    write_divergence_marker_v4,
};
use arb_reth_l1::{
    BatchPayload, CanonicalBeaconClient, CanonicalBlobSidecar, CanonicalCancellation,
    CanonicalExecutionClient, CanonicalExecutionHeader, CanonicalExecutionLog,
    CanonicalMemoryBudget, CanonicalMemoryReservation, DelayedMap, DelayedMessage, DeliveredBatch,
    ObservationDeadlines, RetryDisposition, batch_data_stats, batch_to_feed_messages_cancellable,
    decode_canonical_blob_payload, decode_separate_batch_event_data, extract_calldata_payload,
    parse_inbox_message_data, parse_message_delivered, report_batch_num, report_data_hash,
    sequencer_accumulator, serialize_batch, validate_ordered_blob_commitments,
    verify_accumulator_chain,
};
use clap::Parser;
use eyre::{WrapErr as _, ensure, eyre};
use reth_db_api::models::StorageSettings;
use reth_provider::{BlockNumReader as _, StorageSettingsCache as _};
use reth_storage_api::HeaderProvider as _;

use crate::{
    lifecycle::LifecycleState,
    recovery::{OrdinaryAuthorityEvidence, preflight_ordinary_authority},
};

const L1_GENESIS_HASH: B256 =
    b256!("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3");
const KZG_HELPER_ENV: &str = "ARB_RETH_INTERNAL_KZG_COMMITMENT_HELPER";
const KZG_TRUSTED_SETUP_DIGEST: [u8; 32] =
    alloy_primitives::hex!("d39b9f2d047cc9dca2de58f264b6a09448ccd34db967881a6713eacacf0f26b7");

#[derive(Debug, Parser)]
#[command(
    name = "canonical-observe",
    about = "One-shot stopped canonical-L1 authority observation"
)]
pub struct CanonicalObserveArgs {
    /// Existing stopped Robinhood snapshot datadir.
    #[arg(long, value_name = "PATH")]
    datadir: PathBuf,

    /// Sole pinned Ethereum execution JSON-RPC endpoint.
    #[arg(long, value_name = "URL")]
    l1_rpc: String,

    /// Sole pinned Ethereum beacon REST endpoint.
    #[arg(long, value_name = "URL")]
    l1_beacon: String,
}

struct DatadirLock {
    parent: Arc<std::fs::File>,
    path: PathBuf,
    dev: u64,
    ino: u64,
}

impl DatadirLock {
    fn acquire(directory: &JournalDirectory) -> eyre::Result<Self> {
        let parent = directory.parent_file();
        let result = unsafe { libc::flock(parent.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            return Err(std::io::Error::last_os_error())
                .wrap_err("canonical observer datadir is already locked");
        }
        let metadata = parent.metadata()?;
        let lock = Self {
            parent,
            path: directory.path().to_owned(),
            dev: metadata.dev(),
            ino: metadata.ino(),
        };
        lock.prove_path()?;
        Ok(lock)
    }

    fn prove_path(&self) -> eyre::Result<()> {
        let metadata = std::fs::symlink_metadata(&self.path)?;
        ensure!(
            metadata.is_dir() && metadata.dev() == self.dev && metadata.ino() == self.ino,
            "locked canonical-observer datadir path was replaced"
        );
        Ok(())
    }
}

impl Drop for DatadirLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.parent.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

struct PreparedBatch {
    batch: DeliveredBatch,
    payload_kind: CanonicalPayloadKind,
    payload_digest: B256,
    messages: Vec<ArbEngineInput>,
    batch_start_sequence: u64,
    safe: CanonicalExecutionHeader,
    containing: CanonicalExecutionHeader,
    delivery: CanonicalExecutionLog,
    posting_transaction_hash: B256,
    posting_transaction_index: u32,
    delivery_log_index: u32,
    start_delayed_count: u64,
    delayed_accumulators: Vec<B256>,
    sequencer_mismatch: Option<(B256, B256)>,
    delayed_mismatch: Option<(B256, B256)>,
    _liability: CanonicalMemoryReservation,
}

// One unit is owned at a time; avoid another heap allocation just to shrink the enum.
#[allow(clippy::large_enum_variant)]
enum PreparedUnit {
    Canonical(Vec<PreparedBatch>),
    InvalidatedAuthority {
        batch: PreparedBatch,
        authority: AuthorityRecordV3,
    },
}

pub fn run(args: CanonicalObserveArgs) -> eyre::Result<()> {
    ensure!(
        args.datadir.is_dir(),
        "canonical-observe datadir does not exist"
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let cancellation = CanonicalCancellation::default();
        let deadlines = ObservationDeadlines::starting_at(tokio::time::Instant::now());
        let durable_mutation_started = Arc::new(AtomicBool::new(false));
        let observer = run_inner(
            args,
            cancellation.clone(),
            deadlines,
            durable_mutation_started.clone(),
        );
        supervise_observer(observer, cancellation, deadlines, durable_mutation_started).await
    })
}

async fn supervise_observer(
    observer: impl std::future::Future<Output = eyre::Result<()>>,
    cancellation: CanonicalCancellation,
    deadlines: ObservationDeadlines,
    durable_mutation_started: Arc<AtomicBool>,
) -> eyre::Result<()> {
    let mut observer = Box::pin(observer);
    tokio::select! {
        result = &mut observer => result,
        () = tokio::time::sleep_until(deadlines.work) => {
            cancellation.cancel();
            if durable_mutation_started.load(Ordering::Acquire) {
                return observer.await;
            }
            match tokio::time::timeout_at(deadlines.total, observer).await {
                Ok(result) => result,
                Err(_) => std::process::exit(arb_reth_l1::canonical::OBSERVER_DEADLINE_EXIT_CODE),
            }
        }
    }
}

async fn run_inner(
    args: CanonicalObserveArgs,
    cancellation: CanonicalCancellation,
    deadlines: ObservationDeadlines,
    durable_mutation_started: Arc<AtomicBool>,
) -> eyre::Result<()> {
    let directory = JournalDirectory::open(&args.datadir)?;
    let lock = DatadirLock::acquire(&directory)?;
    require_empty_authority_evidence(preflight_ordinary_authority(&directory, true)?)?;
    let context = production_storage_context();
    let mut journal = inspect_message_journal(&directory, context)?;
    ensure!(
        !journal.has_authenticated_short_tail,
        "canonical observer requires a complete journal tail"
    );
    ensure!(journal.v.is_some(), "canonical observer requires V present");
    let lifecycle = crate::lifecycle::inspect_existing_read_only(&directory, context.anchor)?;
    ensure!(
        lifecycle.state == LifecycleState::Clean,
        "canonical observer requires stopped CLEAN lifecycle"
    );
    validate_stopped_storage(&directory, context, &journal)?;
    lock.prove_path()?;

    let execution = CanonicalExecutionClient::new(args.l1_rpc)?;
    let beacon = CanonicalBeaconClient::new(args.l1_beacon)?;
    ensure!(
        execution.endpoint() != beacon.endpoint(),
        "execution and beacon endpoints must be explicitly distinct protocols"
    );
    let budget = CanonicalMemoryBudget::new();

    let mut completed_attempts = 0usize;
    loop {
        let now = tokio::time::Instant::now();
        let (attempt_number, attempt_deadline) =
            match deadlines.start_attempt(completed_attempts, now) {
                RetryDisposition::Attempt { number, deadline } => (number, deadline),
                RetryDisposition::WorkWindowExhausted => {
                    return Err(eyre!(
                        "canonical provider work window exhausted; use a fresh datadir"
                    ));
                }
                RetryDisposition::AttemptsExhausted => {
                    return Err(eyre!(
                        "canonical observation retries exhausted; use a fresh datadir"
                    ));
                }
            };
        let result = prepare_unit(
            &execution,
            &beacon,
            &budget,
            &cancellation,
            attempt_deadline,
            &journal,
        )
        .await;
        match result {
            Ok(PreparedUnit::Canonical(prepared)) => {
                publish_unit(
                    &directory,
                    context,
                    &lock,
                    &execution,
                    &beacon,
                    &budget,
                    &cancellation,
                    attempt_deadline,
                    &mut journal,
                    prepared,
                    durable_mutation_started.clone(),
                )
                .await?;
                ensure!(
                    journal.v == Some(journal.watermark),
                    "complete canonical unit did not cover through durable J"
                );
                return Ok(());
            }
            Ok(PreparedUnit::InvalidatedAuthority { batch, authority }) => {
                let observation = build_observation(
                    &journal,
                    &batch,
                    authority.start_sequence,
                    authority.end_sequence,
                )?;
                ensure!(
                    authority.evidence_digest != observation.evidence_digest(),
                    "safe advancement without contradictory evidence cannot create cause 2"
                );
                write_authenticated_marker(
                    &directory,
                    &lock,
                    &execution,
                    &beacon,
                    &budget,
                    &cancellation,
                    attempt_deadline,
                    &journal,
                    &batch,
                    authority.start_sequence,
                    observation,
                    DivergenceCauseV4::ExistingAuthorityInvalidatedBySafeReorg,
                    B256::ZERO,
                    B256::ZERO,
                    authority.authority_id,
                    authority.evidence_digest,
                    observation.evidence_digest(),
                )
                .await?;
                return Err(eyre!(
                    "durable existing-authority divergence-v4 marker written; datadir closed"
                ));
            }
            Err(error) => {
                completed_attempts = attempt_number;
                let Some(backoff) = deadlines.backoff_after(attempt_number) else {
                    return Err(error.wrap_err(
                        "canonical observation failed closed after final attempt; use a fresh datadir",
                    ));
                };
                ensure!(
                    tokio::time::Instant::now() + backoff < deadlines.work,
                    "canonical retry backoff exceeds provider work window"
                );
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

fn require_empty_authority_evidence(evidence: OrdinaryAuthorityEvidence) -> eyre::Result<()> {
    match evidence {
        OrdinaryAuthorityEvidence::None => Ok(()),
        OrdinaryAuthorityEvidence::Divergence => Err(eyre!(
            "durable divergence-v4 marker closes canonical observation"
        )),
        OrdinaryAuthorityEvidence::Recovery => {
            Err(eyre!("recovery evidence closes canonical observation"))
        }
    }
}

fn validate_stopped_storage(
    directory: &JournalDirectory,
    context: StorageContextV3,
    journal: &MessageJournalInspection,
) -> eyre::Result<()> {
    ensure!(
        crate::snapshot_trust::read_completion(directory)?
            == crate::snapshot_trust::ApprovedSnapshotTrust::frozen(),
        "snapshot completion is not the exact frozen Robinhood authority"
    );
    ensure!(
        context == production_storage_context(),
        "canonical observer storage context is not the sole production context"
    );
    let (chain_spec, configured_genesis, deployment) =
        super::journal_init::reviewed_robinhood_storage_chain()?;
    let canonical = production_canonical_context();
    ensure!(
        chain_spec.chain().id() == canonical.l2_chain_id
            && configured_genesis.number == canonical.l2_genesis_number
            && configured_genesis.hash_slow() == canonical.l2_genesis_hash
            && deployment.sequencer_inbox == canonical.sequencer_inbox
            && deployment.bridge == canonical.bridge
            && deployment.deployed_at == canonical.deployment_block,
        "compiled Robinhood storage chain differs from canonical context"
    );
    let factory = super::journal_init::open_read_only_factory(directory.path(), chain_spec)?;
    let provider = factory.provider()?;
    ensure!(
        provider.cached_storage_settings() == StorageSettings::v2(),
        "canonical observer requires persisted Reth storage-v2"
    );
    let tip_number = provider.last_block_number()?;
    let tip = provider
        .sealed_header(tip_number)?
        .ok_or_else(|| eyre!("reopened stopped-store tip is absent"))?;
    ensure!(
        (tip_number, tip.hash()) == (journal.watermark.block_number, journal.watermark.block_hash),
        "canonical observer requires exact DB=J"
    );
    let anchor = provider
        .sealed_header(context.anchor.block_number)?
        .ok_or_else(|| eyre!("snapshot anchor header is absent"))?;
    let trust = crate::snapshot_trust::ApprovedSnapshotTrust::frozen();
    ensure!(
        context.anchor.block_number == trust.head_number
            && context.anchor.block_hash == trust.head_hash
            && anchor.state_root == trust.head_state_root,
        "reopened store does not equal the frozen snapshot anchor/state root"
    );
    let v = journal
        .v
        .ok_or_else(|| eyre!("canonical observer requires V"))?;
    let grid_endpoint = journal
        .retained_grid
        .iter()
        .map(|record| record.authority.end_sequence)
        .filter(|sequence| *sequence <= v.sequence)
        .max()
        .unwrap_or(context.anchor.sequence);
    ensure!(
        v.sequence - grid_endpoint < 256,
        "canonical observer off-grid V suffix is not below 256"
    );
    for entry in &journal.entries {
        let header = provider
            .sealed_header(entry.block_number)?
            .ok_or_else(|| eyre!("journal-covered header {} is absent", entry.block_number))?;
        ensure!(
            header.hash() == entry.block_hash && header.parent_hash == entry.parent_hash,
            "journal/store identity mismatch at sequence {}",
            entry.sequence
        );
        ensure!(
            entry.sequence > v.sequence
                || entry.source == arb_reth_engine::ArbEngineInputSource::L1,
            "verified identity {} is not L1-authorized",
            entry.sequence
        );
    }
    drop(provider);
    drop(factory);
    Ok(())
}

async fn prepare_unit(
    execution: &CanonicalExecutionClient,
    beacon: &CanonicalBeaconClient,
    budget: &CanonicalMemoryBudget,
    cancellation: &CanonicalCancellation,
    deadline: tokio::time::Instant,
    journal: &MessageJournalInspection,
) -> eyre::Result<PreparedUnit> {
    ensure!(
        execution.chain_id(budget, cancellation, deadline).await? == 1,
        "L1 chain id is not 1"
    );
    let genesis = execution
        .header_by_number(0, budget, cancellation, deadline)
        .await?;
    ensure!(
        genesis.value().hash == L1_GENESIS_HASH,
        "L1 genesis hash mismatch"
    );
    drop(genesis);
    let safe = execution
        .header_by_tag("safe", budget, cancellation, deadline)
        .await?;
    let safe_header = *safe.value();
    drop(safe);

    let v = journal
        .v
        .ok_or_else(|| eyre!("canonical observer requires V"))?;
    let retained_authorities = std::iter::once(production_bootstrap_authority())
        .chain(
            journal
                .retained_grid
                .iter()
                .map(|record| record.authority)
                .filter(|record| record.end_sequence <= v.sequence),
        )
        .collect::<Vec<_>>();
    let base_record = *retained_authorities
        .last()
        .expect("production bootstrap authority is always retained");
    let mut invalidated = None;
    let mut containing_header = None;
    for record in retained_authorities {
        let locator = record.locator;
        if record.kind != arb_reth_engine::AuthorityKind::Bootstrap {
            let safe_gap = safe_header
                .number
                .checked_sub(locator.containing_l1_number)
                .ok_or_else(|| eyre!("safe L1 precedes a retained authority locator"))?;
            ensure!(
                safe_gap <= arb_reth_l1::canonical::MAX_SAFE_TO_CONTAINING_L1_GAP,
                "retained authority is outside the runtime safe gap"
            );
        }
        let containing = execution
            .header_by_number(locator.containing_l1_number, budget, cancellation, deadline)
            .await?;
        let header = *containing.value();
        drop(containing);
        if header.hash != locator.containing_l1_hash {
            invalidated = Some(record);
            break;
        }
        containing_header = Some(header);
    }
    if let Some(base_record) = invalidated {
        let locator = base_record.locator;
        let safe_gap_start = safe_header
            .number
            .saturating_sub(arb_reth_l1::canonical::MAX_SAFE_TO_CONTAINING_L1_GAP);
        let hints = execution
            .discovery_logs(
                safe_gap_start,
                safe_header.number,
                production_canonical_context().sequencer_inbox,
                arb_reth_l1::SEQUENCER_BATCH_DELIVERED_TOPIC,
                budget,
                cancellation,
                deadline,
            )
            .await?;
        let hints = hints
            .value()
            .iter()
            .filter(|log| batch_sequence(log) == Some(locator.batch_sequence))
            .map(|log| (log.block_hash, log.log_index))
            .collect::<Vec<_>>();
        ensure!(
            hints.len() == 1,
            "invalidated retained authority has no unique contradictory batch in the bounded safe window"
        );
        let contradictory = execution
            .logs_at_hash(
                hints[0].0,
                production_canonical_context().sequencer_inbox,
                arb_reth_l1::SEQUENCER_BATCH_DELIVERED_TOPIC,
                budget,
                cancellation,
                deadline,
            )
            .await?;
        let delivery = contradictory
            .value()
            .iter()
            .filter(|log| {
                batch_sequence(log) == Some(locator.batch_sequence) && log.log_index == hints[0].1
            })
            .cloned()
            .collect::<Vec<_>>();
        ensure!(
            delivery.len() == 1,
            "invalidated authority contradictory batch is not unique on exact refetch"
        );
        let contradictory_header = execution
            .header_by_number(delivery[0].block_number, budget, cancellation, deadline)
            .await?;
        ensure!(
            contradictory_header.value().hash == delivery[0].block_hash,
            "invalidated authority contradictory containing block changed"
        );
        let start_delayed_count = if base_record.kind == arb_reth_engine::AuthorityKind::Bootstrap {
            decode_production_bootstrap_observation().start_delayed_count
        } else {
            previous_batch_delayed_count(
                execution,
                locator.batch_sequence,
                contradictory_header.value().number,
                budget,
                cancellation,
                deadline,
            )
            .await?
        };
        let batch_start_sequence = locator
            .terminal_sequence
            .checked_sub(u64::from(locator.terminal_message_ordinal))
            .ok_or_else(|| eyre!("retained authority batch start underflows"))?;
        let batch = resolve_batch(
            execution,
            beacon,
            budget,
            cancellation,
            deadline,
            safe_header,
            *contradictory_header.value(),
            delivery[0].clone(),
            start_delayed_count,
            batch_start_sequence,
        )
        .await?;
        ensure!(
            base_record.start_sequence <= v.sequence
                && batch
                    .messages
                    .iter()
                    .any(|message| message.sequence_number() == base_record.start_sequence),
            "contradictory batch does not prove the first invalidated authority sequence"
        );
        return Ok(PreparedUnit::InvalidatedAuthority {
            batch,
            authority: base_record,
        });
    }
    let locator = base_record.locator;
    let containing_header = containing_header
        .ok_or_else(|| eyre!("latest retained authority containing header is absent"))?;
    let logs = execution
        .logs_at_hash(
            containing_header.hash,
            production_canonical_context().sequencer_inbox,
            arb_reth_l1::SEQUENCER_BATCH_DELIVERED_TOPIC,
            budget,
            cancellation,
            deadline,
        )
        .await?;
    let deliveries = logs
        .value()
        .iter()
        .filter(|log| {
            batch_sequence(log) == Some(locator.batch_sequence)
                && log.log_index == locator.delivery_log_index
        })
        .collect::<Vec<_>>();
    ensure!(
        deliveries.len() == 1,
        "retained authority batch delivery log is not unique"
    );
    let delivery = (*deliveries[0]).clone();
    drop(logs);
    ensure!(
        delivery.log_index == locator.delivery_log_index
            && delivery.transaction_index == locator.posting_transaction_index
            && delivery.transaction_hash == locator.posting_transaction_hash,
        "retained authority delivery coordinate changed"
    );
    let start_delayed_count = if base_record.kind == arb_reth_engine::AuthorityKind::Bootstrap {
        decode_production_bootstrap_observation().start_delayed_count
    } else {
        previous_batch_delayed_count(
            execution,
            locator.batch_sequence,
            containing_header.number,
            budget,
            cancellation,
            deadline,
        )
        .await?
    };
    let batch_start_sequence = locator
        .terminal_sequence
        .checked_sub(u64::from(locator.terminal_message_ordinal))
        .ok_or_else(|| eyre!("retained authority batch start underflows"))?;
    let first = resolve_batch(
        execution,
        beacon,
        budget,
        cancellation,
        deadline,
        safe_header,
        containing_header,
        delivery,
        start_delayed_count,
        batch_start_sequence,
    )
    .await?;
    let mut unit = vec![first];
    while unit
        .last()
        .and_then(|batch| batch.messages.last())
        .is_some_and(|message| message.sequence_number() < journal.watermark.sequence)
    {
        ensure!(
            unit.len() < arb_reth_l1::canonical::MAX_BATCHES_PER_OBSERVATION_UNIT,
            "complete canonical unit exceeds 64 batches"
        );
        let previous = unit.last().expect("unit is nonempty");
        let next_batch_sequence = previous
            .batch
            .sequence_number
            .checked_add(1)
            .ok_or_else(|| eyre!("batch sequence overflows"))?;
        let next_start_sequence = previous
            .messages
            .last()
            .expect("decoded batch nonempty")
            .sequence_number()
            .checked_add(1)
            .ok_or_else(|| eyre!("message sequence overflows"))?;
        let next_start_delayed = previous.batch.event.after_delayed_messages_read;
        let from = safe_header
            .number
            .saturating_sub(arb_reth_l1::canonical::MAX_DEPENDENCY_CLOSURE_L1_SPAN - 1)
            .max(previous.containing.number);
        let hints = execution
            .dependency_discovery_logs(
                from,
                safe_header.number,
                Some(production_canonical_context().sequencer_inbox),
                arb_reth_l1::SEQUENCER_BATCH_DELIVERED_TOPIC,
                budget,
                cancellation,
                deadline,
            )
            .await?;
        let matching = hints
            .value()
            .iter()
            .filter(|log| batch_sequence(log) == Some(next_batch_sequence))
            .map(|log| (log.block_hash, log.log_index))
            .collect::<Vec<_>>();
        ensure!(
            matching.len() == 1,
            "next complete batch delivery is not unique"
        );
        let exact = execution
            .logs_at_hash(
                matching[0].0,
                production_canonical_context().sequencer_inbox,
                arb_reth_l1::SEQUENCER_BATCH_DELIVERED_TOPIC,
                budget,
                cancellation,
                deadline,
            )
            .await?;
        let deliveries = exact
            .value()
            .iter()
            .filter(|log| {
                batch_sequence(log) == Some(next_batch_sequence) && log.log_index == matching[0].1
            })
            .cloned()
            .collect::<Vec<_>>();
        ensure!(
            deliveries.len() == 1,
            "next complete batch delivery is not unique on exact refetch"
        );
        let delivery = deliveries[0].clone();
        let safe_gap = safe_header
            .number
            .checked_sub(delivery.block_number)
            .ok_or_else(|| eyre!("next batch is above the safe L1 head"))?;
        ensure!(
            safe_gap <= arb_reth_l1::canonical::MAX_SAFE_TO_CONTAINING_L1_GAP,
            "runtime batch is outside the 2048-block safe gap"
        );
        let containing = execution
            .header_by_number(delivery.block_number, budget, cancellation, deadline)
            .await?;
        ensure!(
            containing.value().hash == delivery.block_hash,
            "next batch block hash changed"
        );
        let next = resolve_batch(
            execution,
            beacon,
            budget,
            cancellation,
            deadline,
            safe_header,
            *containing.value(),
            delivery,
            next_start_delayed,
            next_start_sequence,
        )
        .await?;
        ensure!(
            next.batch.before_acc == previous.batch.after_acc,
            "consecutive batch accumulator predecessor mismatch"
        );
        unit.push(next);
    }
    Ok(PreparedUnit::Canonical(unit))
}

fn batch_sequence(log: &CanonicalExecutionLog) -> Option<u64> {
    let topic = log.topics.get(1)?;
    if topic.as_slice()[..24].iter().any(|byte| *byte != 0) {
        return None;
    }
    Some(u64::from_be_bytes(topic.as_slice()[24..].try_into().ok()?))
}

async fn previous_batch_delayed_count(
    execution: &CanonicalExecutionClient,
    target_batch_sequence: u64,
    containing_number: u64,
    budget: &CanonicalMemoryBudget,
    cancellation: &CanonicalCancellation,
    deadline: tokio::time::Instant,
) -> eyre::Result<u64> {
    ensure!(
        target_batch_sequence > 0,
        "non-bootstrap batch has no predecessor"
    );
    let from =
        containing_number.saturating_sub(arb_reth_l1::canonical::MAX_SAFE_TO_CONTAINING_L1_GAP);
    let hints = execution
        .discovery_logs(
            from,
            containing_number,
            production_canonical_context().sequencer_inbox,
            arb_reth_l1::SEQUENCER_BATCH_DELIVERED_TOPIC,
            budget,
            cancellation,
            deadline,
        )
        .await?;
    let mut matching = hints
        .value()
        .iter()
        .filter(|log| batch_sequence(log) == Some(target_batch_sequence - 1));
    let hint = matching
        .next()
        .map(|log| (log.block_hash, log.log_index))
        .ok_or_else(|| eyre!("previous batch is outside bounded discovery"))?;
    ensure!(
        matching.next().is_none(),
        "previous batch discovery hint is not unique"
    );
    drop(hints);
    let exact = execution
        .logs_at_hash(
            hint.0,
            production_canonical_context().sequencer_inbox,
            arb_reth_l1::SEQUENCER_BATCH_DELIVERED_TOPIC,
            budget,
            cancellation,
            deadline,
        )
        .await?;
    let logs = exact
        .value()
        .iter()
        .filter(|log| {
            batch_sequence(log) == Some(target_batch_sequence - 1) && log.log_index == hint.1
        })
        .collect::<Vec<_>>();
    ensure!(logs.len() == 1, "previous batch exact log is not unique");
    let log = logs[0];
    let header = execution
        .header_by_number(log.block_number, budget, cancellation, deadline)
        .await?;
    ensure!(
        header.value().hash == log.block_hash,
        "previous batch exact block is no longer canonical"
    );
    let event = arb_reth_derive_batch_event(log)?;
    Ok(event.after_delayed_messages_read)
}

fn arb_reth_derive_batch_event(
    log: &CanonicalExecutionLog,
) -> eyre::Result<arb_reth_l1::SequencerBatchDeliveredData> {
    ensure!(
        log.address == production_canonical_context().sequencer_inbox
            && log.topics.len() == 4
            && log.topics[0] == arb_reth_l1::SEQUENCER_BATCH_DELIVERED_TOPIC,
        "malformed SequencerBatchDelivered emitter/topics"
    );
    ensure!(
        log.topics[1].as_slice()[..24].iter().all(|byte| *byte == 0),
        "SequencerBatchDelivered sequence exceeds u64"
    );
    ensure!(
        log.data.len() == 7 * 32
            && (1..=5).all(|word| {
                log.data[word * 32..word * 32 + 24]
                    .iter()
                    .all(|byte| *byte == 0)
            })
            && log.data[6 * 32..7 * 32 - 1].iter().all(|byte| *byte == 0),
        "SequencerBatchDelivered has non-canonical ABI words"
    );
    arb_reth_l1::parse_sequencer_batch_delivered(&log.data)
        .map_err(|error| eyre!("decode SequencerBatchDelivered: {error:?}"))
}

#[allow(clippy::too_many_arguments)]
async fn resolve_batch(
    execution: &CanonicalExecutionClient,
    beacon: &CanonicalBeaconClient,
    budget: &CanonicalMemoryBudget,
    cancellation: &CanonicalCancellation,
    deadline: tokio::time::Instant,
    safe: CanonicalExecutionHeader,
    containing: CanonicalExecutionHeader,
    delivery: CanonicalExecutionLog,
    start_delayed_count: u64,
    batch_start_sequence: u64,
) -> eyre::Result<PreparedBatch> {
    ensure!(
        delivery.block_number == containing.number && delivery.block_hash == containing.hash,
        "delivery log is not in the exact containing block"
    );
    let event = arb_reth_derive_batch_event(&delivery)?;
    let sequence_number =
        batch_sequence(&delivery).ok_or_else(|| eyre!("batch sequence absent"))?;
    let before_acc = delivery.topics[2];
    let after_acc = delivery.topics[3];
    let transaction = execution
        .transaction(delivery.transaction_hash, budget, cancellation, deadline)
        .await?;
    ensure!(
        transaction.value().hash == delivery.transaction_hash
            && transaction.value().block_number == containing.number
            && transaction.value().block_hash == containing.hash
            && transaction.value().transaction_index == delivery.transaction_index
            && transaction.value().to == production_canonical_context().sequencer_inbox,
        "posting transaction identity/coordinate/to mismatch"
    );
    let receipt = execution
        .receipt(delivery.transaction_hash, budget, cancellation, deadline)
        .await?;
    ensure!(
        receipt.value().success
            && receipt.value().transaction_hash == delivery.transaction_hash
            && receipt.value().block_number == containing.number
            && receipt.value().block_hash == containing.hash
            && receipt.value().transaction_index == delivery.transaction_index,
        "posting receipt identity/index/status mismatch"
    );
    let receipt_delivery = receipt
        .value()
        .logs
        .iter()
        .filter(|log| log.log_index == delivery.log_index)
        .collect::<Vec<_>>();
    ensure!(
        receipt_delivery.len() == 1 && receipt_delivery[0] == &delivery,
        "posting receipt does not contain the exact delivery log coordinate"
    );

    // The batch retains one resolved payload while decoding temporarily owns a second copy. Charge
    // both representations before source extraction can allocate either one.
    let payload_charge = budget
        .reserve(
            arb_reth_l1::canonical::MAX_RESOLVED_BATCH_PAYLOAD_BYTES * 2,
            deadline,
            cancellation,
        )
        .await?;
    let (transaction, transaction_charge) = transaction.into_parts();
    let transaction_input = transaction.input;
    let transaction_blob_hashes = transaction.blob_versioned_hashes;
    let transaction_blob_hash_bytes = transaction_blob_hashes
        .len()
        .checked_mul(32)
        .ok_or_else(|| eyre!("transaction blob-hash liability overflows"))?;
    let transaction_bytes = transaction_input
        .len()
        .checked_add(transaction_blob_hash_bytes)
        .ok_or_else(|| eyre!("transaction retained liability overflows"))?
        .max(1);
    let transaction_charge = transaction_charge.retain_bytes(transaction_bytes)?;
    drop(receipt);
    let (batch_payload, resolved_override) = match event.data_location {
        arb_reth_l1::data_location::TX_INPUT => (
            BatchPayload::Calldata(
                extract_calldata_payload(&transaction_input)
                    .map_err(|error| eyre!("extract canonical calldata payload: {error}"))?,
            ),
            None,
        ),
        arb_reth_l1::data_location::SEPARATE_BATCH_EVENT => {
            let logs = execution
                .logs_at_hash(
                    containing.hash,
                    production_canonical_context().sequencer_inbox,
                    arb_reth_l1::SEQUENCER_BATCH_DATA_TOPIC,
                    budget,
                    cancellation,
                    deadline,
                )
                .await?;
            let matching = logs
                .value()
                .iter()
                .filter(|log| batch_sequence(log) == Some(sequence_number))
                .collect::<Vec<_>>();
            ensure!(
                matching.len() == 1 && matching[0].topics.len() == 2,
                "separate batch event is not unique or canonically encoded"
            );
            (
                BatchPayload::Calldata(
                    decode_separate_batch_event_data(&matching[0].data)
                        .map_err(|error| eyre!("decode separate batch payload: {error}"))?,
                ),
                None,
            )
        }
        arb_reth_l1::data_location::NO_DATA => (BatchPayload::None, None),
        arb_reth_l1::data_location::BLOB_HASHES => {
            let hashes = transaction_blob_hashes;
            ensure!(
                (1..=arb_reth_l1::canonical::MAX_BLOBS_PER_POSTING_TRANSACTION)
                    .contains(&hashes.len()),
                "posting transaction blob count is outside 1..=16"
            );
            let context = production_canonical_context();
            ensure!(
                containing.timestamp >= context.beacon_genesis_time,
                "containing block predates beacon genesis"
            );
            let slot = (containing.timestamp - context.beacon_genesis_time)
                / u64::from(context.seconds_per_slot);
            let sidecars = beacon
                .sidecars(slot, budget, cancellation, deadline)
                .await?;
            let selected_charge = budget
                .reserve(
                    hashes
                        .len()
                        .checked_mul(
                            arb_reth_l1::BYTES_PER_BLOB
                                + std::mem::size_of::<CanonicalBlobSidecar>(),
                        )
                        .ok_or_else(|| eyre!("selected sidecar liability overflows"))?,
                    deadline,
                    cancellation,
                )
                .await?;
            let selected = select_sidecars(&hashes, sidecars.value())?;
            drop(sidecars);
            validate_ordered_blob_commitments(&hashes, &selected, |blob| {
                kzg_commitment(blob, cancellation, deadline)
                    .map_err(|error| arb_reth_l1::CanonicalError::new(error.to_string()))
            })?;
            let payload = decode_canonical_blob_payload(&selected)?;
            drop(selected);
            drop(selected_charge);
            (
                BatchPayload::Blob {
                    versioned_hashes: hashes,
                    block_number: containing.number,
                },
                Some(payload),
            )
        }
        other => return Err(eyre!("unsupported canonical batch data location {other}")),
    };
    let payload_kind = match event.data_location {
        arb_reth_l1::data_location::TX_INPUT => CanonicalPayloadKind::Calldata,
        arb_reth_l1::data_location::SEPARATE_BATCH_EVENT => CanonicalPayloadKind::SeparateEvent,
        arb_reth_l1::data_location::NO_DATA => CanonicalPayloadKind::NoData,
        arb_reth_l1::data_location::BLOB_HASHES => CanonicalPayloadKind::Blobs,
        _ => unreachable!("data location matched above"),
    };
    let batch = DeliveredBatch {
        sequence_number,
        before_acc,
        after_acc,
        event,
        payload: batch_payload,
    };
    let payload = resolved_override.unwrap_or_else(|| match &batch.payload {
        BatchPayload::Calldata(payload) => payload.clone(),
        BatchPayload::None => Vec::new(),
        BatchPayload::Blob { .. } => unreachable!("blob override supplied"),
    });
    drop(transaction_input);
    drop(transaction_charge);
    ensure!(
        payload.len() <= arb_reth_l1::canonical::MAX_RESOLVED_BATCH_PAYLOAD_BYTES,
        "resolved payload exceeds 16 MiB"
    );
    let after_delayed = batch.event.after_delayed_messages_read;
    ensure!(
        after_delayed >= start_delayed_count
            && after_delayed - start_delayed_count
                <= arb_reth_l1::canonical::MAX_DELAYED_MESSAGES_PER_BATCH as u64,
        "batch delayed dependency count is outside bounds"
    );
    let (delayed, delayed_charge) = fetch_delayed_messages(
        execution,
        budget,
        cancellation,
        deadline,
        containing,
        start_delayed_count,
        after_delayed,
    )
    .await?;
    ensure!(
        delayed.is_empty() || verify_accumulator_chain(&delayed),
        "delayed accumulator chain is nonconsecutive"
    );
    let delayed_accumulator_charge = budget
        .reserve(
            delayed
                .len()
                .checked_add(1)
                .and_then(|count| count.checked_mul(std::mem::size_of::<B256>()))
                .ok_or_else(|| eyre!("delayed-accumulator liability overflows"))?,
            deadline,
            cancellation,
        )
        .await?;
    let mut delayed_accumulators = Vec::with_capacity(delayed.len() + 1);
    delayed_accumulators.push(
        delayed
            .first()
            .map(|message| message.before_inbox_acc)
            .unwrap_or(batch.event.delayed_acc),
    );
    delayed_accumulators.extend(delayed.iter().map(DelayedMessage::accumulator));
    let local_delayed = delayed
        .last()
        .map(DelayedMessage::accumulator)
        .unwrap_or_else(|| {
            if after_delayed == 0 {
                B256::ZERO
            } else {
                batch.event.delayed_acc
            }
        });
    let getter_delayed = if after_delayed == 0 {
        ensure!(
            batch.event.delayed_acc == B256::ZERO,
            "zero delayed count has nonzero accumulator"
        );
        B256::ZERO
    } else {
        delayed_accumulator_call(
            execution,
            after_delayed - 1,
            safe.hash,
            budget,
            cancellation,
            deadline,
        )
        .await?
    };
    ensure!(
        getter_delayed == batch.event.delayed_acc,
        "provider event/delayed getter disagreement"
    );
    let delayed_mismatch = (local_delayed != batch.event.delayed_acc)
        .then_some((batch.event.delayed_acc, local_delayed));
    let getter_sequencer = sequencer_accumulator_call(
        execution,
        sequence_number,
        safe.hash,
        budget,
        cancellation,
        deadline,
    )
    .await?;
    ensure!(
        getter_sequencer == batch.after_acc,
        "provider event/sequencer getter disagreement"
    );
    let local_sequencer = sequencer_accumulator(&batch);
    let sequencer_mismatch =
        (local_sequencer != batch.after_acc).then_some((batch.after_acc, local_sequencer));
    let report_stats = resolve_report_stats(
        execution,
        budget,
        cancellation,
        deadline,
        containing,
        &delayed,
    )
    .await?;
    let decode_charge = budget
        .reserve(
            (arb_reth_l1::canonical::MAX_DECOMPRESSED_BATCH_BYTES * 3)
                .checked_add(delayed_charge.charged_bytes())
                .ok_or_else(|| eyre!("canonical decode liability overflows"))?,
            deadline,
            cancellation,
        )
        .await?;
    let delayed_map = DelayedMap::from_messages(delayed);
    let feed = batch_to_feed_messages_cancellable(
        &batch,
        &payload,
        start_delayed_count,
        &delayed_map,
        &report_stats,
        batch_start_sequence,
        || cancellation.is_cancelled() || tokio::time::Instant::now() >= deadline,
    )
    .map_err(|error| eyre!("decode complete canonical batch: {error}"))?;
    ensure!(
        !feed.is_empty() && feed.len() <= arb_reth_l1::canonical::MAX_MESSAGES_PER_BATCH,
        "decoded canonical batch count is outside 1..=4096"
    );
    for message in &feed {
        ensure!(
            message
                .message_with_meta_data
                .l1_incoming_message
                .l2msg
                .len()
                <= arb_reth_l1::canonical::MAX_SINGLE_MESSAGE_BYTES,
            "canonical message exceeds 16 MiB"
        );
    }
    let message_bytes = feed.iter().try_fold(0usize, |total, message| {
        total
            .checked_add(std::mem::size_of_val(message))
            .and_then(|total| {
                total.checked_add(
                    message
                        .message_with_meta_data
                        .l1_incoming_message
                        .l2msg
                        .len(),
                )
            })
            .ok_or_else(|| eyre!("canonical message liability overflows"))
    })?;
    let retained_batch_payload_bytes = match &batch.payload {
        BatchPayload::Calldata(payload) => payload.len(),
        BatchPayload::Blob {
            versioned_hashes, ..
        } => versioned_hashes.len() * 32,
        BatchPayload::None => 0,
    };
    let retained_bytes = message_bytes
        .checked_add(retained_batch_payload_bytes)
        .and_then(|bytes| bytes.checked_add(transaction_blob_hash_bytes))
        .and_then(|bytes| {
            bytes.checked_add(delayed_accumulators.len() * std::mem::size_of::<B256>())
        })
        .ok_or_else(|| eyre!("canonical retained liability overflows"))?
        .max(1);
    let message_charge = decode_charge
        .merge(payload_charge)?
        .merge(delayed_charge)?
        .merge(delayed_accumulator_charge)?
        .retain_bytes(retained_bytes)?;
    let messages = feed.into_iter().map(ArbEngineInput::l1).collect();
    drop(delayed_map);
    let payload_digest = keccak256(&payload);
    Ok(PreparedBatch {
        batch,
        payload_kind,
        payload_digest,
        messages,
        batch_start_sequence,
        safe,
        containing,
        delivery: delivery.clone(),
        posting_transaction_hash: delivery.transaction_hash,
        posting_transaction_index: delivery.transaction_index,
        delivery_log_index: delivery.log_index,
        start_delayed_count,
        delayed_accumulators,
        sequencer_mismatch,
        delayed_mismatch,
        _liability: message_charge,
    })
}

fn select_sidecars(
    hashes: &[B256],
    sidecars: &[CanonicalBlobSidecar],
) -> eyre::Result<Vec<CanonicalBlobSidecar>> {
    let mut selected = Vec::with_capacity(hashes.len());
    for hash in hashes {
        let matching = sidecars
            .iter()
            .filter(|sidecar| {
                alloy_eips::eip4844::kzg_to_versioned_hash(&sidecar.commitment) == *hash
            })
            .collect::<Vec<_>>();
        ensure!(
            matching.len() == 1,
            "transaction blob has no unique sidecar commitment"
        );
        selected.push(matching[0].clone());
    }
    Ok(selected)
}

async fn fetch_delayed_messages(
    execution: &CanonicalExecutionClient,
    budget: &CanonicalMemoryBudget,
    cancellation: &CanonicalCancellation,
    deadline: tokio::time::Instant,
    containing: CanonicalExecutionHeader,
    start: u64,
    end: u64,
) -> eyre::Result<(Vec<DelayedMessage>, CanonicalMemoryReservation)> {
    let mut retained = budget.reserve(1, deadline, cancellation).await?;
    if start == end {
        return Ok((Vec::new(), retained));
    }
    let from = containing
        .number
        .saturating_sub(arb_reth_l1::canonical::MAX_DEPENDENCY_CLOSURE_L1_SPAN - 1);
    let hints_response = execution
        .dependency_discovery_logs(
            from,
            containing.number,
            Some(production_canonical_context().bridge),
            arb_reth_l1::MESSAGE_DELIVERED_TOPIC,
            budget,
            cancellation,
            deadline,
        )
        .await?;
    let hints = hints_response
        .value()
        .iter()
        .filter(|log| batch_sequence(log).is_some_and(|index| (start..end).contains(&index)))
        .map(|log| {
            (
                batch_sequence(log).expect("filtered delayed index is present"),
                log.block_hash,
                log.log_index,
            )
        })
        .collect::<Vec<_>>();
    drop(hints_response);
    let mut messages = BTreeMap::new();
    for (hinted_index, hinted_block_hash, hinted_log_index) in hints {
        cancellation.check()?;
        let exact_response = execution
            .logs_at_hash(
                hinted_block_hash,
                production_canonical_context().bridge,
                arb_reth_l1::MESSAGE_DELIVERED_TOPIC,
                budget,
                cancellation,
                deadline,
            )
            .await?;
        let exact_logs = exact_response
            .value()
            .iter()
            .filter(|log| {
                batch_sequence(log) == Some(hinted_index) && log.log_index == hinted_log_index
            })
            .collect::<Vec<_>>();
        ensure!(
            exact_logs.len() == 1,
            "delayed metadata exact refetch is not unique"
        );
        let exact = (*exact_logs[0]).clone();
        let exact_header = execution
            .header_by_number(exact.block_number, budget, cancellation, deadline)
            .await?;
        ensure!(
            exact_header.value().hash == exact.block_hash,
            "delayed metadata exact block is no longer canonical"
        );
        let event = parse_message_delivered(&exact.topics, &exact.data, exact.block_number)
            .map_err(|error| eyre!("decode delayed metadata: {error}"))?;
        let body_charge = budget
            .reserve(
                arb_reth_l1::canonical::MAX_SINGLE_MESSAGE_BYTES
                    .checked_add(std::mem::size_of::<DelayedMessage>())
                    .ok_or_else(|| eyre!("delayed-message reservation overflows"))?,
                deadline,
                cancellation,
            )
            .await?;
        let inline = execution
            .logs_at_hash(
                exact.block_hash,
                event.inbox,
                arb_reth_l1::INBOX_MESSAGE_DELIVERED_TOPIC,
                budget,
                cancellation,
                deadline,
            )
            .await?;
        let origin = execution
            .logs_at_hash(
                exact.block_hash,
                event.inbox,
                arb_reth_l1::INBOX_MESSAGE_DELIVERED_FROM_ORIGIN_TOPIC,
                budget,
                cancellation,
                deadline,
            )
            .await?;
        let inline_logs = inline
            .value()
            .iter()
            .filter(|log| batch_sequence(log) == Some(event.index))
            .cloned()
            .collect::<Vec<_>>();
        let origin_logs = origin
            .value()
            .iter()
            .filter(|log| batch_sequence(log) == Some(event.index))
            .cloned()
            .collect::<Vec<_>>();
        ensure!(
            inline_logs.len() + origin_logs.len() == 1,
            "delayed body event is not unique"
        );
        let (body_log, from_origin) = if let Some(log) = inline_logs.first() {
            ensure!(
                log.topics.len() == 2,
                "delayed inline body has malformed indexed topics"
            );
            ((*log).clone(), false)
        } else {
            let log = &origin_logs[0];
            ensure!(
                log.topics.len() == 2 && log.data.is_empty(),
                "delayed from-origin body has malformed event encoding"
            );
            ((*log).clone(), true)
        };
        ensure!(
            body_log.block_hash == exact.block_hash
                && body_log.block_number == exact.block_number
                && body_log.transaction_hash == exact.transaction_hash
                && body_log.transaction_index == exact.transaction_index,
            "delayed metadata/body transaction coordinate mismatch"
        );
        let transaction = execution
            .transaction(body_log.transaction_hash, budget, cancellation, deadline)
            .await?;
        let receipt = execution
            .receipt(body_log.transaction_hash, budget, cancellation, deadline)
            .await?;
        ensure!(
            transaction.value().block_hash == body_log.block_hash
                && transaction.value().block_number == body_log.block_number
                && transaction.value().transaction_index == body_log.transaction_index
                && transaction.value().to == event.inbox
                && receipt.value().success
                && receipt.value().block_hash == body_log.block_hash
                && receipt.value().block_number == body_log.block_number
                && receipt.value().transaction_index == body_log.transaction_index
                && receipt.value().logs.contains(&exact)
                && receipt.value().logs.contains(&body_log),
            "delayed transaction/receipt/log coordinate mismatch"
        );
        let body = if from_origin {
            arb_reth_l1::decode_from_origin_message(&transaction.value().input)
                .map_err(|error| eyre!("decode from-origin delayed body: {error}"))?
        } else {
            parse_inbox_message_data(&body_log.data)
                .map_err(|error| eyre!("decode delayed inline body: {error}"))?
        };
        ensure!(
            body.len() <= arb_reth_l1::canonical::MAX_SINGLE_MESSAGE_BYTES,
            "delayed body exceeds 16 MiB"
        );
        let retained_body = body_charge.retain_bytes(
            body.len()
                .checked_add(std::mem::size_of::<DelayedMessage>())
                .ok_or_else(|| eyre!("delayed-message liability overflows"))?,
        )?;
        retained = retained.merge(retained_body)?;
        let index = event.index;
        ensure!(
            messages.insert(index, event.into_message(body)?).is_none(),
            "duplicate delayed message index"
        );
    }
    ensure!(
        (start..end).all(|index| messages.contains_key(&index)),
        "bounded dependency scan did not close delayed-message range"
    );
    Ok((messages.into_values().collect(), retained))
}

async fn resolve_report_stats(
    execution: &CanonicalExecutionClient,
    budget: &CanonicalMemoryBudget,
    cancellation: &CanonicalCancellation,
    deadline: tokio::time::Instant,
    containing: CanonicalExecutionHeader,
    delayed: &[DelayedMessage],
) -> eyre::Result<BTreeMap<B256, arbitrum_alloy_sequencer::sequencer::feed::BatchDataStats>> {
    let reports = delayed
        .iter()
        .filter(|message| message.kind == arb_reth_l1::assemble::KIND_BATCH_POSTING_REPORT)
        .map(|message| {
            Ok((
                report_batch_num(&message.data)
                    .ok_or_else(|| eyre!("batch posting report sequence is absent"))?,
                report_data_hash(&message.data)
                    .ok_or_else(|| eyre!("batch posting report data hash is absent"))?,
            ))
        })
        .collect::<eyre::Result<Vec<_>>>()?;
    if reports.is_empty() {
        return Ok(BTreeMap::new());
    }
    let unique_sequences = reports
        .iter()
        .map(|(sequence, _)| *sequence)
        .collect::<std::collections::BTreeSet<_>>();
    ensure!(
        unique_sequences.len() <= arb_reth_l1::canonical::MAX_BATCHES_PER_OBSERVATION_UNIT,
        "batch posting report dependency exceeds 64 batches"
    );
    let from = containing
        .number
        .saturating_sub(arb_reth_l1::canonical::MAX_DEPENDENCY_CLOSURE_L1_SPAN - 1);
    let hints_response = execution
        .dependency_discovery_logs(
            from,
            containing.number,
            Some(production_canonical_context().sequencer_inbox),
            arb_reth_l1::SEQUENCER_BATCH_DELIVERED_TOPIC,
            budget,
            cancellation,
            deadline,
        )
        .await?;
    let hints = hints_response
        .value()
        .iter()
        .filter_map(|log| {
            let sequence = batch_sequence(log)?;
            unique_sequences.contains(&sequence).then_some((
                sequence,
                log.block_hash,
                log.log_index,
            ))
        })
        .collect::<Vec<_>>();
    drop(hints_response);
    let mut stats = BTreeMap::new();
    for sequence in unique_sequences {
        cancellation.check()?;
        let candidates = hints
            .iter()
            .filter(|(hinted_sequence, _, _)| *hinted_sequence == sequence)
            .collect::<Vec<_>>();
        ensure!(
            candidates.len() == 1,
            "reported batch delivery is not unique in dependency span"
        );
        let (batch, source_charge) = resolve_reported_batch_source(
            execution,
            budget,
            cancellation,
            deadline,
            candidates[0].0,
            candidates[0].1,
            candidates[0].2,
        )
        .await?;
        let serialized_charge = budget
            .reserve(
                arb_reth_l1::canonical::MAX_RESOLVED_BATCH_PAYLOAD_BYTES,
                deadline,
                cancellation,
            )
            .await?;
        let serialized = serialize_batch(&batch);
        ensure!(
            serialized.len() <= arb_reth_l1::canonical::MAX_RESOLVED_BATCH_PAYLOAD_BYTES,
            "reported batch serialization exceeds 16 MiB"
        );
        let hash = keccak256(&serialized);
        ensure!(
            reports
                .iter()
                .filter(|(reported_sequence, _)| *reported_sequence == sequence)
                .all(|(_, reported_hash)| *reported_hash == hash),
            "batch posting report data hash disagrees with exact source serialization"
        );
        let computed = batch_data_stats(&serialized);
        drop(serialized_charge);
        drop(source_charge);
        ensure!(
            stats.insert(hash, computed).is_none(),
            "duplicate report data hash maps to two batches"
        );
    }
    Ok(stats)
}

async fn resolve_reported_batch_source(
    execution: &CanonicalExecutionClient,
    budget: &CanonicalMemoryBudget,
    cancellation: &CanonicalCancellation,
    deadline: tokio::time::Instant,
    hinted_sequence: u64,
    hinted_block_hash: B256,
    hinted_log_index: u32,
) -> eyre::Result<(DeliveredBatch, CanonicalMemoryReservation)> {
    let exact = execution
        .logs_at_hash(
            hinted_block_hash,
            production_canonical_context().sequencer_inbox,
            arb_reth_l1::SEQUENCER_BATCH_DELIVERED_TOPIC,
            budget,
            cancellation,
            deadline,
        )
        .await?;
    let deliveries = exact
        .value()
        .iter()
        .filter(|log| {
            batch_sequence(log) == Some(hinted_sequence) && log.log_index == hinted_log_index
        })
        .collect::<Vec<_>>();
    ensure!(
        deliveries.len() == 1,
        "reported batch exact delivery log is not unique"
    );
    let delivery = (*deliveries[0]).clone();
    let header = execution
        .header_by_number(delivery.block_number, budget, cancellation, deadline)
        .await?;
    ensure!(
        header.value().hash == delivery.block_hash,
        "reported batch exact block is no longer canonical"
    );
    let event = arb_reth_derive_batch_event(&delivery)?;
    let sequence =
        batch_sequence(&delivery).ok_or_else(|| eyre!("reported batch sequence absent"))?;
    drop(exact);
    let transaction = execution
        .transaction(delivery.transaction_hash, budget, cancellation, deadline)
        .await?;
    let receipt = execution
        .receipt(delivery.transaction_hash, budget, cancellation, deadline)
        .await?;
    ensure!(
        transaction.value().block_hash == delivery.block_hash
            && transaction.value().block_number == delivery.block_number
            && transaction.value().transaction_index == delivery.transaction_index
            && transaction.value().to == production_canonical_context().sequencer_inbox
            && receipt.value().success
            && receipt.value().block_hash == delivery.block_hash
            && receipt.value().block_number == delivery.block_number
            && receipt.value().transaction_index == delivery.transaction_index
            && receipt.value().logs.contains(&delivery),
        "reported batch transaction/receipt/log coordinate mismatch"
    );
    let source_charge = budget
        .reserve(
            arb_reth_l1::canonical::MAX_RESOLVED_BATCH_PAYLOAD_BYTES,
            deadline,
            cancellation,
        )
        .await?;
    let payload = match event.data_location {
        arb_reth_l1::data_location::TX_INPUT => BatchPayload::Calldata(
            extract_calldata_payload(&transaction.value().input)
                .map_err(|error| eyre!("extract reported calldata: {error}"))?,
        ),
        arb_reth_l1::data_location::SEPARATE_BATCH_EVENT => {
            let logs = execution
                .logs_at_hash(
                    delivery.block_hash,
                    production_canonical_context().sequencer_inbox,
                    arb_reth_l1::SEQUENCER_BATCH_DATA_TOPIC,
                    budget,
                    cancellation,
                    deadline,
                )
                .await?;
            let matching = logs
                .value()
                .iter()
                .filter(|log| batch_sequence(log) == Some(sequence))
                .collect::<Vec<_>>();
            ensure!(
                matching.len() == 1 && matching[0].topics.len() == 2,
                "reported separate batch event is not unique or canonically encoded"
            );
            let payload = decode_separate_batch_event_data(&matching[0].data)?;
            ensure!(
                payload.len() <= arb_reth_l1::canonical::MAX_RESOLVED_BATCH_PAYLOAD_BYTES,
                "reported separate-event payload exceeds 16 MiB"
            );
            BatchPayload::Calldata(payload)
        }
        arb_reth_l1::data_location::NO_DATA => BatchPayload::None,
        arb_reth_l1::data_location::BLOB_HASHES => {
            ensure!(
                (1..=arb_reth_l1::canonical::MAX_BLOBS_PER_POSTING_TRANSACTION)
                    .contains(&transaction.value().blob_versioned_hashes.len()),
                "reported batch blob count is outside 1..=16"
            );
            BatchPayload::Blob {
                versioned_hashes: transaction.value().blob_versioned_hashes.clone(),
                block_number: delivery.block_number,
            }
        }
        other => return Err(eyre!("unsupported reported batch data location {other}")),
    };
    let batch = DeliveredBatch {
        sequence_number: sequence,
        before_acc: delivery.topics[2],
        after_acc: delivery.topics[3],
        event,
        payload,
    };
    if let BatchPayload::Calldata(payload) = &batch.payload {
        ensure!(
            payload.len() <= arb_reth_l1::canonical::MAX_RESOLVED_BATCH_PAYLOAD_BYTES,
            "reported calldata payload exceeds 16 MiB"
        );
    }
    let retained_bytes = match &batch.payload {
        BatchPayload::Calldata(payload) => payload.len(),
        BatchPayload::Blob {
            versioned_hashes, ..
        } => versioned_hashes.len() * std::mem::size_of::<B256>(),
        BatchPayload::None => 1,
    };
    Ok((batch, source_charge.retain_bytes(retained_bytes.max(1))?))
}

async fn sequencer_accumulator_call(
    execution: &CanonicalExecutionClient,
    sequence: u64,
    safe_hash: B256,
    budget: &CanonicalMemoryBudget,
    cancellation: &CanonicalCancellation,
    deadline: tokio::time::Instant,
) -> eyre::Result<B256> {
    Ok(execution
        .call_at_hash(
            production_canonical_context().bridge,
            Bytes::from(arb_reth_l1::encode_sequencer_accumulator_call(sequence)),
            safe_hash,
            budget,
            cancellation,
            deadline,
        )
        .await?)
}

async fn delayed_accumulator_call(
    execution: &CanonicalExecutionClient,
    index: u64,
    safe_hash: B256,
    budget: &CanonicalMemoryBudget,
    cancellation: &CanonicalCancellation,
    deadline: tokio::time::Instant,
) -> eyre::Result<B256> {
    Ok(execution
        .call_at_hash(
            production_canonical_context().bridge,
            Bytes::from(arb_reth_l1::encode_delayed_accumulator_call(index)),
            safe_hash,
            budget,
            cancellation,
            deadline,
        )
        .await?)
}

#[allow(clippy::too_many_arguments)]
async fn publish_unit(
    directory: &JournalDirectory,
    context: StorageContextV3,
    lock: &DatadirLock,
    execution: &CanonicalExecutionClient,
    beacon: &CanonicalBeaconClient,
    budget: &CanonicalMemoryBudget,
    cancellation: &CanonicalCancellation,
    deadline: tokio::time::Instant,
    journal: &mut MessageJournalInspection,
    prepared: Vec<PreparedBatch>,
    durable_mutation_started: Arc<AtomicBool>,
) -> eyre::Result<()> {
    let mut simulated = journal.clone();
    for batch in &prepared {
        let comparison = match compare_complete_l1_batch(&simulated, &batch.messages) {
            Ok(comparison) => comparison,
            Err(error) => {
                let Some(sequence) = message_divergence_sequence(&error) else {
                    return Err(error);
                };
                let durable = journal
                    .entry(sequence)
                    .ok_or_else(|| eyre!("divergent durable identity is absent"))?;
                let observed = batch
                    .messages
                    .iter()
                    .find(|message| message.sequence_number() == sequence)
                    .ok_or_else(|| eyre!("divergent canonical message is absent"))?;
                let observed_fingerprint = fingerprint_message(observed.message())?;
                ensure!(
                    !durable
                        .fingerprint
                        .semantically_matches(observed_fingerprint),
                    "semantic enrichment omission cannot create divergence-v4"
                );
                write_authenticated_marker(
                    directory,
                    lock,
                    execution,
                    beacon,
                    budget,
                    cancellation,
                    deadline,
                    journal,
                    batch,
                    sequence,
                    marker_observation(journal, batch, sequence)?,
                    DivergenceCauseV4::FeedL1IdentityMismatch,
                    fingerprint_commitment(durable.fingerprint),
                    fingerprint_commitment(observed_fingerprint),
                    journal.latest_authority_id,
                    journal.latest_authority_chain_digest,
                    marker_observation(journal, batch, sequence)?.evidence_digest(),
                )
                .await?;
                return Err(eyre!(
                    "durable feed/L1 divergence-v4 marker written; datadir closed"
                ));
            }
        };
        let marker_sequence = comparison
            .covered_start_sequence
            .unwrap_or_else(|| journal.v.expect("V checked at startup").sequence + 1);
        if comparison.covered_start_sequence.is_some() {
            if let Some((expected, observed)) = batch.sequencer_mismatch {
                write_authenticated_marker(
                    directory,
                    lock,
                    execution,
                    beacon,
                    budget,
                    cancellation,
                    deadline,
                    journal,
                    batch,
                    marker_sequence,
                    marker_observation(journal, batch, marker_sequence)?,
                    DivergenceCauseV4::SequencerAccumulatorMismatch,
                    B256::ZERO,
                    B256::ZERO,
                    journal.latest_authority_id,
                    expected,
                    observed,
                )
                .await?;
                return Err(eyre!(
                    "durable sequencer-accumulator divergence-v4 marker written; datadir closed"
                ));
            }
            if let Some((expected, observed)) = batch.delayed_mismatch {
                ensure!(
                    batch.batch.event.after_delayed_messages_read > 0,
                    "zero delayed count cannot create cause-4 divergence"
                );
                write_authenticated_marker(
                    directory,
                    lock,
                    execution,
                    beacon,
                    budget,
                    cancellation,
                    deadline,
                    journal,
                    batch,
                    marker_sequence,
                    marker_observation(journal, batch, marker_sequence)?,
                    DivergenceCauseV4::DelayedAccumulatorMismatch,
                    B256::ZERO,
                    B256::ZERO,
                    journal.latest_authority_id,
                    expected,
                    observed,
                )
                .await?;
                return Err(eyre!(
                    "durable delayed-accumulator divergence-v4 marker written; datadir closed"
                ));
            }
        }
        for (start, end) in comparison.authority_splits(context.anchor.sequence)? {
            build_observation(&simulated, batch, start, end)?;
        }
        if let Some(end) = comparison.covered_end_sequence {
            let identity = simulated
                .identity(end)
                .ok_or_else(|| eyre!("simulated authority endpoint is absent"))?;
            simulated.v = Some(arb_reth_engine::MessageJournalAnchor {
                sequence: end,
                block_number: identity.block_number,
                block_hash: identity.block_hash,
            });
        }
    }
    ensure!(
        simulated.v == Some(simulated.watermark),
        "complete comparison unit does not cover every identity through J"
    );
    for batch in prepared {
        publish_prepared(
            directory,
            context,
            lock,
            execution,
            beacon,
            budget,
            cancellation,
            deadline,
            journal,
            batch,
            durable_mutation_started.clone(),
        )
        .await?;
    }
    Ok(())
}

fn marker_observation(
    journal: &MessageJournalInspection,
    prepared: &PreparedBatch,
    candidate: u64,
) -> eyre::Result<CanonicalObservationV1> {
    let end = prepared
        .messages
        .last()
        .ok_or_else(|| eyre!("canonical batch is empty"))?
        .sequence_number()
        .min(journal.watermark.sequence);
    let start = prepared
        .messages
        .first()
        .ok_or_else(|| eyre!("canonical batch is empty"))?
        .sequence_number()
        .max(candidate);
    build_observation(journal, prepared, start, end)
}

#[allow(clippy::too_many_arguments)]
async fn write_authenticated_marker(
    directory: &JournalDirectory,
    lock: &DatadirLock,
    execution: &CanonicalExecutionClient,
    beacon: &CanonicalBeaconClient,
    budget: &CanonicalMemoryBudget,
    cancellation: &CanonicalCancellation,
    deadline: tokio::time::Instant,
    journal: &MessageJournalInspection,
    prepared: &PreparedBatch,
    candidate_sequence: u64,
    observation: CanonicalObservationV1,
    cause: DivergenceCauseV4,
    expected_fingerprint: B256,
    observed_fingerprint: B256,
    cause_authority_id: B256,
    expected_value: B256,
    observed_value: B256,
) -> eyre::Result<()> {
    lock.prove_path()?;
    let fresh = inspect_message_journal(directory, production_storage_context())?;
    ensure!(
        fresh == *journal,
        "journal moved before divergence-v4 marker fence"
    );
    reproduce_marker_evidence(
        execution,
        beacon,
        budget,
        cancellation,
        deadline,
        journal,
        prepared,
        candidate_sequence,
        cause,
        observed_fingerprint,
        expected_value,
        observed_value,
        observation,
    )
    .await?;
    revalidate_provider_fence(
        execution,
        budget,
        cancellation,
        deadline,
        prepared,
        observation,
    )
    .await?;
    let v = journal.v.ok_or_else(|| eyre!("divergence-v4 requires V"))?;
    let marker = DivergenceMarkerV4 {
        cause,
        journal_operation_generation: journal.last_operation_generation,
        authority_chain_position: journal.authority_operation_count,
        context_id: observation.context_id,
        context_digest: observation.context_digest,
        j_sequence: journal.watermark.sequence,
        j_l2_block_number: journal.watermark.block_number,
        j_l2_block_hash: journal.watermark.block_hash,
        v_sequence: v.sequence,
        v_l2_block_number: v.block_number,
        v_l2_block_hash: v.block_hash,
        candidate_sequence,
        candidate_l2_block_number: candidate_sequence,
        expected_fingerprint,
        observed_fingerprint,
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
        cause_authority_id,
        expected_value,
        observed_value,
    };
    marker.validate_against(journal, observation)?;
    cancellation.check()?;
    // Marker work is not an enqueued B1 authority item: the total deadline still applies.
    let marker_directory = directory.clone();
    tokio::task::spawn_blocking(move || write_divergence_marker_v4(&marker_directory, marker))
        .await
        .map_err(|error| eyre!("divergence-v4 writer task failed: {error}"))??;
    ensure!(
        inspect_message_journal(directory, production_storage_context())? == *journal,
        "journal moved during divergence-v4 marker fsync"
    );
    // The complete pre-write proof authorizes permanent closure. The post-write fence is final
    // validation, not prevention: movement or provider failure never clears the durable marker.
    revalidate_provider_fence(
        execution,
        budget,
        cancellation,
        deadline,
        prepared,
        observation,
    )
    .await
    .wrap_err("post-write fence failed; permanent divergence-v4 marker stands")?;
    reproduce_marker_evidence(
        execution,
        beacon,
        budget,
        cancellation,
        deadline,
        journal,
        prepared,
        candidate_sequence,
        cause,
        observed_fingerprint,
        expected_value,
        observed_value,
        observation,
    )
    .await
    .wrap_err("post-write evidence changed; permanent divergence-v4 marker stands")?;
    lock.prove_path()?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn reproduce_marker_evidence(
    execution: &CanonicalExecutionClient,
    beacon: &CanonicalBeaconClient,
    budget: &CanonicalMemoryBudget,
    cancellation: &CanonicalCancellation,
    deadline: tokio::time::Instant,
    journal: &MessageJournalInspection,
    prepared: &PreparedBatch,
    candidate_sequence: u64,
    cause: DivergenceCauseV4,
    observed_fingerprint: B256,
    expected_value: B256,
    observed_value: B256,
    observation: CanonicalObservationV1,
) -> eyre::Result<()> {
    let reproduced = resolve_batch(
        execution,
        beacon,
        budget,
        cancellation,
        deadline,
        prepared.safe,
        prepared.containing,
        prepared.delivery.clone(),
        prepared.start_delayed_count,
        prepared.batch_start_sequence,
    )
    .await?;
    ensure!(
        build_observation(
            journal,
            &reproduced,
            observation.promoted_start_sequence,
            observation.promoted_end_sequence,
        )? == observation,
        "canonical observation changed while reproducing divergence-v4"
    );
    match cause {
        DivergenceCauseV4::FeedL1IdentityMismatch => {
            let message = reproduced
                .messages
                .iter()
                .find(|message| message.sequence_number() == candidate_sequence)
                .ok_or_else(|| eyre!("reproduced cause-1 message is absent"))?;
            ensure!(
                fingerprint_commitment(fingerprint_message(message.message())?)
                    == observed_fingerprint,
                "cause-1 L1 fingerprint did not reproduce"
            );
        }
        DivergenceCauseV4::SequencerAccumulatorMismatch => ensure!(
            reproduced.sequencer_mismatch == Some((expected_value, observed_value)),
            "cause-3 accumulator mismatch did not reproduce"
        ),
        DivergenceCauseV4::DelayedAccumulatorMismatch => ensure!(
            reproduced.delayed_mismatch == Some((expected_value, observed_value)),
            "cause-4 accumulator mismatch did not reproduce"
        ),
        DivergenceCauseV4::CompactObservationMismatch => ensure!(
            observation.evidence_digest() == observed_value && expected_value != observed_value,
            "cause-5 observation mismatch did not reproduce"
        ),
        DivergenceCauseV4::ExistingAuthorityInvalidatedBySafeReorg => {
            let mut found = false;
            for record in journal.bootstrap_authority().into_iter().chain(
                journal
                    .retained_grid
                    .iter()
                    .map(|retained| retained.authority),
            ) {
                let header = execution
                    .header_by_number(
                        record.locator.containing_l1_number,
                        budget,
                        cancellation,
                        deadline,
                    )
                    .await?;
                if record.start_sequence == candidate_sequence {
                    ensure!(
                        header.value().hash != record.locator.containing_l1_hash,
                        "safe advancement alone does not prove invalidated authority"
                    );
                    found = true;
                    break;
                }
                ensure!(
                    header.value().hash == record.locator.containing_l1_hash,
                    "an earlier retained authority was invalidated during the complete fence"
                );
            }
            ensure!(found, "first invalidated authority material is absent");
        }
        DivergenceCauseV4::ImpossibleDurablePredecessorContradiction => {}
    }
    Ok(())
}

async fn revalidate_provider_fence(
    execution: &CanonicalExecutionClient,
    budget: &CanonicalMemoryBudget,
    cancellation: &CanonicalCancellation,
    deadline: tokio::time::Instant,
    prepared: &PreparedBatch,
    observation: CanonicalObservationV1,
) -> eyre::Result<()> {
    let safe = execution
        .header_by_tag("safe", budget, cancellation, deadline)
        .await?;
    let containing = execution
        .header_by_number(prepared.containing.number, budget, cancellation, deadline)
        .await?;
    ensure!(
        *safe.value() == prepared.safe && *containing.value() == prepared.containing,
        "safe/evidence block moved during divergence-v4 fence"
    );
    drop(safe);
    drop(containing);
    let logs = execution
        .logs_at_hash(
            prepared.containing.hash,
            production_canonical_context().sequencer_inbox,
            arb_reth_l1::SEQUENCER_BATCH_DELIVERED_TOPIC,
            budget,
            cancellation,
            deadline,
        )
        .await?;
    ensure!(
        logs.value()
            .iter()
            .filter(|log| **log == prepared.delivery)
            .count()
            == 1,
        "delivery log moved during divergence-v4 fence"
    );
    drop(logs);
    let transaction = execution
        .transaction(
            prepared.posting_transaction_hash,
            budget,
            cancellation,
            deadline,
        )
        .await?;
    ensure!(
        transaction.value().hash == prepared.posting_transaction_hash
            && transaction.value().block_number == prepared.containing.number
            && transaction.value().block_hash == prepared.containing.hash
            && transaction.value().transaction_index == prepared.posting_transaction_index
            && transaction.value().to == production_canonical_context().sequencer_inbox,
        "posting transaction moved during divergence-v4 fence"
    );
    drop(transaction);
    let receipt = execution
        .receipt(
            prepared.posting_transaction_hash,
            budget,
            cancellation,
            deadline,
        )
        .await?;
    ensure!(
        receipt.value().success
            && receipt.value().block_number == prepared.containing.number
            && receipt.value().block_hash == prepared.containing.hash
            && receipt.value().transaction_index == prepared.posting_transaction_index
            && receipt.value().logs.contains(&prepared.delivery),
        "posting receipt moved during divergence-v4 fence"
    );
    drop(receipt);
    ensure!(
        sequencer_accumulator_call(
            execution,
            prepared.batch.sequence_number,
            prepared.safe.hash,
            budget,
            cancellation,
            deadline,
        )
        .await?
            == prepared.batch.after_acc,
        "provider sequencer state moved during divergence-v4 fence"
    );
    if prepared.batch.event.after_delayed_messages_read > 0 {
        ensure!(
            delayed_accumulator_call(
                execution,
                prepared.batch.event.after_delayed_messages_read - 1,
                prepared.safe.hash,
                budget,
                cancellation,
                deadline,
            )
            .await?
                == prepared.batch.event.delayed_acc,
            "provider delayed state moved during divergence-v4 fence"
        );
    }
    if observation.terminal_delayed_count > 0
        && observation.terminal_delayed_count != prepared.batch.event.after_delayed_messages_read
    {
        ensure!(
            delayed_accumulator_call(
                execution,
                observation.terminal_delayed_count - 1,
                prepared.safe.hash,
                budget,
                cancellation,
                deadline,
            )
            .await?
                == observation.terminal_delayed_accumulator,
            "provider delayed state disagrees with the split terminal observation"
        );
    }
    Ok(())
}

fn build_observation(
    journal: &MessageJournalInspection,
    prepared: &PreparedBatch,
    start: u64,
    end: u64,
) -> eyre::Result<CanonicalObservationV1> {
    let terminal = journal
        .identity(end)
        .ok_or_else(|| eyre!("authority terminal identity is not retained"))?;
    let terminal_delayed_count = prepared
        .messages
        .iter()
        .find(|message| message.sequence_number() == end)
        .ok_or_else(|| eyre!("authority terminal canonical message is absent"))?
        .message()
        .message_with_meta_data
        .delayed_messages_read;
    let delayed_offset = terminal_delayed_count
        .checked_sub(prepared.start_delayed_count)
        .and_then(|offset| usize::try_from(offset).ok())
        .ok_or_else(|| eyre!("authority terminal delayed count precedes its batch"))?;
    let local_terminal_delayed_accumulator = *prepared
        .delayed_accumulators
        .get(delayed_offset)
        .ok_or_else(|| eyre!("authority terminal delayed count exceeds its batch"))?;
    // A mismatch marker retains the authenticated event/getter value, not the contradictory
    // local formula. Mid-batch terminals retain their own count/accumulator, never beyond-J data.
    let terminal_delayed_accumulator =
        if terminal_delayed_count == prepared.batch.event.after_delayed_messages_read {
            prepared.batch.event.delayed_acc
        } else {
            local_terminal_delayed_accumulator
        };
    let observation = CanonicalObservationV1 {
        context_id: production_canonical_context().context_id,
        context_digest: production_canonical_context().digest()?,
        safe_l1_number: prepared.safe.number,
        safe_l1_hash: prepared.safe.hash,
        containing_l1_number: prepared.containing.number,
        containing_l1_hash: prepared.containing.hash,
        posting_transaction_hash: prepared.posting_transaction_hash,
        posting_transaction_index: prepared.posting_transaction_index,
        delivery_log_index: prepared.delivery_log_index,
        batch_sequence: prepared.batch.sequence_number,
        terminal_message_ordinal: u32::try_from(end - prepared.batch_start_sequence)?,
        decoded_message_count: u32::try_from(prepared.messages.len())?,
        start_delayed_count: prepared.start_delayed_count,
        terminal_delayed_count,
        terminal_sequencer_accumulator: prepared.batch.after_acc,
        terminal_delayed_accumulator,
        payload_kind: prepared.payload_kind,
        payload_digest: prepared.payload_digest,
        promoted_start_sequence: start,
        promoted_end_sequence: end,
        terminal_l2_block_number: terminal.block_number,
        terminal_l2_block_hash: terminal.block_hash,
        promoted_identities_digest: journal.promoted_identities_digest(start, end)?,
    };
    observation.validate()?;
    Ok(observation)
}

#[allow(clippy::too_many_arguments)]
async fn publish_prepared(
    directory: &JournalDirectory,
    context: StorageContextV3,
    lock: &DatadirLock,
    execution: &CanonicalExecutionClient,
    beacon: &CanonicalBeaconClient,
    budget: &CanonicalMemoryBudget,
    cancellation: &CanonicalCancellation,
    deadline: tokio::time::Instant,
    journal: &mut MessageJournalInspection,
    prepared: PreparedBatch,
    durable_mutation_started: Arc<AtomicBool>,
) -> eyre::Result<()> {
    let comparison = compare_complete_l1_batch(journal, &prepared.messages)?;
    let splits = comparison.authority_splits(context.anchor.sequence)?;
    if splits.is_empty() {
        return Ok(());
    }
    for (start, end) in splits {
        lock.prove_path()?;
        let fresh = inspect_message_journal(directory, context)?;
        let fence = fresh.authority_fence()?;
        ensure!(
            start == fence.verified.sequence + 1,
            "authority split fence became stale"
        );
        let first_observation = build_observation(&fresh, &prepared, start, end)?;
        let second = resolve_batch(
            execution,
            beacon,
            budget,
            cancellation,
            deadline,
            prepared.safe,
            prepared.containing,
            prepared.delivery.clone(),
            prepared.start_delayed_count,
            prepared.batch_start_sequence,
        )
        .await?;
        compare_complete_l1_batch(&fresh, &second.messages)?;
        let observation = build_observation(&fresh, &second, start, end)?;
        if first_observation.evidence_digest() != observation.evidence_digest() {
            write_authenticated_marker(
                directory,
                lock,
                execution,
                beacon,
                budget,
                cancellation,
                deadline,
                &fresh,
                &second,
                start,
                observation,
                DivergenceCauseV4::CompactObservationMismatch,
                B256::ZERO,
                B256::ZERO,
                fresh.latest_authority_id,
                first_observation.evidence_digest(),
                observation.evidence_digest(),
            )
            .await?;
            return Err(eyre!(
                "durable compact-observation divergence-v4 marker written; datadir closed"
            ));
        }
        revalidate_provider_fence(
            execution,
            budget,
            cancellation,
            deadline,
            &second,
            observation,
        )
        .await?;
        drop(second);
        ensure!(
            inspect_message_journal(directory, context)?.authority_fence()? == fence,
            "journal moved during final authority publication fence"
        );
        let candidate = AuthorityCandidateV3 {
            fence,
            start_sequence: start,
            end_sequence: end,
            observation,
        };
        cancellation.check()?;
        let initial_d = alloy_eips::BlockNumHash {
            number: fresh.watermark.block_number,
            hash: fresh.watermark.block_hash,
        };
        let runtime = JournalRuntime::open(directory.clone(), context, initial_d)?;
        // No await between successful enqueue and entering uncancellable durability.
        let acknowledgement = match runtime.client.enqueue_authority(candidate) {
            Ok(acknowledgement) => acknowledgement,
            Err(error) => {
                runtime.shutdown()?;
                return Err(error);
            }
        };
        durable_mutation_started.store(true, Ordering::Release);
        let task = tokio::task::spawn_blocking(move || {
            acknowledgement
                .recv()
                .map_err(|_| eyre!("authority acknowledgement dropped"))?
        })
        .await;
        let result = match task {
            Ok(result) => result,
            Err(error) => {
                let shutdown = runtime.shutdown();
                durable_mutation_started.store(false, Ordering::Release);
                shutdown?;
                return Err(eyre!("authority publication task failed: {error}"));
            }
        };
        let drain = runtime.client.drain();
        let shutdown = runtime.shutdown();
        durable_mutation_started.store(false, Ordering::Release);
        match result {
            Ok(acknowledgement) => {
                drain?;
                shutdown?;
                ensure!(
                    acknowledgement.record.end_sequence == end,
                    "authority acknowledgement endpoint changed"
                );
            }
            Err(error) if is_authority_candidate_stale(&error) => {
                drain?;
                shutdown?;
                let locked = inspect_message_journal(directory, context)?;
                if impossible_predecessor_contradiction(fence, &locked) {
                    write_authenticated_marker(
                        directory,
                        lock,
                        execution,
                        beacon,
                        budget,
                        cancellation,
                        deadline,
                        &locked,
                        &prepared,
                        start,
                        build_observation(&locked, &prepared, start, end)?,
                        DivergenceCauseV4::ImpossibleDurablePredecessorContradiction,
                        B256::ZERO,
                        B256::ZERO,
                        fence.latest_authority_id,
                        fence.latest_authority_id,
                        locked.latest_authority_id,
                    )
                    .await?;
                    return Err(eyre!(
                        "durable impossible-predecessor divergence-v4 marker written; datadir closed"
                    ));
                }
                return Err(eyre!("authority candidate became stale; rebuild required"));
            }
            Err(error) => {
                drop(drain);
                shutdown?;
                return Err(error);
            }
        }
        *journal = inspect_message_journal(directory, context)?;
        ensure!(
            journal.v.is_some_and(|v| v.sequence == end),
            "durable V acknowledgement mismatch"
        );
    }
    lock.prove_path()?;
    Ok(())
}

fn impossible_predecessor_contradiction(
    fence: arb_reth_engine::AuthorityFenceV3,
    locked: &MessageJournalInspection,
) -> bool {
    locked.watermark == fence.journal
        && locked.v == Some(fence.verified)
        && locked.last_operation_generation == fence.journal_operation_generation
        && locked.authority_operation_count == fence.authority_chain_position
        && locked.latest_authority_id != fence.latest_authority_id
}

fn kzg_commitment(
    blob: &[u8; arb_reth_l1::BYTES_PER_BLOB],
    cancellation: &CanonicalCancellation,
    deadline: tokio::time::Instant,
) -> eyre::Result<[u8; 48]> {
    cancellation.check()?;
    let mut child = Command::new(std::env::current_exe()?)
        .env(KZG_HELPER_ENV, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .wrap_err("spawn isolated KZG helper")?;
    run_kzg_helper(&mut child, blob, cancellation, deadline)
}

fn run_kzg_helper(
    child: &mut Child,
    blob: &[u8; arb_reth_l1::BYTES_PER_BLOB],
    cancellation: &CanonicalCancellation,
    deadline: tokio::time::Instant,
) -> eyre::Result<[u8; 48]> {
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| eyre!("KZG helper stdin absent"))?;
    std::thread::scope(|scope| {
        let writer = scope.spawn(move || -> std::io::Result<()> {
            stdin.write_all(&KZG_TRUSTED_SETUP_DIGEST)?;
            stdin.write_all(blob)
        });
        loop {
            if cancellation.is_cancelled() || tokio::time::Instant::now() >= deadline {
                kill_and_reap(child)?;
                let _ = writer.join();
                cancellation.check()?;
                return Err(eyre!("KZG helper missed attempt deadline"));
            }
            if let Some(status) = child.try_wait()? {
                let write_result = writer
                    .join()
                    .map_err(|_| eyre!("KZG helper input writer panicked"))?;
                write_result.wrap_err("write KZG helper input")?;
                ensure!(status.success(), "KZG helper failed with {status}");
                let mut output = Vec::new();
                child
                    .stdout
                    .take()
                    .ok_or_else(|| eyre!("KZG helper stdout absent"))?
                    .take(49)
                    .read_to_end(&mut output)?;
                ensure!(output.len() == 48, "KZG helper output length is not 48");
                return Ok(output.try_into().expect("length checked"));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    })
}

fn kill_and_reap(child: &mut Child) -> eyre::Result<()> {
    if child.try_wait()?.is_none() {
        let result = unsafe { libc::kill(child.id() as i32, libc::SIGKILL) };
        ensure!(
            result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH),
            "failed to SIGKILL KZG helper"
        );
    }
    child.wait()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ObserverFixture {
        prepared: PreparedBatch,
        journal: MessageJournalInspection,
        directory: JournalDirectory,
        execution: CanonicalExecutionClient,
        beacon: CanonicalBeaconClient,
        budget: CanonicalMemoryBudget,
        cancellation: CanonicalCancellation,
        responses: Arc<std::sync::Mutex<BTreeMap<String, serde_json::Value>>>,
        requests: Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
        move_after_marker: Arc<AtomicBool>,
        server: tokio::task::JoinHandle<()>,
        _temp: tempfile::TempDir,
    }

    impl ObserverFixture {
        async fn new(covered: usize, mismatch: Option<usize>) -> Self {
            use serde_json::json;
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

            // Existing offline calldata fixture; synthetic containing/safe coordinates are
            // test-owned. No discovery or external provider supplies authority to this test.
            let metadata: serde_json::Value = serde_json::from_str(include_str!(
                "../../../arb-reth-derive/tests/fixtures/arb1_calldata_batch_497980_meta.json"
            ))
            .unwrap();
            let data = Bytes::from(
                alloy_primitives::hex::decode(
                    metadata["seq_batch_delivered_log_data"].as_str().unwrap(),
                )
                .unwrap(),
            );
            let input = include_str!(
                "../../../arb-reth-l1/tests/fixtures/arb1_calldata_batch_497980_l1_tx_input.hex"
            )
            .trim();
            let event = arb_reth_derive::batch::parse_sequencer_batch_delivered(&data).unwrap();
            let mut batch = DeliveredBatch {
                sequence_number: 497_980,
                before_acc: B256::repeat_byte(1),
                after_acc: B256::ZERO,
                event,
                payload: BatchPayload::Calldata(
                    extract_calldata_payload(&alloy_primitives::hex::decode(input).unwrap())
                        .unwrap(),
                ),
            };
            batch.after_acc = sequencer_accumulator(&batch);
            let containing = CanonicalExecutionHeader {
                number: 25_882_100,
                hash: B256::repeat_byte(2),
                parent_hash: B256::repeat_byte(3),
                timestamp: 1_786_269_023,
            };
            let safe = CanonicalExecutionHeader {
                number: containing.number + 1,
                hash: B256::repeat_byte(4),
                parent_hash: containing.hash,
                timestamp: containing.timestamp + 12,
            };
            let delivery = CanonicalExecutionLog {
                address: production_canonical_context().sequencer_inbox,
                topics: vec![
                    arb_reth_l1::SEQUENCER_BATCH_DELIVERED_TOPIC,
                    B256::from(alloy_primitives::U256::from(batch.sequence_number)),
                    batch.before_acc,
                    batch.after_acc,
                ],
                data,
                block_number: containing.number,
                block_hash: containing.hash,
                transaction_hash: B256::repeat_byte(5),
                transaction_index: 1,
                log_index: 2,
            };
            let log = json!({
                "address": delivery.address, "topics": delivery.topics, "data": delivery.data,
                "blockNumber": format!("0x{:x}", containing.number), "blockHash": containing.hash,
                "transactionHash": delivery.transaction_hash, "transactionIndex": "0x1",
                "logIndex": "0x2", "removed": false,
            });
            let mut responses = BTreeMap::new();
            for header in [safe, containing] {
                let value = json!({
                    "number": format!("0x{:x}", header.number), "hash": header.hash,
                    "parentHash": header.parent_hash, "timestamp": format!("0x{:x}", header.timestamp),
                });
                responses.insert(
                    format!("eth_getBlockByNumber:0x{:x}", header.number),
                    value.clone(),
                );
                if header == safe {
                    responses.insert("eth_getBlockByNumber:safe".to_owned(), value);
                }
            }
            responses.insert("eth_getLogs".to_owned(), json!([log]));
            responses.insert("eth_getTransactionByHash".to_owned(), json!({
                "hash": delivery.transaction_hash, "blockNumber": format!("0x{:x}", containing.number),
                "blockHash": containing.hash, "transactionIndex": "0x1", "to": delivery.address,
                "input": if input.starts_with("0x") { input.to_owned() } else { format!("0x{input}") },
                "blobVersionedHashes": [],
            }));
            responses.insert("eth_getTransactionReceipt".to_owned(), json!({
                "transactionHash": delivery.transaction_hash, "blockNumber": format!("0x{:x}", containing.number),
                "blockHash": containing.hash, "transactionIndex": "0x1", "status": "0x1", "logs": [log],
            }));
            responses.insert(
                format!(
                    "eth_call:{}",
                    Bytes::from(arb_reth_l1::encode_sequencer_accumulator_call(
                        batch.sequence_number
                    ))
                ),
                json!(batch.after_acc),
            );
            responses.insert(
                format!(
                    "eth_call:{}",
                    Bytes::from(arb_reth_l1::encode_delayed_accumulator_call(
                        batch.event.after_delayed_messages_read - 1
                    ))
                ),
                json!(batch.event.delayed_acc),
            );
            let responses = Arc::new(std::sync::Mutex::new(responses));
            let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
            let move_after_marker = Arc::new(AtomicBool::new(false));
            let temp = tempfile::tempdir().unwrap();
            let marker_path = temp.path().join(arb_reth_engine::DIVERGENCE_MARKER_FILE);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn({
                let responses = responses.clone();
                let requests = requests.clone();
                let move_after_marker = move_after_marker.clone();
                async move {
                    loop {
                        let (mut stream, _) = listener.accept().await.unwrap();
                        let mut raw = Vec::new();
                        while !raw.ends_with(b"\r\n\r\n") {
                            raw.push(stream.read_u8().await.unwrap());
                        }
                        let headers = String::from_utf8(raw).unwrap();
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap();
                        let mut body = vec![0; length];
                        stream.read_exact(&mut body).await.unwrap();
                        let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        let method = request["method"].as_str().unwrap();
                        let key = match method {
                            "eth_getBlockByNumber" => {
                                format!("{method}:{}", request["params"][0].as_str().unwrap())
                            }
                            "eth_call" => {
                                assert_eq!(
                                    request["params"][1],
                                    json!({"blockHash": safe.hash, "requireCanonical": true})
                                );
                                format!(
                                    "{method}:{}",
                                    request["params"][0]["data"].as_str().unwrap()
                                )
                            }
                            "eth_getLogs" => {
                                if let Some(requested_hash) =
                                    request["params"][0]["blockHash"].as_str()
                                {
                                    let exact_key = format!("{method}:{requested_hash}");
                                    if responses.lock().unwrap().contains_key(&exact_key) {
                                        exact_key
                                    } else {
                                        assert!(
                                            responses.lock().unwrap().iter().any(|(key, value)| {
                                                key.starts_with("eth_getBlockByNumber:")
                                                    && value["hash"] == requested_hash
                                            }),
                                            "eth_getLogs requested an unknown exact block hash"
                                        );
                                        let topic_key = format!(
                                            "{method}:{}",
                                            request["params"][0]["topics"][0].as_str().unwrap()
                                        );
                                        if responses.lock().unwrap().contains_key(&topic_key) {
                                            topic_key
                                        } else {
                                            method.to_owned()
                                        }
                                    }
                                } else {
                                    let topic_key = format!(
                                        "{method}:{}",
                                        request["params"][0]["topics"][0].as_str().unwrap()
                                    );
                                    if responses.lock().unwrap().contains_key(&topic_key) {
                                        topic_key
                                    } else {
                                        method.to_owned()
                                    }
                                }
                            }
                            "eth_getTransactionByHash" | "eth_getTransactionReceipt" => {
                                let tx_key =
                                    format!("{method}:{}", request["params"][0].as_str().unwrap());
                                if responses.lock().unwrap().contains_key(&tx_key) {
                                    tx_key
                                } else {
                                    method.to_owned()
                                }
                            }
                            _ => method.to_owned(),
                        };
                        let mut result = responses
                            .lock()
                            .unwrap()
                            .get(&key)
                            .unwrap_or_else(|| panic!("unexpected RPC {key}"))
                            .clone();
                        if key == "eth_getBlockByNumber:safe"
                            && move_after_marker.load(Ordering::Acquire)
                            && marker_path.exists()
                        {
                            result["hash"] = json!(B256::repeat_byte(0xee));
                        }
                        requests.lock().unwrap().push(request.clone());
                        let body = serde_json::to_vec(
                            &json!({"jsonrpc": "2.0", "id": request["id"], "result": result}),
                        )
                        .unwrap();
                        stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await.unwrap();
                        stream.write_all(&body).await.unwrap();
                    }
                }
            });
            let execution = CanonicalExecutionClient::new(endpoint.clone()).unwrap();
            let beacon = CanonicalBeaconClient::new(endpoint).unwrap();
            let budget = CanonicalMemoryBudget::default();
            let cancellation = CanonicalCancellation::default();
            let context = production_storage_context();
            let prepared = resolve_batch(
                &execution,
                &beacon,
                &budget,
                &cancellation,
                tokio::time::Instant::now() + Duration::from_secs(30),
                safe,
                containing,
                delivery,
                batch.event.after_delayed_messages_read,
                context.anchor.sequence + 1,
            )
            .await
            .unwrap();
            assert_eq!(prepared.messages.len(), 307);
            assert!(prepared.sequencer_mismatch.is_none());
            let directory = JournalDirectory::open(temp.path()).unwrap();
            let initial =
                arb_reth_engine::initialize_approved_snapshot_journal_v3(&directory, context)
                    .unwrap();
            // Offline stopped-J fixture, not a persistence notification or a production writer
            // bypass. Production inspection authenticates every frame before tests use it.
            let mut media = std::fs::OpenOptions::new()
                .append(true)
                .open(&initial.path)
                .unwrap();
            let mut previous_commit = initial.last_commit_digest;
            let mut parent_hash = context.anchor.block_hash;
            for (ordinal, input) in prepared.messages.iter().take(covered).enumerate() {
                let sequence = input.sequence_number();
                let block_hash = keccak256(sequence.to_be_bytes());
                let mut durable_message = input.message().clone();
                if mismatch == Some(ordinal) {
                    durable_message
                        .message_with_meta_data
                        .l1_incoming_message
                        .header
                        .timestamp += 1;
                }
                let entry = arb_reth_engine::MessageJournalEntry {
                    sequence,
                    block_number: sequence,
                    block_hash,
                    parent_hash,
                    delayed_messages_read: input
                        .message()
                        .message_with_meta_data
                        .delayed_messages_read,
                    fingerprint: fingerprint_message(&durable_message).unwrap(),
                    source: arb_reth_engine::ArbEngineInputSource::Feed,
                };
                use sha2::{Digest as _, Sha256};
                let hash = |domain: &str, payload: &[u8]| {
                    let mut digest = Sha256::new();
                    digest.update((domain.len() as u16).to_be_bytes());
                    digest.update(domain.as_bytes());
                    digest.update((payload.len() as u64).to_be_bytes());
                    digest.update(payload);
                    B256::from_slice(&digest.finalize())
                };
                let identity = arb_reth_engine::encode_identity(entry);
                let mut frame = vec![0; 136 + identity.len()];
                frame[0..4].copy_from_slice(&(132 + identity.len() as u32).to_be_bytes());
                frame[4..8].copy_from_slice(&(identity.len() as u32).to_be_bytes());
                let prefix = hash("arb-reth-journal-v3-frame-prefix", &frame[..8]);
                frame[8..40].copy_from_slice(prefix.as_slice());
                frame[40..48].copy_from_slice(b"ARBJFRM3");
                frame[48..50].copy_from_slice(&3u16.to_be_bytes());
                frame[50] = 0x11;
                frame[52..60].copy_from_slice(
                    &(initial.last_operation_generation + ordinal as u64 + 1).to_be_bytes(),
                );
                frame[60..92].copy_from_slice(previous_commit.as_slice());
                frame[92..96].copy_from_slice(&(identity.len() as u32).to_be_bytes());
                frame[96..288].copy_from_slice(&identity);
                frame[288..296].copy_from_slice(b"ARBJCMT3");
                previous_commit = hash("arb-reth-journal-v3-frame-commit", &frame[..296]);
                frame[296..328].copy_from_slice(previous_commit.as_slice());
                media.write_all(&frame).unwrap();
                parent_hash = block_hash;
            }
            media.sync_all().unwrap();
            drop(media);
            let journal = inspect_message_journal(&directory, context).unwrap();
            Self {
                prepared,
                journal,
                directory,
                execution,
                beacon,
                budget,
                cancellation,
                responses,
                requests,
                move_after_marker,
                server,
                _temp: temp,
            }
        }

        async fn resolve(&self) -> eyre::Result<PreparedBatch> {
            resolve_batch(
                &self.execution,
                &self.beacon,
                &self.budget,
                &self.cancellation,
                tokio::time::Instant::now() + Duration::from_secs(30),
                self.prepared.safe,
                self.prepared.containing,
                self.prepared.delivery.clone(),
                self.prepared.start_delayed_count,
                self.prepared.batch_start_sequence,
            )
            .await
        }

        async fn close(self) {
            self.server.abort();
            assert!(self.server.await.unwrap_err().is_cancelled());
        }
    }

    #[tokio::test]
    async fn production_resolver_rejects_transaction_receipt_and_getter_mutations() {
        use serde_json::json;
        let fixture = ObserverFixture::new(1, None).await;
        for (method, field, wrong) in [
            (
                "eth_getTransactionByHash",
                "hash",
                json!(B256::repeat_byte(9)),
            ),
            (
                "eth_getTransactionByHash",
                "blockHash",
                json!(B256::repeat_byte(9)),
            ),
            ("eth_getTransactionByHash", "transactionIndex", json!("0x2")),
            (
                "eth_getTransactionByHash",
                "to",
                json!(alloy_primitives::Address::ZERO),
            ),
            ("eth_getTransactionReceipt", "status", json!("0x0")),
            (
                "eth_getTransactionReceipt",
                "transactionIndex",
                json!("0x2"),
            ),
            (
                "eth_getTransactionReceipt",
                "blockHash",
                json!(B256::repeat_byte(9)),
            ),
            ("eth_getTransactionReceipt", "logs", json!([])),
        ] {
            let original = fixture
                .responses
                .lock()
                .unwrap()
                .get(method)
                .unwrap()
                .clone();
            fixture.responses.lock().unwrap().get_mut(method).unwrap()[field] = wrong;
            assert!(
                fixture.resolve().await.is_err(),
                "accepted {method}.{field} mutation"
            );
            assert!(
                !fixture
                    .directory
                    .entry_exists(arb_reth_engine::DIVERGENCE_MARKER_FILE)
                    .unwrap()
            );
            fixture
                .responses
                .lock()
                .unwrap()
                .insert(method.to_owned(), original);
        }
        let key = format!(
            "eth_call:{}",
            Bytes::from(arb_reth_l1::encode_sequencer_accumulator_call(
                fixture.prepared.batch.sequence_number
            ))
        );
        fixture
            .responses
            .lock()
            .unwrap()
            .insert(key, json!(B256::repeat_byte(9)));
        assert!(
            fixture
                .resolve()
                .await
                .err()
                .unwrap()
                .to_string()
                .contains("getter disagreement")
        );
        assert_eq!(
            inspect_message_journal(&fixture.directory, production_storage_context()).unwrap(),
            fixture.journal
        );
        fixture.close().await;
    }

    #[tokio::test]
    async fn production_publish_compares_through_mid_batch_j_and_refences_each_split() {
        let mut fixture = ObserverFixture::new(300, None).await;
        let before_position = fixture.journal.authority_operation_count;
        let lock = DatadirLock::acquire(&fixture.directory).unwrap();
        let prepared = fixture.resolve().await.unwrap();
        let flag = Arc::new(AtomicBool::new(false));
        publish_unit(
            &fixture.directory,
            production_storage_context(),
            &lock,
            &fixture.execution,
            &fixture.beacon,
            &fixture.budget,
            &fixture.cancellation,
            tokio::time::Instant::now() + Duration::from_secs(30),
            &mut fixture.journal,
            vec![prepared],
            flag.clone(),
        )
        .await
        .unwrap();
        assert_eq!(fixture.journal.v, Some(fixture.journal.watermark));
        assert_eq!(
            fixture.journal.authority_operation_count,
            before_position + 2
        );
        assert_eq!(
            fixture.journal.watermark.sequence,
            production_storage_context().anchor.sequence + 300
        );
        assert!(!flag.load(Ordering::Acquire));
        {
            let requests = fixture.requests.lock().unwrap();
            assert_eq!(
                requests
                    .iter()
                    .filter(|request| request["method"] == "eth_getBlockByNumber"
                        && request["params"][0] == "safe")
                    .count(),
                2
            );
        }
        fixture
            .responses
            .lock()
            .unwrap()
            .insert("eth_chainId".to_owned(), serde_json::json!("0x1"));
        fixture.responses.lock().unwrap().insert("eth_getBlockByNumber:0x0".to_owned(), serde_json::json!({
            "number": "0x0", "hash": L1_GENESIS_HASH, "parentHash": B256::ZERO, "timestamp": "0x0",
        }));
        let bootstrap_locator = production_bootstrap_authority().locator;
        let predecessor = CanonicalExecutionLog {
            address: fixture.prepared.delivery.address,
            topics: vec![
                arb_reth_l1::SEQUENCER_BATCH_DELIVERED_TOPIC,
                B256::from(alloy_primitives::U256::from(
                    fixture.prepared.batch.sequence_number - 1,
                )),
                B256::repeat_byte(7),
                fixture.prepared.batch.before_acc,
            ],
            data: fixture.prepared.delivery.data.clone(),
            block_number: fixture.prepared.containing.number - 1,
            block_hash: B256::repeat_byte(6),
            transaction_hash: B256::repeat_byte(8),
            transaction_index: fixture.prepared.delivery.transaction_index,
            log_index: fixture.prepared.delivery.log_index,
        };
        let predecessor_json = serde_json::json!({
            "address": predecessor.address,
            "topics": predecessor.topics,
            "data": predecessor.data,
            "blockNumber": format!("0x{:x}", predecessor.block_number),
            "blockHash": predecessor.block_hash,
            "transactionHash": predecessor.transaction_hash,
            "transactionIndex": format!("0x{:x}", predecessor.transaction_index),
            "logIndex": format!("0x{:x}", predecessor.log_index),
            "removed": false,
        });
        {
            let mut responses = fixture.responses.lock().unwrap();
            responses.insert(
                format!(
                    "eth_getBlockByNumber:0x{:x}",
                    bootstrap_locator.containing_l1_number
                ),
                serde_json::json!({
                    "number": format!("0x{:x}", bootstrap_locator.containing_l1_number),
                    "hash": bootstrap_locator.containing_l1_hash,
                    "parentHash": B256::ZERO,
                    "timestamp": "0x0",
                }),
            );
            responses.insert(
                format!("eth_getBlockByNumber:0x{:x}", predecessor.block_number),
                serde_json::json!({
                    "number": format!("0x{:x}", predecessor.block_number),
                    "hash": predecessor.block_hash,
                    "parentHash": B256::ZERO,
                    "timestamp": "0x0",
                }),
            );
            let delivery = responses["eth_getLogs"][0].clone();
            responses.insert(
                format!("eth_getLogs:{}", predecessor.block_hash),
                serde_json::json!([predecessor_json.clone()]),
            );
            responses.insert(
                format!("eth_getLogs:{}", fixture.prepared.containing.hash),
                serde_json::json!([delivery.clone()]),
            );
            responses.insert(
                "eth_getLogs".to_owned(),
                serde_json::json!([predecessor_json, delivery]),
            );
        }
        let prepared = prepare_unit(
            &fixture.execution,
            &fixture.beacon,
            &fixture.budget,
            &fixture.cancellation,
            tokio::time::Instant::now() + Duration::from_secs(30),
            &fixture.journal,
        )
        .await
        .unwrap();
        let PreparedUnit::Canonical(prepared) = prepared else {
            panic!("valid off-grid authority suffix must rederive canonically");
        };
        publish_unit(
            &fixture.directory,
            production_storage_context(),
            &lock,
            &fixture.execution,
            &fixture.beacon,
            &fixture.budget,
            &fixture.cancellation,
            tokio::time::Instant::now() + Duration::from_secs(30),
            &mut fixture.journal,
            prepared,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
        assert_eq!(
            fixture.journal.authority_operation_count,
            before_position + 2,
            "rederiving a valid off-grid suffix must not publish it again"
        );
        assert_eq!(fixture.journal.v, Some(fixture.journal.watermark));
        assert!(
            !fixture
                .directory
                .entry_exists(arb_reth_engine::DIVERGENCE_MARKER_FILE)
                .unwrap()
        );
        drop(lock);
        fixture.close().await;
    }

    #[tokio::test]
    async fn accumulator_and_compact_observation_causes_use_exact_production_fences() {
        use serde_json::json;
        for cause in [
            DivergenceCauseV4::SequencerAccumulatorMismatch,
            DivergenceCauseV4::CompactObservationMismatch,
        ] {
            let mut fixture = ObserverFixture::new(300, None).await;
            let lock = DatadirLock::acquire(&fixture.directory).unwrap();
            let before_journal = fixture.journal.clone();
            let mut prepared = fixture.resolve().await.unwrap();
            if cause == DivergenceCauseV4::SequencerAccumulatorMismatch {
                let wrong = B256::repeat_byte(9);
                fixture.prepared.delivery.topics[3] = wrong;
                {
                    let mut responses = fixture.responses.lock().unwrap();
                    responses.get_mut("eth_getLogs").unwrap()[0]["topics"][3] = json!(wrong);
                    responses.get_mut("eth_getTransactionReceipt").unwrap()["logs"][0]["topics"]
                        [3] = json!(wrong);
                    let key = format!(
                        "eth_call:{}",
                        Bytes::from(arb_reth_l1::encode_sequencer_accumulator_call(
                            prepared.batch.sequence_number
                        ))
                    );
                    responses.insert(key, json!(wrong));
                }
                prepared = fixture.resolve().await.unwrap();
                assert_eq!(
                    prepared.sequencer_mismatch,
                    Some((wrong, fixture.prepared.batch.after_acc))
                );
            } else {
                // Simulate two individually complete observations with the same locator/state
                // but different payload digests. The publication path must use the split's
                // exact second digest, not silently replace its endpoint with J.
                prepared.payload_digest = B256::repeat_byte(9);
            }
            let flag = Arc::new(AtomicBool::new(false));
            let error = if cause == DivergenceCauseV4::CompactObservationMismatch {
                publish_prepared(
                    &fixture.directory,
                    production_storage_context(),
                    &lock,
                    &fixture.execution,
                    &fixture.beacon,
                    &fixture.budget,
                    &fixture.cancellation,
                    tokio::time::Instant::now() + Duration::from_secs(30),
                    &mut fixture.journal,
                    prepared,
                    flag.clone(),
                )
                .await
                .unwrap_err()
            } else {
                publish_unit(
                    &fixture.directory,
                    production_storage_context(),
                    &lock,
                    &fixture.execution,
                    &fixture.beacon,
                    &fixture.budget,
                    &fixture.cancellation,
                    tokio::time::Instant::now() + Duration::from_secs(30),
                    &mut fixture.journal,
                    vec![prepared],
                    flag.clone(),
                )
                .await
                .unwrap_err()
            };
            assert!(error.to_string().contains("marker written"), "{error:?}");
            let marker = arb_reth_engine::read_divergence_marker_v4(&fixture.directory).unwrap();
            assert_eq!(marker.cause, cause);
            assert_eq!(
                marker.candidate_sequence,
                before_journal.v.unwrap().sequence + 1
            );
            assert_eq!(
                marker.cause_authority_id,
                before_journal.latest_authority_id
            );
            if cause == DivergenceCauseV4::CompactObservationMismatch {
                assert_eq!(marker.terminal_message_ordinal, 255);
            }
            assert_eq!(
                inspect_message_journal(&fixture.directory, production_storage_context()).unwrap(),
                before_journal
            );
            assert!(!flag.load(Ordering::Acquire));
            drop(lock);
            fixture.close().await;
        }
    }

    #[tokio::test]
    async fn delayed_cause_keeps_j_terminal_metadata_when_delayed_tail_is_beyond_j() {
        use serde_json::json;
        let mut fixture = ObserverFixture::new(300, None).await;
        let lock = DatadirLock::acquire(&fixture.directory).unwrap();
        let before_journal = fixture.journal.clone();
        let before_acc = fixture.prepared.batch.event.delayed_acc;
        let index = fixture.prepared.start_delayed_count;
        let inbox = alloy_primitives::Address::repeat_byte(0xa);
        let delayed = DelayedMessage {
            kind: 12,
            sender: alloy_primitives::Address::repeat_byte(0xb),
            block_number: fixture.prepared.containing.number,
            timestamp: fixture.prepared.containing.timestamp,
            inbox_seq_num: index,
            base_fee_l1: alloy_primitives::U256::from(7),
            data: vec![0; 32],
            before_inbox_acc: before_acc,
        };
        let wrong = B256::repeat_byte(9);
        assert_ne!(wrong, delayed.accumulator());
        fixture.prepared.batch.event.after_delayed_messages_read += 1;
        fixture.prepared.batch.event.delayed_acc = wrong;
        fixture.prepared.batch.after_acc = sequencer_accumulator(&fixture.prepared.batch);
        fixture.prepared.delivery.topics[3] = fixture.prepared.batch.after_acc;
        let mut delivery_data = fixture.prepared.delivery.data.to_vec();
        delivery_data[..32].copy_from_slice(wrong.as_slice());
        delivery_data[56..64].copy_from_slice(&(index + 1).to_be_bytes());
        fixture.prepared.delivery.data = Bytes::from(delivery_data);
        let mut metadata = vec![0; 6 * 32];
        metadata[12..32].copy_from_slice(inbox.as_slice());
        metadata[63] = delayed.kind;
        metadata[76..96].copy_from_slice(delayed.sender.as_slice());
        metadata[96..128].copy_from_slice(delayed.message_data_hash().as_slice());
        metadata[128..160].copy_from_slice(&delayed.base_fee_l1.to_be_bytes::<32>());
        metadata[184..192].copy_from_slice(&delayed.timestamp.to_be_bytes());
        let mut body = vec![0; 96];
        body[31] = 32;
        body[63] = 32;
        body[64..].copy_from_slice(&delayed.data);
        {
            let mut responses = fixture.responses.lock().unwrap();
            let mut delivery_log = responses["eth_getLogs"][0].clone();
            delivery_log["topics"] = json!(fixture.prepared.delivery.topics);
            delivery_log["data"] = json!(fixture.prepared.delivery.data);
            responses.insert("eth_getLogs".to_owned(), json!([delivery_log]));
            responses.get_mut("eth_getTransactionReceipt").unwrap()["logs"] = json!([delivery_log]);
            let mut delayed_log = delivery_log.clone();
            let tx = B256::repeat_byte(6);
            delayed_log["address"] = json!(production_canonical_context().bridge);
            delayed_log["topics"] = json!([
                arb_reth_l1::MESSAGE_DELIVERED_TOPIC,
                B256::from(alloy_primitives::U256::from(index)),
                before_acc
            ]);
            delayed_log["data"] = json!(Bytes::from(metadata));
            delayed_log["transactionHash"] = json!(tx);
            delayed_log["transactionIndex"] = json!("0x2");
            delayed_log["logIndex"] = json!("0x3");
            let mut body_log = delayed_log.clone();
            body_log["address"] = json!(inbox);
            body_log["topics"] = json!([
                arb_reth_l1::INBOX_MESSAGE_DELIVERED_TOPIC,
                B256::from(alloy_primitives::U256::from(index))
            ]);
            body_log["data"] = json!(Bytes::from(body));
            body_log["logIndex"] = json!("0x4");
            responses.insert(
                format!("eth_getLogs:{:#x}", arb_reth_l1::MESSAGE_DELIVERED_TOPIC),
                json!([delayed_log]),
            );
            responses.insert(
                format!(
                    "eth_getLogs:{:#x}",
                    arb_reth_l1::INBOX_MESSAGE_DELIVERED_TOPIC
                ),
                json!([body_log]),
            );
            responses.insert(
                format!(
                    "eth_getLogs:{:#x}",
                    arb_reth_l1::INBOX_MESSAGE_DELIVERED_FROM_ORIGIN_TOPIC
                ),
                json!([]),
            );
            let mut receipt = responses["eth_getTransactionReceipt"].clone();
            receipt["transactionHash"] = json!(tx);
            receipt["transactionIndex"] = json!("0x2");
            receipt["logs"] = json!([delayed_log, body_log]);
            responses.insert(format!("eth_getTransactionReceipt:{tx:#x}"), receipt);
            let mut transaction = responses["eth_getTransactionByHash"].clone();
            transaction["hash"] = json!(tx);
            transaction["transactionIndex"] = json!("0x2");
            transaction["to"] = json!(inbox);
            responses.insert(format!("eth_getTransactionByHash:{tx:#x}"), transaction);
            responses.insert(
                format!(
                    "eth_call:{}",
                    Bytes::from(arb_reth_l1::encode_delayed_accumulator_call(index))
                ),
                json!(wrong),
            );
            responses.insert(
                format!(
                    "eth_call:{}",
                    Bytes::from(arb_reth_l1::encode_sequencer_accumulator_call(
                        fixture.prepared.batch.sequence_number
                    ))
                ),
                json!(fixture.prepared.batch.after_acc),
            );
        }
        let prepared = fixture.resolve().await.unwrap();
        assert_eq!(prepared.messages.len(), 308);
        assert_eq!(
            prepared.delayed_mismatch,
            Some((wrong, delayed.accumulator()))
        );
        assert!(prepared.sequencer_mismatch.is_none());
        let observation =
            marker_observation(&fixture.journal, &prepared, prepared.batch_start_sequence).unwrap();
        assert_eq!(observation.terminal_delayed_count, index);
        assert_eq!(observation.terminal_delayed_accumulator, before_acc);
        let flag = Arc::new(AtomicBool::new(false));
        let error = publish_unit(
            &fixture.directory,
            production_storage_context(),
            &lock,
            &fixture.execution,
            &fixture.beacon,
            &fixture.budget,
            &fixture.cancellation,
            tokio::time::Instant::now() + Duration::from_secs(30),
            &mut fixture.journal,
            vec![prepared],
            flag.clone(),
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("delayed-accumulator divergence-v4 marker written"),
            "{error:?}"
        );
        let marker = arb_reth_engine::read_divergence_marker_v4(&fixture.directory).unwrap();
        assert_eq!(marker.cause, DivergenceCauseV4::DelayedAccumulatorMismatch);
        assert_eq!(marker.expected_value, wrong);
        assert_eq!(marker.observed_value, delayed.accumulator());
        assert_eq!(marker.terminal_message_ordinal, 299);
        assert_eq!(
            inspect_message_journal(&fixture.directory, production_storage_context()).unwrap(),
            before_journal
        );
        assert!(!flag.load(Ordering::Acquire));
        drop(lock);
        fixture.close().await;
    }

    #[tokio::test]
    async fn retained_authority_invalidation_refences_first_old_record_and_rejects_safe_only() {
        use serde_json::json;
        let mut fixture = ObserverFixture::new(256, None).await;
        let lock = DatadirLock::acquire(&fixture.directory).unwrap();
        let prepared = fixture.resolve().await.unwrap();
        publish_unit(
            &fixture.directory,
            production_storage_context(),
            &lock,
            &fixture.execution,
            &fixture.beacon,
            &fixture.budget,
            &fixture.cancellation,
            tokio::time::Instant::now() + Duration::from_secs(30),
            &mut fixture.journal,
            vec![prepared],
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
        let old = fixture.journal.retained_grid.last().unwrap().authority;
        let mut safe_only = build_observation(
            &fixture.journal,
            &fixture.prepared,
            old.start_sequence,
            old.end_sequence,
        )
        .unwrap();
        safe_only.safe_l1_number += 1;
        safe_only.safe_l1_hash = B256::repeat_byte(7);
        let new_hash = B256::repeat_byte(8);
        {
            let mut responses = fixture.responses.lock().unwrap();
            responses.insert("eth_chainId".to_owned(), json!("0x1"));
            responses.insert("eth_getBlockByNumber:0x0".to_owned(), json!({"number": "0x0", "hash": L1_GENESIS_HASH, "parentHash": B256::ZERO, "timestamp": "0x0"}));
            let bootstrap = production_bootstrap_authority().locator;
            responses.insert(format!("eth_getBlockByNumber:0x{:x}", bootstrap.containing_l1_number), json!({
                "number": format!("0x{:x}", bootstrap.containing_l1_number), "hash": bootstrap.containing_l1_hash,
                "parentHash": B256::ZERO, "timestamp": "0x1",
            }));
            responses
                .get_mut(&format!(
                    "eth_getBlockByNumber:0x{:x}",
                    fixture.prepared.containing.number
                ))
                .unwrap()["hash"] = json!(new_hash);
            let mut delivery = responses["eth_getLogs"][0].clone();
            delivery["blockHash"] = json!(new_hash);
            let mut previous = delivery.clone();
            previous["topics"][1] = json!(B256::from(alloy_primitives::U256::from(
                fixture.prepared.batch.sequence_number - 1
            )));
            previous["logIndex"] = json!("0x0");
            responses.insert("eth_getLogs".to_owned(), json!([previous, delivery]));
            responses.get_mut("eth_getTransactionByHash").unwrap()["blockHash"] = json!(new_hash);
            responses.get_mut("eth_getTransactionReceipt").unwrap()["blockHash"] = json!(new_hash);
            responses.get_mut("eth_getTransactionReceipt").unwrap()["logs"] = json!([delivery]);
        }
        // Duplicate predecessor discovery hints must reject before they acquire authority.
        let logs = fixture.responses.lock().unwrap()["eth_getLogs"].clone();
        fixture
            .responses
            .lock()
            .unwrap()
            .get_mut("eth_getLogs")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .push(logs[0].clone());
        let error = previous_batch_delayed_count(
            &fixture.execution,
            fixture.prepared.batch.sequence_number,
            fixture.prepared.containing.number,
            &fixture.budget,
            &fixture.cancellation,
            tokio::time::Instant::now() + Duration::from_secs(30),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("hint is not unique"));
        fixture
            .responses
            .lock()
            .unwrap()
            .insert("eth_getLogs".to_owned(), logs);
        let unit = prepare_unit(
            &fixture.execution,
            &fixture.beacon,
            &fixture.budget,
            &fixture.cancellation,
            tokio::time::Instant::now() + Duration::from_secs(30),
            &fixture.journal,
        )
        .await
        .unwrap();
        let PreparedUnit::InvalidatedAuthority { batch, authority } = unit else {
            panic!("reorg did not select invalidated authority")
        };
        assert_eq!(authority, old);
        let observation = build_observation(
            &fixture.journal,
            &batch,
            old.start_sequence,
            old.end_sequence,
        )
        .unwrap();
        write_authenticated_marker(
            &fixture.directory,
            &lock,
            &fixture.execution,
            &fixture.beacon,
            &fixture.budget,
            &fixture.cancellation,
            tokio::time::Instant::now() + Duration::from_secs(30),
            &fixture.journal,
            &batch,
            old.start_sequence,
            observation,
            DivergenceCauseV4::ExistingAuthorityInvalidatedBySafeReorg,
            B256::ZERO,
            B256::ZERO,
            old.authority_id,
            old.evidence_digest,
            observation.evidence_digest(),
        )
        .await
        .unwrap();
        let marker = arb_reth_engine::read_divergence_marker_v4(&fixture.directory).unwrap();
        assert_eq!(
            marker.cause,
            DivergenceCauseV4::ExistingAuthorityInvalidatedBySafeReorg
        );
        assert_eq!(marker.expected_value, old.evidence_digest);
        let mut advancement = marker;
        advancement.safe_l1_number = safe_only.safe_l1_number;
        advancement.safe_l1_hash = safe_only.safe_l1_hash;
        advancement.containing_l1_hash = safe_only.containing_l1_hash;
        advancement.observed_value = safe_only.evidence_digest();
        assert!(
            advancement
                .validate_against(&fixture.journal, safe_only)
                .unwrap_err()
                .to_string()
                .contains("safe advancement alone")
        );
        assert_eq!(
            arb_reth_engine::read_divergence_marker_v4(&fixture.directory).unwrap(),
            marker
        );
        drop(lock);
        fixture.close().await;
    }

    #[tokio::test]
    async fn impossible_predecessor_proof_excludes_ordinary_advancement_and_writes_exact_ids() {
        let mut fixture = ObserverFixture::new(300, None).await;
        let lock = DatadirLock::acquire(&fixture.directory).unwrap();
        let before = fixture.journal.authority_fence().unwrap();
        let first = fixture.prepared.batch_start_sequence;
        let observation =
            build_observation(&fixture.journal, &fixture.prepared, first, first + 255).unwrap();
        let runtime = JournalRuntime::open(
            fixture.directory.clone(),
            production_storage_context(),
            alloy_eips::BlockNumHash {
                number: fixture.journal.watermark.block_number,
                hash: fixture.journal.watermark.block_hash,
            },
        )
        .unwrap();
        assert!(
            runtime
                .client
                .enqueue_authority(AuthorityCandidateV3 {
                    fence: before,
                    start_sequence: first,
                    end_sequence: first + 299,
                    observation: build_observation(
                        &fixture.journal,
                        &fixture.prepared,
                        first,
                        first + 299
                    )
                    .unwrap(),
                })
                .is_err(),
            "whole-batch evidence must not weaken the 256-record enqueue cap"
        );
        runtime
            .client
            .enqueue_authority(AuthorityCandidateV3 {
                fence: before,
                start_sequence: first,
                end_sequence: first + 255,
                observation,
            })
            .unwrap()
            .recv()
            .unwrap()
            .unwrap();
        runtime.client.drain().unwrap();
        runtime.shutdown().unwrap();
        fixture.journal =
            inspect_message_journal(&fixture.directory, production_storage_context()).unwrap();
        assert!(
            !impossible_predecessor_contradiction(before, &fixture.journal),
            "ordinary completed candidate is not cause 6"
        );
        let mut impossible = fixture.journal.authority_fence().unwrap();
        // Fault-inject only the remembered predecessor, retaining a real authenticated old ID.
        // Every ordinary movement of the fence below must exclude this impossible-only cause.
        impossible.latest_authority_id = before.latest_authority_id;
        assert!(impossible_predecessor_contradiction(
            impossible,
            &fixture.journal
        ));
        for field in 0..4 {
            let mut ordinary = impossible;
            match field {
                0 => ordinary.journal.sequence -= 1,
                1 => ordinary.verified.sequence -= 1,
                2 => ordinary.journal_operation_generation -= 1,
                _ => ordinary.authority_chain_position -= 1,
            }
            assert!(!impossible_predecessor_contradiction(
                ordinary,
                &fixture.journal
            ));
        }
        let start = fixture.journal.v.unwrap().sequence + 1;
        let observation = build_observation(
            &fixture.journal,
            &fixture.prepared,
            start,
            fixture.journal.watermark.sequence,
        )
        .unwrap();
        write_authenticated_marker(
            &fixture.directory,
            &lock,
            &fixture.execution,
            &fixture.beacon,
            &fixture.budget,
            &fixture.cancellation,
            tokio::time::Instant::now() + Duration::from_secs(30),
            &fixture.journal,
            &fixture.prepared,
            start,
            observation,
            DivergenceCauseV4::ImpossibleDurablePredecessorContradiction,
            B256::ZERO,
            B256::ZERO,
            impossible.latest_authority_id,
            impossible.latest_authority_id,
            fixture.journal.latest_authority_id,
        )
        .await
        .unwrap();
        let marker = arb_reth_engine::read_divergence_marker_v4(&fixture.directory).unwrap();
        assert_eq!(
            marker.cause,
            DivergenceCauseV4::ImpossibleDurablePredecessorContradiction
        );
        assert_eq!(marker.expected_value, before.latest_authority_id);
        assert_eq!(marker.observed_value, fixture.journal.latest_authority_id);
        assert_eq!(
            marker.journal_operation_generation,
            fixture.journal.last_operation_generation
        );
        assert_eq!(
            marker.authority_chain_position,
            fixture.journal.authority_operation_count
        );
        drop(lock);
        fixture.close().await;
    }

    #[tokio::test]
    async fn complete_unit_late_mismatch_blocks_prefix_and_marker_fences_are_permanent() {
        for movement in ["none", "prewrite", "postwrite"] {
            let mut fixture = ObserverFixture::new(300, Some(299)).await;
            let lock = DatadirLock::acquire(&fixture.directory).unwrap();
            let prepared = fixture.resolve().await.unwrap();
            let original_journal = fixture.journal.clone();
            if movement == "prewrite" {
                fixture
                    .responses
                    .lock()
                    .unwrap()
                    .get_mut("eth_getBlockByNumber:safe")
                    .unwrap()["hash"] = serde_json::json!(B256::repeat_byte(9));
            }
            fixture
                .move_after_marker
                .store(movement == "postwrite", Ordering::Release);
            let flag = Arc::new(AtomicBool::new(false));
            let error = publish_unit(
                &fixture.directory,
                production_storage_context(),
                &lock,
                &fixture.execution,
                &fixture.beacon,
                &fixture.budget,
                &fixture.cancellation,
                tokio::time::Instant::now() + Duration::from_secs(30),
                &mut fixture.journal,
                vec![prepared],
                flag.clone(),
            )
            .await
            .unwrap_err();
            assert!(
                !flag.load(Ordering::Acquire),
                "marker must not cross authority enqueue boundary"
            );
            assert_eq!(
                inspect_message_journal(&fixture.directory, production_storage_context()).unwrap(),
                original_journal,
                "later covered mismatch must prevent every earlier split"
            );
            let marker_path = fixture
                .directory
                .path()
                .join(arb_reth_engine::DIVERGENCE_MARKER_FILE);
            if movement == "prewrite" {
                assert!(!marker_path.exists());
                assert!(error.to_string().contains("moved"));
            } else {
                let bytes = std::fs::read(&marker_path).unwrap();
                let marker = DivergenceMarkerV4::decode(&bytes).unwrap();
                assert_eq!(marker.cause, DivergenceCauseV4::FeedL1IdentityMismatch);
                assert_eq!(
                    marker.candidate_sequence,
                    original_journal.watermark.sequence
                );
                assert_eq!(
                    marker.expected_fingerprint,
                    fingerprint_commitment(original_journal.entries[299].fingerprint)
                );
                assert!(write_divergence_marker_v4(&fixture.directory, marker).is_err());
                assert_eq!(
                    std::fs::read(&marker_path).unwrap(),
                    bytes,
                    "permanent marker cannot be replaced"
                );
                if movement == "postwrite" {
                    assert!(
                        error
                            .to_string()
                            .contains("permanent divergence-v4 marker stands")
                    );
                }
            }
            drop(lock);
            fixture.close().await;
        }
    }

    #[tokio::test]
    async fn terminal_metadata_is_prevalidated_before_any_split_and_never_uses_beyond_j() {
        let mut fixture = ObserverFixture::new(300, None).await;
        let lock = DatadirLock::acquire(&fixture.directory).unwrap();
        let mut prepared = fixture.resolve().await.unwrap();
        let count = prepared.start_delayed_count;
        let expected_acc = prepared.batch.event.delayed_acc;
        prepared.batch.event.after_delayed_messages_read += 1;
        prepared.batch.event.delayed_acc = B256::repeat_byte(9);
        prepared.delayed_accumulators.push(B256::repeat_byte(9));
        let observation =
            marker_observation(&fixture.journal, &prepared, prepared.batch_start_sequence).unwrap();
        assert_eq!(observation.terminal_delayed_count, count);
        assert_eq!(observation.terminal_delayed_accumulator, expected_acc);
        assert_eq!(observation.terminal_message_ordinal, 299);
        assert_eq!(observation.decoded_message_count, 307);
        // The first split's ordinal remains valid; only the later split's ordinal exceeds
        // the decoded count. Complete-unit prevalidation must reject before the first I/O.
        prepared.batch_start_sequence -= 20;
        let before_requests = fixture.requests.lock().unwrap().len();
        let before_journal = fixture.journal.clone();
        let flag = Arc::new(AtomicBool::new(false));
        let error = publish_unit(
            &fixture.directory,
            production_storage_context(),
            &lock,
            &fixture.execution,
            &fixture.beacon,
            &fixture.budget,
            &fixture.cancellation,
            tokio::time::Instant::now() + Duration::from_secs(30),
            &mut fixture.journal,
            vec![prepared],
            flag.clone(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("terminal ordinal"));
        assert_eq!(fixture.requests.lock().unwrap().len(), before_requests);
        assert_eq!(
            inspect_message_journal(&fixture.directory, production_storage_context()).unwrap(),
            before_journal
        );
        assert!(!flag.load(Ordering::Acquire));
        drop(lock);
        fixture.close().await;
    }

    #[test]
    fn pre_enqueue_supervisor_exits_74_at_total_deadline() {
        const CHILD: &str = "ITE106B2_DEADLINE_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "commands::canonical_observe::tests::pre_enqueue_supervisor_exits_74_at_total_deadline"])
                .env(CHILD, "1").status().unwrap();
            assert_eq!(status.code(), Some(74));
            return;
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            tokio::time::pause();
            let deadlines = ObservationDeadlines::starting_at(tokio::time::Instant::now());
            let cancellation = CanonicalCancellation::default();
            let check = cancellation.clone();
            let observer = async move {
                tokio::time::sleep_until(deadlines.work + Duration::from_secs(1)).await;
                assert!(check.is_cancelled());
                std::future::pending::<eyre::Result<()>>().await
            };
            supervise_observer(
                observer,
                cancellation,
                deadlines,
                Arc::new(AtomicBool::new(false)),
            )
            .await
            .unwrap();
            panic!("deadline supervisor returned instead of exiting 74");
        });
    }

    fn fake_helper(script: &str) -> Child {
        Command::new("sh")
            .args(["-c", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    #[test]
    fn exclusive_lock_rejects_contention_and_path_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("datadir");
        std::fs::create_dir(&path).unwrap();
        let directory = JournalDirectory::open(&path).unwrap();
        let lock = DatadirLock::acquire(&directory).unwrap();
        let second = JournalDirectory::open(&path).unwrap();
        assert!(DatadirLock::acquire(&second).is_err());
        let replaced = temp.path().join("replaced");
        std::fs::rename(&path, &replaced).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(lock.prove_path().is_err());
    }

    #[test]
    fn helper_cleanup_sigkills_and_reaps() {
        let mut child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id();
        let error = run_kzg_helper(
            &mut child,
            &[0; arb_reth_l1::BYTES_PER_BLOB],
            &CanonicalCancellation::default(),
            tokio::time::Instant::now() + Duration::from_millis(10),
        )
        .unwrap_err();
        assert!(error.to_string().contains("deadline"));
        assert!(child.try_wait().unwrap().is_some());
        let result = unsafe { libc::kill(pid as i32, 0) };
        assert_eq!(result, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    #[test]
    fn helper_success_wrong_lengths_and_failure_are_exact() {
        let blob = [0; arb_reth_l1::BYTES_PER_BLOB];
        let cancellation = CanonicalCancellation::default();
        let deadline = || tokio::time::Instant::now() + Duration::from_secs(5);

        let mut success = fake_helper("cat >/dev/null; head -c 48 /dev/zero");
        assert_eq!(
            run_kzg_helper(&mut success, &blob, &cancellation, deadline()).unwrap(),
            [0; 48]
        );
        assert!(success.try_wait().unwrap().is_some());

        for length in [47, 49] {
            let mut wrong = fake_helper(&format!("cat >/dev/null; head -c {length} /dev/zero"));
            assert!(
                run_kzg_helper(&mut wrong, &blob, &cancellation, deadline())
                    .unwrap_err()
                    .to_string()
                    .contains("output length")
            );
            assert!(wrong.try_wait().unwrap().is_some());
        }

        let mut failure = fake_helper("cat >/dev/null; exit 9");
        assert!(run_kzg_helper(&mut failure, &blob, &cancellation, deadline()).is_err());
        assert!(failure.try_wait().unwrap().is_some());
    }
}
