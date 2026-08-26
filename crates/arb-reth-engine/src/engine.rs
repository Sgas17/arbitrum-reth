//! Engine-tree driver: the production block-production code, shared with the `engine_spike` gate.
//!
//! [`ArbEngineDriver`] stands up reth's [`EngineApiTreeHandler`] for `ArbNode` and drives
//! `feed message -> payload attributes -> native payload builder -> InsertExecutedBlock + ForkchoiceUpdated -> canonicalize` with
//! async persistence: production waits only for fast in-memory canonicalization while the tree's
//! persistence service flushes to MDBX in the background.
//!
//! [`wait_for_head`] is shared by the engine integration tests.

use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use alloy_consensus::Header;
use alloy_consensus::transaction::Recovered;
use alloy_eips::eip2718::Typed2718;
use alloy_evm::EvmEnv;
use alloy_primitives::{Address, B256, BlockNumber, Bytes, Log, StorageKey, StorageValue};
use arb_reth_evm::ArbEvmConfig;
use arb_reth_evm::config::ArbNextBlockEnvAttributes;
use arb_revm::executor::{
    ArbExecCfg, ArbParentHeader, digest_message, is_redeem_scheduled_log,
    scheduled_retries_from_redeem_logs,
};
use arb_revm::{ArbSpecId, ArbosState};
use arbitrum_alloy_consensus::header::ArbHeaderInfo;
use arbitrum_alloy_consensus::reth::{ArbBlock, ArbPrimitives};
use arbitrum_alloy_consensus::{ArbReceiptEnvelope, ArbTxEnvelope};
use arbitrum_alloy_sequencer::sequencer::feed::BroadcastFeedMessage;
use eyre::{WrapErr as _, eyre};
use metrics::{Counter, Histogram};
use std::{
    error::Error,
    fmt,
    sync::{
        OnceLock,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use reth_chain_state::{CanonStateSubscriptions, CanonicalInMemoryState};
use reth_engine_primitives::{
    BeaconEngineMessage, ConsensusEngineEvent, NoopInvalidBlockHook, TreeConfig,
};
use reth_engine_tree::chain::FromOrchestrator;
use reth_engine_tree::engine::{EngineApiEvent, EngineApiKind, EngineApiRequest, FromEngine};
use reth_engine_tree::tree::state_root_strategy::PayloadStateRootHandle;
use reth_engine_tree::tree::{BasicEngineValidator, EngineApiTreeHandler};
use reth_evm::OnStateHook as _;
use reth_evm::execute::BlockBuilder as _;
use reth_evm::{ConfigureEvm as _, Evm as _};
use reth_execution_cache::CacheStats;
use reth_execution_types::{BlockExecutionOutput, BlockExecutionResult};
use reth_payload_builder::{PayloadBuilderHandle, PayloadBuilderService};
use reth_payload_primitives::{BuiltPayload as _, BuiltPayloadExecutedBlock, PayloadKind};
use reth_primitives_traits::{Account, Bytecode, RecoveredBlock, SealedHeader};
use reth_provider::providers::{BlockchainProvider, ProviderNodeTypes};
use reth_provider::{
    AccountReader, BalProvider, BlockHashReader, BlockNumReader, BlockReader, BytecodeReader,
    ChangeSetReader, DatabaseProviderFactory, HashedPostStateProvider, ProviderFactory,
    ProviderResult, StateProofProvider, StateProviderFactory, StateReader, StateRootProvider,
    StorageChangeSetReader, StorageRootProvider,
};
use reth_prune::{Pruner, PrunerBuilder};
use reth_revm::State;
use reth_revm::database::StateProviderDatabase;
use reth_storage_api::{
    DBProvider, PruneCheckpointReader, StageCheckpointReader, StateProvider, StoragePath,
    StorageSettingsCache,
};
use reth_storage_overlay::OverlayManager;
use reth_tasks::Runtime;
use reth_trie::{
    AccountProof, ExecutionWitnessMode, HashedPostState, HashedStorage, MultiProof,
    MultiProofTargets, StorageMultiProof, StorageProof, TrieInput, updates::TrieUpdates,
};
use revm::context_interface::ContextTr as _;

use crate::message_journal::{MessageJournal, MessageJournalAnchor, MessageJournalEntry};
use crate::native_payload::ArbPayloadJobGenerator;
use crate::{
    ArbEngineInput, ArbEngineInputSource, ArbMessageFingerprint, ArbPayloadAttributes,
    ArbPayloadBuilder, ArbPayloadTypes, ArbPayloadValidator, ArbTxExecutionKind,
    ArbTxLogBroadcaster, ArbTxLogEvent, fingerprint_message,
};

const MAX_PENDING_MESSAGES: usize = 50_000;
const MAX_RECENT_MESSAGE_IDENTITIES: usize = 100_000;

/// Deterministic message-identity failure that requires operator recovery before restart.
#[derive(Debug)]
pub struct ArbMessageDivergence {
    sequence: Option<u64>,
    message: String,
}

impl fmt::Display for ArbMessageDivergence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for ArbMessageDivergence {}

fn divergence_at(sequence: u64, message: impl Into<String>) -> eyre::Report {
    eyre::Report::new(ArbMessageDivergence {
        sequence: Some(sequence),
        message: message.into(),
    })
}

/// Returns true when an engine failure proves a deterministic feed/L1 identity disagreement.
pub fn is_message_divergence(error: &eyre::Report) -> bool {
    error.downcast_ref::<ArbMessageDivergence>().is_some()
}

/// Return the exact incoming sequence attached to a deterministic message divergence, if known.
pub fn message_divergence_sequence(error: &eyre::Report) -> Option<u64> {
    error
        .downcast_ref::<ArbMessageDivergence>()
        .and_then(|divergence| divergence.sequence)
}

#[derive(Clone, Copy, Debug)]
struct AppliedMessageIdentity {
    fingerprint: ArbMessageFingerprint,
    source: ArbEngineInputSource,
    block_number: u64,
    block_hash: B256,
    parent_hash: B256,
    delayed_messages_read: u64,
}

impl From<MessageJournalEntry> for AppliedMessageIdentity {
    fn from(entry: MessageJournalEntry) -> Self {
        Self {
            fingerprint: entry.fingerprint,
            source: entry.source,
            block_number: entry.block_number,
            block_hash: entry.block_hash,
            parent_hash: entry.parent_hash,
            delayed_messages_read: entry.delayed_messages_read,
        }
    }
}

impl AppliedMessageIdentity {
    fn journal_entry(self, sequence: u64) -> MessageJournalEntry {
        MessageJournalEntry {
            sequence,
            block_number: self.block_number,
            block_hash: self.block_hash,
            parent_hash: self.parent_hash,
            delayed_messages_read: self.delayed_messages_read,
            fingerprint: self.fingerprint,
            source: self.source,
        }
    }
}

fn validate_batch_report_metadata(
    arbos_version: u64,
    sequence: u64,
    input: &ArbEngineInput,
) -> eyre::Result<()> {
    let incoming = &input.message().message_with_meta_data.l1_incoming_message;
    if arbos_version >= 50 && incoming.header.kind == 13 && incoming.batch_data_stats.is_none() {
        return Err(divergence_at(
            sequence,
            format!(
                "batch posting report at sequence {sequence} is missing BatchDataStats required by ArbOS {arbos_version}"
            ),
        ));
    }
    Ok(())
}

fn merge_same_sequence_inputs(
    existing: &ArbEngineInput,
    incoming: &ArbEngineInput,
) -> eyre::Result<ArbEngineInput> {
    let sequence = existing.sequence_number();
    if incoming.sequence_number() != sequence {
        return Err(divergence_at(
            sequence,
            format!(
                "cannot reconcile different sequences {sequence} and {}",
                incoming.sequence_number()
            ),
        ));
    }
    let existing_fingerprint = fingerprint_message(existing.message())?;
    let incoming_fingerprint = fingerprint_message(incoming.message())?;
    if !existing_fingerprint.semantically_matches(incoming_fingerprint) {
        return Err(divergence_at(
            sequence,
            format!(
                "feed/L1 message disagreement at sequence {sequence}: existing source {:?} core {:#x}, incoming source {:?} core {:#x}",
                existing.source(),
                existing_fingerprint.core,
                incoming.source(),
                incoming_fingerprint.core,
            ),
        ));
    }

    match (existing.source(), incoming.source()) {
        (ArbEngineInputSource::Feed, ArbEngineInputSource::L1) => {
            let claimed_block_hash = match (
                existing.claimed_block_hash(),
                incoming.claimed_block_hash(),
            ) {
                (Some(first), Some(second)) if first != second => {
                    return Err(divergence_at(
                        sequence,
                        format!(
                            "sequencer feed supplied conflicting block hashes at sequence {sequence}: {first:#x} and {second:#x}"
                        ),
                    ));
                }
                (Some(claimed), _) | (_, Some(claimed)) => Some(claimed),
                (None, None) => None,
            };
            Ok(incoming.clone().with_claimed_block_hash(claimed_block_hash))
        }
        (ArbEngineInputSource::L1, _) => Ok(existing.clone()),
        (ArbEngineInputSource::Feed, ArbEngineInputSource::Feed) => {
            match (existing.claimed_block_hash(), incoming.claimed_block_hash()) {
                (Some(first), Some(second)) if first != second => Err(divergence_at(
                    sequence,
                    format!(
                        "sequencer feed supplied conflicting block hashes at sequence {sequence}: {first:#x} and {second:#x}"
                    ),
                )),
                (None, Some(_)) => Ok(incoming.clone()),
                _ => Ok(existing.clone()),
            }
        }
    }
}

#[derive(Debug)]
struct AppliedOverlapPlan {
    overlap_len: usize,
    promotions: Vec<(u64, AppliedMessageIdentity)>,
}

fn plan_applied_l1_chunk(
    inputs: &[ArbEngineInput],
    next_seq: u64,
    anchor_sequence: u64,
    mut l1_authority_sequence: u64,
    previous_l1_sequence: Option<u64>,
    mut identity: impl FnMut(u64) -> Option<AppliedMessageIdentity>,
) -> eyre::Result<AppliedOverlapPlan> {
    for (index, input) in inputs.iter().enumerate() {
        let sequence = input.sequence_number();
        if input.source() != ArbEngineInputSource::L1 {
            return Err(divergence_at(
                sequence,
                format!("L1 reconciliation chunk contains feed input at sequence {sequence}"),
            ));
        }
        if let Some(previous) = index
            .checked_sub(1)
            .map(|index| inputs[index].sequence_number())
        {
            let expected = previous.checked_add(1).ok_or_else(|| {
                divergence_at(
                    sequence,
                    format!("L1 reconciliation sequence overflows after {previous}"),
                )
            })?;
            if sequence != expected {
                return Err(divergence_at(
                    sequence,
                    format!(
                        "L1 reconciliation chunk is not strictly ordered and contiguous: expected sequence {expected}, got {sequence}"
                    ),
                ));
            }
        }
    }

    if let (Some(previous), Some(first)) = (previous_l1_sequence, inputs.first()) {
        let sequence = first.sequence_number();
        let expected = previous.checked_add(1).ok_or_else(|| {
            divergence_at(
                sequence,
                format!("L1 reconciliation sequence overflows after {previous}"),
            )
        })?;
        if sequence != expected {
            return Err(divergence_at(
                sequence,
                format!(
                    "L1 reconciliation chunks are not strictly ordered and contiguous: expected sequence {expected}, got {sequence}"
                ),
            ));
        }
    }

    if let Some(first) = inputs.first()
        && first.sequence_number() > next_seq
    {
        let sequence = first.sequence_number();
        return Err(divergence_at(
            sequence,
            format!(
                "L1 reconciliation starts after the next executable sequence: expected at most sequence {next_seq}, got {sequence}"
            ),
        ));
    }

    let overlap_len = inputs
        .iter()
        .take_while(|input| input.sequence_number() < next_seq)
        .count();
    if let Some(first) = inputs.first()
        && first.sequence_number()
            > l1_authority_sequence
                .checked_add(1)
                .ok_or_else(|| divergence_at(first.sequence_number(), "L1 authority overflow"))?
    {
        let sequence = first.sequence_number();
        return Err(divergence_at(
            sequence,
            format!(
                "L1 overlap starts after the contiguous authority frontier: expected at most sequence {}, got {sequence}",
                l1_authority_sequence + 1,
            ),
        ));
    }
    let mut promotions = Vec::new();
    for input in &inputs[..overlap_len] {
        let sequence = input.sequence_number();
        let Some(mut applied) = identity(sequence) else {
            if sequence > anchor_sequence {
                return Err(divergence_at(
                    sequence,
                    format!(
                        "cannot verify overlap at sequence {sequence}: no durable or in-memory message identity exists"
                    ),
                ));
            }
            continue;
        };
        let incoming = fingerprint_message(input.message()).map_err(|error| {
            divergence_at(
                sequence,
                format!("cannot normalize L1 overlap at sequence {sequence}: {error:#}"),
            )
        })?;
        if !applied.fingerprint.semantically_matches(incoming) {
            return Err(divergence_at(
                sequence,
                format!(
                    "feed/L1 message disagreement at applied sequence {sequence}: applied source {:?} block {:#x} parent {:#x} core {:#x}, incoming source {:?} core {:#x}",
                    applied.source,
                    applied.block_hash,
                    applied.parent_hash,
                    applied.fingerprint.core,
                    input.source(),
                    incoming.core,
                ),
            ));
        }

        let next_authority = l1_authority_sequence.checked_add(1);
        if next_authority == Some(sequence) {
            if applied.source == ArbEngineInputSource::Feed {
                applied.source = ArbEngineInputSource::L1;
                applied.fingerprint = incoming;
                promotions.push((sequence, applied));
            }
            l1_authority_sequence = sequence;
        }
    }

    Ok(AppliedOverlapPlan {
        overlap_len,
        promotions,
    })
}

fn append_durable_message_events(
    journal: &mut MessageJournal,
    pending: &mut VecDeque<MessageJournalEntry>,
    additional: &[MessageJournalEntry],
    durable_tip: u64,
) -> eyre::Result<()> {
    let entries = pending
        .iter()
        .chain(additional)
        .filter(|entry| entry.block_number <= durable_tip)
        .copied()
        .collect::<Vec<_>>();
    journal.append_durable(&entries)?;
    pending.retain(|entry| entry.block_number > durable_tip);
    Ok(())
}

/// The concrete sender type returned by [`EngineApiTreeHandler::spawn_new`] for `ArbNode`.
type ToTree = crossbeam_channel::Sender<
    FromEngine<EngineApiRequest<ArbPayloadTypes, ArbPrimitives>, ArbBlock>,
>;

const SPARSE_HAZARD_SELFDESTRUCT: u8 = 1 << 0;
const SPARSE_HAZARD_CREATED_EMPTY: u8 = 1 << 1;

fn sparse_root_hazards(state: &revm::state::EvmState, preserve_created_empty_accounts: bool) -> u8 {
    let mut hazards = 0;
    for account in state.values() {
        if account.is_selfdestructed() {
            hazards |= SPARSE_HAZARD_SELFDESTRUCT;
        }
        if preserve_created_empty_accounts && account.is_created() && account.is_empty() {
            hazards |= SPARSE_HAZARD_CREATED_EMPTY;
        }
    }
    hazards
}

/// Ensures every driver exit asks the engine tree to flush and release persistence handles.
struct EngineTerminationGuard {
    to_tree: ToTree,
    requested: AtomicBool,
}

impl EngineTerminationGuard {
    fn new(to_tree: ToTree) -> Self {
        Self {
            to_tree,
            requested: AtomicBool::new(false),
        }
    }

    fn request(&self) -> Option<tokio::sync::oneshot::Receiver<()>> {
        if self.requested.swap(true, Ordering::AcqRel) {
            return None;
        }

        let (terminated_tx, terminated_rx) = tokio::sync::oneshot::channel();
        self.to_tree
            .send(FromEngine::Event(FromOrchestrator::Terminate {
                tx: terminated_tx,
            }))
            .ok()?;
        Some(terminated_rx)
    }
}

impl Drop for EngineTerminationGuard {
    fn drop(&mut self) {
        let _ = self.request();
    }
}

/// Produce one block and retain a breakdown of the local block-production work.
///
/// The input components are deliberately separate because the payload builder acquires the state
/// providers and optional state-root task independently. Keep this local seam flat rather than
/// adding an allocation solely to satisfy Clippy.
#[allow(clippy::too_many_arguments)]
pub(crate) fn produce_with_timing<'a>(
    evm_config: &ArbEvmConfig,
    chain_id: u64,
    parent: &SealedHeader<Header>,
    feed_msg: &BroadcastFeedMessage,
    exec_state_provider: Box<dyn StateProvider + 'a>,
    trie_state_provider: Box<dyn StateProvider + 'a>,
    mut state_root_task: Option<PayloadStateRootHandle>,
    tx_log_stream: Option<&ArbTxLogBroadcaster>,
) -> eyre::Result<(
    BuiltPayloadExecutedBlock<ArbPrimitives>,
    ArbBlockProductionTiming,
)> {
    let started_at = Instant::now();
    let parent_header = parent.header();
    let arbos_version =
        arbitrum_alloy_consensus::header::ArbHeaderInfo::decode_header(parent_header)
            .ok()
            .map(|i| i.arbos_format_version as u8);
    let version = arbos_version.unwrap_or(0);

    let arb_parent = ArbParentHeader {
        number: parent_header.number,
        timestamp: parent_header.timestamp,
        beneficiary: parent_header.beneficiary,
        basefee: parent_header.base_fee_per_gas.unwrap_or(0),
        gas_limit: parent_header.gas_limit,
        difficulty: parent_header.difficulty,
        prevrandao: Some(parent_header.mix_hash),
    };
    let cfg = ArbExecCfg {
        chain_id,
        ..ArbExecCfg::default()
    };
    let input =
        digest_message(feed_msg, arb_parent, cfg, version).wrap_err("digest_message failed")?;

    let next_timestamp = input.message.l1_timestamp.max(arb_parent.timestamp);
    let finish_timing_out = Arc::new(std::sync::Mutex::new(Default::default()));
    let attrs = ArbNextBlockEnvAttributes {
        timestamp: next_timestamp,
        suggested_fee_recipient: input.message.poster,
        prev_randao: B256::ZERO,
        gas_limit: input.cfg.block_gas_limit,
        l1_block_number: input.message.l1_block_number,
        l1_base_fee_wei: input.message.l1_base_fee_wei,
        arbos_format_version: version as u64,
        delayed_messages_read: input.message.delayed_messages_read,
        extra_data: Bytes::default(),
        withdrawals: None,
        finish_timing_out: Arc::clone(&finish_timing_out),
    };

    let phase_started_at = Instant::now();

    // `exec_state_provider` / `trie_state_provider` are independent instances. Sharing one would
    // corrupt execution reads versus the trie build.
    let mut state = State::builder()
        .with_database(StateProviderDatabase::new(exec_state_provider))
        .with_bundle_update()
        .build();

    let state_setup = phase_started_at.elapsed();
    let message_preparation = started_at.elapsed().saturating_sub(state_setup);
    let phase_started_at = Instant::now();

    let mut builder = evm_config
        .builder_for_next_block(&mut state, parent, attrs)
        .map_err(|e| eyre!("builder_for_next_block: {e:?}"))?;
    let sparse_hazards_seen = Arc::new(AtomicU8::new(0));
    if let Some(task) = state_root_task.as_mut() {
        let mut sparse_hook = task.take_state_hook();
        let hazards = Arc::clone(&sparse_hazards_seen);
        let preserve_created_empty_accounts =
            !ArbSpecId::from_arbos_version(version as u64).is_enabled_in(ArbSpecId::ARBOS_30);
        builder.evm_mut().db_mut().set_state_hook(Some(Box::new(
            move |update: revm::state::EvmState| {
                let observed = sparse_root_hazards(&update, preserve_created_empty_accounts);
                if observed != 0 {
                    hazards.fetch_or(observed, Ordering::Relaxed);
                }
                sparse_hook.on_state(update);
            },
        )));
    }
    builder
        .apply_pre_execution_changes()
        .wrap_err("apply_pre_execution_changes failed")?;

    // Tx-sequencing priority mirrors Nitro (arbos/block_processor.go:366-374): the start-block
    // internal tx first, then, each iteration, any scheduled redeem (FIFO) before the next sequenced
    // user tx. A user tx that calls `redeem()` schedules an `ArbitrumRetryTx` that Nitro runs
    // immediately after it. Appending scheduled retries to the back of a single user-tx queue runs
    // them after the remaining user txs, which does not change execution/state/gas (the txs are
    // independent) but reorders the block, diverging `transactionsRoot`/`receiptsRoot` and thus the
    // block hash from Nitro. That wrong hash is invisible to a state-root parity check until a later
    // L1-advancing block bakes the (wrong) parent hash into ArbOS state via `record_new_l1_block`.
    // Sender recovery is pure per-tx work; recover the sequenced user txs in parallel up front
    // instead of one ecrecover at a time inside the execution loop. Results (including failures)
    // are carried per-tx so the loop reports the same first-in-order error it would have hit
    // serially. Retries scheduled mid-block and the internal start-block tx carry their sender in
    // the envelope and stay on the cheap inline path.
    let mut user_txs: VecDeque<(
        ArbTxEnvelope,
        Result<Address, alloy_primitives::SignatureError>,
    )> = {
        let txs: Vec<ArbTxEnvelope> = input.message.txs.into_iter().collect();
        if txs.len() > 1 {
            use rayon::iter::{IntoParallelIterator as _, ParallelIterator as _};
            txs.into_par_iter()
                .map(|tx| {
                    let sender = tx.sender();
                    (tx, sender)
                })
                .collect::<Vec<_>>()
                .into()
        } else {
            txs.into_iter()
                .map(|tx| {
                    let sender = tx.sender();
                    (tx, sender)
                })
                .collect()
        }
    };
    let mut redeems: VecDeque<ArbTxEnvelope> = VecDeque::new();
    // Set the block's L2 base fee. ArbOS stores `L2PricingState.BaseFeeWei` = the fee for the next
    // block (each block's start-block `update_pricing_model` computes and stores the successor's
    // fee). So this block's basefee is the value already in state at block start (what the parent's
    // update produced), read here before the start-block tx overwrites it with the next block's fee.
    // Our block env was seeded with the parent header's basefee (`config.rs` `next_evm_env`), which
    // is the fee from two blocks back and is only correct while the fee sits at the `minBaseFee`
    // floor. Fixing it makes user txs pay the right L2 fee + L1 poster gas (posterCost / basefee),
    // and the sealed header (assembler reads `block_env.basefee()`) carry it. Only matters once the
    // gas backlog pushes the fee off the floor.
    let block_base_fee = ArbosState::open()
        .l2_pricing
        .base_fee_wei
        .get(builder.evm_mut().ctx_mut().journal_mut())
        .map_err(|e| eyre!("read L2 base fee for block env: {e}"))?;
    let block_base_fee = u64::try_from(block_base_fee).unwrap_or(u64::MAX);
    builder.evm_mut().ctx_mut().modify_block(|b| {
        b.inner.basefee = block_base_fee;
        b.base_fee_in_block = block_base_fee;
    });
    // Nitro's `BaseFeeInBlock`, kept equal to the base fee it shadows. `GasChargingHook` only reads
    // it when the block env's base fee is zero, which cannot happen here, but leaving the two out of
    // step would be a trap for anything that later does.
    builder.evm_mut().ctx_mut().chain.base_fee_in_block = Some(block_base_fee);

    // Anchor exact MEV simulations after pre-execution changes. Each committed transaction adds
    // only its own state delta to a persistent chain; frontiers do not clone cumulative block
    // state and therefore remain cheap enough for the transaction-by-transaction feed.
    let mut frontier_block = tx_log_stream.map(|stream| {
        let evm_env = EvmEnv::new(
            builder.evm().cfg_env().clone(),
            builder.evm().block().clone(),
        );
        let pre_execution_state = builder.evm_mut().db_mut().cache.clone();
        stream.begin_frontier_block(parent.hash(), evm_env, pre_execution_state)
    });

    let execution_setup = phase_started_at.elapsed();
    let phase_started_at = Instant::now();
    let mut first = builder.executor().start_block_tx();
    let start_block_transaction_construction = phase_started_at.elapsed();
    let phase_started_at = Instant::now();
    let mut start_block_transaction = Duration::ZERO;
    let mut derived_transactions = Duration::ZERO;
    let mut derived_transaction_execution = Duration::ZERO;
    let mut derived_retry_scheduling = Duration::ZERO;
    let mut transaction_index = 0;
    loop {
        let (tx, sender_result, kind) = if let Some(t) = first.take() {
            let sender = t.sender();
            (t, sender, ArbTxExecutionKind::StartBlock)
        } else if let Some(t) = redeems.pop_front() {
            let sender = t.sender();
            (t, sender, ArbTxExecutionKind::ScheduledRetry)
        } else if let Some((t, sender)) = user_txs.pop_front() {
            (t, sender, ArbTxExecutionKind::User)
        } else {
            break;
        };
        let is_internal = matches!(kind, ArbTxExecutionKind::StartBlock);
        let tx_ty = tx.ty();
        let sender: Address =
            sender_result.map_err(|e| eyre!("failed to determine sender for tx {tx_ty}: {e}"))?;
        // Frontier tracking stays active while the feature is enabled even between IPC client
        // reconnects. Full log cloning remains conditional on a connected stream consumer.
        let has_log_subscribers = tx_log_stream.is_some_and(ArbTxLogBroadcaster::has_subscribers);
        let tx_hash = tx_log_stream.map(|_| tx.hash());
        let recovered = Recovered::new_unchecked(tx, sender);
        let mut tx_logs: Vec<Log> = Vec::new();
        let mut tx_success = false;
        let mut tx_event_logs = None;
        let mut tx_gas_used = 0;
        let mut tx_state_update = None;
        let tx_started_at = Instant::now();
        if let Err(e) = builder.execute_transaction_with_result_closure(recovered, |res| {
            tx_success = res.result.result.is_success();
            tx_gas_used = res.result.result.tx_gas_used();
            tx_logs.extend(
                res.result
                    .result
                    .logs()
                    .iter()
                    .filter(|log| is_redeem_scheduled_log(log))
                    .cloned(),
            );
            if tx_log_stream.is_some() {
                tx_state_update = Some(res.result.state.clone());
            }
            if has_log_subscribers {
                tx_event_logs = Some(res.result.result.logs().to_vec());
            }
        }) {
            let tx_execution = tx_started_at.elapsed();
            if is_internal {
                start_block_transaction += tx_execution;
            } else {
                derived_transactions += tx_execution;
                derived_transaction_execution += tx_execution;
            }
            // Nitro `arbos/block_processor.go` (~l.503-549): a derived tx that is INVALID under the
            // state transition, a validation failure like lack-of-funds / NonceTooHigh, NOT a
            // revert, is reverted and dropped, and block production continues without it. This is
            // real on mainnet: an unsigned/contract tx from the delayed inbox whose sender can't
            // pay yields an internal-only block. revm rejects such
            // a tx before applying it, so nothing is added to the block; just skip and move on. Only
            // the internal start-block tx must always succeed. A wrong-but-not-invalid execution
            // divergence is still caught by the state-root parity check downstream.
            if is_internal {
                return Err(e).wrap_err("internal start-block tx failed");
            }
            tracing::debug!(
                target: "arb-reth::engine",
                block = parent_header.number + 1,
                tx_type = tx_ty,
                %sender,
                error = %e,
                "dropping invalid derived transaction",
            );
            continue;
        }
        let frontier_id = match (frontier_block.as_mut(), tx_hash, tx_state_update) {
            (Some(frontier), Some(transaction_hash), Some(update)) => frontier.advance(
                parent_header.number + 1,
                transaction_index,
                transaction_hash,
                update,
                builder.evm().ctx().chain.clone(),
            ),
            _ => B256::ZERO,
        };
        if let (Some(stream), Some(transaction_hash), Some(logs)) =
            (tx_log_stream, tx_hash, tx_event_logs)
        {
            stream.publish(ArbTxLogEvent {
                block_number: parent_header.number + 1,
                transaction_index,
                transaction_hash,
                frontier_id,
                kind,
                success: tx_success,
                gas_used: tx_gas_used,
                logs,
            });
        }
        transaction_index += 1;
        let mut retry_scheduling = Duration::ZERO;
        if tx_success && !tx_logs.is_empty() {
            // FIFO, drained before the next user tx, matching Nitro's cascading-redeem order.
            let retry_scheduling_started_at = Instant::now();
            let retries =
                scheduled_retries_from_redeem_logs(builder.evm_mut().ctx_mut(), &tx_logs, chain_id);
            retry_scheduling = retry_scheduling_started_at.elapsed();
            redeems.extend(retries);
        }

        let tx_execution = tx_started_at.elapsed();
        if is_internal {
            start_block_transaction += tx_execution;
        } else {
            derived_transactions += tx_execution;
            derived_transaction_execution += tx_execution.saturating_sub(retry_scheduling);
            derived_retry_scheduling += retry_scheduling;
        }
    }

    let derived_transactions_unattributed = derived_transactions
        .saturating_sub(derived_transaction_execution + derived_retry_scheduling);

    let execution =
        phase_started_at.elapsed() + execution_setup + start_block_transaction_construction;
    let execution_unattributed = execution.saturating_sub(
        execution_setup
            + start_block_transaction_construction
            + start_block_transaction
            + derived_transactions,
    );
    let phase_started_at = Instant::now();

    let finish_state_timings = Arc::new(FinishStateTimings::default());
    let (state_root_precomputed, state_root_task_wait, state_root_task_succeeded) =
        if let Some(mut task) = state_root_task {
            // Dropping the hook signals that the task has received every ArbOS state transition,
            // including the EIP-2935 prelude and start-block transaction.
            builder.evm_mut().db_mut().set_state_hook(None);
            let wait_started_at = Instant::now();
            let sparse_hazards = sparse_hazards_seen.load(Ordering::Relaxed);
            if sparse_hazards != 0 {
                // The pinned sparse converter cannot represent storage wipes and pre-ArbOS 30
                // created-empty accounts faithfully. Wait for the task to release its proof
                // workers and preserved-trie cache, discard its result, then let `finish` compute
                // the authoritative root from the merged bundle state.
                if let Err(err) = task.state_root() {
                    tracing::debug!(
                        target: "arb-reth::engine",
                        block = parent_header.number + 1,
                        job = task.name(),
                        %err,
                        "incompatible state-root task ended with an error before serial fallback",
                    );
                }
                tracing::debug!(
                    target: "arb-reth::engine",
                    block = parent_header.number + 1,
                    selfdestruct = sparse_hazards & SPARSE_HAZARD_SELFDESTRUCT != 0,
                    created_empty = sparse_hazards & SPARSE_HAZARD_CREATED_EMPTY != 0,
                    "using synchronous state root for sparse-incompatible account lifecycle",
                );
                (None, Some(wait_started_at.elapsed()), false)
            } else {
                match task.state_root() {
                    Ok(outcome) => (
                        Some((
                            outcome.state_root,
                            Arc::unwrap_or_clone(outcome.trie_updates),
                        )),
                        Some(wait_started_at.elapsed()),
                        true,
                    ),
                    Err(err) => {
                        tracing::warn!(
                            target: "arb-reth::engine",
                            block = parent_header.number + 1,
                            job = task.name(),
                            %err,
                            "state-root task failed; falling back to synchronous state root",
                        );
                        (None, Some(wait_started_at.elapsed()), false)
                    }
                }
            }
        } else {
            (None, None, false)
        };
    let outcome = builder
        .finish(
            FinishTimingStateProvider::new(trie_state_provider, Arc::clone(&finish_state_timings)),
            state_root_precomputed,
        )
        .wrap_err("BlockBuilder::finish failed")?;

    let finish = phase_started_at.elapsed();
    let finish_state_root = finish_state_timings.state_root();
    let finish_hashed_state = finish_state_timings.hashed_post_state();
    let finish_timing = finish_timing_out
        .lock()
        .map(|timing| *timing)
        .unwrap_or_default();
    let finish_unattributed = finish.saturating_sub(
        finish_timing.executor_finish
            + finish_hashed_state
            + finish_state_root
            + state_root_task_wait.unwrap_or_default()
            + finish_timing.block_assembly,
    );

    let bundle = state.take_bundle();
    drop(state);

    let recovered_block: RecoveredBlock<ArbBlock> = outcome.block;
    let execution_output = Arc::new(BlockExecutionOutput {
        result: BlockExecutionResult {
            receipts: outcome.execution_result.receipts,
            requests: outcome.execution_result.requests,
            gas_used: outcome.execution_result.gas_used,
            blob_gas_used: outcome.execution_result.blob_gas_used,
        },
        state: bundle,
    });

    // BuiltPayloadExecutedBlock wants unsorted hashed_state / trie_updates.
    Ok((
        BuiltPayloadExecutedBlock {
            recovered_block: Arc::new(recovered_block),
            execution_output,
            hashed_state: Arc::new(outcome.hashed_state),
            trie_updates: Arc::new(outcome.trie_updates),
        },
        ArbBlockProductionTiming {
            total: started_at.elapsed(),
            parent_state: Duration::ZERO,
            message_preparation,
            state_setup,
            execution,
            execution_setup,
            start_block_transaction_construction,
            start_block_transaction,
            derived_transactions,
            derived_transaction_execution,
            derived_retry_scheduling,
            derived_transactions_unattributed,
            execution_unattributed,
            finish,
            finish_executor: finish_timing.executor_finish,
            finish_hashed_state,
            finish_state_root,
            finish_state_root_task_wait: state_root_task_wait,
            state_root_task_succeeded,
            finish_assembly: finish_timing.block_assembly,
            finish_unattributed,
        },
    ))
}

struct EngineBlockMetricHandles {
    payload_attributes: Histogram,
    payload_job: Histogram,
    payload_job_launch: Histogram,
    payload_job_resolve: Histogram,
    payload_job_overhead: Histogram,
    production: Histogram,
    production_unattributed: Histogram,
    parent_state: Histogram,
    message_preparation: Histogram,
    state_setup: Histogram,
    execution: Histogram,
    execution_setup: Histogram,
    start_block_transaction_construction: Histogram,
    start_block_transaction: Histogram,
    derived_transactions: Histogram,
    derived_transaction_execution: Histogram,
    derived_retry_scheduling: Histogram,
    derived_transactions_unattributed: Histogram,
    execution_unattributed: Histogram,
    finish: Histogram,
    finish_executor: Histogram,
    finish_hashed_state: Histogram,
    finish_state_root: Histogram,
    finish_state_root_task_wait: Histogram,
    state_root_task_native_success: Counter,
    state_root_task_fallback: Counter,
    finish_assembly: Histogram,
    finish_unattributed: Histogram,
    engine_handoff: Histogram,
    engine_insert: Histogram,
    engine_forkchoice: Histogram,
    canonicalization_wait: Histogram,
    apply_overhead: Histogram,
    total: Histogram,
    mgas_per_second: Histogram,
}

fn engine_block_metric_handles() -> &'static EngineBlockMetricHandles {
    static HANDLES: OnceLock<EngineBlockMetricHandles> = OnceLock::new();
    HANDLES.get_or_init(|| EngineBlockMetricHandles {
        payload_attributes: metrics::histogram!("arb_reth.engine_block_payload_attributes_seconds"),
        payload_job: metrics::histogram!("arb_reth.engine_block_payload_job_seconds"),
        payload_job_launch: metrics::histogram!("arb_reth.engine_block_payload_job_launch_seconds"),
        payload_job_resolve: metrics::histogram!(
            "arb_reth.engine_block_payload_job_resolve_seconds"
        ),
        payload_job_overhead: metrics::histogram!(
            "arb_reth.engine_block_payload_job_overhead_seconds"
        ),
        production: metrics::histogram!("arb_reth.engine_block_production_seconds"),
        production_unattributed: metrics::histogram!(
            "arb_reth.engine_block_production_unattributed_seconds"
        ),
        parent_state: metrics::histogram!("arb_reth.engine_block_parent_state_seconds"),
        message_preparation: metrics::histogram!(
            "arb_reth.engine_block_message_preparation_seconds"
        ),
        state_setup: metrics::histogram!("arb_reth.engine_block_state_setup_seconds"),
        execution: metrics::histogram!("arb_reth.engine_block_execution_seconds"),
        execution_setup: metrics::histogram!("arb_reth.engine_block_execution_setup_seconds"),
        start_block_transaction_construction: metrics::histogram!(
            "arb_reth.engine_block_start_block_transaction_construction_seconds"
        ),
        start_block_transaction: metrics::histogram!(
            "arb_reth.engine_block_start_block_transaction_seconds"
        ),
        derived_transactions: metrics::histogram!(
            "arb_reth.engine_block_derived_transactions_seconds"
        ),
        derived_transaction_execution: metrics::histogram!(
            "arb_reth.engine_block_derived_transaction_execution_seconds"
        ),
        derived_retry_scheduling: metrics::histogram!(
            "arb_reth.engine_block_derived_retry_scheduling_seconds"
        ),
        derived_transactions_unattributed: metrics::histogram!(
            "arb_reth.engine_block_derived_transactions_unattributed_seconds"
        ),
        execution_unattributed: metrics::histogram!(
            "arb_reth.engine_block_execution_unattributed_seconds"
        ),
        finish: metrics::histogram!("arb_reth.engine_block_finish_seconds"),
        finish_executor: metrics::histogram!("arb_reth.engine_block_finish_executor_seconds"),
        finish_hashed_state: metrics::histogram!(
            "arb_reth.engine_block_finish_hashed_state_seconds"
        ),
        finish_state_root: metrics::histogram!("arb_reth.engine_block_finish_state_root_seconds"),
        finish_state_root_task_wait: metrics::histogram!(
            "arb_reth.engine_block_finish_state_root_task_wait_seconds"
        ),
        state_root_task_native_success: metrics::counter!(
            "arb_reth.engine_block_state_root_task_total",
            "mode" => "native_payload_builder",
            "result" => "success",
        ),
        state_root_task_fallback: metrics::counter!(
            "arb_reth.engine_block_state_root_task_total",
            "mode" => "native_payload_builder",
            "result" => "fallback",
        ),
        finish_assembly: metrics::histogram!("arb_reth.engine_block_finish_assembly_seconds"),
        finish_unattributed: metrics::histogram!(
            "arb_reth.engine_block_finish_unattributed_seconds"
        ),
        engine_handoff: metrics::histogram!("arb_reth.engine_block_engine_handoff_seconds"),
        engine_insert: metrics::histogram!("arb_reth.engine_block_engine_insert_seconds"),
        engine_forkchoice: metrics::histogram!("arb_reth.engine_block_engine_forkchoice_seconds"),
        canonicalization_wait: metrics::histogram!(
            "arb_reth.engine_block_canonicalization_wait_seconds"
        ),
        apply_overhead: metrics::histogram!("arb_reth.engine_block_apply_overhead_seconds"),
        total: metrics::histogram!("arb_reth.engine_block_total_seconds"),
        mgas_per_second: metrics::histogram!("arb_reth.engine_block_mgas_per_second"),
    })
}

/// Poll the tree's view (events, best block number, and in-memory head) until block `bn` with
/// hash `expected_hash` is canonical, or a bounded timeout elapses.
pub async fn wait_for_head<P>(
    provider: &P,
    canonical: &CanonicalInMemoryState<ArbPrimitives>,
    obs_rx: &mut tokio::sync::mpsc::UnboundedReceiver<(u64, B256)>,
    bn: u64,
    expected_hash: B256,
) -> bool
where
    P: BlockHashReader + BlockNumReader,
{
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if matches!(provider.block_hash(bn), Ok(Some(hash)) if hash == expected_hash) {
            return true;
        }
        let head = canonical.get_canonical_head();
        if head.header().number == bn && head.hash() == expected_hash {
            return true;
        }
        while let Ok((number, hash)) = obs_rx.try_recv() {
            if number == bn && hash == expected_hash {
                return true;
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        match tokio::time::timeout(remaining, obs_rx.recv()).await {
            Ok(Some((number, hash))) if number == bn && hash == expected_hash => return true,
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => return false,
        }
    }
}

/// Engine-tree persistence tuning (reth [`TreeConfig`]).
///
/// reth's defaults (`persistence_threshold=2`, `memory_block_buffer_target=0`,
/// `persistence_backpressure_threshold=16`) suit a live validator: persist promptly, hold almost
/// nothing in memory.
///
#[derive(Debug, Clone, Copy)]
pub struct ArbEngineTuning {
    /// Persist once the canonical tip is this many blocks ahead of the last persisted block.
    pub persistence_threshold: u64,
    /// Keep this many of the most-recent blocks in memory (target size of the unpersisted buffer).
    pub memory_block_buffer_target: u64,
    /// Hard backpressure: stall block production once this many blocks are unpersisted.
    pub persistence_backpressure_threshold: u64,
    /// Size in bytes of reth's cross-block execution cache.
    ///
    /// Reth's bare [`TreeConfig`] default is intentionally large for a general-purpose node. A
    /// 256 MiB cache keeps the serial Arbitrum producer's fixed-cache tables dense and matches
    /// the previously measured direct-driver configuration.
    pub execution_cache_size: usize,
    /// Share Reth's cross-block execution cache with the native payload builder.
    ///
    /// The Arbitrum driver builds one payload at a time, so the shared cache cannot race a
    /// concurrent payload job and can safely serve repeated account, storage, and bytecode reads.
    pub share_execution_cache_with_payload_builder: bool,
    /// Share reth's sparse trie task with the native payload builder.
    ///
    /// This overlaps state-root computation with ArbOS execution. It is disabled by default to
    /// retain reth's conservative payload-builder behavior on hosts that may build payloads in
    /// parallel.
    pub share_sparse_trie_with_payload_builder: bool,
}

impl Default for ArbEngineTuning {
    fn default() -> Self {
        // reth's stock shallow defaults: prompt persistence and a minimal buffer.
        Self::reth_defaults()
    }
}

impl ArbEngineTuning {
    /// reth's stock defaults: prompt persistence, minimal in-memory buffer. Right for low-latency
    /// / small runs (and tests that assert a produced block is durably persisted immediately);
    /// use [`Default`] for bulk historical sync throughput.
    pub fn reth_defaults() -> Self {
        Self {
            persistence_threshold: 2,
            memory_block_buffer_target: 0,
            persistence_backpressure_threshold: 16,
            execution_cache_size: 256 * 1024 * 1024,
            share_execution_cache_with_payload_builder: true,
            share_sparse_trie_with_payload_builder: false,
        }
    }

    /// Build a reth [`TreeConfig`] from these knobs (all other fields keep reth defaults).
    pub fn to_tree_config(self) -> TreeConfig {
        TreeConfig::default()
            // TreeConfig validates its invariants after every builder call. Set the upper bound
            // first so deep configurations are valid in debug builds too.
            .with_persistence_backpressure_threshold(self.persistence_backpressure_threshold)
            .with_persistence_threshold(self.persistence_threshold)
            .with_memory_block_buffer_target(self.memory_block_buffer_target)
            .with_cross_block_cache_size(self.execution_cache_size)
            .with_share_execution_cache_with_payload_builder(
                self.share_execution_cache_with_payload_builder,
            )
            .with_share_sparse_trie_with_payload_builder(
                self.share_sparse_trie_with_payload_builder,
            )
    }
}

/// Timings for one message that produced a canonical block.
///
/// `block_production` includes ArbOS execution, state-root computation, and header sealing.
/// The other fields cover the engine-tree handoff through in-memory canonicalization. Persistence
/// to MDBX remains asynchronous and is intentionally outside this critical-path measurement.
#[derive(Debug, Clone, Copy)]
pub struct ArbAppliedMessageTiming {
    /// Instant immediately before native payload attributes are constructed.
    pub started_at: Instant,
    /// Instant at which the produced block became canonical, before metric emission.
    pub completed_at: Instant,
    /// Constructing Arbitrum payload attributes from the ordered message and current parent.
    pub payload_attributes: Duration,
    /// Full Reth payload-job lifecycle, from attributes FCU send until the built payload resolves.
    pub payload_job: Duration,
    /// Payload-job launch through the attributes FCU response.
    pub payload_job_launch: Duration,
    /// Waiting for the launched payload job to resolve after the attributes FCU response.
    pub payload_job_resolve: Duration,
    /// Payload-job lifecycle time outside the builder's measured block production.
    pub payload_job_overhead: Duration,
    /// Execution, state-root computation, and block/header construction.
    pub block_production: Duration,
    /// Block-production work outside parent state, message preparation, state setup, execution,
    /// and finalisation.
    pub block_production_unattributed: Duration,
    /// Parent-state provider setup before `produce` begins.
    pub block_parent_state: Duration,
    /// Feed-message digesting and next-block environment construction.
    pub block_message_preparation: Duration,
    /// Creation of revm's journaled state over the parent provider.
    pub block_state_setup: Duration,
    /// ArbOS pre-execution and transaction execution.
    pub block_execution: Duration,
    /// Block-builder creation, pre-execution changes, and base-fee setup before the first tx.
    pub block_execution_setup: Duration,
    /// Construction of ArbOS's mandatory internal start-block transaction.
    pub block_start_block_transaction_construction: Duration,
    /// Execution of ArbOS's mandatory internal start-block transaction.
    pub block_start_block_transaction: Duration,
    /// Execution of derived user and retry transactions, including retry scheduling.
    pub block_derived_transactions: Duration,
    /// Derived transaction execution and commit work, excluding retry scheduling.
    pub block_derived_transaction_execution: Duration,
    /// Extraction and enqueueing of retries emitted by successful derived transactions.
    pub block_derived_retry_scheduling: Duration,
    /// Small remainder after named derived-transaction phases, kept for exact accounting.
    pub block_derived_transactions_unattributed: Duration,
    /// Small remainder after the named block-execution phases, kept to make the breakdown exact.
    pub block_execution_unattributed: Duration,
    /// Total generic block finalization after ArbOS transactions complete.
    pub block_finish: Duration,
    /// ArbOS executor finalization, principally reading post-execution header metadata.
    pub block_finish_executor: Duration,
    /// Hashing the executed bundle into the post-state representation used by the trie.
    pub block_finish_hashed_state: Duration,
    /// Computing the post-state root and trie updates.
    pub block_finish_state_root: Duration,
    /// Waiting for the sparse state-root task after execution, if one was started.
    pub block_finish_state_root_task_wait: Option<Duration>,
    /// Whether the sparse task supplied the result. `None` means no task was started.
    pub block_finish_state_root_task_succeeded: Option<bool>,
    /// Transaction/receipt roots, logs bloom, and Arbitrum header/block assembly.
    pub block_finish_assembly: Duration,
    /// Generic finalization work not assigned to one of the named phases.
    pub block_finish_unattributed: Duration,
    /// Full engine-tree handoff, from executed-block insertion until canonical state is observable.
    pub engine_handoff: Duration,
    /// Sending the executed block to the engine tree.
    pub engine_insert: Duration,
    /// Forkchoice request and response from the engine tree, nested inside `engine_handoff`.
    pub engine_forkchoice: Duration,
    /// Waiting for canonical state, concurrently with `engine_forkchoice` and nested inside
    /// `engine_handoff`.
    pub canonicalization_wait: Duration,
    /// Total time in the in-order apply path.
    pub total: Duration,
}

/// Breakdown of local work performed while producing an Arbitrum block.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ArbBlockProductionTiming {
    pub(crate) total: Duration,
    pub(crate) parent_state: Duration,
    pub(crate) message_preparation: Duration,
    pub(crate) state_setup: Duration,
    pub(crate) execution: Duration,
    pub(crate) execution_setup: Duration,
    pub(crate) start_block_transaction_construction: Duration,
    pub(crate) start_block_transaction: Duration,
    pub(crate) derived_transactions: Duration,
    pub(crate) derived_transaction_execution: Duration,
    pub(crate) derived_retry_scheduling: Duration,
    pub(crate) derived_transactions_unattributed: Duration,
    pub(crate) execution_unattributed: Duration,
    pub(crate) finish: Duration,
    pub(crate) finish_executor: Duration,
    pub(crate) finish_hashed_state: Duration,
    pub(crate) finish_state_root: Duration,
    pub(crate) finish_state_root_task_wait: Option<Duration>,
    pub(crate) state_root_task_succeeded: bool,
    pub(crate) finish_assembly: Duration,
    pub(crate) finish_unattributed: Duration,
}

/// Driver-side timing around Reth's native payload-job lifecycle.
#[derive(Debug, Clone, Copy)]
struct ArbPayloadJobTiming {
    attributes: Duration,
    job: Duration,
    launch: Duration,
    resolve: Duration,
}

/// Completion of a final forkchoice request queued behind an inserted local block.
struct ArbForkchoiceCompletion {
    completed_at: Instant,
    elapsed: Duration,
}

/// A produced block whose final forkchoice request is still in flight.
///
/// Keeping this in the driver lets the next payload-attributes request enter the engine queue
/// before we await this response. The engine processes those requests in order, so the next
/// payload job can only start after this block is canonical, without requiring the producer to
/// round-trip through the final FCU first.
struct PendingAppliedBlock {
    sequence_number: u64,
    new_hash: B256,
    new_header: Header,
    production_timing: ArbBlockProductionTiming,
    execution_cache_stats: Option<Arc<CacheStats>>,
    payload_timing: ArbPayloadJobTiming,
    started_at: Instant,
    engine_handoff_started_at: Instant,
    canonicalization_started_at: Instant,
    engine_insert: Duration,
    forkchoice: Option<tokio::task::JoinHandle<eyre::Result<ArbForkchoiceCompletion>>>,
}

/// The generic reth block builder owns post-state hashing and state-root calculation. Wrap its
/// provider so ArbOS production can expose those two phases without changing consensus behavior.
#[derive(Debug, Default)]
struct FinishStateTimings {
    hashed_post_state_nanos: AtomicU64,
    state_root_nanos: AtomicU64,
}

impl FinishStateTimings {
    fn record_hashed_post_state(&self, elapsed: Duration) {
        self.hashed_post_state_nanos.store(
            elapsed.as_nanos().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
    }

    fn record_state_root(&self, elapsed: Duration) {
        self.state_root_nanos.store(
            elapsed.as_nanos().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
    }

    fn hashed_post_state(&self) -> Duration {
        Duration::from_nanos(self.hashed_post_state_nanos.load(Ordering::Relaxed))
    }

    fn state_root(&self) -> Duration {
        Duration::from_nanos(self.state_root_nanos.load(Ordering::Relaxed))
    }
}

#[derive(Debug)]
struct FinishTimingStateProvider<P> {
    inner: P,
    timings: Arc<FinishStateTimings>,
}

impl<P> FinishTimingStateProvider<P> {
    const fn new(inner: P, timings: Arc<FinishStateTimings>) -> Self {
        Self { inner, timings }
    }
}

impl<P: AccountReader> AccountReader for FinishTimingStateProvider<P> {
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        self.inner.basic_account(address)
    }
}

impl<P: BytecodeReader> BytecodeReader for FinishTimingStateProvider<P> {
    fn bytecode_by_hash(&self, code_hash: &B256) -> ProviderResult<Option<Bytecode>> {
        self.inner.bytecode_by_hash(code_hash)
    }
}

impl<P: StateProvider> StateProvider for FinishTimingStateProvider<P> {
    fn storage(
        &self,
        account: Address,
        storage_key: StorageKey,
    ) -> ProviderResult<Option<StorageValue>> {
        self.inner.storage(account, storage_key)
    }
}

impl<P: StateRootProvider> StateRootProvider for FinishTimingStateProvider<P> {
    fn state_root(&self, hashed_state: HashedPostState) -> ProviderResult<B256> {
        self.inner.state_root(hashed_state)
    }

    fn state_root_from_nodes(&self, input: TrieInput) -> ProviderResult<B256> {
        self.inner.state_root_from_nodes(input)
    }

    fn state_root_with_updates(
        &self,
        hashed_state: HashedPostState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        let started_at = Instant::now();
        let result = self.inner.state_root_with_updates(hashed_state);
        self.timings.record_state_root(started_at.elapsed());
        result
    }

    fn state_root_from_nodes_with_updates(
        &self,
        input: TrieInput,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        self.inner.state_root_from_nodes_with_updates(input)
    }
}

impl<P: StateProofProvider> StateProofProvider for FinishTimingStateProvider<P> {
    fn proof(
        &self,
        input: TrieInput,
        address: Address,
        slots: &[B256],
    ) -> ProviderResult<AccountProof> {
        self.inner.proof(input, address, slots)
    }

    fn multiproof(
        &self,
        input: TrieInput,
        targets: MultiProofTargets,
    ) -> ProviderResult<MultiProof> {
        self.inner.multiproof(input, targets)
    }

    fn witness(
        &self,
        input: TrieInput,
        target: HashedPostState,
        mode: ExecutionWitnessMode,
    ) -> ProviderResult<Vec<Bytes>> {
        self.inner.witness(input, target, mode)
    }
}

impl<P: StorageRootProvider> StorageRootProvider for FinishTimingStateProvider<P> {
    fn storage_root(
        &self,
        address: Address,
        hashed_storage: HashedStorage,
    ) -> ProviderResult<B256> {
        self.inner.storage_root(address, hashed_storage)
    }

    fn storage_proof(
        &self,
        address: Address,
        slot: B256,
        hashed_storage: HashedStorage,
    ) -> ProviderResult<StorageProof> {
        self.inner.storage_proof(address, slot, hashed_storage)
    }

    fn storage_multiproof(
        &self,
        address: Address,
        slots: &[B256],
        hashed_storage: HashedStorage,
    ) -> ProviderResult<StorageMultiProof> {
        self.inner
            .storage_multiproof(address, slots, hashed_storage)
    }
}

impl<P: BlockHashReader> BlockHashReader for FinishTimingStateProvider<P> {
    fn block_hash(&self, number: BlockNumber) -> ProviderResult<Option<B256>> {
        self.inner.block_hash(number)
    }

    fn canonical_hashes_range(
        &self,
        start: BlockNumber,
        end: BlockNumber,
    ) -> ProviderResult<Vec<B256>> {
        self.inner.canonical_hashes_range(start, end)
    }
}

impl<P: HashedPostStateProvider> HashedPostStateProvider for FinishTimingStateProvider<P> {
    fn hashed_post_state(&self, bundle_state: &reth_revm::db::BundleState) -> HashedPostState {
        let started_at = Instant::now();
        let result = self.inner.hashed_post_state(bundle_state);
        self.timings.record_hashed_post_state(started_at.elapsed());
        result
    }
}

/// Engine-tree driver for `ArbNode`.
///
/// Owns the tree's request sender, the current tip, and a receiver of canonicalization
/// observations. Each [`advance`](ArbEngineDriver::advance) produces a block against the tree
/// overlay, feeds it via `InsertExecutedBlock` + `ForkchoiceUpdated`, and returns once the block
/// is canonical in memory. Persistence to MDBX happens asynchronously in the tree's background
/// persistence service.
pub struct ArbEngineDriver<N>
where
    N: ProviderNodeTypes<Primitives = ArbPrimitives>,
    BlockchainProvider<N>: DatabaseProviderFactory
        + BlockReader<Block = ArbBlock, Header = Header>
        + StateProviderFactory
        + StateReader<Receipt = ArbReceiptEnvelope>
        + HashedPostStateProvider
        + BalProvider
        + ChangeSetReader
        + BlockNumReader
        + Clone
        + 'static,
    <BlockchainProvider<N> as DatabaseProviderFactory>::Provider: BlockReader<Block = ArbBlock, Header = Header>
        + StageCheckpointReader
        + PruneCheckpointReader
        + ChangeSetReader
        + StorageChangeSetReader
        + BlockNumReader
        + StorageSettingsCache
        + StoragePath
        + DBProvider,
{
    provider: BlockchainProvider<N>,
    tip: SealedHeader<Header>,
    to_tree: ToTree,
    // Sends termination on error and panic paths before the persistence proxy is joined.
    engine_termination_guard: EngineTerminationGuard,
    // Declared after both tree senders so they drop before this joins the proxy thread.
    _persistence_proxy_guard: crate::storage_v2::PersistenceProxyGuard,
    /// Reth's local payload-builder service for deterministic ArbOS message payloads.
    payload_builder: PayloadBuilderHandle<ArbPayloadTypes>,
    canonical: CanonicalInMemoryState<ArbPrimitives>,
    obs_rx: tokio::sync::mpsc::UnboundedReceiver<(u64, B256)>,
    /// The final FCU for the most recently produced block. Historical catch-up may leave this in
    /// flight until the next payload-attributes request has been queued behind it.
    pending_applied: Option<PendingAppliedBlock>,
    /// Sequence-reconciliation cursor (arb-reth's `TransactionStreamer` analogue). `next_seq` is the
    /// next message index to apply; a feed/derived message with `sequence_number` maps to L2 block
    /// `sequence_number + genesis_block`. Messages below `next_seq` are already-applied duplicates
    /// (dropped); the one equal to it is applied; ones above it are feed-ahead and buffered in
    /// `pending` until derivation closes the gap. Feed/L1 copies are compared by normalized message
    /// identity across both the current process and restarts through the durable journal.
    next_seq: u64,
    /// Feed-ahead reorder buffer, retaining source authority and rejecting conflicting copies.
    pending: BTreeMap<u64, ArbEngineInput>,
    /// Bounded identities for comparing delayed L1 copies with already-executed feed messages.
    recent_messages: BTreeMap<u64, AppliedMessageIdentity>,
    genesis_block: u64,
    message_journal: MessageJournal,
    pending_journal_events: VecDeque<MessageJournalEntry>,
    /// Last sequence observed from the ordered L1 chunk stream in this process.
    last_l1_sequence: Option<u64>,
    l1_verified_tip: Arc<AtomicU64>,
}

fn open_message_journal_for_tip(
    datadir: &std::path::Path,
    genesis_block: u64,
    tip_number: u64,
    tip_hash: B256,
    allow_bootstrap: bool,
) -> eyre::Result<MessageJournal> {
    let journal_path = MessageJournal::path_in(datadir);
    let divergence_path = MessageJournal::divergence_path_in(datadir);
    if divergence_path.exists() {
        return Err(eyre!(
            "unresolved feed/L1 divergence marker at {}; keep the node stopped, rewind/recover, then clear the marker explicitly",
            divergence_path.display()
        ));
    }
    let expected_sequence = tip_number.checked_sub(genesis_block).ok_or_else(|| {
        eyre!("durable database tip {tip_number} is below L2 genesis block {genesis_block}")
    })?;
    let journal = if journal_path.exists() {
        if allow_bootstrap {
            return Err(eyre!(
                "message journal already exists at {}; remove --init-message-journal-at-tip after its one successful use",
                journal_path.display()
            ));
        }
        MessageJournal::open(journal_path)?
    } else {
        if tip_number != genesis_block && !allow_bootstrap {
            return Err(eyre!(
                "message journal is missing for non-genesis database tip {tip_number} at {}; initialize an explicit trusted anchor with --init-message-journal-at-tip",
                journal_path.display()
            ));
        }
        MessageJournal::create(
            journal_path,
            MessageJournalAnchor {
                sequence: expected_sequence,
                block_number: tip_number,
                block_hash: tip_hash,
            },
        )?
    };
    let journal_tip = journal.watermark();
    if journal_tip.sequence != expected_sequence
        || journal_tip.block_number != tip_number
        || journal_tip.block_hash != tip_hash
    {
        let recovery = if journal_tip.block_number < tip_number {
            "rewind the database to the journal watermark"
        } else {
            "rerun the interrupted rewind at the current database tip"
        };
        return Err(eyre!(
            "message journal watermark {} / {} ({:#x}) does not match durable database tip {} / {} ({:#x}); keep the node stopped and {recovery} before restarting",
            journal_tip.sequence,
            journal_tip.block_number,
            journal_tip.block_hash,
            expected_sequence,
            tip_number,
            tip_hash,
        ));
    }
    Ok(journal)
}

impl<N> ArbEngineDriver<N>
where
    N: ProviderNodeTypes<Primitives = ArbPrimitives>,
    BlockchainProvider<N>: DatabaseProviderFactory
        + BlockReader<Block = ArbBlock, Header = Header>
        + StateProviderFactory
        + StateReader<Receipt = ArbReceiptEnvelope>
        + HashedPostStateProvider
        + BalProvider
        + ChangeSetReader
        + BlockNumReader
        + Clone
        + 'static,
    <BlockchainProvider<N> as DatabaseProviderFactory>::Provider: BlockReader<Block = ArbBlock, Header = Header>
        + StageCheckpointReader
        + PruneCheckpointReader
        + ChangeSetReader
        + StorageChangeSetReader
        + BlockNumReader
        + StorageSettingsCache
        + StoragePath
        + DBProvider,
{
    /// Stand up the engine tree over `factory`/`provider` and wire the event-drain task.
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        factory: ProviderFactory<N>,
        provider: BlockchainProvider<N>,
        evm_config: ArbEvmConfig,
        chain_id: u64,
        genesis_tip: SealedHeader<Header>,
        genesis_block: u64,
        canonical: CanonicalInMemoryState<ArbPrimitives>,
        runtime: Runtime,
        tuning: ArbEngineTuning,
        prune_builder: Option<PrunerBuilder>,
        allow_message_journal_bootstrap: bool,
        l1_verified_tip: Arc<AtomicU64>,
        tx_log_stream: Option<ArbTxLogBroadcaster>,
    ) -> eyre::Result<Self> {
        let message_journal = {
            let db_provider = factory.database_provider_ro()?;
            let db_path = db_provider.storage_path();
            let datadir = db_path.parent().ok_or_else(|| {
                eyre!("database path {} has no datadir parent", db_path.display())
            })?;
            open_message_journal_for_tip(
                datadir,
                genesis_block,
                genesis_tip.number,
                genesis_tip.hash(),
                allow_message_journal_bootstrap,
            )?
        };

        // ---- persistence service (real MDBX writer; pruner from --prune.* flags) ----
        let (_finished_exex_height_tx, finished_exex_height_rx) =
            tokio::sync::watch::channel(reth_exex_types::FinishedExExHeight::NoExExs);
        // With no `--prune.*` flags this stays an archive node: a noop pruner (empty segment set)
        // that keeps all history. When pruning is configured, reth's `PrunerBuilder` turns the
        // requested `PruneModes` into the real segment set; the engine-tree persistence service
        // below runs it after each commit batch (at the configured block interval).
        let pruner = match prune_builder {
            Some(builder) => builder.build_with_provider_factory(factory.clone()),
            None => Pruner::new_with_factory(
                factory.clone(),
                vec![],
                5,
                0,
                None,
                finished_exex_height_rx,
            ),
        };
        let (sync_metrics_tx, _sync_metrics_rx) =
            tokio::sync::mpsc::unbounded_channel::<reth_stages_api::MetricEvent>();
        let (persistence, persistence_proxy_guard) =
            crate::storage_v2::spawn_persistence(factory, pruner, sync_metrics_tx);

        // ---- engine-tree wiring (all reth components) ----
        let consensus: Arc<dyn reth_consensus::FullConsensus<ArbPrimitives>> =
            Arc::new(reth_consensus::noop::NoopConsensus::default());
        let state_trie_overlays = OverlayManager::new(runtime.state_trie_overlay_worker_pool());
        let tree_config = tuning.to_tree_config();
        tracing::info!(
            target: "arb-reth::engine",
            persistence_threshold = tuning.persistence_threshold,
            memory_block_buffer_target = tuning.memory_block_buffer_target,
            persistence_backpressure_threshold = tuning.persistence_backpressure_threshold,
            share_execution_cache = tuning.share_execution_cache_with_payload_builder,
            share_sparse_trie = tuning.share_sparse_trie_with_payload_builder,
            "engine-tree payload and persistence configuration",
        );

        let payload_validator = BasicEngineValidator::new(
            provider.clone(),
            consensus.clone(),
            evm_config.clone(),
            ArbPayloadValidator,
            tree_config.clone(),
            Box::new(NoopInvalidBlockHook::default()),
            state_trie_overlays.clone(),
            runtime.clone(),
        );

        let builder = match tx_log_stream {
            Some(stream) => ArbPayloadBuilder::with_tx_log_stream(
                provider.clone(),
                evm_config.clone(),
                chain_id,
                stream,
            ),
            None => ArbPayloadBuilder::new(provider.clone(), evm_config.clone(), chain_id),
        };
        let generator = ArbPayloadJobGenerator::new(provider.clone(), runtime.clone(), builder);
        let (service, payload_builder) = PayloadBuilderService::<_, _, ArbPayloadTypes>::new(
            generator,
            provider.canonical_state_stream(),
        );
        runtime.spawn_critical_os_thread(
            "arb-payload-service",
            "arb native payload builder service",
            service,
        );

        let (to_tree, mut from_tree) = EngineApiTreeHandler::spawn_new(
            provider.clone(),
            consensus,
            payload_validator,
            persistence,
            payload_builder.clone(),
            canonical.clone(),
            state_trie_overlays.clone(),
            tree_config.clone(),
            EngineApiKind::Ethereum,
            evm_config.clone(),
            runtime.clone(),
        );

        // Drain events on a background task so the tree channel never blocks. Only forward
        // committed-chain events: `CanonicalBlockAdded` is emitted when an executed block is
        // inserted as pending and is not proof that RPC-visible canonical state has advanced.
        let (obs_tx, obs_rx) = tokio::sync::mpsc::unbounded_channel::<(u64, B256)>();
        tokio::spawn(async move {
            while let Some(ev) = from_tree.recv().await {
                if let EngineApiEvent::BeaconConsensus(
                    ConsensusEngineEvent::CanonicalChainCommitted(header, _),
                ) = ev
                {
                    let _ = obs_tx.send((header.number, header.hash()));
                }
            }
        });

        // Seed the dedup cursor from the resumed tip: the next message to apply is the one that
        // produces block tip+1, i.e. message index tip.number - genesis_block + 1.
        let next_seq = genesis_tip.number.saturating_sub(genesis_block) + 1;
        Ok(Self {
            provider,
            tip: genesis_tip,
            engine_termination_guard: EngineTerminationGuard::new(to_tree.clone()),
            to_tree,
            _persistence_proxy_guard: persistence_proxy_guard,
            payload_builder,
            canonical,
            obs_rx,
            pending_applied: None,
            next_seq,
            pending: BTreeMap::new(),
            recent_messages: BTreeMap::new(),
            genesis_block,
            message_journal,
            pending_journal_events: VecDeque::new(),
            last_l1_sequence: None,
            l1_verified_tip,
        })
    }

    /// Produce, insert, and canonicalize one block from a feed message.
    ///
    /// Waits only for fast in-memory canonicalization (the tree persists to MDBX asynchronously).
    /// Returns the hash of the newly-produced block, which becomes the new tip.
    /// Reconcile and apply one incoming message (from either the feed or L1 derivation), Nitro
    /// `TransactionStreamer` style. Drops it if already applied (`sequence_number < next_seq`),
    /// applies it if it is the next expected message, or buffers it as feed-ahead otherwise; after
    /// applying, drains any now-contiguous buffered messages. Returns the resulting head hash.
    pub async fn advance(&mut self, input: &ArbEngineInput) -> eyre::Result<B256> {
        self.advance_with_applied(input, |_, _| {}).await
    }

    /// Like [`Self::advance`], while notifying the caller after each message has become the
    /// canonical in-memory head. This includes buffered feed-ahead messages drained after a gap
    /// closes, and deliberately excludes duplicate messages that were not applied.
    pub async fn advance_with_applied<F>(
        &mut self,
        input: &ArbEngineInput,
        mut on_applied: F,
    ) -> eyre::Result<B256>
    where
        F: FnMut(u64, ArbAppliedMessageTiming),
    {
        self.advance_with_applied_inner(input, false, true, &mut on_applied)
            .await
    }

    /// Like [`Self::advance_with_applied`], but allows the final block's forkchoice response to
    /// remain in flight when the caller already has another message ready. The next call queues
    /// its payload-attributes FCU first, then settles this block, preserving engine request order
    /// while overlapping the two driver round trips. `drain_pending` must be false before the tail
    /// of an ordered L1 chunk so each authoritative copy is compared before a buffered feed copy
    /// can execute.
    pub async fn advance_with_applied_overlap<F>(
        &mut self,
        input: &ArbEngineInput,
        defer_tail: bool,
        drain_pending: bool,
        mut on_applied: F,
    ) -> eyre::Result<B256>
    where
        F: FnMut(u64, ArbAppliedMessageTiming),
    {
        self.advance_with_applied_inner(input, defer_tail, drain_pending, &mut on_applied)
            .await
    }

    /// Reconcile the already-applied prefix of one ordered L1-derived chunk without execution.
    ///
    /// The complete chunk is validated and compared before any feed authority is promoted. The
    /// return value is the fully source-resolved suffix that the caller must submit to the normal
    /// execution path.
    pub async fn reconcile_applied_l1_chunk<F>(
        &mut self,
        inputs: &[ArbEngineInput],
        mut on_applied: F,
    ) -> eyre::Result<Vec<ArbEngineInput>>
    where
        F: FnMut(u64, ArbAppliedMessageTiming),
    {
        let authority_sequence = self.l1_authority_sequence();
        let plan = plan_applied_l1_chunk(
            inputs,
            self.next_seq,
            self.message_journal.anchor().sequence,
            authority_sequence,
            self.last_l1_sequence,
            |sequence| self.applied_identity(sequence),
        )?;
        let resolved_suffix = inputs[plan.overlap_len..]
            .iter()
            .map(|input| match self.pending.get(&input.sequence_number()) {
                Some(buffered) => merge_same_sequence_inputs(buffered, input),
                None => Ok(input.clone()),
            })
            .collect::<eyre::Result<Vec<_>>>()?;

        if plan.overlap_len > 0 {
            let durable_tip = self.provider.last_block_number()?;
            let durable_promotions = plan
                .promotions
                .iter()
                .map(|&(sequence, identity)| identity.journal_entry(sequence))
                .collect::<Vec<_>>();
            append_durable_message_events(
                &mut self.message_journal,
                &mut self.pending_journal_events,
                &durable_promotions,
                durable_tip,
            )?;

            for (sequence, identity) in plan.promotions {
                self.recent_messages.insert(sequence, identity);
                if identity.block_number > durable_tip {
                    self.pending_journal_events
                        .push_back(identity.journal_entry(sequence));
                }
            }
            self.trim_recent_messages();
            self.publish_l1_verified_tip();

            if let Some((sequence_number, timing)) = self.settle_pending_applied().await? {
                on_applied(sequence_number, timing);
            }
        }
        if let Some(last) = inputs.last() {
            self.last_l1_sequence = Some(last.sequence_number());
        }
        Ok(resolved_suffix)
    }

    async fn advance_with_applied_inner<F>(
        &mut self,
        input: &ArbEngineInput,
        defer_tail: bool,
        drain_pending: bool,
        on_applied: &mut F,
    ) -> eyre::Result<B256>
    where
        F: FnMut(u64, ArbAppliedMessageTiming),
    {
        let seq = input.sequence_number();
        if seq < self.next_seq && input.source() == ArbEngineInputSource::L1 {
            self.reconcile_applied_l1_chunk(core::slice::from_ref(input), on_applied)
                .await?;
            return Ok(self.tip.hash());
        }
        self.flush_durable_message_journal()?;
        if seq < self.next_seq {
            self.verify_applied_overlap(input)?;
            if let Some((sequence_number, timing)) = self.settle_pending_applied().await? {
                on_applied(sequence_number, timing);
            }
            return Ok(self.tip.hash());
        }
        if seq > self.next_seq {
            if let Some(existing) = self.pending.get(&seq) {
                let reconciled = merge_same_sequence_inputs(existing, input)?;
                self.pending.insert(seq, reconciled);
            } else if self.pending.len() < MAX_PENDING_MESSAGES {
                self.pending.insert(seq, input.clone());
            } else if input.source() == ArbEngineInputSource::L1 {
                return Err(eyre!(
                    "authoritative L1 message at sequence {seq} cannot enter full feed-ahead buffer"
                ));
            }
            if let Some((sequence_number, timing)) = self.settle_pending_applied().await? {
                on_applied(sequence_number, timing);
            }
            return Ok(self.tip.hash());
        }

        // If a feed-ahead copy already occupies the sequence that L1 just closed, compare before
        // choosing the authoritative representation. Never let map insertion order choose history.
        let selected = match self.pending.get(&seq) {
            Some(buffered) => merge_same_sequence_inputs(buffered, input)?,
            None => input.clone(),
        };

        // seq == next_seq: queue this block, then drain the contiguous feed-ahead buffer. Each
        // subsequent payload-attributes request is queued before the previous final FCU is
        // awaited, which restores the native engine overlap without reading pending state.
        let parent_hash = self.tip.hash();
        let (mut hash, completed) = self
            .apply_one_native(seq, &selected, Instant::now())
            .await?;
        self.record_applied_message(seq, &selected, hash, parent_hash)?;
        self.pending.remove(&seq);
        if let Some((sequence_number, timing)) = completed {
            on_applied(sequence_number, timing);
        }
        self.next_seq += 1;
        while drain_pending && let Some(buffered) = self.pending.get(&self.next_seq).cloned() {
            let sequence_number = self.next_seq;
            let parent_hash = self.tip.hash();
            let (new_hash, completed) = self
                .apply_one_native(sequence_number, &buffered, Instant::now())
                .await?;
            self.record_applied_message(sequence_number, &buffered, new_hash, parent_hash)?;
            self.pending.remove(&sequence_number);
            hash = new_hash;
            if let Some((completed_sequence, timing)) = completed {
                on_applied(completed_sequence, timing);
            }
            self.next_seq += 1;
        }

        if !defer_tail
            && let Some((sequence_number, timing)) = self.settle_pending_applied().await?
        {
            on_applied(sequence_number, timing);
        }

        // Discard any stragglers now below the cursor (a feed dup that lost the race to L1).
        self.pending.retain(|k, _| *k >= self.next_seq);
        Ok(hash)
    }

    fn verify_applied_overlap(&mut self, input: &ArbEngineInput) -> eyre::Result<()> {
        let sequence = input.sequence_number();
        let applied = self.applied_identity(sequence);
        let Some(applied) = applied else {
            if sequence > self.message_journal.anchor().sequence {
                return Err(divergence_at(
                    sequence,
                    format!(
                        "cannot verify overlap at sequence {sequence}: no durable or in-memory message identity exists"
                    ),
                ));
            }
            // The explicit or compacted journal anchor trusts the older prefix as one indivisible
            // L1-verified snapshot.
            return Ok(());
        };
        let incoming = fingerprint_message(input.message()).map_err(|error| {
            divergence_at(
                sequence,
                format!("cannot normalize overlap at sequence {sequence}: {error:#}"),
            )
        })?;
        if !applied.fingerprint.semantically_matches(incoming) {
            return Err(divergence_at(
                sequence,
                format!(
                    "feed/L1 message disagreement at applied sequence {sequence}: applied source {:?} block {:#x} parent {:#x} core {:#x}, incoming source {:?} core {:#x}",
                    applied.source,
                    applied.block_hash,
                    applied.parent_hash,
                    applied.fingerprint.core,
                    input.source(),
                    incoming.core,
                ),
            ));
        }
        Ok(())
    }

    fn applied_identity(&self, sequence: u64) -> Option<AppliedMessageIdentity> {
        self.recent_messages
            .get(&sequence)
            .copied()
            .or_else(|| self.message_journal.entry(sequence).map(Into::into))
    }

    fn l1_authority_sequence(&self) -> u64 {
        let mut sequence = self.message_journal.anchor().sequence;
        while let Some(next) = sequence.checked_add(1) {
            if next >= self.next_seq
                || self
                    .applied_identity(next)
                    .is_none_or(|identity| identity.source != ArbEngineInputSource::L1)
            {
                break;
            }
            sequence = next;
        }
        sequence
    }

    fn publish_l1_verified_tip(&self) {
        let verified = self.message_journal.l1_verified_tip();
        self.l1_verified_tip
            .fetch_max(verified.block_number, Ordering::Release);
    }

    fn record_applied_message(
        &mut self,
        sequence: u64,
        input: &ArbEngineInput,
        block_hash: B256,
        parent_hash: B256,
    ) -> eyre::Result<()> {
        let block_number = self
            .genesis_block
            .checked_add(sequence)
            .ok_or_else(|| eyre!("message sequence overflows L2 block number"))?;
        if block_number != self.tip.number {
            return Err(eyre!(
                "message sequence {sequence} maps to block {block_number}, but produced tip is {}",
                self.tip.number
            ));
        }
        let identity = AppliedMessageIdentity {
            fingerprint: fingerprint_message(input.message())?,
            source: input.source(),
            block_number,
            block_hash,
            parent_hash,
            delayed_messages_read: input.message().message_with_meta_data.delayed_messages_read,
        };
        self.recent_messages.insert(sequence, identity);
        self.pending_journal_events
            .push_back(identity.journal_entry(sequence));
        self.trim_recent_messages();
        Ok(())
    }

    fn trim_recent_messages(&mut self) {
        while self.recent_messages.len() > MAX_RECENT_MESSAGE_IDENTITIES {
            let Some(oldest) = self.recent_messages.first_key_value().map(|(&key, _)| key) else {
                break;
            };
            self.recent_messages.remove(&oldest);
        }
    }

    /// Durably block automatic restart after any fail-closed driver error.
    pub fn write_divergence_marker(&self, input: &ArbEngineInput, error: &str) -> eyre::Result<()> {
        self.message_journal.write_divergence_marker(
            self.tip.number,
            self.tip.hash(),
            self.next_seq,
            input,
            error,
        )
    }

    /// Persist a divergence marker using the exact buffered message identified by the typed error.
    pub fn write_divergence_marker_for_error(
        &self,
        fallback: &ArbEngineInput,
        error: &eyre::Report,
    ) -> eyre::Result<()> {
        let input = message_divergence_sequence(error)
            .and_then(|sequence| self.pending.get(&sequence))
            .unwrap_or(fallback);
        self.write_divergence_marker(input, &format!("{error:#}"))
    }

    /// Number of durability batches appended by this driver's message journal.
    #[doc(hidden)]
    pub const fn message_journal_append_operations(&self) -> usize {
        self.message_journal.append_operations()
    }

    /// Persist every journal event whose corresponding block is already durable in Reth.
    pub fn flush_durable_message_journal(&mut self) -> eyre::Result<()> {
        if self.pending_journal_events.is_empty() {
            return Ok(());
        }
        let durable_tip = self.provider.last_block_number()?;
        append_durable_message_events(
            &mut self.message_journal,
            &mut self.pending_journal_events,
            &[],
            durable_tip,
        )?;
        self.publish_l1_verified_tip();
        Ok(())
    }

    /// Drive Reth's local payload lifecycle for one already-ordered Arbitrum message.
    async fn apply_one_native(
        &mut self,
        sequence_number: u64,
        input: &ArbEngineInput,
        started_at: Instant,
    ) -> eyre::Result<(B256, Option<(u64, ArbAppliedMessageTiming)>)> {
        let parent_arbos_version = ArbHeaderInfo::decode_header(self.tip.header())
            .map(|info| info.arbos_format_version)
            .unwrap_or_default();
        validate_batch_report_metadata(parent_arbos_version, sequence_number, input)?;

        let payload_builder = self.payload_builder.clone();
        let parent = self.tip.hash();
        let phase_started_at = Instant::now();
        let attributes = self.native_payload_attributes(input.message());
        let payload_attributes = phase_started_at.elapsed();

        // This is Reth's standard local-builder entry point. The engine tree validates the
        // attributes, creates the sparse state-root task, and passes its handle to the builder.
        let payload_job_started_at = Instant::now();
        let (fcu_tx, fcu_rx) = tokio::sync::oneshot::channel();
        self.to_tree
            .send(FromEngine::Request(EngineApiRequest::Beacon(
                BeaconEngineMessage::ForkchoiceUpdated {
                    state: alloy_rpc_types_engine::ForkchoiceState {
                        head_block_hash: parent,
                        safe_block_hash: parent,
                        finalized_block_hash: B256::ZERO,
                    },
                    payload_attrs: Some(attributes),
                    tx: fcu_tx,
                },
            )))
            .map_err(|e| eyre!("send native payload FCU: {e}"))?;

        // The preceding block's final FCU was enqueued before this attributes FCU. Settle it now:
        // Reth can process this request and launch the next payload job as soon as canonicalization
        // completes, instead of waiting for another producer-to-engine round trip.
        let completed_previous = self.settle_pending_applied().await?;

        let build_fcu = fcu_rx
            .await
            .wrap_err("native payload FCU response channel")?;
        let build_fcu = build_fcu.wrap_err("native payload FCU RethResult")?;
        let build_fcu = build_fcu
            .await
            .map_err(|e| eyre!("native payload FCU error: {e:?}"))?;
        let payload_id = build_fcu
            .payload_id
            .ok_or_else(|| eyre!("native payload FCU returned no payload id"))?;
        let payload_job_launch = payload_job_started_at.elapsed();

        // Arbitrum has no competitive transaction-pool selection: resolve the deterministic
        // one-message build immediately, then hand its executed result back to the tree exactly
        // as Reth's regular engine launcher does for a locally built payload.
        let payload_resolve_started_at = Instant::now();
        let payload = payload_builder
            .resolve_kind(payload_id, PayloadKind::Earliest)
            .await
            .ok_or_else(|| eyre!("native payload job {payload_id:?} disappeared"))?
            .map_err(|e| eyre!("native payload job {payload_id:?} failed: {e}"))?;
        let payload_job_resolve = payload_resolve_started_at.elapsed();
        let payload_job = payload_job_started_at.elapsed();
        let production_timing = payload.production_timing();
        let execution_cache_stats = payload.execution_cache_stats();
        let mut built = payload
            .executed_block()
            .ok_or_else(|| eyre!("native payload {payload_id:?} omitted execution output"))?;
        crate::storage_v2::mark_live_hashed_storage_wipes(&mut built);

        let produced_hash = built.recovered_block.hash();
        if let Some(claimed_hash) = input.claimed_block_hash()
            && claimed_hash != produced_hash
        {
            return Err(divergence_at(
                sequence_number,
                format!(
                    "sequencer feed block hash mismatch at sequence {sequence_number}: claimed \
                 {claimed_hash:#x}, produced {produced_hash:#x}"
                ),
            ));
        }

        let new_hash = self.queue_applied_block(
            sequence_number,
            built,
            production_timing,
            execution_cache_stats,
            ArbPayloadJobTiming {
                attributes: payload_attributes,
                job: payload_job,
                launch: payload_job_launch,
                resolve: payload_job_resolve,
            },
            started_at,
        )?;

        Ok((new_hash, completed_previous))
    }

    fn native_payload_attributes(&self, msg: &BroadcastFeedMessage) -> ArbPayloadAttributes {
        let parent = self.tip.header();
        let l1_timestamp = msg
            .message_with_meta_data
            .l1_incoming_message
            .header
            .timestamp;

        ArbPayloadAttributes {
            timestamp: l1_timestamp.max(parent.timestamp),
            message: msg.clone(),
        }
    }

    /// Insert one locally executed block and queue the FCU that makes it canonical.
    fn queue_applied_block(
        &mut self,
        sequence_number: u64,
        built: BuiltPayloadExecutedBlock<ArbPrimitives>,
        production_timing: ArbBlockProductionTiming,
        execution_cache_stats: Option<Arc<CacheStats>>,
        payload_timing: ArbPayloadJobTiming,
        started_at: Instant,
    ) -> eyre::Result<B256> {
        debug_assert!(self.pending_applied.is_none());
        let new_hash = built.recovered_block.hash();
        let new_header = built.recovered_block.header().clone();
        let new_number = new_header.number;

        // Feed the executed block to the tree (no re-execution).
        let engine_handoff_started_at = Instant::now();
        let phase_started_at = Instant::now();
        self.to_tree
            .send(FromEngine::Request(EngineApiRequest::InsertExecutedBlock(
                built,
            )))
            .map_err(|e| eyre!("send InsertExecutedBlock: {e}"))?;
        let engine_insert = phase_started_at.elapsed();

        // Drive canonicalization via ForkchoiceUpdated (head = new block).
        let phase_started_at = Instant::now();
        let (fcu_tx, fcu_rx) = tokio::sync::oneshot::channel();
        let fcu_state = alloy_rpc_types_engine::ForkchoiceState {
            head_block_hash: new_hash,
            safe_block_hash: new_hash,
            finalized_block_hash: B256::ZERO,
        };
        self.to_tree
            .send(FromEngine::Request(EngineApiRequest::Beacon(
                BeaconEngineMessage::ForkchoiceUpdated {
                    state: fcu_state,
                    payload_attrs: None,
                    tx: fcu_tx,
                },
            )))
            .map_err(|e| eyre!("send ForkchoiceUpdated: {e}"))?;

        // Poll the response independently of the producer. If another message is already queued,
        // its attributes FCU can be sent behind this request before the driver joins this task.
        let canonicalization_started_at = Instant::now();
        let forkchoice = tokio::spawn(async move {
            let fcu_res = fcu_rx.await.wrap_err("FCU response channel")?;
            let fcu_res = fcu_res.wrap_err("FCU RethResult")?;
            fcu_res
                .await
                .map_err(|e| eyre!("block {new_number} FCU error: {e:?}"))?;
            Ok(ArbForkchoiceCompletion {
                completed_at: Instant::now(),
                elapsed: phase_started_at.elapsed(),
            })
        });

        self.tip = SealedHeader::new(new_header.clone(), new_hash);
        self.pending_applied = Some(PendingAppliedBlock {
            sequence_number,
            new_hash,
            new_header,
            production_timing,
            execution_cache_stats,
            payload_timing,
            started_at,
            engine_handoff_started_at,
            canonicalization_started_at,
            engine_insert,
            forkchoice: Some(forkchoice),
        });
        Ok(new_hash)
    }

    /// Settle and account for the queued final FCU, if any.
    async fn settle_pending_applied(
        &mut self,
    ) -> eyre::Result<Option<(u64, ArbAppliedMessageTiming)>> {
        let Some(mut pending) = self.pending_applied.take() else {
            return Ok(None);
        };
        let forkchoice = pending
            .forkchoice
            .take()
            .expect("queued block must retain its final FCU task")
            .await
            .wrap_err("final FCU task panicked")??;

        // A successful FCU response should already imply this, but retain an exact hash check so
        // a future engine-tree behavior change cannot turn the overlap into an early callback.
        let was_observable_at_response = matches!(self.provider.block_hash(pending.new_header.number), Ok(Some(hash)) if hash == pending.new_hash)
            || {
                let head = self
                    .provider
                    .canonical_in_memory_state()
                    .get_canonical_head();
                head.header().number == pending.new_header.number && head.hash() == pending.new_hash
            };
        if was_observable_at_response {
            // The exact provider check is authoritative. Drain the redundant committed events so
            // the observation channel cannot grow throughout a long historical sync.
            while self.obs_rx.try_recv().is_ok() {}
        } else {
            let canonicalized = wait_for_head(
                &self.provider,
                &self.provider.canonical_in_memory_state(),
                &mut self.obs_rx,
                pending.new_header.number,
                pending.new_hash,
            )
            .await;
            if !canonicalized {
                return Err(eyre!(
                    "block {} was NOT canonicalized within timeout (head hash {:#x})",
                    pending.new_header.number,
                    pending.new_hash,
                ));
            }
        }

        let completed_at = if was_observable_at_response {
            forkchoice.completed_at
        } else {
            Instant::now()
        };
        let engine_handoff =
            completed_at.saturating_duration_since(pending.engine_handoff_started_at);
        let canonicalization_wait =
            completed_at.saturating_duration_since(pending.canonicalization_started_at);
        let sequence_number = pending.sequence_number;
        let timing = Self::record_completed_block(
            pending,
            forkchoice.elapsed,
            canonicalization_wait,
            engine_handoff,
            completed_at,
        );
        Ok(Some((sequence_number, timing)))
    }

    fn record_completed_block(
        pending: PendingAppliedBlock,
        engine_forkchoice: Duration,
        canonicalization_wait: Duration,
        engine_handoff: Duration,
        completed_at: Instant,
    ) -> ArbAppliedMessageTiming {
        let PendingAppliedBlock {
            new_hash,
            new_header,
            production_timing,
            execution_cache_stats,
            payload_timing,
            started_at,
            engine_insert,
            ..
        } = pending;
        let new_number = new_header.number;
        let block_production = production_timing.total;
        let named_production = production_timing.parent_state
            + production_timing.message_preparation
            + production_timing.state_setup
            + production_timing.execution
            + production_timing.finish;
        let block_production_unattributed = block_production.saturating_sub(named_production);
        let payload_job_overhead = payload_timing.job.saturating_sub(block_production);
        let total = completed_at.saturating_duration_since(started_at);

        // Source-independent production timings. The feed-latency recorder only observes messages
        // seen on the websocket and therefore intentionally omits L1-derived catch-up blocks.
        // These histograms cover every canonical block and are the stable benchmark surface for
        // execution/cache/state-root work.
        if let Some(stats) = execution_cache_stats {
            crate::native_payload::record_execution_cache_stats(&stats);
        }
        let block_metrics = engine_block_metric_handles();
        block_metrics
            .payload_attributes
            .record(payload_timing.attributes.as_secs_f64());
        block_metrics
            .payload_job
            .record(payload_timing.job.as_secs_f64());
        block_metrics
            .payload_job_launch
            .record(payload_timing.launch.as_secs_f64());
        block_metrics
            .payload_job_resolve
            .record(payload_timing.resolve.as_secs_f64());
        block_metrics
            .payload_job_overhead
            .record(payload_job_overhead.as_secs_f64());
        block_metrics
            .production
            .record(block_production.as_secs_f64());
        block_metrics
            .production_unattributed
            .record(block_production_unattributed.as_secs_f64());
        block_metrics
            .parent_state
            .record(production_timing.parent_state.as_secs_f64());
        block_metrics
            .message_preparation
            .record(production_timing.message_preparation.as_secs_f64());
        block_metrics
            .state_setup
            .record(production_timing.state_setup.as_secs_f64());
        block_metrics
            .execution
            .record(production_timing.execution.as_secs_f64());
        block_metrics
            .execution_setup
            .record(production_timing.execution_setup.as_secs_f64());
        block_metrics.start_block_transaction_construction.record(
            production_timing
                .start_block_transaction_construction
                .as_secs_f64(),
        );
        block_metrics
            .start_block_transaction
            .record(production_timing.start_block_transaction.as_secs_f64());
        block_metrics
            .derived_transactions
            .record(production_timing.derived_transactions.as_secs_f64());
        block_metrics.derived_transaction_execution.record(
            production_timing
                .derived_transaction_execution
                .as_secs_f64(),
        );
        block_metrics
            .derived_retry_scheduling
            .record(production_timing.derived_retry_scheduling.as_secs_f64());
        block_metrics.derived_transactions_unattributed.record(
            production_timing
                .derived_transactions_unattributed
                .as_secs_f64(),
        );
        block_metrics
            .execution_unattributed
            .record(production_timing.execution_unattributed.as_secs_f64());
        block_metrics
            .finish
            .record(production_timing.finish.as_secs_f64());
        block_metrics
            .finish_executor
            .record(production_timing.finish_executor.as_secs_f64());
        block_metrics
            .finish_hashed_state
            .record(production_timing.finish_hashed_state.as_secs_f64());
        block_metrics
            .finish_state_root
            .record(production_timing.finish_state_root.as_secs_f64());
        if let Some(wait) = production_timing.finish_state_root_task_wait {
            block_metrics
                .finish_state_root_task_wait
                .record(wait.as_secs_f64());
            if production_timing.state_root_task_succeeded {
                block_metrics.state_root_task_native_success.increment(1);
            } else {
                block_metrics.state_root_task_fallback.increment(1);
            }
        }
        block_metrics
            .finish_assembly
            .record(production_timing.finish_assembly.as_secs_f64());
        block_metrics
            .finish_unattributed
            .record(production_timing.finish_unattributed.as_secs_f64());
        block_metrics
            .engine_handoff
            .record(engine_handoff.as_secs_f64());
        block_metrics
            .engine_insert
            .record(engine_insert.as_secs_f64());
        block_metrics
            .engine_forkchoice
            .record(engine_forkchoice.as_secs_f64());
        block_metrics
            .canonicalization_wait
            .record(canonicalization_wait.as_secs_f64());
        let named_apply = payload_timing.attributes + payload_timing.job + engine_handoff;
        block_metrics
            .apply_overhead
            .record(total.saturating_sub(named_apply).as_secs_f64());
        block_metrics.total.record(total.as_secs_f64());
        let production_seconds = block_production.as_secs_f64();
        let mgas_per_second = if production_seconds > 0.0 {
            new_header.gas_used as f64 / 1_000_000.0 / production_seconds
        } else {
            0.0
        };
        block_metrics.mgas_per_second.record(mgas_per_second);

        // Per-block production trace (observability) + per-phase timing breakdown.
        tracing::info!(
            target: "arb-reth::engine",
            number = new_number,
            %new_hash,
            state_root = %new_header.state_root,
            gas_used = new_header.gas_used,
            "produced block",
        );
        tracing::debug!(
            target: "arb-reth::engine::timing",
            number = new_number,
            us_attributes = payload_timing.attributes.as_micros(),
            us_payload_job = payload_timing.job.as_micros(),
            us_payload_overhead = payload_job_overhead.as_micros(),
            us_produce = block_production.as_micros(),
            us_handoff = engine_handoff.as_micros(),
            us_insert = engine_insert.as_micros(),
            us_fcu = engine_forkchoice.as_micros(),
            us_wait = canonicalization_wait.as_micros(),
            us_total = total.as_micros(),
            "advance timing",
        );

        ArbAppliedMessageTiming {
            started_at,
            completed_at,
            payload_attributes: payload_timing.attributes,
            payload_job: payload_timing.job,
            payload_job_launch: payload_timing.launch,
            payload_job_resolve: payload_timing.resolve,
            payload_job_overhead,
            block_production,
            block_production_unattributed,
            block_parent_state: production_timing.parent_state,
            block_message_preparation: production_timing.message_preparation,
            block_state_setup: production_timing.state_setup,
            block_execution: production_timing.execution,
            block_execution_setup: production_timing.execution_setup,
            block_start_block_transaction_construction: production_timing
                .start_block_transaction_construction,
            block_start_block_transaction: production_timing.start_block_transaction,
            block_derived_transactions: production_timing.derived_transactions,
            block_derived_transaction_execution: production_timing.derived_transaction_execution,
            block_derived_retry_scheduling: production_timing.derived_retry_scheduling,
            block_derived_transactions_unattributed: production_timing
                .derived_transactions_unattributed,
            block_execution_unattributed: production_timing.execution_unattributed,
            block_finish: production_timing.finish,
            block_finish_executor: production_timing.finish_executor,
            block_finish_hashed_state: production_timing.finish_hashed_state,
            block_finish_state_root: production_timing.finish_state_root,
            block_finish_state_root_task_wait: production_timing.finish_state_root_task_wait,
            block_finish_state_root_task_succeeded: production_timing
                .finish_state_root_task_wait
                .map(|_| production_timing.state_root_task_succeeded),
            block_finish_assembly: production_timing.finish_assembly,
            block_finish_unattributed: production_timing.finish_unattributed,
            engine_handoff,
            engine_insert,
            engine_forkchoice,
            canonicalization_wait,
            total,
        }
    }

    /// Returns the current chain tip (the parent for the next block).
    pub fn tip(&self) -> &SealedHeader<Header> {
        &self.tip
    }

    /// Returns a clone of the in-memory canonical state (shared with the `BlockchainProvider`).
    pub fn canonical_in_memory(&self) -> CanonicalInMemoryState<ArbPrimitives> {
        self.canonical.clone()
    }

    /// Ask the engine tree to persist its in-memory tail and terminate.
    pub async fn shutdown(&self) {
        let Some(terminated_rx) = self.engine_termination_guard.request() else {
            tracing::warn!(
                target: "arb-reth::engine",
                "engine termination was already requested or the engine channel is closed",
            );
            return;
        };

        match tokio::time::timeout(Duration::from_secs(10), terminated_rx).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => tracing::warn!(
                target: "arb-reth::engine",
                %err,
                "engine termination response channel closed",
            ),
            Err(_) => tracing::warn!(
                target: "arb-reth::engine",
                target_block = self.tip.number,
                "timed out waiting for engine termination",
            ),
        }
    }
}

#[cfg(test)]
mod termination_tests {
    use super::*;

    #[test]
    fn dropping_driver_guard_requests_engine_termination() {
        let (to_tree, from_driver) = crossbeam_channel::unbounded();
        drop(EngineTerminationGuard::new(to_tree));

        let message = from_driver
            .recv_timeout(Duration::from_secs(1))
            .expect("termination event");
        let FromEngine::Event(FromOrchestrator::Terminate { tx }) = message else {
            panic!("unexpected engine message")
        };
        // The guard intentionally drops the acknowledgement receiver after requesting shutdown.
        assert!(tx.send(()).is_err());
    }
}

#[cfg(test)]
mod reconciliation_tests {
    use super::*;
    use arbitrum_alloy_sequencer::sequencer::feed::BatchDataStats;
    use base64::{Engine as _, prelude::BASE64_STANDARD};

    #[test]
    fn journal_startup_gate_requires_explicit_bootstrap_and_exact_tip() -> eyre::Result<()> {
        let dir = tempfile::tempdir()?;
        let hash = B256::repeat_byte(0x11);

        let missing = open_message_journal_for_tip(dir.path(), 0, 10, hash, false)
            .err()
            .expect("non-genesis tip must not be trusted implicitly");
        assert!(
            missing
                .to_string()
                .contains("--init-message-journal-at-tip")
        );

        open_message_journal_for_tip(dir.path(), 0, 10, hash, true)?;
        let repeated = open_message_journal_for_tip(dir.path(), 0, 10, hash, true)
            .err()
            .expect("bootstrap flag must be one-shot");
        assert!(repeated.to_string().contains("already exists"));
        open_message_journal_for_tip(dir.path(), 0, 10, hash, false)?;

        let mismatch =
            open_message_journal_for_tip(dir.path(), 0, 11, B256::repeat_byte(0x22), false)
                .err()
                .expect("DB ahead of journal must refuse startup");
        assert!(
            mismatch
                .to_string()
                .contains("rewind the database to the journal watermark")
        );

        std::fs::write(
            MessageJournal::divergence_path_in(dir.path()),
            b"torn marker",
        )?;
        let marked = open_message_journal_for_tip(dir.path(), 0, 10, hash, false)
            .err()
            .expect("any marker file must block startup");
        assert!(marked.to_string().contains("unresolved feed/L1 divergence"));
        Ok(())
    }

    #[test]
    fn only_typed_message_failures_are_divergence() {
        assert!(is_message_divergence(&divergence_at(1, "message mismatch")));
        assert!(!is_message_divergence(&eyre!("engine timeout")));
    }

    fn message() -> BroadcastFeedMessage {
        serde_json::from_str(include_str!(
            "../../arb-reth-node/tests/fixtures/deposit_message_only.json"
        ))
        .expect("fixture must parse")
    }

    fn input(sequence: u64) -> ArbEngineInput {
        let mut message = message();
        message.sequence_number = sequence;
        ArbEngineInput::l1(message)
    }

    fn identity(sequence: u64, source: ArbEngineInputSource) -> AppliedMessageIdentity {
        AppliedMessageIdentity {
            fingerprint: fingerprint_message(input(sequence).message()).unwrap(),
            source,
            block_number: sequence + 100,
            block_hash: B256::with_last_byte(sequence as u8),
            parent_hash: B256::with_last_byte(sequence.saturating_sub(1) as u8),
            delayed_messages_read: 1,
        }
    }

    #[test]
    fn matching_l1_copy_retains_buffered_feed_hash_claim() {
        let feed = ArbEngineInput::feed(message(), Some(B256::repeat_byte(0x11)));
        let l1 = ArbEngineInput::l1(message());

        let selected = merge_same_sequence_inputs(&feed, &l1).unwrap();
        assert_eq!(selected.source(), ArbEngineInputSource::L1);
        assert_eq!(selected.claimed_block_hash(), Some(B256::repeat_byte(0x11)));
    }

    #[test]
    fn conflicting_l1_copy_is_rejected() {
        let feed = ArbEngineInput::feed(message(), None);
        let mut changed = message();
        changed.message_with_meta_data.delayed_messages_read += 1;
        let l1 = ArbEngineInput::l1(changed);

        let error = merge_same_sequence_inputs(&feed, &l1).unwrap_err();
        assert!(error.to_string().contains("feed/L1 message disagreement"));
    }

    #[test]
    fn conflicting_feed_hash_claims_are_rejected() {
        let first = ArbEngineInput::feed(message(), Some(B256::repeat_byte(0x11)));
        let second = ArbEngineInput::feed(message(), Some(B256::repeat_byte(0x22)));

        let error = merge_same_sequence_inputs(&first, &second).unwrap_err();
        assert!(error.to_string().contains("conflicting block hashes"));
    }

    #[test]
    fn plans_maximal_matching_overlap_and_leaves_feed_suffix_unsafe() {
        let identities = (1..=3)
            .map(|sequence| (sequence, identity(sequence, ArbEngineInputSource::Feed)))
            .collect::<BTreeMap<_, _>>();
        let chunk = [input(1), input(2)];
        let plan = plan_applied_l1_chunk(&chunk, 4, 0, 0, None, |sequence| {
            identities.get(&sequence).copied()
        })
        .unwrap();

        assert_eq!(plan.overlap_len, 2);
        assert_eq!(
            plan.promotions
                .iter()
                .map(|(sequence, _)| *sequence)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(
            identities.get(&3).unwrap().source,
            ArbEngineInputSource::Feed,
            "an absent feed-executed suffix is not divergence or L1-authoritative"
        );
    }

    #[test]
    fn validates_the_complete_chunk_before_planning_promotions() {
        let identities = (1..=3)
            .map(|sequence| (sequence, identity(sequence, ArbEngineInputSource::Feed)))
            .collect::<BTreeMap<_, _>>();
        for chunk in [[input(1), input(3)], [input(2), input(1)]] {
            let error = plan_applied_l1_chunk(&chunk, 4, 0, 0, None, |sequence| {
                identities.get(&sequence).copied()
            })
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("strictly ordered and contiguous")
            );
            assert!(is_message_divergence(&error));
        }
    }

    #[test]
    fn rejects_gaps_at_overlap_and_chunk_boundaries() {
        let identities = (1..=3)
            .map(|sequence| (sequence, identity(sequence, ArbEngineInputSource::Feed)))
            .collect::<BTreeMap<_, _>>();

        let skipped_overlap = plan_applied_l1_chunk(&[input(2)], 4, 0, 0, None, |sequence| {
            identities.get(&sequence).copied()
        })
        .unwrap_err();
        assert_eq!(message_divergence_sequence(&skipped_overlap), Some(2));
        assert!(skipped_overlap.to_string().contains("authority frontier"));

        let cross_chunk_gap = plan_applied_l1_chunk(&[input(3)], 4, 0, 2, Some(1), |sequence| {
            identities.get(&sequence).copied()
        })
        .unwrap_err();
        assert_eq!(message_divergence_sequence(&cross_chunk_gap), Some(3));
        assert!(
            cross_chunk_gap
                .to_string()
                .contains("strictly ordered and contiguous")
        );

        let initial_execution_gap = plan_applied_l1_chunk(&[input(3)], 1, 0, 0, None, |sequence| {
            identities.get(&sequence).copied()
        })
        .unwrap_err();
        assert_eq!(message_divergence_sequence(&initial_execution_gap), Some(3));
        assert!(
            initial_execution_gap
                .to_string()
                .contains("next executable sequence")
        );

        let skipped_authority = plan_applied_l1_chunk(&[input(5)], 5, 0, 0, None, |sequence| {
            identities.get(&sequence).copied()
        })
        .unwrap_err();
        assert_eq!(message_divergence_sequence(&skipped_authority), Some(5));
        assert!(skipped_authority.to_string().contains("authority frontier"));
    }

    #[test]
    fn production_planner_rejects_every_execution_sensitive_mismatch() {
        let original = input(1);
        let payload = BASE64_STANDARD
            .decode(
                &original
                    .message()
                    .message_with_meta_data
                    .l1_incoming_message
                    .l2msg,
            )
            .expect("fixture payload");
        assert!(payload.len() > 2, "fixture must exercise payload ordering");

        let mut changed_messages = Vec::new();
        for changed_payload in {
            let mut omitted = payload.clone();
            omitted.remove(1);
            let mut added = payload.clone();
            added.insert(1, 0xaa);
            let mut reordered = payload;
            reordered.swap(0, 1);
            [omitted, added, reordered]
        } {
            let mut changed = original.message().clone();
            changed.message_with_meta_data.l1_incoming_message.l2msg =
                BASE64_STANDARD.encode(changed_payload);
            changed_messages.push(changed);
        }
        let mut typed_metadata = original.message().clone();
        typed_metadata
            .message_with_meta_data
            .l1_incoming_message
            .header
            .timestamp += 1;
        changed_messages.push(typed_metadata);
        let mut delayed_cursor = original.message().clone();
        delayed_cursor.message_with_meta_data.delayed_messages_read += 1;
        changed_messages.push(delayed_cursor);

        let stored = identity(1, ArbEngineInputSource::Feed);
        for changed in changed_messages {
            let error =
                plan_applied_l1_chunk(&[ArbEngineInput::l1(changed)], 2, 0, 0, None, |_| {
                    Some(stored)
                })
                .unwrap_err();
            assert_eq!(message_divergence_sequence(&error), Some(1));
            assert!(error.to_string().contains("feed/L1 message disagreement"));
        }

        let mut complete = original.message().clone();
        complete
            .message_with_meta_data
            .l1_incoming_message
            .header
            .kind = 13;
        complete
            .message_with_meta_data
            .l1_incoming_message
            .batch_data_stats = Some(BatchDataStats {
            length: 100,
            non_zeros: 80,
        });
        let complete_identity = AppliedMessageIdentity {
            fingerprint: fingerprint_message(&complete).unwrap(),
            ..stored
        };
        let mut incompatible = complete.clone();
        incompatible
            .message_with_meta_data
            .l1_incoming_message
            .batch_data_stats
            .as_mut()
            .unwrap()
            .non_zeros = 79;
        assert!(
            plan_applied_l1_chunk(
                &[ArbEngineInput::l1(incompatible)],
                2,
                0,
                0,
                None,
                |_| Some(complete_identity),
            )
            .is_err()
        );

        complete
            .message_with_meta_data
            .l1_incoming_message
            .batch_data_stats = None;
        let permitted_missing =
            plan_applied_l1_chunk(&[ArbEngineInput::l1(complete)], 2, 0, 0, None, |_| {
                Some(complete_identity)
            })
            .expect("Nitro permits one representation to omit enrichment");
        assert_eq!(permitted_missing.promotions.len(), 1);
    }

    #[test]
    fn missing_identity_blocks_every_later_promotion() {
        let identities = BTreeMap::from([
            (1, identity(1, ArbEngineInputSource::Feed)),
            (3, identity(3, ArbEngineInputSource::Feed)),
        ]);
        let error =
            plan_applied_l1_chunk(&[input(1), input(2), input(3)], 4, 0, 0, None, |sequence| {
                identities.get(&sequence).copied()
            })
            .unwrap_err();

        assert_eq!(message_divergence_sequence(&error), Some(2));
        assert!(error.to_string().contains("no durable or in-memory"));
        assert_eq!(
            identities.get(&3).unwrap().source,
            ArbEngineInputSource::Feed
        );
    }

    #[test]
    fn unaligned_chunks_produce_the_same_authority_prefix() {
        let initial = (1..=3)
            .map(|sequence| (sequence, identity(sequence, ArbEngineInputSource::Feed)))
            .collect::<BTreeMap<_, _>>();
        let whole =
            plan_applied_l1_chunk(&[input(1), input(2), input(3)], 4, 0, 0, None, |sequence| {
                initial.get(&sequence).copied()
            })
            .unwrap();

        let mut split = initial;
        let first = plan_applied_l1_chunk(&[input(1)], 4, 0, 0, None, |sequence| {
            split.get(&sequence).copied()
        })
        .unwrap();
        for (sequence, promoted) in first.promotions {
            split.insert(sequence, promoted);
        }
        let second = plan_applied_l1_chunk(&[input(2), input(3)], 4, 0, 1, Some(1), |sequence| {
            split.get(&sequence).copied()
        })
        .unwrap();

        assert_eq!(whole.promotions.len(), 3);
        assert_eq!(second.promotions.len(), 2);
        assert_eq!(second.promotions.last().unwrap().0, 3);
    }

    #[test]
    fn durable_promotions_share_one_append_operation() -> eyre::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = MessageJournal::path_in(dir.path());
        let anchor = MessageJournalAnchor {
            sequence: 0,
            block_number: 100,
            block_hash: B256::repeat_byte(0x10),
        };
        let mut journal = MessageJournal::create(path, anchor)?;
        let feed = [
            identity(1, ArbEngineInputSource::Feed).journal_entry(1),
            identity(2, ArbEngineInputSource::Feed).journal_entry(2),
        ];
        let mut pending = VecDeque::from(feed);
        let promotions = [
            identity(1, ArbEngineInputSource::L1).journal_entry(1),
            identity(2, ArbEngineInputSource::L1).journal_entry(2),
        ];

        append_durable_message_events(&mut journal, &mut pending, &promotions, 102)?;

        assert_eq!(journal.append_operations(), 1);
        assert_eq!(journal.l1_verified_tip().sequence, 2);
        assert!(pending.is_empty());
        Ok(())
    }

    #[test]
    fn non_durable_promotion_cannot_publish_early() -> eyre::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = MessageJournal::path_in(dir.path());
        let anchor = MessageJournalAnchor {
            sequence: 0,
            block_number: 100,
            block_hash: B256::repeat_byte(0x10),
        };
        let mut journal = MessageJournal::create(path, anchor)?;
        let mut pending = VecDeque::from([
            identity(1, ArbEngineInputSource::Feed).journal_entry(1),
            identity(2, ArbEngineInputSource::Feed).journal_entry(2),
        ]);
        let promotions = [
            identity(1, ArbEngineInputSource::L1).journal_entry(1),
            identity(2, ArbEngineInputSource::L1).journal_entry(2),
        ];

        append_durable_message_events(&mut journal, &mut pending, &promotions, 101)?;
        pending.push_back(promotions[1]);
        assert_eq!(journal.l1_verified_tip().sequence, 1);
        assert_eq!(
            pending.len(),
            2,
            "feed and promotion for block 102 remain queued"
        );

        append_durable_message_events(&mut journal, &mut pending, &[], 102)?;
        assert_eq!(journal.l1_verified_tip().sequence, 2);
        Ok(())
    }

    #[test]
    fn arbos_fifty_requires_batch_report_stats() {
        let mut report = message();
        report
            .message_with_meta_data
            .l1_incoming_message
            .header
            .kind = 13;
        let input = ArbEngineInput::feed(report.clone(), None);
        validate_batch_report_metadata(49, 1, &input).unwrap();
        assert!(validate_batch_report_metadata(50, 1, &input).is_err());

        report
            .message_with_meta_data
            .l1_incoming_message
            .batch_data_stats = Some(arbitrum_alloy_sequencer::sequencer::feed::BatchDataStats {
            length: 100,
            non_zeros: 80,
        });
        validate_batch_report_metadata(50, 1, &ArbEngineInput::feed(report, None)).unwrap();
    }
}

#[cfg(test)]
mod sparse_compatibility_tests {
    use alloy_primitives::{Address, U256};
    use revm::state::{Account as RevmAccount, EvmState};

    use super::*;

    #[test]
    fn selfdestruct_always_requires_serial_root() {
        let mut account = RevmAccount::default();
        account.mark_touch();
        account.mark_selfdestruct();
        let mut state = EvmState::default();
        state.insert(Address::ZERO, account);

        assert_ne!(
            sparse_root_hazards(&state, false) & SPARSE_HAZARD_SELFDESTRUCT,
            0
        );
        assert_ne!(
            sparse_root_hazards(&state, true) & SPARSE_HAZARD_SELFDESTRUCT,
            0
        );
    }

    #[test]
    fn created_empty_requires_serial_root_only_when_preserved() {
        let mut account = RevmAccount::default();
        account.mark_touch();
        account.mark_created();
        let mut state = EvmState::default();
        state.insert(Address::ZERO, account);

        assert_eq!(sparse_root_hazards(&state, false), 0);
        assert_ne!(
            sparse_root_hazards(&state, true) & SPARSE_HAZARD_CREATED_EMPTY,
            0
        );
    }

    #[test]
    fn ordinary_empty_and_created_nonempty_accounts_stay_sparse() {
        let mut touched_empty = RevmAccount::default();
        touched_empty.mark_touch();

        let mut created_nonempty = RevmAccount::default();
        created_nonempty.mark_touch();
        created_nonempty.mark_created();
        created_nonempty.info.balance = U256::from(1);

        let mut state = EvmState::default();
        state.insert(Address::ZERO, touched_empty);
        state.insert(Address::with_last_byte(1), created_nonempty);
        assert_eq!(sparse_root_hazards(&state, true), 0);
    }
}
