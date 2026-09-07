//! Finite, provider-independent primitives for the stopped B2 canonical observer.
//!
//! The normal synchronizer deliberately remains separate. This module contains only the frozen
//! aggregate-memory, deadline, accumulator, and blob-commitment contracts shared by the one-shot
//! observer and its offline providers.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use alloy_eips::eip4844::kzg_to_versioned_hash;
use alloy_primitives::{Address, B256, Bytes, keccak256};
use arb_reth_derive::blob::BYTES_PER_BLOB;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

use crate::{DeliveredBatch, serialize_batch};

pub const MAX_SAFE_TO_CONTAINING_L1_GAP: u64 = 2_048;
pub const MAX_DEPENDENCY_CLOSURE_L1_SPAN: u64 = 8_192;
pub const MAX_BATCHES_PER_OBSERVATION_UNIT: usize = 64;
pub const MAX_MESSAGES_PER_BATCH: usize = 4_096;
pub const MAX_DELAYED_MESSAGES_PER_BATCH: usize = 1_024;
pub const MAX_BLOBS_PER_POSTING_TRANSACTION: usize = 16;
pub const MAX_EXACT_LOGS_PER_BLOCK: usize = 4_096;
pub const MAX_HTTP_WIRE_BODY_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_RPC_DECODED_BODY_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_RESOLVED_BATCH_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_DECOMPRESSED_BATCH_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_SINGLE_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
pub const OBSERVER_FIXED_MEMORY_RESERVE: usize = 32 * 1024 * 1024;
pub const OBSERVER_DYNAMIC_MEMORY_BYTES: usize = 480 * 1024 * 1024;
pub const MEMORY_PERMIT_QUANTUM: usize = 4 * 1024;
pub const MAX_EXECUTION_RPC_IN_FLIGHT: usize = 8;
pub const MAX_BEACON_RPC_IN_FLIGHT: usize = 2;
pub const MAX_TRANSIENT_ATTEMPTS: usize = 3;
pub const OBSERVATION_ATTEMPT_TIME: Duration = Duration::from_secs(120);
pub const OBSERVER_TOTAL_TIME: Duration = Duration::from_secs(300);
pub const PROVIDER_WORK_TIME: Duration = Duration::from_secs(285);
pub const CANCELLATION_JOIN_TIME: Duration = Duration::from_secs(15);
pub const MIN_NEW_ATTEMPT_TIME: Duration = Duration::from_secs(5);
pub const RETRY_BACKOFFS: [Duration; 2] = [Duration::from_secs(1), Duration::from_secs(2)];
pub const OBSERVER_DEADLINE_EXIT_CODE: i32 = 74;

const DYNAMIC_PERMIT_COUNT: usize = OBSERVER_DYNAMIC_MEMORY_BYTES / MEMORY_PERMIT_QUANTUM;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalError(String);

impl CanonicalError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for CanonicalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for CanonicalError {}

type CanonicalResult<T> = Result<T, CanonicalError>;

#[derive(serde::Deserialize)]
struct RpcEnvelope<T> {
    result: T,
    error: Option<serde_json::Value>,
}

/// Serde's reader consumes input incrementally (including inside strings). Never give it an
/// unchecked slice: every bounded segment tests both cancellation and the monotonic deadline.
fn parse_json<T: serde::de::DeserializeOwned>(
    body: &[u8],
    cancellation: &CanonicalCancellation,
    deadline: tokio::time::Instant,
) -> CanonicalResult<T> {
    struct Segments<'a> {
        remaining: &'a [u8],
        consumed: usize,
        cancellation: &'a CanonicalCancellation,
        deadline: tokio::time::Instant,
    }
    impl std::io::Read for Segments<'_> {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if self.consumed.is_multiple_of(MEMORY_PERMIT_QUANTUM)
                && (self.cancellation.is_cancelled()
                    || tokio::time::Instant::now() >= self.deadline)
            {
                return Err(std::io::Error::other(
                    "canonical JSON parsing cancelled or expired",
                ));
            }
            let count = output
                .len()
                .min(self.remaining.len())
                .min(MEMORY_PERMIT_QUANTUM - self.consumed % MEMORY_PERMIT_QUANTUM);
            output[..count].copy_from_slice(&self.remaining[..count]);
            self.remaining = &self.remaining[count..];
            self.consumed += count;
            Ok(count)
        }
    }
    let value = serde_json::from_reader(Segments {
        remaining: body,
        consumed: 0,
        cancellation,
        deadline,
    })
    .map_err(|error| CanonicalError::new(format!("incremental JSON decode: {error}")))?;
    cancellation.check()?;
    if tokio::time::Instant::now() >= deadline {
        return Err(CanonicalError::new(
            "canonical JSON parsing deadline expired",
        ));
    }
    Ok(value)
}

/// A typed provider result that retains every wire/decode/parse permit until the result is
/// consumed. This prevents copied provider objects from escaping the aggregate budget.
#[derive(Debug)]
pub struct ReservedValue<T> {
    value: T,
    _liability: CanonicalMemoryReservation,
}

impl<T> ReservedValue<T> {
    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn into_parts(self) -> (T, CanonicalMemoryReservation) {
        (self.value, self._liability)
    }

    pub fn try_map<U>(
        self,
        map: impl FnOnce(T) -> CanonicalResult<U>,
    ) -> CanonicalResult<ReservedValue<U>> {
        let value = map(self.value)?;
        Ok(ReservedValue {
            value,
            _liability: self._liability,
        })
    }
}

/// Pinned execution JSON-RPC endpoint used only by the stopped observer. Responses are read in
/// bounded chunks only after the aggregate budget reserves the complete wire/decode/parse
/// liability. Redirects are disabled so an endpoint cannot silently change during an attempt.
#[derive(Clone, Debug)]
pub struct CanonicalRpcClient {
    endpoint: String,
    http: reqwest::Client,
}

impl CanonicalRpcClient {
    pub fn new(endpoint: impl Into<String>) -> CanonicalResult<Self> {
        let endpoint = endpoint.into();
        let parsed = reqwest::Url::parse(&endpoint)
            .map_err(|error| CanonicalError::new(format!("invalid canonical RPC URL: {error}")))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(CanonicalError::new(
                "canonical RPC URL must use http or https",
            ));
        }
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| CanonicalError::new(format!("build canonical RPC client: {error}")))?;
        Ok(Self { endpoint, http })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub async fn request_typed<T: serde::de::DeserializeOwned>(
        &self,
        method: &'static str,
        params: serde_json::Value,
        budget: &CanonicalMemoryBudget,
        cancellation: &CanonicalCancellation,
        deadline: tokio::time::Instant,
    ) -> CanonicalResult<ReservedValue<T>> {
        cancellation.check()?;
        let request_charge = budget
            .reserve(MEMORY_PERMIT_QUANTUM, deadline, cancellation)
            .await?;
        let request = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }))
        .map_err(|error| CanonicalError::new(format!("encode {method} request: {error}")))?;
        if request.len() > MEMORY_PERMIT_QUANTUM {
            return Err(CanonicalError::new(
                "canonical JSON-RPC request exceeds one permit quantum",
            ));
        }

        let mut body_charge = budget
            .reserve(MEMORY_PERMIT_QUANTUM * 2, deadline, cancellation)
            .await?;
        let parsed = budget
            .reserve(MAX_RPC_DECODED_BODY_BYTES, deadline, cancellation)
            .await?;
        let response = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                return Err(CanonicalError::new("canonical observation was cancelled"));
            },
            response = tokio::time::timeout_at(
                deadline,
                self.http
                    .post(&self.endpoint)
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(request)
                    .send(),
            ) => response
                .map_err(|_| CanonicalError::new(format!("{method} missed attempt deadline")))?
                .map_err(|error| CanonicalError::new(format!("{method} transport: {error}")))?,
        };
        drop(request_charge);
        if !response.status().is_success() {
            return Err(CanonicalError::new(format!(
                "{method} returned HTTP {}",
                response.status()
            )));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_HTTP_WIRE_BODY_BYTES as u64)
        {
            return Err(CanonicalError::new(format!(
                "{method} HTTP body exceeds 32 MiB"
            )));
        }
        let mut response = response;
        let mut body = Vec::new();
        while let Some(chunk) = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                return Err(CanonicalError::new("canonical observation was cancelled"));
            },
            chunk = tokio::time::timeout_at(deadline, response.chunk()) => chunk
                .map_err(|_| CanonicalError::new(format!("{method} body missed attempt deadline")))?
                .map_err(|error| CanonicalError::new(format!("{method} response body: {error}")))?,
        } {
            cancellation.check()?;
            let next = body
                .len()
                .checked_add(chunk.len())
                .ok_or_else(|| CanonicalError::new("canonical HTTP body length overflow"))?;
            if next > MAX_HTTP_WIRE_BODY_BYTES {
                return Err(CanonicalError::new(format!(
                    "{method} HTTP body exceeds 32 MiB"
                )));
            }
            let required = next
                .checked_mul(2)
                .ok_or_else(|| CanonicalError::new("canonical HTTP liability overflow"))?
                .max(MEMORY_PERMIT_QUANTUM * 2);
            let charged = body_charge.charged_bytes();
            if required > charged {
                body_charge = body_charge.merge(
                    budget
                        .reserve(required - charged, deadline, cancellation)
                        .await?,
                )?;
            }
            body.try_reserve_exact(chunk.len())
                .map_err(|_| CanonicalError::new("canonical HTTP body allocation failed"))?;
            body.extend_from_slice(&chunk);
        }
        if body.len() > MAX_RPC_DECODED_BODY_BYTES {
            return Err(CanonicalError::new(format!(
                "{method} decoded body exceeds 64 MiB"
            )));
        }
        let envelope: RpcEnvelope<T> = parse_json(&body, cancellation, deadline)?;
        if envelope.error.is_some() {
            return Err(CanonicalError::new(format!("{method} JSON-RPC error")));
        }
        drop(body);
        drop(body_charge);
        Ok(ReservedValue {
            value: envelope.result,
            _liability: parsed,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalExecutionHeader {
    pub number: u64,
    pub hash: B256,
    pub parent_hash: B256,
    pub timestamp: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalExecutionLog {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
    pub block_number: u64,
    pub block_hash: B256,
    pub transaction_hash: B256,
    pub transaction_index: u32,
    pub log_index: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalExecutionTransaction {
    pub hash: B256,
    pub block_number: u64,
    pub block_hash: B256,
    pub transaction_index: u32,
    pub to: Address,
    pub input: Bytes,
    pub blob_versioned_hashes: Vec<B256>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalExecutionReceipt {
    pub transaction_hash: B256,
    pub block_number: u64,
    pub block_hash: B256,
    pub transaction_index: u32,
    pub success: bool,
    pub logs: Vec<CanonicalExecutionLog>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawExecutionHeader {
    number: String,
    hash: B256,
    parent_hash: B256,
    timestamp: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawExecutionLog {
    address: Address,
    topics: Vec<B256>,
    data: Bytes,
    block_number: String,
    block_hash: B256,
    transaction_hash: B256,
    transaction_index: String,
    log_index: String,
    removed: bool,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawExecutionTransaction {
    hash: B256,
    block_number: Option<String>,
    block_hash: Option<B256>,
    transaction_index: Option<String>,
    to: Option<Address>,
    input: Bytes,
    #[serde(default)]
    blob_versioned_hashes: Vec<B256>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawExecutionReceipt {
    transaction_hash: B256,
    block_number: String,
    block_hash: B256,
    transaction_index: String,
    status: String,
    logs: Vec<RawExecutionLog>,
}

fn quantity(value: &str, field: &str) -> CanonicalResult<u64> {
    let digits = value
        .strip_prefix("0x")
        .ok_or_else(|| CanonicalError::new(format!("{field} is not a hex quantity")))?;
    if digits.is_empty() || (digits.len() > 1 && digits.starts_with('0')) {
        return Err(CanonicalError::new(format!(
            "{field} is not a canonical hex quantity"
        )));
    }
    u64::from_str_radix(digits, 16)
        .map_err(|error| CanonicalError::new(format!("invalid {field}: {error}")))
}

fn quantity_param(value: u64) -> String {
    format!("0x{value:x}")
}

impl RawExecutionHeader {
    fn checked(self) -> CanonicalResult<CanonicalExecutionHeader> {
        Ok(CanonicalExecutionHeader {
            number: quantity(&self.number, "block number")?,
            hash: self.hash,
            parent_hash: self.parent_hash,
            timestamp: quantity(&self.timestamp, "block timestamp")?,
        })
    }
}

impl RawExecutionLog {
    fn checked(self) -> CanonicalResult<CanonicalExecutionLog> {
        if self.removed {
            return Err(CanonicalError::new("canonical execution log is removed"));
        }
        Ok(CanonicalExecutionLog {
            address: self.address,
            topics: self.topics,
            data: self.data,
            block_number: quantity(&self.block_number, "log block number")?,
            block_hash: self.block_hash,
            transaction_hash: self.transaction_hash,
            transaction_index: u32::try_from(quantity(
                &self.transaction_index,
                "log transaction index",
            )?)
            .map_err(|_| CanonicalError::new("log transaction index exceeds u32"))?,
            log_index: u32::try_from(quantity(&self.log_index, "log index")?)
                .map_err(|_| CanonicalError::new("log index exceeds u32"))?,
        })
    }
}

impl RawExecutionTransaction {
    fn checked(self) -> CanonicalResult<CanonicalExecutionTransaction> {
        Ok(CanonicalExecutionTransaction {
            hash: self.hash,
            block_number: quantity(
                self.block_number
                    .as_deref()
                    .ok_or_else(|| CanonicalError::new("transaction has no block number"))?,
                "transaction block number",
            )?,
            block_hash: self
                .block_hash
                .ok_or_else(|| CanonicalError::new("transaction has no block hash"))?,
            transaction_index: u32::try_from(quantity(
                self.transaction_index
                    .as_deref()
                    .ok_or_else(|| CanonicalError::new("transaction has no index"))?,
                "transaction index",
            )?)
            .map_err(|_| CanonicalError::new("transaction index exceeds u32"))?,
            to: self
                .to
                .ok_or_else(|| CanonicalError::new("posting transaction is contract creation"))?,
            input: self.input,
            blob_versioned_hashes: self.blob_versioned_hashes,
        })
    }
}

impl RawExecutionReceipt {
    fn checked(self) -> CanonicalResult<CanonicalExecutionReceipt> {
        let logs = self
            .logs
            .into_iter()
            .map(RawExecutionLog::checked)
            .collect::<CanonicalResult<Vec<_>>>()?;
        Ok(CanonicalExecutionReceipt {
            transaction_hash: self.transaction_hash,
            block_number: quantity(&self.block_number, "receipt block number")?,
            block_hash: self.block_hash,
            transaction_index: u32::try_from(quantity(
                &self.transaction_index,
                "receipt transaction index",
            )?)
            .map_err(|_| CanonicalError::new("receipt transaction index exceeds u32"))?,
            success: quantity(&self.status, "receipt status")? == 1,
            logs,
        })
    }
}

/// Exact, hash-fenced execution reads for the stopped observer. Numeric ranges are exposed only
/// by `discovery_logs`; all authority-bearing logs must be re-read with `logs_at_hash`.
#[derive(Clone, Debug)]
pub struct CanonicalExecutionClient {
    rpc: CanonicalRpcClient,
}

impl CanonicalExecutionClient {
    pub fn new(endpoint: impl Into<String>) -> CanonicalResult<Self> {
        Ok(Self {
            rpc: CanonicalRpcClient::new(endpoint)?,
        })
    }

    pub fn endpoint(&self) -> &str {
        self.rpc.endpoint()
    }

    pub async fn chain_id(
        &self,
        budget: &CanonicalMemoryBudget,
        cancellation: &CanonicalCancellation,
        deadline: tokio::time::Instant,
    ) -> CanonicalResult<u64> {
        let result: ReservedValue<String> = self
            .rpc
            .request_typed(
                "eth_chainId",
                serde_json::json!([]),
                budget,
                cancellation,
                deadline,
            )
            .await?;
        quantity(result.value(), "chain id")
    }

    pub async fn header_by_tag(
        &self,
        tag: &'static str,
        budget: &CanonicalMemoryBudget,
        cancellation: &CanonicalCancellation,
        deadline: tokio::time::Instant,
    ) -> CanonicalResult<ReservedValue<CanonicalExecutionHeader>> {
        let result: ReservedValue<Option<RawExecutionHeader>> = self
            .rpc
            .request_typed(
                "eth_getBlockByNumber",
                serde_json::json!([tag, false]),
                budget,
                cancellation,
                deadline,
            )
            .await?;
        result.try_map(|header| {
            header
                .ok_or_else(|| CanonicalError::new(format!("{tag} block is unavailable")))?
                .checked()
        })
    }

    pub async fn header_by_number(
        &self,
        number: u64,
        budget: &CanonicalMemoryBudget,
        cancellation: &CanonicalCancellation,
        deadline: tokio::time::Instant,
    ) -> CanonicalResult<ReservedValue<CanonicalExecutionHeader>> {
        let result: ReservedValue<Option<RawExecutionHeader>> = self
            .rpc
            .request_typed(
                "eth_getBlockByNumber",
                serde_json::json!([quantity_param(number), false]),
                budget,
                cancellation,
                deadline,
            )
            .await?;
        result.try_map(|header| {
            let header = header
                .ok_or_else(|| CanonicalError::new(format!("block {number} is unavailable")))?
                .checked()?;
            if header.number != number {
                return Err(CanonicalError::new(format!(
                    "block {number} response has number {}",
                    header.number
                )));
            }
            Ok(header)
        })
    }

    async fn logs(
        &self,
        filter: serde_json::Value,
        budget: &CanonicalMemoryBudget,
        cancellation: &CanonicalCancellation,
        deadline: tokio::time::Instant,
    ) -> CanonicalResult<ReservedValue<Vec<CanonicalExecutionLog>>> {
        let result: ReservedValue<Vec<RawExecutionLog>> = self
            .rpc
            .request_typed(
                "eth_getLogs",
                serde_json::json!([filter]),
                budget,
                cancellation,
                deadline,
            )
            .await?;
        result.try_map(|logs| {
            let mut per_block = std::collections::BTreeMap::<u64, (B256, usize)>::new();
            let mut checked = Vec::with_capacity(logs.len());
            for log in logs {
                let log = log.checked()?;
                let (block_hash, count) = per_block
                    .entry(log.block_number)
                    .or_insert((log.block_hash, 0));
                if *block_hash != log.block_hash {
                    return Err(CanonicalError::new(
                        "execution log result has two hashes for one block number",
                    ));
                }
                *count = count
                    .checked_add(1)
                    .ok_or_else(|| CanonicalError::new("execution per-block log count overflow"))?;
                if *count > MAX_EXACT_LOGS_PER_BLOCK {
                    return Err(CanonicalError::new(
                        "execution log result exceeds 4096 entries in one block",
                    ));
                }
                checked.push(log);
            }
            Ok(checked)
        })
    }

    pub async fn logs_at_hash(
        &self,
        block_hash: B256,
        address: Address,
        topic0: B256,
        budget: &CanonicalMemoryBudget,
        cancellation: &CanonicalCancellation,
        deadline: tokio::time::Instant,
    ) -> CanonicalResult<ReservedValue<Vec<CanonicalExecutionLog>>> {
        self.logs(
            serde_json::json!({
                "blockHash": format!("{block_hash:#x}"),
                "address": format!("{address:#x}"),
                "topics": [format!("{topic0:#x}")],
            }),
            budget,
            cancellation,
            deadline,
        )
        .await?
        .try_map(|logs| {
            if logs.iter().all(|log| {
                log.block_hash == block_hash
                    && log.address == address
                    && log.topics.first() == Some(&topic0)
            }) {
                Ok(logs)
            } else {
                Err(CanonicalError::new(
                    "exact execution logs violate the requested block/emitter/topic fence",
                ))
            }
        })
    }

    pub async fn logs_at_hash_for_topic(
        &self,
        block_hash: B256,
        topic0: B256,
        budget: &CanonicalMemoryBudget,
        cancellation: &CanonicalCancellation,
        deadline: tokio::time::Instant,
    ) -> CanonicalResult<ReservedValue<Vec<CanonicalExecutionLog>>> {
        self.logs(
            serde_json::json!({
                "blockHash": format!("{block_hash:#x}"),
                "topics": [format!("{topic0:#x}")],
            }),
            budget,
            cancellation,
            deadline,
        )
        .await?
        .try_map(|logs| {
            if logs
                .iter()
                .all(|log| log.block_hash == block_hash && log.topics.first() == Some(&topic0))
            {
                Ok(logs)
            } else {
                Err(CanonicalError::new(
                    "exact execution logs violate the requested block/topic fence",
                ))
            }
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn discovery_logs(
        &self,
        from: u64,
        to: u64,
        address: Address,
        topic0: B256,
        budget: &CanonicalMemoryBudget,
        cancellation: &CanonicalCancellation,
        deadline: tokio::time::Instant,
    ) -> CanonicalResult<ReservedValue<Vec<CanonicalExecutionLog>>> {
        if from > to || to - from > MAX_SAFE_TO_CONTAINING_L1_GAP {
            return Err(CanonicalError::new(
                "numeric discovery range exceeds safe-to-containing bound",
            ));
        }
        self.logs(
            serde_json::json!({
                "fromBlock": quantity_param(from),
                "toBlock": quantity_param(to),
                "address": format!("{address:#x}"),
                "topics": [format!("{topic0:#x}")],
            }),
            budget,
            cancellation,
            deadline,
        )
        .await?
        .try_map(|logs| {
            if logs.iter().all(|log| {
                (from..=to).contains(&log.block_number)
                    && log.address == address
                    && log.topics.first() == Some(&topic0)
            }) {
                Ok(logs)
            } else {
                Err(CanonicalError::new(
                    "discovery logs violate the requested range/emitter/topic fence",
                ))
            }
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn dependency_discovery_logs(
        &self,
        from: u64,
        to: u64,
        address: Option<Address>,
        topic0: B256,
        budget: &CanonicalMemoryBudget,
        cancellation: &CanonicalCancellation,
        deadline: tokio::time::Instant,
    ) -> CanonicalResult<ReservedValue<Vec<CanonicalExecutionLog>>> {
        if from > to || to - from >= MAX_DEPENDENCY_CLOSURE_L1_SPAN {
            return Err(CanonicalError::new(
                "numeric dependency discovery exceeds 8192 blocks",
            ));
        }
        let mut filter = serde_json::json!({
            "fromBlock": quantity_param(from),
            "toBlock": quantity_param(to),
            "topics": [format!("{topic0:#x}")],
        });
        if let Some(address) = address {
            filter["address"] = serde_json::Value::String(format!("{address:#x}"));
        }
        self.logs(filter, budget, cancellation, deadline)
            .await?
            .try_map(|logs| {
                if logs.iter().all(|log| {
                    (from..=to).contains(&log.block_number)
                        && address.is_none_or(|address| log.address == address)
                        && log.topics.first() == Some(&topic0)
                }) {
                    Ok(logs)
                } else {
                    Err(CanonicalError::new(
                        "dependency logs violate the requested range/emitter/topic fence",
                    ))
                }
            })
    }

    pub async fn transaction(
        &self,
        hash: B256,
        budget: &CanonicalMemoryBudget,
        cancellation: &CanonicalCancellation,
        deadline: tokio::time::Instant,
    ) -> CanonicalResult<ReservedValue<CanonicalExecutionTransaction>> {
        let result: ReservedValue<Option<RawExecutionTransaction>> = self
            .rpc
            .request_typed(
                "eth_getTransactionByHash",
                serde_json::json!([format!("{hash:#x}")]),
                budget,
                cancellation,
                deadline,
            )
            .await?;
        result.try_map(|transaction| {
            let transaction = transaction
                .ok_or_else(|| CanonicalError::new("posting transaction is unavailable"))?
                .checked()?;
            if transaction.hash != hash {
                return Err(CanonicalError::new("posting transaction hash mismatch"));
            }
            Ok(transaction)
        })
    }

    pub async fn receipt(
        &self,
        hash: B256,
        budget: &CanonicalMemoryBudget,
        cancellation: &CanonicalCancellation,
        deadline: tokio::time::Instant,
    ) -> CanonicalResult<ReservedValue<CanonicalExecutionReceipt>> {
        let result: ReservedValue<Option<RawExecutionReceipt>> = self
            .rpc
            .request_typed(
                "eth_getTransactionReceipt",
                serde_json::json!([format!("{hash:#x}")]),
                budget,
                cancellation,
                deadline,
            )
            .await?;
        result.try_map(|receipt| {
            let receipt = receipt
                .ok_or_else(|| CanonicalError::new("posting receipt is unavailable"))?
                .checked()?;
            if receipt.transaction_hash != hash {
                return Err(CanonicalError::new(
                    "posting receipt transaction hash mismatch",
                ));
            }
            Ok(receipt)
        })
    }

    pub async fn call_at_hash(
        &self,
        to: Address,
        data: Bytes,
        block_hash: B256,
        budget: &CanonicalMemoryBudget,
        cancellation: &CanonicalCancellation,
        deadline: tokio::time::Instant,
    ) -> CanonicalResult<B256> {
        let result: ReservedValue<Bytes> = self
            .rpc
            .request_typed(
                "eth_call",
                serde_json::json!([
                    {"to": format!("{to:#x}"), "data": format!("{data}")},
                    {"blockHash": format!("{block_hash:#x}"), "requireCanonical": true}
                ]),
                budget,
                cancellation,
                deadline,
            )
            .await?;
        if result.value().len() != 32 {
            return Err(CanonicalError::new(
                "exact-safe state call did not return one bytes32",
            ));
        }
        Ok(B256::from_slice(result.value()))
    }
}

#[derive(serde::Deserialize)]
struct RawCanonicalBeaconResponse {
    data: Vec<RawCanonicalBeaconSidecar>,
}

#[derive(serde::Deserialize)]
struct RawCanonicalBeaconSidecar {
    blob: String,
    index: String,
    kzg_commitment: String,
    kzg_proof: String,
    signed_block_header: RawCanonicalSignedHeader,
}

#[derive(serde::Deserialize)]
struct RawCanonicalSignedHeader {
    message: RawCanonicalBeaconHeader,
}

#[derive(serde::Deserialize)]
struct RawCanonicalBeaconHeader {
    slot: String,
}

/// Redirect-free, bounded beacon client used only for reconstructed recent blob sidecars.
#[derive(Clone, Debug)]
pub struct CanonicalBeaconClient {
    base: String,
    http: reqwest::Client,
}

impl CanonicalBeaconClient {
    pub fn new(base: impl Into<String>) -> CanonicalResult<Self> {
        let base = base.into().trim_end_matches('/').to_owned();
        let parsed = reqwest::Url::parse(&base).map_err(|error| {
            CanonicalError::new(format!("invalid canonical beacon URL: {error}"))
        })?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(CanonicalError::new(
                "canonical beacon URL must use http or https",
            ));
        }
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| {
                CanonicalError::new(format!("build canonical beacon client: {error}"))
            })?;
        Ok(Self { base, http })
    }

    pub fn endpoint(&self) -> &str {
        &self.base
    }

    pub async fn sidecars(
        &self,
        slot: u64,
        budget: &CanonicalMemoryBudget,
        cancellation: &CanonicalCancellation,
        deadline: tokio::time::Instant,
    ) -> CanonicalResult<ReservedValue<Vec<CanonicalBlobSidecar>>> {
        let mut body_charge = budget
            .reserve(MEMORY_PERMIT_QUANTUM * 2, deadline, cancellation)
            .await?;
        let parsed = budget
            .reserve(MAX_RPC_DECODED_BODY_BYTES, deadline, cancellation)
            .await?;
        let url = format!("{}/eth/v1/beacon/blob_sidecars/{slot}", self.base);
        let response = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                return Err(CanonicalError::new("canonical observation was cancelled"));
            },
            response = tokio::time::timeout_at(deadline, self.http.get(url).send()) => response
                .map_err(|_| CanonicalError::new("beacon sidecars missed attempt deadline"))?
                .map_err(|error| CanonicalError::new(format!("beacon sidecars transport: {error}")))?,
        };
        if !response.status().is_success() {
            return Err(CanonicalError::new(format!(
                "beacon sidecars returned HTTP {}",
                response.status()
            )));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_HTTP_WIRE_BODY_BYTES as u64)
        {
            return Err(CanonicalError::new("beacon HTTP body exceeds 32 MiB"));
        }
        let mut response = response;
        let mut body = Vec::new();
        while let Some(chunk) = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                return Err(CanonicalError::new("canonical observation was cancelled"));
            },
            chunk = tokio::time::timeout_at(deadline, response.chunk()) => chunk
                .map_err(|_| CanonicalError::new("beacon body missed attempt deadline"))?
                .map_err(|error| CanonicalError::new(format!("beacon response body: {error}")))?,
        } {
            cancellation.check()?;
            let next = body
                .len()
                .checked_add(chunk.len())
                .ok_or_else(|| CanonicalError::new("beacon body length overflow"))?;
            if next > MAX_HTTP_WIRE_BODY_BYTES {
                return Err(CanonicalError::new("beacon HTTP body exceeds 32 MiB"));
            }
            let required = next
                .checked_mul(2)
                .ok_or_else(|| CanonicalError::new("beacon HTTP liability overflow"))?
                .max(MEMORY_PERMIT_QUANTUM * 2);
            let charged = body_charge.charged_bytes();
            if required > charged {
                body_charge = body_charge.merge(
                    budget
                        .reserve(required - charged, deadline, cancellation)
                        .await?,
                )?;
            }
            body.try_reserve_exact(chunk.len())
                .map_err(|_| CanonicalError::new("beacon HTTP body allocation failed"))?;
            body.extend_from_slice(&chunk);
        }
        let raw: RawCanonicalBeaconResponse = parse_json(&body, cancellation, deadline)?;
        drop(body);
        drop(body_charge);
        if raw.data.len() > MAX_BLOBS_PER_POSTING_TRANSACTION {
            return Err(CanonicalError::new(
                "beacon sidecar result exceeds 16 entries",
            ));
        }
        let converted = budget
            .reserve(
                MAX_BLOBS_PER_POSTING_TRANSACTION
                    .checked_mul(BYTES_PER_BLOB + std::mem::size_of::<CanonicalBlobSidecar>())
                    .ok_or_else(|| CanonicalError::new("beacon conversion liability overflow"))?,
                deadline,
                cancellation,
            )
            .await?;
        let mut sidecars = Vec::with_capacity(raw.data.len());
        for raw in raw.data {
            cancellation.check()?;
            let sidecar_slot = raw
                .signed_block_header
                .message
                .slot
                .parse::<u64>()
                .map_err(|error| CanonicalError::new(format!("invalid beacon slot: {error}")))?;
            if sidecar_slot != slot {
                return Err(CanonicalError::new("beacon sidecar slot mismatch"));
            }
            raw.index
                .parse::<u64>()
                .map_err(|error| CanonicalError::new(format!("invalid sidecar index: {error}")))?;
            let blob = alloy_primitives::hex::decode(raw.blob)
                .map_err(|error| CanonicalError::new(format!("invalid sidecar blob: {error}")))?;
            let commitment =
                alloy_primitives::hex::decode(raw.kzg_commitment).map_err(|error| {
                    CanonicalError::new(format!("invalid sidecar commitment: {error}"))
                })?;
            let proof = alloy_primitives::hex::decode(raw.kzg_proof)
                .map_err(|error| CanonicalError::new(format!("invalid sidecar proof: {error}")))?;
            sidecars.push(CanonicalBlobSidecar {
                blob: Box::new(blob.try_into().map_err(|value: Vec<u8>| {
                    CanonicalError::new(format!(
                        "sidecar blob length {} is not {BYTES_PER_BLOB}",
                        value.len()
                    ))
                })?),
                commitment: commitment.try_into().map_err(|value: Vec<u8>| {
                    CanonicalError::new(format!(
                        "sidecar commitment length {} is not 48",
                        value.len()
                    ))
                })?,
                proof: proof.try_into().map_err(|value: Vec<u8>| {
                    CanonicalError::new(format!("sidecar proof length {} is not 48", value.len()))
                })?,
            });
        }
        let retained_bytes = sidecars
            .len()
            .checked_mul(BYTES_PER_BLOB + std::mem::size_of::<CanonicalBlobSidecar>())
            .ok_or_else(|| CanonicalError::new("beacon sidecar liability overflow"))?
            .max(1);
        drop(parsed);
        Ok(ReservedValue {
            value: sidecars,
            _liability: converted.retain_bytes(retained_bytes)?,
        })
    }
}

/// Cooperative cancellation checked by every observer streaming/parser loop.
#[derive(Clone, Debug, Default)]
pub struct CanonicalCancellation {
    cancelled: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl CanonicalCancellation {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub fn check(&self) -> CanonicalResult<()> {
        if self.is_cancelled() {
            return Err(CanonicalError::new("canonical observation was cancelled"));
        }
        Ok(())
    }

    pub async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        let notified = self.notify.notified();
        if self.is_cancelled() {
            return;
        }
        notified.await;
    }
}

/// The one authoritative 480-MiB weighted budget. The non-allocatable 32-MiB reserve is not
/// represented by permits and therefore cannot accidentally be consumed by provider objects.
#[derive(Clone, Debug)]
pub struct CanonicalMemoryBudget {
    semaphore: Arc<Semaphore>,
}

impl Default for CanonicalMemoryBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl CanonicalMemoryBudget {
    pub fn new() -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(DYNAMIC_PERMIT_COUNT)),
        }
    }

    pub fn available_bytes(&self) -> usize {
        self.semaphore.available_permits() * MEMORY_PERMIT_QUANTUM
    }

    pub async fn reserve(
        &self,
        bytes: usize,
        deadline: tokio::time::Instant,
        cancellation: &CanonicalCancellation,
    ) -> CanonicalResult<CanonicalMemoryReservation> {
        let permits = permits_for(bytes)?;
        cancellation.check()?;
        let permit_count = u32::try_from(permits)
            .map_err(|_| CanonicalError::new("memory permit count overflow"))?;
        let acquire = self.semaphore.clone().acquire_many_owned(permit_count);
        let permit = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                return Err(CanonicalError::new("canonical observation was cancelled"));
            },
            result = tokio::time::timeout_at(deadline, acquire) => {
                result
                    .map_err(|_| CanonicalError::new("canonical memory reservation missed attempt deadline"))?
                    .map_err(|_| CanonicalError::new("canonical memory budget is closed"))?
            }
        };
        Ok(CanonicalMemoryReservation {
            charged_bytes: permits * MEMORY_PERMIT_QUANTUM,
            permit,
        })
    }
}

/// A transferable aggregate-memory liability token. Queued/owned representations carry this
/// value with them; dropping the old representation is what releases its permits.
#[derive(Debug)]
pub struct CanonicalMemoryReservation {
    charged_bytes: usize,
    permit: OwnedSemaphorePermit,
}

impl CanonicalMemoryReservation {
    pub fn charged_bytes(&self) -> usize {
        self.charged_bytes
    }

    pub fn merge(mut self, other: Self) -> CanonicalResult<Self> {
        self.charged_bytes = self
            .charged_bytes
            .checked_add(other.charged_bytes)
            .ok_or_else(|| CanonicalError::new("aggregate memory liability overflow"))?;
        self.permit.merge(other.permit);
        Ok(self)
    }

    /// Release every whole-quantum permit above one retained representation's checked liability.
    pub fn retain_bytes(mut self, bytes: usize) -> CanonicalResult<Self> {
        let retained_permits = permits_for(bytes)?;
        let current_permits = self.charged_bytes / MEMORY_PERMIT_QUANTUM;
        if retained_permits > current_permits {
            return Err(CanonicalError::new(
                "retained memory liability exceeds its existing reservation",
            ));
        }
        let released = current_permits - retained_permits;
        if released != 0 {
            drop(
                self.permit
                    .split(released)
                    .expect("released permits are within the owned reservation"),
            );
        }
        self.charged_bytes = retained_permits * MEMORY_PERMIT_QUANTUM;
        Ok(self)
    }
}

fn permits_for(bytes: usize) -> CanonicalResult<usize> {
    let rounded = bytes
        .checked_add(MEMORY_PERMIT_QUANTUM - 1)
        .ok_or_else(|| CanonicalError::new("memory reservation size overflow"))?;
    let permits = rounded / MEMORY_PERMIT_QUANTUM;
    if permits > DYNAMIC_PERMIT_COUNT {
        return Err(CanonicalError::new(
            "single memory reservation exceeds the 480-MiB dynamic budget",
        ));
    }
    Ok(permits)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservationDeadlines {
    pub start: tokio::time::Instant,
    pub work: tokio::time::Instant,
    pub total: tokio::time::Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryDisposition {
    Attempt {
        number: usize,
        deadline: tokio::time::Instant,
    },
    WorkWindowExhausted,
    AttemptsExhausted,
}

impl ObservationDeadlines {
    pub fn starting_at(start: tokio::time::Instant) -> Self {
        Self {
            start,
            work: start + PROVIDER_WORK_TIME,
            total: start + OBSERVER_TOTAL_TIME,
        }
    }

    pub fn start_attempt(
        self,
        completed_attempts: usize,
        now: tokio::time::Instant,
    ) -> RetryDisposition {
        if completed_attempts >= MAX_TRANSIENT_ATTEMPTS {
            return RetryDisposition::AttemptsExhausted;
        }
        if self.work.saturating_duration_since(now) < MIN_NEW_ATTEMPT_TIME {
            return RetryDisposition::WorkWindowExhausted;
        }
        RetryDisposition::Attempt {
            number: completed_attempts + 1,
            deadline: (now + OBSERVATION_ATTEMPT_TIME).min(self.work),
        }
    }

    pub fn backoff_after(self, attempt_number: usize) -> Option<Duration> {
        RETRY_BACKOFFS.get(attempt_number.checked_sub(1)?).copied()
    }
}

/// Exact SequencerInbox accumulator step over Nitro's serialized source bytes.
pub fn sequencer_accumulator(batch: &DeliveredBatch) -> B256 {
    let data_hash = keccak256(serialize_batch(batch));
    keccak256(
        [
            batch.before_acc.as_slice(),
            data_hash.as_slice(),
            batch.event.delayed_acc.as_slice(),
        ]
        .concat(),
    )
}

/// One reconstructed beacon sidecar. `proof` is retained only so tests prove that a placeholder
/// cannot authorize: production validation deliberately never reads it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalBlobSidecar {
    pub blob: Box<[u8; BYTES_PER_BLOB]>,
    pub commitment: [u8; 48],
    pub proof: [u8; 48],
}

/// Recompute each commitment in a killable helper, then bind it to the sidecar and signed posting
/// transaction in exact order. Provider proof bytes are ignored and cannot affect the result.
pub fn validate_ordered_blob_commitments(
    transaction_versioned_hashes: &[B256],
    sidecars: &[CanonicalBlobSidecar],
    mut commitment: impl FnMut(&[u8; BYTES_PER_BLOB]) -> CanonicalResult<[u8; 48]>,
) -> CanonicalResult<()> {
    if transaction_versioned_hashes.is_empty()
        || transaction_versioned_hashes.len() > MAX_BLOBS_PER_POSTING_TRANSACTION
    {
        return Err(CanonicalError::new(
            "posting transaction blob count is outside 1..=16",
        ));
    }
    if sidecars.len() != transaction_versioned_hashes.len() {
        return Err(CanonicalError::new(
            "sidecar count differs from posting transaction blob count",
        ));
    }
    for (index, (expected_hash, sidecar)) in transaction_versioned_hashes
        .iter()
        .zip(sidecars)
        .enumerate()
    {
        let local = commitment(&sidecar.blob)?;
        if local != sidecar.commitment {
            return Err(CanonicalError::new(format!(
                "local KZG commitment differs from sidecar at transaction blob index {index}"
            )));
        }
        if kzg_to_versioned_hash(&local) != *expected_hash {
            return Err(CanonicalError::new(format!(
                "local KZG commitment differs from signed transaction versioned hash at index {index}"
            )));
        }
    }
    Ok(())
}

/// Decode already commitment-bound blobs into the exact Nitro batch payload.
pub fn decode_canonical_blob_payload(
    sidecars: &[CanonicalBlobSidecar],
) -> CanonicalResult<Vec<u8>> {
    let blobs = sidecars
        .iter()
        .map(|sidecar| *sidecar.blob)
        .collect::<Vec<_>>();
    let payload = arb_reth_derive::blob::decode_blobs(&blobs)
        .map_err(|error| CanonicalError::new(format!("decode canonical blobs: {error:?}")))?;
    if payload.len() > MAX_RESOLVED_BATCH_PAYLOAD_BYTES {
        return Err(CanonicalError::new("resolved blob payload exceeds 16 MiB"));
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, b256};
    use std::{
        io::{Read as _, Write as _},
        net::TcpListener,
        sync::mpsc,
    };

    #[test]
    fn incremental_json_checks_deadline_and_cancellation_inside_large_strings() {
        let body = serde_json::to_vec(&"x".repeat(MAX_HTTP_WIRE_BODY_BYTES - 2)).unwrap();
        let cancellation = CanonicalCancellation::default();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(1);
        let error = parse_json::<String>(&body, &cancellation, deadline).unwrap_err();
        assert!(error.to_string().contains("cancelled or expired"));
        cancellation.cancel();
        assert!(
            parse_json::<String>(
                b"\"valid\"",
                &cancellation,
                tokio::time::Instant::now() + Duration::from_secs(1)
            )
            .is_err()
        );
        let fresh = CanonicalCancellation::default();
        let text = "é\\\"".repeat(MEMORY_PERMIT_QUANTUM);
        let encoded = serde_json::to_vec(&text).unwrap();
        assert_eq!(
            parse_json::<String>(
                &encoded,
                &fresh,
                tokio::time::Instant::now() + Duration::from_secs(5)
            )
            .unwrap(),
            text
        );
        assert!(
            parse_json::<serde_json::Value>(
                b"{} trailing",
                &fresh,
                tokio::time::Instant::now() + Duration::from_secs(5)
            )
            .is_err()
        );
    }

    fn serve_once(
        status: &str,
        response_headers: &str,
        body: &str,
    ) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = mpsc::channel();
        let status = status.to_owned();
        let response_headers = response_headers.to_owned();
        let body = body.to_owned();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 4096];
            let header_end = loop {
                let read = stream.read(&mut chunk).unwrap();
                assert_ne!(read, 0);
                request.extend_from_slice(&chunk[..read]);
                if let Some(index) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    break index + 4;
                }
            };
            let headers = std::str::from_utf8(&request[..header_end]).unwrap();
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            while request.len() - header_end < content_length {
                let read = stream.read(&mut chunk).unwrap();
                assert_ne!(read, 0);
                request.extend_from_slice(&chunk[..read]);
            }
            sender.send(String::from_utf8(request).unwrap()).unwrap();
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{response_headers}\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        (format!("http://{address}"), receiver)
    }

    #[tokio::test]
    async fn aggregate_memory_rounding_transfer_dual_representation_and_cancel() {
        let budget = CanonicalMemoryBudget::new();
        let cancel = CanonicalCancellation::default();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let one = budget.reserve(1, deadline, &cancel).await.unwrap();
        assert_eq!(one.charged_bytes(), MEMORY_PERMIT_QUANTUM);
        let old = budget
            .reserve(
                OBSERVER_DYNAMIC_MEMORY_BYTES - MEMORY_PERMIT_QUANTUM,
                deadline,
                &cancel,
            )
            .await
            .unwrap();
        assert_eq!(
            budget.available_bytes(),
            0,
            "old and new representations retain both charges"
        );
        drop(old);
        let transferred = one;
        assert_eq!(transferred.charged_bytes(), MEMORY_PERMIT_QUANTUM);
        drop(transferred);
        assert_eq!(budget.available_bytes(), OBSERVER_DYNAMIC_MEMORY_BYTES);
        assert!(budget.reserve(usize::MAX, deadline, &cancel).await.is_err());

        let all = budget
            .reserve(OBSERVER_DYNAMIC_MEMORY_BYTES, deadline, &cancel)
            .await
            .unwrap();
        let waiting = {
            let budget = budget.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                budget
                    .reserve(
                        1,
                        tokio::time::Instant::now() + Duration::from_secs(60),
                        &cancel,
                    )
                    .await
            })
        };
        tokio::task::yield_now().await;
        cancel.cancel();
        assert!(waiting.await.unwrap().is_err());
        drop(all);
    }

    #[tokio::test]
    async fn localhost_provider_rejects_redirects_and_wrong_numeric_identity() {
        let (endpoint, request) = serve_once(
            "302 Found",
            "Location: http://127.0.0.1:1/\r\n",
            "redirect rejected",
        );
        let client = CanonicalRpcClient::new(endpoint).unwrap();
        let budget = CanonicalMemoryBudget::new();
        let cancel = CanonicalCancellation::default();
        assert!(
            client
                .request_typed::<serde_json::Value>(
                    "eth_chainId",
                    serde_json::json!([]),
                    &budget,
                    &cancel,
                    tokio::time::Instant::now() + Duration::from_secs(2),
                )
                .await
                .unwrap_err()
                .to_string()
                .contains("HTTP 302")
        );
        assert!(request.recv().unwrap().contains("eth_chainId"));

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "number": "0x8",
                "hash": format!("{:#x}", b256!("1111111111111111111111111111111111111111111111111111111111111111")),
                "parentHash": format!("{:#x}", b256!("2222222222222222222222222222222222222222222222222222222222222222")),
                "timestamp": "0x9"
            }
        })
        .to_string();
        let (endpoint, request) = serve_once("200 OK", "", &body);
        let execution = CanonicalExecutionClient::new(endpoint).unwrap();
        assert!(
            execution
                .header_by_number(
                    7,
                    &budget,
                    &cancel,
                    tokio::time::Instant::now() + Duration::from_secs(2),
                )
                .await
                .unwrap_err()
                .to_string()
                .contains("response has number 8")
        );
        let request = request.recv().unwrap();
        assert!(request.contains("eth_getBlockByNumber"));
        let request: serde_json::Value =
            serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(request["params"], serde_json::json!(["0x7", false]));
    }

    #[tokio::test]
    async fn localhost_provider_uses_eip_1898_and_strict_typed_fields() {
        let call_hash = b256!("3333333333333333333333333333333333333333333333333333333333333333");
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": format!("0x{}", "44".repeat(32)),
        })
        .to_string();
        let (endpoint, request) = serve_once("200 OK", "", &body);
        let execution = CanonicalExecutionClient::new(endpoint).unwrap();
        let budget = CanonicalMemoryBudget::new();
        let cancel = CanonicalCancellation::default();
        assert_eq!(
            execution
                .call_at_hash(
                    address!("1111111111111111111111111111111111111111"),
                    Bytes::from_static(&[0xaa, 0xbb]),
                    call_hash,
                    &budget,
                    &cancel,
                    tokio::time::Instant::now() + Duration::from_secs(2),
                )
                .await
                .unwrap(),
            b256!("4444444444444444444444444444444444444444444444444444444444444444")
        );
        let request = request.recv().unwrap();
        assert!(request.contains("eth_call"));
        let request: serde_json::Value =
            serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(
            request["params"][1],
            serde_json::json!({
                "blockHash": format!("{call_hash:#x}"),
                "requireCanonical": true,
            })
        );

        assert!(quantity("0x00", "test").is_err());
        assert!(quantity("7", "test").is_err());
        let removed: RawExecutionLog = serde_json::from_value(serde_json::json!({
            "address": "0x1111111111111111111111111111111111111111",
            "topics": [],
            "data": "0x",
            "blockNumber": "0x1",
            "blockHash": format!("{call_hash:#x}"),
            "transactionHash": format!("{call_hash:#x}"),
            "transactionIndex": "0x0",
            "logIndex": "0x0",
            "removed": true,
        }))
        .unwrap();
        assert!(removed.checked().is_err());
    }

    #[test]
    fn exact_attempt_work_cleanup_schedule() {
        let start = tokio::time::Instant::now();
        let deadlines = ObservationDeadlines::starting_at(start);
        assert_eq!(deadlines.work - start, Duration::from_secs(285));
        assert_eq!(deadlines.total - deadlines.work, Duration::from_secs(15));
        assert_eq!(deadlines.total - start, Duration::from_secs(300));
        assert_eq!(
            deadlines.start_attempt(0, start),
            RetryDisposition::Attempt {
                number: 1,
                deadline: start + Duration::from_secs(120)
            }
        );
        assert_eq!(deadlines.backoff_after(1), Some(Duration::from_secs(1)));
        assert_eq!(deadlines.backoff_after(2), Some(Duration::from_secs(2)));
        assert_eq!(deadlines.backoff_after(3), None);
        assert_eq!(
            deadlines.start_attempt(2, start + Duration::from_secs(280)),
            RetryDisposition::Attempt {
                number: 3,
                deadline: deadlines.work,
            }
        );
        assert_eq!(
            deadlines.start_attempt(2, start + Duration::from_secs(281)),
            RetryDisposition::WorkWindowExhausted
        );
        assert_eq!(
            deadlines.start_attempt(3, start),
            RetryDisposition::AttemptsExhausted
        );
        assert_eq!(OBSERVER_DEADLINE_EXIT_CODE, 74);
    }

    #[tokio::test(start_paused = true)]
    async fn paused_time_cancellation_joins_inside_cleanup_window() {
        let start = tokio::time::Instant::now();
        let deadlines = ObservationDeadlines::starting_at(start);
        let cancellation = CanonicalCancellation::default();
        let joined = {
            let cancellation = cancellation.clone();
            tokio::spawn(async move {
                cancellation.cancelled().await;
                tokio::task::yield_now().await;
                17
            })
        };
        tokio::time::advance(PROVIDER_WORK_TIME).await;
        assert_eq!(tokio::time::Instant::now(), deadlines.work);
        cancellation.cancel();
        assert_eq!(
            tokio::time::timeout_at(deadlines.total, joined)
                .await
                .unwrap()
                .unwrap(),
            17
        );
        assert!(tokio::time::Instant::now() < deadlines.total);
    }

    #[test]
    fn blob_order_and_commitment_bind_but_placeholder_proof_does_not_authorize() {
        let commitments = [[0x11; 48], [0x22; 48]];
        let hashes = commitments.map(|value| kzg_to_versioned_hash(&value));
        let sidecars = commitments.map(|value| CanonicalBlobSidecar {
            blob: Box::new([value[0]; BYTES_PER_BLOB]),
            commitment: value,
            proof: alloy_primitives::hex!(
                "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            ),
        });
        validate_ordered_blob_commitments(&hashes, &sidecars, |blob| Ok([blob[0]; 48])).unwrap();
        let mut reordered = sidecars.clone();
        reordered.swap(0, 1);
        assert!(
            validate_ordered_blob_commitments(&hashes, &reordered, |blob| Ok([blob[0]; 48]))
                .is_err()
        );
        let mut wrong = sidecars;
        wrong[0].commitment[0] ^= 1;
        assert!(
            validate_ordered_blob_commitments(&hashes, &wrong, |blob| Ok([blob[0]; 48])).is_err()
        );
        assert_eq!(
            hashes[0],
            b256!("01a127dff9f9bbfa1dff5275a99464123998e95bf11dd579f2ffcab301bc7350")
        );
    }
}
