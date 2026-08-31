use std::{
    fs::File,
    hint::black_box,
    io::Write as _,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

use alloy_primitives::{B256, keccak256};
use arbitrum_alloy_sequencer::sequencer::feed::BroadcastFeedMessage;
use serde::Serialize;

use arb_reth_engine::{
    ArbEngineInput, ArbEngineInputSource, JournalBenchmarkAdapter, MessageJournalEntry,
    fingerprint_message,
};

const WARMUP_MESSAGES: usize = 10_000;
const MEASURED_MESSAGES: usize = 100_000;
const REPEATS: usize = 5;
const BASELINE_COMMIT: &str = "ab1ab20c5d8245ca0cbc4d89fe2117c5fce00924";
const BASELINE_TREE: &str = "215dabf36cbfe93d4276682dc7e31ab4bff88f36";
const CORPUS_SHA256: &str = "fbe357e36740581eb8231da98bb23c864aa784b1cb687732028ec417999fe791";
const CORPUS: &[u8] = include_bytes!("../tests/fixtures/ite106a-benchmark-corpus-v1.json");
const CORPUS_MANIFEST: &str = include_str!("../tests/fixtures/ite106a-benchmark-corpus-v1.sha256");
const ADAPTER_SOURCE: &[u8] = include_bytes!("../src/message_journal.rs");
const JOURNAL_STORAGE_ROOT: &str = "/dev/shm";

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Pressure {
    Idle,
    Maximum,
}

#[derive(Serialize)]
struct Percentiles {
    p50: u64,
    p95: u64,
    p99: u64,
    p99_9: u64,
}

#[derive(Serialize)]
struct StageSamples {
    raw_nanoseconds: Vec<u64>,
    nearest_rank: Percentiles,
}

#[derive(Serialize)]
struct Run {
    pressure: Pressure,
    repeat: usize,
    fingerprint: StageSamples,
    reserve_and_enqueue: StageSamples,
}

#[derive(Serialize)]
struct Provenance {
    schema: &'static str,
    compiler: String,
    required_cargo_invocation: &'static str,
    release_asserted: bool,
    baseline_commit: &'static str,
    baseline_tree: &'static str,
    candidate_commit: String,
    candidate_tree: String,
    checkout_dirty: bool,
    adapter_source_keccak256: B256,
    corpus_sha256: &'static str,
    corpus_manifest: &'static str,
    warmup_messages: usize,
    measured_messages: usize,
    repeats: usize,
    persistence_tuning: &'static str,
    journal_storage: &'static str,
    stage_clock_boundaries: [&'static str; 2],
    pressure_generator: &'static str,
    host: String,
    kernel: String,
    cpu_affinity: String,
    governor: String,
    rustflags: String,
}

#[derive(Serialize)]
struct Output {
    provenance: Provenance,
    runs: Vec<Run>,
}

fn nearest_rank(sorted: &[u64], numerator: usize, denominator: usize) -> u64 {
    assert!(!sorted.is_empty());
    let rank = sorted
        .len()
        .saturating_mul(numerator)
        .div_ceil(denominator)
        .clamp(1, sorted.len());
    sorted[rank - 1]
}

fn summarize(raw_nanoseconds: Vec<u64>) -> StageSamples {
    let mut sorted = raw_nanoseconds.clone();
    sorted.sort_unstable();
    StageSamples {
        nearest_rank: Percentiles {
            p50: nearest_rank(&sorted, 50, 100),
            p95: nearest_rank(&sorted, 95, 100),
            p99: nearest_rank(&sorted, 99, 100),
            p99_9: nearest_rank(&sorted, 999, 1_000),
        },
        raw_nanoseconds,
    }
}

async fn run_once(pressure: Pressure, repeat: usize) -> eyre::Result<Run> {
    let directory = tempfile::Builder::new()
        .prefix("ite106b1-benchmark-")
        .tempdir_in(JOURNAL_STORAGE_ROOT)?;
    let journal_directory = arb_reth_engine::JournalDirectory::open(directory.path())?;
    let mut adapter =
        JournalBenchmarkAdapter::new(matches!(pressure, Pressure::Maximum), journal_directory)
            .await?;
    let first_sequence = adapter.first_sequence();
    let mut parent_hash = B256::ZERO;
    let mut fingerprint = Vec::with_capacity(MEASURED_MESSAGES);
    let mut reserve_and_enqueue = Vec::with_capacity(MEASURED_MESSAGES);
    for index in 0..WARMUP_MESSAGES + MEASURED_MESSAGES {
        let sequence = first_sequence + index as u64;
        let mut message: BroadcastFeedMessage = serde_json::from_slice(black_box(CORPUS))?;
        message.sequence_number = sequence;
        let input = ArbEngineInput::feed(message, None);

        let start = Instant::now();
        let fingerprinted = fingerprint_message(black_box(input.message()))?;
        let fingerprint_ns = start.elapsed().as_nanos() as u64;

        let mut block_preimage = [0u8; 40];
        block_preimage[..8].copy_from_slice(&sequence.to_be_bytes());
        block_preimage[8..].copy_from_slice(fingerprinted.core.as_slice());
        let block_hash = keccak256(block_preimage);
        let entry = MessageJournalEntry {
            sequence,
            block_number: sequence,
            block_hash,
            parent_hash,
            delayed_messages_read: input.message().message_with_meta_data.delayed_messages_read,
            fingerprint: fingerprinted,
            source: ArbEngineInputSource::Feed,
        };
        let start = Instant::now();
        adapter.reserve_and_enqueue(entry).await?;
        let enqueue_ns = start.elapsed().as_nanos() as u64;
        adapter.persist_and_drain(entry).await?;
        parent_hash = block_hash;

        if index >= WARMUP_MESSAGES {
            fingerprint.push(fingerprint_ns);
            reserve_and_enqueue.push(enqueue_ns);
        }
    }
    drop(adapter);
    Ok(Run {
        pressure,
        repeat,
        fingerprint: summarize(fingerprint),
        reserve_and_enqueue: summarize(reserve_and_enqueue),
    })
}

fn read_trimmed(path: impl AsRef<Path>, fallback: &str) -> String {
    std::fs::read_to_string(path)
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|_| fallback.to_owned())
}

fn command_output(program: &str, arguments: &[&str]) -> String {
    Command::new(program)
        .args(arguments)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|output| !output.is_empty())
        .unwrap_or_else(|| "unavailable".to_owned())
}

fn checkout_dirty() -> bool {
    Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=normal"])
        .output()
        .map_or(true, |output| {
            !output.status.success() || !output.stdout.is_empty()
        })
}

fn parse_output() -> eyre::Result<PathBuf> {
    let mut arguments = std::env::args_os().skip(1);
    let flag = arguments.next();
    let path = arguments.next();
    eyre::ensure!(
        flag.as_deref() == Some(std::ffi::OsStr::new("--output"))
            && path.is_some()
            && arguments.next().is_none(),
        "usage: ite106b1_benchmark --output PATH"
    );
    Ok(PathBuf::from(path.unwrap()))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> eyre::Result<()> {
    eyre::ensure!(
        !cfg!(debug_assertions),
        "ITE-106B1 benchmark requires --release"
    );
    let checkout_dirty = checkout_dirty();
    eyre::ensure!(
        !checkout_dirty,
        "ITE-106B1 benchmark requires an immutable clean checkout"
    );
    let output_path = parse_output()?;
    let mut runs = Vec::with_capacity(REPEATS * 2);
    for pressure in [Pressure::Idle, Pressure::Maximum] {
        for repeat in 1..=REPEATS {
            runs.push(run_once(pressure, repeat).await?);
        }
    }
    let output = Output {
        provenance: Provenance {
            schema: "ite106b1-production-journal-v3-benchmark-v1",
            compiler: command_output("rustc", &["+1.97.1", "-Vv"]),
            required_cargo_invocation: "cargo +1.97.1 run -p arb-reth-engine --example ite106b1_benchmark --release --locked --offline -- --output PATH",
            release_asserted: !cfg!(debug_assertions),
            baseline_commit: BASELINE_COMMIT,
            baseline_tree: BASELINE_TREE,
            candidate_commit: command_output("git", &["rev-parse", "HEAD"]),
            candidate_tree: command_output("git", &["rev-parse", "HEAD^{tree}"]),
            checkout_dirty,
            adapter_source_keccak256: keccak256(ADAPTER_SOURCE),
            corpus_sha256: CORPUS_SHA256,
            corpus_manifest: CORPUS_MANIFEST,
            warmup_messages: WARMUP_MESSAGES,
            measured_messages: MEASURED_MESSAGES,
            repeats: REPEATS,
            persistence_tuning: "work_items=1024,record_liabilities=4096,outstanding_bytes=67108864,protected_execution_work=1,protected_execution_records=1,max_unjournaled_distance=1024",
            journal_storage: "/dev/shm tmpfs synthetic local storage; production worker append/sync/reread/compaction enabled",
            stage_clock_boundaries: [
                "before production fingerprint_message -> after exact fingerprint",
                "before production reserve_execution -> after production enqueue_executed acceptance",
            ],
            pressure_generator: "idle=empty production admission; maximum=production execution liabilities held at the largest count allowed by the 1024 work cap and the shrinking 110000 retained-identity bound; every measured identity traverses production append/sync/reread/ack/compaction outside the measured enqueue interval",
            host: read_trimmed("/etc/hostname", "unavailable"),
            kernel: read_trimmed("/proc/sys/kernel/osrelease", "unavailable"),
            cpu_affinity: read_trimmed("/proc/self/status", "unavailable")
                .lines()
                .find_map(|line| line.strip_prefix("Cpus_allowed_list:\t"))
                .unwrap_or("unavailable")
                .to_owned(),
            governor: read_trimmed(
                "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
                "unavailable",
            ),
            rustflags: std::env::var("RUSTFLAGS")
                .or_else(|_| std::env::var("CARGO_ENCODED_RUSTFLAGS"))
                .unwrap_or_else(|_| "unset".to_owned()),
        },
        runs,
    };
    let mut file = File::create(output_path)?;
    serde_json::to_writer(&mut file, &output)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_rank_and_frozen_harness_shape() {
        let values = (1..=1_000).collect::<Vec<_>>();
        assert_eq!(nearest_rank(&values, 50, 100), 500);
        assert_eq!(nearest_rank(&values, 95, 100), 950);
        assert_eq!(nearest_rank(&values, 99, 100), 990);
        assert_eq!(nearest_rank(&values, 999, 1_000), 999);
        assert_eq!(
            (WARMUP_MESSAGES, MEASURED_MESSAGES, REPEATS),
            (10_000, 100_000, 5)
        );
        assert_eq!(CORPUS.len(), 584);
        assert_eq!(
            CORPUS_MANIFEST,
            "fbe357e36740581eb8231da98bb23c864aa784b1cb687732028ec417999fe791  ite106a-benchmark-corpus-v1.json\n"
        );
        let message: BroadcastFeedMessage = serde_json::from_slice(CORPUS).unwrap();
        assert_eq!(message.sequence_number, 707);
    }
}
