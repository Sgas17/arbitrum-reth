use std::{
    fs::File,
    hint::black_box,
    io::Write as _,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Instant,
};

use alloy_primitives::{B256, b256, keccak256};
use arb_reth_engine::{CanonicalObservationV1, decode_production_bootstrap_observation};
use arb_reth_l1::{
    CanonicalBlobSidecar, DelayedMap, SequencerBatchDeliveredData, decode_canonical_blob_payload,
    decode_payload_messages_cancellable,
};
use serde::Serialize;

const OBSERVATION_ITERATIONS: usize = 100_000;
const DECOMPRESSION_ITERATIONS: usize = 20;
const REPEATS: usize = 5;
const SETUP_DIGEST: [u8; 32] =
    alloy_primitives::hex!("d39b9f2d047cc9dca2de58f264b6a09448ccd34db967881a6713eacacf0f26b7");
const PAYLOAD_DIGEST: B256 =
    b256!("baf0c248491c20a8d1439cfaee7d713b39f7d8b8a1266403e0c5affa14976d2d");

#[derive(Serialize)]
struct Run {
    repeat: usize,
    observation_iterations: usize,
    observation_nanoseconds: u64,
    observations_per_second: u64,
    decompression_iterations: usize,
    decompression_nanoseconds: u64,
    decompressed_payload_bytes_per_second: u64,
    decoded_messages_per_second: u64,
    kzg_nanoseconds: Vec<u64>,
    kzg_blob_bytes_per_second: Vec<u64>,
    parent_peak_rss_kib: u64,
    helper_peak_rss_kib: u64,
}

#[derive(Serialize)]
struct Provenance {
    schema: &'static str,
    compiler: String,
    candidate_commit: String,
    candidate_tree: String,
    checkout_dirty: bool,
    sidecar_fixture: String,
    sidecar_fixture_sha256: String,
    payload_bytes: usize,
    payload_keccak256: B256,
    decoded_messages: usize,
    observation_iterations: usize,
    decompression_iterations: usize,
    kzg_blobs: usize,
    repeats: usize,
}

#[derive(Serialize)]
struct Output {
    provenance: Provenance,
    runs: Vec<Run>,
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

fn sha256(path: &Path) -> eyre::Result<String> {
    use sha2::{Digest as _, Sha256};

    let bytes = std::fs::read(path)?;
    Ok(alloy_primitives::hex::encode(Sha256::digest(bytes)))
}

fn parse_arguments() -> eyre::Result<(PathBuf, PathBuf, PathBuf)> {
    let mut arguments = std::env::args_os().skip(1);
    let mut sidecars = None;
    let mut helper = None;
    let mut output = None;
    while let Some(argument) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| eyre::eyre!("missing value for {argument:?}"))?;
        match argument.to_str() {
            Some("--sidecars") => sidecars = Some(PathBuf::from(value)),
            Some("--helper") => helper = Some(PathBuf::from(value)),
            Some("--output") => output = Some(PathBuf::from(value)),
            _ => return Err(eyre::eyre!("unknown benchmark argument {argument:?}")),
        }
    }
    Ok((
        sidecars.ok_or_else(|| eyre::eyre!("--sidecars is required"))?,
        helper.ok_or_else(|| eyre::eyre!("--helper is required"))?,
        output.ok_or_else(|| eyre::eyre!("--output is required"))?,
    ))
}

fn load_sidecars(path: &Path) -> eyre::Result<Vec<CanonicalBlobSidecar>> {
    let fixture: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
    fixture["data"]
        .as_array()
        .ok_or_else(|| eyre::eyre!("sidecar fixture has no data array"))?
        .iter()
        .map(|sidecar| {
            Ok(CanonicalBlobSidecar {
                blob: Box::new(
                    alloy_primitives::hex::decode(
                        sidecar["blob"]
                            .as_str()
                            .ok_or_else(|| eyre::eyre!("sidecar blob is absent"))?,
                    )?
                    .try_into()
                    .map_err(|value: Vec<u8>| {
                        eyre::eyre!("sidecar blob length is {}", value.len())
                    })?,
                ),
                commitment: alloy_primitives::hex::decode(
                    sidecar["kzg_commitment"]
                        .as_str()
                        .ok_or_else(|| eyre::eyre!("sidecar commitment is absent"))?,
                )?
                .try_into()
                .map_err(|value: Vec<u8>| {
                    eyre::eyre!("sidecar commitment length is {}", value.len())
                })?,
                proof: alloy_primitives::hex::decode(
                    sidecar["kzg_proof"]
                        .as_str()
                        .ok_or_else(|| eyre::eyre!("sidecar proof is absent"))?,
                )?
                .try_into()
                .map_err(|value: Vec<u8>| eyre::eyre!("sidecar proof length is {}", value.len()))?,
            })
        })
        .collect()
}

fn helper_commitment(helper: &Path, blob: &[u8; c_kzg::BYTES_PER_BLOB]) -> eyre::Result<[u8; 48]> {
    let mut child = Command::new(helper)
        .env("ARB_RETH_INTERNAL_KZG_COMMITMENT_HELPER", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| eyre::eyre!("KZG helper stdin is absent"))?;
    stdin.write_all(&SETUP_DIGEST)?;
    stdin.write_all(blob)?;
    drop(stdin);
    let output = child.wait_with_output()?;
    eyre::ensure!(output.status.success(), "KZG helper failed");
    output
        .stdout
        .try_into()
        .map_err(|value: Vec<u8>| eyre::eyre!("KZG helper wrote {} bytes", value.len()))
}

fn peak_rss(who: libc::c_int) -> eyre::Result<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    let result = unsafe { libc::getrusage(who, usage.as_mut_ptr()) };
    eyre::ensure!(
        result == 0,
        "getrusage failed: {}",
        std::io::Error::last_os_error()
    );
    let usage = unsafe { usage.assume_init() };
    Ok(u64::try_from(usage.ru_maxrss)?)
}

fn rate(units: usize, nanoseconds: u64) -> u64 {
    (units as u128 * 1_000_000_000 / u128::from(nanoseconds.max(1))) as u64
}

fn main() -> eyre::Result<()> {
    eyre::ensure!(
        !cfg!(debug_assertions),
        "background benchmark requires --release"
    );
    eyre::ensure!(
        !checkout_dirty(),
        "background benchmark requires a clean checkout"
    );
    let (sidecar_path, helper, output_path) = parse_arguments()?;
    let sidecars = load_sidecars(&sidecar_path)?;
    eyre::ensure!(
        sidecars.len() == 3,
        "fixture must contain exactly three blobs"
    );
    let payload = decode_canonical_blob_payload(&sidecars)?;
    eyre::ensure!(payload.len() == 384_442 && keccak256(&payload) == PAYLOAD_DIGEST);
    let event = SequencerBatchDeliveredData {
        delayed_acc: B256::ZERO,
        after_delayed_messages_read: 111_405,
        min_timestamp: 1_785_919_823,
        max_timestamp: 1_786_269_023,
        min_l1_block: 25_687_538,
        max_l1_block: 25_716_638,
        data_location: arb_reth_l1::data_location::BLOB_HASHES,
    };
    let delayed = DelayedMap::from_messages(Vec::new());
    let decoded = decode_payload_messages_cancellable(
        &event.batch_header(),
        &payload,
        111_405,
        &delayed,
        || false,
    )?;
    eyre::ensure!(decoded.len() == 346, "fixture must decode 346 messages");
    let observation = decode_production_bootstrap_observation().encode();

    let mut runs = Vec::with_capacity(REPEATS);
    for repeat in 1..=REPEATS {
        let start = Instant::now();
        for _ in 0..OBSERVATION_ITERATIONS {
            black_box(CanonicalObservationV1::decode(black_box(&observation))?);
        }
        let observation_nanoseconds = start.elapsed().as_nanos() as u64;

        let start = Instant::now();
        for _ in 0..DECOMPRESSION_ITERATIONS {
            let messages = decode_payload_messages_cancellable(
                &event.batch_header(),
                black_box(&payload),
                111_405,
                &delayed,
                || false,
            )?;
            eyre::ensure!(messages.len() == 346);
            black_box(messages);
        }
        let decompression_nanoseconds = start.elapsed().as_nanos() as u64;

        let mut kzg_nanoseconds = Vec::with_capacity(sidecars.len());
        let mut kzg_blob_bytes_per_second = Vec::with_capacity(sidecars.len());
        for sidecar in &sidecars {
            let start = Instant::now();
            let commitment = helper_commitment(&helper, black_box(&sidecar.blob))?;
            let elapsed = start.elapsed().as_nanos() as u64;
            eyre::ensure!(commitment == sidecar.commitment);
            kzg_nanoseconds.push(elapsed);
            kzg_blob_bytes_per_second.push(rate(c_kzg::BYTES_PER_BLOB, elapsed));
        }
        runs.push(Run {
            repeat,
            observation_iterations: OBSERVATION_ITERATIONS,
            observation_nanoseconds,
            observations_per_second: rate(OBSERVATION_ITERATIONS, observation_nanoseconds),
            decompression_iterations: DECOMPRESSION_ITERATIONS,
            decompression_nanoseconds,
            decompressed_payload_bytes_per_second: rate(
                payload.len() * DECOMPRESSION_ITERATIONS,
                decompression_nanoseconds,
            ),
            decoded_messages_per_second: rate(
                decoded.len() * DECOMPRESSION_ITERATIONS,
                decompression_nanoseconds,
            ),
            kzg_nanoseconds,
            kzg_blob_bytes_per_second,
            parent_peak_rss_kib: peak_rss(libc::RUSAGE_SELF)?,
            helper_peak_rss_kib: peak_rss(libc::RUSAGE_CHILDREN)?,
        });
    }

    let output = Output {
        provenance: Provenance {
            schema: "ite106b2-offline-background-benchmark-v1",
            compiler: command_output("rustc", &["+1.97.1", "-Vv"]),
            candidate_commit: command_output("git", &["rev-parse", "HEAD"]),
            candidate_tree: command_output("git", &["rev-parse", "HEAD^{tree}"]),
            checkout_dirty: false,
            sidecar_fixture: sidecar_path.display().to_string(),
            sidecar_fixture_sha256: sha256(&sidecar_path)?,
            payload_bytes: payload.len(),
            payload_keccak256: keccak256(&payload),
            decoded_messages: decoded.len(),
            observation_iterations: OBSERVATION_ITERATIONS,
            decompression_iterations: DECOMPRESSION_ITERATIONS,
            kzg_blobs: sidecars.len(),
            repeats: REPEATS,
        },
        runs,
    };
    let mut file = File::create(output_path)?;
    serde_json::to_writer(&mut file, &output)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}
