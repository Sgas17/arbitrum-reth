use std::{
    io::Write as _,
    os::fd::AsRawFd as _,
    os::unix::process::CommandExt as _,
    process::{Command, Stdio},
};

use alloy_primitives::{B256, b256, keccak256};
use arb_reth_derive::{batch::BatchHeader, delayed::NoDelayed};
use arb_reth_l1::{
    CanonicalBlobSidecar, decode_canonical_blob_payload, decode_payload_messages,
    decode_payload_messages_cancellable, derived_to_feed_message,
};

const SETUP_DIGEST: [u8; 32] =
    alloy_primitives::hex!("d39b9f2d047cc9dca2de58f264b6a09448ccd34db967881a6713eacacf0f26b7");

fn packet_sidecars() -> (serde_json::Value, Vec<CanonicalBlobSidecar>) {
    let fixture = std::fs::read("/tmp/ITE-106B2-bootstrap-full-selected-sidecars-v1.json")
        .expect("launch-packet sidecar fixture");
    let value: serde_json::Value = serde_json::from_slice(&fixture).unwrap();
    let sidecars = value["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|sidecar| CanonicalBlobSidecar {
            blob: Box::new(
                alloy_primitives::hex::decode(sidecar["blob"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ),
            commitment: alloy_primitives::hex::decode(sidecar["kzg_commitment"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            proof: alloy_primitives::hex::decode(sidecar["kzg_proof"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        })
        .collect();
    (value, sidecars)
}

fn helper_commitment(blob: &[u8; c_kzg::BYTES_PER_BLOB]) -> Vec<u8> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_arb-reth"))
        .env("ARB_RETH_INTERNAL_KZG_COMMITMENT_HELPER", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&SETUP_DIGEST).unwrap();
    stdin.write_all(blob).unwrap();
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout.len(), 48);
    output.stdout
}

#[test]
fn exact_batch_91908_reconstructs_346_messages_and_anchor_ordinal_320() {
    let (value, sidecars) = packet_sidecars();
    let expected_hashes = [
        b256!("01fd20e3b4bf38c4af791376f4bae5973ae2fbc355a7d619fcd98486a5454ddd"),
        b256!("01dcc35762d2eafdb2cca70dfd7d280145de1f8dd87851ab86230d4faa7b42ea"),
        b256!("01ce56f918ceeac5543f8b30586f66a1460a29e92bf5ccc595386b30563592de"),
    ];
    for ((raw, sidecar), expected_hash) in value["data"]
        .as_array()
        .unwrap()
        .iter()
        .zip(&sidecars)
        .zip(expected_hashes)
    {
        assert_eq!(helper_commitment(&sidecar.blob), sidecar.commitment);
        assert_eq!(
            alloy_eips::eip4844::kzg_to_versioned_hash(&sidecar.commitment),
            expected_hash
        );
        assert_eq!(
            raw["kzg_proof"].as_str().unwrap(),
            "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "placeholder proofs are fixture data, not an authorizing input"
        );
    }

    let payload = decode_canonical_blob_payload(&sidecars).unwrap();
    assert_eq!(payload.len(), 384_442);
    assert_eq!(
        keccak256(&payload),
        b256!("baf0c248491c20a8d1439cfaee7d713b39f7d8b8a1266403e0c5affa14976d2d")
    );
    let messages = decode_payload_messages(
        &BatchHeader {
            min_timestamp: 1_785_919_823,
            max_timestamp: 1_786_269_023,
            min_l1_block: 25_687_538,
            max_l1_block: 25_716_638,
            after_delayed_messages: 111_405,
        },
        &payload,
        111_405,
        &NoDelayed,
    )
    .unwrap();
    assert_eq!(
        decode_payload_messages_cancellable(
            &BatchHeader {
                min_timestamp: 1_785_919_823,
                max_timestamp: 1_786_269_023,
                min_l1_block: 25_687_538,
                max_l1_block: 25_716_638,
                after_delayed_messages: 111_405,
            },
            &payload,
            111_405,
            &NoDelayed,
            || false,
        )
        .unwrap(),
        messages,
    );
    assert_eq!(messages.len(), 346);
    let anchor = derived_to_feed_message(&messages[320], 320);
    let expected: arbitrum_alloy_sequencer::sequencer::feed::BroadcastFeedMessage =
        serde_json::from_slice(
            &std::fs::read("/tmp/ITE-106B2-bootstrap-target-message.json").unwrap(),
        )
        .unwrap();
    assert_eq!(anchor, expected);
    assert_eq!(31_804_824 + 320, 31_805_144);
    assert_eq!(
        B256::from_slice(&SETUP_DIGEST),
        arb_reth_engine::production_canonical_context().kzg_trusted_setup_digest
    );
}

#[test]
fn helper_rejects_wrong_setup_short_input_trailing_input_and_public_arguments() {
    let binary = env!("CARGO_BIN_EXE_arb-reth");
    let mut wrong_setup = vec![0; 32 + c_kzg::BYTES_PER_BLOB];
    wrong_setup[32..].fill(1);
    let short = SETUP_DIGEST.to_vec();
    let mut trailing = SETUP_DIGEST.to_vec();
    trailing.extend_from_slice(&[0; c_kzg::BYTES_PER_BLOB]);
    trailing.push(0);
    for input in [wrong_setup, short, trailing] {
        let mut child = Command::new(binary)
            .env("ARB_RETH_INTERNAL_KZG_COMMITMENT_HELPER", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let _ = child.stdin.take().unwrap().write_all(&input);
        assert!(!child.wait().unwrap().success());
    }
    assert!(
        !Command::new(binary)
            .arg("--help")
            .env("ARB_RETH_INTERNAL_KZG_COMMITMENT_HELPER", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn helper_rejects_an_inherited_non_stdio_descriptor() {
    let inherited = std::fs::File::open("/dev/null").unwrap();
    let descriptor = inherited.as_raw_fd();
    let mut command = Command::new(env!("CARGO_BIN_EXE_arb-reth"));
    command
        .env("ARB_RETH_INTERNAL_KZG_COMMITMENT_HELPER", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Change only the child descriptor table. Changing the parent races every other spawn.
    unsafe {
        command.pre_exec(move || {
            let flags = libc::fcntl(descriptor, libc::F_GETFD);
            if flags < 0 || libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    assert!(!command.status().unwrap().success());
}
