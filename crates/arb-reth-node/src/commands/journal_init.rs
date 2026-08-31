//! One-shot trusted v3 journal plus lifecycle initialization.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use alloy_consensus::Header;
use alloy_rlp::Decodable as _;
use arb_reth_engine::{
    JournalDirectory, MessageJournalAnchor, StorageContextV3, initialize_journal_v3,
};
use clap::Parser;
use eyre::{ensure, eyre};
use reth_chainspec::EthChainSpec;
use reth_db::{ClientVersion, mdbx::DatabaseArguments, open_db_read_only};
use reth_db_api::models::StorageSettings;
use reth_node_types::NodeTypesWithDBAdapter;
use reth_provider::{
    BlockNumReader, ProviderFactory, StorageSettingsCache,
    providers::{RocksDBProvider, StaticFileProvider},
};
use reth_storage_api::HeaderProvider;
use reth_tasks::Runtime;

use crate::{
    ArbNode,
    lifecycle::LifecycleGuard,
    snapshot_trust::{load_approved_descriptor, read_completion, verify_snapshot_metadata},
};

type ArbNodeTypesWithDB = NodeTypesWithDBAdapter<ArbNode, reth_db::DatabaseEnv>;

#[derive(Debug, Parser)]
#[command(
    name = "journal-v3-init",
    about = "One-shot trusted compact-storage journal and lifecycle initialization"
)]
pub struct JournalV3InitArgs {
    /// Existing stopped datadir containing the read-only reopened store.
    #[arg(long, value_name = "PATH")]
    datadir: PathBuf,

    /// Arbitrum chain-config JSON for exact-genesis initialization.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["chain_info", "genesis_json"])]
    chain: Option<PathBuf>,

    /// Nitro chaininfo.json, paired with --genesis.
    #[arg(long = "chain-info", value_name = "PATH", requires = "genesis_json")]
    chain_info: Option<PathBuf>,

    /// Nitro genesis.json, paired with --chain-info.
    #[arg(long = "genesis", value_name = "PATH", requires = "chain_info")]
    genesis_json: Option<PathBuf>,

    /// Exact allowlisted descriptor for a completed Robinhood full snapshot.
    #[arg(
        long = "snapshot-trust-descriptor",
        value_name = "PATH",
        requires_all = ["chain_info", "genesis_json"]
    )]
    snapshot_trust_descriptor: Option<PathBuf>,
}

pub fn run(args: JournalV3InitArgs) -> eyre::Result<()> {
    ensure!(
        args.datadir.is_dir(),
        "journal-v3-init datadir does not exist"
    );
    let directory = JournalDirectory::open(&args.datadir)?;
    reject_preexisting_authority(&args, &directory)?;

    let (chain_spec, configured_genesis, deployment) = reviewed_storage_chain(
        args.chain.as_deref(),
        args.chain_info.as_deref(),
        args.genesis_json.as_deref(),
        args.snapshot_trust_descriptor.as_deref(),
    )?;
    let factory = open_read_only_factory(&args.datadir, chain_spec.clone())?;
    let provider = factory.provider()?;
    ensure!(
        provider.cached_storage_settings() == StorageSettings::v2(),
        "journal-v3-init requires persisted Reth storage-v2"
    );
    let head_number = provider.last_block_number()?;
    let head = provider
        .sealed_header(head_number)?
        .ok_or_else(|| eyre!("reopened store head {head_number} is missing"))?;

    let anchor = if let Some(path) = &args.snapshot_trust_descriptor {
        let trust = load_approved_descriptor(path)?;
        ensure!(
            read_completion(&directory)? == trust,
            "snapshot completion and descriptor differ"
        );
        ensure!(
            head_number == trust.head_number
                && head.hash() == trust.head_hash
                && head.state_root == trust.head_state_root,
            "reopened snapshot store does not match frozen completion identity"
        );
        MessageJournalAnchor {
            sequence: head_number
                .checked_sub(configured_genesis.number)
                .ok_or_else(|| eyre!("snapshot head precedes configured genesis"))?,
            block_number: head_number,
            block_hash: head.hash(),
        }
    } else {
        ensure!(
            head_number == configured_genesis.number
                && head.hash() == configured_genesis.hash_slow()
                && head.state_root == configured_genesis.state_root,
            "reopened store is not exactly the configured genesis identity"
        );
        ensure!(
            provider
                .sealed_header(
                    head_number
                        .checked_add(1)
                        .ok_or_else(|| eyre!("genesis number overflow"))?
                )?
                .is_none(),
            "exact-genesis store contains a successor"
        );
        MessageJournalAnchor {
            sequence: 0,
            block_number: head_number,
            block_hash: head.hash(),
        }
    };
    drop(provider);
    drop(factory);

    let context = StorageContextV3 {
        l2_chain_id: chain_spec.chain().id(),
        l2_genesis_number: configured_genesis.number,
        l2_genesis_hash: configured_genesis.hash_slow(),
        sequencer_inbox: deployment.sequencer_inbox,
        bridge: deployment.bridge,
        deployment_block: deployment.deployed_at,
        anchor,
    };
    initialize_combined_authority(&directory, context)
}

fn initialize_combined_authority(
    directory: &JournalDirectory,
    context: StorageContextV3,
) -> eyre::Result<()> {
    let inspection = initialize_journal_v3(directory, context)?;
    ensure!(
        inspection.anchor() == context.anchor,
        "freshly reopened lineage-zero anchor changed"
    );
    combined_init_failpoint("journal_final");
    let lifecycle = LifecycleGuard::initialize(directory, context.anchor)?;
    ensure!(
        lifecycle.selected().state == crate::lifecycle::LifecycleState::Clean,
        "combined initialization did not commit CLEAN lifecycle evidence"
    );
    Ok(())
}

fn combined_init_failpoint(name: &str) {
    if std::env::var_os("ARB_RETH_COMBINED_INIT_FAILPOINT").as_deref()
        == Some(std::ffi::OsStr::new(name))
    {
        unsafe extern "C" {
            fn _exit(status: i32) -> !;
        }
        // SAFETY: this production test seam intentionally simulates sudden process loss.
        unsafe { _exit(86) }
    }
}

pub(crate) fn reviewed_storage_chain(
    chain: Option<&Path>,
    chain_info: Option<&Path>,
    genesis: Option<&Path>,
    snapshot_trust_descriptor: Option<&Path>,
) -> eyre::Result<(Arc<reth_chainspec::ChainSpec>, Header, InitDeployment)> {
    match (chain, chain_info, genesis, snapshot_trust_descriptor) {
        (Some(chain), None, None, None) => {
            let bytes = std::fs::read(chain)?;
            let supplied = crate::arbos_init_from_chain_config_json(&bytes)?;
            let reviewed = arb_reth_genesis::arbitrum_one::init_config();
            ensure!(
                supplied.initial_arbos_version == reviewed.initial_arbos_version
                    && supplied.initial_chain_owner == reviewed.initial_chain_owner
                    && supplied.chain_id == reviewed.chain_id
                    && supplied.genesis_block_number == reviewed.genesis_block_number
                    && supplied.initial_l1_base_fee == reviewed.initial_l1_base_fee
                    && supplied.debug_precompiles == reviewed.debug_precompiles,
                "--chain does not equal the compile-time-reviewed Arbitrum One chain specification"
            );
            let genesis = reviewed_arbitrum_one_genesis()?;
            let spec = crate::arb_chain_spec_with_header(
                crate::ARB_ONE_CHAIN_ID,
                genesis.clone(),
                arb_reth_genesis::arbitrum_one::GENESIS_BLOCK_HASH,
            );
            Ok((
                spec.clone(),
                genesis,
                InitDeployment {
                    sequencer_inbox: arb_reth_l1::SEQUENCER_INBOX_MAINNET,
                    bridge: arb_reth_l1::BRIDGE_MAINNET,
                    deployed_at: arb_reth_l1::SEQUENCER_INBOX_DEPLOY_BLOCK_MAINNET,
                },
            ))
        }
        (None, Some(chain_info), Some(genesis), Some(descriptor)) => {
            let chain_info = std::fs::read(chain_info)?;
            let genesis = std::fs::read(genesis)?;
            let trust = load_approved_descriptor(descriptor)?;
            verify_snapshot_metadata(trust, &chain_info, &genesis)?;
            let (spec, _, info) = crate::orbit_chain_from_files(&chain_info, &genesis)?;
            ensure!(
                spec.chain().id() == trust.chain_id,
                "approved snapshot metadata and parsed chain identity differ"
            );
            let spec = Arc::new(spec);
            Ok((
                spec.clone(),
                spec.genesis_header().clone(),
                InitDeployment {
                    sequencer_inbox: info.rollup.sequencer_inbox,
                    bridge: info.rollup.bridge,
                    deployed_at: info.rollup.deployed_at,
                },
            ))
        }
        _ => Err(eyre!(
            "storage context requires either exact reviewed Arbitrum One --chain or the compile-time-allowlisted --chain-info/--genesis/--snapshot-trust-descriptor set"
        )),
    }
}

fn reviewed_arbitrum_one_genesis() -> eyre::Result<Header> {
    const REVIEWED_HEAD: &str = include_str!("../../tests/fixtures/arb1_nitro_genesis_head.stream");
    let mut fields = REVIEWED_HEAD.split_ascii_whitespace();
    ensure!(
        fields.next() == Some("H"),
        "reviewed genesis record kind changed"
    );
    ensure!(
        fields.next() == Some("22207817"),
        "reviewed genesis number changed"
    );
    ensure!(
        fields.next() == Some("7d237dd685b96381544e223f8906e35645d63b89c19983f2246db48568c07986"),
        "reviewed genesis hash changed"
    );
    let encoded = alloy_primitives::hex::decode(
        fields
            .next()
            .ok_or_else(|| eyre!("reviewed genesis header is missing"))?,
    )?;
    ensure!(
        fields.next().is_none(),
        "reviewed genesis record has extra fields"
    );
    let mut input = encoded.as_slice();
    let header = Header::decode(&mut input).map_err(|error| eyre!(error))?;
    ensure!(input.is_empty(), "reviewed genesis RLP has trailing bytes");
    ensure!(
        header.number == arb_reth_genesis::arbitrum_one::GENESIS_BLOCK_NUMBER
            && header.timestamp == arb_reth_genesis::arbitrum_one::GENESIS_TIMESTAMP
            && header.state_root == arb_reth_genesis::arbitrum_one::GENESIS_STATE_ROOT
            && header.hash_slow() == arb_reth_genesis::arbitrum_one::GENESIS_BLOCK_HASH,
        "compile-time-reviewed Arbitrum One genesis identity is inconsistent"
    );
    Ok(header)
}

pub(crate) struct InitDeployment {
    pub(crate) sequencer_inbox: alloy_primitives::Address,
    pub(crate) bridge: alloy_primitives::Address,
    pub(crate) deployed_at: u64,
}

pub(crate) fn open_read_only_factory(
    datadir: &std::path::Path,
    chain_spec: Arc<reth_chainspec::ChainSpec>,
) -> eyre::Result<ProviderFactory<ArbNodeTypesWithDB>> {
    let db = open_db_read_only(
        datadir.join("db"),
        DatabaseArguments::new(ClientVersion::default()),
    )?;
    let static_files = StaticFileProvider::read_only(datadir.join("static_files"))?;
    let rocksdb = RocksDBProvider::builder(datadir.join("rocksdb"))
        .with_default_tables()
        .with_read_only(true)
        .build()
        .map_err(|error| eyre!("open RocksDB read-only for journal-v3-init: {error}"))?;
    let factory: ProviderFactory<ArbNodeTypesWithDB> =
        ProviderFactory::new(db, chain_spec, static_files, rocksdb, Runtime::test())?;
    factory.set_storage_settings_cache(StorageSettings::v2());
    Ok(factory)
}

fn reject_preexisting_authority(
    args: &JournalV3InitArgs,
    directory: &JournalDirectory,
) -> eyre::Result<()> {
    let names = directory.entry_names()?;
    for name in &names {
        let store = matches!(name.as_str(), "db" | "static_files" | "rocksdb");
        let completion = args.snapshot_trust_descriptor.is_some()
            && name == crate::snapshot_trust::SNAPSHOT_COMPLETION_FILE;
        ensure!(
            store || completion,
            "journal-v3-init target contains unexpected sibling {name}"
        );
        let metadata = std::fs::symlink_metadata(directory.entry_path(name)?)?;
        ensure!(
            (store && metadata.file_type().is_dir())
                || (completion && metadata.file_type().is_file()),
            "journal-v3-init target contains malformed allowed path {name}"
        );
    }
    for required in ["db", "static_files", "rocksdb"] {
        ensure!(
            names.iter().any(|name| name == required),
            "journal-v3-init target is missing required store {required}"
        );
    }
    if args.snapshot_trust_descriptor.is_some() {
        ensure!(
            names
                .iter()
                .any(|name| name == crate::snapshot_trust::SNAPSHOT_COMPLETION_FILE),
            "journal-v3-init snapshot target is missing exact completion"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;
    use arb_reth_engine::{LIFECYCLE_FILE, inspect_message_journal};

    use super::*;
    use crate::lifecycle::LifecycleState;

    const ARBITRUM_ONE_CHAIN_CONFIG: &[u8] = br#"{"chainId":42161,"arbitrum":{"InitialArbOSVersion":6,"InitialChainOwner":"0xd345e41ae2cb00311956aa7109fc801ae8c81a52","GenesisBlockNum":22207817,"AllowDebugPrecompiles":false}}"#;
    const APPROVED_DESCRIPTOR: &[u8] = br#"{"version":1,"chain_id":4663,"chain_info_sha256":"cf6c0aa2bc520a28fe8983f783676bc43de94cc25a57a1cdc9b1f0afc5208f0a","genesis_sha256":"353e6f6441b47695b41cee0c3645cde8dd7492d2f7f574bfb6aa4371e41bb6ba","stream_size":449373850334,"stream_sha256":"807b4d71baeeb913826d823a76faa0056a6ea0a79fc808346feb2dfecdc8d39f","head_number":31805144,"head_hash":"0xcc8b407211b69dbac3e16dc083a980db25da7133de714d5f69b7f3d068278990","head_state_root":"0x2ffae11ce686dd861271bf2728c115cdb711887cc6b6a624127bb607e43ce9b1"}"#;
    const ROBINHOOD_CHAIN_INFO: &[u8] =
        include_bytes!("../../tests/fixtures/robinhood-chain-info.json");
    const ROBINHOOD_GENESIS: &[u8] = include_bytes!("../../tests/fixtures/robinhood-genesis.json");

    #[test]
    fn storage_context_sources_are_compile_time_reviewed() {
        let dir = tempfile::tempdir().unwrap();
        let chain = dir.path().join("arb1.json");
        std::fs::write(&chain, ARBITRUM_ONE_CHAIN_CONFIG).unwrap();
        let (spec, genesis, deployment) =
            reviewed_storage_chain(Some(&chain), None, None, None).unwrap();
        assert_eq!(spec.chain().id(), crate::ARB_ONE_CHAIN_ID);
        assert_eq!(
            genesis.number,
            arb_reth_genesis::arbitrum_one::GENESIS_BLOCK_NUMBER
        );
        assert_eq!(
            genesis.hash_slow(),
            arb_reth_genesis::arbitrum_one::GENESIS_BLOCK_HASH
        );
        assert_eq!(
            genesis.state_root,
            arb_reth_genesis::arbitrum_one::GENESIS_STATE_ROOT
        );
        assert_eq!(
            deployment.sequencer_inbox,
            arb_reth_l1::SEQUENCER_INBOX_MAINNET
        );
        assert_eq!(deployment.bridge, arb_reth_l1::BRIDGE_MAINNET);
        assert_eq!(
            deployment.deployed_at,
            arb_reth_l1::SEQUENCER_INBOX_DEPLOY_BLOCK_MAINNET
        );

        let changed = dir.path().join("changed.json");
        std::fs::write(
            &changed,
            String::from_utf8_lossy(ARBITRUM_ONE_CHAIN_CONFIG).replace("42161", "42162"),
        )
        .unwrap();
        assert!(reviewed_storage_chain(Some(&changed), None, None, None).is_err());

        let chain_info = dir.path().join("chain-info.json");
        let robinhood_genesis = dir.path().join("genesis.json");
        let descriptor = dir.path().join("descriptor.json");
        std::fs::write(&chain_info, ROBINHOOD_CHAIN_INFO).unwrap();
        std::fs::write(&robinhood_genesis, ROBINHOOD_GENESIS).unwrap();
        std::fs::write(&descriptor, APPROVED_DESCRIPTOR).unwrap();
        let (spec, _, _) = reviewed_storage_chain(
            None,
            Some(&chain_info),
            Some(&robinhood_genesis),
            Some(&descriptor),
        )
        .unwrap();
        assert_eq!(spec.chain().id(), 4_663);
        assert!(
            reviewed_storage_chain(None, Some(&chain_info), Some(&robinhood_genesis), None)
                .is_err()
        );
        let mut changed_chain_info = ROBINHOOD_CHAIN_INFO.to_vec();
        changed_chain_info[0] ^= 1;
        std::fs::write(&chain_info, changed_chain_info).unwrap();
        assert!(
            reviewed_storage_chain(
                None,
                Some(&chain_info),
                Some(&robinhood_genesis),
                Some(&descriptor),
            )
            .is_err()
        );
    }

    fn anchor() -> MessageJournalAnchor {
        MessageJournalAnchor {
            sequence: 0,
            block_number: 100,
            block_hash: B256::repeat_byte(0x42),
        }
    }

    fn context() -> StorageContextV3 {
        StorageContextV3 {
            l2_chain_id: 42_161,
            l2_genesis_number: 100,
            l2_genesis_hash: B256::repeat_byte(0x11),
            sequencer_inbox: alloy_primitives::Address::repeat_byte(0x22),
            bridge: alloy_primitives::Address::repeat_byte(0x33),
            deployment_block: 44,
            anchor: anchor(),
        }
    }

    #[test]
    fn initialization_inventory_is_an_exact_allowlist() {
        fn args(datadir: &Path, snapshot: bool) -> JournalV3InitArgs {
            JournalV3InitArgs {
                datadir: datadir.to_path_buf(),
                chain: (!snapshot).then(|| PathBuf::from("reviewed-chain.json")),
                chain_info: snapshot.then(|| PathBuf::from("chain-info.json")),
                genesis_json: snapshot.then(|| PathBuf::from("genesis.json")),
                snapshot_trust_descriptor: snapshot.then(|| PathBuf::from("descriptor.json")),
            }
        }

        let exact = tempfile::tempdir().unwrap();
        for store in ["db", "static_files", "rocksdb"] {
            std::fs::create_dir(exact.path().join(store)).unwrap();
        }
        let directory = JournalDirectory::open(exact.path()).unwrap();
        reject_preexisting_authority(&args(exact.path(), false), &directory).unwrap();

        std::fs::write(exact.path().join("unrelated.txt"), b"unexpected").unwrap();
        assert!(reject_preexisting_authority(&args(exact.path(), false), &directory).is_err());
        std::fs::remove_file(exact.path().join("unrelated.txt")).unwrap();

        std::fs::write(
            exact
                .path()
                .join(crate::snapshot_trust::SNAPSHOT_COMPLETION_FILE),
            b"completion",
        )
        .unwrap();
        assert!(reject_preexisting_authority(&args(exact.path(), false), &directory).is_err());
        reject_preexisting_authority(&args(exact.path(), true), &directory).unwrap();

        std::fs::remove_dir_all(exact.path().join("rocksdb")).unwrap();
        assert!(reject_preexisting_authority(&args(exact.path(), true), &directory).is_err());

        std::fs::create_dir(exact.path().join("rocksdb")).unwrap();
        std::fs::remove_dir_all(exact.path().join("db")).unwrap();
        std::fs::write(exact.path().join("db"), b"not a store").unwrap();
        assert!(reject_preexisting_authority(&args(exact.path(), true), &directory).is_err());
        std::fs::remove_file(exact.path().join("db")).unwrap();

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(exact.path().join("static_files"), exact.path().join("db"))
                .unwrap();
            assert!(reject_preexisting_authority(&args(exact.path(), true), &directory).is_err());
            std::fs::remove_file(exact.path().join("db")).unwrap();
        }

        std::fs::create_dir(exact.path().join("db")).unwrap();
        let completion = exact
            .path()
            .join(crate::snapshot_trust::SNAPSHOT_COMPLETION_FILE);
        std::fs::remove_file(&completion).unwrap();
        std::fs::create_dir(&completion).unwrap();
        assert!(reject_preexisting_authority(&args(exact.path(), true), &directory).is_err());
    }

    #[test]
    fn combined_initialization_crash_matrix() {
        const CHILD_DATADIR: &str = "ARB_RETH_COMBINED_INIT_TEST_DATADIR";
        if let Some(datadir) = std::env::var_os(CHILD_DATADIR) {
            let directory = JournalDirectory::open(std::path::Path::new(&datadir)).unwrap();
            initialize_combined_authority(&directory, context()).unwrap();
            return;
        }

        let points = [
            ("journal_final", None),
            ("provisional_full_written", None),
            ("provisional_synced", None),
            ("provisional_entry_proved", None),
            ("a_initializing_body_written", None),
            (
                "a_initializing_checksum_written",
                Some(LifecycleState::Initializing),
            ),
            (
                "a_initializing_full_written",
                Some(LifecycleState::Initializing),
            ),
            ("a_initializing_synced", Some(LifecycleState::Initializing)),
            (
                "a_initializing_entry_proved",
                Some(LifecycleState::Initializing),
            ),
            (
                "b_initializing_body_written",
                Some(LifecycleState::Initializing),
            ),
            (
                "b_initializing_checksum_written",
                Some(LifecycleState::Initializing),
            ),
            (
                "b_initializing_full_written",
                Some(LifecycleState::Initializing),
            ),
            ("b_initializing_synced", Some(LifecycleState::Initializing)),
            ("b_initializing_reread", Some(LifecycleState::Initializing)),
            (
                "b_initializing_parent_synced",
                Some(LifecycleState::Initializing),
            ),
            (
                "b_initializing_entry_proved",
                Some(LifecycleState::Initializing),
            ),
            ("b_clean_body_written", Some(LifecycleState::Initializing)),
            ("b_clean_checksum_written", Some(LifecycleState::Clean)),
            ("b_clean_full_written", Some(LifecycleState::Clean)),
            ("b_clean_synced", Some(LifecycleState::Clean)),
            ("b_clean_reread", Some(LifecycleState::Clean)),
            ("b_clean_entry_proved", Some(LifecycleState::Clean)),
        ];
        let executable = std::env::current_exe().unwrap();
        for (point, expected) in points {
            let dir = tempfile::tempdir().unwrap();
            let mut command = std::process::Command::new(&executable);
            command
                .args([
                    "--exact",
                    "commands::journal_init::tests::combined_initialization_crash_matrix",
                    "--nocapture",
                ])
                .env(CHILD_DATADIR, dir.path());
            if point == "journal_final" {
                command.env("ARB_RETH_COMBINED_INIT_FAILPOINT", point);
            } else {
                command.env("ARB_RETH_LIFECYCLE_FAILPOINT", point);
            }
            let status = command.status().unwrap();
            assert_eq!(status.code(), Some(86), "failpoint {point} did not crash");

            let directory = JournalDirectory::open(dir.path()).unwrap();
            let journal = inspect_message_journal(&directory, context()).unwrap();
            assert_eq!(journal.anchor(), anchor());
            let reopened = LifecycleGuard::open_existing(&directory, anchor());
            match expected {
                Some(state) => assert_eq!(
                    reopened.unwrap().selected().state,
                    state,
                    "failpoint {point} selected the wrong lifecycle state"
                ),
                None => {
                    assert!(!directory.entry_exists(LIFECYCLE_FILE).unwrap() || reopened.is_err())
                }
            }
            assert!(
                initialize_combined_authority(&directory, context()).is_err(),
                "interrupted combined initialization was resumable at {point}"
            );
        }
    }
}
