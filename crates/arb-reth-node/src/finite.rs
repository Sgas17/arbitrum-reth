//! Stopped, bounded L1 execution for recovery callers.
//!
//! This module deliberately has no ordinary-node options. A caller resolves the boot and strict
//! checkpoint before entering here; this module neither reads a resume log nor selects one.

use std::{path::Path, sync::Arc};

use eyre::eyre;
use reth_chainspec::ChainSpec;
use reth_db::{Database, DatabaseEnv};
use reth_node_builder::{LaunchContext, NodeBuilder, NodeConfig, WithLaunchContext};
use reth_provider::providers::StaticFileProvider;
use reth_provider::{BlockNumReader, HeaderProvider};
use reth_tasks::TaskExecutor;

use crate::launcher::ArbLaunchMode;
use crate::trusted_l2::HeaderObservation;
use crate::{
    ArbEngineTuning, ArbLauncher, ArbNode, L1ResumeCheckpoint, L1SyncConfig, L1SyncError,
    run_l1_sync,
};

/// Fully resolved chain and rollup facts supplied by the existing bootstrap.
#[derive(Clone)]
pub struct ResolvedRollupBoot {
    /// The exact chain specification selected during bootstrap.
    pub chain_spec: Arc<ChainSpec>,
    /// Arbitrum chain id used by the engine driver.
    pub chain_id: u64,
    /// Absolute L2 number of the rollup genesis block.
    pub genesis_block: u64,
    /// Bootstrap-resolved L1 SequencerInbox.
    pub sequencer_inbox: alloy_primitives::Address,
    /// Bootstrap-resolved L1 Bridge.
    pub bridge: alloy_primitives::Address,
}

/// One construction for stopped finite execution.
///
/// The launch context is intentionally not an input: it is derived from the same configured
/// builder datadir as the database. The retained database clone is the exact environment installed
/// into the builder and is used only for pre-start identity checks.
pub struct StoppedFiniteRethLaunch {
    builder: WithLaunchContext<NodeBuilder<DatabaseEnv, ChainSpec>>,
    database: DatabaseEnv,
}

impl StoppedFiniteRethLaunch {
    /// Construct the only finite Reth launch input from one config, database, and executor.
    pub fn new(
        config: NodeConfig<ChainSpec>,
        database: DatabaseEnv,
        executor: TaskExecutor,
    ) -> Self {
        let builder = NodeBuilder::new(config)
            .with_database(database.clone())
            .with_launch_context(executor);
        Self { builder, database }
    }

    fn validate_database(&self, boot: &ResolvedRollupBoot, checkpoint: u64) -> eyre::Result<()> {
        let configured_db = self.builder.config().datadir().db();
        if !same_path(&configured_db, &self.database.path()) {
            return Err(eyre!(
                "finite database path does not match configured datadir"
            ));
        }
        let static_files =
            StaticFileProvider::<arbitrum_alloy_consensus::reth::ArbPrimitives>::read_only(
                self.builder.config().datadir().static_files(),
            )
            .map_err(|error| eyre!("open finite static files: {error}"))?;
        let _tip = static_files
            .header_by_number(checkpoint)
            .map_err(|error| eyre!("read finite database tip header: {error}"))?
            .ok_or_else(|| eyre!("finite database tip header is missing"))?;
        if let Some(next) = checkpoint.checked_add(1)
            && static_files
                .header_by_number(next)
                .map_err(|error| eyre!("read finite database tail header: {error}"))?
                .is_some()
        {
            return Err(eyre!(
                "finite database durable tip exceeds checkpoint {checkpoint}"
            ));
        }
        let genesis = static_files
            .header_by_number(boot.genesis_block)
            .map_err(|error| eyre!("read finite database genesis header: {error}"))?
            .ok_or_else(|| eyre!("finite database genesis header is missing"))?;
        if genesis.hash_slow() != boot.chain_spec.genesis_hash() {
            return Err(eyre!(
                "finite database genesis hash does not match resolved boot"
            ));
        }
        Ok(())
    }
}

fn same_path(left: &Path, right: &Path) -> bool {
    left == right
        || (left.canonicalize().ok() == right.canonicalize().ok() && left.canonicalize().is_ok())
}

/// Strict, already-selected finite derivation inputs.
#[derive(Clone)]
pub struct StoppedFiniteConfig {
    pub checkpoint: L1ResumeCheckpoint,
    pub l1_sync: L1SyncConfig,
    pub frontier: u64,
}

impl StoppedFiniteConfig {
    /// Reject every cross-authority mismatch before any launcher component or task starts.
    pub fn validate(
        &self,
        boot: &ResolvedRollupBoot,
        reth: &StoppedFiniteRethLaunch,
    ) -> eyre::Result<()> {
        let checkpoint = self.checkpoint;
        let sync = &self.l1_sync;
        if boot.chain_spec.chain().id() != boot.chain_id {
            return Err(eyre!(
                "resolved boot chain-spec chain ID does not match resolved boot chain ID"
            ));
        }
        if reth.builder.config().chain.chain().id() != boot.chain_id {
            return Err(eyre!(
                "configured chain-spec chain ID does not match resolved boot"
            ));
        }
        if reth.builder.config().chain.genesis_hash() != boot.chain_spec.genesis_hash() {
            return Err(eyre!("configured chain spec does not match resolved boot"));
        }
        if checkpoint.l2_block < boot.genesis_block || self.frontier < boot.genesis_block {
            return Err(eyre!("finite checkpoint or frontier is below boot genesis"));
        }
        if checkpoint.l2_block > self.frontier {
            return Err(eyre!("finite checkpoint is above frontier"));
        }
        if sync.start_block != checkpoint.l1_block
            || sync.start_delayed_count != checkpoint.delayed_count
            || sync.start_l2_block != checkpoint.l2_block
            || sync.db_tip_l2 != checkpoint.l2_block
            || sync.genesis_block != boot.genesis_block
            || sync.l2_frontier != Some(self.frontier)
        {
            return Err(eyre!(
                "L1 sync configuration does not exactly match the selected checkpoint"
            ));
        }
        if sync.sequencer_inbox != boot.sequencer_inbox || sync.bridge != boot.bridge {
            return Err(eyre!("L1 sync rollup contracts do not match resolved boot"));
        }
        if sync.end_block.is_none_or(|end| end < checkpoint.l1_block) {
            return Err(eyre!(
                "stopped finite execution requires a bounded L1 end block at or after checkpoint"
            ));
        }
        if sync.checkpoint_path.is_some()
            || sync.batch_window == 0
            || sync.delayed_window == 0
            || sync.prefetch_windows == 0
        {
            return Err(eyre!(
                "stopped finite execution cannot use resume metadata and requires non-zero L1 windows"
            ));
        }
        validate_http_url("L1 RPC", &sync.l1_rpc)?;
        if let Some(beacon) = &sync.l1_beacon {
            // Beacon is deliberately only an untrusted blob transport. Bootstrap provides no
            // cryptographic network/timing fact for an arbitrary URL, so none is inferred here.
            validate_http_url("L1 beacon", beacon)?;
        }
        reth.validate_database(boot, checkpoint.l2_block)
    }
}

fn validate_http_url(name: &str, value: &str) -> eyre::Result<()> {
    let url = value
        .parse::<url::Url>()
        .map_err(|error| eyre!("invalid stopped finite {name} URL: {error}"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(eyre!(
            "stopped finite {name} URL must use HTTP(S) with a host"
        ));
    }
    Ok(())
}

/// Run bounded L1 derivation through a non-serving engine and return its exact durable tip.
pub async fn run_stopped_finite(
    reth: StoppedFiniteRethLaunch,
    boot: ResolvedRollupBoot,
    finite: StoppedFiniteConfig,
) -> eyre::Result<HeaderObservation> {
    finite.validate(&boot, &reth)?;
    let StoppedFiniteRethLaunch { mut builder, .. } = reth;
    builder.config_mut().rpc.disable_auth_server = true;
    let tuning = ArbEngineTuning::from_tree_config(builder.config().tree_config());
    let data_dir = builder.config().datadir();
    let executor = builder.task_executor().clone();
    let (l1_tx, l1_rx) = tokio::sync::mpsc::channel(4096);
    let (feed_tx, feed_rx) = tokio::sync::mpsc::channel(1);
    drop(feed_tx);
    let node_builder = builder.node(ArbNode);
    let launcher = ArbLauncher {
        ctx: LaunchContext::new(executor, data_dir),
        chain_id: boot.chain_id,
        genesis_block: boot.genesis_block,
        tuning,
        mode: ArbLaunchMode::Finite {
            frontier: finite.frontier,
        },
        feed_messages: feed_rx,
        l1_messages: l1_rx,
        feed_latency: None,
        tx_log_stream: None,
    };
    let handle = node_builder.launch_with(launcher).await?;
    let provider = handle.provider.clone();
    let persisted_tip = move || {
        provider
            .last_block_number()
            .map_err(|error| L1SyncError::PersistedTip {
                detail: error.to_string(),
            })
    };
    handle
        .finish_finite_l1_execution(run_l1_sync(finite.l1_sync, l1_tx, persisted_tip))
        .await
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use super::*;
    use alloy_primitives::{U256, address};
    use arb_revm::arbos_init::ArbosInitConfig;
    use arbitrum_alloy_sequencer::sequencer::feed::BroadcastFeedMessage;
    use reth_db::{ClientVersion, init_db, mdbx::DatabaseArguments};

    use crate::L1SyncCompletion;
    use reth_node_builder::{LaunchNode, NodeBuilder, NodeConfig};
    use reth_tasks::Runtime;

    /// Test-only producer injection keeps the production entrypoint hardwired to `run_l1_sync`.
    async fn run_stopped_finite_with_producer<P, F>(
        reth: StoppedFiniteRethLaunch,
        boot: ResolvedRollupBoot,
        finite: StoppedFiniteConfig,
        producer: P,
    ) -> eyre::Result<HeaderObservation>
    where
        P: FnOnce(tokio::sync::mpsc::Sender<BroadcastFeedMessage>) -> F,
        F: std::future::Future<Output = Result<L1SyncCompletion, L1SyncError>>,
    {
        finite.validate(&boot, &reth)?;
        let StoppedFiniteRethLaunch { mut builder, .. } = reth;
        builder.config_mut().rpc.disable_auth_server = true;
        let tuning = ArbEngineTuning::from_tree_config(builder.config().tree_config());
        let data_dir = builder.config().datadir();
        let executor = builder.task_executor().clone();
        let (l1_tx, l1_rx) = tokio::sync::mpsc::channel(4096);
        let (feed_tx, feed_rx) = tokio::sync::mpsc::channel(1);
        drop(feed_tx);
        let node_builder = builder.node(ArbNode);
        let launcher = ArbLauncher {
            ctx: LaunchContext::new(executor, data_dir),
            chain_id: boot.chain_id,
            genesis_block: boot.genesis_block,
            tuning,
            mode: ArbLaunchMode::Finite {
                frontier: finite.frontier,
            },
            feed_messages: feed_rx,
            l1_messages: l1_rx,
            feed_latency: None,
            tx_log_stream: None,
        };
        node_builder
            .launch_with(launcher)
            .await?
            .finish_finite_l1_execution(producer(l1_tx))
            .await
    }

    fn boot() -> ResolvedRollupBoot {
        ResolvedRollupBoot {
            chain_spec: reth_chainspec::MAINNET.clone(),
            chain_id: 1,
            genesis_block: 0,
            sequencer_inbox: arb_reth_l1::SEQUENCER_INBOX_MAINNET,
            bridge: arb_reth_l1::BRIDGE_MAINNET,
        }
    }

    fn config() -> StoppedFiniteConfig {
        let mut l1_sync = L1SyncConfig::mainnet("http://127.0.0.1:1".into(), 1, 0);
        l1_sync.end_block = Some(1);
        l1_sync.l2_frontier = Some(0);
        StoppedFiniteConfig {
            checkpoint: L1ResumeCheckpoint {
                l1_block: 1,
                delayed_count: 0,
                l2_block: 0,
            },
            l1_sync,
            frontier: 0,
        }
    }

    #[test]
    fn rejects_checkpoint_above_frontier_and_non_http_endpoints_before_launch() {
        let mut finite = config();
        finite.frontier = 0;
        finite.checkpoint.l2_block = 1;
        assert!(
            finite
                .validate(&boot(), &launch())
                .unwrap_err()
                .to_string()
                .contains("above frontier")
        );
        let mut finite = config();
        finite.l1_sync.l1_rpc = "ws://localhost".into();
        assert!(
            finite
                .validate(&boot(), &launch())
                .unwrap_err()
                .to_string()
                .contains("HTTP(S)")
        );
        let mut finite = config();
        finite.l1_sync.l1_beacon = Some("file:///tmp/beacon".into());
        assert!(
            finite
                .validate(&boot(), &launch())
                .unwrap_err()
                .to_string()
                .contains("HTTP(S)")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn stopped_finite_entrypoint_persists_frontier_and_drops_same_window_tail() {
        const CHECKPOINT: u64 = 2;
        const FRONTIER: u64 = 5;
        const TAIL: u64 = FRONTIER + 1;
        let runtime = Runtime::test();
        let datadir = reth_db::test_utils::tempdir_path();
        let maybe =
            reth_node_core::dirs::MaybePlatformPath::<reth_node_core::dirs::DataDirPath>::from(
                datadir.clone(),
            );
        let chain_spec = testnode_chain_spec();
        let config = NodeConfig::test()
            .with_chain(chain_spec.clone())
            .with_datadir_args(reth_node_core::args::DatadirArgs {
                datadir: maybe.clone(),
                ..Default::default()
            });
        let seed_config = NodeConfig::test()
            .with_chain(chain_spec.clone())
            .with_datadir_args(reth_node_core::args::DatadirArgs {
                datadir: maybe.clone(),
                rocksdb_path: Some(datadir.join("seed-rocksdb")),
                ..Default::default()
            });
        let seed_data_dir = maybe
            .clone()
            .unwrap_or_chain_default(chain_spec.chain(), seed_config.datadir.clone());
        let data_dir = maybe.unwrap_or_chain_default(chain_spec.chain(), config.datadir.clone());
        let static_files_path = data_dir.static_files();
        let db = init_db(
            data_dir.db(),
            DatabaseArguments::new(ClientVersion::default()),
        )
        .expect("open testnode database");

        let fixture: BroadcastFeedMessage =
            serde_json::from_str(include_str!("../tests/fixtures/deposit_message_only.json"))
                .expect("valid launcher deposit fixture");
        // Seed a non-genesis durable checkpoint through the same finite launcher lifecycle. No
        // serving endpoint is configured; the launched engine executes this fixture block.
        let (feed_tx, feed_rx) = tokio::sync::mpsc::channel(1);
        let (l1_tx, l1_rx) = tokio::sync::mpsc::channel(CHECKPOINT as usize);
        for sequence_number in 1..=CHECKPOINT {
            let mut checkpoint_message = fixture.clone();
            checkpoint_message.sequence_number = sequence_number;
            l1_tx
                .send(checkpoint_message)
                .await
                .expect("seed input receiver");
        }
        drop((feed_tx, l1_tx));
        let checkpoint = ArbLauncher {
            ctx: LaunchContext::new(runtime.clone(), seed_data_dir),
            chain_id: 412346,
            genesis_block: 0,
            tuning: ArbEngineTuning::reth_defaults(),
            mode: ArbLaunchMode::Finite {
                frontier: CHECKPOINT,
            },
            feed_messages: feed_rx,
            l1_messages: l1_rx,
            feed_latency: None,
            tx_log_stream: None,
        }
        .launch_node(
            NodeBuilder::new(seed_config)
                .with_database(db.clone())
                .node(ArbNode),
        )
        .await
        .expect("seed finite checkpoint")
        .finish_finite_l1_execution(async {
            Ok(L1SyncCompletion::FrontierReached {
                frontier: CHECKPOINT,
            })
        })
        .await
        .expect("persist fixture checkpoint");
        assert_eq!(checkpoint.number, CHECKPOINT);

        // A snapshot boot may use a nonzero imported-genesis floor. This foreign database has a
        // non-genesis checkpoint at 2, but its header at the selected boot floor (1) belongs to
        // the seeded chain, not the resolved boot. Validation must reject it before launch.
        let mismatched_chain_spec = testnode_chain_spec_with_genesis(1);
        let mismatched_config = NodeConfig::test()
            .with_chain(mismatched_chain_spec.clone())
            .with_datadir_args(reth_node_core::args::DatadirArgs {
                datadir: maybe.clone(),
                ..Default::default()
            });
        let mut mismatched_sync = L1SyncConfig::mainnet("http://127.0.0.1:1".into(), 122, 0);
        mismatched_sync.end_block = Some(122);
        mismatched_sync.start_l2_block = CHECKPOINT;
        mismatched_sync.db_tip_l2 = CHECKPOINT;
        mismatched_sync.genesis_block = 1;
        mismatched_sync.l2_frontier = Some(CHECKPOINT);
        let producer_started = Arc::new(AtomicBool::new(false));
        let producer_started_at_launch = producer_started.clone();
        let error = run_stopped_finite_with_producer(
            StoppedFiniteRethLaunch::new(mismatched_config, db.clone(), runtime.clone()),
            ResolvedRollupBoot {
                chain_spec: mismatched_chain_spec,
                chain_id: 412346,
                genesis_block: 1,
                sequencer_inbox: arb_reth_l1::SEQUENCER_INBOX_MAINNET,
                bridge: arb_reth_l1::BRIDGE_MAINNET,
            },
            StoppedFiniteConfig {
                checkpoint: L1ResumeCheckpoint {
                    l1_block: 122,
                    delayed_count: 0,
                    l2_block: CHECKPOINT,
                },
                l1_sync: mismatched_sync,
                frontier: CHECKPOINT,
            },
            move |_| async move {
                producer_started_at_launch.store(true, Ordering::SeqCst);
                Ok(L1SyncCompletion::FrontierReached {
                    frontier: CHECKPOINT,
                })
            },
        )
        .await
        .expect_err("foreign database genesis must reject before launch");
        assert!(
            error
                .to_string()
                .contains("genesis hash does not match resolved boot")
        );
        assert!(
            !producer_started.load(Ordering::SeqCst),
            "pre-start rejection must not begin launch tasks"
        );

        // Terminate the completed launch's remaining Reth tasks before a new lifecycle opens
        // its RocksDB provider over the durable checkpoint.
        runtime.graceful_shutdown();
        drop(runtime);
        let runtime = Runtime::test();

        let boot = ResolvedRollupBoot {
            chain_spec,
            chain_id: 412346,
            genesis_block: 0,
            sequencer_inbox: arb_reth_l1::SEQUENCER_INBOX_MAINNET,
            bridge: arb_reth_l1::BRIDGE_MAINNET,
        };
        let mut l1_sync = L1SyncConfig::mainnet("http://127.0.0.1:1".into(), 122, 0);
        l1_sync.end_block = Some(122);
        l1_sync.start_l2_block = CHECKPOINT;
        l1_sync.db_tip_l2 = CHECKPOINT;
        l1_sync.l2_frontier = Some(FRONTIER);
        let finite = StoppedFiniteConfig {
            checkpoint: L1ResumeCheckpoint {
                l1_block: 122,
                delayed_count: 0,
                l2_block: CHECKPOINT,
            },
            l1_sync,
            frontier: FRONTIER,
        };
        let result = run_stopped_finite_with_producer(
            StoppedFiniteRethLaunch::new(config, db.clone(), runtime),
            boot,
            finite,
            move |l1_tx| async move {
                // These messages model one derived L1 window: the tail is already presented when
                // typed completion closes input, so immutable frontier admission must reject it.
                for sequence_number in CHECKPOINT + 1..=TAIL {
                    let mut message = fixture.clone();
                    message.sequence_number = sequence_number;
                    l1_tx.send(message).await.expect("finite input receiver");
                }
                Ok(L1SyncCompletion::FrontierReached { frontier: FRONTIER })
            },
        )
        .await
        .expect("stopped finite entrypoint");

        assert_eq!(
            result.number, FRONTIER,
            "returned durable header is frontier"
        );
        let static_files =
            StaticFileProvider::<arbitrum_alloy_consensus::reth::ArbPrimitives>::read_only(
                static_files_path,
            )
            .expect("open durable static files");
        assert!(
            static_files
                .header_by_number(FRONTIER)
                .expect("read durable frontier")
                .is_some(),
            "frontier header must be durable"
        );
        assert!(
            static_files
                .header_by_number(TAIL)
                .expect("read same-window tail")
                .is_none(),
            "frontier + 1 tail must not be durable"
        );
    }

    fn testnode_chain_spec() -> Arc<ChainSpec> {
        testnode_chain_spec_with_genesis(0)
    }

    fn testnode_chain_spec_with_genesis(genesis_block_number: u64) -> Arc<ChainSpec> {
        let init = ArbosInitConfig {
            initial_arbos_version: 40,
            initial_chain_owner: address!("5E1497dD1f08C87b2d8FE23e9AAB6c1De833D927"),
            chain_id: U256::from(412346u64),
            genesis_block_number,
            initial_l1_base_fee: U256::from(167u64),
            serialized_chain_config: include_bytes!(
                "../tests/fixtures/testnode_l2_chain_config.json"
            )
            .to_vec(),
            debug_precompiles: true,
        };
        Arc::new(crate::arb_chain_spec(&init).expect("build testnode chain spec"))
    }

    fn launch() -> StoppedFiniteRethLaunch {
        let runtime = Runtime::test();
        let datadir = reth_db::test_utils::tempdir_path();
        let maybe =
            reth_node_core::dirs::MaybePlatformPath::<reth_node_core::dirs::DataDirPath>::from(
                datadir,
            );
        let config = NodeConfig::test()
            .with_chain(reth_chainspec::MAINNET.clone())
            .with_datadir_args(reth_node_core::args::DatadirArgs {
                datadir: maybe.clone(),
                ..Default::default()
            });
        let data_dir =
            maybe.unwrap_or_chain_default(reth_chainspec::MAINNET.chain(), config.datadir.clone());
        StoppedFiniteRethLaunch::new(
            config,
            init_db(
                data_dir.db(),
                DatabaseArguments::new(ClientVersion::default()),
            )
            .unwrap(),
            runtime,
        )
    }
}
