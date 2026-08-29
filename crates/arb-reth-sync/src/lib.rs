//! `arb-reth-sync`: the L1-derivation catch-up runtime.
//!
//! Split out of `arb-reth-node`. `l1_sync` walks L1 windows through `arb-reth-l1`'s readers into a
//! feed-message channel. Phase A deliberately has no checkpoint producer or compatibility reader.
//! The node depends on this crate and spawns `run_l1_sync` as a feed producer; the fetch/derive
//! primitives live in `arb-reth-l1`.

pub mod l1_sync;

pub use l1_sync::{L1SyncConfig, L1SyncError, run_l1_sync, supervise_l1_sync};
