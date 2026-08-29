# Robinhood mainnet

Robinhood Chain is an Orbit chain with chain ID `4663`, rooted on Ethereum mainnet. `arb-reth` boots it from Robinhood's `chaininfo.json` and genesis files, then derives batches from L1. It can follow the public sequencer feed while it catches up.

> **Phase-A closure:** the current binary is a non-deployable storage/lifecycle test artifact. It
> cannot launch normal service, derive canonical L1 authority, publish a verified tip, resume from a
> checkpoint, or permit trading. The commands below describe inputs for later phases, not an
> authorization to operate Phase A.

This is an operator recipe for the current mainnet configuration. Keep credentials out of shell history, repository files, and process listings.

## Bootstrap files

Download the mainnet `chaininfo.json` and `genesis.json` from Robinhood's [Run a full node guide](https://docs.robinhood.com/chain/run-a-full-node/). Robinhood publishes both files there for full-node operators.

The copies currently under `crates/arb-reth-node/tests/fixtures` exist to exercise the Orbit boot parser. They are test fixtures, not an operator distribution contract, and may be moved or removed from this repository at any time. Keep downloaded files in operator-controlled storage and pass their paths explicitly.

## Requirements

- A release build of `arb-reth`.
- An archive-capable Ethereum mainnet execution RPC.
- An Ethereum mainnet beacon API. Robinhood has blob batches, so the beacon endpoint is required for a complete sync.
- Sufficient disk for the retained history and a persistent datadir. Do not place the datadir in a temporary directory.

Build the binary from the repository root:

```sh
cargo build --release -p arb-reth-node --bin arb-reth
```

Set the paths and RPC credentials in the environment. The execution and beacon endpoints below are placeholders and should be supplied by the operator.

```sh
export ARB_RETH="$PWD"
export DATADIR="$HOME/arb-data/robinhood-mainnet"
export L1_RPC="https://your-ethereum-archive-rpc.example"
export L1_BEACON="https://your-ethereum-beacon-api.example"
export FEED_URL="wss://feed.mainnet.chain.robinhood.com"
export CHAIN_INFO="$HOME/rh/config/robinhood-chain-info.json"
export GENESIS="$HOME/rh/config/robinhood-genesis.json"
```

The canonical RPC is `https://rpc.mainnet.chain.robinhood.com`. It is useful for parity checks, not for L1 derivation.

## Node inputs for a later authorized phase

Phase A neither creates a journal during node startup nor resumes from a stored L1 checkpoint. A
datadir must first pass the exact allowlisted full-snapshot import and one-shot `journal-v2-init`
flow documented in the [snapshot command](../commands/snapshot.md). Even then, Phase A classifies
the v2 journal/lifecycle and remains closed rather than authorizing service. The command shape below
is retained only to document non-authority tuning for the later phase that enables service.

```sh
"$ARB_RETH/target/release/arb-reth" node \
  --datadir "$DATADIR" \
  --chain-info "$CHAIN_INFO" \
  --genesis "$GENESIS" \
  --l1-rpc "$L1_RPC" \
  --l1-beacon "$L1_BEACON" \
  --l1-getlogs-range 500 \
  --l1-prefetch 32 \
  --feed-url "$FEED_URL" \
  --persistence-threshold 128 \
  --memory-buffer-target 0 \
  --persistence-backpressure 512 \
  --full \
  --http --http.port 8547
```

`--full` is the recommended local full-node profile: it retains the recent history and receipts
needed for normal operation and safe unwinds, while removing older data that an archive node would
keep indefinitely. Omit it to run an archive node. Do not use `--minimal` for a parity-monitoring
or recovery-oriented node; it retains less data. See the [node command](../commands/node.md) for
the retained windows and granular pruning controls.

The feed and L1 derivation may run together. The feed improves time at the tip, while L1 remains the source of durable historical derivation. Feed messages ahead of the L1 cursor are reconciled by sequence number and applied when they become contiguous.

`--l1-getlogs-range 500` and `--l1-prefetch 32` are good starting values for an endpoint that permits wide log ranges and concurrent blob requests. Reduce the range when the provider limits `eth_getLogs`; reduce prefetch when the beacon service is rate-limited.

## Check progress

Phase A exposes no service-ready state, so there is no operational sync progress or parity procedure.
Only fixture/local-storage validation and the constant closed-state metrics are meaningful until a
separately authorized phase implements canonical-L1 authority and service readiness.

## Recover from a confirmed divergence

Phase A has no manual divergence rewind, `arb-l1-resume.json` producer/reader, or repaired-suffix
rederivation. Stop and use a fresh approved snapshot or operator diagnosis. An explicit
`--l1-start-block`/`--l1-start-delayed` pair is only an in-memory derivation start; it cannot create
canonical authority or bypass Phase-A closure.

See the [node command](../commands/node.md), [observability guide](../observability/README.md), and [rewind command](../commands/rewind.md) for option details.
