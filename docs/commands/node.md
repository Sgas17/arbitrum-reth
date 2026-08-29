# `arb-reth node`

Runs the node, opens the database, derives L2 messages from L1, and optionally serves HTTP JSON-RPC.

> **Phase-A closure:** this binary is a non-deployable storage/lifecycle test artifact. It always
> reports `trading_permitted = false` and `phase_complete = false`. Exact DB/journal classification
> does not authorize service; Phase B must add canonical-L1/recovery authority before a node may
> launch normally.

## Inputs

- `--datadir`: node database directory.
- `--l1-rpc`: archive-capable L1 execution endpoint. Required for L1 derivation.
- `--l1-beacon`: beacon API endpoint. Required when the selected range contains blob batches.
- One boot mode:
  - `--snapshot-head <blocks.stream> --snapshot-trust-descriptor <descriptor>` for the exact
    allowlisted Robinhood full snapshot.
  - `--chain-info <chaininfo.json> --genesis <genesis.json>` for an Orbit chain booted from genesis.
  - `--chain <chain-config.json>` for a chain-config boot.

For a snapshot-seeded database:

```sh
arb-reth node \
  --datadir /data/arb1 \
  --snapshot-head /data/head.stream \
  --snapshot-trust-descriptor /tmp/robinhood-snapshot-trust-v1.json \
  --l1-rpc https://your-archive-rpc.example \
  --l1-beacon https://your-beacon-api.example \
  --http --http.port 8545
```

For an Orbit chain:

```sh
arb-reth node \
  --datadir /data/orbit \
  --chain-info chaininfo.json \
  --genesis genesis.json \
  --l1-rpc https://your-archive-rpc.example \
  --http
```

## L1 derivation

Phase A has no L1 checkpoint producer or reader and cannot establish an L1-verified frontier. If a
later authorized phase starts derivation, it must rederive from batch 0 or use an explicit
`--l1-start-block`/`--l1-start-delayed` pair. Existing `arb-l1-resume.json` final or temporary files
reject Phase-A startup.

When no chain, chain-info/genesis pair, or snapshot head supplies the chain specification,
`--l1-rpc` also bootstraps genesis from the L1 Initialize message. That path requires an explicit
`--datadir` so local divergence/recovery markers and stopped storage are classified before the
parent endpoint is contacted.

The only message authority is the v2 lineage named
`arb-message-journal-v2-g00000000000000000000.log`, paired with the exact 8192-byte
`arb-node-lifecycle-v1.bin`. The offline `arb-reth journal-v2-init` command creates both once from
an exact configured genesis or the compile-time-allowlisted completed Robinhood snapshot. The node
does not create either artifact and Clap rejects removed v1/trusted-tip bootstrap flags.

`arb-message-divergence.json` always blocks startup. Phase-A `rewind` is unavailable, and the node
never deletes or forgives that marker automatically.

An unclean lifecycle always freezes evidence before mutable storage opens. Exact `DB==J` remains
closed. A supported exact `DB>J` suffix of at most 1024 identities may be unwound by a disposable
worker to J, followed by worker exit and a fresh parent reopen, but the result also remains closed.
`J>DB`, identity mismatch, unsupported storage/pruning, or larger distance requires a fresh
snapshot or operator diagnosis. Phase A never rederives a repaired suffix or clears quarantine into
ordinary service.

Without canonical L1 authority, journal compaction preserves every identity. Admission permanently
stops before 110,000 retained identities.

Use `--l1-start-block` and `--l1-start-delayed` only when the supplied values describe the existing L2 tip. `--l1-end-block` caps derivation at an inclusive L1 height. `--l1-getlogs-range` should match the provider's `eth_getLogs` span limit. `--l1-prefetch` controls concurrent batch resolution.

## Sequencer feed

`--feed-url` connects to a live sequencer relay. A relay is a tip source, not a history source, so use L1 derivation or a snapshot to catch up first. L1 derivation and the feed can run together; messages already applied through one source are reconciled by sequence number.

Repeat `--feed-url` to race different relays. `--feed-connections N` opens `N` OS-selected
WebSockets to every supplied relay. With no connection or source option, the default is one such
ordinary socket. The first decoded copy of a sequence is sent to the engine; duplicates are
discarded by a bounded coordinator before they can delay execution. For example:

```sh
arb-reth node \
  --feed-url wss://relay-a.example/feed \
  --feed-url wss://relay-b.example/feed \
  --feed-connections 3 \
  ...
```

This creates six sockets. The first socket starts immediately and subsequent handshakes are
staggered by one second. Each socket reconnects independently with bounded exponential backoff.
HTTP 429 responses use a separate 30-second to five-minute backoff so an excessive connection
count does not hammer the relay. The reconnect cursor advances only across a contiguous observed
sequence prefix, so a faster connection cannot make reconnecting peers skip a gap.

For distinct network identities, repeat `--feed-source IP=COUNT`. Each declaration opens that many
connections **per relay**, binding each TCP socket to the named local address before DNS-selected
connection and TLS/WebSocket handshakes. If any source is declared and `--feed-connections` is
omitted, there is no hidden OS-selected lane. Supplying both intentionally combines the unbound and
source-bound groups. Duplicate IP declarations, zero counts and more than 64 expanded sockets are
refused at startup.

```sh
arb-reth node \
  --feed-url wss://relay.example/feed \
  --feed-source 192.0.2.10=3 \
  --feed-source 192.0.2.11=2 \
  --feed-connections 1 \
  ...
```

That example opens three sockets from `192.0.2.10`, two from `192.0.2.11`, and one ordinary
OS-selected socket. On EC2, the declared addresses are private ENI addresses; map each to an EIP
when distinct public source identities are required. Merely assigning secondary addresses without
binding leaves ordinary sockets on the primary address.

Start with two or three connections per relay and use the source metrics to verify that additional
connections still win messages often enough to justify their bandwidth. The node accepts at most
64 total feed connections, but a relay may enforce a much lower per-IP limit. Excess sockets stay
on the rate-limit backoff and do not affect established connections. Endpoint paths, query strings,
and credentials are excluded from logs and metric labels.

`--no-l1-derive` makes the feed the only producer. It still needs `--l1-rpc` to bootstrap chain information, and it is appropriate only for a datadir that is already at the feed's retained range.

## Metrics

Pass `--metrics 127.0.0.1:9001` to serve reth's Prometheus endpoint. See the [observability guide](../observability/README.md) for feed latency, engine-tree, persistence, and Prometheus scrape details.

## MEV transaction-log IPC

`--mev-tx-log-ipc /run/arb-reth/mev-logs.sock` opens a local Unix socket. Each connected client
receives one compact binary frame after every included ArbOS transaction finishes EVM execution.
Events include the provisional block number, transaction index and hash, transaction kind, status,
gas used, and logs. They are deliberately pre-canonical: there is no block hash yet, and a later
state-root or engine-insertion failure can discard the enclosing block. See the [wire
specification](../mev-tx-log-ipc.md) before implementing a consumer.

Enabling the feed also installs `arb_simulateAtFrontier`. Version-2 feed frames carry the exact
post-transaction `frontierId` accepted by this method, allowing a client to simulate against the
same in-progress state that produced the observed logs.

The stream is best effort. A slow client is disconnected rather than delaying execution; reconnect
to resume from the current transaction. Log payloads are allocated only while a client is
connected. Frontier state deltas are retained whenever the feature is enabled.

## Execution cache

- `--engine.cross-block-cache-size <MiB>` controls Reth's cross-block account, storage, and
  bytecode cache. It defaults to 256 MiB for ArbOS's serial producer; Reth's generic 4 GiB
  `TreeConfig` default is unnecessarily sparse here.

## Payload execution

- `--share-execution-cache-with-payload-builder <true|false>` shares Reth's cross-block account,
  storage, and bytecode cache with the serial Arbitrum payload builder. It defaults to `true`.
- `--share-sparse-trie-with-payload-builder` lets Reth compute the state root concurrently with
  ArbOS execution. It is opt-in and requires useful state-root worker parallelism.

The node builds only one Arbitrum payload at a time. Do not reuse these settings in a node that can
run concurrent payload jobs without first reviewing Reth's cache and sparse-trie ownership rules.

## Persistence controls

- `--persistence-threshold`: number of canonical blocks before a persistence batch.
- `--memory-buffer-target`: recent blocks retained in memory before flushing.
- `--persistence-backpressure`: maximum unpersisted gap before block production stalls.

There is no durability-bypass option. All supported journal and lifecycle transitions use the
frozen synchronization protocol.

Start with the defaults unless a benchmark or recovery plan justifies changing them.

## History pruning

Without pruning flags, `arb-reth` is an archive node and retains all historical state and receipts.

- `--full` uses reth's full-node profile. It prunes sender recovery completely and retains the
  unwind-safe recent window for account history, storage history, and receipts.
- `--minimal` is more aggressive and also prunes transaction lookups, receipts, and static-file
  data according to reth's minimal-storage profile.
- `--prune.block-interval N` sets how often the persistence service may prune.
- `--prune.minimum-distance N` sets the minimum recent block window that pruning must retain.

The root `arb-start-sync.sh` wrapper exposes the two profiles as `--full` and `--minimal`, plus the
interval and minimum-distance options. For granular segment rules, invoke `arb-reth node --help`
directly and use the corresponding `--prune.*` flags.

Use pruning only after the chain has completed its initial import or catch-up. A pruned node cannot
serve arbitrary historical state, receipts, or transaction lookups that were intentionally removed.
