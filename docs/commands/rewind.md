# `arb-reth rewind`

`rewind` removes blocks above a chosen L2 height and truncates the message journal and L1 resume log to the same canonical identity. Stop the node before running it.

For a confirmed first divergent block `N`, keep `N - 1`:

```sh
arb-reth rewind \
  --datadir /data/arb1 \
  --snapshot-head /data/head.stream \
  --diverged-at N
```

Use `--to <block>` when the desired surviving tip is already known. Run `--dry-run` first to validate the target and inspect the changeset range without writing.

Recovery commits the database unwind first, then truncates `arb-message-journal.ndjson` and `arb-l1-resume.json`, validates the final database tip, and clears `arb-message-divergence.json` last. If the command is interrupted after the database commit, rerun it with the same target; an equal current tip is accepted so sidecar recovery can finish. A legacy datadir without a message journal is also accepted.

The boot information must match the datadir:

- Snapshot-seeded datadir: pass `--snapshot-head`.
- Orbit datadir: pass `--chain-info <chaininfo.json> --genesis <genesis.json>`.

Do not rewind because a reference RPC temporarily lacks a tip block. Confirm the mismatch with stable, non-null state roots first.
