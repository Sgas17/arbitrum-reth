# `arb-reth snapshot`

Snapshot tools convert streams into a Storage V2 reth datadir and inspect hashed state. In Phase A,
only one exact compile-time-allowlisted Robinhood full snapshot may produce authority-completion
evidence. Older state-only/Nitro-genesis conversion tools do not write Phase-A completion and cannot
be used to initialize or launch a Phase-A datadir.

## Import workflow

The approved import requires all four exact external inputs: full snapshot stream, Robinhood
`chaininfo.json`, Robinhood `genesis.json`, and the descriptor whose exact bytes are allowlisted in
the binary. The target must be fresh. Import streams forward once, authenticates exact length and
SHA-256 while consuming it, validates the reopened head/hash/state root, and only then writes the
288-byte `arb-snapshot-completion-v1.bin` record.

```sh
arb-reth snapshot import-full \
  --stream /data/robinhood-full-snapshot.stream \
  --out /data/robinhood \
  --chain-info /data/robinhood-chaininfo.json \
  --genesis /data/robinhood-genesis.json \
  --snapshot-trust-descriptor /tmp/robinhood-snapshot-trust-v1.json
```

Interrupted or failed import targets are not resumable. Discard the target and start from a fresh
directory. The detached `snapshot finalize` path is disabled and cannot manufacture completion.

After successful import, stop all writers and run the one-shot combined v2 journal/lifecycle
initializer against the same exact inputs:

```sh
arb-reth journal-v2-init \
  --datadir /data/robinhood \
  --chain-info /data/robinhood-chaininfo.json \
  --genesis /data/robinhood-genesis.json \
  --snapshot-trust-descriptor /tmp/robinhood-snapshot-trust-v1.json
```

The command exclusively creates lineage 0 and the exact lifecycle A/B file. Any pre-existing journal
or lifecycle artifact refuses the whole command; interrupted combined initialization requires a
fresh target/snapshot rather than resume, replacement, migration, or trusted-tip fallback.

Phase A remains `trading_permitted = false` and `phase_complete = false` after successful setup.

## Read

`snapshot read` opens the converted datadir read-only and queries hashed state using a normal address input.

```sh
arb-reth snapshot read --db /data/arb1 --addr 0x1234...
arb-reth snapshot read --db /data/arb1 --addr 0x1234... --slot 0x0000...
arb-reth snapshot read --db /data/arb1 --addr 0x1234... --list-storage
```

The command prints account data and, when requested, a storage value or the non-zero storage slots for the address.
