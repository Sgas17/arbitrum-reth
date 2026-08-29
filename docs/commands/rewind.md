# `arb-reth rewind`

Manual rewind is unavailable in Phase A. The command parses its existing target arguments and then
exits closed without opening or mutating the datadir because canonical-L1 and recovery authority do
not exist until Phase B.

Phase A has no v1 journal or L1 resume sidecar reader/writer and offers no compatibility rewind.
Unclean startup may perform only the bounded stopped-worker `DB>J` repair defined by the v2 journal
and lifecycle classifier; that repair remains phase-incomplete and does not resume service.
