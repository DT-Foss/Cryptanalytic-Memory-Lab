# APPLE-VIEW-0006

This isolated experiment tests whether exact carry-switch proof participation
transfers across ChaCha20 targets through a fixed-size O1-style stream state.
No mutable sibling or project module is imported.

Files:

- `apple_view_6_stream_transfer.py` — self-contained Full20 circuit,
  incremental exact propagation, proof replay, 1,346-byte addressed stream
  state, BUILD/freeze/EVAL protocol, comparators, resource ledger, and CLI.
- `apple_view_6_test_stream_transfer.py` — ten deterministic circuit, state,
  split-boundary, exact-certificate, and output-confinement tests.
- `apple_view_6_result.json` — complete machine-readable reference run.
- `apple_view_6_report.md` — result, limits, and the next mechanism breadcrumb.

Reproduce from this directory:

```text
python3 -m unittest -v apple_view_6_test_stream_transfer.py
python3 apple_view_6_stream_transfer.py --output apple_view_6_result.json
```

The default matrix uses one CPU process, no CDCL/Boolean branching, no network,
and no GPU/MPS. Its hard limits are 90 CPU seconds and 256 MiB peak RSS.
