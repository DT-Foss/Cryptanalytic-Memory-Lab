# APPLE-VIEW-0007

This isolated experiment tests whether exact proof-DAG predecessor paths improve
raw Full20/Full256 wrong-candidate rejection over APPLE6 unary proof memory.  No
mutable sibling or project module is imported.

Files:

- `apple_view_7_proof_edge_transfer.py` — self-contained Full20 circuit, exact
  inference-event DAG slicing/replay, 113,570-byte addressed edge state,
  BUILD/freeze/EVAL protocol, embedded exact APPLE6 comparator, resource ledger,
  and CLI.
- `apple_view_7_test_proof_edge_transfer.py` — eleven deterministic circuit,
  state, path, split-boundary, comparator-hash, proof-replay, and confinement
  tests on a non-reference seed.
- `apple_view_7_result.json` — complete machine-readable sealed reference run.
- `apple_view_7_report.md` — frozen design, exact result, failure mechanism, and
  the retained breadcrumb.

Reproduce from this directory:

```text
python3 -m unittest -v apple_view_7_test_proof_edge_transfer.py
python3 apple_view_7_proof_edge_transfer.py --output apple_view_7_result.json
```

Reference decision: **FAIL**.  The edge reader totals 1,340 raw first-conflict
switches, versus exact APPLE6 unary 1,268 and best fixed structural 1,031.
Certificate-only improvement cannot pass this experiment.  All exact rejection,
proof replay, freeze, and truth-retention controls pass.

The default matrix uses one CPU process, no CDCL/Boolean branching, no network,
and no GPU/MPS.  Its hard limits are 120 CPU seconds and 256 MiB peak RSS.
