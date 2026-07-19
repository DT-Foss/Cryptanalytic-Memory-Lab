# APPLE-VIEW-0005

This isolated experiment turns the 336 unresolved `c31` identities from
APPLE-VIEW-0004 into named switches.  It asks whether a complete wrong 256-bit
candidate can be rejected while a material fraction of those identities is
still absent.  It does not import mutable project or sibling-experiment code.

Files:

- `apple_view_5_sparse_switches.py` — self-contained ChaCha20 circuit,
  incremental exact propagator, four fixed orders, two bounded gain pickers,
  reason-DAG proof slicing, resource ledger, and CLI.
- `apple_view_5_test_sparse_switches.py` — ten correctness, boundary,
  determinism, and exact-certificate tests.
- `apple_view_5_result.json` — complete machine-readable reference result.
- `apple_view_5_report.md` — concise scientific result and next breadcrumb.

Reproduce from this directory:

```text
python3 -m unittest -v apple_view_5_test_sparse_switches.py
python3 apple_view_5_sparse_switches.py --output apple_view_5_result.json
```

The reference run uses one CPU process, no CDCL or Boolean branching, no
network, and no GPU/MPS.  Its fixed limits are 45 CPU seconds and 192 MiB peak
RSS.
