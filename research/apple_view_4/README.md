# Apple View 4

This isolated track tests the direct counterexample to Apple View 3: exact
partial-carry constraints receive both a complete candidate key and the public
ChaCha20 output, then propagate bidirectionally without CDCL search.

- [`apple_view_4_report.md`](apple_view_4_report.md) — result and boundary
- [`apple_view_4_result.json`](apple_view_4_result.json) — machine-readable run
- [`apple_view_4_bidirectional_carry.py`](apple_view_4_bidirectional_carry.py) — experiment
- [`apple_view_4_test_bidirectional_carry.py`](apple_view_4_test_bidirectional_carry.py) — tests

The frozen success gate failed: depths 24, 28, 29, and 30 rejected none of four
fixed wrong Full256 probes.  Depth 31 rejected all four but is the complete
forward relation, not a shortcut.
