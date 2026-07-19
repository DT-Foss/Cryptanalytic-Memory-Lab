# Apple View 3

This isolated track tests whether globally restoring ChaCha20 carry recurrence
by bit depth yields a cheap Full256 candidate filter.

- [`apple_view_3_report.md`](apple_view_3_report.md) — result and boundary
- [`apple_view_3_result.json`](apple_view_3_result.json) — machine-readable run
- [`apple_view_3_carry_depth.py`](apple_view_3_carry_depth.py) — experiment
- [`apple_view_3_test_carry_depth.py`](apple_view_3_test_carry_depth.py) — tests

The measured mechanism is closed: depths `0..30` determine no final output bits;
depth `31` is the full exact computation and adds no shortcut.
