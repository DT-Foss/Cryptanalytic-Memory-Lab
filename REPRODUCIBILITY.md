# Reproducibility

Every outcome-bearing experiment binds its inputs, source revision, executable
and output artifacts with SHA-256. Run directories are immutable evidence; do
not overwrite or replay a consumed target/page ordinal.

## Verify the current O1C-0079 record

From the repository root:

```bash
cd runs/20260720_085738_O1C-0079_apple8-decision-ownership-v1
shasum -a 256 -c artifacts.sha256
cd ../..
```

The authoritative archived result is
`research/O1C0079_APPLE8_DECISION_OWNERSHIP_RESULT_20260720.json`. Its SHA-256
is `ce68d10eed83d9a0d90518c579f4e1841cd8a6791e4cd975d0d27a64bcc6251e`.
The zero-call erratum preserves that file and the complete capsule unchanged.

## Test the parsers, ownership replay and runner

Python 3.11 or newer is required. The package pins NumPy for historical byte
reproduction.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/pip install -e .
PYTHONPATH=src .venv/bin/python -m pytest -q \
  tests/test_o1c79_decision_ownership_v1.py \
  tests/test_joint_score_sieve_v20.py \
  tests/test_o1c79_apple8_decision_ownership_prepare.py \
  tests/test_o1c79_apple8_decision_ownership_run.py
```

This focused current-release suite contains 77 tests. Historical learned-state
tests additionally require `pip install -e '.[train]'`. Runtime-freeze tests
must be executed under the exact CPython/NumPy identity sealed by their config;
a mismatch is an expected provenance rejection, not a portable-suite failure.

The production executable is platform-specific and intentionally excluded from
Git. The O1C-0079 preflight records its exact source, compiler flags, CaDiCaL
header/library hashes, byte-identical double-build result and final executable
hash. Rebuild against CaDiCaL 3.0.0, then compare the executable SHA-256 to the
frozen gate before any execution.

## Scientific replay boundary

Do not rerun O1C-0079 Page 6 / lineage 19: its sole call is consumed. Parser,
manifest and zero-call classification validation are reproducible without a
solver call. New scientific work must use a fresh page, lineage and monotone
attempt ID.
