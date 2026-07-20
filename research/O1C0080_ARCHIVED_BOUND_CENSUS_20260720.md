# O1C-0080 archived one-bit bound census

This is a target-free, zero-call census over immutable public evidence. It does
not run CaDiCaL, consume the Page-7 science call, read a target or truth key, or
perform a reveal or refit. The canonical result is
`research/O1C0080_ARCHIVED_BOUND_CENSUS_20260720.json` (1,091,321 bytes,
SHA-256 `59b270c357090afef7b2ff0aa3d3a6350ec6e022aac5e62d3d5b7cf4cf1682d7`).

## Exact terminal population

All 19 archived v6-compatible terminal snapshots pass fixed file/raw digests,
potential/grouping identity, state hashes, trail/pending validation, and a full
recomputation of their group caches. Deduplication by identical assignment and
cache state leaves 13 exact parents.

- 1,580 eligible parent/key pairs and 3,160 exact child bounds were evaluated.
- Key variable 241 is absent from the frozen potential and is never probed.
- No pair crosses the strict threshold and no pair has both children below it.
- The closest child is O1C-0074 episode 01, variable 105:
  parent `15.531057646608152`, U0 `15.224559961355952`, U1
  `14.842606678748025`, still `0.2364278808550626` above tau.
- The complete 1,580-row terminal ledger is persisted. Its canonical row-stream
  SHA-256 is `f92fc111b23a4896e5c73a51531d8d3059566b72527a533e473727afd43b8216`.

The production full-scan equivalence coverage is bounded and explicit: all 13
parent U values plus both children of each of the 12 parents having at least one
eligible key variable (24 child values). The finite test fixture exhaustively
checks every partial assignment and unassigned variable. This is not described
as an exhaustive production full scan of all 3,160 children.

Exact terminal operation counts are 32,213 incident group recomputations and
2,005,144 incident table-row evaluations. The bounded production full-scan
cross-check evaluates 4,245,888 table rows.

## Visible-event lower envelope

The 549 serialized nonzero O1C-0079 proposal markers are a separate, explicitly
inexact population. Only eight release batches expose target levels, while the
native run records 138 backtracks. The missing 130 or more targets make exact
callback-parent reconstruction impossible. Exact zero-return parent population
is therefore 0; the 1,038 zero returns are not included.

The replay retains assignments removed by unrecorded backtracks. Those stale
constraints can only lower a grouped upper bound, so its 81,632 pairs form a
lower envelope rather than exact same-parent states. The minimum child is
`29.42639570750978` at callback 667, level 253, variable 158. Because even this
lower envelope remains above tau, monotonicity certifies no strict-prunable
child—and therefore no crossing—within the 549-marker scope. It says nothing
about the future Page-7 trajectory.

The maximum observed envelope drop, `4.335772097681144`, is retained only as a
breadcrumb. A difference of two lower-envelope values is not monotonic and does
not certify a native-state drop or crossing. The bounded 81,632-row stream is
represented by aggregate counters, extrema, and canonical SHA-256
`2fd439f488306f4d8ef231dc26b795718e7e7777cc43fbf11770a3408dbc2ee4`.

## Reproduction

```sh
PYTHONPATH=src python -m o1_crypto_lab.o1c80_archived_bound_census \
  --check research/O1C0080_ARCHIVED_BOUND_CENSUS_20260720.json

PYTHONPATH=src pytest -q tests/test_o1c80_archived_bound_census.py
```

The successful generation pass on the archived host used `/usr/bin/time -l` and
measured 39.05 seconds wall time, 40.28 seconds user time, 0.57 seconds system
time, 189,743,104 bytes maximum resident set size, and 148,472,480 bytes peak
memory footprint. Runtime and RSS are intentionally excluded from canonical
JSON because they are host-dependent; deterministic operation counts are
persisted instead.
