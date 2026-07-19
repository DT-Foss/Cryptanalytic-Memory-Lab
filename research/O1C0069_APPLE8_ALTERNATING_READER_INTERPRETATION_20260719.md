# O1C-0069 — APPLE8 alternating-reader composition interpretation

- **Recorded:** 2026-07-19T17:14:14+02:00 (`Europe/Berlin`).
- **Classification:** `EPISODIC_VAULT_ALTERNATING_READER_NO_GAIN`.
- **Source:** `d6dfc06f3e7d6dfcc29d696829927b132bad23aa`.
- **Capsule:**
  [`runs/20260719_170824_O1C-0069_apple8-alternating-reader-v1`](../runs/20260719_170824_O1C-0069_apple8-alternating-reader-v1/RUN.md).
- **Seals:** authoritative result SHA-256
  `43512370d7243d57bb3ffaed445ee9196315e350d3ee1169ee0c0d8ad94ba89b`;
  capsule manifest SHA-256
  `2a78e568f0be7eafad4d117cd84aeadd0d495d19296d8ba85676496219377cb8`.

## Result

The sole authorized local-ordinal-`0`/lineage-ordinal-`5` call imported the
sealed O1C-0068 vault and explicitly forced the phase-1 reader with seed `0`.
It requested `512` conflicts and observed/billed `514` (`+2` overshoot). Native
status is `UNKNOWN`; no model or key was returned and no truth byte, reveal,
fresh target, entropy, refit, MPS or GPU call occurred.

The call fully emitted exactly one `2,951`-literal clause. It was an input-vault
duplicate at vault index `7` (zero-based; the eighth stored clause), with SHA-256
`b5da89ef9791d65487e214da71e4f36b0600ceea033cc1917c4ba9f392f89c84`,
so `0` novel clauses and `0` novel literals survived. The vault is byte-stable
at `202` clauses / `599,728` literals / `2,399,911 B`, SHA-256
`cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858`.

Search used `4,517` decisions and `1,192,529` propagations. The minimum observed
upper bound is `9.111031965569408`, while the empty-assignment root upper bound
is `262.68644197084643`. Native wall/CPU are `0.367456/1.080018 s` at
`398,032,896 B` peak RSS. End-to-end runner elapsed time is
`16.869109082996147 s`, runner peak RSS is `323,895,296 B`, and exactly one
native science process was consumed.

## Exact phase-1 fixed point

O1C-0069 does more than merely fail its novelty gate. Its phase-1 native search
trace is exactly the O1C-0067 trace even though the imported vault is much
larger:

| field | O1C-0067 phase 1 | O1C-0069 phase 1 |
|---|---:|---:|
| preloaded clauses | 12 | 202 |
| preloaded literals | 35,061 | 599,728 |
| conflicts | 514 | 514 |
| decisions | 4,517 | 4,517 |
| propagations | 1,192,529 | 1,192,529 |
| minimum upper bound | 9.111031965569408 | 9.111031965569408 |
| root upper bound | 262.68644197084643 | 262.68644197084643 |
| emitted clauses | 1 input duplicate | 1 input duplicate |
| emitted-clause SHA-256 | `b5da89ef9791d654...` | `b5da89ef9791d654...` |
| assignment-state SHA-256 | `12438ec40b77e976...` | `12438ec40b77e976...` |
| native trace SHA-256 | `676386a030ce3dcf...` | `676386a030ce3dcf...` |

The target, CNF, potential, grouping, threshold, seed and requested soft horizon
are also unchanged, and target-free preflight proved that native v8's explicit
phase 1 normalizes exactly to native v6's default reader. Therefore none of the
190 phase-0 clauses added by O1C-0068 changes the recorded phase-1 trajectory
within this bounded call. Passive import alone does not make the complementary
evidence readable by this operator.

This refutes `H-ALTERNATING-READER-COMPOSITION-073` only for one-step passive
phase-0-vault to phase-1 composition at this exact seed and soft horizon. It does
not refute the vault mechanism, reader diversity, active clause-conditioned
decisions or other explicit operators. O1C-0068 already establishes that a
different reader exposes a large distinct exclusion population.

## Threshold boundary

The frozen threshold `tau = 14.606178797892962` and the reported minimum upper
bound are in the same compiled score family and use the same retained direction
`score >= tau`, but they are not the same population or statistic. The threshold
comes from the maximum score of 4,096 complete decoys minus the frozen safety
margin; `9.111031965569408` is the minimum admissible upper bound among partial
trails visited in this one call. For any particular visited trail `a`, strict
`U(a) < tau` safely excludes every completion of `a` from
`CNF and score >= tau`. The minimum alone is existential traversal telemetry,
not a bound on all trails. Since the root bound remains
`262.68644197084643 > tau`, O1C-0069 establishes neither global threshold-region
exhaustion nor CNF-only UNSAT or key recovery. The full formal proof is sealed in
the O1C-0068 interpretation note.

## Next mechanism

Do not replay lineage ordinal `5`, continue passive alternation, sweep phases,
raise the horizon or scale RAM. The cheapest discriminating successor is an
active vault-conditioned reader: reduce the sealed phase-0 exclusion population
target-free into a deterministic bounded per-variable phase field, then make
that field steer phase-1 decisions explicitly. This tests the missing operation
identified here—reading the stored evidence—rather than storing the same
evidence again.

O1C-0070 may be precommitted only if the public derivation is nontrivial, exact,
truth-free and deterministic; the native API can bind every applied phase; a
synthetic fixture proves that the field changes the intended decisions; and all
source, vault, capacity and one-call/no-retry identities freeze cleanly. Until
those target-free gates pass, no additional Full-256 science call is authorized.

The authoritative machine result is
[`O1C0069_APPLE8_ALTERNATING_READER_RESULT_20260719.json`](O1C0069_APPLE8_ALTERNATING_READER_RESULT_20260719.json).
