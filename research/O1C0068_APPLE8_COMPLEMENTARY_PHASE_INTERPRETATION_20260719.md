# O1C-0068 — APPLE8 complementary-phase interpretation

- **Recorded:** 2026-07-19T16:18:58+02:00 (`Europe/Berlin`).
- **Classification:** `EPISODIC_VAULT_COMPLEMENTARY_PHASE_GAIN`.
- **Source:** `8446414d73e871de829c182ca4cd5b500e4d9d14`.
- **Capsule:**
  [`runs/20260719_161838_O1C-0068_apple8-complementary-phase-v1`](../runs/20260719_161838_O1C-0068_apple8-complementary-phase-v1/RUN.md).
- **Seals:** authoritative result SHA-256
  `d494887d2be96516211acf09ff8852a88a44576044723223b9057942fd7aea80`;
  capsule manifest SHA-256
  `dd0236774c1352238cce86458a8f01380aa32dc538dbe80a3c1744b0f126a745`.

## Result

The one authorized local-ordinal-`0`/lineage-ordinal-`4` call forced the
complementary initial phase with `forcephase=true`, `phase=0` and seed `0`.
Native code fully emitted `195` clauses with no pending clause: `190` are novel
and `5` repeat earlier emissions within this call; none duplicates an input-vault
clause. The retained vault therefore grows from `12` to `202` clauses, `35,061`
to `599,728` literals, and `140,483` to `2,399,911 B`.

The native call requested, observed and billed exactly `512` conflicts. It used
`5.331635 s` native wall, `5.925889 s` native CPU and `397,099,008 B` peak RSS.
It returned status `UNKNOWN` and no model or key; it read no truth byte and used
no fresh target, reveal, entropy, refit, MPS or GPU call.

At the same requested soft horizon, O1C-0068 versus O1C-0067 changes decisions
`4,517 -> 1,330` (`-3,187`), propagations
`1,192,529 -> 31,944,523` (`+30,751,994`), and minimum observed upper bound
`9.111031965569408 -> 12.8607806294803`
(`+3.749748663910893`). O1C-0067 actually observed/billed `514` conflicts,
whereas O1C-0068 observed/billed `512`. The complementary trajectory is thus a
large novelty gain with fewer decisions but far more propagation; its higher
minimum upper bound is not a new bound frontier.

## Formal threshold and no-good scope

The frozen threshold is

`tau = 14.606178797892962`.

Its provenance is O1C-0061's maximum over `4,096` complete decoy scores,
`14.606178797992964`, minus the `1e-10` safety margin and rounded downward by
the frozen `nextafter(..., -infinity)` rule. O1C-0061 and O1C-0068 use the same
compiled potential-score metric and retain the same direction,
`score >= tau`. They do not report the same population or statistic: the decoy
maximum is a complete-key panel statistic, while a solver minimum upper bound is
the minimum over partial trails actually visited in one bounded trajectory.

Formally, write the compiled score as

`score(x) = c + sum_f phi_f(x)`

and let the width-6 grouping partition the factors exactly as
`F = G_1 disjoint-union ... disjoint-union G_m`. For a partial trail `a`, let
`R_i(a)` be the rows of group `G_i` consistent with `a`. Each stored group-row
value is the exact binary64-lattice sum of its factors rounded once upward:

`E_i(r) = upward(sum_{f in G_i} phi_f(r))`.

The group contribution and root bound are

`M_i(a) = max_{r in R_i(a)} E_i(r)` and
`U(a) = upward(c + sum_i M_i(a))`,

where the root sum is also accumulated exactly on the binary64 lattice and
rounded once upward. For every completion `x` extending `a`, its row `r_i(x)`
belongs to `R_i(a)`. Factor partitioning gives neither omission nor double
counting, upward group sums give
`sum_{f in G_i} phi_f(x) <= E_i(r_i(x)) <= M_i(a)`, and the upward exact root
sum preserves the inequality. Hence

`score(x) <= U(a)`

for every completion `x` of `a`. Therefore `U(a) < tau` implies every such
completion has `score(x) < tau`; the clause negating `a` is a safe local no-good
for `CNF ∧ score >= tau`. The comparison must be strict because equality is
retained: `U(a) = tau` cannot exclude a completion whose score equals `tau`.
These clauses are not consequences of the ChaCha CNF alone.

In particular, O1C-0066 episode 1's minimum
`7.973483108047071` means only that at least one visited partial trail attained
that local admissible bound. It is existential traversal telemetry, not a bound
on every trail or on the complete candidate population. The empty-assignment
root upper bound remains `262.68644197084643 > tau`; no root pruning, global
exhaustion, CNF UNSAT or key recovery follows.

## Durable exclusion evidence

The counters and serialized-vault hashes form a continuous archive chain:

- O1C-0066 episode 0 takes the empty vault
  `43377d8b5c116f2e3deac2064a16bbc526ae2c31bb2999c074084b81faa4ce94`
  to the 6-clause vault
  `22edf530a36666dd464f74c190e3a64d1b7470d8580fe24f97747d905504cbf5`.
- O1C-0066 episode 1 imports that hash, fully emits `7` clauses with `0`
  pending (`6` novel, `1` duplicate), and seals the final 12-clause vault
  `371dd8454e46eb6c53549efa53e6412f5798b22a06e6f96c927ab74df2ba687a`.
- O1C-0067 imports and preserves that exact 12-clause hash. O1C-0068 imports it,
  fully emits `195` clauses with `0` pending, and seals the 202-clause vault
  `cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858`.

This is durable evidence for `190` additional local exclusions in the frozen
threshold-constrained problem. It is not evidence that the unrestricted CNF or
key space has been solved.

## Interpretation and next action

Changing only the initial-phase reader broke O1C-0067's reader-specific
duplicate fixed point. The gain is mechanistic and operator-specific: the
complementary phase exposes a different set of exact threshold no-goods. It is
not recovery, a truth claim, or evidence that phase choice uniformly improves
search efficiency.

The highest-return successor is O1C-0069: exactly one explicit
alternating-reader composition call from the sealed 202-clause vault with
`forcephase=true`, `phase=1`, seed `0` and the same requested `512` conflicts.
This is a new composed state, not an O1C-0067 replay: the phase is explicit and
the input vault is `202`, not `12`, clauses. Reserving the full observed
O1C-0068 envelope as if all `195` emissions were novel gives a matched projection
of `397` clauses, `1,179,254` literals and `4,718,795 B`, below the frozen
`512`-clause, `1,600,000`-literal and `8,388,608 B` caps. That projection is not
a formal worst-case bound for an arbitrary 512-conflict trajectory, so the hard
native first-crossing capacity terminal remains the guard. After that one
bounded cycle, exact subsumption/minimization and capacity-aware retention are
the next vault lever. Do not replay either consumed ordinal, run a blind phase
sweep or raise the horizon blindly.

The authoritative machine result is
[`O1C0068_APPLE8_COMPLEMENTARY_PHASE_RESULT_20260719.json`](O1C0068_APPLE8_COMPLEMENTARY_PHASE_RESULT_20260719.json).
