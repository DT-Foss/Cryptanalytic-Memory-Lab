# O1C-0040 — Complete-Candidate Relation Rank

Recorded 2026-07-18T22:22:55+02:00 from source commit `284f7f2`.

## Result

`CLAUSE_RELATION_CANDIDATE_OBJECTIVE_NULL`.

O1C-0039's frozen H16/`|J|=0.5` relation fields were scored on the true complete
ChaCha forward execution and 4,096 deterministic attacker-generated decoys per
consumed DEVELOPMENT target. The exact forward-wire evaluator reproduced the
O1C-0039 truth-edge counts (`238/432`, `159/279`) without a solver.

| Scorer | development-0000 | development-0001 | Geometric rank fraction |
|---|---:|---:|---:|
| Primary raw | 1,905/4,097 | 2,292/4,097 | 51.0022% |
| Key-rotated raw | 1,181/4,097 | 3,110/4,097 | 46.7777% |
| Factor-rotated raw | 1,657/4,097 | 3,576/4,097 | 59.4147% |
| Primary surprise | 1,078/4,097 | 1,461/4,097 | 30.6315% |
| Key-rotated surprise | 107/4,097 | 423/4,097 | 5.1927% |
| Factor-rotated surprise | 1,442/4,097 | 3,500/4,097 | 54.8341% |

The only correction beyond raw absolute score was frozen in advance: BUILD
relation reliability minus each edge's attacker-generated structural match rate
in Jeffreys-smoothed log odds. It improves the primary numerical rank but is
dominated by the key-rotated control. Neither predeclared method puts primary in
the top quartile on both targets.

## Interpretation

The O1C-0039 relation accuracy is reproducible but mostly structural: arbitrary
keys exhibit almost the same late-round/feed-forward key-to-carry relations.
Correct pair signs therefore are not recovered key bits and their raw sum is not
a target-specific search objective. This closes H16 branch-difference clause
occurrence plus the single structural-surprise correction, not the paired proof
stream or relational completion in general.

The next reader keeps branch identity and moves one causal level deeper: signed
antecedent chains that exist under only `k_i=0` or `k_i=1`. No H16, weight,
surprise or conflict-budget sweep follows on these opened targets.

## Resources and artifacts

- 3.981557 elapsed seconds; 101,466,112 B peak RSS.
- 8,194 exact candidate forward evaluations; 8,192 decoy keys.
- Zero solver, sibling, fresh-target, MPS or GPU calls.
- Capsule manifest SHA-256: `58f9350eafa2e0a842a00aecf7e32ea4d12f52e52af2f48b3c2c1ff8e247883f`.
- Result SHA-256: `941d7fe9b7bf52f223ad0c3571248dbd739bd3233aa981e3c6f1b114bed95b7d`.
- Score-freeze SHA-256: `8662b53d75e4bb7849e5302a8f3b2a878ac75eff9810dee6910b4d3305d047da`.
- [Immutable capsule](../runs/20260718_222255_O1C-0040_relation-candidate-rank-v1/RUN.md)
- [Canonical machine result](O1C0040_RELATION_CANDIDATE_RANK_RESULT_20260718.json)
