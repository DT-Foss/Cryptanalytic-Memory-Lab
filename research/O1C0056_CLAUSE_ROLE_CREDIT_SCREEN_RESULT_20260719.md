# O1C-0056 — clause-role credit screen

- **Started:** 2026-07-19T06:17:10+02:00
- **Recorded:** 2026-07-19T06:17:16+02:00
- **Source commit:** `9de519a973595b76f8a2ef512a5edc518499901a`
- **Classification:** `CLAUSE_ROLE_CREDIT_MEMBERSHIP_NO_EXACT_W11_CLOSE`
- **Boundary:** consumed O1C-0044 target, post-reveal W11 with 245 correct key
  bits fixed; exactly one 512-conflict native call and no tuning, promotion,
  rotation, sweep, fresh-target, sibling, GPU or MPS work
- **Resources:** 5.687863334 s total wall, 1.928103 s native wall,
  127,057,920 B peak RSS, 2,662 B persistent state

## Result

| Measure | O1C-0055 all-member | O1C-0056 one-role | Delta |
|---|---:|---:|---:|
| Status | UNKNOWN | UNKNOWN | — |
| Conflicts | 512 | 512 | 0 |
| Decisions | 513 | 513 | 0 |
| Propagations | 12,083,477 | 12,013,641 | -69,836 |
| Matched owner members | 2,684 | 2,662 | -22 |
| Selected credit updates | 2,057 | 512 | -1,545 |
| Credit reorderings | 167 | 142 | -25 |
| Persistent penalized cells | 18 | 18 | 0 |
| Differentiated groups | 7 | 7 | 0 |
| Native wall | 1.590827 s | 1.928103 s | +0.337276 s |

The sole W11 call does not recover or publicly verify the key. Localization is
exact: all 512 learned clauses contain matched live owners and each produces
exactly one selected role and one `-32` update. Across 2,662 matched members,
2,150 are discarded; 508 clauses contain multiple matched members. Every
selection is at the current decision level, none is below it and no deepest-
level tie occurs. The 512 updates total 16,384 negative units.

This removes O1C-0055's diffuse per-clause fan-out but does not change the exact
gate. The state still retains 18 penalized cells across seven groups, 142
actions reorder and `502/513` decisions repeat. Propagations fall by 69,836,
while native wall rises by 0.337276 s. Neither telemetry movement is an exact
close.

## Mechanism boundary

The frozen selector chooses the matched live external-decision owner with the
greatest owner level, breaking ties by group then member. The bounded state is
exactly 2,662 bytes: 2,016 action bytes, 630 owner bytes and a 16-byte callback
bitmap. Final ledgers prove:

- `selected_deepest_members = clauses_with_membership = penalty_updates = 512`;
- `discarded_matched_members + selected_deepest_members = 2,662`;
- all 512 selections occur at the current level, with zero below and zero ties;
- callback state is closed and same-sign owner violations are zero.

Owner localization therefore works as specified. Refute only the frozen fixed
negative `-32` deepest/current-owner rule: do not tune its sign, scale, groups or
cap. The retained breadcrumb is narrower—every conflict exposes one unique
current-level role despite multi-owner fan-out, so a later successor must model
outcome or utility because a conflict can be productive. Do not revisit owner
localization. Immediate ROI shifts to the Apple joint-score sieve and O1C-0057
multi-block lamps; a causal successor, if resumed later, should be outcome- or
utility-conditioned role credit without an efficacy claim in advance.

Telemetry hashes:

- complete bounded state: `d1989f070411112511daafb4d52ff177fae3ca2557579fbad8e9562bca059aa6`
- clause-role trace: `5a6a5542047e23fbc75937cd84c6f2181f8fdf4b305a4e5731f9ca280fe6d00a`
- selection trace: `96bb848e2dd8c765d30ccbedc368475955197393f468ba4dcef122991c24d424`
- native executable: `cfdf138e166254dc0539f0a0c1ad9a8b979f1cdb8597589f11c087334ac9f882`

Authoritative JSON SHA-256:
`f2dda492e7c6af7d0cea12a9aeb33ae5da7b08d8e4e352c18b695f9683a48740`.

Reproducibility capsule:
[`runs/20260719_061710_O1C-0056_clause-role-credit-screen-v1`](../runs/20260719_061710_O1C-0056_clause-role-credit-screen-v1/RUN.md).
