# O1C-0056 — clause-role credit screen

- **Started:** 2026-07-19T06:17:10+02:00
- **Recorded:** 2026-07-19T06:17:16+02:00
- **Source commit:** `9de519a973595b76f8a2ef512a5edc518499901a`
- **Classification:** `CLAUSE_ROLE_CREDIT_MEMBERSHIP_NO_EXACT_W11_CLOSE`
- **Gate:** failed (`no-exact-clause-role-credit-primary-w11`)
- **Boundary:** consumed O1C-0044 target, post-reveal W11 with 245 correct
  key bits fixed; one 512-conflict native call, no follow-up, tuning, rotation,
  sweep, fresh-target, sibling, GPU or MPS work
- **Resources:** 5.687863334 s total wall, 1.928103 s native wall,
  127,057,920 B peak RSS, 2,662 B persistent state

## Frozen mechanism

Each exact learned clause matches only negative literals of live external
decision owners. O1C-0056 selects exactly one matched role: greatest owner
level, then lowest group and member on a tie. That cell receives one fixed
`-32` update. The state remains 2,016 action bytes, 630 owner bytes and a
16-byte callback bitmap.

## Result

The only call returns `UNKNOWN` at 512 conflicts, 513 decisions and 12,013,641
propagations. All 512 clauses contain membership and all select exactly one
current-level role. The clauses contain 2,662 matched members; 2,150 are
discarded, 508 clauses contain multiple matched members, and no deepest-level
tie occurs. The 512 updates total 16,384 negative units. Eighteen persistent
cells across seven groups remain penalized, 142 actions reorder and 502/513
decisions repeat.

| Measure | O1C-0055 all-member | O1C-0056 one-role | Delta |
|---|---:|---:|---:|
| Conflicts | 512 | 512 | 0 |
| Decisions | 513 | 513 | 0 |
| Propagations | 12,083,477 | 12,013,641 | -69,836 |
| Credit reorderings | 167 | 142 | -25 |
| Selected credit updates | 2,057 | 512 | -1,545 |
| Native wall | 1.590827 s | 1.928103 s | +0.337276 s |

Owner localization works exactly and removes diffuse fan-out. The frozen
negative `-32` deepest/current-owner rule still does not close W11 and is closed
without sign, scale, cap or group tuning. Because every clause exposes one
unique current-level role despite multi-owner fan-out, a later causal successor
must model outcome or utility—conflicts can be productive—rather than revisit
owner localization. Immediate ROI moves to the Apple joint-score sieve and
O1C-0057 multi-block lamps.

Authoritative result SHA-256:
`f2dda492e7c6af7d0cea12a9aeb33ae5da7b08d8e4e352c18b695f9683a48740`.
