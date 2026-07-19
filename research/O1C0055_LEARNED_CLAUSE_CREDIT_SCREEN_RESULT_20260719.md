# O1C-0055 — exact learned-clause credit screen

- **Started:** 2026-07-19T05:37:03+02:00
- **Recorded:** 2026-07-19T05:37:08+02:00
- **Source commit:** `8d7aa3d6053356ab7c5b95661df6548697505959`
- **Classification:** `LEARNED_CLAUSE_CREDIT_MEMBERSHIP_NO_EXACT_W11_CLOSE`
- **Boundary:** consumed Full20 target, post-reveal W11 with 245 correct key
  bits fixed; exactly one 512-conflict native call and no promotion work
- **Resources:** 4.951483084 s wall, 2.024342 s parent CPU,
  2.654086 s child CPU, 127,057,920 B peak RSS

## Result

| Mechanism | Status | Conflicts | Decisions | Propagations | Unique penalized cells | Reorders |
|---|---|---:|---:|---:|---:|---:|
| O1C-0052 owner-undo `-32` | UNKNOWN | 512 | 513 | 12,066,879 | 18 | 162 |
| O1C-0055 learned-clause all-member `-32` | UNKNOWN | 512 | 513 | 12,083,477 | 18 | 167 |

The sole W11 call did not recover or publicly verify the key. Exact learned-
clause plumbing is fully active: all 512 learned clauses contain at least one
matching live external-decision owner. Across 43,483 streamed clause literals,
2,684 owner members match the required opposite sign. Deduplication leaves 2,057
per-clause distinct `(group,mask)` penalties and exactly 65,824 `-32` units.

Yet the persistent state still touches only 18 unique action cells and
differentiates seven groups—the same support size as O1C-0052. It reorders 167
choices instead of 162, adds 16,598 propagations and leaves repeated decisions
at `502/513`. The callback therefore supplies exact contradiction membership,
but `-32` on every represented owner converts a five-member clause average into
diffuse collective blame rather than causal localization.

## Consumed truth diagnostic

This diagnostic was computed only after the already-consumed target was open and
is neither fresh evidence nor a success claim. Eight groups receive some
negative credit. The true mask is penalized in six of eight, was actually
visited in six of eight and accumulates `-17,568` credit. It is top or tied-top
in only two groups. Its deterministic rank counts among the four masks are:

| True-mask rank | Groups |
|---:|---:|
| 1 | 2 |
| 2 | 1 |
| 3 | 2 |
| 4 | 3 |

This strengthens closure of indiscriminate negative all-member credit. Changing
the sign or scale would reinterpret the same unlocalized set and is not a new
causal test.

## Mechanism boundary

The bounded state is exactly 2,662 bytes: 2,016 bytes for `4×63` action cells,
630 bytes for two live owners per group and 16 bytes for the callback bitmap.
The hook matches only `clause_literal = -owner_literal`, deduplicates repeated
members and distinct cells, and applies no credit when backtracking owners that
were absent from the learned clause.

The useful breadcrumb is fan-out: each conflict contains on average
`2,684/512 = 5.2421875` matched live owners and
`2,057/512 = 4.017578125` distinct represented cells. The next distinct
operator keeps exact membership but chooses one member by a frozen solver role,
beginning with deepest/current-level membership. Close all-member `-32` without
sign, magnitude, pair-group or cap tuning.

Telemetry hashes:

- complete bounded state: `295d27d5943267dcc0b839bea4ab5a125207824901347a04e730416b193a8ca7`
- learned-clause trace: `2f250ab8610c1c60cd6c5147a96a537adb644056eadd74f38865df107fea614a`
- selection trace: `20da739fba2caa17781ca68ed66e523b2806211560dcfd0e8f9320c8f8898a36`
- native executable: `1b82e44df28697084853e8bc1b049025a58c7b9c799084609ea2c2954e722cf4`

Authoritative JSON SHA-256:
`569b9770a690357b64dcfc44bce79b1a7eedb1f9688e5c03ad6f185b50adc9b8`.
