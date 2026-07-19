# O1C-0055 — exact learned-clause credit screen

- **Started:** 2026-07-19T05:37:03+02:00
- **Recorded:** 2026-07-19T05:37:08+02:00
- **Source commit:** `8d7aa3d6053356ab7c5b95661df6548697505959`
- **Classification:** `LEARNED_CLAUSE_CREDIT_MEMBERSHIP_NO_EXACT_W11_CLOSE`
- **Gate:** failed (`no-exact-learned-clause-credit-primary-w11`)
- **Boundary:** consumed Full20 target, post-reveal W11 with 245 correct key
  bits fixed; one 512-conflict native call, no follow-up/fresh-target/sibling/
  GPU/MPS work
- **Resources:** 4.951483084 s wall, 2.024342 s parent CPU,
  2.654086 s child CPU, 127,057,920 B peak RSS

## Frozen mechanism

O1C-0055 preserves the frozen 63 pair groups, four action cells per group,
primary potential, seed and W11 cap. A CaDiCaL learned-clause callback streams
each minimized clause exactly once. A clause literal matches only a live
external decision owner when it is the negation of that owner literal. After
member and `(group,mask)` deduplication, every represented cell receives exactly
`-32`; backtrack-only owner clears receive zero credit.

Persistent state is exactly 2,016 action bytes, 630 owner bytes and a 16-byte
clause-member bitmap: 2,662 bytes total.

## Result

The only call returns `UNKNOWN` at 512 conflicts, 513 decisions and 12,083,477
propagations. All 512 learned clauses contain matched live-owner membership.
Their 43,483 streamed literals yield 2,684 matched owner members and 2,057
per-clause distinct cell penalties, or 65,824 negative units. Nevertheless only
18 unique state cells are penalized across seven differentiated groups; 167
actions reorder and 502/513 decisions repeat.

O1C-0052 reached the same 18 unique cells and seven groups with 162 reorderings
and 12,066,879 propagations. Exact clause membership is therefore a real hook,
but penalizing every represented owner reproduces the same diffuse negative
blame and does not close W11.

The consumed post-result truth view strengthens that closure: among eight groups
with negative credit, the true mask is penalized in six, receives `-17,568`
total credit and is top/tied-top in only two. Its deterministic four-mask ranks
are `1:2, 2:1, 3:2, 4:3`, and the true action was visited in six of eight groups.
This is not fresh evidence or success.

Close all-member `-32` learned-clause credit without sign, scale, group or cap
tuning. Retain the measured clause fan-out—5.24 matched owners and 4.02 distinct
penalized cells per conflict—as the reason to select one exact role-conditioned
member, beginning with the deepest/current-level clause owner.

Authoritative result SHA-256:
`569b9770a690357b64dcfc44bce79b1a7eedb1f9688e5c03ad6f185b50adc9b8`.
