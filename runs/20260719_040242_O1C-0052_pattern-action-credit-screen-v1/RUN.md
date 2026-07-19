# O1C-0052 — exact pattern-action credit screen

- **Started:** 2026-07-19T04:02:42+02:00
- **Recorded:** 2026-07-19T04:02:47+02:00
- **Source commit:** `b32608d5cebbd547582a6dc8c371482e191e08a5`
- **Classification:** `PATTERN_ACTION_CREDIT_NO_EXACT_W11_CLOSE`
- **Gate:** failed (`no-exact-pattern-primary-w11`)
- **Boundary:** consumed Full20 target, post-reveal W11 with 245 correct key
  bits fixed; one 512-conflict call, no fresh target/sibling/GPU/MPS work
- **Resources:** 5.098155667 s wall, 128,303,104 B peak RSS

## Frozen mechanism

O1C-0052 retains the O1C-0050 owner horizon, frozen O1C-0048 pair groups,
primary potential, seed and 512-conflict cap. It changes only the credit address:
each group has four exact mask cells. An actual owner undo penalizes only its
selected `(group, mask)` cell. The persistent state is exactly 2,016 action
bytes plus 630 owner bytes, or 2,646 bytes total.

## Result

The single W11 call returned `UNKNOWN` at 512 conflicts, 513 decisions and
12,066,879 propagations. No follow-up was authorized. The state reordered 162
of 448 later selections and differentiated 18 action cells across seven groups,
but repeated decisions remain `502/513`.

Group `(59,60)` cycles all four masks with 48/50/48/51 conflict-owner undos.
Every visited action cell is penalized, including the true mask in six of eight
active groups after reveal. Negative owner-undo credit is therefore a tabu
signal rather than localized causal evidence. Close this formula without a
scale/group/cap sweep. Test positive support for the deepest action surviving a
conflict backjump before adding exact proof-antecedent plumbing.

Authoritative result SHA-256:
`7ef0f0416ef9d884c2041d8e6396291f4b3991e9cc5e485d2a6aa3cd36bea8de`.
