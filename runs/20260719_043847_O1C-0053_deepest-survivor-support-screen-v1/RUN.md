# O1C-0053 — deepest-survivor support screen

- **Started:** 2026-07-19T04:38:47+02:00
- **Recorded:** 2026-07-19T04:38:53+02:00
- **Source commit:** `0b89887f961f50fced087a987a6a2c4fb2122b18`
- **Classification:** `SURVIVOR_SUPPORT_NO_EXACT_W11_CLOSE`
- **Gate:** failed (`no-exact-survivor-primary-w11`)
- **Boundary:** consumed Full20 target, post-reveal W11 with 245 correct key
  bits fixed; one 512-conflict call, no fresh target/sibling/GPU/MPS work
- **Resources:** 5.326337459 s wall, 127,893,504 B peak RSS

## Frozen mechanism

O1C-0053 retains the O1C-0052 four-action cells, owner horizon, frozen
O1C-0048 pair groups, primary potential, seed and 512-conflict cap. On each
conflict-bearing backtrack it clears undone owners without reward or penalty,
then gives exactly `+32` support to the single deepest remaining owner, with a
fixed lower-group/lower-member tie break. The persistent state remains exactly
2,016 action bytes plus 630 owner bytes, or 2,646 bytes total.

## Result

The single W11 call returned `UNKNOWN` at 512 conflicts, 513 decisions and
12,068,568 propagations. No follow-up was authorized. All 512 conflict
callbacks found a survivor and emitted 512 updates totaling 16,384 support
units. Support reached nine action cells in eight groups, reordered 111 of 496
credit-modulated selections and differentiated two groups, but repeated
decisions remain `502/513`.

After reveal, the true mask received support in four of eight active groups and
9,472 of 16,384 units; it was top-supported in exactly four of eight. This is a
consumed-target breadcrumb, not prospective success. Deepest-trail survival is
route-active but insufficiently causal to close W11. Close this proxy without a
scale/group/cap sweep and move to exact learned-conflict/first-UIP antecedent
membership.

Authoritative result SHA-256:
`ab616087ec4aaf5862dbda0b0139146ea845b9a1cbe3cff0881e9a596e00f16a`.
