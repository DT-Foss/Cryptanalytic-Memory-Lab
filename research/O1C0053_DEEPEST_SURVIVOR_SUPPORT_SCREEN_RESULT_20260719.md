# O1C-0053 — deepest-survivor support screen

- **Started:** 2026-07-19T04:38:47+02:00
- **Recorded:** 2026-07-19T04:38:53+02:00
- **Source commit:** `0b89887f961f50fced087a987a6a2c4fb2122b18`
- **Classification:** `SURVIVOR_SUPPORT_NO_EXACT_W11_CLOSE`
- **Gate:** failed (`no-exact-survivor-primary-w11`)
- **Boundary:** consumed Full20 target, post-reveal W11 with 245 correct key
  bits fixed; one 512-conflict call, no fresh target/sibling/GPU/MPS work
- **Resources:** 5.326337459 s wall, 127,893,504 B peak RSS

## Result

| Primary W11 mechanism | Status | Exact key | Conflicts | Decisions | Propagations |
|---|---|---:|---:|---:|---:|
| O1C-0052 exact-pattern penalty | UNKNOWN | no | 512 | 513 | 12,066,879 |
| O1C-0053 deepest-survivor support | UNKNOWN | no | 512 | 513 | 12,068,568 |

The sole prospective call did not recover the key before the unchanged cap.
The exact gate therefore failed and the runner skipped static W11, both rotated
W11 arms and all three Full256 calls. The result is one native call and 512
requested conflicts, not the seven-call promotion maximum.

## What changed and why it was insufficient

The frozen 2,646-byte state gave exactly `+32` support to one deepest externally
owned action that survived each conflict backjump. All 512 conflict callbacks
had a surviving owner, producing 512 support updates and 16,384 total support
units. No assignment, propagation, undone-owner or all-survivor support was
issued. The mechanism was therefore active exactly as frozen, not inert.

Support reached nine action cells in eight groups. It differentiated two groups
and reordered 111 of 496 credit-modulated selections. Nevertheless, repeated
external decisions remain exactly `502/513`, and the call is still cap-censored.
Positive survival support therefore changed the route without providing enough
causal discrimination to close even the consumed-target W11 qualification.

A post-result truth diagnostic is only a consumed-target breadcrumb: the true
mask received support in four of eight active groups, was the top-supported mask
in exactly four of eight, and collected 9,472 of 16,384 support units. Those
numbers were computed after reveal and are neither prospective success nor fresh
evidence. They show that survival is not pure noise, but its concentration is
too incomplete and self-reinforcing to identify the exact key.

Close deepest-survivor proxy support on these frozen disjoint pairs. Do not tune
its scale, groups, cap or reward breadth. The distinct next step is exact
conflict-antecedent membership: bind credit to actions represented on the actual
learned-conflict/first-UIP proof path instead of inferring causality from trail
survival.

Telemetry hashes:

- bounded state: `acc16fb14f0772468b52941c4075cf0515e21c40e923c1c3a68f13348de5fce3`
- action state: `2f0c77e31f1b8f05a463e15d8478f415b0060c1806d08349e857378b38aa2c88`
- owner state: `094a98e86b5355a52b2675cdbc03fafbbc3c106777826ed9da1e7a83240e0173`
- selection trace: `e074d950e69563d78ca03e3102a1ea73600b1db0179ec0e3cc06f36b2dff3f1d`
- survivor-support trace: `9577bf07fde25720ef0e7a24318353705a3726eed291b5db6f4a25ea9e1be7a2`

Authoritative JSON SHA-256:
`ab616087ec4aaf5862dbda0b0139146ea845b9a1cbe3cff0881e9a596e00f16a`.
