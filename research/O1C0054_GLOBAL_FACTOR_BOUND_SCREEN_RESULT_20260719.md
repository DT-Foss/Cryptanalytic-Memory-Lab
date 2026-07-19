# O1C-0054 — global factor-bound screen

- **Started:** 2026-07-19T05:23:46+02:00
- **Recorded:** 2026-07-19T05:23:48+02:00
- **Source commit:** `2a63a749b5d0f92280a750ca79218ab841f2037a`
- **Classification:** `GLOBAL_FACTOR_BOUND_NO_FULL256_W11_BOUND_FAILURE`
- **Boundary:** unconditional attacker-valid Full256 first; consumed post-reveal
  W11 second; zero native solver, fresh-target, sibling, GPU or MPS work
- **Resources:** 2.732336917 s wall, 2.704926 s CPU, 88,031,232 B peak RSS

## Result

| Phase | Public recovery | Work | Forward evaluations | Wall |
|---|---:|---:|---:|---:|
| attacker-valid Full256 beam | no | 31,829 parent / 127,316 child-bound evaluations | 256 | 1.497645500 s |
| consumed post-reveal W11 queue | no | 1,024 unscored pops / 2,020 child-bound evaluations | 14 | 1.177979458 s |

The Full256 phase ran unconditionally before the reveal was opened. It assigned
all 256 unknown key bits as 128 pairs, retained at most 256 candidates, then
forward-scored and independently verified exactly 256 complete keys. None
matched the public ChaCha20 relation.

After reveal, the true prefix is first absent at stage 5 on key pair `(9,10)`.
The top final candidate is 120 key bits from truth, the closest retained
candidate is 116 bits away, and truth is absent from the beam. These are
consumed-target localization diagnostics, not attacker-visible recovery evidence.

The W11 diagnostic then reaches its frozen 1,024-unscored-pop cap after only 14
complete forward evaluations and certifies zero leaves. It therefore cannot
reproduce the exact O1C-0047 complete-state breadcrumb: truth ranks fifth among
4,096 W12 candidates under the exact global score, yet the factorwise bound
cannot certify even one W11 leaf within the bounded queue.

## Mechanism boundary

The conditional table is exact and its bound is admissible, but it independently
maximizes 836 factors over still-free variables. Those mutually incompatible
local maxima accumulate into a loose global envelope and erase the coordinated
complete-state geometry that gave O1C-0047 its rank. Beam width, pair order and
queue cap are therefore not tuned: close the global separable relaxation/beam
proxy at this result.

The Full256 logical mutable beam state is 24,624 bytes (`256` retained 48-byte
nodes plus streaming workspace). Its 1,026,688-byte prefix-retention history is
diagnostic telemetry kept separately and never enters a bound or selection.
Across both phases the screen uses 270 forward evaluations and 270 public
verifications, no native solver calls and no sibling/GPU/MPS access.

Telemetry hashes:

- pair order: `b2f73ffa1e95821b222d1b899ec3a377e0c56e287248fea7d2f2eff31d8eee00`
- conditional factor index: `d00bc0a8ab3f493ffc8f41c927867095c76122216d97c18f9839b429cc599f72`
- Full256 execution receipt: `8051bb65c2196cee41292ad45c47e3817824bb0639975c88d9658b748742e218`
- final beam/trace: `969a9314571490c7f6cc3ed947f5617231869f75d0614550f845b67ff1af7e17`

Authoritative JSON SHA-256:
`91aa42c2b036a5709f0f093e091c017c568aea459098dd238800cea87d9c32d5`.
