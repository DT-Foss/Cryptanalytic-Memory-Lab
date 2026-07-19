# O1C-0054 — global factor-bound screen

- **Started:** 2026-07-19T05:23:46+02:00
- **Recorded:** 2026-07-19T05:23:48+02:00
- **Source commit:** `2a63a749b5d0f92280a750ca79218ab841f2037a`
- **Classification:** `GLOBAL_FACTOR_BOUND_NO_FULL256_W11_BOUND_FAILURE`
- **Gate:** failed (`no-public-full256-recovery-and-no-certified-w11-leaf`)
- **Boundary:** unconditional attacker-valid public Full256 beam executed before
  reveal; one consumed post-reveal W11 diagnostic followed; zero native solver,
  fresh-target, sibling, GPU or MPS work
- **Resources:** 2.732336917 s wall, 2.704926 s CPU, 88,031,232 B peak RSS

## Frozen mechanism

O1C-0054 compiles the unchanged O1C-0044 primary factor field into an exact
conditional table over 636 unary-key and 200 binary-key factors. For every
partial key prefix it computes an admissible global bound by maximizing each
factor independently over its unassigned key and internal variables. The
attacker-valid beam assigns all 128 frozen/completion key pairs at width 256,
then forward-scores and publicly verifies exactly 256 complete keys.

The Full256 live beam retains at most 256 logical 48-byte nodes. Including the
root and streaming selection workspace, its declared logical mutable state is
24,624 bytes. The 1,026,688-byte retained-prefix history is diagnostic telemetry
and is recorded separately; it does not enter scoring or beam selection.

## Result

The public-only Full256 run executed unconditionally before any reveal read. It
expanded 31,829 parents, evaluated 127,316 child bounds, forward-scored and
publicly verified 256 complete candidates in 1.497645500 seconds, and recovered
no key. After reveal, the true prefix is first absent at stage 5 on pair
`(9,10)`. The final top and minimum candidate Hamming distances are 120 and 116,
and the truth is absent from the final beam.

The subsequent consumed W11 best-first diagnostic reaches the 1,024-unscored-pop
cap after 2,020 child-bound evaluations and only 14 forward evaluations. It
certifies zero leaves, so it cannot reproduce the exact O1C-0047 W12 truth rank
5 even in the one-bit-smaller W11 domain.

Close this global separable factor-max relaxation and its width-256 beam without
a width, pair-order, cap or bound-scale sweep. The retained breadcrumb is sharp:
the exact complete-state score ranks truth fifth on W12, but independently
maximizing every factor destroys enough coordination that Full256 loses truth at
five assigned pairs and W11 cannot certify one leaf under its frozen cap. Move
the causal branch to exact learned-clause membership at the conflict boundary.

Authoritative result SHA-256:
`91aa42c2b036a5709f0f093e091c017c568aea459098dd238800cea87d9c32d5`.
