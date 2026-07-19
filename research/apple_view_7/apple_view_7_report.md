# Apple view 7: a proof path without start credit arrives last

## Experiment frozen before EVAL

APPLE-VIEW-0006 showed that unary proof participation transfers to smaller
held-out proof certificates, but not to an earlier raw conflict.  This run made
exactly one mechanism change: replace unary membership/recency with a bounded
proof-DAG predecessor memory.  The prospective statement was literal:

> A proof is a path, not a bag.

The Full20/Full256 circuit, BUILD/EVAL fixtures, probes, three BUILD collectors,
and fixed structural comparators are unchanged.  The exact frozen APPLE6 unary
order is embedded as an additional comparator and verified by its SHA-256
`47bcaca7e350042cfa3283fbb89978b5fb7f2a50bc8b53e765750878da73f92b`.

For every exact replayed BUILD proof, the inference-event DAG is sliced first.
Base-constraint paths are then made transparent.  Each proof switch streams one
canonical exact edge from the latest of its nearest causal predecessor switch
events.  Roots and the latest conflict-facing terminal are streamed into their
own endpoint channels.  Eighteen BUILD proofs produced 4,189 predecessor-edge
events, 414 root events, and 18 terminal events.

The complete state is one fixed 113,570-byte `bytearray`:

```text
2-byte saturating proof-batch clock
+ 336 × 336 addressed uint8 directed-edge counters
+ 336 uint8 root counters
+ 336 uint8 terminal counters
```

The one frozen reader starts from frequent terminals, recursively emits the
strongest observed predecessor before its successor, then covers remaining
identities by incident edge support.  There is no threshold, sweep, gradient,
NN, target slot, EVAL feedback, or post-result reader change.  State and order
were frozen before the two disjoint EVAL targets were generated.

The decisive gate was intentionally stricter than APPLE6: raw held-out total
first-conflict switches had to be strictly below both the exact APPLE6 unary
total `1268` and the exact best fixed structural total `1031`.  A smaller proof
certificate could not pass the gate.

## Held-out result

| Scheduler | First-conflict switches, total / mean | Exact certificate switches, total / mean | First-pass constraint visits |
|---|---:|---:|---:|
| frozen proof-edge predecessor | **1,340 / 335.00** | 1,003 / 250.75 | **357,508** |
| exact APPLE6 frozen unary | 1,268 / 317.00 | **997 / 249.25** | 361,451 |
| early→final | 1,048 / 262.00 | 1,038 / 259.50 | 385,692 |
| final→early | **1,031 / 257.75** | 1,015 / 253.75 | 366,197 |
| deterministic public random | 1,332 / 333.00 | 1,027 / 256.75 | 354,085 |
| immediate public gain | 1,079 / 269.75 | 1,013 / 253.25 | 382,641 |
| immediate candidate gain | 1,048 / 262.00 | 1,038 / 259.50 | 385,692 |

The gate **fails plainly**:

```text
1340 > 1268 > 1031
edge     unary    best fixed
```

The learned order needs exactly 335 switches on all four held-out probes.  It
therefore loses not only to final→early and APPLE6 unary, but even to the public
random total of 1,332.  Lower constraint visits do not rescue the primary
metric.

The exact replayed edge certificates are `252, 249, 250, 252`, totaling 1,003.
That beats the fixed final→early certificate total 1,015 and is strictly smaller
than the best fixed structural certificate on three of four probes.  It still
loses to APPLE6 unary's 997.  More importantly, certificate-only gain was
prospectively forbidden from passing this experiment, so the decision remains
negative.

All 28 held-out wrong-candidate strategy passes rejected exactly.  Every sliced
certificate independently replayed to conflict.  Every held-out truth/strategy
control completed consistently.  Frozen-state SHA was identical before and
after EVAL.  The experiment recovers zero key bits and makes no entropy-reduction
claim.

## What failed mechanically

The failure is unusually localized.  All four learned passes close on identity
11 at position 335, leaving only identity 331 disabled.  In the frozen BUILD
state, identity 11 is an exact root in 12 proof batches, but it has zero incident
predecessor-edge support.  Identities 3 and 331 have the same pattern and occupy
positions 334 and 336.  The terminal-backward reader therefore places several
repeatedly necessary proof starts at the very end.

The state did retain useful dependency-core information: its 1,003-switch exact
certificate total remains below the best fixed structural 1,015.  But the
reader's edge-support priority erased the operational value of an isolated root.
In simple terms:

> A path is not only its arrows; it also needs a start marker that receives
> first-class scheduling credit.

This is the one preserved breadcrumb, not a post-EVAL rescue sweep.  A future
distinct experiment can prospectively test root-to-terminal path scheduling or
context-conditioned edge banks.  APPLE7 itself is closed on the frozen result.

An independent main-track result arrived only after this design was frozen:
O1C51's dominant unary delayed-credit group changed from `(143,144)` at W10 to
`(59,60)` at W11 when bit 177 became free.  It did not influence APPLE7, but it
converges on the same boundary: context-free unary credit can change meaning
when the causal situation changes.  This observation is interpretive only.

## Reproduction ledger

Reference run: 2026-07-19 03:35:58–03:37:23 CEST.

- BUILD: 3 targets, 6 wrong probes, 18 exact proof batches, 4,189 predecessor
  edges, 414 roots, and 18 terminals;
- frozen state: 113,570 bytes, 1,198 positive directed-edge addresses, SHA-256
  `b951eb1f01bfbe9e98d9c701041eb62e554e40adeb07c4376ba1e06050663241`;
- frozen order SHA-256:
  `b17c05c1a417c7e1978dad4c519bec68894988e50a81f686b00af1a235a14a84`;
- EVAL: 2 targets, 4 wrong probes, 7 schedulers, edge reader always first;
- 10,152,138 constraint visits, 68,920,592 truth-table rows, 46 exact proof
  replays;
- 83.777569 CPU seconds / 84.397724 wall seconds;
- 68,321,280 bytes peak process RSS;
- source SHA-256:
  `2e11e5984b24ccce0038960f2a65f8eead4958cfebb0259922a18229fe5ae2c2`;
- tests SHA-256:
  `72d718eb8ae8ecb5b08dfe50bcaff22fcd9843adf7ea14447ab0689e40d6d138`;
- result SHA-256:
  `c7c4355097b4f8e334f2700eab169e60c8c95d505cb1b17d2d529f77cbb3f533`;
- scientific payload SHA-256:
  `d6ae5f022ee5172a87660c9721839b0c880b83dc82a60e430ac052be05ba440a`.

The machine JSON contains every BUILD edge event, the complete frozen state and
order, all held-out passes and exact proof slices, truth controls, raw gate,
hashes, timestamps, and resource ledger.
