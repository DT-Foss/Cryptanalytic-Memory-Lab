# O1C-0051 — delayed pair-credit W11 promotion

- **Started:** 2026-07-19T03:32:51+02:00
- **Recorded:** 2026-07-19T03:32:57+02:00
- **Source commit:** `652d2c62be236cb421ecac86a6d09a6f65156dd3`
- **Classification:** `DELAYED_PAIR_CREDIT_NO_EXACT_W11_CLOSE`
- **Gate:** failed (`no-exact-delayed-primary-w11`)
- **Boundary:** consumed Full20 target, post-reveal W11 with 245 correct key
  bits fixed; one 512-conflict call, no fresh target/sibling/GPU/MPS work
- **Resources:** 5.6889655 s wall, 128,335,872 B peak RSS

## Result

| Delayed primary | Status | Exact key | Conflicts | Decisions | Propagations |
|---|---|---:|---:|---:|---:|
| O1C-0050 W10 | SAT | yes | 302 | 307 | 7,141,980 |
| O1C-0051 W11 | UNKNOWN | no | 512 | 513 | 11,983,327 |

The prospective gate required a SAT model that matched both the independently
verified public target and the revealed truth key while honoring the fixed W11
prefix. The sole delayed-primary call returned `UNKNOWN` at the unchanged cap,
so telemetry and wall time could not pass. The runner then closed exactly as
frozen: static-primary W11, both delayed W11 rotations and all three delayed
Full256 calls were skipped. Current work is one native call and 512 requested
conflicts, not the seven-call promotion maximum.

## Localized mechanism boundary

The same 1,134-byte owner state still assigns every conflict-bearing backtrack
to an undone pair owner, but its dominant group changes abruptly when W11 frees
bit 177:

| Pair group | W10 conflict-owner undos | W11 conflict-owner undos |
|---|---:|---:|
| `(143, 144)` | 227 | 1 |
| `(59, 60)` | 55 | 382 |

O1C-0050 therefore remains a real W10 exact-work gain, but its scalar unary
group credit does not extend the exact frontier. Group `(59,60)` is penalized on
382 conflict-owner undos, yet all four pair masks share that one group credit;
the native rule still selects the raw top pattern and 502 of 513 decisions are
repeats. The result localizes action/polarity and context blindness, but does not
establish that any specific contextual model will pass.

Close the unchanged delayed-unary scheduler on these disjoint pairs. The only
warranted successor keeps the same groups and 512-conflict cap while testing
bounded context/action-conditioned credit. The cheapest discriminator is one
separate credit for each of four pair patterns across 63 groups (`4×63`), not a
weight sweep or a presumed static predecessor edge.

Authoritative JSON SHA-256:
`aa8fec70d1f97d7a127791699c5340db28168389beeeab32c70d2b1b3121c058`.
