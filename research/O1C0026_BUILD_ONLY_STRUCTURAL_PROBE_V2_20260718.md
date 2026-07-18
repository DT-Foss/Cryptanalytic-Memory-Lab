# O1C-0026 BUILD-only structural probe v2

- **Recorded:** `2026-07-18T05:31:51+02:00`
- **Status:** source instrument validated; no attempt reserved
- **Claim level:** `RETROSPECTIVE_STRUCTURAL_ONLY`
- **Policy:** `2e2c1e56d4a9db94a575337a74e6523fe300f05bc5a2b21228ecfd151f808a7f`
- **Machine path:** CPU-only; no solver, entropy, MPS or GPU

## Outcome

The dedicated-self v2 projection works on all four real 256-bit BUILD FAPs and
keeps its identity-shuffled control genuinely matched:

| Metric | Primary | Pair-shuffled |
|---|---:|---:|
| Shape | `1024 x 768` | `1024 x 768` |
| RMS | `1.0497150e-5` | `1.0405888e-5` |
| Nonzero values | `54.4923%` | `52.7098%` |
| Zero coordinate rows | `85` | `85` |

The RMS ratio is `1.00877`, cosine similarity is only `0.02759`, and the two
arms are byte-identical in exactly the `85` genuinely branch-empty rows. Thus
the control preserves scale and primitive work while destroying pair identity;
it is not a disguised duplicate of the primary.

## Self-touch breadcrumb

Across the same BUILD-only raw pools, binary64 `psi`-odd self-touch is nonzero in
`1610/3072 = 52.408854%` of horizon-coordinate cells with RMS
`0.005490716`. One off-diagonal cell is nonzero in
`84273/783360 = 10.757889%` with RMS `0.000622317`. Self is therefore `4.87x`
denser and `8.82x` stronger than an individual off-diagonal cell.

The v2 operator retains that energy in bucket zero but divides the complete
16D touch sketch by `sqrt(256)`. Self is still only exposed through
`self_touch x proof_context`; it is not a free unary feature. Retaining self does
not rescue the 85 rows whose paired branches contain no interaction input.

## Resource receipt

- source bytes read: `8,231,208`
- DEVELOPMENT FAPs / labels opened: `0 / 0`
- complete primary plus shuffled projection wall time: `1.609594 s`
- process peak RSS: `105,955,328` bytes (`101.05 MiB`)
- deployment live state remains exactly `6,144 + 2,048 = 8,192` bytes; the
  measured RSS includes Python, NumPy, deserialized audit tensors and two
  retrospective matrices and is not deployment state
- accounted simultaneous NumPy payload is `12,672` bytes; a warmed
  256-coordinate `tracemalloc` probe measured a maximum `14,529` bytes of
  process-local projection scratch,
  below the frozen `16,384`-byte ceiling

## Claim boundary

This is a mechanism and resource result, not a learned key-signal result. No
BUILD label, O1C-0022 offset or ridge model was opened or fitted. The formal
four-fold test remains gated on authoritative finalized O1C-0022/O1C-0023
artifacts and W52 resource availability. A future null closes only
`fap_ancestry_touch_bilinear_proxy_v2`, never parent R07 or all possible FAP
interactions.
