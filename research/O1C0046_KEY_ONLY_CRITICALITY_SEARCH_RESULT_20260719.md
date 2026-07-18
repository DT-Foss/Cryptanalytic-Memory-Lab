# O1C-0046 — Key-only criticality search

- **Recorded:** 2026-07-19T00:24:50+02:00
- **Classification:** `KEY_ONLY_POTENTIAL_FAMILY_GAIN_WITHOUT_PRIMARY_MARGIN`
- **Source freeze:** `b0f8bcbd38fd5eb93d25712c1fd92fbeea5d18ae`
- **Target:** consumed O1C-0044 standard ChaCha20-R20 relation, all 256 key bits
  unknown in every attacker-valid Full-256 row

## Result

The change did what it was intended to do mechanically: all 447–500 potential
variables remain visible for conditioning, but the external scheduler can choose
only 126 designated key coordinates. It never externally decides a ChaCha
internal variable. The three O1C-0045 potential files are reused byte-for-byte;
the reader, target, residual sets, seed and 512-conflict cap are unchanged.

Full-256 remains unresolved in all four arms. On the explicit post-reveal
completion ceiling:

| Residual | Internal | Primary | Key rotation | Clause rotation |
|---:|---:|---:|---:|---:|
| 8 bits | SAT / 217 conflicts | SAT / 43 | SAT / 195 | SAT / 22 |
| 9 bits | UNKNOWN / 512 | SAT / 87 | SAT / 331 | SAT / 46 |

Every SAT model has Hamming distance zero from the consumed truth and
independently reproduces the public ChaCha20 output.

Compared with the O1C-0045 all-variable scheduler, primary drops from 152 to 43
conflicts at width 8 and from 281 to 87 at width 9. Its Full-256 external
decision requests drop from 26,712 to 6,591. This confirms that internal-variable
decisions were consuming substantial work. It does **not** recover the original
target-specific margin: the clause-rotated arm uses the identical 126-variable
decision set and remains better at both widths, 22 and 46 conflicts. The exact
frontier therefore stays at nine residual bits and no Full-256 key is recovered.

## Boundary and decision

- Full-256 search and attacker freeze precede reveal.
- Residual 8/9 rows use 247/248 truth-key units and are ceiling diagnostics, not
  attacker-valid recovered bits.
- No refit, fresh target, sibling access, MPS or GPU work occurred.
- Greedy local marginal branching is now closed in both all-variable and
  key-only forms. Preserve O1C-0044's transferred global rank signal, but next
  test it as bounded best-first key prefixes or score-aware factor activation
  rather than another local marginal scheduler.

## Cost and artifacts

- 7.767220 s elapsed; 122,552,320 B peak RSS
- 12 native calls; 6,144 requested conflicts
- 35,478 B persistent capsule payload
- Result SHA-256:
  `0f2ffeb436114a35aabf2d4dea7f5fe3ab7bdc2c37665539b1df97ee14fd562b`
- Attacker freeze SHA-256:
  `7dd7656728b70346d37796d1fc0cf8fc2d15f8760061fa5bd31187063bb9e308`
- Capsule manifest SHA-256:
  `54ddd2f32ca76708a1530be3cbfd1ade8d420ee324cb2bd68114035d674620ec`
- [Capsule](../runs/20260719_002450_O1C-0046_key-only-criticality-search-v1/RUN.md)
- [Machine-readable result](O1C0046_KEY_ONLY_CRITICALITY_SEARCH_RESULT_20260719.json)
