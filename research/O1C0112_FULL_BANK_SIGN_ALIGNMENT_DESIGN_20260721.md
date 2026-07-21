# O1C-0112 — Frozen full-bank sign-alignment design

- **Frozen before historical truth access:** 2026-07-21 (`Europe/Berlin`).
- **Parent result:** O1C-0109, SHA-256
  `22ec1c6a2f67c0ec89c85347865c4fc248c43ad2dacc8955fd76a72940a52c28`.
- **Final living bank:** 24,576 bytes, SHA-256
  `efffdc2021d3c62bd92e4557a8515f1728bd3350582010b0b4a90a0d2fc65951`.
- **Prior bank:** 24,576 bytes, SHA-256
  `62360d82b191b2e323c7205d950651ac1ad592cc9365892bf5c58d932b64087f`.
- **Calls:** zero solver, native, target-generation, refit, MPS or GPU calls.
  The only later truth access may be the already sealed historical O1C-0057
  reveal, after source, tests, config and canonical score freeze are sealed.

## Why this freeze precedes O1C-0111 reveal

O1C-0111 sees only the two coordinates at which a threshold crossing was locally
prunable. The existing O1 living bank already holds bounded sufficient statistics
for 255 coordinates across 449,663 paired child-bound observations. Opening the
historical truth before freezing this reader would destroy the clean pre-truth
status of a much broader measurement. O1C-0112 therefore freezes first; afterward
O1C-0111 and O1C-0112 may use the same single broker-verified historical reveal.

## Exact input geometry

Both banks are decoded as 256 variable-ordered records using the existing
`<QddQQddQQddd` little-endian 96-byte ABI. Each record contains count, raw and
parent-centered moments/sign counts, and robust-z moments. Semantic validation
is identical to the production adapter: finite moments, nonnegative M2, valid
sign partitions and absolute-z ordering. Variable 241 / coordinate 240 is the
only zero record and is an abstention; the other 255 coordinates are evaluated.

Pre-truth census of the final bank:

- count sum 449,663; 255 nonzero records;
- `raw_mean`: 245 positive / 10 negative / zero exact zeros;
- `centered_mean`: 112 positive / 143 negative / zero exact zeros;
- `robust_z_mean`: 113 positive / 142 negative / zero exact zeros.

The O1C-0109 increment is reconstructed from the prior/final sufficient
statistics without replay: 33,569 observations over the same 255 coordinates,
with per-coordinate counts from 1 through 534.

## Frozen primary reader

For every nonempty coordinate `v`, define the bit-1 evidence score

`S_v = -final.robust_z_mean_v`.

Predict bit 1 when `S_v > 0`, bit 0 when `S_v < 0`, and abstain only when the
score is exactly zero or the record is empty. This orientation is fixed before
truth access and follows the same `U1-U0` convention as O1C-0111: positive
bit-1 evidence corresponds to a lower relative bit-1 child bound. No global or
coordinate-wise sign inversion is allowed after reveal.

The primary arm alone determines classification. It is the cumulative living
state, not the newest batch, because the moonshot hypothesis is that evidence
compounds across the stream.

## Frozen secondary arms

The following diagnostics are reported but cannot rescue or change the primary:

1. `-final.centered_mean`;
2. negative final centered signed consistency;
3. `-final.raw_mean`;
4. negative O1C-0109 increment robust-z mean;
5. negative O1C-0109 increment centered mean;
6. negative O1C-0109 increment raw mean.

For a field mean, the increment is reconstructed in binary64 as
`fsum([N_final * mean_final, -N_prior * mean_prior]) / (N_final-N_prior)`.
No secondary choice, combination, calibration, width sweep or post-reveal
selection is authorized by this attempt.

## Measurements and controls

Use the project's RFC little-bit-within-byte mapping from
`living_inverse.key_bits`. Report for every frozen arm:

- evaluated coordinates, abstentions and correct-bit count;
- exact one-sided fair-coin binomial tail;
- identity weighted alignment `sum(truth_spin_v * S_v)`;
- all 255 nonidentity cyclic truth-coordinate rotations plus identity, with
  conservative tie rank;
- global sign-flip alignment and strict margin;
- exact bytes among the 31 fully predicted bytes and exact 16-bit words among
  the 15 fully predicted words; the incomplete coordinate-240 byte/word is
  excluded, never filled from truth.

No calibrated NLL, posterior entropy or beam claim is permitted because the
score scale has not been prospectively calibrated.

## Frozen classification ladder

Only the primary arm may trigger these tiers:

1. `RETROSPECTIVE_FULL_BANK_DIRECTIONAL_SIGNAL` requires at least 240 evaluated
   coordinates, one-sided binomial tail at most 0.01, cyclic-rank fraction at
   most 0.05, and positive identity-over-sign-flip margin.
2. `RETROSPECTIVE_FULL_BANK_BIT_ADVANTAGE_BREADCRUMB` requires at least 240
   evaluated coordinates, one-sided binomial tail at most 0.05, and positive
   identity-over-sign-flip margin, while failing the stronger tier.
3. Otherwise classify `RETROSPECTIVE_FULL_BANK_NO_DIRECTIONAL_ALIGNMENT`.

For 255 evaluated coordinates the first two bit-count thresholds are 147 and
142 correct respectively, but the exact rational tails remain authoritative.
Even the strongest tier is retrospective and authorizes only an unchanged
prospective reader on fresh output-only targets. It is not itself attacker-valid
entropy reduction, independent recovery, a posterior, a beam hit or a SOTA
recovery claim. A null result closes this exact sign reader but preserves the
bank as a proven bounded proof-mining memory and motivates a different learned
binding, not post-hoc sign reversal.

