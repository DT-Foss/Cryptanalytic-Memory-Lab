# O1C-0026 — Proof-Ancestry Pair Residual

- **Recorded:** `2026-07-18T04:18:00+02:00`
- **Status:** conditional source design; no attempt reserved
- **Claim level:** `RETROSPECTIVE`
- **Upstream decision:** authoritative finalized `O1C-0023` only
- **Scientific inputs:** the four already-consumed O1C-0018 BUILD FAPs and the
  authoritative finalized O1C-0022 BUILD-LOO artifacts
- **Fresh targets, solver branches, entropy, MPS and GPU calls:** `0`

## Decision boundary

O1C-0026 may reserve an attempt only when all of the following are true:

1. `RunCapsuleManager.finalized_attempt("O1C-0023")` returns a complete,
   manifest-valid capsule;
2. its hash-bound `decision.json` and `next_operator_graph.json` agree on
   `operator.operator_id == "proof_ancestry_pair_residual_v1"`;
3. that decision names the authoritative finalized O1C-0022 result and capsule;
4. the O1C-0022 result has the all-real-primary-null reason surface that selected
   R07; and
5. the four BUILD FAPs are the exact members
   `artifacts/pools/build-0000.fap` through `build-0003.fap` of finalized
   O1C-0018.

A pending prerequisite, another selected operator, a failed upstream capsule or
any hash mismatch exits without an O1C-0026 reservation. Development FAPs are
never opened.

## Question answered

O1C-0022 asks whether its frozen unary 330D reader emits portable scalar packet
orientation. R07 asks the next distinct question:

> Does the already-public FAP contain target-portable orientation in interactions
> between the assumed key coordinate and proof-ancestry coordinates that the
> unary O1C-0022 scalar collapsed?

This is not another quantizer, vault or beam sweep. A pass finds a representation
missing from the unary reader. A clean null closes the interaction information
available in the current 330D summary and authorizes a richer proof sensor.

## Honest input boundary

Every FAP branch tensor is exact finite `float32[3,256,2,330]` with horizons
`[64,96,65]`. The available columns are:

| Half-open columns | Public field |
|---|---|
| `[0,10)` | nine `log1p` resource/proof scalars plus exact-conflict-present |
| `6` | `log1p_antecedent_link_count` |
| `7` | `log1p_maximum_ancestry_depth` |
| `9` | `exact_conflict_event_present` |
| `[10,74)` | 64D proof motif |
| `[74,330)` | 256D ancestry `key_touch` |

`key_touch[j]` is the normalized cumulative weight of proof-DAG nodes whose
ancestry mask touches key coordinate `j`. The FAP does **not** retain raw clauses,
literal signs, individual antecedent edges or exact pair co-occurrence. O1C-0026
therefore measures projected

```text
(assumed coordinate i) x (ancestry-touch coordinate j)
```

interactions. It must never label them raw antecedent pairs or signed clause
pairs. Branch polarity supplies the sign of the public contrast; it does not
reconstruct literal polarity discarded by FAP summarization.

## Frozen feature operator

Let `v[h,i,b,c]` be one FAP value for horizon `h`, assumption coordinate `i`,
branch `b in {0,1}` and column `c`. First apply the bounded transform

```text
psi(x) = x / (1 + abs(x))
odd(v)  = (psi(v[h,i,1]) - psi(v[h,i,0])) / 2
even(v) = (psi(v[h,i,1]) + psi(v[h,i,0])) / 2
```

Branch swap negates every `odd` vector and preserves every `even` vector.

For each `(h,i)`, form:

```text
odd_touch[j]  = odd(v[..., 74+j]), j != i
even_touch[j] = even(v[..., 74+j]), j != i

odd_context  = odd(v[..., [6,7,9,10:74]])   # 67 values
even_context = even(v[..., [6,7,9,10:74]])  # 67 values
```

The self-touch value `j=i` is zeroed before projection. No constant context is
added, so the primary feature cannot reduce to a free unary touch term.

### Fixed hash projection

Projection is frozen independently of every result and label. SHA-256 domains are

```text
o1c26/touch-sketch/v1\0
o1c26/context-sketch/v1\0
o1c26/pair-shuffle/v1\0
```

followed by fixed-width big-endian `(horizon_index, i, source_index)`. For touch
source `j`, the first digest byte modulo `16` gives its bucket and the low bit of
the second byte gives sign. Context source `c` uses eight buckets by the same
rule. There is no configurable seed.

For each horizon, compute 16D touch sketches and 8D context sketches, normalized
by `sqrt(255)` and `sqrt(67)` respectively. The primary residual row is

```text
concat_h(
    sketch(odd_touch)  outer sketch(even_context),
    sketch(even_touch) outer sketch(odd_context)
)
```

with shape `3 * 2 * 16 * 8 = 768` float64 values per target coordinate. Both
terms are polarity-odd. Repeating feature construction must be byte-identical;
actual branch swap must negate all 768 values to an absolute tolerance of
`1e-12` after float64 promotion.

The projection tables, column inventory, source FAP hashes and exact 768D feature
schema freeze before any BUILD label is read.

## Four-fold residual learning

O1C-0026 keeps the exact O1C-0022 outer folds. For held-out BUILD target `f`:

1. the other three BUILD FAPs are training rows;
2. `folds/build-ffff/calibration/raw_predictions.f64le`, the frozen O1C-0022
   normalized-float calibration scale and the three training labels reconstruct
   the same-reader training offsets;
3. the held-out offset is the K256 `normalized_float_delta_sum` slice of the
   frozen O1C-0022 calibrated prediction;
4. no held-out label is available while the projection, residual model,
   calibration predictions, residual scale and outer prediction freeze; and
5. only after persistence of that fold's prediction freeze is the consumed BUILD
   label opened for scoring.

For a feature matrix `X`, binary signs `y in {-1,+1}` and frozen offset logits
`o`, fit one deterministic offset-aware ridge residual:

```text
r = y - tanh(o / 2)
lambda = max(trace(X.T @ X) / 768, 2**-20)
w = X.T @ solve(X @ X.T + lambda * I, r)
raw_residual = X @ w
```

All operations use float64. A non-finite value or failed positive-definite solve
is an operational failure, not a scientific null.

Residual magnitude is calibrated without orientation reversal. Inside each outer
fold, three inner target-held-out fits generate one frozen residual prediction
for every training target. A 401-point grid `alpha in [0,2]` minimizes aggregate
training NLL of

```text
offset + alpha * raw_residual
```

using only those inner-held-out predictions; ties choose the smaller alpha. The
model is then refit on all three training targets and emits one outer-held-out
residual. No negative alpha is legal.

## Matched controls

Every learned control uses the same four outer folds, inner prediction lifecycle,
768 columns, ridge rule, alpha grid and source rows.

1. **`normalized_float_offset_only`** — unchanged O1C-0022 K256 normalized-float
   logit, with no fitted residual. This is the primary improvement baseline.
2. **`pair_identity_shuffled`** — before touch sketching, `key_touch[j]` is moved
   by one SHA-256-derived permutation fixed for `(h,i)` and shared by all four
   targets. Primitive values and work are unchanged; assumption-to-ancestry
   identity is broken.
3. **`additive_factorized_matched`** — each of the two outer-product blocks is
   replaced by `touch[a] + context[b]` at the same `(a,b)` position. It has the
   same 768 columns and fit work but no bilinear interaction.
4. **`polarity_even_common_mode`** — both blocks use only even touch and even
   context, with a fixed sign-balanced copy for the second block. It has identical
   dimensions and tests common-mode target difficulty rather than assumption
   orientation.

Two diagnostic ablations do not enter the pass gate: zero columns `9`
(exact-conflict gate) or `[10,74)` (motifs) before constructing the primary row.
They localize a positive primary result without selecting it.

## Result and gates

For each fold and arm, report full-key NLL, compression from the exact 256-bit
uniform baseline, correct bits, primary-minus-offset improvement and all matched
control margins. Also report the four alpha values, projection/model hashes and
the K256 O1C-0022 source offsets.

`PROJECTED_ANCESTRY_PAIR_RESIDUAL_PRESENT` requires all of:

- every lifecycle, hash, finiteness, branch-swap and zero-work invariant passes;
- primary compression is positive in all four held-out folds;
- mean primary compression is at least `+1.0` bit per key;
- primary improves on `normalized_float_offset_only` in all four folds;
- mean primary-minus-offset improvement is at least `+1.0` bit per key; and
- mean primary compression is strictly greater than each of
  `pair_identity_shuffled`, `additive_factorized_matched` and
  `polarity_even_common_mode`.

Otherwise a scientifically complete run is
`PROJECTED_ANCESTRY_PAIR_RESIDUAL_NULL`. Its result must retain these mutually
non-exclusive breadcrumbs:

- `primary_absolute_signal_null`;
- `outer_fold_nonportable`;
- `pair_identity_not_specific`;
- `bilinear_not_needed`;
- `common_mode_not_rejected`;
- `exact_conflict_ablation_material`; and
- `motif_ablation_material`.

A clean null closes only interaction information recoverable from the current
330D FAP summary. It does not close raw proof antecedents, literal-polarity pairs
or exact contradiction traces that were never present in the input.

## Work and state ceilings

The formal config should freeze these ceilings:

| Resource | Ceiling / exact requirement |
|---|---:|
| O1C-0018 BUILD FAPs opened | exactly `4` |
| DEVELOPMENT FAPs opened | exactly `0` |
| FAP branch-feature float32 values consumed | exactly `4*3*256*2*330 = 2,027,520` |
| projected target-coordinate rows | exactly `4*256 = 1,024` per arm |
| learned arms | exactly `4` including primary and three learned controls |
| ridge fits | exactly `4 folds * 4 arms * (3 inner + 1 outer) = 64` |
| alpha-grid NLL evaluations | exactly `4*4*401*3*256 = 4,927,488` bit evaluations |
| fresh targets / entropy / solver branches | exactly `0 / 0 / 0` |
| sibling writes / MPS / GPU | exactly `0 / 0 / 0` |
| CPU / wall | at most `180 / 240` seconds |
| peak resident memory | at most `512 MiB` |
| source artifact bytes read | at most `64 MiB` |
| persistent artifacts | at most `32 MiB` |
| one frozen residual weight vector | exactly `768` float64 = `6,144` bytes |
| retained primary deployment slow state | at most `8 KiB` |
| retained 256-logit posterior | exactly `2,048` bytes float64 |
| O1C-0021 vault state, if replayed | exactly `352` bytes |
| peak per-coordinate feature scratch | at most `16 KiB`, separately billed |

Projection tables are frozen model data, not live target state. No FAP tensor,
feature matrix, transcript or candidate dictionary may be retained as deployment
state. This attempt measures a reader representation on consumed BUILD data; it
does not claim an 8 KiB end-to-end attacker state until the frozen residual is
streamed into the vault under a later prospective design.

## Required artifacts

- `source_index.json`
- `o1c0023_decision.json`
- `projection_policy.json`
- `projection_freeze.json`
- `features/primary.f64le` and one feature tensor per learned control
- `folds/build-XXXX/inner_prediction_freeze.json`
- `folds/build-XXXX/model.f64le`
- `folds/build-XXXX/outer_prediction.f64le`
- `folds/build-XXXX/prediction_freeze.json`
- `post_freeze_labels.bitpack`
- `proof_ancestry_pair_residual_result.json`
- `structural_work_ledger.json`
- `artifact_index.json`

Feature tensors are retrospective audit artifacts, not deployment state. All four
outer predictions and their source/model commitments freeze before
`post_freeze_labels.bitpack` is materialized inside the capsule.

## Failure-memory transition

O1C-0023 uses the canonical failure-memory functions in
`o1c22_postresult_composer.py`, not the separate generic JSONL ledger in
`failure_memory.py`.

- A pass does not close the operator. Preserve its operator fingerprint and feed
  the frozen residual into a separately frozen vault/O1C-0024 handoff.
- A scientifically complete null becomes `outcome="NO_LIFT"` for the exact R07
  operator fingerprint and exact O1C-0022 result context.
- Resource, launch, persistence or lifecycle failure becomes
  `outcome="OPERATIONAL_FAILURE"` and must not close R07.

The updated failure memory cannot live inside O1C-0026 because its entry binds the
finalized O1C-0026 capsule manifest. After O1C-0026 finalizes, a later composer
attempt reads its authoritative manifest and result hash, calls
`record_operator_failure(...)`, and persists the new canonical memory. On a
clean null, that memory makes the next decision advance to
`exact_contradiction_antecedent_reader_v1` without repeating R07.

## Next transition

- **Pass:** freeze the pair-residual reader bytes and stream its 256 logits through
  the existing 352-byte addressed vault, then through O1C-0024's exact global
  frontier. No fresh target is authorized by this retrospective result alone.
- **Null:** stop fitting new readers to the collapsed 330D summary. The next sensor
  must preserve raw antecedent-edge/pair identity or exact contradiction events
  before `summarize_probe_prefixes` averages them away.
