# O1C-0026 — Proof-Ancestry Pair Residual

- **Recorded:** `2026-07-18T04:18:00+02:00`
- **Status:** conditional proxy v2 source-frozen at `0af57fb`; no attempt reserved
- **Claim level:** `RETROSPECTIVE`
- **Upstream decision:** authoritative finalized `O1C-0023` only
- **Projection policy SHA-256:**
  `2e2c1e56d4a9db94a575337a74e6523fe300f05bc5a2b21228ecfd151f808a7f`
- **Scientific inputs:** the four already-consumed O1C-0018 BUILD FAPs and the
  authoritative finalized O1C-0022 BUILD-LOO artifacts
- **Fresh targets, solver branches, entropy, MPS and GPU calls:** `0`

The label-free structural probe is recorded separately in
`O1C0026_BUILD_ONLY_STRUCTURAL_PROBE_V2_20260718.md`. It validates real-FAP ABI,
control scaling and resources but is not an O1C-0026 scientific run or result.

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
never deserialized or exposed to scientific code. Whole-capsule byte hashing by
the authoritative `RunCapsuleManager.verify()` is integrity work and is billed
separately from a scientific FAP open; it cannot expose DEVELOPMENT tensors to
the operator.

## Question answered

O1C-0022 asks whether its frozen unary 330D reader emits portable scalar packet
orientation. R07 asks the next distinct question:

> Does the already-public FAP contain target-portable orientation in interactions
> between the assumed key coordinate and proof-ancestry coordinates that the
> unary O1C-0022 scalar collapsed?

This is not another quantizer, vault or beam sweep. A pass shows that this fixed
second-order inductive bias improves the frozen O1C-0022 scalar output. It does
not prove O1C-0019's gated nonlinear reader class was incapable of representing
the relation. A clean null closes only this exact v2 projected basis and
authorizes a richer proof sensor.

## Honest input boundary

Every FAP branch tensor is exact finite `float32[3,256,2,330]` with raw FAP
horizon order `[64,96,65]`. That order is distinct from O1C-0022's reader order
and must never be translated through an O1C-0022 horizon index. The available
columns are:

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

Each stored float32 value is promoted exactly to binary64 before `abs`, addition
or division; `psi`, odd/even decomposition, sketch accumulation and outer
products are all binary64 operations.

Branch swap negates every `odd` vector and preserves every `even` vector.

For each `(h,i)`, form:

```text
odd_touch[j]  = odd(v[..., 74+j]), j in 0..255
even_touch[j] = even(v[..., 74+j]), j in 0..255

odd_context  = odd(v[..., [6,7,9,10:74]])   # 67 values
even_context = even(v[..., [6,7,9,10:74]])  # 67 values
```

The self-touch value `j=i` is retained in a dedicated touch-sketch lane. This is
not a free unary feature: it enters the primary only through multiplication by
proof context. A BUILD-only, label-free audit found self-touch contrast to be
nonzero in `1610/3072 = 52.408854%` of coordinate/horizon cells with RMS
`0.005490716`, versus `84273/783360 = 10.757889%` and RMS `0.000622317` for an
off-diagonal cell. It is `4.87x` denser and `8.82x` stronger. Both the old
self-excluded projection and the retained-self projection have the same
`85/1024` genuinely branch-empty target-coordinate rows, all in BUILD-0000;
self retention preserves dense energy but does not manufacture coverage.

### Fixed hash projection

Projection is frozen independently of every result and label. SHA-256 domains are

```text
o1c26/touch-sketch/v2\0
o1c26/context-sketch/v2\0
o1c26/pair-shuffle/v2\0
```

followed by fixed-width big-endian `(horizon_index, i, source_index)`. For an
off-diagonal touch source `j`, the exact suffix is
`struct.pack(">HHH", horizon_index, i, j)`.
For context source column `c`, the same suffix contains the actual FAP column
number `c`, not its position in the 67-column subset. The first digest byte
modulo `15`, plus one, gives off-diagonal touch bucket `1..15` (modulo `8` for
context bucket `0..7`); an even second digest byte gives sign `+1` and an odd
byte gives sign `-1` for every source, including self. Touch bucket `0` is the
dedicated self lane. Horizon indices are exactly `0,1,2` for horizons
`[64,96,65]`. There is no configurable seed.

For each horizon, compute 16D touch sketches and 8D context sketches. After all
256 signed touch values accumulate, divide the complete 16D touch sketch by
`sqrt(256)=16`; divide the context sketch by `sqrt(67)`. This matched global
normalization participates in the matched v2 scheme, where the dedicated self
lane carries `17.682865%` of real BUILD feature energy. The rejected asymmetric
scheme that left self unscaled while normalizing off-diagonals assigned it
`98.22%`. The primary residual row is

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
4. that fold's held-out label is not supplied to its projection, residual model,
   calibration predictions, residual scale or outer prediction before freeze;
   historical use as a training target in another retrospective fold is
   explicitly recorded rather than denied; and
5. only after persistence of that fold's prediction freeze is the consumed BUILD
   label opened for scoring.

For a feature matrix `X`, binary signs `y in {-1,+1}` and frozen offset logits
`o`, fit one deterministic scale-invariant offset-aware ridge residual. Let
`s2 = sum(X*X)/768`. If `s2 == 0`, the raw prediction and weights are exactly
positive zero. Otherwise:

```text
r = y - tanh(o / 2)
Z = X / sqrt(s2)
u = Z.T @ solve(Z @ Z.T + I, r)
raw_residual = (X / sqrt(s2)) @ u
```

After alpha selection, persist the raw-space effective weight
`beta = alpha*u/sqrt(s2)`, so inference is simply `offset + X@beta`. The
standardized Gram matrix has condition number at most `769`. All operations use
float64. A non-finite value or failed positive-definite solve is an operational
failure, not a scientific null. Persisted weights are hashed products of the
frozen run; cross-BLAS recomputation is verified numerically, not claimed
byte-identical across platforms.

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
2. **`pair_identity_shuffled`** — for each `(h,i)`, sort all 256 touch
   coordinates by
   `SHA256(b"o1c26/pair-shuffle/v2\\0" + struct.pack(">HHH", h, i, j))` with
   `j` as the tie breaker. Move the value at sorted position `k` to the
   coordinate at position `(k+1) mod 256`, then sketch by the destination
   coordinate. This is a fixed-point-free permutation shared by all four
   targets. Primitive values and work are unchanged; assumption-to-ancestry
   identity is broken.
3. **`additive_factorized_matched`** — replace the first bilinear block by
   `odd_touch_sketch[a]/sqrt(8)` broadcast over all eight `b`, and the second
   block by `odd_context_sketch[b]/sqrt(16)` broadcast over all sixteen `a`.
   The extra factors remove repeated-column regularization bias. It has the same
   768 columns and fit work, remains exactly polarity-odd, and contains only
   unary additive main effects.
4. **`polarity_even_common_mode`** — the first block is
   `even_touch_sketch[a] * even_context_sketch[b] / sqrt(2)`; the second is the
   same magnitude multiplied by `+1` when `(a+b)` is even and `-1` otherwise.
   The checkerboard has exactly 64 signs of each kind per horizon and the two
   blocks retain matched total energy. This arm is branch-swap invariant, has
   identical dimensions and tests common-mode target difficulty rather than
   assumption orientation.

Four diagnostic ablations do not enter the pass gate: zero column `9`
(exact-conflict gate), zero columns `[10,74)` (motifs), zero touch lane `0`
(off-diagonal only), or zero touch lanes `1..15` (self only) before constructing
the primary row. They are inference-only: each outer fold applies its
already-frozen effective primary weight to the ablated held-out row. They
perform no ridge fit, alpha selection or model selection, and their feature
tensors are not persisted. They localize a positive primary result without
selecting it.

## Result and gates

For each fold and arm, report full-key NLL, compression from the exact 256-bit
uniform baseline, correct bits, primary-minus-offset improvement and all matched
control margins. Also report the four alpha values, projection/model hashes and
the K256 O1C-0022 source offsets.

`FAP_ANCESTRY_TOUCH_BILINEAR_PROXY_PRESENT` requires all of:

- every lifecycle, hash, finiteness, branch-swap and zero-work invariant passes;
- primary compression is positive in all four held-out folds;
- mean primary compression is at least `+1.0` bit per key;
- primary improves on `normalized_float_offset_only` in all four folds;
- mean primary-minus-offset improvement is at least `+1.0` bit per key; and
- mean primary compression is strictly greater than each of
  `pair_identity_shuffled`, `additive_factorized_matched` and
  `polarity_even_common_mode`.

Otherwise a scientifically complete run is
`FAP_ANCESTRY_TOUCH_BILINEAR_PROXY_NULL`. Its result must retain these mutually
non-exclusive breadcrumbs:

- `primary_absolute_signal_null`;
- `outer_fold_nonportable`;
- `pair_identity_not_specific`;
- `bilinear_not_needed`;
- `common_mode_not_rejected`;
- `exact_conflict_ablation_material`; and
- `motif_ablation_material`.

A clean null closes only `fap_ancestry_touch_bilinear_proxy_v2`: this exact
16-by-8 CountSketch, context inventory, normalization and residual learner. It
does not close other interactions of the 330D FAP, raw proof antecedents,
literal-polarity pairs or exact contradiction traces that were never present in
the input.

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
| inference-only ablation bit evaluations | exactly `4*4*256 = 4,096` |
| fresh targets / entropy / solver branches | exactly `0 / 0 / 0` |
| sibling writes / MPS / GPU | exactly `0 / 0 / 0` |
| CPU / wall | at most `180 / 240` seconds |
| peak resident memory | at most `512 MiB` |
| source artifact bytes read | at most `64 MiB` |
| persistent artifacts | at most `32 MiB` |
| one frozen residual weight vector | exactly `768` float64 = `6,144` bytes |
| retained primary deployment reader weights (`alpha*w` already folded) | exactly `6,144` bytes |
| retained 256-logit posterior | exactly `2,048` bytes float64 |
| O1C-0021 vault state, if replayed | exactly `352` bytes |
| accounted simultaneous NumPy payload | exactly `12,672` bytes |
| measured warmed process-local projection scratch | at most `14,529` bytes over all 256 primary coordinates, below the `16,384`-byte ceiling |

Projection tables are frozen model data, not live target state. No FAP tensor,
feature matrix, transcript or candidate dictionary may be retained as deployment
state. This attempt measures a reader representation on consumed BUILD data; it
does not claim an 8 KiB end-to-end attacker state until the frozen residual is
streamed into the vault under a later prospective design.

The source-only implementation may expose a bounded streaming inference state
containing exactly one immutable effective `float64[768]` weight vector with
`alpha` already multiplied in and one mutable `float64[256]` posterior: exactly
`8,192` live bytes total. It must construct one coordinate row at a time and
discard it immediately. Projection tables and immutable metadata are model
data, not live target state. That implementation is an instrument, not an
O1C-0026 attempt or scientific result, until the authoritative O1C-0023
selection gate and finalized-capsule checks above pass.

## Required artifacts

- `source_index.json`
- `o1c0023_decision.json`
- `projection_policy.json`
- `projection_freeze.json`
- `features/primary.f64le` and one feature tensor per learned control; no
  diagnostic-ablation feature tensor
- `folds/build-XXXX/inner_prediction_freeze.json`
- `folds/build-XXXX/models.f64le` with exact shape `float64le[4,768]` in learned
  arm order `[primary,pair_identity_shuffled,additive_factorized_matched,
  polarity_even_common_mode]`; each row already contains `alpha*w`
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
`failure_memory.py`. O1C-0026 is explicitly a collapsed-FAP proxy below R07,
not the raw signed-pair/exact-antecedent sensor named by R07 itself.

- A pass does not close the operator. Preserve its operator fingerprint and feed
  the frozen residual into a separately frozen vault/O1C-0024 handoff.
- A scientifically complete null records a local
  `fap_ancestry_touch_bilinear_proxy_v2` no-lift breadcrumb. It must **not** call
  `record_operator_failure(...)` on the parent R07 fingerprint, because the FAP
  lacks the signed literals, raw pair co-occurrences and antecedent edges that
  R07 names.
- Resource, launch, persistence or lifecycle failure becomes
  `outcome="OPERATIONAL_FAILURE"` and must not close R07.

Any parent failure-memory update cannot live inside O1C-0026 because it would
both bind the finalized O1C-0026 manifest and over-close R07. After a clean
proxy null, a later composer may advance *within* R07 to
`exact_contradiction_antecedent_reader_v1`, while retaining R07 as unclosed. A
future exact raw-pair sensor, not this proxy, is responsible for closing that
parent fingerprint.

## Next transition

- **Pass:** freeze the pair-residual reader bytes and stream its 256 logits through
  the existing 352-byte addressed vault, then through O1C-0024's exact global
  frontier. No fresh target is authorized by this retrospective result alone.
- **Null:** stop fitting new readers to the collapsed 330D summary. The next sensor
  must preserve raw antecedent-edge/pair identity or exact contradiction events
  before `summarize_probe_prefixes` averages them away.
