# O1C-0022 Artifact-Causal Vault BUILD-LOO design

- **Frozen intent date:** 2026-07-18
- **Attempt:** `O1C-0022`
- **Claim level:** `RETROSPECTIVE` architecture/observability gate
- **Solver work:** zero new branches; reuse four immutable O1C-0018 BUILD action
  pools only
- **Execution prerequisite:** the reserved, finalized O1C-0019 capsule and its four
  fold-local frozen readers
- **Scientific boundary:** all 256 ChaCha20 key bits remain unknown at inference;
  the `12/52/128/256` ladder changes only how many public coordinate sensors are
  observed

## Decision

O1C-0022 joins the corrected incremental O1C-0019 proof reader to the exact
addressed O1C-0021 vault contract.  It does not invent a new hand-ranked proof
scalar and does not ask the synthetic O1C-0021 coefficient reader to reinterpret
real evidence.  The upstream O1C-0019 reader emits its native incremental

```text
q_after(bit, horizon) - q_before(bit, horizon)
```

for paired public `k_i=0/1` proof-prefix observations.  A label-free frozen
quantizer converts those deltas to small signed integers, which are accumulated
in the 256-coordinate int8 vault.  The O1C-0019 target-local reader state and the
352-byte downstream accumulator are accounted separately; only the downstream
vault is claimed to be 352 bytes.

Before freezing that decision, a 1.5-second exact rerun tested the tempting
handcrafted alternative: 4 rank regimes x 8 manually summed feature families,
with leave-one-BUILD-out beta-binomial orientation and three smoothing values.
Every width and every smoothing value had negative code-length gain. The least
negative post-hoc member (`alpha=16`) reached `519/1024` aggregate bits at K=256
but lost `213.404152` bits. This is an exploratory negative breadcrumb, not a
frozen efficacy attempt. Its complete inputs, formulas, variants, metrics and
intermediate hashes are recorded in
[`O1C0022_HANDCRAFTED_SCALAR_DIAGNOSTIC_20260718.json`](O1C0022_HANDCRAFTED_SCALAR_DIAGNOSTIC_20260718.json).

```text
public Full-Round FAP [3,256,2,330]
        |
        v
frozen fold-local O1C-0019 incremental reader
        |
        +-- float q_after-q_before ceiling
        |
        v
BUILD-public per-horizon median-|delta| quantizer
        |
        v
O1C-0021 CausalEvidenceState
80-byte fast-state reservation + 256-byte int8 vault + 16-byte counters
        |
        v
frozen 256-bit posterior / NLL / rank diagnostics
```

## Public input and lifecycle

For held-out fold `f`, only these artifacts may be loaded before prediction
freeze:

1. the verified O1C-0018 action-pool corpus;
2. `folds/build-XXXX/reader.bin` from finalized O1C-0019;
3. its exact `learning_freeze.json` receipt;
4. the committed O1C-0022 config and source bytes.

The reader was trained by O1C-0019 on the other three BUILD episodes.  O1C-0022
replays those three public pools through the already-frozen reader solely to fit
one magnitude scale per horizon.  The scale is the median finite nonzero
absolute delta, with deterministic fallback `1.0`.  It consumes neither labels
nor signed rewards.  Every held-out delta, scale, state, arm prediction and hash
is persisted before `labels_after_prediction_freeze()` is called.

## Nested width intervention

One domain-separated SHA-256 permutation supplies a single nested coordinate
order.  Fresh reader fast state is used for each prefix:

| Active public sensors | Packet slots | Exact public work |
|---:|---:|---:|
| 12 | 36 | 2,304 |
| 52 | 156 | 9,984 |
| 128 | 384 | 24,576 |
| 256 | 768 | 49,152 |

Each coordinate is streamed locally in O1C-0019's frozen ordered horizons
`64 -> 65 -> 96`.  The work is `2 * maximum_horizon * K = 192K`; no secret bit
is fixed, exposed or removed.  The ladder therefore discriminates
cross-coordinate interference from evidence absence without retreating to a
reduced-key cipher.

Across four folds, quantizer training consumes `9,216` packet slots and the four
held-out width ladders consume `5,376`. One actual polarity-swapped K=256 replay
per fold contributes another `3,072` slots. The exact total is therefore
`17,664` reader slot observations and `1,130,496` public work units. They are
artifact replays, not new solver branches.

## Quantized update

For horizon scale `s_h > 0` and finite reader delta `d_h`, O1C-0022 freezes

```text
q_h = clip(sign(d_h) * floor(abs(d_h / s_h) + 0.5), -8, 8)
```

and skips exact zero updates.  A coordinate-local packet group applies all three
horizon updates atomically.  Its identifier commits to the schema, public pool,
reader, active-set and coordinate.  An immediate repeat of that identifier must
leave all 352 serialized state bytes unchanged.  This is a bounded one-group
duplicate guard, not an unbounded deduplication index.

## Matched arms and bottleneck interpretation

| Arm | What it isolates |
|---|---|
| `raw_float_delta_sum` | exact unscaled compounding emitted by the frozen reader |
| `normalized_float_delta_sum` | pre-quantization ceiling after label-free horizon scaling |
| `quantized_int8_vault` | bounded addressed retention of the same deltas |
| `last_horizon_only` | whether compounding adds anything beyond the deepest packet |
| `unit_sign_sum` | whether learned magnitude/confidence matters |
| `coordinate_shuffled_vault` | coordinate binding and target-specific address control |
| `zero_prior` | exact 256-bit random-posterior baseline |

The exact already-frozen O1C-0019 `learned_reader_exhaustive` K=256 posterior is
also imported and hash-verified as a source anchor. It is not refit and does not
participate in the width-gate calibration; it tells whether the adapter improves
or damages the upstream packet posterior.

Each nonzero arm receives its own single nonnegative scalar selected on the
three non-held-out BUILD labels by a frozen 401-point grid over `[0,2]`; ties use
the smaller scale and sign reversal is forbidden. This is posterior calibration,
not quantizer fitting. It prevents arbitrary raw logit magnitude from deciding
the NLL gate while preserving the question of whether O1C-0019 learned the
correct orientation. In this retrospective LOO corpus a label may already have
been opened as training data in another fold; the hard boundary is fold-local:
the current held-out ordinal is absent from that fold's calibration-label ledger,
and its scale and prediction artifacts freeze before its label is used there.

Interpretation is mechanical:

- float and int8 both null: no portable real packet orientation;
- float positive, int8 null: quantization or saturation failure;
- small `K` positive and large `K` null: reader-state interference/dilution;
- vault positive but O1C-0019 picker null: sensing works and policy credit/routing is
  the remaining bottleneck;
- shuffled/unit/last control wins: address, confidence or independent compounding
  claim fails respectively.

The predeclared promotion gate requires positive K=256 compression in all four
folds, at least `+1.0` mean bit, strict mean growth across the width ladder,
positive K=256 margins over the coordinate-shuffled, unit-sign and last-horizon
controls, and retention of at least 90% of positive float compression. Integrity
failures override efficacy.

## O1-O boundary

O1-O's `.causal` files are deterministic MessagePack triplet graphs used for
intent routing and fragment selection; they do not numerically execute a state
transition.  O1C-0022 therefore adds a literal, isolated O1-O-compatible graph
envelope plus a byte-exact public-FSM executor as a control path.  It must encode

```text
b"CAUSAL" || uint16_be(1) || zlib(msgpack(graph))
```

and replay the 64-byte `[4,8,2]` O1C-0021 table into the exact 273-byte public
FSM state.  This proves deterministic composition/export/replay parity; it is
not counted as new cryptanalytic evidence.  The authoritative graph is exported
only after O1C-0021's formal table exists.

## Direct resume

1. Finish and source-freeze the adapter, O1-O control, config and focused tests.
2. Leave O1C-0019's existing watcher as the sole launcher while W52 is active.
3. After finalized O1C-0019 exists, run O1C-0022 once from a clean commit.
4. If the K=256 reader/vault gate passes, attack one untouched O1C-0018
   DEVELOPMENT pool under a new prospective O1C identity; otherwise change only
   the stage localized by the width/control matrix.
