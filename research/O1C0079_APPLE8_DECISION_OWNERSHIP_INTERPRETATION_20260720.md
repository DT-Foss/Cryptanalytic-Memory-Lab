# O1C-0079 — APPLE8 decision-ownership interpretation

- **Started:** 2026-07-20T08:57:38+02:00 (`Europe/Berlin`).
- **Raw result recorded:** 2026-07-20T08:58:18+02:00.
- **Erratum recorded:** 2026-07-20T09:13:16+02:00; zero solver calls.
- **Corrected classification:**
  `DECISION_OWNERSHIP_QUALIFIED_PREFIX_MECHANISM_ONLY`.
- **Corrected stop:** `qualified-prefix-activation-without-science-gain`.
- **Execution commit:** `8b058cbfe62d93d0263a275f4081982f382a4355`.
- **Corrected validator commit:**
  `665ea8260ae7127baabc83af2fe208080f6f58f9`.
- **Capsule:**
  [`runs/20260720_085738_O1C-0079_apple8-decision-ownership-v1`](../runs/20260720_085738_O1C-0079_apple8-decision-ownership-v1/RUN.md).
- **Seals:** immutable raw result SHA-256
  `ce68d10eed83d9a0d90518c579f4e1841cd8a6791e4cd975d0d27a64bcc6251e`;
  capsule artifact-manifest SHA-256
  `f7cd0de5ba58a59de913db88ba3e9ce2ae1b486a4e922700f65dff3aa5d39475`;
  zero-call erratum SHA-256
  `b5c2465a532486aaf68a6a622f2312de29ec8a52ea6cea70c9d9c36f19985fa9`.

## Result and archival correction

O1C-0079 consumed its sole fresh Page-6/local-0/lineage-19 call and returned a
complete native result. Central decision-instance ownership and the unchanged
11-row prefix both activated; the call produced no cryptanalytic science gain.

The immutable raw result instead records
`DECISION_OWNERSHIP_NO_ACTIVATION_NO_GAIN`. That classification is false for one
isolated validator reason: the archived validator searched all serialized native
text for `returned-ever` and matched the positive eligibility descriptor
`origin-row-level-token;never-returned-ever-plus-variable-sign`. It therefore
set `old_returned_ever_runtime_absent=false` even though the evidence identifies
the new central runtime and rule exactly.

The corrected validator checks four explicit runtime identities: native and
central parent schemas, the eligibility rule and the assignment-notification
rule. Revalidation of the already archived canonical evidence gives:

| Axis | Raw archived field | Corrected conclusion |
|---|---:|---:|
| Operational decision ownership | false | **true** |
| Qualified prefix activation | false | **true** |
| Cryptanalytic science gain | false | **false** |

No solver, truth, reveal, target, refit, MPS or GPU call was made for the
correction. The raw result, capsule, compressed evidence and manifest remain
byte-for-byte unchanged. The canonical
[`zero-call erratum`](O1C0079_APPLE8_DECISION_OWNERSHIP_ZERO_CALL_ERRATUM_20260720.json)
is the authority for the corrected classification; it does not replace or
rewrite the historical result.

## Exact ownership evidence

All `549` nonzero proposals were immediately bound to solver levels and all
`549` were retired. The ledger contains `547` confirmed releases and two
level-bound unobserved releases, with zero live tokens and zero omitted events.
The two non-eager cases are direct witnesses for the repaired lifecycle:

| Token | Owned proposal | Terminal state | Later assignment |
|---:|---:|---|---|
| 75 | `-108` | level-bound unobserved release | `+108`, `FOREIGN`, token 0 |
| 110 | `-112` | level-bound unobserved release | `+112`, `FOREIGN`, token 0 |

Across the call, `9,966` assignments are classified foreign and zero opposite
assignments claim an owned token. Proposal, binding and release totals are
equal; no stale historical proposal releases a later assignment. This satisfies
the predeclared operational gate and directly repairs the lifecycle alias that
terminated O1C-0078.

Origin accounting is also total:

- rank original and contrast each bind and release `254` tokens;
- frontier initial and contrast each bind and release `16` tokens;
- prefix binds and releases `9` tokens;
- the central reader makes `1,587` callbacks: `549` nonzero and `1,038` zero.

## Qualified prefix activation

The exact unchanged prefix consumes all `11` rows before the first non-prefix
decision. Nine rows become owned level-bound decisions and are released; two are
already assigned in the falsifying direction. There are zero preassigned-rescue
skips. Every bound prefix token retires consistently, the native result returns,
and trace SHA-256
`038e9b874c522c6b07cb4829484fce3d8b13f757dd94240a4883a478ed51c3ec`
differs from O1C-0077's frozen
`706ad4fa13a8a47cd81f99bc693c1bede46612112214e6f77dc52ee61d32bf15`.
These facts pass the precommitted qualified-prefix gate. They establish a search
mechanism, not useful key evidence.

## Science and work boundary

The minimum visited-trail upper bound is `18.742222666780805` against
`tau=14.606178797892962`, a gap of `4.136043868887843`. The call records zero
safe threshold prunes, zero emitted or globally novel clauses, zero complete
models, zero public keys and no other sub-256 progress. O1C-0068 remains
untouched.

Compared with O1C-0077, decisions rise `884→1,587` while propagations fall
`4,754,555→468,611` (`-90.14%`). O1C-0077's minimum UB was
`14.656823218163392`; the O1C-0079 minimum moves away from the threshold. These
whole-call differences use successive residency pages and are operational
telemetry, not a same-input causal estimate or a science gain.

The call uses exactly `128/128/128` requested, actual and billed conflicts with
no retry. Native work is `176,794 us` wall, `994,976 us` CPU and
`390,922,240 B` peak RSS. Runner elapsed time is `40.11452975 s` at
`330,285,056 B` peak; the complete command, including preflight, is `80.96 s`.
No swaps occur.

## Decision and successor

Stop the qualified-prefix path: ownership is operationally repaired and the
prefix mechanism activates, but it yields no prune, clause, model or sub-256
gain. Never retry Page 6 or lineage 19, and do not refit the prefix.

The next distinct proposal is O1C-0080, a Page-7 exact one-bit bound-crossing
reader. Advance the unchanged 550-clause attic after the real Page-6 activation
with `advance_causal_residency`, `fully_emitted_union_indices=()` and lineage 20.
The deterministic identity-bound empty rollover receipt/chunk is required; it
contains no fabricated clause, occurrence or emission. The provisional active
Page 7 is `256` clauses / `663,409` literals, SHA-256
`92b6e547e143cdaf2f28fe731fd356bc69806926ee569205d6def432144258ff`,
with selection-order SHA-256
`776819396914179fe1a0ae9b443a6c0775e32c70bf36658b6dfe7043002dc723`.

Hold the public instance, scorer, threshold, K256 projection, seed and
128-conflict horizon fixed. For one candidate bit at one parent trail, compute
both exact child bounds `U0` and `U1`; intervene only when
`min(U0,U1)<tau` and the comparison certifies either an asymmetric threshold
crossing or both children below threshold. The science gate remains an actual
safe prune, certified closure, globally novel clause or public verified model.
A depth-2 fallback is eligible only after a genuine measured near-crossing, not
as a blind expansion. No O1C-0080 science call is authorized yet.

## Artifact boundary

- [`Raw result`](O1C0079_APPLE8_DECISION_OWNERSHIP_RESULT_20260720.json) —
  immutable SHA-256
  `ce68d10eed83d9a0d90518c579f4e1841cd8a6791e4cd975d0d27a64bcc6251e`.
- Native gzip/uncompressed SHA-256:
  `ec75d6c336d9dbfeb243f9992f624c8c3a71cdb0b1322bc0a713076911aa0f65`
  / `acda128d4a4ebc32376de7fce3ef40de72e20539befebe56eaea4276a43fd283`.
- Ownership gzip/uncompressed SHA-256:
  `6403d8a674a5c563eb8e30fdcaabb5745122654a234dd1cb0b2ef77f90de34e3`
  / `87e6476486fa02624fab9b6b6f84c00dded60fbcefef871475201439849d4a0b`.
- [`Design`](O1C0079_APPLE8_DECISION_OWNERSHIP_DESIGN_20260720.md) and
  [`zero-call erratum`](O1C0079_APPLE8_DECISION_OWNERSHIP_ZERO_CALL_ERRATUM_20260720.json),
  SHA-256
  `b5c2465a532486aaf68a6a622f2312de29ec8a52ea6cea70c9d9c36f19985fa9`.
