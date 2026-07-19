# O1C-0070 — APPLE8 vault-conditioned phase-reader interpretation

- **Recorded:** 2026-07-19T18:11:03+02:00 (`Europe/Berlin`).
- **Classification:** `EPISODIC_VAULT_ACTIVE_PHASE_READER_NO_GAIN`.
- **Source:** `c5ad5c40f0ac84f65d281cf2366d2ca6b6c49a52`.
- **Capsule:**
  [`runs/20260719_181048_O1C-0070_apple8-vault-phase-reader-v1`](../runs/20260719_181048_O1C-0070_apple8-vault-phase-reader-v1/RUN.md).
- **Seals:** authoritative result SHA-256
  `778d2b91935ff2ae663ea706e5b7b66c8cfed2f02007ba8359e8c1cb7ff45cd7`;
  capsule manifest SHA-256
  `ca5e0dfc724dc541b5311e2fc1453fc017f4ccd562d510aad341a53188d194c2`.

## Result

The sole authorized local-ordinal-`0`/lineage-ordinal-`6` call imported the
sealed 202-clause O1C-0069 vault and applied the target-free phase field derived
from O1C-0068's exact 190-clause suffix. The field supplies `139` positive and
`116` negative per-variable phases; unsupported variable `241` retains the
verified phase-1 fallback. Native code made `255` phase calls with seed `0`.
This reader changes polarity only: it controls neither variable order nor
confidence magnitude.

The call requested `512` conflicts and observed/billed `514` (`+2` soft-limit
overshoot). It returned `UNKNOWN`, emitted `0` eligible clauses and therefore
recorded `0` novel and `0` duplicate clauses. No model or key was returned. The
input and output vaults are byte-identical at `202` clauses / `599,728` literals
/ `2,399,911 B`, SHA-256
`cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858`.

Search used `2,297` decisions and `1,169,826` propagations. The minimum observed
upper bound is `18.846601115977638`, while the empty-assignment root upper bound
remains `262.68644197084643`. Native wall/CPU are
`0.316808/1.023602 s` at `406,568,960 B` peak RSS. End-to-end runner elapsed
time is `16.31510445800086 s`, runner peak RSS is `326,664,192 B`, and exactly
one native science process was consumed.

## Active reader, failed gain gate

O1C-0070 does not reproduce O1C-0069's passive phase-1 trajectory:

| field | O1C-0069 passive phase 1 | O1C-0070 cut-majority phase field |
|---|---:|---:|
| input vault clauses | 202 | 202 |
| conflicts | 514 | 514 |
| decisions | 4,517 | 2,297 |
| propagations | 1,192,529 | 1,169,826 |
| minimum upper bound | 9.111031965569408 | 18.846601115977638 |
| root upper bound | 262.68644197084643 | 262.68644197084643 |
| eligible emissions | 1 input duplicate | 0 |
| novel clauses | 0 | 0 |
| native trace SHA-256 | `676386a030ce3dcf...` | `5c5fb773ac889d46...` |

The distinct trace, `-2,220` decisions, `-22,703` propagations and
`+9.73556915040823` minimum-upper-bound delta establish that the reader is
active rather than inert. In particular, it steers this bounded process into a
higher-minimum-UB visited population. That direction is descriptive telemetry,
not efficacy: the precommitted gate required a publicly verified key or at least
one novel exact threshold no-good in addition to a distinct trace. O1C-0070
produces neither. Therefore `H-VAULT-CONDITIONED-PHASE-074` is refuted
specifically for phase-only gain at this sealed reader, seed and soft horizon.
The active-not-inert trace is retained as the mechanism breadcrumb.
Its full SHA-256 is
`5c5fb773ac889d46bc26c2742dccfe4ca6559f7dd5f02d5dd0f83b1760aa712f`;
O1C-0069's comparator is
`676386a030ce3dcfea0fccdaea60d482a2da8de4992102669585fff3fb896a91`.

## Threshold boundary

The frozen threshold is `tau = 14.606178797892962`. The often-compared minimum
upper bound `7.973483108047071` belongs to **O1C-0066 episode 1**, as clarified
in the O1C-0068 and O1C-0069 interpretation notes; it is not an O1C-0068 result
(O1C-0068 reports `12.8607806294803`). Threshold and minimum upper bounds use
the same compiled score metric and retained direction `score >= tau`, but they
describe different populations and statistics.

Formally, let `V` be the partial trails visited in O1C-0066 episode 1 and let
`m = min_{a in V} U(a) = 7.973483108047071`. Then
`exists a* in V: U(a*) = m`. Because the exact admissible bound guarantees
`for all x in Ext(a*): S(x) <= U(a*) < tau`, it follows that
`Ext(a*) intersection {x : S(x) >= tau} = empty`.

Thus that particular visited trail is safely pruned. But `m < tau` does **not**
imply `U(a) < tau` for every `a in V`; a minimum is existential, not universal.
Moreover `U(root) = 262.68644197084643 > tau`, so no global prune, global
threshold-region exhaustion or CNF-only UNSAT follows. O1C-0070's own minimum
`18.846601115977638` is above the threshold and changes none of these claims.

## Lineage and claim boundary

Only lineage ordinal `6` was consumed; no earlier ordinal was replayed and no
retry is authorized. The parent recorded `2,565` known completed billed
conflicts, so adding O1C-0070's observed `514` yields `3,079` known completed
billed conflicts. The full lineage actual remains `null` because O1C-0066's
failed ordinal `2` has unknown billing; `3,079` must not be relabeled as that
full actual total.

No truth-key byte, reveal, fresh target, entropy, refit, MPS or GPU call was
used. The archived clauses remain valid only for
`CNF and potential-score >= threshold`, not as CNF-only consequences. The
result is neither a model, key recovery, UNSAT certificate nor global vault
exhaustion.

## Direct resume point

Close the phase-only operator. Do not issue a second O1C-0070 phase call, replay
ordinal `6`, sweep phases, change the horizon or raise RAM. The next
discriminating mechanism is a **separately precommitted confidence-ranked
`cb_decide`/variable-order operator**. It may reuse the sealed field's signs and
magnitudes, but it must receive a new target-free specification, native binding,
public consequence fixture, attempt identity and one-call decision before any
science execution. This changes the missing control surface—variable order and
confidence—not the closed phase setting.

The authoritative machine result is
[`O1C0070_APPLE8_VAULT_PHASE_READER_RESULT_20260719.json`](O1C0070_APPLE8_VAULT_PHASE_READER_RESULT_20260719.json).
