# O1C-0071 — APPLE8 vault-ranked-decision interpretation

- **Recorded:** 2026-07-19T19:28:15+02:00 (`Europe/Berlin`).
- **Classification:** `EPISODIC_VAULT_ACTIVE_RANKED_DECISION_NO_GAIN`.
- **Source:** `66400bc6cc76653fb0a4b2c5bd64af498f4a49d3`.
- **Capsule:**
  [`runs/20260719_192742_O1C-0071_apple8-vault-ranked-decision-v1`](../runs/20260719_192742_O1C-0071_apple8-vault-ranked-decision-v1/RUN.md).
- **Seals:** authoritative result SHA-256
  `84ffbe35ae83266dd4993ad70b6dc988f4a13a8595861c23f36f0d610334cb41`;
  capsule artifact-manifest SHA-256
  `c7bbbd9d7ad0d37b80b956a3ad8141254a460ddf763ae84109a067e0343294d9`;
  machine-readable tail-cascade analysis SHA-256
  `8172db9a9d8265f61a1b1191682db06f879939d99271b0f5ba96108f7ccb8259`.

## Result

The sole authorized local-ordinal-`0`/lineage-ordinal-`7` call imported the
sealed 202-clause O1C-0070 vault. Its target-free reader ranked the 255
nonzero-delta key variables by descending absolute vault vote, then descending
singleton grouped-bound gap, then ascending variable. The returned literal sign
is the frozen vote sign. Zero-delta variable `241` is omitted. The rank order,
table and reader specification are sealed respectively by SHA-256
`26c0063f4eed586ef67535cccabacc07d945587a603cbb56dbb3b2225a32a2f5`,
`d3a007ebee7c515289d33be30757f769b2c1fde618fb5c6c312ea9f3509380ae`
and `974d0f915ef827ecaa453f795a649f78b72bd38be7f413c8eb2c104de58e4543`.

The call requested `512` conflicts and observed/billed `513` (`+1` soft-limit
overshoot). Native status is `0`. It emitted `0` eligible clauses, hence `0`
novel and `0` duplicate clauses, and returned no model or key. The input and
output vaults are byte-identical at `202` clauses / `599,728` literals /
`2,399,911 B`, SHA-256
`cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858`.
No `phase()` call was made.

The active callback records `763` `cb_decide` calls: `499` nonzero returns,
`264` zero/delegate returns, `255` unique returned variables and `244`
redecisions. The first solver fallback is call `256`, immediately after every
ranked variable has been offered once. Search used `763` decisions and
`91,260,183` propagations, reached minimum/root upper bounds
`19.297551436176224/262.68644197084643`, and took `14.818087 s` native wall
(`15.388436 s` native CPU) at `405,553,152 B` peak RSS. End-to-end runner
elapsed time is `36.94019316699996 s`; runner peak RSS is `283,738,112 B`.

## Strong order control, failed gain gate

Against O1C-0070, which changes polarity but leaves order to the solver,
O1C-0071 changes the bounded search sharply:

| field | O1C-0070 phase reader | O1C-0071 ranked `cb_decide` |
|---|---:|---:|
| billed conflicts | 514 | 513 |
| decisions | 2,297 | 763 |
| propagations | 1,169,826 | 91,260,183 |
| minimum upper bound | 18.846601115977638 | 19.297551436176224 |
| native wall | 0.316808 s | 14.818087 s |
| eligible / novel clauses | 0 / 0 | 0 / 0 |
| model | none | none |

Decisions fall by `1,534` (`-66.78%`), while propagations increase by
`90,090,357` to `78.01x` the O1C-0070 count. Minimum UB rises by
`0.4509503201985865` (about `+0.45095`), and native wall grows to about
`46.77x`. The callback therefore exerts strong order control, but lower decision
count is not efficacy: the precommitted gate required a publicly verified key
or at least one novel exact threshold no-good. O1C-0071 produces neither.

## Exact tail cascade

The returned sequence identifies the failure mechanism exactly. Ranks `1..248`
are each returned exactly once and therefore form a callback-visible stable
prefix: none is returned twice. Only ranks `249..255` are redecided, with
respective extra-return counts
`1, 3, 7, 15, 31, 62, 125`. These extras sum to `244`, exactly matching the
telemetry's redecision total.

The callback trace does not prove that every prefix literal remained assigned
continuously; a backtracked row could have been repropagated before the next
`cb_decide`. Calling the prefix “fixed” is therefore only the inference that it
needed no callback-visible reinjection, not a stronger trail-residency claim.

This is a binary-counter-like tail cascade: after a backtrack frees a low-ranked
literal, the callback scans the immutable ranking from the beginning and
reasserts the first currently unassigned literal with the same frozen sign.
Successive tail releases therefore retrigger nested prefixes of the seven-bit
tail instead of letting native CDCL choose a new causal direction. The sequence
is near powers of two (`1,3,7,15,31,63,127`), truncated by two horizon-edge
effects to `62` and `125`. The consequence is a propagation furnace: only 763
decisions drive more than 91 million propagations, without one new clause or a
model. This closes static same-sign reassertion, not confidence-ranked order as
an informative control surface.

The exact sequence audit is preserved in
[`O1C0071_RANKED_DECISION_TAIL_CASCADE_ANALYSIS_20260719.json`](O1C0071_RANKED_DECISION_TAIL_CASCADE_ANALYSIS_20260719.json).

## Threshold and lineage boundary

The frozen threshold is `tau = 14.606178797892962`. The often-compared minimum
upper bound `7.973483108047071` belongs to **O1C-0066 episode 1**, not O1C-0068
(which reports `12.8607806294803`). Threshold and minimum UB share the compiled
score metric and retained direction `score >= tau`, but describe different
populations and statistics. A visited trail with strict `U(a) < tau` is safely
pruned; a minimum below threshold does not put every visited trail below
threshold, and root UB `262.68644197084643 > tau` rules out any global-prune,
UNSAT or threshold-region-exhaustion claim. O1C-0071's own minimum is above the
threshold.

Only lineage ordinal `7` was consumed, exactly one native call was made, and no
retry is authorized. Known completed lineage billing becomes `3,592`; the full
lineage actual remains `null` because O1C-0066's failed ordinal `2` has unknown
billing. No truth-key byte, reveal, fresh target, entropy, refit, MPS or GPU call
was used. The retained clauses remain valid only for
`CNF and potential-score >= threshold`, not as CNF-only consequences.

## Direct resume point

Do not rerun O1C-0071, replay lineage ordinal `7`, sweep rank variants, change
the horizon, add phase steering or raise RAM. The next mechanism is a new
**backtrack-release / one-shot causal reader**: each ranked bit may be injected
at most once; if native search backtracks over it, that bit is permanently
delegated to the solver for the rest of the call. This preserves the initial
confidence-ranked intervention while preventing static same-sign reinjection
from rebuilding the binary-counter tail. It requires a new target-free
specification, attempt identity and one-call gate; it is not an O1C-0071 rerun or
sweep.

The authoritative machine result is
[`O1C0071_APPLE8_VAULT_RANKED_DECISION_RESULT_20260719.json`](O1C0071_APPLE8_VAULT_RANKED_DECISION_RESULT_20260719.json).
