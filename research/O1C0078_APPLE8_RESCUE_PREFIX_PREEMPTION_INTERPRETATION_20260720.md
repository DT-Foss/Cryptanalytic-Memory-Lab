# O1C-0078 — APPLE8 rescue-prefix-preemption interpretation

- **Started:** 2026-07-20T06:55:05+02:00 (`Europe/Berlin`).
- **Recorded:** 2026-07-20T06:55:37+02:00 (`Europe/Berlin`).
- **Classification:** `RESCUE_PREFIX_PREEMPTION_OPERATIONAL_TERMINAL`.
- **Source freeze:** `ced7e5917194362b84d44625f7f9f6484bb555ad`.
- **Execution:** `2840824b2aa482f30dfbd39060c200994fc09957`.
- **Capsule:**
  [`runs/20260720_065505_O1C-0078_apple8-rescue-prefix-preemption-v1`](../runs/20260720_065505_O1C-0078_apple8-rescue-prefix-preemption-v1/RUN.md).
- **Seals:** authoritative result SHA-256
  `f72821443ed7e7dd80698a39288ff31f9c8f52a120bb745e713e3b23b1822fed`;
  capsule artifact-manifest SHA-256
  `5d358863162a64f27d215fc4b91258c73194d2458f89d9dd7495bb1e05e50a69`.

## Result boundary

O1C-0078 consumes its sole predeclared local-0 / lineage-18 native call on
fresh Page 5. It requests 128 conflicts, but no native result is returned;
actual conflicts are unknown and billed conflicts are `null`. The native process
exits with
status 1 after `29.31788737498573 s`; its exact terminal stderr is:

```text
cadical_o1_joint_score_sieve_v16: backtrack-release guided assignment sign differs
```

Standard output is empty. The runner stops without retry and classifies the
attempt `RESCUE_PREFIX_PREEMPTION_OPERATIONAL_TERMINAL`. Because there is no
native result payload, O1C-0078 has no measured prefix activation, trace,
solver status, bound, prune, emitted clause or model. Recorded aggregate science
fields are failure-finalized at zero safe threshold prunes, zero globally novel
clauses and no public key; those zeros are not native measurements. This is an
operational boundary, neither a scientific negative nor a cryptanalytic gain.

The bound input and capsule identify Page 5 SHA-256
`07c73013705898e228a05b0578b0f8090a6f094c427dbd8f32d856467b08e208`
as fresh; it is now consumed and must never be presented as fresh again. The
failure-finalized claim field `no_science_input_sha256_reused=false` is a
conservative fallback because postvalidation did not complete, not positive
evidence of input reuse. No output residency or new attic evidence exists to
import from this failed call.

## What control flow does prove

The inherited v11 backtrack-release reader can throw this exact exception only
for a rank row whose `returned_state` bit is already set. That bit is set only
after the inherited parent `cb_decide` returned the ranked literal. The O1C-0078
outer reader, in turn, calls that parent only after its prefix cursor has
consumed all 11 sealed rows. Therefore the failure proves this narrow control-
flow reachability statement:

```text
all 11 prefix rows consumed -> parent handoff reached
-> inherited ranked literal returned earlier -> failing release check reached
```

It does **not** prove the predeclared activation gate. With native stdout absent,
there is no evidence for at least one actual prefix once-return, zero
preassigned-rescue skips, all 11 rows falsifying at handoff, or a trace distinct
from O1C-0077. `qualified_prefix_preemption_activated=false` is therefore the
only sound publication value. Prefix-row consumption is a control-flow fact,
not qualified activation.

## Strongest code-path inference

The proven failure state is narrower than a full event reconstruction: the v11
ledger marks a rank row as returned-ever and unreleased, while the assignment
currently disappearing on that variable has the opposite sign. Empty stdout
means the exact event route is unobserved. The strongest code-path inference is
that nested readers lack sufficient decision ownership/provenance and conflate
proposal history with current assignment ownership; another reader,
propagation, or a later decision is a possible source of the counter-assignment,
but the artifact does not establish which layer created it. The missing
composition primitive is therefore:

> nested readers conflate proposal history with current assignment ownership.

This is not evidence that the 11-row prefix is scientifically ineffective. It
shows that release accounting needs explicit decision provenance before nested
O1 readers can be interpreted safely.

## Threshold boundary: 14.61 versus 7.973

Let `S(k)` be the compiled complete-key score and retain exactly
`S(k)>=tau`, where `tau=14.606178797892962`. For any visited partial trail `a`,
the grouped bound is admissible:

```text
for every complete k extending a: S(k) <= U(a)
```

The threshold and every reported `U(a)` use the same compiled score metric,
the same units and the same maximization/retained direction. They are not the
same statistic or population. `tau` is a fixed membership cutoff over complete
key scores; a reported minimum UB is `min_{a in V} U(a)` over the particular
partial trails `V` visited in one episode.

For one particular visited trail, strict `U(a)<tau` is a formally safe local
prune:

```text
for every k extending a: S(k) <= U(a) < tau
therefore no completion of a is in {k : S(k) >= tau}
```

Equality is insufficient because the retained rule includes `S(k)=tau`. A
minimum below threshold proves at least one visited subtree is locally
prunable; it does not bound every trail, the root population or the entire
retained region.

`7.973483108047071` is O1C-0066 episode 1's minimum visited-trail UB. That
episode separately records seven realized safe trail prunes. The minimum is
neither a prune count nor global exhaustion. It is not current and not an
O1C-0068 value. O1C-0068's minimum is `12.8607806294803`, and O1C-0068 remains
untouched. O1C-0077's minimum is
`14.656823218163392>14.606178797892962`, with zero safe prunes. O1C-0078
returns no native bound telemetry, so it adds no threshold claim.

## Highest-ROI successor

Do not replay O1C-0078, lineage 18 or Page 5. O1C-0079 should first reproduce
the conflicting ownership sequence in a zero-science synthetic trace. Replace
the nested implicit ledgers with one explicit arbiter/ownership ledger that
records, for each live assignment, the proposing reader, signed literal,
decision instance and release transition. A reader may release only the
decision instance it owns; proposal history remains separate and cannot assert
the sign of a later assignment.

After this invariant passes synthetic opposite-sign, propagation-owned,
backtracked and nested-parent traces, derive fresh Page 6 / lineage 19 by
burning Page 5 without importing a nonexistent native output. Then make one
fresh, unchanged-budget science call. Do not alter the 11-row scientific prefix
from this operational failure, and do not sweep Page, K, rank, phase, horizon,
seed, threshold, RAM or caps.

The north star remains a reproducible attacker-valid Full-256 search/recovery
advance and ultimately exact independent ChaCha20 verification. The ownership
repair is warranted only because it restores interpretability of the already
reached nested-reader path; it is not itself a science result.

## Resources and publication

Runner elapsed time is `31.211805499973707 s`; native-failure elapsed time is
`29.31788737498573 s`. Native/watchdog peak RSS is `404,815,872 B`, runner peak
RSS is `381,730,816 B`, and persistent artifacts occupy `12,137,843 B`. The
single call is requested at 128 conflicts; actual and billed work remain
unknown / `null`. There are
zero publication-recovery solver calls, retries, truth reads, reveal calls,
fresh targets, refits, rank/K/horizon sweeps, phase calls, MPS calls or GPU
calls.

Capsule `result.json` is byte-identical to the authoritative research result,
and all `33/33` artifact-manifest entries validate. Cite the sealed result for
the terminal classification and resource totals.

## Direct resume point

Resume from the synthetic ownership reproducer, not from another solver call.
Preserve the immutable 550-clause / 558-occurrence attic, the separate
202-clause rank source, the exact 11-row prefix identity `b5debc5f…`, and
consumed lineages through 18. Derive Page 6 / lineage 19 from the durable Page-5
burn only after the arbiter owns proposal and assignment provenance explicitly.

The authoritative machine result is
[`O1C0078_APPLE8_RESCUE_PREFIX_PREEMPTION_RESULT_20260720.json`](O1C0078_APPLE8_RESCUE_PREFIX_PREEMPTION_RESULT_20260720.json).
