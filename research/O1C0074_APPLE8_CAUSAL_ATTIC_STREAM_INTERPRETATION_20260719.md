# O1C-0074 — APPLE8 causal-attic stream interpretation

- **Recorded:** 2026-07-19T23:21:48+02:00 (`Europe/Berlin`).
- **Classification:** `CAUSAL_ATTIC_STREAM_NOVEL_CLAUSE_GAIN`.
- **Source/execution:** `a5f2ad130e2e13c39a5e888f927d86d5fdd68d78`.
- **Capsule:**
  [`runs/20260719_231823_O1C-0074_apple8-causal-attic-stream-v1`](../runs/20260719_231823_O1C-0074_apple8-causal-attic-stream-v1/RUN.md).
- **Seals:** authoritative result SHA-256
  `b6bc2895459e3256fa4c857b67bd786b36d80ab5018a9c73709a2096cd169127`;
  capsule artifact-manifest SHA-256
  `7a3f272268296005c5c6e532d377eb100244f38e941a102876abbfd732a8049b`.

## Publication lifecycle

The sealed capsule `result.json` is byte-identical to the published research
result; both hash to
`b6bc2895459e3256fa4c857b67bd786b36d80ab5018a9c73709a2096cd169127`.
The capsule `artifacts.sha256` validates all `54/54` listed artifacts. Its
`publication_source.json` is the deliberately pre-finalization source record,
not an authoritative result: it differs only because
`resources.persistent_artifact_bytes` is `0` there and `30,567,197` after final
publication. Cite the sealed/published `result.json`, never the pre-finalization
source, for final resource totals.

## Result

O1C-0074 completes all four predeclared local episodes `0..3`, consuming lineage
ordinals `10..13` once each. Every episode requests, observes and bills exactly
`128` conflicts. The aggregate ledger is therefore `4/4` native calls and
`512/512` requested/billed conflicts, with no retry, operational failure, model
or key.

The run implements the two-level O1 memory boundary frozen before science:

1. the complete immutable causal attic retains every unique certified clause
   and every duplicate witness occurrence;
2. only a deterministic `256`-clause projection is live inside each solver;
3. the immutable 202-clause O1C-0073 parent, SHA-256
   `cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858`,
   remains a separate reader/rank source; and
4. every completed episode is durably archived before the next projection is
   derived.

The complete attic grows from `513→550` unique clauses and
`1,397,774→1,488,224` literals. Witness occurrences grow `515→558`, while the
number of duplicate occurrences grows `2→8`. Thus `37` globally new exact
threshold-relative exclusions are retained rather than lost at the old
512-clause residency boundary. The final complete union is `5,955,287 B`.

The active state stays exactly `256` clauses throughout. Its SHA-256 sequence is

`fb7528bf… → ccfad8b3… → 78696f2b… → 78696f2b… → 78696f2b…`.

The final active projection contains `652,184` literals / `2,609,951 B`, SHA-256
`78696f2b662beda4b371aa547350cc66b2105bc4dcaf0b982af2d1279e3012ed`.
Capacity is therefore a durable rollover event rather than a science terminal.

## Four-episode causal sequence

| local / lineage | decisions | propagations | minimum UB | threshold prunes / emissions | global effect | next active SHA |
|---:|---:|---:|---:|---:|---|---|
| `0 / 10` | 2,437 | 2,956,417 | 13.527469461337148 | `6 / 6` | six rediscovered attic clauses, union indices `202..207`; `0` globally novel | `ccfad8b3…` |
| `1 / 11` | 3,536 | 2,954,223 | 13.140486923093844 | `37 / 37` | `37` globally novel clauses, union indices `513..549` | `78696f2b…` |
| `2 / 12` | 2,288 | 2,890,144 | 14.67138759145431 | `0 / 0` | no new occurrence or clause | `78696f2b…` |
| `3 / 13` | 2,288 | 2,890,144 | 14.67138759145431 | `0 / 0` | no new occurrence or clause | `78696f2b…` |

Native status is `0` in every episode and root UB is always
`262.68644197084643`. The immutable reader source remains byte-identical across
the stream.

## Mechanistic interpretation

Episode 0 is not a null. Its six emissions are exact global duplicates that were
present in the complete attic but absent from the initial live K256 projection.
Recording those six recurrence events changes only their occurrence coverage in
the complete ledger. The frozen projection rule then promotes all six clauses
into the next live reservoir, changing the projection from `fb7528bf…` to
`ccfad8b3…` without changing the rank source, target, seed, reader or episode
budget.

The immediately following episode emits 37 globally new clauses. All 37 are
durably added as union indices `513..549`, after which deterministic reprojection
changes the live state to `78696f2b…`. This is the positive O1 mechanism:

> repeated public evidence changes bounded attention; the changed bounded
> attention exposes new exact evidence one episode later; the complete attic
> retains both the repetitions and the discoveries.

The result supports `H-CAUSAL-ATTIC-078`. It is the first completed stream in
this line where duplicate occurrence is not discarded as wasted work: recurrence
is an attention signal, the live state changes, and a subsequent bounded episode
adds new exact exclusions without exceeding the fixed 256-clause live budget.
The sequence is mechanistically identified inside this frozen stream; it is not
yet a claim that these six clauses are uniquely necessary under every possible
residency policy.

## Exact fixed point and stop boundary

Episodes 2 and 3 are bit-identical on the active vault, reader evidence, sieve
trace and vault telemetry. They make the same `2,288` decisions and
`2,890,144` propagations, reach the same minimum UB, and emit nothing. The
static deterministic projection has therefore reached an exact bounded fixed
point at this reader, seed and 128-conflict horizon.

That fixed point closes replay of `78696f2b…`; it does not close the complete
attic, the release-contrast reader, bounded active memory, or other nonrepeating
attention/residency rules. A fifth identical episode is forbidden because the
fourth already reproduced the third byte-for-byte. The next experiment must
change the bounded residency/attention mechanism target-free, not repeat this
projection or increase the horizon/RAM cap.

## Formal threshold and upper-bound rule

Let `S(x)` be the compiled complete-key score and let

`R_tau = {x : S(x) >= tau}`, with `tau = 14.606178797892962`.

For a visited partial trail `a`, let `C(a)` be its complete-key extensions. The
width-6 calculation is admissible:

`U(a) >= max {S(x) : x in C(a)}`.

The threshold and every reported upper bound therefore use the same score units
and the same retained direction `S(x)>=tau`. They do **not** have the same
statistic or population: `tau` is one fixed membership cutoff, whereas a run's
minimum UB is `min_{a in V} U(a)` over that run-specific set `V` of visited
partial trails.

For each particular visited trail, strict inequality gives

`U(a) < tau  =>  C(a) intersect R_tau is empty`.

Negating that trail is therefore a mathematically safe prune of all its
descendants from the retained score region. A reported minimum below threshold
proves only that at least one such visited trail exists. It does not prove that
all visited trails, unvisited trails or the root can be pruned.

The historical `7.973483108047071` is O1C-0066 episode 1's visited-trail
minimum, not an O1C-0068 value. O1C-0068 reports `12.8607806294803`.
O1C-0074 episodes 0 and 1 report minima below threshold and exactly `6` and `37`
safe trail prunes; episodes 2 and 3 report
`14.67138759145431 > tau` and zero prunes. Root UB remains
`262.68644197084643 > tau` in all four episodes. Consequently O1C-0074 proves
local exact branch removal, not global pruning, CNF-only UNSAT or exhaustion of
the threshold region.

## Resources and claim boundary

End-to-end elapsed time is `204.95784179099428 s`; runner peak RSS is
`504,233,984 B`, and persistent artifacts occupy `30,567,197 B`. The largest
per-episode native peak is `412,270,592 B`. No truth-key byte, fresh target,
scientific entropy, reveal, refit, phase, rank sweep, K sweep, MPS or GPU call is
used.

Known completed lineage billing advances from `4,283` through ordinal `9` to
`4,795` through ordinal `13`. The historical full actual total remains `null`
because failed ordinal `2` is unbilled. The 37 clauses are exact exclusions
relative to the frozen `CNF and score>=threshold` region; they are not CNF-only
consequences, recovered key bits or an entropy estimate.

## Direct resume point

Do not replay any O1C-0074 episode, especially the exact ordinal-12/13 fixed
point. Do not sweep K, horizon, rank, phase, seed, threshold, RAM or clause caps.
Preserve the complete 550-clause attic, all 558 witness occurrences, the separate
immutable rank source and the final K256 projection.

The next action is zero-call analysis and freeze of one **nonrepeating bounded
residency/attention mechanism** for a distinct O1C-0075 attempt. It must use only
the recorded public clause/occurrence/subsumption structure, keep the complete
attic immutable, and make a deterministic live-state change instead of replaying
the saturated `78696f2b…` projection. The exact O1C-0075 policy remains to be
chosen from that analysis; no science call is authorized merely by this result.

The authoritative machine result is
[`O1C0074_APPLE8_CAUSAL_ATTIC_STREAM_RESULT_20260719.json`](O1C0074_APPLE8_CAUSAL_ATTIC_STREAM_RESULT_20260719.json).
