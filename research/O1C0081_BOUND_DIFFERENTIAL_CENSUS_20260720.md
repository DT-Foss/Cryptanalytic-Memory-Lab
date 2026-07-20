# O1C-0081 — Target-free bound-differential census

## Outcome

The sealed O1C-0080 retained prefix supports a new **query-priority mechanism candidate**, not key-bit orientation or recovery. No solver, target, truth, reveal, refit, MPS, or GPU call occurred.

## Population boundary

- Exact retained events analyzed: `16384`
- Retained probes: `[1, 16384]`; calls: `[1, 74]`
- Full trace: `285725` events / `16286325` bytes / `c6f6c2a9ecf17bdd8f74891f5ffc7fba7f9658c4c95310d0c2f00f8b65093f5c`
- Omitted suffix values: unavailable and **not inferred**; the full trace is used only through count/bytes/digest metadata
- Separate global minimum witness: probe `37567`, call `413`, variable `115`, minimum `18.464862193097684`, margin above threshold `3.8586833952047215`; excluded from all prefix accumulators

## Recorded-prefix signal

- Raw `d=U0-U1`: min `-3.721211809959186`, max `1.8624800468152216`, mean `0.435558404488658`
- Raw positive: `15601/16384` = `0.95220947265625`
- After within-parent median centering: mean `-0.006465018506553668`, positive fraction `0.498779296875`
- Interpretation: the large raw positive majority is common-mode contaminated. Raw sign is therefore not a posterior.

## Persistent query-priority candidates

Ranking is target-free. Eligibility first requires at least `37` retained-parent observations; within that persistent population the score is `abs(mean robust-z) * sqrt(count) * directional stability`. Its sign is deliberately not mapped to a key bit.

| rank | variable | count | centered mean | robust-z mean | stability | score |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 185 | 73 | -2.752744217128212 | -10.738855030935364 | 1.0 | 91.75281760473375 |
| 2 | 170 | 73 | -1.033919835905002 | -4.028603228275275 | 1.0 | 34.42040107078224 |
| 3 | 129 | 61 | -0.7061339681159688 | -2.723968417491693 | 1.0 | 21.274873449894457 |
| 4 | 202 | 73 | 0.6182840218695863 | 2.447006360710873 | 1.0 | 20.90723151072952 |
| 5 | 187 | 73 | 0.6561165106976458 | 2.6858179687186974 | 0.8493150684931506 | 19.48977540556668 |
| 6 | 33 | 73 | -0.5735805848558241 | -2.237455413405396 | 1.0 | 19.116827432116686 |
| 7 | 83 | 73 | 0.5598117894845962 | 2.197901090249083 | 1.0 | 18.77887514692565 |
| 8 | 34 | 73 | 0.5183862381712196 | 2.065957273257483 | 1.0 | 17.651546680377926 |
| 9 | 110 | 73 | -0.4678741498232387 | -1.846021424354226 | 1.0 | 15.772413963618908 |
| 10 | 206 | 74 | 0.4497571079307305 | 1.770934981377631 | 1.0 | 15.234158736594459 |
| 11 | 97 | 73 | -0.4536745935805549 | -1.7677347254355193 | 1.0 | 15.103532114848933 |
| 12 | 237 | 74 | 0.43571053608842075 | 1.7148278100225949 | 1.0 | 14.751506598784742 |
| 13 | 239 | 68 | 0.4451495174209003 | 1.7586232246409037 | 1.0 | 14.501978621717562 |
| 14 | 196 | 73 | 0.4170261785937166 | 1.6595901808321163 | 1.0 | 14.179544720721799 |
| 15 | 212 | 73 | -0.4156703519162403 | -1.651382765935969 | 1.0 | 14.109420537109742 |
| 16 | 43 | 73 | -0.4100711273020642 | -1.5989684412440712 | 1.0 | 13.661592350633878 |

## Target-free controls

- Within-parent cyclic permutation: top-16 overlap `3`, priority correlation `-0.028412595664496245`. This is one deterministic control, not a p-value.
- Temporal split: `[1, 37]` versus `[38, 74]`, centered-mean correlation `0.8538130771826461`, sign agreement `0.8110599078341014`, top-16 overlap `4`.

## Bounded-state operator

A packed live bank is `28672` bytes: `24576` bytes for 256 coordinate accumulators plus `4096` bytes of one-parent median/MAD scratch. This excludes offline JSON materialization and remains `O(256)`.

## Next action

Implement the parent-centered signed-differential stream as a fresh, target-blind query-priority operator. Keep belief orientation as a separate disabled field until independently calibrated. Do not replay Page 7 / lineage 20 and do not infer omitted trace values.
