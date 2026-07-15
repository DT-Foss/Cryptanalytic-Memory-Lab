# First Reproducible Results — 2026-07-15

These are five-seed smoke tests of the integration instruments, not a cipher-level
cryptanalytic claim.

## Reproducibility anchors

| Artifact | SHA-256 |
|---|---|
| `configs/quick.json` | `942acf41622787fe58420492ed72593bf3f7bc68e03752035c0965cfbe5ea3de` |
| `runs/quick.json` | `755e0ebee06337ac576a19d8408e4f5d9ae5d29b0c87063b021210b5b29e39da` |
| Embedded benchmark result | `de9a8503ab336f770bd6c20d5a99c865a364ecd72d91a57a644f1e58b1e3aafb` |
| `runs/o1o-2026-02-18-replay.json` | `2f106c488c7eab15aee1cbed80114f6de2c33a9a2858152b1e2dc373d2b8dac1` |
| `runs/fullround-source-verification.json` | `8920811c6424a9d81be36ae658bcbbc3f09f5c826f04c768e493ea33a5d8458b` |

The benchmark was independently recomputed in memory and matched `runs/quick.json`
byte-for-value, including the embedded result hash.

## Closed-gate MQAR-256 storage

Longest sweep: 65,536 irrelevant tokens, 256 shuffled bindings, shuffled queries,
five seeds.

| Arm | State scalars | Serialized bytes | Mean bit accuracy | Exact 256-bit rate | State frozen |
|---|---:|---:|---:|---:|---:|
| Direct bit vault | 256 | 64 | 100.0000% | 5/5 | 5/5 |
| Holographic equal-cell | 256 | 2,048 | 83.5938% | 0/5 | 5/5 |
| CountSketch under-capacity | 64 | 512 | 70.1562% | 0/5 | 5/5 |
| Full-context hard attention | 197,376 | 657,920 | 100.0000% | 5/5 | 0/5 |

Interpretation:

- the harness ceiling and direct fixed-width register both reconstruct exactly;
- the equal-cell holographic state survives the haystack but is crosstalk-limited;
- the under-capacity collision control fails as intended;
- full context remains exact by retaining the stream, but visibly violates bounded
  state;
- because bounded arms receive an explicit closed relevance gate, this result does
  not test learned O1 token selection.

Equal scalar count is not equal storage: the direct binary register is 64 logical
serialized bytes including validity, while 128 complex128 channels require 2,048.

## Streaming weak-evidence integration

Each relation supplies one signed scalar for each of 256 bit positions. The longest
point therefore consumes 1,024 relation vectors or 262,144 scalar observations per
seed while retaining a fixed 2,048-byte log-odds state.

| Mode at 1,024 relations | Mean bit accuracy | Exact 256-bit rate | Mean Brier |
|---|---:|---:|---:|
| Independent 55% signal | 99.8438% | 3/5 | 0.001251 |
| No-signal 50% control | 49.3750% | 0/5 | 0.441546 |
| Perfectly correlated 55% orientation | 55.8594% | 0/5 | 0.441406 |

The distinction is the useful result: genuinely new weak evidence accumulates;
repeating one correlated orientation does not create new information; chance stays
at chance. The 55% stream is synthetic oracle evidence and says nothing yet about
whether a full-round cipher exposes such a bias.

## Real O1-O session replay

The supplied `2026-02-18_013412` session normalized deterministically to 54 events:

- 16/16 generation compile positives;
- 10/16 structural-verification positives;
- 8/16 process positives and 8/16 process negatives;
- capability and mission outcomes remain explicitly unknown for all 16 tasks;
- engagement summary: 28 discovered services, 10 logical tools, 8 process successes,
  six adaptive retries, three retry recoveries and one chained tool;
- neutral bounded TargetModel ingestion: 54 observations, zero inferred reward and
  state hash `4ca00bef964ff18f2c72090a76ed4bda707180211871313a2e119dfd55bc0865`.

Replay input snapshot:
`199e0244db96628625d6af89eed61a3c39093c90131f624b3be81b31990f0657`.

No generated program was imported or executed. Raw output is omitted; only byte
counts and unsalted integrity fingerprints remain, and those fingerprints are not a
confidentiality mechanism. Retry/follow-up counts are authentic aggregates; the
old schema did not retain parent IDs, so no edge ancestry is inferred.

## Published recovery source

The clean sibling `fullround-key-recovery` verified all 570 manifest members with
zero missing and zero mismatched files. Manifest SHA-256:
`9c3ac76f3f012ff24c07e2e4dbe335e5156eca28fee9986aeb53c1b6cb2a4cc3`.

## Next decisive gate

Build a small frozen Stage-3 dataset from SHA-verified public challenge/config/result
members and attacker-computable Causal/Solver features. O1-O then searches a finite
provenance-typed operator registry on training/validation keys; the exact proposal
and plan are frozen; O1 integrates the resulting held-out evidence; a single disjoint
test is consumed; the established backend confirms any rank or recovery result.
