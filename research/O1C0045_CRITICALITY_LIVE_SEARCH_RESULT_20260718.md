# O1C-0045 — Parent-criticality live exact search

O1C-0045 converts the prospectively transferred O1C-0044 joint-rank reader into
live reversible CaDiCaL guidance without fitting another weight. The conversion
is exact: across all 4,096 frozen decoys and the revealed truth, every primary,
key-rotated and clause-rotated score agrees within `1.25e-14`; the compiled
primary truth remains rank `54/4097`.

## Result

At the attacker-valid Full-256 boundary, every arm remains `UNKNOWN` at the
matched 512-conflict limit. No key was recovered.

The post-reveal residual ceiling separates decoder geometry from evidence:

| Residual | Internal | Primary | Key rotated | Clause rotated |
|---:|---:|---:|---:|---:|
| 8 | SAT / 217 conflicts | SAT / 152 | SAT / 51 | SAT / 69 |
| 9 | UNKNOWN / 512 | SAT / 281 | SAT / 69 | SAT / 129 |

Every SAT model is the exact 256-bit key and independently reproduces the public
ChaCha20 output. The primary field therefore expands this consumed target's
completion frontier from internal width 8 to width 9. Both coordinate controls
do so as well and outperform primary, so the gain belongs to the local potential
family/general factor geometry, not yet to O1C-0044's target-specific orientation.
Classification:
`CRITICALITY_POTENTIAL_FAMILY_EXPANDS_RESIDUAL_FRONTIER_WITHOUT_PRIMARY_MARGIN`.

## Mechanistic conclusion

The strong static rank objective survives compilation, but the current scheduler
greedily chooses among all 447–500 observed key and internal variables using a
local uniform-marginal energy difference. That lets generic clause geometry
dominate the globally discriminative score. The smallest next test keeps every
internal factor variable observable for conditioning while allowing the external
policy to decide only key variables; native CDCL retains internal branching.
The reader, factor tables, target, residual sets and 512-conflict boundary remain
unchanged. No fresh key is authorized until primary beats both rotations in real
search work.

## Boundary and cost

- Full-256 search and all potential hashes froze before the consumed reveal was
  opened by the runner.
- Residual 8/9 prefixes are explicit post-reveal oracle conditions and are not
  attacker-known bits.
- `17.290067` elapsed seconds; `130,269,184` B process peak; 12 native calls;
  6,144 requested conflicts; 4,097 forward evaluations; 851,164 persistent bytes.
- Zero fresh entropy, sibling reads/writes, MPS or GPU work.

Artifacts: [immutable capsule](../runs/20260719_001005_O1C-0045_criticality-live-search-v1/RUN.md),
[machine result](O1C0045_CRITICALITY_LIVE_SEARCH_RESULT_20260718.json).
