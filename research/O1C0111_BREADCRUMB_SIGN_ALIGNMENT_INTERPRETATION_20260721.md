# O1C-0111 — frozen breadcrumb-sign alignment

Date: 2026-07-21  
Classification: `RETROSPECTIVE_TWO_COORDINATE_MIXED_OR_WRONG`

## Result

The O1C-0109 hidden local-prunable sidecar contained 100 exact events but only two unique key coordinates, 193 and 196. Before historical truth was read, the frozen ONE-prunable reader predicted bit 0 at both coordinates. Both corresponding historical key bits are 1.

Primary ONE-prunable accuracy is therefore `0/2`; the secondary BOTH-prunable reader is also `0/2`. Identity alignment loses to the global sign flip and has conservative cyclic rank `256/256` in both arms. The two-coordinate diagnostic fails, and its deliberately disabled broad-posterior gate remains closed.

## Meaning

The hidden local field is real solver telemetry, but its raw event sign is not a key-bit orientation. Event count must not be mistaken for coordinate coverage: 100 rows collapse to two coordinates. No bit, entropy, posterior, beam, or recovery claim follows.

This closes direct ONE/BOTH-prunable sign reading on the consumed O1C-0109 target. Do not flip the sign after reveal, rescale it, or continue this historical target. The retained breadcrumb is architectural: local-prunable events are a useful selection/causal-address signal, not a label by themselves.

## Provenance

- score freeze SHA-256: `deb329ad15a822ff9511f02f1a4657eb8dddce30f3d656a79b21ec34f44d35ee`
- result identity SHA-256: `372368b9a2506bdc5ce2eb7cd8926f0fa8f81d2abf3563da5e60c735ca51cb74`
- serialized result file SHA-256: `337a075c097fd756ff1676f139835c6143753de464d114f101c7ed20dc702b52`
- joint capsule: `runs/20260721_113111_793173_O1C-0111_O1C-0112_joint-refrozen-historical-alignment-v1`
- resources: zero solver/native/fresh-target/refit calls; one cached broker-verified historical truth object shared with O1C-0112

## Next action

Use the field to choose or bind causal operators on a fresh public-output target. Any next bit reader must learn orientation from independent BUILD targets and freeze before the fresh target; the historical sign may not seed it.
