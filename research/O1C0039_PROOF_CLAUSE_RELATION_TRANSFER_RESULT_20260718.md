# O1C-0039 — Proof-Clause Relation Transfer

Recorded 2026-07-18T22:02:17+02:00 from source commit `fdd0874`.

## Result

`RELATION_TRANSFER_ONLY`.

The frozen H16 signed proof-clause contrast transferred from four consumed BUILD
targets to both O1C-0018 DEVELOPMENT targets. The extractor saw only the public
counter, nonce, output and its own paired `k_i=0/1` solver events while all 256
target-key bits remained unknown.

| Metric | development-0000 | development-0001 | Pooled |
|---|---:|---:|---:|
| Relation edges | 432 | 279 | 711 |
| Primary correct | 238 | 159 | 397 |
| Primary accuracy | 55.0926% | 56.9892% | 55.8368% |
| Key-rotated accuracy | 53.9352% | 51.2545% | 52.8833% |
| Factor-rotated accuracy | 50.9259% | 47.3118% | 49.5077% |
| Bounded field bytes | 3,512 | 2,288 | 5,800 |

The exact selection was frozen on BUILD at H16 and absolute score `|J|=0.5`;
no alternate horizon or weight was tried after opening DEVELOPMENT labels. Both
fields, both coordinate controls, residual-coordinate choices and every Full-256
search result were committed in `attacker_freeze.json` before the label artifact
was opened.

## Search boundary

The transferred pairwise relation is real, but the current first-encounter
external factor decisions did not yet convert it into exact-search efficacy.
Internal, primary and both rotated Full-256 arms produced zero verified keys at
512 conflicts. The explicitly post-reveal residual-9 ceiling also produced zero
recoveries in primary, hint-only and rotation arms. O1C-0038 therefore remains the
exact residual ceiling at eight bits; O1C-0039 does not claim recovered key bits,
entropy removal or a ChaCha20 break.

The useful new fact is narrower and attacker-valid: a 2.3--3.5 KiB bounded state
extracted from target-specific solver proof streams predicts signed key-to-internal
relations above chance on two unseen keys. The next question is no longer whether
such relations exist, but whether their aggregate score ranks the true forward
execution above decoys and can be injected as a live reversible search objective.

## Resources and artifacts

- 12.202150 elapsed seconds; 142,262,272 B peak RSS.
- 1,024 native paired branches; 18 exact-solver calls; 8,192 requested conflicts.
- Zero sibling reads/writes, fresh targets, MPS calls or GPU calls.
- Capsule manifest SHA-256: `1bda99959ca5367a16e92d7c579d2f24e3b1216852ad04b2e1061b2b9f21898f`.
- Result SHA-256: `f1c6860f59db4fd5c1aca2123ac23c69b5f4f01e99d05ff53a2144f3fa594b87`.
- Attacker-freeze SHA-256: `a8ed2b3d7acdce935b07c052a05f64d7ad3e288e7b3707c706f2d56fdaaefb14`.
- [Immutable capsule](../runs/20260718_220217_O1C-0039_proof-clause-relation-v1/RUN.md)
- [Canonical machine result](O1C0039_PROOF_CLAUSE_RELATION_RESULT_20260718.json)

## Resume point

Keep H16 and `|J|=0.5` frozen. On the two now-consumed DEVELOPMENT targets,
forward-evaluate the frozen relation objective for the true key and a large
attacker-computable decoy panel. If true-key rank is positive, replace the
one-shot factor decisions with context-reversible live score aggregation and
measure equal-work Full-256 search. If rank is null, close clause-occurrence
factors without a weight sweep and move one causal level deeper to signed
antecedent-chain relations.
