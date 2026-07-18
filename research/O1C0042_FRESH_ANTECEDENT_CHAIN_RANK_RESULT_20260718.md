# O1C-0042 — Fresh antecedent-chain rank replication

Recorded 2026-07-18T23:04:37+02:00 from source commit `75d78b2`.

## Outcome

`FRESH_CHAIN_RANK_NOT_REPLICATED`

One `os.urandom` call generated a sealed standard 20-round ChaCha20 target. Only
its counter, nonce, output and commitment were published. O1C-0041's H16
branch-exclusive unique-leaf extractor, unit occurrence weights, global
orientation `-1`, 4,096-candidate panel and endpoint rotations were frozen before
that entropy call and remained unchanged.

The broker opened the key only after the complete candidate-key and three-score
artifact hashes had a signed freeze receipt. The revealed key independently
reproduces the public ChaCha20 block.

| Arm | Rank | Rank fraction | Truth z |
|---|---:|---:|---:|
| primary | 1371/4097 | 0.334635 | +0.360857 |
| key rotated | 1399/4097 | 0.341469 | +0.335990 |
| factor rotated | 3385/4097 | 0.826214 | -0.856915 |

Primary retains a small endpoint-control margin but misses the frozen best-quarter
gate. The strong consumed-panel concentration from O1C-0041 therefore does not
replicate on this one fresh key. There is no retry and no exact-key recovery.

## Decision

Close the exact `unique signed leaf set -> weighted pair sum` reader. Do not tune
H16, global sign, capacity, occurrence weights or the fresh panel. Preserve the
positive architectural clue that exact branch identity and endpoint identity
remain directionally better than both rotations.

The next reader keeps information destroyed at the leaf collapse: ordered direct
parent role and candidate-relative antecedent-clause criticality, including which
literal uniquely satisfies a functional clause. Test it only on already consumed
BUILD/DEVELOPMENT targets before another fresh target is considered.

## Resources and integrity

- elapsed: `7.435433` s;
- peak RSS: `131,579,904` B;
- native H16 branches: `512`;
- complete forward evaluations: `4,097`;
- scientific entropy calls / fresh targets: `1 / 1`;
- persistent capsule bytes: `255,960`;
- sibling reads/writes, MPS and GPU calls: `0`;
- capsule manifest SHA-256:
  `801328d47c01dfcaa62d70df6324912120428f256fadb05a35bab5818e4d42b3`;
- result SHA-256:
  `590275ac33be41ee61769f6a57fe3a512d9acb7a822fb304d64ef69db559309d`.

[Immutable capsule](../runs/20260718_230437_O1C-0042_fresh-antecedent-chain-rank-v1/RUN.md)

