# O1C-0044 — Fresh parent-criticality joint-rank transfer

Recorded 2026-07-18T23:42:33+02:00 from source commit `24de293`.

## Outcome

`FRESH_PARENT_CRITICALITY_RANK_TRANSFER`

One sealed standard 20-round ChaCha20 target was created by exactly one
`os.urandom` call. Before that entropy call, O1C-0043's H16 field definition,
15-channel reader, weight hash, 4,096-candidate panel and two endpoint rotations
were fixed. The key remained behind a commitment until the natural field,
candidate keys, per-arm calibration and all three score vectors had frozen.

| Arm | Rank | Rank fraction | Truth z |
|---|---:|---:|---:|
| primary | **54/4097** | **0.0131804** | **+2.32498** |
| key rotated | 3567/4097 | 0.870637 | -1.04211 |
| clause rotated | 2972/4097 | 0.725409 | -0.558601 |

The frozen prediction and both endpoint-control gates pass. The opened key
independently reproduces the public ChaCha20 output. No refit, retry or second
fresh key occurred.

This is a prospective attacker-computable complete-key joint-rank transfer with
all 256 key bits unknown at scoring time. It is not exact key recovery and does
not yet prove less real search work: each panel candidate still receives a full
forward execution. The result earns the next progress rung—inject the unchanged
target-specific criticality factors into exact search and measure equal-work
conflicts, time-to-hit and effective residual width.

## Mechanism

The useful signal comes from where a candidate execution makes target-selected
original functional clauses critical inside ordered branch-exclusive RUP paths.
Public output units and direct derived-clause satisfaction remain excluded. The
reader is byte-identical to O1C-0043:
`c4149a4695b13efac42268162f8381956c9616f24f25741abbce8d46be6f4d30`.

## Resources and integrity

- elapsed: `11.095178` s;
- peak RSS: `142,262,272` B;
- native H16 branches: `512`;
- complete forward evaluations: `4,097`;
- fresh targets / entropy calls: `1 / 1`;
- sibling reads/writes and MPS/GPU calls: `0`;
- persistent capsule: `284,774` B;
- capsule manifest SHA-256:
  `d22c6fa2e29b87641fb70e7a087777c8030b139132ecda43620b5b8f2f4bb38a`;
- result SHA-256:
  `b22f76e3fa9be4393f7e0cf03c3fa6f53607427b96ca630a45168ff03f93ef9e`.

[Immutable capsule](../runs/20260718_234233_O1C-0044_fresh-parent-criticality-rank-v1/RUN.md)
