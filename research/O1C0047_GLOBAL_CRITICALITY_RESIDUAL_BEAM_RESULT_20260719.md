# O1C-0047 — Global criticality residual beam

- **Recorded:** 2026-07-19T00:40:19+02:00
- **Classification:** `POST_REVEAL_GLOBAL_CRITICALITY_COMPRESSES_RESIDUAL16`
- **Source freeze:** `0a34020cb1f3cd88929d55811c9b2b48fa247f7c`
- **Target:** consumed O1C-0044 ChaCha20-R20 target

## Result

The unchanged O1C-0044 complete-assignment score was evaluated over every key in
a nested local cube. The 16 coordinates were selected by the frozen parent-score
support order. Every candidate is a complete 256-bit key and receives a real
full-round public forward execution before scoring.

| Residual cube | Primary truth rank | Key rotation | Clause rotation |
|---:|---:|---:|---:|
| 8 bits / 256 | **1** | 241 | 176 |
| 12 bits / 4,096 | **5** | 3,870 | 2,710 |
| 16 bits / 65,536 | **50** | 60,592 | 43,059 |

The width-16 primary rank fraction is `0.0007629395` (top `0.0763%`). The frozen
top-256 primary beam contains exactly one key matching the public ChaCha20 output,
at rank 50, and independent verification identifies it as the exact consumed
key. Neither rotated top-256 beam contains a public match.

Within this privileged W16 cube, the unchanged global score reduces exhaustive
enumeration from 65,536 candidates to time-to-hit 50: `10.356144` bits of search
compression and `5.643856` effective enumeration bits. This directly explains
O1C-0045/0046: the signal exists at complete-state level, while their greedy
one-variable reductions discard it.

## Boundary

This is a **post-reveal completion ceiling**, not attacker-valid Full-256
recovery. The other 240 key bits are fixed to consumed truth. No target labels
enter the frozen score itself, no reader is refit, and coordinate selection does
not use these cube outcomes; nevertheless the cube construction has privileged
truth and cannot be called a 256-unknown attack.

The next authorized conversion is the smallest pre-reveal pairwise key-group or
prefix scheduler that approximates this complete-state ordering inside the exact
solver. It must compare primary with internal and both rotations under matched
work before any fresh target.

## Cost and artifacts

- 67.546893 s elapsed; 67.067707 CPU s
- 89,325,568 B peak RSS
- 65,536 complete forward evaluations; 196,608 potential scores
- 769 independent public-output verifications
- 1,647,038 B persistent capsule payload
- Result SHA-256:
  `91709eb6c7a0f378e8ef0046a81d4211a428d75fa6636553c218c023cab3380d`
- Capsule manifest SHA-256:
  `2c4bbb4986b175e84748da9c2bf24f65aecff5e3ff0a3d95e3b0ee2bbd2bf117`
- [Capsule](../runs/20260719_004019_O1C-0047_global-criticality-residual-beam-v1/RUN.md)
- [Machine-readable result](O1C0047_GLOBAL_CRITICALITY_RESIDUAL_BEAM_RESULT_20260719.json)
