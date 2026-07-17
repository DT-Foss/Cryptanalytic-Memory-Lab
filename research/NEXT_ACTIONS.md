# Ranked Next Actions

Last ranked: 2026-07-17T02:44:45+02:00.

| Rank | Action | SOTA potential | Information gain | Reuse | Cost | Decision unlocked |
|---:|---|---:|---:|---:|---:|---|
| 1 | `O1C-0008`: implement exact traced Full-Round ChaCha20, a public-only attacker view, physically separate privileged teacher labels and structured/uniform 256-bit contrast generation | State of the art | Very high | Very high | Low | Creates the first honest full-width learning and attack substrate |
| 2 | Implement the progress vector: 256-bit NLL, stable-bit count, byte/16-bit ranks, million-decoy true-key rank, effective compression and exact-beam verification | State of the art | Very high | Very high | Low | Makes one real bit visible instead of calling every non-recovery a zero |
| 3 | `O1C-0009`: train matched raw-output, candidate-relative and teacher-distilled 256-bit readers on CPU; target traces are unrepresentable in the deployment type | State of the art | Very high | High | Medium | Localizes whether public output, self-generated trace or distillation supplies the first transferable bit |
| 4 | `O1C-0010`: stream evidence into the 20,492-byte O1 state with H1/H2/H4/H8, wavelengths 64/96/65, A465 PoE and A469 positive bucket-local correction | State of the art | Very high | Very high | Medium | Tests the actual O1/O1-O synthesis on a full 256-bit target |
| 5 | Freeze a new uniform random target and run matched shuffled-key, output-flip and wrong-nonce controls; feed the revealed result into the attic only after completion | State of the art | Very high | High | Medium | Converts development signal into a genuine next-challenge learning loop |
| 6 | Spend MPS/GPU only after CPU diagnostics show reusable entropy reduction and only in explicit windows that do not compete with W52 | High | Medium | High | High | Preserves recovery resources while scaling a demonstrated mechanism |

## Hard target contract

- Standard ChaCha20, 20 rounds plus feed-forward.
- All 256 key bits are unknown and sampled uniformly for serious holdouts.
- Public counter, nonce and output are known.
- Target internal state, carry trace, target-key prefix and target solver trace are
  unavailable to every deployment component.
- A model may compute any trace for keys it generated itself.
- Twelve-bit windows are internal interventions only, never reduced-width targets.
- No `2^256` enumeration, candidate dictionary or growing transcript in living
  state.

## Resource gate while sibling W52 is active

- Keep `arx-carry-leak` read-only.
- Run source generation, unit tests and small CPU batches locally.
- Recheck memory pressure and process RSS before long training.
- No MPS window and no large proof-corpus copy while recovery workers are active.

## Do not spend the next cycle on

- scaling a recovered-width ladder from W12 through W52;
- repeating O1C-0007's unary A355 sweep;
- storing W52's 64 MiB pair permutations;
- global unconstrained copula corrections after A468's tail failure;
- treating raw ciphertext Hamming distance as dense evidence;
- polishing SOTA prose before a stable held-out bit exists;
- building a huge trainer before the attacker/teacher type boundary and metrics are
  executable.
