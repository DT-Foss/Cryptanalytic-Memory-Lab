# Ranked Next Actions

Last ranked: 2026-07-17T04:53:42+02:00.

| Rank | Action | SOTA potential | Information gain | Reuse | Cost | Decision unlocked |
|---:|---|---:|---:|---:|---:|---|
| 1 | `O1C-0011`: compile a target-independent one-block exact ChaCha20 CNF with stable 256 key and 512 symbolic-output literal maps, streaming DIMACS below 256 MiB | State of the art infrastructure | Very high | Very high | Medium | Creates the first attacker-valid upstream sensor after end-output regression is closed |
| 2 | Prove the CNF/map contract on known full-width keys: unit-key solve reproduces all 512 outputs; unit-output plus revealed key is SAT; one flipped output is UNSAT | Infrastructure | Very high | Very high | Low | Prevents spending paired probes on a mis-mapped formula |
| 3 | On known uniform full-width keys, run symmetric `k_i=0/1` probes at frozen horizons and stream conflict, propagation, decision and proof-ancestry deltas; never reduce key width | State of the art | Very high | Very high | Medium | Identifies whether any public solver event has cross-key bit orientation |
| 4 | Feed event families through three 64/96/65 O1 vault timescales and compare unary, A465 PoE and identity-preserving A469 local interactions | State of the art | Very high | High | Medium | Tests the actual O1/O1-O synthesis with bounded state and matched work |
| 5 | Freeze on known TRAIN/CAL keys, then open a new sealed full-256 panel with assumption-swap, output-permutation, output-flip and ancestry-erasure controls | State of the art | Very high | High | High | Converts an upstream breadcrumb into prospective entropy reduction |
| 6 | Spend MPS/GPU only after CPU solver events show reusable entropy reduction and only in explicit windows that do not compete with W52 | High | Medium | High | High | Preserves recovery resources while scaling a demonstrated mechanism |

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
- fitting another direct/relative/distilled reader on raw final-output features or
  revisiting O1C-0010's signed scale;
- storing W52's 64 MiB pair permutations;
- global unconstrained copula corrections after A468's tail failure;
- treating raw ciphertext Hamming distance as dense evidence;
- polishing SOTA prose before a stable held-out bit exists;
- building a huge trainer before the attacker/teacher type boundary and metrics are
  executable.
