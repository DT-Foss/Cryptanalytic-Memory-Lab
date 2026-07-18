# O1C-0025 — Logit-native full-256 frontier handoff

- Recorded: `2026-07-18T04:15:00+02:00`
- Attempt: `O1C-0025`
- Claim level: `INSTRUMENT`; no scientific run is reserved
- Fresh targets, labels, reveals, solver work, entropy, sibling reads/writes,
  MPS and GPU: `0`

## Decision

O1C-0024 solved global factorized decoding from probabilities. The real
O1C-0019/O1C-0022 path natively emits calibrated log-odds. Converting those
values with a binary64 sigmoid is not a total handoff: sufficiently strong
positive or negative evidence rounds to exactly `1` or `0`, which O1C-0024
correctly rejects and which would erase relative penalties among confident bits.

O1C-0025 keeps the frozen O1C-0024 decoder byte-exact and adds the missing thin
adapter. For a natural-logit

```text
l_i = ln(P(K_i=1) / P(K_i=0)),
```

the exact factorized quantities needed by the frontier are computed without a
probability materialization:

```text
MAP bit                 = 1[l_i >= 0]
flip penalty in bits    = abs(l_i) / ln(2)
MAP log2 probability    = -softplus(-abs(l_i)) / ln(2)
```

The adapter uses O1C-0024's global best-first topology but ranks native logits
by exact common-power-of-two integer units of their binary64 absolute values.
Division by `ln(2)` is display-only. This preserves the true factorized ordering
even when two displayed bit penalties round to the same float or a sigmoid loses
the sign of a subnormal input. Runtime and retained search state remain
`O(K log K)` and `O(K)`; there is no `2^256` enumeration or candidate-indexed
memory. The frozen O1C-0024 source remains byte-exact.

## Exact upstream slice

Each O1C-0022 held-out prediction payload is float64 little-endian with shape
`[4 widths, 7 arms, 256 coordinates]`, exactly `57,344` bytes. The prospective
handoff is fixed before any result exists:

```text
width index 3 = K256
arm index   2 = quantized_int8_vault
selected shape = [256]
selected bytes = 2,048
```

The adapter validates the complete payload, finite values, arm/width identity
and exact byte counts, then returns an immutable selected vector. It never reads
`labels.bitpack`, a reveal, an evaluation or a true key. A different future
operator may call the generic logit decoder directly, but it may not silently
reinterpret O1C-0022's frozen arm selection.

## Freeze certificate

Before post-reveal evaluation, the certificate commits:

- source capsule manifest and artifact-index hashes;
- source prediction-freeze hash;
- exact source artifact path, hash, shape and byte count;
- exact selected-logit hash and `2,048` bytes;
- public-target hash, width, arm, coordinate order and logit semantics;
- candidate limit, logit-native exact-unit tie policy and zero truth/label reads.

The constructor does not accept those lifecycle hashes as unsupported labels.
It verifies the supplied capsule manifest, artifact index, O1C-0022 held-out
prediction-freeze document and its upstream O1C-0019 prediction-freeze document.
The chain must bind the exact selected artifact to
K256/`quantized_int8_vault`, the fold path, fold ordinal, target ID, action pool
and finally the upstream
`public_view_sha256 == public_target.digest()`. Candidate limit is fixed to
`65,536`. Any mismatched but individually well-formed payload fails closed.

This source instrument proves internal consistency of the supplied chain. It
does not pretend that caller-controlled bytes authenticate themselves as the
future authoritative attempt: a formal deployment must first obtain them from
`RunCapsuleManager.finalized_attempt("O1C-0022")` and verify that finalized
manifest. O1C-0025 cannot perform that resolution yet because O1C-0022 has not
finalized, and it reserves no run.

The certificate contains no key or target trace. Exact ChaCha20 verification is
attacker-valid because it consumes only candidate keys and the public counter,
nonce and output. Hamming distance or true rank remains a separate post-freeze,
post-reveal diagnostic.

## Discriminators

1. A fixed moderate, well-resolved logit panel must produce identical ranked
   keys and topology as O1C-0024 after an independently computed non-saturating
   sigmoid, with displayed penalties and log2 scores equal to `1e-12`. This is
   a discriminator, not a universal binary64 roundtrip claim.
2. Adjacent binary64 logits whose probability-space penalties collide must keep
   their exact natural-logit order; logits with magnitude `1000` must remain
   finite and ordered although their binary64 sigmoid would be exactly `0/1`.
3. Equal penalties must keep the O1C-0024 topology tie order.
4. A constructed standard 20-round ChaCha20 target must be found at the declared
   rank by public verification, with truth absent from generation.
5. Certificate and selected bytes must be deterministic and hash-recomputable;
   dummy lifecycle hashes, a foreign public target, a foreign fold, off-config
   widths/arms/limits, malformed shapes, byte counts, hashes and non-finite
   logits must fail closed.

## Transition

This closes only the deployment handoff; it does not create cryptanalytic signal.
If frozen O1C-0022 produces portable positive K256 evidence, its logit slice can
now enter O1C-0024 immediately and be verified without reveal. If O1C-0022 returns
an all-float null, no decoder or quantizer change can create missing orientation:
O1C-0023 must instead select `proof_ancestry_pair_residual_v1`, testing projected
assumption-coordinate x ancestry-coordinate interactions on consumed BUILD data.

## Source verification

- 14 focused O1C-0025 tests pass, including extreme-logit saturation, an
  exhaustive rational subset-order proof, the adjacent-binary64 ULP regression,
  complete lifecycle/target binding, exact O1C-0022 slice binding,
  foreign-vector rejection, deterministic ties and a standard 20-round public
  ChaCha20 rank-four hit.
- The 18 neighboring O1C-0024 decoder/runner tests remain green; Ruff, Mypy,
  `py_compile` and JSON validation pass.
- A non-formal CPU-only 65,536-candidate smoke of the final exact-integer engine
  emitted the complete frontier in `0.937653` wall seconds with `44,384,256`
  process peak-RSS bytes. It consumed no target, solver, sibling, entropy or
  accelerator work and is a performance smoke, not a scientific result.
