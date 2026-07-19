# Apple view 3: one anonymous carry poisons the scalar stream

## The smallest exact question

APPLE-VIEW-0002 made every non-LSB carry independent and consequently erased
all public linear key information.  This continuation restores the real carry
recursion globally, one bit layer at a time, in all 336 additions of one
standard 20-round ChaCha20 block:

```text
sum_i       = x_i XOR y_i XOR c_i
c_(i+1)     = majority(x_i, y_i, c_i)       for i < depth
c_(i+1)     = UNKNOWN                        for i >= depth
```

Instead of asking a large solver to invert the cipher, the experiment asks a
smaller attacker-valid question for each complete 256-bit probe key:

> Does exact forward carry knowledge determine even one public output bit, and
> if so, does that bit already contradict the observed block?

The evaluator uses exact strong three-valued logic.  A known bit is guaranteed
to have that value for every completion of the remaining unknown carries.
Therefore a known mismatch rigorously rejects the probe key.  A survivor is
only “not rejected by this forward abstraction”; it is not claimed
satisfiable.  This keeps the result one-sided and exact without pretending that
32 probes estimate the global 256-bit entropy.

## Boundary

- Primitive: one RFC 8439 ChaCha20 block with all 20 rounds and all 256 key bits
  unknown in the base problem.
- Public view: constants, counter, 96-bit nonce, and one 512-bit output.
- Target: fixed SHAKE-256 build target, committed unsealed; no fresh or sealed
  challenge was consumed.
- Thirty-two fixed SHAKE-256 probe keys are derived independently of the public
  output.  They are diagnostic membership probes, not a recovery enumeration.
- Neither target nor truth enters probe generation, and the truth key never
  enters `score_probe`; it is used after each depth only to prove that the
  abstraction did not reject the real execution.
- One CPU process, no network, GPU, or MPS.

## Reference result

| Carry depth | exact recurrences | free carries left | known final bits | exactly rejected probes |
|---:|---:|---:|---:|---:|
| 0 | 0 | 10,416 | 0 | 0/32 |
| 8 | 2,688 | 7,728 | 0 | 0/32 |
| 16 | 5,376 | 5,040 | 0 | 0/32 |
| 24 | 8,064 | 2,352 | 0 | 0/32 |
| 28 | 9,408 | 1,008 | 0 | 0/32 |
| 29 | 9,744 | 672 | 0 | 0/32 |
| 30 | 10,080 | 336 | 0 | 0/32 |
| 31 | 10,416 | 0 | 512 | 32/32 |

No partial depth produced a public output bit or rejected a probe.  Only depth
31—the ordinary exact forward block—recovered all 512 output bits and rejected
all 32 wrong probes.  There was no key recovery, no exact key bit, and no
claimed entropy reduction.

The useful trace is inside the first double round.  At depth 30, every addition
has only its last carry unresolved.  The number of known state bits after the
eight quarter rounds is nevertheless:

```text
512 initially -> 473 -> 426 -> 372 -> 325 -> 247 -> 166 -> 82 -> 0
```

At depth 29 it is `454 -> 381 -> 313 -> 240 -> 183 -> 121 -> 59 -> 0`.
Thus a single anonymous carry per addition is enough for rotations and XORs to
cover the entire state within one double round.  This is why slowly increasing
scalar carry depth has an all-or-nothing output frontier.

## What this closes, and the breadcrumb

Close the scalar continuation “replace unresolved carries by one undifferentiated
UNKNOWN and wait for a final known bit.”  It gives no partial Full256 branch
filter at any depth below 31.

The negative boundary is narrow.  The missing object is not another carry
layer; it is **identity and relation between unknowns**.  `UNKNOWN XOR UNKNOWN`
is scalar-unknown even when both occurrences came from the same carry and would
cancel, and forward evaluation cannot use the public output backward.  The next
simple-but-expert attempt should therefore keep compact carry identities or
relations—an affine/paired abstract domain, a small carry automaton, or an
O1-bound operator stream—and intersect them with public output constraints
before diffusion erases their labels.  That is directly compatible with the
main O1/O1-O direction: bind the unresolved event instead of discarding its
identity.

## Reproduction and ledger

Run from this directory:

```text
python3 -m unittest -v apple_view_3_test_carry_depth.py
python3 apple_view_3_carry_depth.py --output apple_view_3_result.json
```

Eleven tests pass.  They cover the RFC block vector, exhaustive abstract-majority
soundness, 2,048 deterministic adder checks across all 32 depths, exact depth-31
equivalence to concrete full-round ChaCha20, the fixed below-31 collapse, truth
non-rejection, output-independent probes, JSON safety, and path confinement.

Reference run: 2026-07-19 02:15:18–02:15:31 CEST.  It executed 1,056 abstract
full blocks, 354,816 abstract word additions, 5,499,648 exact carry recurrences,
and 10,813,440 abstract XOR bits in 13.232632 CPU seconds / 13.291865 wall
seconds.  Peak process RSS was 27,295,744 bytes and peak traced Python allocation
was 74,044 bytes, below the fixed 30-second CPU and 128-MiB limits.

Hashes for this reference:

```text
source  0873bdcbae3d28b26a2d77f97767fed9565ee096a5b9b992810353a4ffde5b1a
tests   bdc953dfcf8219584e0bd2ed91f88915db6ebd470d7dfaef02a4c4b70cc8d746
result  db8f803174f80df64639b343cf3e7906efd2cab8709e99a94c182c86d6ab8293
science db62ceaa6de7568abfbda2d3abcb8ca56e99ea72a91141a17594774d3ec080d5
target  95d023ce709273f535fae443309833c2fbde58e09493671b3a8b8a10633a2a0e
```

The complete per-depth rows, first-double-round traces, fixed target, artifact
hashes, and resource counters are in `apple_view_3_result.json`.
