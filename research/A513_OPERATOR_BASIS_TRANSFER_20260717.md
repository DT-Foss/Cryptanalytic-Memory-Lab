# A513 Operator-Basis Transfer Note

- **Recorded:** 2026-07-17T09:23:45+02:00 (`Europe/Berlin`)
- **Source handling:** read-only inspection of the sibling `arx-carry-leak`
  workspace; zero sibling writes
- **Claim boundary:** architecture input for a future O1 sensor, not an O1C-0015
  result and not an O1C-0015 inference input

## Transferable result

The sibling recovery line has moved beyond a single standard-output encoding.
Its frozen A512 preflight records the already-qualified A508
`XOR_DELTA_STATE_R20` representation against `FINAL_DELTA_R20` on public
standard ChaCha20 outputs:

| Width | Conflict ratio | Propagation ratio | Paired improvements |
|---|---:|---:|---:|
| W20 | 0.6742 | 0.4502 | 3/4 conflicts, 4/4 propagations |
| W24 | 0.6122 | 0.5170 | 4/4 conflicts, 4/4 propagations |

A513 then freezes six exactly equivalent zero-sum operator bases over the eight
public output blocks: adjacent chain, balanced tree, Gray chain, modular
Möbius-3D, a deduplicated union frame and the complete pairwise frame. Every
basis cancels the shared secret addend, retains standard feed-forward output,
passes exact span/unimodularity gates, and is being compared under the same
solver budget.

## O1 interpretation

Equivalent public equations can produce different proof trajectories even when
they carry the same mathematical solution set. This supplies a stronger notion
of holographic wavelength than merely stopping one solver at horizons 64, 96
and 65:

```text
public ChaCha output
  -> equivalent exact operator basis
  -> paired proof/carry stream
  -> basis-bound holographic phase
  -> coordinate query reader
```

The basis ID is public and target-independent, so it can bind a reader operator
without leaking the unknown key. The causal Attic can retain exact relations and
cross-basis proof motifs; the bounded O1 state needs to hold only the current
evidence field and a small basis/operator address.

## Decision for the active ladder

O1C-0015 remains the already selected two-wavelength blind replication:
unchanged h96 plus the fixed equal-logit h96+h65 reader on 32 new sealed keys.
Importing A513 now would mix a new sensor with the replication question.

If O1C-0015 does not establish a transferable unary direction, the next sensor
successor combines the query-rooted carry/proof cone with a small fixed subset
of A513-style exact operator bases. It must reuse one public target, freeze every
basis and phase before target entropy, and measure basis complementarity rather
than multiply independent key searches.
