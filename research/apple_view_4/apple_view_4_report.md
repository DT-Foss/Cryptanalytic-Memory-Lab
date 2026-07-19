# Apple view 4: bidirectional local constraints still hit the depth-31 cliff

## Direct counterexperiment

APPLE-VIEW-0003 replaced unresolved carries by scalar `UNKNOWN` and propagated
only forward.  This run gives the partial circuit both ends:

```text
complete 256-bit probe key  ->  partial-carry ChaCha20 relation  <-  public block
```

Every XOR2, XOR3, and carry-majority gate is an exact Boolean truth-table
constraint.  Deterministic generalized arc consistency repeatedly removes
locally impossible values from either direction until a fixed point.  There is
no branching, CDCL, stochastic choice, or conflict budget.  If a constraint has
no compatible truth-table row, the complete probe key is rigorously impossible.
If propagation stops without a conflict, the result is only `UNKNOWN`, not SAT.

For carry depth `d`, every one of the 336 additions uses the real recurrence for
`c1..c_d`; the remaining carries are independent existential Boolean variables.
The prospectively reduced matrix is depths `24,28,29,30,31` and four fixed
SHAKE-256 probe keys.  The probes use neither target nor truth.  The matrix was
reduced before the reference run because an initial 8-depth × 8-probe attempt
reached the hard run boundary without publishing a result.

## Attacker boundary

- Standard RFC 8439 ChaCha20 block, all 20 rounds, all 256 key bits unknown in
  the base problem.
- Public input: constants, counter, 96-bit nonce, and one 512-bit output block.
- A complete candidate key is only a diagnostic assumption for exact rejection;
  this experiment does not generate candidates or recover a key.
- Fixed unsealed build target; no fresh or sealed challenge was consumed.
- Truth is used only after propagation to verify that every relaxation retains
  the real execution.
- One CPU process; no solver search, network, GPU, or MPS.

The frozen success gate was: **at least one wrong probe conflicts at depth below
31**.

## Result

| Depth | exact majority constraints | free carries | truth status | assigned vars, wrong probes | exact conflicts |
|---:|---:|---:|---|---:|---:|
| 24 | 8,064 | 2,352 | UNKNOWN | 2,962–2,985 | 0/4 |
| 28 | 9,408 | 1,008 | UNKNOWN | 3,848–3,893 | 0/4 |
| 29 | 9,744 | 672 | UNKNOWN | 4,131–4,205 | 0/4 |
| 30 | 10,080 | 336 | UNKNOWN | 4,490–4,620 | 0/4 |
| 31 | 10,416 | 0 | CONSISTENT_COMPLETE | 29,438–29,852 before conflict | 4/4 |

The success gate failed.  Bidirectional propagation penetrated substantially
further than scalar forward propagation—at depth 30 it inferred another
3,720–3,850 variables beyond the 770 fixed constants/key/output variables—but
the one remaining free carry per addition absorbed every local contradiction.
Only the complete depth-31 relation rejected the four wrong probes.  The true
key never conflicted and became a complete consistent assignment at depth 31.

There was no key recovery, recovered key bit, or global entropy claim.  Four
probes are not used to estimate a rejection probability.

## Boundary and next breadcrumb

Close only this mechanism: local truth-table propagation, even from both ends,
does not turn partial carry depth into a Full256 filter on this fixed matrix.
Unlike Apple View 3, public constraints do flow backward and assign thousands
of internal variables, so the failure is no longer “no signal enters.”  The
failure is that locally consistent carry choices do not have to agree along a
large enough cycle to produce a contradiction.

The next distinct mechanism must join correlations across constraints rather
than repeat deeper local propagation.  Small bounded candidates include paired
carry identities, affine relations between repeated unknowns, short
quarter-round cycle cuts, or an O1-bound stream that preserves which carry event
reappears where.  That is the smallest remaining step between scalar/local
consistency and expensive unrestricted search.

## Reproduction and ledger

Run from this directory:

```text
python3 -m unittest -v apple_view_4_test_bidirectional_carry.py
python3 apple_view_4_bidirectional_carry.py --output apple_view_4_result.json
```

Ten tests pass.  They cover the RFC block vector, fixed probe/target generation,
truth-free compilation, exact global gate counts, a synthetic backward XOR
inference and conflict, truth retention, depth-31 concrete completion and false
conflict, one-sided JSON semantics, stable scientific hashing, and output path
confinement.

Reference run: 2026-07-19 02:30:30–02:30:48 CEST.  It compiled five networks
with 158,330 variables and 152,672 exact constraints in total, performed 25
propagations, visited 663,596 constraints, checked 4,525,456 truth-table rows,
and inferred 208,901 assignments.  Runtime was 18.020902 CPU seconds / 18.124440
wall seconds.  Peak process RSS was 87,867,392 bytes and peak traced Python
allocation was 22,156,308 bytes, below the fixed 30-second CPU and 128-MiB
limits.

Reference hashes:

```text
source  5df8889dff469d3add31f70b83d12f4e96ebfa9dd9241b7affb351ed118878b4
tests   a5062bf5de2909da63c4ce9c668ea9cd498ef94f9af04f2bdb62771be86ff01e
result  08f45f60b625dd1f20357144a322caaa3eee66cc349d54d41f43e0e30dc5e461
science b6ea61515410088487ec90888a5127773280214935a4983dd45d3139aea48949
target  fa12050df20cc4c4d2f33a1b1d88e52f6194ee72bc01b928d00ca4d0d161c527
```

The full per-probe rows, constraint counts, propagation work, resource ledger,
and stable scientific payload hash are in `apple_view_4_result.json`.
