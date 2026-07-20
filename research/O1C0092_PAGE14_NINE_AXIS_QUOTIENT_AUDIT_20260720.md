# O1C-0092 Page-14 nine-axis quotient audit

Recorded 2026-07-20 CEST. This is a read-only structural audit of the sealed
O1C-0092 episode vault, with the sealed O1C-0082 episode vault used only for
the requested historical comparison. No solver, native executable, preflight,
target, truth-key, reveal, refit, retry or replay was used. No claim below
depends on a hidden-key value.

Clauses are treated as canonical signed-literal sets. A key-projection bit is
`1` when the positive literal is present and `0` when the negative literal is
present. Canonical clause hashes use the vault encoding
`u32le-length;signed-i32le-dimacs-literals` in strictly increasing absolute
variable order. Derived projection hashes use compact sorted ASCII JSON with
one trailing newline.

## Sealed source and exact population

The audited source is
`runs/20260720_205659_306771_O1C-0092_apple8-parent-centered-continuation-v1/episodes/00/vault.json`.

| Field | Exact value |
|---|---:|
| Serialized bytes | `5,265,088` |
| File SHA-256 | `8cb5123d0867923a778ef08d64f73b71f51f8c41003b913da183f21e91dbd61b` |
| Schema | `o1-256-cadical-score-threshold-no-good-vault-telemetry-v1` |
| Fully emitted clauses | `261` |
| Fully emitted literals | `756,414` |
| Fully emitted aggregate SHA-256 | `dad3883312e769efb4a650557a8cd0fdf0e53e0ca6ecbc840fb335c76730fce0` |
| New/current-duplicate/input-duplicate clauses | `261 / 0 / 0` |
| Empty or tautological clauses | `0 / 0` |
| Distinct clause identities | `261` |
| Distinct witness identities | `261` |
| Unsigned variable union | `2,953` |
| Unsigned support intersection | `2,827` |
| Terminal reason | `capacity_clause_count` |

The exact clause-length histogram is:

```text
2,879 x 1
2,883 x 1
2,898 x 256
2,915 x 1
2,916 x 1
2,933 x 1
```

All 261 witnesses have source `trail_upper_bound`. The vault's own semantic
rule is
`valid-for-identical-CNF-and-score-potential-at-threshold;not-CNF-entailed`.
That boundary is material: the clauses are exact exclusions for the sealed
score-threshold problem, not unconditional consequences of the CNF alone.

## Common signed core

The intersection of all 261 clauses contains exactly `2,709` signed literals:

- `245` key literals over variables `1..256`;
- `2,464` internal literals;
- canonical clause SHA-256
  `80778216ca840ef50729fe16c146c235841e16e70bd86b87ba37edd674e16b19`.

The key coordinates absent from the signed intersection are

```text
15, 18, 23, 28, 100, 118, 181, 216, 220, 238, 241
```

Variable `241` is absent from every clause. Variable `220` is present in only
four clauses, twice positively and twice negatively. The other nine listed
coordinates occur everywhere but switch polarity.

The 100 fixed-positive key coordinates are:

```text
1, 4, 6, 10, 11, 16, 20, 21, 26, 30, 33, 35, 38, 39, 42, 43,
44, 46, 48, 51, 53, 55, 57, 60, 63, 67, 69, 70, 74, 76, 80, 84,
85, 90, 92, 94, 96, 97, 99, 103, 106, 109, 110, 113, 115, 121,
127, 129, 131, 135, 139, 141, 143, 146, 147, 149, 155, 158,
160, 162, 165, 168, 169, 170, 173, 175, 178, 179, 183, 185,
188, 189, 190, 192, 196, 198, 200, 201, 203, 204, 206, 209,
212, 214, 215, 219, 222, 223, 226, 228, 230, 233, 236, 240,
242, 243, 246, 249, 253, 255
```

Every other key coordinate outside the 11-coordinate exception set is fixed
negative. This complement rule identifies all 245 signed key literals without
printing the 2,464-literal internal portion.

## The 256-row tail is a nine-axis repetition code

Clauses `5..260` are the 256 equal-length tail rows. They all have exactly
`2,898` literals on one identical unsigned support. Their signed intersection
has `2,780` literals and canonical clause SHA-256
`cf45b2d8579e49592590346fed334da66588e889115abadbff1f1ddafa6e9380`.
The remaining `118` variables switch sign.

Those 118 signs have affine rank nine and are not independent. Every one is
an exact copy or complement, across all 256 rows, of one of these ordered key
axes:

```text
(15, 18, 23, 28, 100, 118, 181, 216, 238)
```

For an axis bit `b`, a variable in the `same` column is positive exactly when
`b=1`; a variable in the `inverted` column is positive exactly when `b=0`.
The weight is the total number of variables that flip with that axis.

| Axis | Same variables | Inverted variables | Weight |
|---:|---|---|---:|
| `15` | `15, 63464, 63631, 127208, 127375, 190952, 191119` | `127209` | `8` |
| `18` | `18, 31595, 31762, 159083, 159250` | `222827` | `6` |
| `23` | `23, 31601, 31767, 31768, 127216, 127383, 222832, 222999` | `159088` | `9` |
| `28` | `28, 31605, 31772, 95349, 95350, 95352, 95353, 95516, 95517, 95518, 95519, 95520, 127221, 127388, 254709, 254710, 254876, 254877` | `190965, 254711` | `20` |
| `100` | `100, 63101, 63716, 222461, 223076` | `31229, 94973, 126845, 158717` | `9` |
| `118` | `118, 31215, 31862, 63087, 63088, 63734, 63735, 190575, 190576, 190577, 191222, 191223, 191224, 254319, 254966` | `190578` | `16` |
| `181` | `181, 95305, 95669, 127177, 127179, 127541, 127542` | `63433, 127181, 190921, 222793, 254473` | `12` |
| `216` | `216, 62289, 62291, 63832, 63833, 63834, 157905, 159448, 159449, 253521, 253523, 255064, 255065, 255066` | `62293, 94159, 126031, 221647, 253525` | `19` |
| `238` | `238, 30779, 30781, 31982, 31983, 126395, 126397, 127598, 127599, 158267, 159470, 222011, 222013, 223214, 223215` | `30783, 62651, 126399, 222015` | `19` |

The weights sum to `118`. There are exactly 18 distinct copy/complement
functions: both polarities of each of the nine axes. As an independent audit
seal, encode each switching variable in increasing order as
`[variable, inversion_bit, 1 << axis_position]`, then compact-JSON encode the
118 rows with a trailing newline. The resulting 1,574-byte map has SHA-256
`c3103ef67f4edf1cb93f7443e1c3f7866bdb30af53c7866ca9376be396618185`.

## Cube geometry and multiplicities

Use the eight-axis order

```text
(15, 18, 23, 28, 100, 118, 181, 216)
```

and retain `238` as the ninth marker axis. The 256 tail rows are not an exact
8-bit cube:

- they contain 254 distinct eight-axis projections;
- the `00000110` and `01000110` projections are missing;
- `00000000` and `10000000` each occur twice, once with `+238` and once with
  `-238`;
- equivalently, the nine-axis set is the complete `+238` face with the two
  holes above, plus the two `-238` intrusions;
- its nine-axis affine rank is `9`, but the 256-point set is not affine;
- no deletion of one of the nine literal coordinates yields 256 unique
  eight-bit projections.

The two intrusions are tail indices `259` and `260`:

| Index | Eight-axis pattern | `238` | Clause SHA-256 |
|---:|---|---:|---|
| `259` | `00000000` | `-` | `fc5241329354bdf3c4e637a5092ccaa8d450737ad388dfac039bef0b6dda232e` |
| `260` | `10000000` | `-` | `52fbc38425dd92098a082481c245f8be144c2fa5abdb821448e0b4c7014580d8` |

The five prefix rows fill the two holes:

| Index | Literals | Eight-axis pattern | `220` | `238` | Clause SHA-256 |
|---:|---:|---|---:|---:|---|
| `0` | `2,883` | `00000110` | `+` | `+` | `08d79d0a2f4e8c5674a57d4922070671a00ed5f83f2fcf749b80badea456e900` |
| `1` | `2,915` | `00000110` | `+` | `+` | `89812b91408e9f8c8bb76e19767b76aef8d64eec59f280356a3eb0d5a3021feb` |
| `2` | `2,933` | `00000110` | `-` | `+` | `6241a56d6dcfe516d018ee1ea137eb1719add6389b9b674aa0b6df23462ba161` |
| `3` | `2,916` | `00000110` | `-` | `+` | `59b7b1281f2188319fca2fd7edb7bc1f8822b5789812236d11ffeccfa51def16` |
| `4` | `2,879` | `01000110` | absent | `+` | `27cefb7e40da1e0ac878e9b08956800e3919dfc31961ebcfe840cd2635d91b13` |

Consequently, all 261 rows projected onto the eight axes cover the exact
256-cell cube, but with these exact multiplicities:

- `253` patterns occur once;
- `00000000` and `10000000` occur twice;
- `00000110` occurs four times.

The full key projection has `259` unique signed tuples and set SHA-256
`7c3d76baea7bc37271955b6c55da8960db9d1cca215f62dabf5f2662bdd5d255`.
The eight-axis projection has `256` unique tuples and set SHA-256
`4a636f3bd41a00b65530dfeddafdab63df678da776e6978c621fcc1369b1d396`.
The tail's nine-axis projection has `256` unique tuples and set SHA-256
`77b966b9ccc19bfdc05a318556b393818f9d9728af3ad2e1b9965bd800107439`.

## Hamming edges, resolution and subsumption

The unique eight-axis cube has the expected `1,024` Hamming-distance-one
edges. Clause multiplicities expand these to `1,065` raw clause pairs whose
eight-axis projections differ at exactly one coordinate. Every such pair has
between `5` and `38` additional complementary non-pivot literals; the median
is `11` and the mean is `11.656338028169014`. Every projected edge therefore
produces a tautological full-clause resolvent.

Across all `33,930` unordered full-clause pairs:

- exactly `0` pairs contain exactly one complementary variable;
- exactly `0` non-tautological simple resolvents exist;
- the 256 equal-support tail clauses have minimum full Hamming distance `6`,
  attained by `127` pairs;
- there are no full-clause Hamming edges;
- there is exactly one proper signed-set subsumption.

The sole subsumption is clause `3` strictly subsuming clause `2`. Clause `2`
has these 17 additional literals:

```text
94539, -95733, -126413, -126415, 126417, -127605, -127606,
-127607, -127608, -190157, -190159, 190161, -191350, -191351,
-191352, 253899, -255093
```

Deleting clause `2` is therefore an exact formula-preserving simplification.
It removes `2,933` literal occurrences, or `0.3877506233%` of this telemetry
population. No other clause can be removed by exact equality or subsumption.

## Relation to the O1C-0082 cube

The comparison source is
`runs/20260720_143008_461948_O1C-0082_apple8-parent-centered-v1/episodes/00/vault.json`.

| Field | O1C-0082 | O1C-0092 |
|---|---:|---:|
| Serialized bytes | `5,160,861` | `5,265,088` |
| File SHA-256 | `9c7705591948e1f3b4ee1589cf431c8bd9a5844bad670ddb1c713c4d1d3e5445` | `8cb5123d0867923a778ef08d64f73b71f51f8c41003b913da183f21e91dbd61b` |
| Clauses / literals | `257 / 743,129` | `261 / 756,414` |
| Aggregate SHA-256 | `bcc424b009ff132348d5ac73227162395853d894c68ced65f9cd6494c3c0868d` | `dad3883312e769efb4a650557a8cd0fdf0e53e0ca6ecbc840fb335c76730fce0` |
| Common signed core | `2,764` | `2,709` |
| Key / internal core | `247 / 2,517` | `245 / 2,464` |
| Canonical core SHA-256 | `9aa383f819d1aa4b1216937ee341aa6a773d1d3456e1ea622494ef1a4345ea06` | `80778216ca840ef50729fe16c146c235841e16e70bd86b87ba37edd674e16b19` |
| Unique full key projections | `256` | `259` |
| Simple non-tautological resolvents | `0` | `0` |
| Strict internal subsumptions | `1` | `1` |

O1C-0082's eight varying key axes are
`{21,24,49,55,66,90,100,153}`. In the explicit order
`(21,24,49,55,66,90,100,153)`, all 256 patterns occur and `00100111` occurs
twice, at indices `0` and `1`. Index `1` strictly subsumes index `0`; deleting
index `0` leaves one row for every projected cube cell. The unique cube has
`1,024` projected edges, expanded by the duplicate to `1,032` raw pairs. Each
has `6..23` other complementary literals, so O1C-0082 also has no simple
non-tautological resolvent. Its full key-projection set SHA-256 is
`4d822158d8667187e6427c993ff6b7589e362515a19ab81121e0ecbe161a202d`.

O1C-0092 is thus not a recurrence of O1C-0082's clean projected cube. Only
axis `100` belongs to both varying-axis sets. Coordinate `238` changes from
fixed positive in O1C-0082 to O1C-0092's near-constant ninth marker;
coordinate `220` changes from fixed negative to sparse optional. Of the `238`
key coordinates fixed in both populations, `180` retain their sign and `58`
flip. These changes forbid interpreting either common orientation as a stable
key-bit belief.

## Exact consequence for key recovery

There is no key-only consequence from this vault family in isolation.

Let `F` be the conjunction of the 261 emitted clauses. The internal literal
`-30373`, among 2,464 others, occurs in every clause. For any assignment to all
256 key variables, setting variable `30373=false` makes `-30373` true and
satisfies every clause in `F`. Therefore the existential projection

```text
exists internal_variables . F
```

is identically true over the key domain. In particular:

- the complete eight-axis projection excludes no eight-bit assignment;
- neither sign of `220` or `238` is forced;
- variable `241` receives no literal evidence at all;
- the 245 common key signs are shared disjuncts, not unit clauses or a
  backbone;
- projection obtained by dropping internal literals would strengthen the
  clauses and is not an authorized logical inference.

The bound CNF can constrain internal variables, so this tautology statement is
strictly about the emitted vault family by itself. Establishing a key-only
consequence for the combined CNF-plus-score-threshold problem would require a
separate proof against the same sealed CNF and score identity. This audit did
not perform that proof.

## Highest-ROI mechanism: lossless nine-axis quotient

The recommended mechanism is a lossless representation and audit quotient,
not immediate logical substitution:

1. Store the five prefix clauses unchanged (`14,526` literal entries).
2. Store the 256-row tail's `2,780`-literal signed core once.
3. Store the `118`-variable copy/complement map above once.
4. Store one nine-bit pattern for each tail row.
5. Reconstruct the original canonical clauses byte-for-byte before passing
   them to any consumer that expects the flat vault format.

Even before bit-packing steps 3 and 4, merely sharing the tail core changes the
literal-entry accounting from

```text
raw                 = 756,414
five prefix rows    =  14,526
one tail core       =   2,780
tail residuals      =  30,208  (256 x 118)
factored total      =  47,514
saved               = 708,900
ratio               = 15.9198131077x
reduction           = 93.7185192236%
```

The nine-bit codewords and 118-row decoder can compress the residual portion
further, but no serialized-byte claim is made until a canonical quotient
format and round-trip validator exist. The 15.92x figure is therefore a
conservative, exact literal-entry ratio, not a projected file-size benchmark.

This quotient is immediately useful for lossless storage, identity checking,
Hamming analysis and focused subsumption. It must not be used to replace
internal variables by key axes in the logical problem merely because their
signs co-vary in these 256 observations. Such substitution becomes admissible
only after the bound CNF supplies a checkable proof of each copy/complement
equivalence. A later proof-generating elimination or BDD over the resulting
nine-dimensional residual would then be the highest-leverage route to testing
for a genuine key-only consequence.

## Claim boundary

This audit establishes a structural repetition quotient, one exact
subsumption, and a lossless compression opportunity. It does not establish a
key bit, key orientation, prefix closure, key posterior, entropy reduction,
CNF entailment, non-tautological resolvent, complete model or attacker-valid
domain reduction. O1C-0092 Page 14 and its lineage remain burned and are not
authorized for retry or replay.
