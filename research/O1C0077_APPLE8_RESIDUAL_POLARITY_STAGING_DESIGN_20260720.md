# O1C-0077 — APPLE8 residual-polarity staging design

- **Frozen:** 2026-07-20T02:02:39+02:00 (`Europe/Berlin`).
- **Hypothesis:** `H-RESIDUAL-POLARITY-STAGING-081`.
- **Direct parent:** O1C-0076 authoritative result SHA-256
  `9459f80444b2dc196251623dfc1f59f014e6593b3b5cd7d8bbaaa5c62f0b671e`;
  capsule-manifest SHA-256
  `875655a95a30a4f0df01e130a074b0b6a82b98c683575818ad5110cc6a6f1366`.
- **Isolation:** O1C-0077 adds only attempt-owned files in this lab. O1C-0068
  and sibling projects remain unchanged.

## Why this call

O1C-0076 closed the parent-zero intervention point. Its parent reader returned
zero 1,778 times, but the first zero arrived only at callback 256. By then all
29 residual literals of the selected clause were assigned: 18 in the
falsifying direction and 11 in the rescue direction. Consequently the outer
reader made zero substitutions and reproduced the frozen trace exactly.

O1C-0077 acts earlier without replacing the public rank. The selected clause
intersects the immutable 255-row rank in only five **residual** variables. Three
rank polarities already falsify the clause. Two rescue polarities are flipped
in memory before the embedded readers are constructed. This is the smallest
operator that can stage the public boundary before propagation removes it.

## Canonical Page 4 parent plan

The ordinary causal-frontier v1 plan is re-derived from the canonical
uncompressed O1C-0076 native result, never from capsule `result.json` and never
from O1C-0075 provenance:

| binding | frozen value |
|---|---|
| native gzip | `0ca67f629bfc62f62d3705c74f3fef44aff3d5e4646048798a7006c722d02658` |
| canonical native JSON | `5cee812cc99b824b43b345f20b2eed253a09090a69866de2f3c4fa074c95e198` / `252,812 B` |
| native schema / trace | `o1-256-cadical-joint-score-sieve-result-v14` / `f64441a20619d788ab935a870d86f8df8fa07caf4ac4fdda26cc95d10363aa70` |
| fresh Page 4 | `b57e3091df7eca20137f4c63e3bc125aa8978c2ff183a7396de3a2a4a79acf33` / `2,874,139 B` |
| source assignment | `c62a8e3c41694b25c86aa8e66dfc9072cec7d23b7efd39fc4c766ef8ea2418d2` / `2,981 B` |
| active / union / occurrence | `232 / 526 / 534` |
| selected clause | `c4a9c471f9eb45829764a841fb8c6971eecdc8b9a9e251732d65875647f25322` / `2,438` literals |
| terminal clause state | `2,409 false / 0 true / 29 unassigned` |
| residual / falsifying i32le | `ed2056882fd69ed2fc6ffb502ae251e3d7876fa4131b0fa35396d73305deccd7` / `71de3130c414926ba0527d1d427b99400454a90e40152b20c68ff02c06c7fe48` |
| canonical parent plan | `83dbfbddd51bdbacb95a892cf3bc7e3c3953bc3e62b674d1f8388de7de53db30` / `4,479 B` |
| parent-plan body checksum | `91e83bb6aa42d70e7fc341b5827f6db02b3f5bd049eec0b6b7a3bfe3bc57d7aa` |

The plan parses, validates against Page 4, reserializes byte-identically and
re-derives the same deterministic winner under `true_count = 0`, minimum
unassigned count, clause SHA-256 and active-index tie-breaking.

## Frozen staging operator

The public rank source remains vault
`cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858`.
Its canonical table is `9,180 B` with SHA-256
`d3a007ebee7c515289d33be30757f769b2c1fde618fb5c6c312ea9f3509380ae`;
its immutable 255-literal order is `1,020 B` with SHA-256
`26c0063f4eed586ef67535cccabacc07d945587a603cbb56dbb3b2225a32a2f5`.

The five intersections remain in that exact rank order:

| rank row | clause literal | source rank literal | effective literal |
|---:|---:|---:|---:|
| 28 | `+105` | `-105` | `-105` |
| 131 | `-106` | `+106` | `+106` |
| 224 | `+131` | `+131` | `-131` |
| 226 | `-130` | `-130` | `+130` |
| 235 | `-129` | `+129` | `+129` |

Only two source-to-effective overlays are legal:

```text
row 224: +131 -> -131
row 226: -130 -> +130
```

No row moves; no delta, bound, gap or tie-break field changes. The effective
order SHA-256 is
`6ab071e611809ee898e81d0659ff0736453dd390d26c739383826c94276ad086`.
The overlay is applied before constructing the embedded v14/v12 reader stack,
so no inner reader can cache the source polarities first. A later contrast is
always the opposite of the **effective** literal, not the opposite of the
source literal.

The complete zero-call seed freezes this parent layer and the canonical staging
plan together. The staging binary is serialized only through the separately
gated `o1-residual-polarity-staging-plan-v1` core API; its two overlays do not
alter the parent frontier plan, Page 4, source assignment or attic identities.

## One-call protocol

- local episode `0`, fresh lineage ordinal `17`, seed `0`;
- exactly one call and exactly `128` requested conflicts;
- fresh Page 4 is the sole active input;
- timeout `45 s`, per-process memory cap `536,870,912 B`, CPU only;
- no retry, sweep, second page, threshold/rank/K/phase/horizon change or RAM
  increase;
- zero truth, reveal, fresh-target, entropy, refit, MPS and GPU calls;
- incomplete or invalid execution consumes lineage 17; publication recovery
  may issue zero solver and zero verifier calls.

Before the call, preflight must bind the final staging module, adapter, native,
preparation and runner hashes, reconstruct both source and effective orders,
and prove that only rows 224 and 226 differ. No science call is authorized by
this design or seed alone.

## Predeclared readout

Mechanism activation requires both:

1. at least one actual staged literal is returned; and
2. the outer native trace differs from
   `f64441a20619d788ab935a870d86f8df8fa07caf4ac4fdda26cc95d10363aa70`.

The selected clause is live-active only when its current state has
`true_count = 0` and `unassigned_count <= 1`. A changed trace alone is not a
science gain. Promotion requires at least one certified safe prune, one
globally novel certified exact clause, a public verified model, or formal
threshold-region exhaustion.

If the call has no science gain, the next operator is already sealed: the exact
11-row prefix preemptor

```text
130 -131 31874 63746 190565 190566 190569 191212 191213 191216 191234
```

with i32le SHA-256
`b5debc5f55f7cbc1e728d00ce1d14d0c437249793f8c10e8b80e614a00ed155c`.
There is no retry of this two-overlay operator.

## Zero-call seed

Directory:
`research/o1c77_residual_polarity_staging_seed_20260720`

- 19 immutable artifacts: nine attic chunks, Page 4, occurrence/relation/
  activation ledgers, source assignment, both plan documents/binaries and
  parent provenance;
- manifest SHA-256
  `141fe794225afae26068d7b4e6eabe0cb52d55faf4592de1bb912c4b915e35e3`
  (`35,747 B`);
- frontier-plan document SHA-256
  `e81aad2f075c39b19ddbbbdb0bff525449d17841a0bffd01126858f4886cb149`;
- staging-plan binary/document SHA-256
  `db99c44c1a08203f691c197172d71dad73ac12c64326d48461fac10316ee3167` /
  `140fc1450aab6380345cfac84d4655cd59747ccc121e01169d11c36624f53e90`;
- parent-provenance SHA-256
  `38ec86fbc63285f122222bf02fdd327ef36888c7eb97f4bcc22fb43382ecbdf4`;
- zero native, science, reveal, truth, refit and entropy calls.

## Threshold semantics

The fixed threshold `tau = 14.606178797892962` and a trail upper bound share
score units and retained direction, but they are not the same statistic or
population. Formally, admissibility makes `U(a) < tau` a safe prune only for
descendants of that specific visited trail `a`; it is not a global prune unless
the root or every relevant frontier is covered. The historical
`7.973483108047071` is O1C-0066 episode 1, while O1C-0076 reached minimum upper
bound `14.67138759145431 > tau` and made zero safe prunes. O1C-0068's minimum is
`12.8607806294803`; O1C-0068 remains untouched.
