# O1C-0104 — Page-20 closure-composed causal rollover

- **Recorded/published:** `2026-07-21T05:33:54+02:00` (`Europe/Berlin`).
- **Classification:** `PAGE20_CLOSURE_COMPOSED_CAUSAL_ROLLOVER_PREPARED`.
- **Calls:** zero native preflight, solver, science, target, truth, reveal or
  refit calls. Page 20 / lineage 33 is fresh, unburned and unauthorized until
  O1C-0105 persists intent.

## Result

O1C-0104 atomically ingests O1C-0103's 266 native occurrences as one immutable
265-clause / 755,792-literal / 3,024,419-byte lineage-32 chunk, SHA-256
`f97ec1c743338054d1152ed007730d8379d9959ff401062e1589c2cd07c46687`.
Occurrence 16 remains the exact duplicate of occurrence 15; no evidence row is
discarded or promoted into a false unique clause.

The pure native CausalAttic now contains 21 chunks / 2,603 unique clauses /
7,358,158 literals / 29,443,235 bytes, with 2,613 occurrences, ten duplicate
occurrences, 14 native strict-subsumption relations and 2,592 native
undominated clauses. Its union SHA-256 is
`8a5a10d81cf3108d1105fdbbe84dc33491e68d10ac0c0ecf946e91d8585e2510`.

## Append-only logical registry

The previous 2,343-identity logical registry remains a byte-exact prefix. The
new append-only order is:

1. 2,338 historical native emitted identities;
2. five inherited O1C-0102 derived identities;
3. 265 new O1C-0103 native identities in first-emission order;
4. 84 new O1C-0104 derived identities in proof-topological order.

Logical indices are therefore `0..2337`, `2338..2342`, `2343..2607` and
`2608..2691`. Native union indices remain a separate contiguous namespace:
new-native logical index `i` maps to emitted-union index `i-5`. This boundary is
explicitly tested at logical indices 2337/2338/2342/2343/2607/2608.

The 2,692-clause logical encoding has 7,611,885 literals / 30,458,499 bytes:

- inventory SHA-256
  `9b61b7e9dc9c299c311f46a6f3dce683798b589fb1994b96987fc69768a6379f`;
- vault SHA-256
  `ed53e022239f84f3bc9bbb2a822170405e362ba1a0a98a1d887e9c38d79f0220`;
- clause aggregate SHA-256
  `dda34c8808a9b53949653de0bed7ff31cecc69bc5042942f11920214ee23cbd5`;
- 119 total logical strict-subsumption relations and 2,579 logical
  undominated identities.

The inherited five-clause proof namespace remains byte-exact. The new
84-clause fixed-point closure is 239,208 literals / 957,359 bytes, SHA-256
`f351b4d6c5226efbdf63ffb1093b48260a6f2e80fb363334dba615a8ed27abe8`.
Its resident 52-clause Gen-1 antichain is 147,752 literals / 591,407 bytes,
SHA-256
`44175f53721783710a15bf8fcc69567ab2107469fabb777e62df166f6a047a10`.
Derived clauses receive zero native occurrence rows and never enter the native
attic.

## Fresh Page 20

Fresh Page 20 / lineage 33 contains exactly:

- 192 native emitted clauses;
- three inherited derived clauses;
- 52 new derived clauses.

The resulting 247-clause page has 690,319 literals / 2,762,455 bytes, SHA-256
`537f63c5284e15e451739f7369fbe6ee8dddbc5dfdb15b26988269a1e40e5519`.
It leaves 265 clause slots, exactly matching O1C-0103's observed unique burst;
literal headroom is 909,681 and payload headroom is 5,626,153 bytes. Future
literal/payload safety is not claimed.

The pure-native 247-clause selector candidate `1b46e9d8…` is never activated.
The returned in-memory state, active artifact, residency document, activation
ledger and manifest all bind the composed Page-20 identity. The native selector
state remains separately replayable without fabricating derived attic entries.

The 24,576-byte bank remains
`c0db45c1aa8889d5ed5c01c974f405c7da5c8c2d869597c53652f65512ee58d7`;
the 52,015-byte priority receipt remains
`f025fffa2f5471bfe3bd9315c90fce711724161b63e8c6a1b033cf7eb95a057a`.

## Claim boundary

O1C-0104 is lossless public representation/state preparation for the next
Full-256 call. It preserves O1C-0103's real exact score-threshold no-good gain
and exact resolution consequences. It is not a new native science result, key
recovery, model, posterior, CNF-entailment claim, action crossing or
attacker-valid entropy/domain reduction.

The focused final gate passes 18 tests. Ruff is clean and Pyright reports zero
errors/warnings. A focused contract review caught and fixed two pre-publication
issues: chronological logical/native index mapping, and an in-memory base-page
authority mismatch. No Page was burned while fixing either issue.

## Reproducibility and next action

The canonical atomic bundle contains 16 files / 9,605,074 bytes. Its 15
manifest-listed artifact hashes all verify. The self-manifest is 9,830 bytes,
SHA-256
`2e784eea7ef8fb85913e45246935fa26206626bebf52f0dcb5fc8b9672ba59c5`:

- [Manifest](o1c104_page20_causal_rollover_seed_20260721/causal-rollover-preparation-manifest.json)
- [Prepared bundle](o1c104_page20_causal_rollover_seed_20260721/)

O1C-0105 must bind native v31, adapter v34, runner and config to this exact
manifest, Page, bank, priority receipt and both inherited/new derived triplets.
After one focused serialized contract gate and one zero-call preflight, it may
persist intent and consume Page 20 / lineage 33 exactly once. Page 19 is never
replayed.
