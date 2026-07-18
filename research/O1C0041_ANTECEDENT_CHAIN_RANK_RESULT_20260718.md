# O1C-0041 — Branch-exclusive antecedent-chain candidate rank

Recorded 2026-07-18T22:55:50+02:00 from source commit `63fed13`.

## Outcome

`RETROSPECTIVE_CHAIN_RANK_SIGNAL_WITH_CONTROL_MARGIN`

The H16 reader preserves exact branch identity before collapsing each exclusive
proof chain into its unique signed original-clause leaves. Its bounded fields use
unit-scale integer occurrence scores and contain 177–956 key-to-wire edges.

The deliberately strict BUILD rule required all four truth scores to have the
same sign relative to their own 4,096-decoy mean. It selected nothing because the
four signs were `[-1,-1,-1,+1]`; the fourth deviation was only `z=+0.1174`.

The separately frozen A465-style BUILD rank-product rule compares the two global
orientations without using DEVELOPMENT labels. It selects orientation `-1`:

- natural BUILD geometric rank fraction: `0.7078391447`;
- reversed BUILD geometric rank fraction: `0.0932550519`.

That single BUILD-selected orientation was frozen before the DEVELOPMENT label
artifact was opened. Against 4,096 deterministic complete 256-bit decoys per
target, it produces:

| Target | Primary rank | Rank fraction | Key rotation | Factor rotation |
|---|---:|---:|---:|---:|
| development-0000 | 80/4097 | 0.0195265 | 1050/4097 | 1989/4097 |
| development-0001 | 998/4097 | 0.243593 | 1167/4097 | 223/4097 |

Primary geometric rank fraction is `0.0689674709`, versus `0.2701867912` for key
rotation and `0.1625563200` for factor rotation. Thus the branch-exclusive chain
representation retains complete-candidate information that terminal clause
occurrence in O1C-0040 erased.

## Boundary and decision

All six targets were already consumed during mechanism discovery. The result is
therefore a real retrospective joint-rank breadcrumb, not prospective transfer,
entropy reduction over the full `2^256` domain, or key recovery. It nevertheless
passes the predeclared consumed-target rank and control gates.

Freeze the chain extractor, H16 horizon, unit occurrence weights, global
orientation `-1`, coordinate controls and complete-candidate scorer unchanged.
Spend exactly one fresh standard Full-256 target as O1C-0042. A fresh positive
rank earns context-reversible live-CDCL integration; a fresh null closes this
unique-leaf reader and moves to signed parent-role or pivot-literal identity.

## Resources and integrity

- elapsed: `31.551941` s;
- peak RSS: `131,629,056` B;
- native H16 branches: `3,072`;
- complete forward evaluations: `24,582`;
- persistent capsule bytes: `75,614`;
- sibling reads/writes, MPS and GPU calls: `0`;
- capsule manifest SHA-256:
  `467666d371d79d8dfaca27294383880627b14262691b822cab0fcce54a7c471d`;
- result SHA-256:
  `e5d619098e231a69a4e50f7032863d7744557c66b5951e84a31829b0debae186`.

[Immutable capsule](../runs/20260718_225550_O1C-0041_antecedent-chain-rank-v1/RUN.md)

