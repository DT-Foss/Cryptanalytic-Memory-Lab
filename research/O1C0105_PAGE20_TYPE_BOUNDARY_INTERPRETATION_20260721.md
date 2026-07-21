# O1C-0105 — Page-20 clause-type boundary

- Recorded: `2026-07-21T06:10:18.171226+02:00` (`Europe/Berlin`)
- Classification: `PARENT_CENTERED_CONTINUATION_OPERATIONAL_TERMINAL`
- Science gain: `false`
- Raw result: `O1C0105_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260721.json`
- Raw-result SHA-256: `f4e4e2ef4fcec6817b3fa6cf445448cae9aa693460c14cd2a8f7a7a3a295d66b`
- Capsule: `runs/20260721_060959_396348_O1C-0105_apple8-parent-centered-continuation-v1`
- Capsule manifest SHA-256: `5185f293b51a1185cca1d06f18f6c4ca85172bd1245bb08867df293a995f8d97`
- Intent SHA-256: `013ad6009c770b1370a935584ccd0f85acbc737b4895ab3ee09c6e6d58a558f9`

## Outcome

The sole O1C-0105 lineage-33 attempt consumed Page 20 exactly once. The
persisted intent burned Page 20 and lineage 33 at
`2026-07-21T06:10:02.933000+02:00`. Retry and replay remain forbidden.

The run terminated in adapter validation with:

```text
joint-score-sieve-v34 adapter failed:
joint-score-sieve-v8 grouped no-good certification differs
```

No native process was launched. The retained failure has `command=null`,
`returncode=null`, no stdout or stderr, no RSS samples, no actual/billed
conflict count and no native result. The accounting conservatively consumes the
single authorized call and all 128 requested conflicts. Total wall time was
`15.273985124978935 s`; CPU time was `15.223448999999999 s`.

This is an operational type-contract failure, not a negative cryptanalytic
measurement. It establishes no key, model, posterior, beam, entropy/domain
reduction, native clause emission or solver-search result.

## Exact root cause

Page 20 is byte-correct and all publication seals verify. Its active order is:

1. 192 native emitted score-threshold no-goods;
2. three inherited O1C-0102 resolution clauses;
3. 52 new O1C-0104 resolution clauses.

The legacy flat score-threshold vault certifier requires every partial active
clause `C` to satisfy the stronger standalone theorem

```text
grouped_upper(partial_assignment(C)) < 14.606178797892962
```

The census is exact:

| Active class | Pass | Fail |
|---|---:|---:|
| Native emitted | 192 | 0 |
| Inherited derived | 3 | 0 |
| New derived | 41 | 11 |
| Total | 236 | 11 |

All eleven failures are valid Generation-1 resolution consequences over pivot
variable 223. Resolution removes the pivot assignment and enlarges the set of
compatible completions, so the sufficient grouped upper bound is not closed
under this operation. Exact propositional proof validity therefore does not
imply the narrower standalone score-no-good certificate.

The failing O1C-0104 closure indices are:

```text
1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 14
```

Their grouped upper bounds range from `14.607976124977816` to
`14.660684299458420`, all at or above the strict threshold. The first failure
is Page-20 zero-based index 196, logical index 2609, SHA-256
`2ff456abec0cbe71de6600b2d1e0e97be89b7db306d7cde98e8765c84b90db04`.

Python rejected the first such clause before constructing the native command.
Native v6 independently enforces the same grouped-bound theorem, so bypassing
the adapter would not have repaired the contract.

## Architectural interpretation

The causal attic now contains two distinct proof types that the original flat
vault format cannot label:

- **score-certified no-goods**, independently admissible to the existing native
  input channel;
- **resolution-certified consequences**, logically valid but not necessarily
  independently score-certified after pivot elimination.

The eleven clauses are retained in the append-only 2,692-identity logical
registry and in the immutable O1C-0104 proof closure. They are not discarded or
reclassified as native observations. They must remain external proof memory
until a proof-aware native clause channel exists.

## Fresh roll-forward

O1C-0106 has atomically published a distinct Page 21 / lineage 34 without
reusing Page 20:

- 203 emitted score-certified clauses;
- all three independently score-certified inherited derived clauses;
- 41 independently score-certified new derived clauses;
- all eleven general resolution consequences retained in logical sidecars only;
- 247 active clauses and 265 native clause slots of headroom;
- real-page `247/247` grouped certification completed before publication and
  required again before any future intent.

The independently reconstructed candidate has 690,330 literals, 2,762,499
bytes and SHA-256
`36091952f38fbe5b73e20311083c7e1bfc30271cfcd6dba2f46f73f051f65fa8`.
Its maximum active grouped upper bound is
`14.605986705470585 < 14.606178797892962`, a strict margin of
`0.00019209242237749891`. The canonical 17-file manifest SHA-256 is
`91044c235473c1a24fdeeb283454babc5ebc800ea19236840dd7193d6f3c96c2`;
residency SHA-256 is
`b55e8cb25a84c64883bd5a90ff620f5c4e3bfb62960ae97ca2dfc4eef9987f75`,
activation-ledger SHA-256 is
`cd74577f064a70f8725a0e11c1ced134814e2735e594945d8bdfb01827f5230a`
and certification-audit SHA-256 is
`cec84918ddaba8d0c8d8b6513a8a681c1108a088089ba2534d27d7b37e2f1125`.
Publication used zero calls/reads/reveals/refits and leaves Page 21 unburned.

This roll-forward is a new typed-memory mechanism and fresh page identity, not
an O1C-0105 retry or Page-20 replay. O1C-0107 may bind only this exact state,
run one zero-call preflight and then consume lineage 34 at most once.

See the [O1C-0106 result](O1C0106_PAGE21_TYPE_SAFE_ROLLOVER_RESULT_20260721.md)
and [canonical manifest](o1c106_page21_type_safe_rollover_seed_20260721/causal-rollover-preparation-manifest.json).
