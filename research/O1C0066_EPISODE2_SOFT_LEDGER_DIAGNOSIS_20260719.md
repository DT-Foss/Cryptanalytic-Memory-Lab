# O1C-0066 episode-2 soft-ledger diagnosis

- **Recorded:** 2026-07-19T14:14:16+02:00 (`Europe/Berlin`).
- **Scope:** read-only diagnosis of the sealed O1C-0066 result and committed
  source at `881c461c79dc1fd9aa51aed89d3f2a8b298c2284`.
- **Additional solver calls / target bytes / truth bytes:** `0 / 0 / 0`.
- **Retry authorized:** `false`.

## Exact conclusion

The third O1C-0066 native process returned a syntactically parseable result, but
the adapter rejected its soft conflict ledger. The exact observed conflict count
was not retained. The committed code nevertheless makes the failing condition
identifiable:

1. native v6 reads `conflicts_before_solve` and `conflicts`, rejects a regressing
   counter, and emits `solve_conflicts = conflicts - conflicts_before_solve`;
2. the v7 parser preserves those five nonnegative native statistic fields;
3. v8 passes them to the v5 soft-ledger derivation with requested work `512`;
4. all algebraic identities are therefore true by construction;
5. the only remaining rejection is the frozen, but unproved, upper bound of one
   overshoot conflict and `513` billed conflicts.

Episode 2 therefore returned at least `514` solve/billed conflicts and at least
`2` conflicts of soft-limit overshoot. The exact value is not recoverable from
the sealed capsule because adapter-validation failure telemetry recorded
`stdout=null`, `stderr=null` and no native-result sidecar.

This is an adapter contract failure, not a cryptanalytic negative, threshold
UNSAT, resource stop or key-space statement. It does not alter the two completed
episodes' certified `0→6→12` clause compounding result.

## Why `+2` is not the fix

CaDiCaL's public conflict limit is a soft search horizon. Its limit check is not
an assertion at every internal conflict increment; propagation, external
propagation and model checking can pass the requested horizon before the next
check. Replacing the observed `+1` assumption by another guessed constant would
repeat the same failure at a later episode.

The smallest honest successor is a versioned adapter ledger that:

- retains exact type and algebra checks;
- treats `512` as requested work, not a hard observed maximum;
- bills and reports the actual nonnegative `solve_conflicts` and derived
  overshoot;
- keeps process count, wall time and RSS as hard resource caps;
- preserves bounded native command/stdout/stderr and the raw payload hash on any
  post-process adapter failure.

A truly hard conflict cap would require a larger pinned CaDiCaL/native change
that checks the horizon at the solver loop head and every conflict increment. It
is not justified for the next discriminating test.

## Target-free gates for O1C-0067

1. A synthetic native-stat row with `conflicts=514`,
   `conflicts_before_solve=0`, `solve_conflicts=514` and requested `512` must
   normalize to billed `514`, unused `0`, overshoot `2`.
2. Forged rows whose `solve_conflicts` differs from
   `conflicts-conflicts_before_solve` must still fail closed.
3. A successful synthetic subprocess followed by an injected adapter failure
   must preserve return code, command and exact bounded stdout/stderr in failure
   telemetry.
4. No O1C-0066 ordinal is replayed. Any paid O1C-0067 continuation must bind a
   distinct invocation and the retained 12-clause vault after these gates pass.

## Evidence

- Authoritative result:
  `research/O1C0066_APPLE8_EPISODIC_VAULT_RESULT_20260719.json`, SHA-256
  `b8b61d0f2feaa9c544c1fef30cba4c7cead90c390a577a444405d45ad85000e3`.
- Sealed capsule:
  `runs/20260719_135856_O1C-0066_apple8-episodic-vault-v1`, manifest SHA-256
  `b0022997a1c316e71131268b3e3e5524aee4de8167013463f845646c8982d562`.
- Episode-2 intent:
  `episodes/02/intent.json`, SHA-256
  `7a2fb83611fbc6108e2e3503f406141c13b1087a951a075147cdb679fedd62ed`.
- Episode-2 terminal failure:
  `episodes/02/terminal_failure.json`, SHA-256
  `0915eb4220000bf80a3326b6533976220e4f08eba1ee98fd69296e856ea64834`.

