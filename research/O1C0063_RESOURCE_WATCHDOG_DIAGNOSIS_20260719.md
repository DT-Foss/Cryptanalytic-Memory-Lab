# O1C-0063 terminal resource diagnosis

Recorded: `2026-07-19T11:16:43+02:00` (`Europe/Berlin`)

## Outcome

`O1C-0063` is an operational failure with no science result. Its only native
call was consumed, it is not retried, no complete key was returned, and no
truth/reveal bytes were read.

The lifecycle repair did remove the O1C-0062 failure: O1C-0062 reached its
invalid disconnect after about one second, whereas O1C-0063 launched the repaired
native executable and remained in the real Full-256 solve path for
`17.763142674 s` before the parent watchdog stopped it.

## Diagnosis

The terminal event is a high-confidence Darwin physical-footprint watchdog
stop:

- native intent mtime: `1784451828961687960 ns`;
- native failure mtime: `1784451846724830634 ns`;
- elapsed intent-to-failure interval: `17.763142674 s`;
- configured native timeout: `30.0 s`, so the deadline could not have fired;
- configured peak ceiling: `805306368 B` (`768 MiB`);
- frozen Darwin guard: `33554432 B` (`32 MiB`);
- watchdog kill threshold: `771751936 B` (`736 MiB`), sampled every `0.01 s`;
- macOS launch records show the exact frozen executable started at
  `2026-07-19T11:03:49.339+02:00`;
- no new native crash/corpse report exists, unlike O1C-0062;
- the generic error text has no child-stderr suffix, placing the failure in the
  parent execution-exception path rather than a native nonzero exit.

A watchdog-query race is the only remaining low-probability alternative. The
O1C-0063 adapter discarded the underlying exception cause, so the sealed capsule
cannot distinguish those two branches byte-for-byte after the fact.

## Serialization defect and fix-forward

The base adapter raises a bare `O1RelationalSearchError` from the process error.
O1C-0063's failure serializer inspects only the outer exception and therefore
persisted neither the cause chain nor elapsed time, observed footprint, watchdog
threshold, return code, signal, stdout, or stderr.

`O1C-0064` is the authorized new-ID fix-forward, not a retry. It keeps the exact
Full-256 CNF, public potential, threshold, seed and requested `4096` conflicts,
while changing only the operational envelope:

- additive cause-preserving process telemetry;
- `1 GiB` explicit peak ceiling (`992 MiB` guarded threshold);
- `45 s` explicit timeout;
- one frozen native call;
- public 8/8 verification before any truth access;
- immutable O1C-0063 result, manifest, failure and executable hashes as repair
  provenance.

The separate compatibility-grouping track remains independent of this resource
repair. It will be promoted only after its public upper-bound safety and
determinism tests pass.

## Immutable evidence

- Capsule: `runs/20260719_110348_O1C-0063_apple8-crossblock-consequence-sieve-4k-repair-v1`
- Authoritative result SHA-256:
  `fdf46885ff0c268057a8118743d127d39203a219b323729cc05ff6e1f48c23a2`
- Capsule manifest SHA-256:
  `d652b9d6d1dc1fcc7c83594d236223a958cef427e6263cb964dd479b110d7b1a`
- Native failure SHA-256:
  `cb0e42774f5d1326ff79081e96768b9aec870d72f5c008caea67d5a2e9e8d0b5`
- Frozen executable SHA-256:
  `a87044336c3ad137d42405ea3db20795c4b8a2fc65d977a59235cb2ab47ae467`
