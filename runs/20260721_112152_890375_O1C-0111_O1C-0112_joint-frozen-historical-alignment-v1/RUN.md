# O1C-0111 + O1C-0112 — terminal pre-truth contract rejection

Created: 2026-07-21 11:21:52 CEST  
Terminal failure: 2026-07-21 11:23:10 CEST  
Parent commit: `82cc1d66373fa296489494bc90811810df3e97cd`

## Outcome

Both truth-blind score-freeze envelopes and their joint freeze were durably written before any reveal-file read. The first O1C112 reveal-reader attempt then rejected the SHA-sealed historical reveal solely because its JSON bytes were not byte-canonical.

The rejection occurred after one physical file read and JSON parse, but before `verify_reveal`, before extraction of the commitment preimage, and before construction of any truth bits. Therefore this capsule contains **zero broker calls, zero key bytes, zero truth bits, zero solver calls, and zero result files**.

This capsule is terminal and will not be reused. The reader contract is corrected and independently refrozen in a new capsule before any subsequent reveal read.

## Preserved evidence

- O1C111 score-freeze envelope: 5,447 bytes, SHA-256 `1d484e0eb01983e300c2e714d02e854cb5bbaf5df20d5756774d7d5117f4c14e`
- O1C112 score-freeze envelope: 367,211 bytes, SHA-256 `61ef74b465038f8af966d48770b14bf8de477845aff2530bd280407e8bd5dcda`
- joint score freeze: 849 bytes, SHA-256 `2525e8eacddaccb9ec25a0068bb75b9d17315ef38a265920133f949e052fa3b5`
- historical reveal file read count: 1
- historical reveal file SHA-256: `63706f65c9e355711621e2188494514d1c201306d2b6a5c6928833aedfd77efd`
- rejected contract: raw reveal bytes must equal canonical JSON encoding
- valid contract retained: exact file SHA/size plus broker semantic verification

## Next action

Commit the corrected O1C112 reader and its regression test, create new score-freeze envelopes, and evaluate O1C111 plus O1C112 from one cached broker-verified truth object in a fresh run capsule.
