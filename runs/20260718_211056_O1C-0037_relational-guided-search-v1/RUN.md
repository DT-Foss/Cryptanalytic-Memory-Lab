# O1C Run O1C-0037

- Status: `completed`
- Started: `2026-07-18T21:10:41+02:00`
- Ended: `2026-07-18T21:10:56+02:00`
- Elapsed seconds: `14.513263041000755`
- Target: standard ChaCha20-R20, all 256 bits unknown at deployment
- Real O1 exact recovery: `0`
- Oracle exact guidance: `True`
- One-error repair through 32,768 conflicts: `False`
- Decision: `CLOSE_KEY_ONLY_FIRST_ENCOUNTER_CDCL_GUIDANCE`

The exact truth-prior ceiling recovers and independently verifies the complete key. The frozen O1 and shuffled fields do not improve exact search, and one wrong key-only first-encounter hint is not repaired.
