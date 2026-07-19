# O1C-0065 grouped-native integration preflight

- **Recorded:** 2026-07-19T12:34:31+02:00 (`Europe/Berlin`).
- **Scope:** lifecycle-safe native width-6 integration, adapter validation,
  resource telemetry and zero-call O1C-0065 preflight.
- **Scientific calls:** zero Full-256 target-CNF calls, zero truth/reveal reads,
  zero fresh targets, zero entropy, MPS or GPU calls.

## Frozen implementation identity

- Native source SHA-256:
  `36d4498724c7f0c465fb1177aaa24b5cbb73cd3703cd8ad0d23a2aa1a51e4e81`.
- Exact runner-build executable SHA-256:
  `847a51457680ffa13472558f6bd690dede3a4e7a2b346fae6a206683e32779e7`.
- Python v7 SHA-256:
  `69a111e6162476701e6e09461bd540288e874279bd78e8282c9883a5e65e4bca`.
- O1C-0065 runner/config/test SHA-256:
  `8bbda2fac2ad53c37fc8a1f32293a96bd82afd2f17c5aacbce481b89c0354605`,
  `ca50881062a33783b437a5b4012a47bb15b597e87b8bea8e8e13db16f506709d`,
  `a540813d2e8c311d5aa9388d7a055622ce13b033b2d2bd860dce67e04e7233a0`.

The native source compiles with C++17, `-O3 -DNDEBUG -Wall -Wextra -Werror`
against the pinned CaDiCaL 3.0.0 bytes. Its grouped CLI help path also exits
successfully and declares the required `--grouping` input.

## Exact mechanism checks

- 70 focused grouping/v6/v7/O1C64/O1C65 tests pass.
- Ruff check and format check pass; Pyright reports zero errors.
- A real synthetic v7-to-native subprocess reaches `SATISFIED`, including one
  higher-order three-factor group, exact grouped-state-v2 decoding and 14
  adapter RSS samples. This is a mechanism smoke, not cipher evidence.
- A target-free public-geometry smoke uses the frozen APPLE-VIEW-0008 potential
  with an empty 257,024-variable CNF and a root-pruning threshold. It reproduces:
  - grouping SHA-256
    `3da85bae132d829252a68f0e3fd99220ea7d1ef365042806af810ff02f75f636`;
  - `2,885` groups: `28` singleton, `1,641` pair and `1,216` higher-order;
  - maximum group size `8`, `176,912` rows, `17,025` incidences and
    `115,700` serialized bytes;
  - root upper bound `262.68644197084643`, f64le
    `327693aafb6a7040`;
  - lifecycle terminal `UNSATISFIED`, 8 RSS samples and `61,898,752 B` sampled
    peak.

One preliminary empty-CNF smoke declared only 2,981 variables and was rejected
before solving because the public potential's maximum variable is 255,104. The
header was corrected to the frozen relation's 257,024-variable envelope; no
target relation or scientific attempt was consumed.

## O1C-0065 authorization boundary

The current ordinary CLI preflight passes with:

- frozen APPLE8 CNF SHA-256
  `e1fc0ac93724004291c960ea06e5584c598853b9ea8370552be09f29e73e2432`;
- frozen potential SHA-256
  `8c6101b49c7050caf895bd9c496c05bcea9f43a2b27f378d7306be38b00d5390`;
- threshold `14.606178797892962`, seed `0`, requested conflicts `512`, maximum
  billed conflicts `513`;
- native calls `0`, files written `0`, truth bytes read `false`;
- memory-pressure free percentage `50` at the recorded check.

The preflight correctly reports `ready_for_science=false` before these bytes are
committed. The only next execution is: commit the frozen integration, rerun the
commit-bound preflight, then consume exactly one matched O1C-0065 Full-256 call.
No retry is authorized.
