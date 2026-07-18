# O1C-0028 — Horizon-Major Full-256 Hot Routing Result

## Frozen result

- Attempt: `O1C-0028`
- Classification: `HORIZON_MAJOR_HOT_ROUTING_PASS`
- Claim: synthetic `VALIDATION` of transport, state ABI and hot/cold routing
- Source commit: `17c02dfdbf56de6a81ae34700b258815bf0b7f88`
- Capsule: `runs/20260718_103518_O1C-0028_horizon-major-hot-routing-full256-v1`
- Manifest: `aab7484b36b4a7c6e59ad556d41f44fbb88477b2f3f1f45270c0685e7a16ce09`
- Result commitment: `ed3517f215be1c06e7b10882f2eeb6d494ab1f75916f9979edd04729c76abc6e`
- Primary state: `02837fe664dc8b75b4dc651fc4d5fd6981b4c9a2653d4040c276fbe124047abe`
- Completed: `2026-07-18T10:35:18.765086+02:00`

This result contains no ChaCha20 evidence, unknown key, real/ChaCha target label,
solver result, fresh entropy or authoritative O1C-0023 decision. Its only labels
are 1,280 preregistered synthetic mechanism-fit values. It supports no key-bit,
entropy-reduction or recovery claim.

## What passed

One complete 256-coordinate packet ledger carries H64/H65/H96 incremental
q-deltas. The adapter transposes coordinate-local rows into exactly three dense
horizon-major `float32[3,256]` groups in packet time order H64/H65/H96 and V2
wavelength order H64/H96/H65. Each encoding is 9,216 bytes.

The groups enter one self-describing V2 polyphase state:

- persistent state: 25,128 bytes;
- basis SHA: `75b0c13e830c2bf586c0df5fd180eb84ff0d7676b2f28759cc3ce0e3c4f579f6`;
- stream-length-dependent state: zero;
- primary consume calls: one;
- primary reingested groups: zero;
- hot reader bindings: two;
- cold replay probes: thirteen.

All 14 preregistered gates pass:

1. complete K256 packet geometry;
2. byte-exact extraction codec;
3. separate normalized and int8 transports;
4. canonical packet-order invariance;
5. allocation-alignment state invariance;
6. coordinate-major sparse negative control rejection;
7. exact complement oddness;
8. independent complex128 reference bound;
9. matched coordinate permutation;
10. distinct immutable hot bindings;
11. cold operators require replay without mutation;
12. BUILD-only synthetic holdout generalization;
13. exact zero-design abstention;
14. exact state serialization and size.

## Resource result

- mechanism CPU: 0.112165 seconds;
- measured mechanism wall: 0.123936 seconds;
- complete capsule elapsed: 0.143779 seconds;
- peak RSS: 44,892,160 bytes / 42.8125 MiB;
- persistent capsule artifacts: 378,809 bytes;
- failed budgets: none;
- network, sibling, GPU, MPS, solver and secret reads: zero.

Eight additional fresh processes independently emitted the same result SHA at
42.562–45.438 MiB RSS. A second formal invocation returned the verified finalized
capsule without replaying the mechanism.

## Two important breadcrumbs

### Horizon-major transposition is required

Treating each coordinate packet as a sparse full-width time step advances every
resonator 256 times. Early coordinates then decay solely because their ledger row
appeared early. Reversing packet order changes the sparse state. Transposing the
same complete ledger to three horizon-major groups makes packet row order
irrelevant while preserving every delta and coordinate.

### O1C-0027 V1 remains immutable; V2 is a cold migration

The original vectorized complex64 recurrence can choose fused or unfused
arithmetic from allocation alignment on this NumPy/macOS runtime, producing two
one-ULP byte variants. O1C-0028 does not rewrite or reinterpret O1C-0027. V2
freezes nine float32 rounding points, locally freezes floating-error policy and
prefixes serialized state with its 32-byte basis digest. Legacy or foreign bytes
raise `ReplayRequiredError`. After one cold V1→V2 replay, reader weight and
temperature changes are genuinely hot.

## Lightweight authoritative wire boundary

The formal runner does not import Torch or the historical O1C-0019 controller
stack. A pure-standard-library codec independently reconstructs packet groups,
group IDs, group SHA values, ordered-ledger SHA, extraction work/slot totals and
the frozen median quantizer. Golden compatibility tests prove byte-for-byte parity
with the pinned producer SHA `82b8f172...`. This reduces fresh-process RSS from
about 208 MiB to about 43 MiB without changing the scientific result.

The codec authenticates content, not provenance. A real successor must still
resolve and verify the finalized source capsule, artifact index, member SHA,
source result and freeze receipt before decoding packet bytes.

## Authoritative successor contract

The next efficacy-bearing use receives a new O1C identity. For held-out fold A:

1. resolve A's already-frozen reader and quantizer, whose upstream training never
   used A labels;
2. generate and freeze B/C/D packet bytes, streams and V2 states with exactly
   that fold-A reader/quantizer, never with B/C/D own-heldout readers that trained
   with A; the hot-fit stage has no label input during this step;
3. only then let the hot-fit stage load B/C/D calibration labels, fit its horizon
   weights/temperature and freeze the fit receipt plus complete lineage;
4. bind that frozen fit, then freeze A packet bytes, V2 state and logits before
   opening A's label;
5. verify the actual authoritative O1C-0023 decision graph, not a synthetic
   descriptor;
6. preserve normalized, quantized, shuffled, complement, permutation and
   common-mode controls;
7. score entropy reduction, bit accuracy, byte/block ranks and exact global
   frontier without changing the frozen reader.

This nested construction prevents a reader trained with A labels from entering
A's fit indirectly. Any evidence, quantizer, coordinate addressing, encoder,
recurrence or phase change is cold and requires a new state replay. Only the exact
fitted horizon weights and global confidence temperature are hot.

## Decision

Freeze O1C-0028 as the packet/V2/hot-routing API. Do not rerun its synthetic
fixture and do not promote its perfect synthetic fit. Wait for finalized
O1C-0019→O1C-0022→O1C-0023 authority, then execute the nested real successor under
a new attempt ID. The architecture/iteration bottleneck is now cheap and
reproducible; portable full-round causal orientation remains the scientific
bottleneck.
