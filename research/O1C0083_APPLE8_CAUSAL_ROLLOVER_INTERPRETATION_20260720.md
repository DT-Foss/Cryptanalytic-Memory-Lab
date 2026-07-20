# O1C-0083 APPLE8 causal-attic Page-9 rollover — interpretation

O1C-0083 was prepared and recorded at `2026-07-20T15:31:57+02:00` (`Europe/Berlin`) as `CAUSAL_ATTIC_PAGE9_ROLLOVER_PREPARED`. It is a zero-call enabling and mechanism gain: the complete O1C-0082 harvest now lives in the immutable causal attic, and a fresh bounded Page-9 projection with explicit headroom is byte-sealed. It is not a new cryptanalytic result, key/model/closure result, entropy gain or domain reduction.

The authoritative [result](O1C0083_APPLE8_CAUSAL_ROLLOVER_RESULT_20260720.json), [config](../configs/o1c83_apple8_causal_rollover_v1.json), and [preparation manifest](o1c83_causal_rollover_seed_20260720/causal-rollover-preparation-manifest.json) bind code commit `ddb9368c0a2f5cf469148c30748c416ace805225`, capacity API commits `b9eff33` and monotone fix `65c122b`, and manifest SHA-256 `b8a829a642159640a10cc553c6c27e5312cae4fbda8f75975688c6d14afe7dda`.

## Sealed rollover

The preparation imports O1C-0082 result SHA-256 `013692cf836e594c8580734e0c95a9f0dd18ad7536c457274a1fe5684df1ad4f`, capsule-manifest SHA-256 `3256a85e1095ffeaee349d3248035cb53470b1921abd58dd230e1617696134e6`, and vault-telemetry SHA-256 `9c7705591948e1f3b4ee1589cf431c8bd9a5844bad670ddb1c713c4d1d3e5445`. The new immutable [chunk](o1c83_causal_rollover_seed_20260720/lineage-22-new-chunk.vault) is `257` clauses / `743,129` literals / `2,973,735 B`, SHA-256 `19e294822deb3b98904e9d14b944fe167cd3ff048f7d04d870c003b34cdadaf0`. All 257 occurrences are new and unique.

The resulting attic contains `13` chunks, `807` unique clauses, `815` occurrences, `9` strict subsumption relations and `801` undominated clauses. Its directly inspectable state is sealed by [residency](o1c83_causal_rollover_seed_20260720/residency.json) SHA-256 `2509b084b56a28be24163b60e94d7c2a631ddacddc5469b1ab8db4bc5a7876dd`, [activation ledger](o1c83_causal_rollover_seed_20260720/activation-ledger.json) SHA-256 `e1bb54ff72920f66f3e882182a7d709e7c46d4bb7694f432430e24d519fee3ad`, [occurrence ledger](o1c83_causal_rollover_seed_20260720/occurrence-ledger.json) SHA-256 `b011f4c7bbda808fc78827353fe39ddec334b067f4744bd89f1a3bc31dcacb1f`, and [relation closure](o1c83_causal_rollover_seed_20260720/subsumption-relations.json) SHA-256 `c599e44573e5c1be1740d1bd6fe40970cf562746e9e77ee927d7021030b58e43`.

## Page 9 and capacity

The [Page-9 active projection](o1c83_causal_rollover_seed_20260720/page-09-active.bin) is a fresh identity, SHA-256 `8c3b8cc33badd4aa23920caabc5ea3fc5006675d93805578b74b2b20788c8204`. Explicit `next_active_limit=255` selects `255` clauses / `721,187` literals / `2,885,959 B`: `4` structural roots, `43` pinned-core clauses and `208` new-debt clauses. Against the sealed live caps it leaves headroom for `257` clauses / `878,813` literals / `5,502,649 B`. The projection is confirmed, implemented and sealed.

The O1C-0082 [final priority bank](o1c83_causal_rollover_seed_20260720/final-parent-centered-priority-bank.bin) remains byte-identical at `24,576 B`, SHA-256 `05b8acf3ecd5423016e5d7ef7d649f790e758e3477a943fe7306280064a4c630`. Its validated priority-state receipt is `51,949 B`, SHA-256 `e351258722638285684c1197ba0115c3699aa8feffe44ff61e526319e519bb0f`. It contains `256` ordered 96-byte records, `255` eligible coordinates, zero-count variable `241`, and maximum evolved count `575`. These are live continuation bytes and are deliberately incompatible with the fresh 74-parent seed parser. A future Page-9 runner must accept and validate the live continuation digest and receipt; parsing this bank as a fresh seed is forbidden.

## Audit and claim boundary

The [common-core audit](o1c83_causal_rollover_seed_20260720/common-signed-intersection-audit.json), SHA-256 `2a14bc7382f90bb038223852fd8c5fcfb2c99145338800efead72cb6c1dbb83c`, retains canonical core SHA-256 `9aa383f819d1aa4b1216937ee341aa6a773d1d3456e1ea622494ef1a4345ea06` and `2,764` literals. Exact grouped `U=18.66656376905567` exceeds `tau=14.606178797892962` by `4.0603849711627085`; the core is nonprunable, and deletion cannot create a certifying subset under the same bound.

Preparation consumed zero solver, native, science, target, truth, reveal or refit calls. It created no production intent. Page 9 and lineage 22 are not burned, and there is no authorization to replay Page 8. The nine-file bundle totals `6,256,851 B`. Measured preflight used `66.35 s` real / `65.72 s` user / `0.35 s` system, `371,752,960 B` maximum RSS, zero swaps and zero block input/output. Focused O1C-0083 verification passed `8` tests in `90.91 s`; the broader historical suite passed `120` tests in `162.13 s`; Ruff and Pyright are clean.

## Next active hypothesis

`H-PARENT-CENTERED-ATTIC-ROLLOVER-087` is supported at preparation level. The active successor is `H-PARENT-CENTERED-COMPOUNDING-088`: build a continuation-bank-capable Page-9 runner and preflight, validate every source/input/projection/bank/invocation hash, then freeze at most one fresh Page-9 / lineage-22 production call. Accept further globally novel clauses, certified closure/model/key, or attacker-valid entropy/domain gain. Do not replay Page 8, run a cap/RAM sweep, reinterpret priority as key-bit belief, or burn Page 9 before the continuation parser and all seals pass. Exact independently verified 256-bit key recovery remains the north star.
