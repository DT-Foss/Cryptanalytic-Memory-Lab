# Apple view 6: proof relevance transfers; early scheduling does not yet

## Experiment frozen before EVAL

APPLE-VIEW-0005 found that an exact wrong-candidate conflict often depends on
only 250–265 of the 336 named `c31` carry identities.  This run asks the next
real question: can a tiny stream memory learn those useful identities on other
targets and transfer them to a disjoint Full20/Full256 target?

The BUILD stream contains three deterministic ChaCha20 targets, two complete
output-independent wrong probes per target, and three proof collectors per
probe: early→final, final→early, and deterministic public random.  Every
collector conflict is independently proof-replayed before its participating
identity events enter memory.  That produces 18 proof batches and 4,603 exact
identity events.

The complete learned state is one 1,346-byte `bytearray`:

```text
2-byte saturating proof-batch clock
+ 336 × (2-byte saturating frequency + 2-byte last-seen batch)
```

There is no NN, gradient, hidden target slot, or growing index.  After one pass
over BUILD, the reader sorts identity by descending frequency, descending
recency, then identity number.  State and order are frozen.  Only then are two
disjoint EVAL targets with two wrong probes each generated.

For every held-out target, the frozen learned scheduler is scored before any
comparator.  No held-out proof updates memory.  All wrong-candidate passes finish
before any held-out truth key is used.  Comparators are early→final,
final→early, deterministic public random, immediate public gain, and immediate
candidate-local gain.  Every scheduler enables the same exact switch primitive
on the same depth-30 relation.

## Held-out result

| Scheduler | First-conflict switches, total / mean | Exact certificate switches, total / mean | First-pass constraint visits |
|---|---:|---:|---:|
| frozen proof frequency/recency | **1,268 / 317.00** | **997 / 249.25** | **361,451** |
| early→final | 1,048 / 262.00 | 1,038 / 259.50 | 385,692 |
| final→early | **1,031 / 257.75** | 1,015 / 253.75 | 366,197 |
| deterministic public random | 1,332 / 333.00 | 1,027 / 256.75 | 354,085 |
| immediate public gain | 1,079 / 269.75 | 1,013 / 253.25 | 382,641 |
| immediate candidate gain | 1,048 / 262.00 | 1,038 / 259.50 | 385,692 |

The result is sharply split.

The frozen state is **not yet a better early-stop scheduler**.  It needs exactly
317 switches on all four held-out probes, versus 257–259 for the best fixed
final→early order.  The prospectively defined aggregate gate therefore fails
its first arm, even though learned propagation visits 4,746 fewer constraints
than final→early.

But proof relevance transfers cleanly.  The frozen order produces exact replayed
certificates of `248, 248, 251, 250` switches.  On the same four cases, the best
certificate available from any fixed early/final/random comparator is
`251, 252, 257, 255`.  The learned certificate is strictly smaller on **all four
held-out probes**, by `3, 4, 6, 5` switches respectively.  Its aggregate is 997
switches versus 1,015 for the best fixed structural comparator, and it also
beats immediate public gain's 1,013.

That satisfies the frozen second gate arm: a strictly smaller exact held-out
certificate.  Each certificate was sliced from the reason DAG and then replayed
as a fresh exact conflict.  This is not merely a score.  It also does **not**
mean the scheduler knew the 248-switch subset before seeing its first conflict;
the raw 317-switch stopping point remains the scheduling problem.

All 24 held-out wrong-candidate strategy runs rejected exactly.  Every held-out
truth/strategy control completed consistently.  Frozen-state SHA was identical
before and after EVAL.

## What the stream actually learned

All 336 identities appeared in BUILD between 10 and 18 times.  The frequency
field nevertheless moved identities with repeated proof participation to the
front.  This was enough to reduce the eventual dependency core on unseen
targets, but not enough to place the final conflict-closing identity early.

That gives one clean breadcrumb rather than a rescue sweep:

> Identity-level proof membership transfers; conflict-closing sequence does not.

The next distinct O1 mechanism should stream the already available proof-DAG
edges or predecessor pairs, so credit binds “identity A makes identity B
decisive” rather than only “identity A appeared.”  Certificate size remains the
teacher, while held-out first-conflict position is the optimization target.

This remains a complete-candidate filter.  It generates no candidates, recovers
zero key bits, and makes no global entropy-reduction claim.

## Reproduction ledger

Reference run: 2026-07-19 03:10:01–03:11:06 CEST.

- BUILD: 3 targets, 6 wrong probes, 18 exact proof batches, 4,603 streamed
  identity events;
- frozen state: 1,346 bytes, SHA-256
  `e097265577a4d7fc9bf6a3ae951079b4ba6a8d12d7ca6580f4f107dbfbbd75b6`;
- frozen order SHA-256:
  `47bcaca7e350042cfa3283fbb89978b5fb7f2a50bc8b53e765750878da73f92b`;
- EVAL: 2 targets, 4 wrong probes, 6 schedulers, learned always first;
- 9,254,691 constraint visits, 62,849,996 truth-table rows, 42 exact proof
  replays;
- 64.166830 CPU seconds / 64.317798 wall seconds;
- 62,226,432 bytes peak process RSS;
- source SHA-256:
  `edcd2fa209eb91f47f9627b43580c78f9dfc388b1408859abc801e73bebb8001`;
- tests SHA-256:
  `7fd8dbc0da9f62c7cdff961b9d20471a949c9d5f0d9479b09b44c08e24dcf4e1`;
- result SHA-256:
  `c44a6e2aecd6240c8789c1fca7975372ce8975d4554b247cb4d4ffd1cd0f677c`;
- scientific payload SHA-256:
  `7144a093c05cb3f834450a93160d9419688bdd9c8d72543340eb3eb5c4f51665`.

The machine JSON includes every BUILD event, complete frozen state, all orders,
held-out first passes, proof certificates and replay results, truth controls,
aggregate gate fields, hashes, timestamps, and resources.
