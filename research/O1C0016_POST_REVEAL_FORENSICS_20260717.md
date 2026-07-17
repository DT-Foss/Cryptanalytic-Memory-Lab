# O1C-0016 Post-Reveal Forensics

- **Completed:** 2026-07-17T12:20:25+02:00
- **Capsule:** `runs/20260717_115325_O1C-0016_full256-polyphase-blind-replication-v2/`
- **Scientific classification:** `NOT_REPLICATED`
- **Architecture classification:** `DO_NOT_PROMOTE`
- **Integrity classification:** `PASS`

## Decision

The frozen unary h96 orientation and its fixed equal-logit h96+h65 successor do
not remove transferable code length from fresh standard twenty-round ChaCha20
keys. This closes the current hand-oriented global proof-difficulty reader. It
does not close the exact public-CNF sensor, the bounded O1 state, query-rooted
proof/carry evidence, sparse higher-order interventions or a learned online
reader.

No O1C-0015 or O1C-0016 target may be reused for reader selection or efficacy
measurement.

## Independent integrity result

An independent audit verified all 680 manifested members with no missing,
mismatched or unexpected files. Manifest:
`fd0469885ee436414f94d708006cc40d86fc730d25b618167c7d664b3fe195ea`.
The clean preregistration commit, source modules, canonical config, protocol
freeze, prediction-set freeze, reveal receipts and evaluation hash chain all
match. Every one of the 32 public outputs was also recomputed through an
independent ChaCha20 implementation; every commitment opens.

All predictions and controls were persisted before reveal. The 32 target IDs,
keys, salts, public views and outputs are unique, and no key or salt occurs in a
pre-reveal JSON artifact. The exact-code access counters report zero sibling
reads/writes, MPS calls and GPU calls.

## Frozen primary result

| Reader | Correct bits | Compression (bit/key) | Conditional z |
|---|---:|---:|---:|
| h96+h65 equal-logit ensemble | 4,093 / 8,192 | -0.078249 | -0.416562 |
| exact h96 | 4,052 / 8,192 | -0.175000 | -0.8171 |
| reconstructed h65 | 4,100 / 8,192 | -0.033913 | +0.2962 |
| matched shuffled ensemble | 4,100 / 8,192 | +0.001976 | control |

The ensemble is positive on only 11/32 targets and loses to its matched shuffled
control by `-0.080225` bit/key (`z=-0.555358`). It improves h96 by `+0.096751`
bit/key but loses to the stronger h65 component by `-0.044336` bit/key. The
predeclared polyphase-promotion z is only `1.004470`, below `1.644854`.

There are zero exact keys. The best million-decoy rank is 45,147 and the median is
604,297. Under the uniform null, obtaining at least one rank as good as 45,147 in
32 trials has probability approximately 0.772; it is not anomalous.

## Null-like structure at every useful resolution

- Byte ranks: 4/1,024 top-1, 16 top-4 and 61 top-16; uniform expectations are
  exactly 4, 16 and 64.
- 16-bit ranks: zero top-16 groups; the best truth rank is 166/65,536.
- Coordinate stability: six coordinates are correct on at least 22/32 targets,
  versus 6.41 expected under independent fair bits.
- The best coordinate reaches 24/32. The familywise probability that at least one
  of 256 fair coordinates reaches 24/32 is approximately 0.592.
- No coordinate is correct on all targets.
- O1C-0014 to O1C-0016 per-coordinate compression correlation is `-0.0067` for
  h96 and `-0.044` for the ensemble; coordinate signs transfer at chance.

Pooling the exact h96 reader across O1C-0013, O1C-0014 and O1C-0016 yields
5,364/10,752 bits, mean compression `-0.08457` bit/key and conditional
`z=+0.134`. The earlier positive panels therefore collapse to the null under the
larger prospective sample.

## What the sensor actually learned

The result is more informative than a generic low-power failure:

1. Per-target h65 primary compression and matched-shuffled compression correlate
   at `0.999905`. The h65 field is dominated by target/public-instance difficulty
   or amplitude rather than key-label orientation.
2. The reconstructed shuffled-h96 logits are exactly zero. The shuffled-h65
   logits are, to floating-point residual below `4e-9`, a fixed positive
   `0.38857049` multiple of the primary-h65 logits. The matched control is
   therefore a shrunken view of the same common-mode geometry, not an independent
   orientation.
3. h96 and h65 raw logits correlate only about `0.326` and agree in sign on about
   61.9% of cells. The fixed ensemble beats both components on only 4/32 targets
   and loses `0.1527` bit/key to an oracle that picks the better component per
   target.
4. The three public-evidence controls remain mixed: output-bit flip is `+0.254`,
   wrong nonce `-0.078`, and byte rotation `+0.516` bit/key. The factual anchor
   even loses slightly to byte rotation.

The global proof prefix contains repeatable public-instance structure, but the
hand-fitted unary map does not know which polarity corresponds to the hidden key.
More targets, a deeper fixed prefix or another fixed blend would amplify this
common mode rather than create orientation.

## Highest-ROI architecture pivot

The next organism must learn the signal rather than receive a hand-authored signal
definition. We specify only its legal perception/action space and truth boundary:

- **Perception:** raw bounded causal event deltas, assumption/proof ancestry,
  horizon transitions, antisymmetry residuals and matched factual/control fields.
- **Actions:** choose coordinate, sparse pair/triple, horizon, reader operator,
  phase and compute budget.
- **Fast state:** target-local O1/GSSM state may adapt online through label-free
  objectives such as cross-horizon predictability, novelty, control separation,
  contradiction reduction and repeatability. It resets for each target.
- **Slow state:** O1/O1-O reader and policy weights learn on self-generated known
  BUILD keys and on completed challenges only after reveal. Challenge `n` may
  improve challenge `n+1`, never itself.
- **Truth:** exact key labels during BUILD and exact public ChaCha20 verification
  at the terminal boundary. Only exact UNSAT or verification may create hard 0/1
  posterior mass.

Before learning orientation, subtract or whiten the common-mode difficulty field.
The first structured interaction is the Boolean Möbius difference

```text
m_i  = F(k_i=1) - F(k_i=0)
m_ij = F(1,1) - F(1,0) - F(0,1) + F(0,0)
```

with only causally linked sparse pairs initially eligible. The scheduler score is
learned utility plus uncertainty, surprise and coverage debt; an epsilon floor
prevents unvisited coordinates from becoming false zero-probability regions.

This turns O1C-0016's negative result into the next testable proposition: remove
what is common to both orientations, then let the continuous O1/O1-O loop discover
which residual event geometry predicts information gain per unit work.

## Resource result

The full 32-target run used 17,920 native branches, 1,972.625 billed CPU seconds,
1,620.537 wall seconds, 414.813 MiB conservative peak RSS, 67,584 bytes of live
target state and 6,768,561 persistent artifact bytes. Every frozen resource gate
passed. This validates the full-256 bounded-state lifecycle on CPU; it does not
validate inverse efficacy.
