# O1C-0038 — Exact Full-256 residual completion frontier

O1C-0038 corrects the tied-prefix control discovered after O1C-0037 and measures
the exact relation's useful completion radius. The target is the already-consumed
`build-0000` public ChaCha20-R20 instance. Prefix order is frozen from the
absolute O1C-0022 K256 confidence field, while every supplied sign is replaced
post reveal by the exact truth. No key unit clauses are added: the prefix enters
as reversible first-encounter CDCL decisions, and every SAT model is independently
verified against the public block relation.

At a 512-conflict ceiling, residual widths `0, 1, 2, 4, 8` all recover the exact
256-bit key; widths `9` and `16` remain unresolved. The eight-bit residual closes
in `89` conflicts and `135,441 us`. The nine-bit residual remains unresolved at
`512`, `2,048`, `8,192` and `32,768` conflicts; the largest arm takes
`6,770,843 us`. Every supplied prefix contains exactly as many correct bits as
declared, including the tied-confidence cases.

This is a post-reveal mechanism ceiling, not attacker-valid key recovery. Its
value is concrete: the exact bridge already has an O1-ordered eight-bit completion
zone, but key-only guidance has essentially zero practical error radius. The next
attacker-valid mechanism must therefore reduce joint/effective residual width
toward this zone using target-specific relation or proof factors; another unary
Hamming reader is not enough.

- Source commit: `1596c3eb9467124e1ba7e6c218277d0a7a1abebe`
- Elapsed: `11.494730 s`
- Peak RSS: `139,575,296 B`
- Native solver calls: `10`
- Requested conflict ledger: `46,592`
- Capsule manifest: `78798e6d1f0c1078482c09a2cb48df041e14bf8238c4e54f0d6843315c3f538e`
- [Immutable capsule](../runs/20260718_212009_O1C-0038_exact-residual-completion-v1/RUN.md)
- [Machine-readable result](O1C0038_EXACT_RESIDUAL_COMPLETION_RESULT_20260718.json)

