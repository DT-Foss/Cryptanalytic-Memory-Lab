# O1C-0066 — APPLE8 episodic score-threshold no-good vault

- Classification: `EPISODIC_VAULT_OPERATIONAL_TERMINAL`
- Stop reason: `native-call-or-resource-terminal`
- Native solver episodes: `3`
- Truth key bytes read: `false`
- Vault scope: `CNF and potential_score >= threshold` (not CNF-only)

Each episode is a fresh subprocess, not a retry. Only fully emitted exact score-threshold no-goods survive in first-emission order.
