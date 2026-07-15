# Direct12 Source Boundary v1

This ledger pins 71 exact files from the read-only sibling
`../arx-carry-leak`. It is a lab-owned byte ledger, not a claim that these files
belong to the clean `fullround-key-recovery` publication manifest.

## Source state at curation

- Repository HEAD: `97fa868b96771951d5fb2c26aa1785e9d05c4cde`
- Worktree state: dirty; the Direct12 research artifacts are untracked at that
  commit.
- Lab ledger: `provenance/direct12_source_v1.sha256`
- Source mutation: none. Every listed byte was read and hashed in place.
- Clean Fullround manifest coverage for A272/A342/A348/A349: zero members.

The ledger is therefore suitable for deterministic read-only ingestion and for
creating an immutable lab snapshot. It is not suitable for silently upgrading a
result to a publication-manifest or clean-commit claim.

## Allowed discovery/calibration inputs

- The four pinned implementation modules are references for an independent lab
  reimplementation; they are never imported from the sibling worktree.
- A272 measurement shards are TRAIN/calibration only. Their known-key labels are
  available only through a separate label reader.
- A342 design/result may provide the already-selected semantic pair and frozen
  model parameters; no A349 feedback may change them.
- A348 shards are calibration features. Its result document is post-reveal and
  may be opened only by a calibration broker.
- A349 design, selection, implementation, preflight, 16 measurement shards and
  frozen order are pre-result inputs. The order may be used as a fixed full-field
  reference, never as a source of target labels.

## Hard discovery denylist

The following paths and any future sibling with the same result stem must never be
read by feature extraction, selection or O1-bank calibration:

```text
research/results/v1/chacha20_round20_holdout_selected_w46_recovery_a325_v1.json
research/results/v1/chacha20_round20_fresh_w46_factor2_replication_a345_progress_v1.json
research/results/v1/chacha20_round20_w46_a349_order_prospective_recovery_a350_progress_v1.json
research/results/v1/chacha20_round20_fresh_w46_factor2_replication_a345_v1.json
research/results/v1/chacha20_round20_w46_direct12_prospective_a345_validation_a349_v1.json
research/results/v1/chacha20_round20_w46_direct12_prospective_a345_validation_a349_v1.md
research/results/v1/chacha20_round20_w46_direct12_prospective_a345_validation_a349_v1.causal
research/results/v1/chacha20_round20_w46_a349_order_prospective_recovery_a350_v1.json
```

Progress files are volatile and are denied by path/stem, not by a pinned hash.
At curation time the final A349/A350 outcome files were absent. A progress file
existed, but no progress fact may influence the lab mechanism or budget selection.
