# O1C Run O1C-0001

- Schema: `o1c-run-capsule-v1`
- Status: `completed`
- Claim level: `SMOKE`
- Git commit: `d897c531a7b065117eeefadfb95b067f38f5370a`
- Started (Europe/Berlin): `2026-07-15T12:25:29.422054+02:00`
- Ended (Europe/Berlin): `2026-07-15T12:25:29.781677+02:00`
- Elapsed seconds: `0.359623`
- Command: `o1-crypto-lab stage3-ingest --config '/Users/bhkmie/Documents/Krypto karm/Kryptkram codex/o1-cryptanalytic-memory-lab/configs/stage3_a296_a297_ingest_v1.json'`

## Hypothesis

The manifest-pinned A296/A297 artifacts contain a complete target-blind solver-trajectory dataset that can be normalized without reading post-reveal results.

## Prediction

Twelve episodes decode to 3,072 unique cells and 12,288 UNKNOWN model-free stages with one deterministic 57-feature vector per cell and no labels in the dataset artifact.

## Controls

- exact compressed and raw byte/hash agreement with each target-blind order
- complete 256-cell and four-horizon coverage
- UNKNOWN nonterminal status, clear watchdogs and empty model bits
- post-reveal panel results inaccessible to the discovery adapter
- elapsed time and cell identity excluded from the feature vector

## Budgets

```json
{
  "expected_cells": 3072,
  "expected_episodes": 12,
  "expected_stages": 12288,
  "external_solver_calls": 0,
  "gpu_seconds": 0,
  "max_raw_bytes_per_episode": 67108864
}
```

## Pinned source hashes

- `fullround_manifest`: `9c3ac76f3f012ff24c07e2e4dbe335e5156eca28fee9986aeb53c1b6cb2a4cc3`
- `ingest_config`: `7929a1d70e6ac4ca38d824cb3e6a700c4c4dd002bf060fdb18302ac5cc626791`
- `stage3_adapter`: `9c8abd64b687c623b8943055c152a87cc050ca1264f4563b40f33d9970c27da2`
- `stage3_ingest_pipeline`: `da6adf4fe67a44818bfe818c845fa17b85cd960166b1fe9fa29ba77a31b7a201`

## Metrics

```json
{
  "by_split": {
    "RETROSPECTIVE_HOLDOUT": 2,
    "SEALED_DEPLOYMENT": 0,
    "TEST": 0,
    "TRAIN": 4,
    "TRANSFER_HOLDOUT": 4,
    "VALIDATION": 2
  },
  "cells": 3072,
  "config_sha256": "7929a1d70e6ac4ca38d824cb3e6a700c4c4dd002bf060fdb18302ac5cc626791",
  "dataset_sha256": "ccd1c4e236cba798362745b0430beecf294599e1ac4332fd5d8ad4f8625161c1",
  "episodes": 12,
  "external_solver_calls": 0,
  "feature_count": 57,
  "feature_schema_sha256": "06cb50c470eab596a279a349c372f53b5bb086bcfe1f78acd2bf4e86f62c12e0",
  "gpu_seconds": 0,
  "manifest_sha256": "9c3ac76f3f012ff24c07e2e4dbe335e5156eca28fee9986aeb53c1b6cb2a4cc3",
  "post_reveal_members_read": 0,
  "schema": "o1-crypto-stage3-ingest-metrics-v1",
  "selected_members_verified": 24,
  "source_commit": "40bdfe3acaa61d4c812be1e32f71d58e4df66d8e",
  "stages": 12288,
  "target_labels_read": 0
}
```

## Next highest-ROI action

Fit executable readers on TRAIN only, select on VALIDATION, freeze, then reveal retrospective and transfer labels in a separately logged phase.
