# O1C Run O1C-0002

- Schema: `o1c-run-capsule-v1`
- Status: `completed`
- Claim level: `RETROSPECTIVE`
- Git commit: `5f456c616b50458cba97a0201d636b5fdb743d32`
- Started (Europe/Berlin): `2026-07-15T12:32:36.233720+02:00`
- Ended (Europe/Berlin): `2026-07-15T12:32:40.806892+02:00`
- Elapsed seconds: `4.573172`
- Command: `o1-crypto-lab stage3-reader --config '/Users/bhkmie/Documents/Krypto karm/Kryptkram codex/o1-cryptanalytic-memory-lab/configs/stage3_reader_retrospective_v1.json'`

## Hypothesis

Attacker-computable solver-trajectory geometry contains a stable high-eight-bit cell signal that transfers beyond the four training targets.

## Prediction

A TRAIN-only reader selected on two VALIDATION targets will beat numeric, public-hash and the published target-blind score on mean log2 rank gain in both the untouched A296 retrospective pair and the W32 A297 transfer panel.

## Controls

- post-reveal aggregate results are read only by a child-process label broker
- holdout broker calls occur only after the plan and complete orders are written and hash-bound
- numeric ascending, public-hash and published target-blind score baselines
- all readers score the same 256 cells with the same 57-feature input
- exact familywise validation-selection null over all 65,536 two-label pairs
- no GPU, cipher execution, solver execution or caller-supplied information gain

## Budgets

```json
{
  "candidate_operators": 119,
  "cells_per_target": 256,
  "external_solver_calls": 0,
  "gpu_seconds": 0,
  "retrospective_holdout_targets": 2,
  "train_targets": 4,
  "transfer_holdout_targets": 4,
  "validation_targets": 2
}
```

## Pinned source hashes

- `fullround_manifest`: `9c3ac76f3f012ff24c07e2e4dbe335e5156eca28fee9986aeb53c1b6cb2a4cc3`
- `ingest_config`: `7929a1d70e6ac4ca38d824cb3e6a700c4c4dd002bf060fdb18302ac5cc626791`
- `label_broker`: `f8de803ec41b8fc73978f060907a7e8550581ae9a31a24d2de33d23151f93bb2`
- `o1c_0001_capsule_manifest`: `376e3b27f107d132421e29c2669f468a57c8417924928ce41badadf14d3dd05f`
- `reader_config`: `42e7cf443ad8952eb626acac20ce3d2d223e59f85a263a4870453b7e334bbc08`
- `reader_experiment`: `ddfd84daa4fd903ca8472f488183bc0fa072bd17b105c43b38b5dffc53938b89`
- `stage3_adapter`: `9c8abd64b687c623b8943055c152a87cc050ca1264f4563b40f33d9970c27da2`
- `stage3_ingest_pipeline`: `da6adf4fe67a44818bfe818c845fa17b85cd960166b1fe9fa29ba77a31b7a201`
- `trajectory_reader`: `692c859bdca69793c57fe1acc92713c36e098efba4ab2ce9f20d05995fc00453`

## Metrics

```json
{
  "candidate_operators": 119,
  "external_solver_calls": 0,
  "familywise_validation_selection_null": {
    "candidate_operators": 119,
    "familywise_p_ge_observed": 0.6641387939453125,
    "label_pairs_enumerated": 65536,
    "null": "two independent uniformly random correct cells over 0..255",
    "null_best_mean_gain": 3.8234298371212714,
    "null_best_median_gain": 3.7421500808579786,
    "null_best_quantiles": {
      "q50": 3.7421500808579786,
      "q90": 5.04655470219574,
      "q95": 5.5,
      "q99": 6.415037499278844
    },
    "observed_selected_mean_log2_rank_gain": 3.3481096259114485,
    "schema": "o1-crypto-exact-familywise-selection-null-v1"
  },
  "gpu_seconds": 0,
  "holdout_labels_read_before_freeze": 0,
  "plan_sha256": "ae2bda0e6a337b5396cbbab2e72108c38f67543b137f2e266a4f3943d7d7a587",
  "retrospective_holdout": {
    "mean_log2_rank_gain": 0.8006281540309035,
    "mean_reciprocal_rank": 0.0076388888888888895,
    "median_log2_rank_gain": 0.8006281540309035,
    "targets": 2,
    "top_k": [
      {
        "count": 0,
        "k": 1,
        "rate": 0.0
      },
      {
        "count": 0,
        "k": 4,
        "rate": 0.0
      },
      {
        "count": 0,
        "k": 8,
        "rate": 0.0
      },
      {
        "count": 0,
        "k": 16,
        "rate": 0.0
      },
      {
        "count": 0,
        "k": 32,
        "rate": 0.0
      }
    ]
  },
  "schema": "o1-crypto-stage3-reader-metrics-v1",
  "selected_feature": "h8.search_propagations",
  "selected_operator": "feature.rank.047.+1",
  "success_gate_passed": false,
  "transfer_holdout": {
    "mean_log2_rank_gain": 1.104380178549594,
    "mean_reciprocal_rank": 0.011191339790614367,
    "median_log2_rank_gain": 0.8558553289095151,
    "targets": 4,
    "top_k": [
      {
        "count": 0,
        "k": 1,
        "rate": 0.0
      },
      {
        "count": 0,
        "k": 4,
        "rate": 0.0
      },
      {
        "count": 0,
        "k": 8,
        "rate": 0.0
      },
      {
        "count": 0,
        "k": 16,
        "rate": 0.0
      },
      {
        "count": 0,
        "k": 32,
        "rate": 0.0
      }
    ]
  },
  "validation": {
    "mean_log2_rank_gain": 3.3481096259114485,
    "mean_reciprocal_rank": 0.06882911392405064,
    "median_log2_rank_gain": 3.3481096259114485,
    "targets": 2,
    "top_k": [
      {
        "count": 0,
        "k": 1,
        "rate": 0.0
      },
      {
        "count": 0,
        "k": 4,
        "rate": 0.0
      },
      {
        "count": 1,
        "k": 8,
        "rate": 0.5
      },
      {
        "count": 1,
        "k": 16,
        "rate": 0.5
      },
      {
        "count": 1,
        "k": 32,
        "rate": 0.5
      }
    ]
  }
}
```

## Next highest-ROI action

If transfer fails, preserve the feature-level breadcrumb and move to the richer 532-dimensional temporal/XOR/Laplacian reader before adding memory complexity.
