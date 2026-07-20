# O1C Run O1C-0018

- Schema: `o1c-run-capsule-v1`
- Status: `completed`
- Claim level: `TEST`
- Git commit: `f40e71aa8ed80b4653acf44d98e14eabec18a955`
- Started (Europe/Berlin): `2026-07-17T15:28:27.988908+02:00`
- Ended (Europe/Berlin): `2026-07-17T15:36:58.863904+02:00`
- Elapsed seconds: `510.874996`
- Command: `/Library/Frameworks/Python.framework/Versions/3.13/bin/python3 -m o1_crypto_lab.full256_online_real_gate_run --config '/Users/bhkmie/Documents/Krypto karm/Kryptkram codex/o1-cryptanalytic-memory-lab/configs/full256_online_real_gate_dev_v1.json'`

## Hypothesis

A bounded O1 reader trained only after four deterministic known-key BUILD reveals can discover predictive structure directly in anonymous 330-channel full-round ChaCha20 paired-proof streams, and a signed reveal-delayed reward critic can use that living state to select a sub-exhaustive action trajectory with higher compression-versus-requested-conflict area than matched shifted-reward, frozen-static, shortest-first and uniform-hash controls.

## Prediction

On two disjoint deterministic DEVELOPMENT targets with all 256 key bits unknown at probe time, the fixed exhaustive reader will average at least 0.25 bit of compression, remain positive on both targets and beat both an untrained reader and a coordinate-rotation control by at least 0.10 bit. Across one nested trajectory at work caps 16384, 32768 and 57600, the true learned picker will beat every matched control by at least 0.05 mean IAUC bit and win against all controls on both targets. Structural polarity, common-only, same-reader, freeze-order, bounded-state and zero-accelerator gates must hold exactly.

## Controls

- all BUILD and DEVELOPMENT proof pools are standard twenty-round ChaCha20 public-output instances with zero key or internal trace input to the probe
- every immutable approximately two-megabyte public action pool is persisted before its associated key labels can be materialized
- BUILD uses one fixed exhaustive pool-blind Latin action schedule; no BUILD action is selected from its target label or unexecuted pool content
- each BUILD live trajectory and fast-state commitment is persisted before that target key is revealed for reader and critic learning
- the true and shifted-reward critics share byte-identical O1 reader weights; only their reveal-time reward labels differ
- the static reward arm freezes signed per-action BUILD delta-NLL divided by requested work and receives no live O1 adaptation
- shortest-first and uniform-hash controls share identical affordability and minimum-coordinate-coverage rules
- W1, W2 and W3 are byte-frozen prefixes of one continuing trajectory rather than three restarted tests
- all DEVELOPMENT raw predictions, policy predictions and action ledgers are persisted before any DEVELOPMENT labels are materialized
- polarity swapping must negate the full 256-logit field exactly and common-only observations must produce exact zero orientation
- the native solver currently generates the whole public pool first, so this attempt claims logical requested-conflict efficiency but not solver wall-clock savings
- the DEVELOPMENT corpus seed is unique to O1C-0018; zero entropy may affect corpus, model or scoring, while capsule IDs and temporary path names are explicitly outside scientific state; no sibling read/write, MPS or GPU call is permitted

## Budgets

```json
{
  "maximum_cpu_seconds": 1800,
  "maximum_gpu_calls": 0,
  "maximum_mps_calls": 0,
  "maximum_native_solver_branches": 4096,
  "maximum_persistent_artifact_bytes": 24000000,
  "maximum_physical_public_pools": 6,
  "maximum_resident_memory_mib": 768,
  "maximum_scientific_entropy_calls": 0,
  "maximum_sibling_reads": 0,
  "maximum_sibling_writes": 0,
  "maximum_wall_seconds": 1800
}
```

## Pinned source hashes

- `config`: `fd539d2a2461f879ebdbcad2c29f3c6de7c514385fece2ef1bf8ddb06707056a`
- `module_cadical_sensor`: `af24c17ae98817d6ad5d6fa30be227aecaf4be3753738bda3c34fae12948fa90`
- `module_causal_bitfield`: `54ac8c9b78b9e3ba2aabf5676fcce730a52aee345db4713c54f9c7c054b84e8a`
- `module_chacha_trace`: `58b8272f2cdd6665291158cecc2456258d3cb58f2ab3970d1c4c38e749473b01`
- `module_full256_action_pool`: `df0d6a0df60d811e7cf674aa1a91b22a80834fab3acee534f77f7e1c289c1883`
- `module_full256_cnf`: `76572366adbcadf1525cb25f4c84f5b78ff99be9b63acd721530e53532d9a0e0`
- `module_full256_online_real_gate`: `1bde2e7024bcb7d5aaa439c9bc636e784f794d26d8a7329b5139a8aed63ca049`
- `module_full256_online_real_gate_run`: `b8da1708f1fd428a2d0bfdadfbb62e8a69a7759b195011adab15f07bc70c5683`
- `module_full256_paired_sensor`: `8117048a9ea05b138974602c26f58e69fcf51add9b22a837e4cfa0e8a9794175`
- `module_full256_probe_core`: `c122ae196dd48912793e60895b2cd6bba1023bf59b417f10ddb0d67c8b4da8f5`
- `module_full256_proof_pool`: `7fec03dd03ffe61144f836491db9be7094dda20a80e1aedd4e6a7c26a689d30c`
- `module_living_inverse`: `16c22a9776b693c40e0d6c3a3196c73c7a4c15913bde0bdb14e8d9fc4dbe127e`
- `module_o1_streaming_core`: `c918789a668d2e4a47f927cfe44e7e0dd3825e84dfa46e29aa48dee14d737fd7`
- `module_online_causal_controller`: `e28cd7d43b71040d91ea850d1ff76b700feaa20996825ea35448221c9936f157`
- `module_run_capsule`: `13681939e0a5cd09d4f32c6d92c9a56894cfe8af90f07d5d4190c96b90a1b664`
- `native_cadical_pair_sensor`: `67c094e069e8884e4761f82d2d797b594ef326a6ddcf0243dacd8019ae235669`
- `native_cadical_tracer_3_0_0`: `36e1983eb865800aec1c042c4df4abfbcbc8ced3c82e2bf4baad340639c887fe`
- `pyproject`: `0248ec0fe7d42390b62e358fdd52f63d64f7d4e699f0f41ef77c569699716bd0`

## Metrics

```json
{
  "budget_checks": {
    "cpu": true,
    "gpu": true,
    "mps": true,
    "native_solver_branches": true,
    "persistent_artifacts": true,
    "physical_public_pools": true,
    "resident_memory": true,
    "scientific_entropy": true,
    "sibling_reads": true,
    "sibling_writes": true,
    "wall": true
  },
  "child_cpu_seconds": 82.162717,
  "classification": "NO_RAW_SIGNAL_PICKER_UNINTERPRETABLE",
  "cpu_seconds": 545.0243310000001,
  "expected_native_solver_branches": 3072,
  "failed_budgets": [],
  "gates": {
    "all_checkpoint_paths_are_nested_prefixes": true,
    "all_checkpoint_slack_within_bound": true,
    "all_prediction_trajectories_frozen_before_labels": true,
    "common_only_orientation_zero": true,
    "exact_polarity_swap_antisymmetry": true,
    "picker_gate_passed": false,
    "raw_primary_mean_compression": false,
    "raw_primary_over_coordinate_rotation": false,
    "raw_primary_over_untrained": true,
    "raw_primary_positive_targets": false,
    "raw_signal_gate_passed": false,
    "shared_reader_for_true_and_shifted_critics": true,
    "structural_gate_passed": true,
    "success_gate_passed": false,
    "true_picker_over_shifted_reward_iauc": true,
    "true_picker_over_shortest_first_iauc": true,
    "true_picker_over_static_reward_iauc": false,
    "true_picker_over_uniform_hash_iauc": false,
    "true_picker_target_wins": false,
    "zero_entropy_calls_affecting_scientific_state": true,
    "zero_evaluation_slow_updates": true,
    "zero_gpu_calls": true,
    "zero_mps_calls": true,
    "zero_sibling_writes": true,
    "zero_target_key_inputs_to_probe": true,
    "zero_target_trace_inputs": true
  },
  "margins": {
    "picker_true_all_control_target_wins": 1,
    "picker_true_minus_hash_mean_iauc_bits": -0.12075845490110759,
    "picker_true_minus_shifted_mean_iauc_bits": 0.22139683479433891,
    "picker_true_minus_shortest_mean_iauc_bits": 0.07116439574182307,
    "picker_true_minus_static_mean_iauc_bits": -0.2625597583406378,
    "raw_primary_minus_rotation_mean_bits": -1.4886065512120297,
    "raw_primary_minus_rotation_z": -2.223444782310097,
    "raw_primary_minus_untrained_mean_bits": 0.7243707279910154,
    "raw_primary_minus_untrained_z": 46.54614715618637
  },
  "native_solver_branches": 3072,
  "operational_failure": false,
  "operationally_complete": true,
  "parent_cpu_seconds": 462.86161400000003,
  "peak_rss_bytes": 315703296,
  "persistent_artifact_bytes": 13139765,
  "physical_public_pools": 6,
  "policy_arms": {
    "build_static_reward": {
      "checkpoints": [
        {
          "bit_accuracy": 0.509765625,
          "compression_stddev_bits": 0.1278297368563787,
          "conditional_z_score": 2.5992881788444127,
          "exact_keys": 0,
          "maximum_correct_bits": 133,
          "mean_action_count": 116.0,
          "mean_compression_bits": 0.23494777080063045,
          "mean_correct_bits_per_target": 130.5,
          "mean_requested_work": 16294.0,
          "minimum_correct_bits": 128,
          "name": "build_static_reward",
          "positive_targets": 2,
          "work_cap": 16384
        },
        {
          "bit_accuracy": 0.51171875,
          "compression_stddev_bits": 0.29678605193860924,
          "conditional_z_score": 1.261245717960253,
          "exact_keys": 0,
          "maximum_correct_bits": 134,
          "mean_action_count": 225.0,
          "mean_compression_bits": 0.2646843073190297,
          "mean_correct_bits_per_target": 131.0,
          "mean_requested_work": 32740.0,
          "minimum_correct_bits": 128,
          "name": "build_static_reward",
          "positive_targets": 2,
          "work_cap": 32768
        },
        {
          "bit_accuracy": 0.521484375,
          "compression_stddev_bits": 0.29589297788338426,
          "conditional_z_score": 0.3481253312996293,
          "exact_keys": 0,
          "maximum_correct_bits": 136,
          "mean_action_count": 387.0,
          "mean_compression_bits": 0.07283754285458599,
          "mean_correct_bits_per_target": 133.5,
          "mean_requested_work": 57540.0,
          "minimum_correct_bits": 131,
          "name": "build_static_reward",
          "positive_targets": 1,
          "work_cap": 57600
        }
      ],
      "iauc_conditional_z_score": 1.213635269602321,
      "mean_iauc_bits": 0.17729575107317383
    },
    "learned_shifted_reward": {
      "checkpoints": [
        {
          "bit_accuracy": 0.4765625,
          "compression_stddev_bits": 0.15152982842471147,
          "conditional_z_score": 0.7959035659544728,
          "exact_keys": 0,
          "maximum_correct_bits": 129,
          "mean_action_count": 118.0,
          "mean_compression_bits": 0.08527929161513725,
          "mean_correct_bits_per_target": 122.0,
          "mean_requested_work": 16332.0,
          "minimum_correct_bits": 115,
          "name": "learned_shifted_reward",
          "positive_targets": 1,
          "work_cap": 16384
        },
        {
          "bit_accuracy": 0.48828125,
          "compression_stddev_bits": 0.2798871305346136,
          "conditional_z_score": -1.882589691994835,
          "exact_keys": 0,
          "maximum_correct_bits": 127,
          "mean_action_count": 241.0,
          "mean_compression_bits": -0.3725834915501025,
          "mean_correct_bits_per_target": 125.0,
          "mean_requested_work": 32678.0,
          "minimum_correct_bits": 123,
          "name": "learned_shifted_reward",
          "positive_targets": 0,
          "work_cap": 32768
        },
        {
          "bit_accuracy": 0.462890625,
          "compression_stddev_bits": 0.7798141746616816,
          "conditional_z_score": -1.655954752147219,
          "exact_keys": 0,
          "maximum_correct_bits": 123,
          "mean_action_count": 404.0,
          "mean_compression_bits": -0.9131131412400464,
          "mean_correct_bits_per_target": 118.5,
          "mean_requested_work": 57575.0,
          "minimum_correct_bits": 114,
          "name": "learned_shifted_reward",
          "positive_targets": 0,
          "work_cap": 57600
        }
      ],
      "iauc_conditional_z_score": -1.9234617294571097,
      "mean_iauc_bits": -0.3066608420618029
    },
    "learned_true_reward": {
      "checkpoints": [
        {
          "bit_accuracy": 0.470703125,
          "compression_stddev_bits": 0.11785429645504616,
          "conditional_z_score": 2.9220535885483194,
          "exact_keys": 0,
          "maximum_correct_bits": 127,
          "mean_action_count": 118.5,
          "mean_compression_bits": 0.24351100784554092,
          "mean_correct_bits_per_target": 120.5,
          "mean_requested_work": 16303.0,
          "minimum_correct_bits": 114,
          "name": "learned_true_reward",
          "positive_targets": 2,
          "work_cap": 16384
        },
        {
          "bit_accuracy": 0.494140625,
          "compression_stddev_bits": 0.42236968409630604,
          "conditional_z_score": -0.4155225529920965,
          "exact_keys": 0,
          "maximum_correct_bits": 130,
          "mean_action_count": 241.0,
          "mean_compression_bits": -0.12410016005479463,
          "mean_correct_bits_per_target": 126.5,
          "mean_requested_work": 32710.0,
          "minimum_correct_bits": 123,
          "name": "learned_true_reward",
          "positive_targets": 1,
          "work_cap": 32768
        },
        {
          "bit_accuracy": 0.490234375,
          "compression_stddev_bits": 0.786130337623247,
          "conditional_z_score": -0.912957756623659,
          "exact_keys": 0,
          "maximum_correct_bits": 126,
          "mean_action_count": 403.5,
          "mean_compression_bits": -0.5074932164036028,
          "mean_correct_bits_per_target": 125.5,
          "mean_requested_work": 57538.0,
          "minimum_correct_bits": 125,
          "name": "learned_true_reward",
          "positive_targets": 1,
          "work_cap": 57600
        }
      ],
      "iauc_conditional_z_score": -0.4184913833978435,
      "mean_iauc_bits": -0.085264007267464
    },
    "shortest_first": {
      "checkpoints": [
        {
          "bit_accuracy": 0.48828125,
          "compression_stddev_bits": 0.1451569707296745,
          "conditional_z_score": -0.6254568648442648,
          "exact_keys": 0,
          "maximum_correct_bits": 127,
          "mean_action_count": 128.0,
          "mean_compression_bits": -0.06419781724517293,
          "mean_correct_bits_per_target": 125.0,
          "mean_requested_work": 16384.0,
          "minimum_correct_bits": 123,
          "name": "shortest_first",
          "positive_targets": 1,
          "work_cap": 16384
        },
        {
          "bit_accuracy": 0.470703125,
          "compression_stddev_bits": 0.04953434765014169,
          "conditional_z_score": -10.48127079800969,
          "exact_keys": 0,
          "maximum_correct_bits": 125,
          "mean_action_count": 256.0,
          "mean_compression_bits": -0.36711775741471797,
          "mean_correct_bits_per_target": 120.5,
          "mean_requested_work": 32768.0,
          "minimum_correct_bits": 116,
          "name": "shortest_first",
          "positive_targets": 0,
          "work_cap": 32768
        },
        {
          "bit_accuracy": 0.501953125,
          "compression_stddev_bits": 0.26278663219652176,
          "conditional_z_score": -0.17044274517026575,
          "exact_keys": 0,
          "maximum_correct_bits": 134,
          "mean_action_count": 447.0,
          "mean_compression_bits": -0.03167136575218876,
          "mean_correct_bits_per_target": 128.5,
          "mean_requested_work": 57598.0,
          "minimum_correct_bits": 123,
          "name": "shortest_first",
          "positive_targets": 1,
          "work_cap": 57600
        }
      ],
      "iauc_conditional_z_score": -6.687112748402375,
      "mean_iauc_bits": -0.15642840300928706
    },
    "uniform_hash": {
      "checkpoints": [
        {
          "bit_accuracy": 0.474609375,
          "compression_stddev_bits": 0.0177432119923123,
          "conditional_z_score": 4.316457756218075,
          "exact_keys": 0,
          "maximum_correct_bits": 125,
          "mean_action_count": 106.0,
          "mean_compression_bits": 0.05415577043110886,
          "mean_correct_bits_per_target": 121.5,
          "mean_requested_work": 16270.0,
          "minimum_correct_bits": 118,
          "name": "uniform_hash",
          "positive_targets": 2,
          "work_cap": 16384
        },
        {
          "bit_accuracy": 0.4921875,
          "compression_stddev_bits": 0.177327555055786,
          "conditional_z_score": 0.3053291126824995,
          "exact_keys": 0,
          "maximum_correct_bits": 130,
          "mean_action_count": 214.0,
          "mean_compression_bits": 0.03828506986489799,
          "mean_correct_bits_per_target": 126.0,
          "mean_requested_work": 32724.0,
          "minimum_correct_bits": 122,
          "name": "uniform_hash",
          "positive_targets": 1,
          "work_cap": 32768
        },
        {
          "bit_accuracy": 0.50390625,
          "compression_stddev_bits": 0.47989582697597744,
          "conditional_z_score": 0.08704902538236356,
          "exact_keys": 0,
          "maximum_correct_bits": 133,
          "mean_action_count": 383.0,
          "mean_compression_bits": 0.029539006791324596,
          "mean_correct_bits_per_target": 129.0,
          "mean_requested_work": 57558.0,
          "minimum_correct_bits": 125,
          "name": "uniform_hash",
          "positive_targets": 1,
          "work_cap": 57600
        }
      ],
      "iauc_conditional_z_score": 1.4257357082542796,
      "mean_iauc_bits": 0.03549444763364358
    }
  },
  "raw_arms": {
    "coordinate_rotation_control": {
      "bit_accuracy": 0.474609375,
      "compression_stddev_bits": 0.7831367299538442,
      "conditional_z_score": 0.36832245575134986,
      "exact_keys": 0,
      "maximum_correct_bits": 125,
      "mean_compression_bits": 0.2039627190971487,
      "mean_correct_bits_per_target": 121.5,
      "minimum_correct_bits": 118,
      "name": "coordinate_rotation_control",
      "positive_targets": 1
    },
    "learned_reader_full_field": {
      "bit_accuracy": 0.478515625,
      "compression_stddev_bits": 0.16368578190284314,
      "conditional_z_score": -11.099074758210591,
      "exact_keys": 0,
      "maximum_correct_bits": 127,
      "mean_compression_bits": -1.284643832114881,
      "mean_correct_bits_per_target": 122.5,
      "minimum_correct_bits": 118,
      "name": "learned_reader_full_field",
      "positive_targets": 0
    },
    "raw_o1_end_state": {
      "bit_accuracy": 0.48046875,
      "compression_stddev_bits": 0.16796020705966525,
      "conditional_z_score": -0.7863187519899739,
      "exact_keys": 0,
      "maximum_correct_bits": 133,
      "mean_compression_bits": -0.0933877767213005,
      "mean_correct_bits_per_target": 123.0,
      "minimum_correct_bits": 113,
      "name": "raw_o1_end_state",
      "positive_targets": 1
    },
    "untrained_reader_full_field": {
      "bit_accuracy": 0.484375,
      "compression_stddev_bits": 0.1856943684411344,
      "conditional_z_score": -15.300278957072608,
      "exact_keys": 0,
      "maximum_correct_bits": 128,
      "mean_compression_bits": -2.0090145601058964,
      "mean_correct_bits_per_target": 124.0,
      "minimum_correct_bits": 120,
      "name": "untrained_reader_full_field",
      "positive_targets": 0
    }
  },
  "result_sha256": "db92bd86849ff93e0f9b935a72f64f1b4bd46b134747c913ee82e5d772ac11c9",
  "schema": "o1-256-fullround-online-real-gate-cli-result-v1",
  "scientific_success_gate_passed": false,
  "wall_seconds": 510.83213291689754
}
```

## Next highest-ROI action

If DUAL_PASS, freeze this exact reader/picker lineage and build the lazy one-action native executor before a disjoint formal EVALUATION replication. If RAW_ONLY_PASS, preserve the reader and change only picker credit assignment or context. If no raw signal appears, retain the signed per-action BUILD reward map and use its horizon, coordinate and channel residuals to choose the next causal sensor view without resweeping this field.
