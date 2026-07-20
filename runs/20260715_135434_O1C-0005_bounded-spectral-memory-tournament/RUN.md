# O1C Run O1C-0005

- Schema: `o1c-run-capsule-v1`
- Status: `completed`
- Claim level: `VALIDATION`
- Git commit: `a1ebe8a01bcfc1369b413e53c2e15ab4be043cb5`
- Started (Europe/Berlin): `2026-07-15T13:54:34.168388+02:00`
- Ended (Europe/Berlin): `2026-07-15T13:55:12.739054+02:00`
- Elapsed seconds: `38.570666`
- Command: `o1-crypto-lab bounded-memory-tournament --config '/Users/bhkmie/Documents/Krypto karm/Kryptkram codex/o1-cryptanalytic-memory-lab/configs/bounded_memory_tournament_v1.json'`

## Hypothesis

Distributed multi-target spectral support and a dense low-precision O1 Bit-Vault will preserve the verified Direct12 ordering more efficiently and more transferably than sparse modes selected from one calibration field.

## Prediction

At matched declared state, A272-distributed 16-slot masks will beat low-degree and candidate-ID controls on target-blind A349 field fidelity, while a 4-bit dense multi-slot Bit-Vault with frozen A348 scales will exceed 0.98 A349 rank-Spearman without retaining candidate rows or a KV table.

## Controls

- all mask and scale policies are frozen from A272 TRAIN and/or A348 CALIBRATION fields before the A349 score file is opened
- O1-O receives A348 target-blind field fidelity and declared state/work only; it receives neither A348 rank labels nor any A349 metric
- the O1-O selection-source hash is built only from A272, the reader, A348 and mechanism/gate configs; whole-capsule manifests containing A349 are provenance-only and cannot affect selection
- future-template and complete-order persistence require hash-bound callback receipts; in-memory freezing alone cannot pass the evidence gate
- every A349 order is persisted before the separate A348 truth registry is opened
- low-degree, deterministic candidate-ID random, full-float ceiling and direct quantized dictionary ceiling controls are reported
- the dictionary ceiling is explicitly invalid as an O1 mechanism and can never win the mechanism gate
- online recurrent state, integrity state, static plan storage, offline policy learning, evaluator-only reference workspace, controls and query work are reported separately
- no KV cache, no full O(T) attention, no retained candidate rows and no mutable sibling path
- A349 target, outcome and progress remain unread

## Budgets

```json
{
  "A349_target_labels": 0,
  "a272_training_fields": 20,
  "a348_calibration_cells": 4096,
  "a349_target_blind_development_cells": 4096,
  "gpu_seconds": 0,
  "new_solver_calls": 0
}
```

## Pinned source hashes

- `module_artifacts`: `dabb5588f67f9e89af93996cbcc646601e336e9db18e29804ad0bfeddbf913d9`
- `module_cli`: `6d2ed2e3dbea819c3f1c842faabe63eba7fa728edc52c5924716dd06a8e330c2`
- `module_direct12`: `e83138ec93d45bcf32307ea4d930ed92838e3d27cbb0765667b237d681630e21`
- `module_isolation`: `50399219de30c9f9e3ed23ee1d5b4c434d8736107316a7647276aa481900b652`
- `module_multislot_spectral`: `1191370ae67eee87d5fe300331eee257d48359ef0011cc106d83d48ccbc9c0e6`
- `module_o1o_selector`: `d648fbfdf41ab6392a4859082c9d3d33492c9ee7f765ae6d98d99e3ca2341e46`
- `module_orchestrator`: `3351034b5a7fdc59a972834e62e5b469b0e04d7464594a4c954f38c95044b114`
- `module_quantized_spectral`: `d2678e7efbdd9a49bc13c535478ac927533fa2dea87f2dba26aa408940a4df0a`
- `module_run_capsule`: `96e708011399e3ec73e54c0f32a360308b15475d5498fe4f69600ad2f3adeb76`
- `module_shape532`: `f41e657ea8414e94431ad431a31248202d322e4a762e9d42bf28d95d3f406aaf`
- `module_spectral_experiment`: `c1f6eb54623d2977f7f8b01decea28cec6634aa44b5fe45828d0cc68e15d4f40`
- `module_stage3`: `9c8abd64b687c623b8943055c152a87cc050ca1264f4563b40f33d9970c27da2`
- `module_types`: `91e3e8116b40fec516b6467dd4e22ae7a4aed9e4343f0dcce80be8b9da6d6693`
- `module_walsh_memory`: `0e959d021ad7e3f965142e40c57390d9d949badaecb59fd5486d00552a7922ce`
- `o1c_0003_capsule_manifest`: `d7dcb2b2c3f39d866c7820dbc7423ce55b4d5c9df6634d5a00126a954a0a065d`
- `o1c_0004_capsule_manifest`: `ac3333606e0aaf47dc519553c0e9407fc8ab67dba5319ed340eac579cb25c7bf`
- `tournament_config`: `85e4bf1aa02ac3110a599aef05827d2effc9811b392e46657855f5d203dce693`

## Metrics

```json
{
  "comparisons": {
    "a272_multislot_k2048_A349_rank_spearman": 0.8714770053858202,
    "best_candidate_id_random_k2048_A349_rank_spearman": 0.716922760017269,
    "candidate_id_random_k2048_A349_rank_spearman": {
      "global-candidate-id-random-k2048-s17-control": 0.716922760017269,
      "global-candidate-id-random-k2048-s29-control": 0.6994258829050293,
      "global-candidate-id-random-k2048-s5-control": 0.6841785920899639
    },
    "distributed_minus_best_candidate_id_random": 0.15455424536855122,
    "distributed_minus_low_degree": 0.37722071640158616,
    "global_a348_sparse_k2048_A349_rank_spearman": 0.7972250916854533,
    "global_low_degree_k2048_A349_rank_spearman": 0.494256288984234,
    "quantized_4bit_h1_25_A349_rank_spearman": 0.9901983485302834,
    "quantized_4bit_h1_25_A349_top32_overlap": 0.71875,
    "quantized_4bit_minus_sparse_a348_energy": 0.19297325684483013
  },
  "costs": {
    "A272_truth_labels_read": 0,
    "A348_truth_labels_read": 1,
    "A349_target_labels_read": 0,
    "calibration_arms": 72,
    "complete_A349_orders_frozen": 86,
    "declared_update_accumulations_calibration_plus_deployment": 311689216,
    "deployment_arms": 72,
    "dictionary_controls": 14,
    "gpu_seconds": 0,
    "new_solver_calls": 0,
    "offline_policy_learning": {
      "A272_reader_feature_values_materialized": 2723840,
      "A272_reader_truth_labels_used": 0,
      "global_4096_point_FWHT_butterflies": 221184,
      "global_A348_energy_policy_fits": 9,
      "multislot_256_point_source_FWHTs": 720,
      "multislot_learned_budgets": 10,
      "multislot_policy_FWHT_butterflies": 737280,
      "quantized_scale_calibration_field_scans": 14,
      "quantized_scale_calibration_values_examined": 57344
    },
    "phase_seconds": {
      "calibration_tournament_seconds": 20.462952666915953,
      "deployment_tournament_seconds": 17.587701624725014,
      "o1o_selection_seconds": 0.003370082937180996,
      "post_freeze_a348_audit_seconds": 0.02870750008150935,
      "source_verification_seconds": 0.43822833290323615,
      "total_seconds": 38.52129062497988
    },
    "reconstruction_and_evaluation": {
      "FWHT_butterflies_calibration_plus_deployment": 2801664,
      "dictionary_control_quantizations": 57344,
      "dictionary_control_retained_candidate_entries": 57344,
      "evaluator_workspace_counted_as_online_state": false,
      "logical_peak_evaluator_workspace_bytes_lower_bound": 114688,
      "ranking_items_calibration_deployment_and_dictionary": 647168,
      "workspace_components": "reference, approximation and error float64 fields plus two uint16 rankings; Python object heap and top-k sets not measured"
    },
    "selected_template_static_storage": {
      "calibration_scores_retained": 0,
      "online_state_bytes": 6668,
      "slot_scale_bytes": 128,
      "slot_scale_values": 16
    }
  },
  "labels": {
    "A272_truth_labels_read": 0,
    "A348_truth_labels_read": 1,
    "A349_target_labels_read": 0
  },
  "schema": "o1-crypto-bounded-memory-tournament-metrics-v1",
  "selected_arm": {
    "calibration_clip_count": 0,
    "family": "o1-multislot-quantized-walsh-bit-vault",
    "labels": [
      "CONTROL"
    ],
    "memory_plan_sha256": "69c5882e3807123dfdcf9eaca6846700377e9f95c84e7136ccec2b162bd9355c",
    "name": "quantized-bit-vault-4bit-h1.25",
    "rank_kendall": 0.9120328239468865,
    "rank_spearman": 0.9904664475609107,
    "serialized_online_state_bytes": 6668,
    "split": "VALIDATION",
    "top_k_overlap": [
      {
        "fraction": 1.0,
        "k": 1
      },
      {
        "fraction": 0.75,
        "k": 8
      },
      {
        "fraction": 0.75,
        "k": 32
      },
      {
        "fraction": 0.796875,
        "k": 128
      },
      {
        "fraction": 0.904296875,
        "k": 512
      }
    ],
    "work_units": 1044480
  },
  "selection_sha256": "5aaf243457850fbc1435cad8ff257da4eaf6a9b3ec983042f46dde690c1a5983",
  "success_gate_passed": true,
  "success_gates": {
    "A349_target_labels_zero": true,
    "all_A349_orders_persisted_before_A348_truth": true,
    "dense_low_precision_beats_sparse_calibration_support": true,
    "dictionary_controls_disqualified": true,
    "distributed_support_beats_all_candidate_id_random_at_k2048": true,
    "distributed_support_beats_low_degree_at_k2048": true,
    "future_template_persisted_before_A349_field_open": true,
    "immutable_sources_verified": true,
    "o1o_selected_eligible_mechanism": true,
    "o1o_selected_within_state_gate": true,
    "quantized_4bit_A349_spearman_above_0_98": true,
    "selected_deployment_has_no_candidate_rows": true
  }
}
```

## Next highest-ROI action

Carry the O1-O-frozen plan template to a new lab-owned Direct12 field that has never been used for architecture development, freeze its order, and only then run exact equal-work recovery and independent cipher confirmation.
