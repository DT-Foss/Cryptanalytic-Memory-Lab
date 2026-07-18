"""O1C-0036 direct eight-block O1-to-A526 BUILD experiment."""

from __future__ import annotations

import hashlib
import json
import math
import os
import resource
import tempfile
import time
from datetime import datetime
from pathlib import Path

import numpy as np

from .a448_knownkey_corpus import default_sibling_root, load_a448_knownkey_corpus
from .a526_completion_frontier import evaluate_a526_complement_topk
from .a526_eight_block_o1 import (
    A526EightBlockExample,
    A526EightBlockTrainingConfig,
    generate_uniform_eight_block_examples,
    train_a526_eight_block_reader,
)
from .living_inverse import key_bits


ATTEMPT_ID = "O1C-0036"
FRONTIER_LIMIT = 65_536
RESULT_RELATIVE = Path(
    "research/O1C0036_EIGHT_BLOCK_A526_READER_RESULT_20260718.json"
)
RESULT_SCHEMA = "o1-256-eight-block-a526-reader-result-v1"


class O1C36RunError(RuntimeError):
    """The direct O1-to-A526 run or result publication differs."""


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _peak_rss_bytes() -> int:
    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return value if value > 16 * 1024 * 1024 else value * 1024


def _loss_bits(logits: np.ndarray, labels: np.ndarray) -> np.ndarray:
    values = np.asarray(logits, dtype=np.float64)
    truth = np.asarray(labels, dtype=np.float64)
    if values.shape != truth.shape or values.ndim != 2:
        raise O1C36RunError("logit and label matrices differ")
    natural = np.logaddexp(0.0, values) - truth * values
    return natural.sum(axis=1) / math.log(2.0)


def _atomic_json(path: Path, value: object) -> None:
    payload = (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def run() -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    sibling = default_sibling_root().resolve(strict=True)
    config = A526EightBlockTrainingConfig(
        training_targets=1024,
        epochs=6,
        batch_size=16,
        learning_rate=2e-3,
        weight_decay=1e-4,
        cpu_threads=2,
        corpus_seed=526036,
        model_seed=526204,
        model_dimension=32,
        heads=4,
        head_dimension=8,
        holographic_slots=4,
        feedforward_dimension=64,
    )
    source_paths = {
        "reader": root / "src/o1_crypto_lab/a526_eight_block_o1.py",
        "corpus_adapter": root / "src/o1_crypto_lab/a448_knownkey_corpus.py",
        "frontier": root / "src/o1_crypto_lab/a526_completion_frontier.py",
        "runner": root / "src/o1_crypto_lab/o1c36_eight_block_a526_run.py",
    }
    source_hashes = {name: _sha256_file(path) for name, path in source_paths.items()}
    started = time.perf_counter()
    cpu_started = time.process_time()

    training = generate_uniform_eight_block_examples(
        count=config.training_targets, seed=config.corpus_seed
    )
    trained = train_a526_eight_block_reader(training, config)
    sibling_targets = load_a448_knownkey_corpus(sibling)
    evaluation = tuple(
        A526EightBlockExample(
            public=target.public,
            teacher_key=target.teacher_key,
            example_id=f"{target.source}-{target.source_index:03d}",
        )
        for target in sibling_targets
    )
    training_keys = {example.teacher_key for example in training}
    if any(example.teacher_key in training_keys for example in evaluation):
        raise O1C36RunError("synthetic training and sibling evaluation keys overlap")
    fixed_logits = trained.predict_fixed_logits(
        [example.public for example in evaluation], batch_size=16
    )
    full_logits = np.zeros((len(evaluation), 256), dtype=np.float64)
    full_logits[:, 52:] = fixed_logits
    labels = np.stack(
        [key_bits(example.teacher_key)[52:] for example in evaluation]
    ).astype(np.float64)
    predicted = fixed_logits >= 0.0
    correct_by_target = np.equal(predicted, labels).sum(axis=1)
    correct_by_coordinate = np.equal(predicted, labels).mean(axis=0)
    loss_bits = _loss_bits(fixed_logits, labels)
    compression_bits = 204.0 - loss_bits

    frontier_rows = []
    for example, logits in zip(evaluation, full_logits, strict=True):
        frontier_rows.append(
            evaluate_a526_complement_topk(
                logits,
                truth_key=example.teacher_key,
                limit=FRONTIER_LIMIT,
            )
        )
    best_beam = np.asarray(
        [row["best_beam_correct_fixed_bits"] for row in frontier_rows],
        dtype=np.int64,
    )
    exact_ranks = [
        row["exact_complement_rank_one_based"]
        for row in frontier_rows
        if row["exact_complement_in_beam"]
    ]
    elapsed = time.perf_counter() - started
    cpu_seconds = time.process_time() - cpu_started
    total_bits = int(labels.size)
    total_correct = int(correct_by_target.sum())
    result: dict[str, object] = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "target_contract": {
            "cipher": "ChaCha20",
            "rounds": 20,
            "unknown_key_bits_at_deployment": 256,
            "public_input": "counter_nonce_eight_output_blocks_only",
            "sibling_known_210_bits_removed_from_model_input": True,
            "training_labels_deployment_visible": False,
        },
        "architecture": {
            "state": "existing_selective_holographic_O1_core",
            "public_word_tokens": 132,
            "queried_coordinates": [52, 255],
            "fast_state_bytes_batch1": config.core_config.fast_state_bytes(),
            "model_parameters": trained.parameter_count,
            "model_sha256": trained.model_sha256,
            "frontier": "exact_factorized_topK_over_A526_fixed_complement",
            "frontier_limit": FRONTIER_LIMIT,
            "residual_backend": "unchanged_A526_W52",
            "backend_launched": False,
        },
        "data": {
            "synthetic_uniform_training_targets": len(training),
            "sibling_read_only_evaluation_targets": len(evaluation),
            "evaluation_blocks": 8,
            "evaluation_targets_per_block": 16,
            "training_evaluation_key_overlap": 0,
            "sibling_writes": 0,
        },
        "training": {
            "config": config.describe(),
            "epoch_losses": list(trained.epoch_losses),
        },
        "metrics": {
            "fixed_bit_random_baseline": 102.0,
            "map_correct_fixed_bits_mean": float(correct_by_target.mean()),
            "map_correct_fixed_bits_min": int(correct_by_target.min()),
            "map_correct_fixed_bits_max": int(correct_by_target.max()),
            "aggregate_fixed_bit_accuracy": total_correct / total_bits,
            "aggregate_fixed_bits_correct": total_correct,
            "aggregate_fixed_bits_scored": total_bits,
            "heldout_loss_bits_mean": float(loss_bits.mean()),
            "heldout_compression_bits_mean": float(compression_bits.mean()),
            "heldout_compression_bits_min": float(compression_bits.min()),
            "heldout_compression_bits_max": float(compression_bits.max()),
            "coordinate_accuracy_min": float(correct_by_coordinate.min()),
            "coordinate_accuracy_max": float(correct_by_coordinate.max()),
            "coordinates_at_least_0_60_accuracy_posthoc": int(
                np.count_nonzero(correct_by_coordinate >= 0.60)
            ),
            "best_top65536_correct_fixed_bits_mean": float(best_beam.mean()),
            "best_top65536_correct_fixed_bits_min": int(best_beam.min()),
            "best_top65536_correct_fixed_bits_max": int(best_beam.max()),
            "exact_complements_in_top65536": len(exact_ranks),
            "exact_complement_ranks": exact_ranks,
            "minimum_induced_work_log2_when_absent": 52.0
            + math.log2(FRONTIER_LIMIT + 1),
        },
        "resources": {
            "elapsed_seconds": elapsed,
            "cpu_seconds": cpu_seconds,
            "peak_rss_bytes": _peak_rss_bytes(),
            "device": "CPU",
            "MPS_or_GPU": False,
        },
        "source_sha256": source_hashes,
    }
    compression = float(compression_bits.mean())
    exact = len(exact_ranks)
    if exact:
        decision = "POSITIVE_EXACT_COMPLEMENT_IN_BEAM_REPEAT_UNCHANGED"
    elif compression > 0.0:
        decision = "CANDIDATE_SUB256_EFFECT_REQUIRES_UNCHANGED_REPEAT"
    else:
        decision = "CLOSE_DIRECT_RAW_EIGHT_BLOCK_OUTPUT_READER"
    result["decision"] = decision
    result["next_action"] = (
        "Repeat this exact model once on a disjoint consumed panel before any fresh target."
        if compression > 0.0 or exact
        else "Keep the A526 bridge, close raw output-only O1, and move to the minimal joint relational decoder using attacker-computable ChaCha constraints."
    )
    _atomic_json(root / RESULT_RELATIVE, result)
    return result


def main() -> int:
    result = run()
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
