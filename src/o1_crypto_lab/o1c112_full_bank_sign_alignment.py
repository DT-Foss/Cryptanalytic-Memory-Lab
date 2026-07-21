"""Frozen retrospective sign alignment over the complete O1 living bank.

O1C-0112 authenticates the sealed O1C-0109 result and capsule, decodes its
final 256-coordinate sufficient-statistic bank together with the O1C-0108
prior bank, and freezes one primary plus six diagnostic readers.  Historical
truth is unavailable to preparation and is read exactly once, through the
sealed O1C-0057 broker reveal, only by finalization.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import stat
import struct
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import cast

from . import o1c109_apple8_parent_centered_continuation_run as _o1c109
from .full256_broker import verify_reveal
from .living_inverse import KEY_BITS, canonical_json_bytes, key_bits


ATTEMPT_ID = "O1C-0112"
CONFIG_SCHEMA = "o1-256-o1c112-full-bank-sign-alignment-config-v1"
SCORE_FREEZE_SCHEMA = "o1-256-o1c112-full-bank-sign-score-freeze-v1"
SCORE_FREEZE_ENVELOPE_SCHEMA = (
    "o1-256-o1c112-full-bank-sign-score-freeze-envelope-v1"
)
RESULT_SCHEMA = "o1-256-o1c112-full-bank-sign-alignment-result-v1"
DEFAULT_CONFIG_RELATIVE = Path("configs/o1c112_full_bank_sign_alignment_v1.json")

DESIGN_RELATIVE = Path(
    "research/O1C0112_FULL_BANK_SIGN_ALIGNMENT_DESIGN_20260721.md"
)
DESIGN_BYTES = 5_413
DESIGN_SHA256 = "5a5e2a9923d3620381a988fa66246c82f0a95c6e33adb73b95c7fe0883a314a7"
DESIGN_COMMIT = "02d04e3"

PARENT_CAPSULE_RELATIVE = Path(
    "runs/20260721_103413_313078_O1C-0109_apple8-parent-centered-continuation-v1"
)
PARENT_MANIFEST_RELATIVE = PARENT_CAPSULE_RELATIVE / "artifacts.sha256"
PARENT_MANIFEST_BYTES = 5_726
PARENT_MANIFEST_SHA256 = (
    "050a073b24fb2866b87e8353c1c8357c6598fa2eb9cf54119ee2991d7a99f2d0"
)
PARENT_RESULT_RELATIVE = PARENT_CAPSULE_RELATIVE / "result.json"
AUTHORITATIVE_RESULT_RELATIVE = Path(
    "research/O1C0109_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260721.json"
)
PARENT_RESULT_BYTES = 17_638
PARENT_RESULT_SHA256 = (
    "22ec1c6a2f67c0ec89c85347865c4fc248c43ad2dacc8955fd76a72940a52c28"
)
PARENT_CLASSIFICATION = "PARENT_CENTERED_CONTINUATION_NOVEL_CLAUSE_GAIN"

FINAL_BANK_RELATIVE = (
    PARENT_CAPSULE_RELATIVE
    / "episodes/00/final-parent-centered-priority-bank.bin"
)
PRIOR_BANK_RELATIVE = Path(
    "research/o1c108_page22_type_safe_causal_rollover_seed_20260721/"
    "final-parent-centered-priority-bank.bin"
)
PARENT_INITIAL_BANK_RELATIVE = (
    PARENT_CAPSULE_RELATIVE / "initial/final-parent-centered-priority-bank.bin"
)
FINAL_BANK_SHA256 = "efffdc2021d3c62bd92e4557a8515f1728bd3350582010b0b4a90a0d2fc65951"
PRIOR_BANK_SHA256 = "62360d82b191b2e323c7205d950651ac1ad592cc9365892bf5c58d932b64087f"

HISTORICAL_REVEAL_RELATIVE = Path(
    "runs/20260719_062932_O1C-0057_multiblock-parent-criticality-rank-v1/"
    "reveal.json"
)
HISTORICAL_REVEAL_BYTES = 2_714
HISTORICAL_REVEAL_FILE_SHA256 = (
    "63706f65c9e355711621e2188494514d1c201306d2b6a5c6928833aedfd77efd"
)
HISTORICAL_REVEAL_INNER_SHA256 = (
    "e935acf5284f7d7f5997e022de5959458e814456ad884217bb98e7ca0c1c480f"
)

COORDINATE_COUNT = 256
MISSING_VARIABLE = 241
RECORD_FORMAT = "<QddQQddQQddd"
RECORD_STRUCT = struct.Struct(RECORD_FORMAT)
RECORD_BYTES = 96
BANK_BYTES = COORDINATE_COUNT * RECORD_BYTES

PRIMARY_ARM = "negative_final_robust_z_mean"
SECONDARY_ARMS = (
    "negative_final_centered_mean",
    "negative_final_centered_signed_consistency",
    "negative_final_raw_mean",
    "negative_increment_robust_z_mean",
    "negative_increment_centered_mean",
    "negative_increment_raw_mean",
)
ARM_FORMULAS = {
    PRIMARY_ARM: "S_v=-final.robust_z_mean",
    SECONDARY_ARMS[0]: "S_v=-final.centered_mean",
    SECONDARY_ARMS[1]: (
        "S_v=-(final.centered_positive_count-final.centered_negative_count)"
        "/final.count"
    ),
    SECONDARY_ARMS[2]: "S_v=-final.raw_mean",
    SECONDARY_ARMS[3]: (
        "S_v=-fsum([N_final*final.robust_z_mean,"
        "-N_prior*prior.robust_z_mean])/(N_final-N_prior)"
    ),
    SECONDARY_ARMS[4]: (
        "S_v=-fsum([N_final*final.centered_mean,"
        "-N_prior*prior.centered_mean])/(N_final-N_prior)"
    ),
    SECONDARY_ARMS[5]: (
        "S_v=-fsum([N_final*final.raw_mean,"
        "-N_prior*prior.raw_mean])/(N_final-N_prior)"
    ),
}
CONTROL_DOMAIN = "o1c112-cyclic-truth-coordinate-rotation-v1"
RESULT_IDENTITY_RULE = "sha256(canonical-json(result-without-result_sha256))"

STRONG_CLASSIFICATION = "RETROSPECTIVE_FULL_BANK_DIRECTIONAL_SIGNAL"
BREADCRUMB_CLASSIFICATION = "RETROSPECTIVE_FULL_BANK_BIT_ADVANTAGE_BREADCRUMB"
NULL_CLASSIFICATION = "RETROSPECTIVE_FULL_BANK_NO_DIRECTIONAL_ALIGNMENT"

EXPECTED_CENSUS: dict[str, object] = {
    "final": {
        "serialized_bytes": BANK_BYTES,
        "sha256": FINAL_BANK_SHA256,
        "count_sum": 449_663,
        "nonzero_coordinate_count": 255,
        "minimum_nonzero_count": 240,
        "maximum_count": 4_006,
        "zero_variables": [MISSING_VARIABLE],
        "raw_mean_signs": {"positive": 245, "negative": 10, "zero": 0},
        "centered_mean_signs": {"positive": 112, "negative": 143, "zero": 0},
        "robust_z_mean_signs": {"positive": 113, "negative": 142, "zero": 0},
        "centered_signed_consistency_signs": {
            "positive": 120,
            "negative": 135,
            "zero": 0,
        },
    },
    "prior": {
        "serialized_bytes": BANK_BYTES,
        "sha256": PRIOR_BANK_SHA256,
        "count_sum": 416_094,
        "nonzero_coordinate_count": 255,
        "minimum_nonzero_count": 238,
        "maximum_count": 3_688,
        "zero_variables": [MISSING_VARIABLE],
        "raw_mean_signs": {"positive": 245, "negative": 10, "zero": 0},
        "centered_mean_signs": {"positive": 110, "negative": 145, "zero": 0},
        "robust_z_mean_signs": {"positive": 112, "negative": 143, "zero": 0},
        "centered_signed_consistency_signs": {
            "positive": 121,
            "negative": 134,
            "zero": 0,
        },
    },
    "increment": {
        "count_sum": 33_569,
        "nonzero_coordinate_count": 255,
        "minimum_nonzero_count": 1,
        "maximum_count": 534,
        "zero_variables": [MISSING_VARIABLE],
        "all_coordinate_counts_monotone": True,
    },
    "arm_predictions": {
        PRIMARY_ARM: {"bit_1": 142, "bit_0": 113, "abstain": 1},
        SECONDARY_ARMS[0]: {"bit_1": 143, "bit_0": 112, "abstain": 1},
        SECONDARY_ARMS[1]: {"bit_1": 135, "bit_0": 120, "abstain": 1},
        SECONDARY_ARMS[2]: {"bit_1": 10, "bit_0": 245, "abstain": 1},
        SECONDARY_ARMS[3]: {"bit_1": 144, "bit_0": 111, "abstain": 1},
        SECONDARY_ARMS[4]: {"bit_1": 145, "bit_0": 110, "abstain": 1},
        SECONDARY_ARMS[5]: {"bit_1": 30, "bit_0": 225, "abstain": 1},
    },
}


class O1C112FullBankSignAlignmentError(ValueError):
    """A frozen input, bank invariant, truth gate, or result differs."""


@dataclass(frozen=True)
class BankRecord:
    """One variable-bound 96-byte sufficient-statistic record."""

    variable: int
    count: int
    raw_mean: float
    raw_m2: float
    raw_positive_count: int
    raw_zero_count: int
    centered_mean: float
    centered_m2: float
    centered_positive_count: int
    centered_zero_count: int
    robust_z_mean: float
    robust_abs_z_mean: float
    robust_abs_z_max: float


@dataclass(frozen=True)
class HistoricalTruth:
    """One broker-verified historical key, available only after score freeze."""

    key: bytes
    source_file_sha256: str
    reveal_sha256: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.key, bytes)
            or len(self.key) != 32
            or not _is_sha256(self.source_file_sha256)
            or not _is_sha256(self.reveal_sha256)
        ):
            raise O1C112FullBankSignAlignmentError(
                "historical truth evidence differs"
            )


@dataclass(frozen=True)
class PreparedFullBankAnalysis:
    """Authenticated truth-free score state and the later reveal commitment."""

    root: Path
    config: Mapping[str, object]
    config_sha256: str
    score_freeze: Mapping[str, object]
    score_freeze_bytes: bytes
    score_freeze_sha256: str
    reveal_path: Path
    reveal_serialized_bytes: int
    reveal_file_sha256: str


TruthReader = Callable[[Path, int, str, str], HistoricalTruth]


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise O1C112FullBankSignAlignmentError(f"{label} is not an object")
    return cast(Mapping[str, object], value)


def _sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise O1C112FullBankSignAlignmentError(f"{label} is not an array")
    return value


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise O1C112FullBankSignAlignmentError(f"{label} is not an integer")
    return value


def _number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise O1C112FullBankSignAlignmentError(f"{label} is not numeric")
    result = float(value)
    if not math.isfinite(result):
        raise O1C112FullBankSignAlignmentError(f"{label} is not finite")
    return result


def _validate_sha(value: object, label: str) -> str:
    if not _is_sha256(value):
        raise O1C112FullBankSignAlignmentError(f"{label} SHA-256 differs")
    return cast(str, value)


def _regular_file(path: Path, label: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise O1C112FullBankSignAlignmentError(f"{label} is absent") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise O1C112FullBankSignAlignmentError(
            f"{label} is not a sealed regular file"
        )
    return path


def _relative_file(root: Path, value: object, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise O1C112FullBankSignAlignmentError(f"{label} path differs")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise O1C112FullBankSignAlignmentError(f"{label} escapes the lab")
    path = _regular_file(root / relative, label).resolve(strict=True)
    if not path.is_relative_to(root):
        raise O1C112FullBankSignAlignmentError(f"{label} escapes the lab")
    return path


def _future_relative_file(root: Path, value: object, label: str) -> Path:
    """Resolve a committed later path without touching its truth-bearing file."""

    if not isinstance(value, str) or not value:
        raise O1C112FullBankSignAlignmentError(f"{label} path differs")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise O1C112FullBankSignAlignmentError(f"{label} escapes the lab")
    return root / relative


def _read_canonical_json(path: Path, label: str) -> tuple[dict[str, object], bytes]:
    payload = _regular_file(path, label).read_bytes()
    try:
        raw = json.loads(payload.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C112FullBankSignAlignmentError(f"{label} JSON differs") from exc
    document = dict(_mapping(raw, label))
    if canonical_json_bytes(document) != payload:
        raise O1C112FullBankSignAlignmentError(f"{label} is not canonical JSON")
    return document, payload


def _sealed_payload(
    root: Path,
    row: Mapping[str, object],
    label: str,
    *,
    expected_keys: set[str] = {"path", "serialized_bytes", "sha256"},
) -> tuple[Path, bytes]:
    if set(row) != expected_keys:
        raise O1C112FullBankSignAlignmentError(f"{label} seal fields differ")
    path = _relative_file(root, row.get("path"), label)
    payload = path.read_bytes()
    expected_bytes = _integer(row.get("serialized_bytes"), f"{label} bytes")
    expected_sha = _validate_sha(row.get("sha256"), label)
    if len(payload) != expected_bytes or _sha256(payload) != expected_sha:
        raise O1C112FullBankSignAlignmentError(f"{label} seal differs")
    return path, payload


def _sealed_row(path: Path, serialized_bytes: int, sha256: str) -> dict[str, object]:
    return {
        "path": path.as_posix(),
        "serialized_bytes": serialized_bytes,
        "sha256": sha256,
    }


def _frozen_reader_contract() -> dict[str, object]:
    return {
        "abi": RECORD_FORMAT,
        "abstention_rule": "record.count == 0 or S_v == 0.0",
        "coordinate_count": COORDINATE_COUNT,
        "missing_variable": MISSING_VARIABLE,
        "prediction_rule": "bit1-if-S_v-positive;bit0-if-S_v-negative",
        "primary_arm": PRIMARY_ARM,
        "primary_formula": ARM_FORMULAS[PRIMARY_ARM],
        "secondary_arms": [
            {"arm": arm, "formula": ARM_FORMULAS[arm]} for arm in SECONDARY_ARMS
        ],
        "secondary_cannot_change_primary": True,
        "record_bytes": RECORD_BYTES,
        "bank_bytes": BANK_BYTES,
        "increment_formula": (
            "math.fsum([N_final*mean_final,-N_prior*mean_prior])"
            "/(N_final-N_prior)"
        ),
    }


def _frozen_controls_contract() -> dict[str, object]:
    return {
        "conservative_ties": True,
        "cyclic_offset_count": KEY_BITS,
        "domain": CONTROL_DOMAIN,
        "global_sign_flip": True,
        "identity_offset": 0,
        "rotation_formula": "truth_spin[(coordinate_index+offset)%256]",
        "bit_order": "RFC-little-bit-within-byte",
        "fully_predicted_byte_count": 31,
        "excluded_byte_indices": [30],
        "fully_predicted_word16_count": 15,
        "excluded_word16_indices": [15],
    }


def _frozen_gates_contract() -> dict[str, object]:
    return {
        "strong": {
            "classification": STRONG_CLASSIFICATION,
            "minimum_evaluated_coordinates": 240,
            "maximum_binomial_tail": {"numerator": 1, "denominator": 100},
            "maximum_cyclic_rank_fraction": {"numerator": 1, "denominator": 20},
            "require_positive_identity_over_sign_flip_margin": True,
        },
        "breadcrumb": {
            "classification": BREADCRUMB_CLASSIFICATION,
            "minimum_evaluated_coordinates": 240,
            "maximum_binomial_tail": {"numerator": 1, "denominator": 20},
            "require_positive_identity_over_sign_flip_margin": True,
            "requires_strong_gate_failure": True,
        },
        "otherwise_classification": NULL_CLASSIFICATION,
    }


def _frozen_budgets_contract() -> dict[str, object]:
    return {
        "maximum_fresh_reveal_calls": 0,
        "maximum_fresh_targets": 0,
        "maximum_gpu_calls": 0,
        "maximum_historical_reveal_file_reads": 1,
        "maximum_mps_calls": 0,
        "maximum_native_solver_calls": 0,
        "maximum_refits": 0,
        "maximum_science_solver_calls": 0,
        "maximum_target_generation_calls": 0,
    }


def _validate_frozen_contract(config: Mapping[str, object]) -> None:
    expected_top = {
        "schema",
        "attempt_id",
        "claim_level",
        "design",
        "parent",
        "inputs",
        "source",
        "expected_census",
        "reader",
        "controls",
        "gates",
        "budgets",
        "next_action",
    }
    if (
        set(config) != expected_top
        or config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or config.get("claim_level") != "RETROSPECTIVE_FULL_BANK_DIAGNOSTIC"
        or config.get("next_action")
        != "Replicate the unchanged frozen primary reader on fresh output-only targets; never continue the historical target from this diagnostic."
    ):
        raise O1C112FullBankSignAlignmentError("frozen config header differs")

    if _mapping(config.get("design"), "design") != {
        "path": DESIGN_RELATIVE.as_posix(),
        "serialized_bytes": DESIGN_BYTES,
        "sha256": DESIGN_SHA256,
        "git_commit": DESIGN_COMMIT,
    }:
        raise O1C112FullBankSignAlignmentError("frozen design differs")

    if _mapping(config.get("parent"), "parent") != {
        "capsule": PARENT_CAPSULE_RELATIVE.as_posix(),
        "capsule_manifest": _sealed_row(
            PARENT_MANIFEST_RELATIVE,
            PARENT_MANIFEST_BYTES,
            PARENT_MANIFEST_SHA256,
        ),
        "capsule_result": _sealed_row(
            PARENT_RESULT_RELATIVE, PARENT_RESULT_BYTES, PARENT_RESULT_SHA256
        ),
        "authoritative_result": _sealed_row(
            AUTHORITATIVE_RESULT_RELATIVE,
            PARENT_RESULT_BYTES,
            PARENT_RESULT_SHA256,
        ),
        "classification": PARENT_CLASSIFICATION,
    }:
        raise O1C112FullBankSignAlignmentError("frozen parent differs")

    if _mapping(config.get("inputs"), "inputs") != {
        "final_bank": _sealed_row(FINAL_BANK_RELATIVE, BANK_BYTES, FINAL_BANK_SHA256),
        "prior_bank": _sealed_row(PRIOR_BANK_RELATIVE, BANK_BYTES, PRIOR_BANK_SHA256),
        "historical_reveal": _sealed_row(
            HISTORICAL_REVEAL_RELATIVE,
            HISTORICAL_REVEAL_BYTES,
            HISTORICAL_REVEAL_FILE_SHA256,
        ),
    }:
        raise O1C112FullBankSignAlignmentError("frozen inputs differ")
    if config.get("expected_census") != EXPECTED_CENSUS:
        raise O1C112FullBankSignAlignmentError("frozen census differs")
    if config.get("reader") != _frozen_reader_contract():
        raise O1C112FullBankSignAlignmentError("frozen reader differs")
    if config.get("controls") != _frozen_controls_contract():
        raise O1C112FullBankSignAlignmentError("frozen controls differ")
    if config.get("gates") != _frozen_gates_contract():
        raise O1C112FullBankSignAlignmentError("frozen gates differ")
    if config.get("budgets") != _frozen_budgets_contract():
        raise O1C112FullBankSignAlignmentError("frozen budgets differ")

    source = _mapping(config.get("source"), "source")
    if set(source) != {"module", "tests"}:
        raise O1C112FullBankSignAlignmentError("source seal fields differ")
    expected_paths = {
        "module": "src/o1_crypto_lab/o1c112_full_bank_sign_alignment.py",
        "tests": "tests/test_o1c112_full_bank_sign_alignment.py",
    }
    for name, expected_path in expected_paths.items():
        row = _mapping(source.get(name), f"source {name}")
        if (
            set(row) != {"path", "serialized_bytes", "sha256"}
            or row.get("path") != expected_path
            or _integer(row.get("serialized_bytes"), f"source {name} bytes") <= 0
        ):
            raise O1C112FullBankSignAlignmentError(f"source {name} differs")
        _validate_sha(row.get("sha256"), f"source {name}")


def load_config(
    path: str | Path = DEFAULT_CONFIG_RELATIVE,
    *,
    root: Path | None = None,
) -> tuple[dict[str, object], str]:
    """Load canonical configuration and authenticate design/source seals."""

    base = (root or lab_root()).resolve(strict=True)
    config_path = Path(path)
    if not config_path.is_absolute():
        config_path = base / config_path
    config_path = _regular_file(config_path.resolve(strict=True), "O1C112 config")
    if not config_path.is_relative_to(base):
        raise O1C112FullBankSignAlignmentError("config escapes the lab")
    config, payload = _read_canonical_json(config_path, "O1C112 config")
    _validate_frozen_contract(config)
    design = _mapping(config["design"], "design")
    _sealed_payload(
        base, design, "frozen design", expected_keys=set(design)
    )
    source = _mapping(config["source"], "source")
    for name in ("module", "tests"):
        _sealed_payload(
            base, _mapping(source[name], f"source {name}"), f"O1C112 {name}"
        )
    return config, _sha256(payload)


def decode_priority_bank(
    payload: bytes, *, expected_sha256: str
) -> tuple[BankRecord, ...]:
    """Strictly decode the production 256-by-96-byte living-bank ABI."""

    if not isinstance(payload, bytes) or len(payload) != BANK_BYTES:
        raise O1C112FullBankSignAlignmentError("priority bank byte count differs")
    if _sha256(payload) != _validate_sha(expected_sha256, "priority bank expected"):
        raise O1C112FullBankSignAlignmentError("priority bank SHA-256 differs")

    records: list[BankRecord] = []
    for variable in range(1, COORDINATE_COUNT + 1):
        values = RECORD_STRUCT.unpack_from(payload, (variable - 1) * RECORD_BYTES)
        record = BankRecord(variable, *values)
        floats = (
            record.raw_mean,
            record.raw_m2,
            record.centered_mean,
            record.centered_m2,
            record.robust_z_mean,
            record.robust_abs_z_mean,
            record.robust_abs_z_max,
        )
        if any(not math.isfinite(value) for value in floats):
            raise O1C112FullBankSignAlignmentError("priority bank finite record differs")
        if record.raw_m2 < 0.0 or record.centered_m2 < 0.0:
            raise O1C112FullBankSignAlignmentError("priority bank M2 differs")
        if (
            record.raw_positive_count + record.raw_zero_count > record.count
            or record.centered_positive_count + record.centered_zero_count
            > record.count
        ):
            raise O1C112FullBankSignAlignmentError(
                "priority bank sign partition differs"
            )
        if (
            record.robust_abs_z_mean < 0.0
            or record.robust_abs_z_max < 0.0
            or record.robust_abs_z_mean < abs(record.robust_z_mean)
            or record.robust_abs_z_max < record.robust_abs_z_mean
        ):
            raise O1C112FullBankSignAlignmentError(
                "priority bank absolute-z order differs"
            )
        records.append(record)

    zero_variables = [record.variable for record in records if record.count == 0]
    missing = payload[
        (MISSING_VARIABLE - 1) * RECORD_BYTES : MISSING_VARIABLE * RECORD_BYTES
    ]
    if zero_variables != [MISSING_VARIABLE] or missing != bytes(RECORD_BYTES):
        raise O1C112FullBankSignAlignmentError(
            "priority bank zero-coordinate contract differs"
        )
    return tuple(records)


def _sign_census(values: Sequence[float]) -> dict[str, int]:
    return {
        "positive": sum(value > 0.0 for value in values),
        "negative": sum(value < 0.0 for value in values),
        "zero": sum(value == 0.0 for value in values),
    }


def _centered_signed_consistency(record: BankRecord) -> float:
    if record.count == 0:
        return 0.0
    negative = record.count - record.centered_positive_count - record.centered_zero_count
    return (record.centered_positive_count - negative) / record.count


def _bank_census(
    payload: bytes, records: Sequence[BankRecord]
) -> dict[str, object]:
    nonzero = [record for record in records if record.count]
    return {
        "serialized_bytes": len(payload),
        "sha256": _sha256(payload),
        "count_sum": sum(record.count for record in records),
        "nonzero_coordinate_count": len(nonzero),
        "minimum_nonzero_count": min(record.count for record in nonzero),
        "maximum_count": max(record.count for record in records),
        "zero_variables": [record.variable for record in records if not record.count],
        "raw_mean_signs": _sign_census([record.raw_mean for record in nonzero]),
        "centered_mean_signs": _sign_census(
            [record.centered_mean for record in nonzero]
        ),
        "robust_z_mean_signs": _sign_census(
            [record.robust_z_mean for record in nonzero]
        ),
        "centered_signed_consistency_signs": _sign_census(
            [_centered_signed_consistency(record) for record in nonzero]
        ),
    }


def _increment_census(
    prior: Sequence[BankRecord], final: Sequence[BankRecord]
) -> dict[str, object]:
    deltas = [
        new.count - old.count for old, new in zip(prior, final, strict=True)
    ]
    return {
        "count_sum": sum(deltas),
        "nonzero_coordinate_count": sum(delta > 0 for delta in deltas),
        "minimum_nonzero_count": min(delta for delta in deltas if delta),
        "maximum_count": max(deltas),
        "zero_variables": [
            variable for variable, delta in enumerate(deltas, start=1) if delta == 0
        ],
        "all_coordinate_counts_monotone": all(delta >= 0 for delta in deltas),
    }


def _increment_mean(
    prior: BankRecord, final: BankRecord, field: str
) -> float:
    increment_count = final.count - prior.count
    if increment_count == 0:
        return 0.0
    prior_mean = cast(float, getattr(prior, field))
    final_mean = cast(float, getattr(final, field))
    value = math.fsum(
        [final.count * final_mean, -(prior.count * prior_mean)]
    ) / increment_count
    if not math.isfinite(value):
        raise O1C112FullBankSignAlignmentError("increment mean differs")
    return value


def _arm_score(arm: str, prior: BankRecord, final: BankRecord) -> float:
    if arm == PRIMARY_ARM:
        score = -final.robust_z_mean
    elif arm == SECONDARY_ARMS[0]:
        score = -final.centered_mean
    elif arm == SECONDARY_ARMS[1]:
        score = -_centered_signed_consistency(final)
    elif arm == SECONDARY_ARMS[2]:
        score = -final.raw_mean
    elif arm == SECONDARY_ARMS[3]:
        score = -_increment_mean(prior, final, "robust_z_mean")
    elif arm == SECONDARY_ARMS[4]:
        score = -_increment_mean(prior, final, "centered_mean")
    elif arm == SECONDARY_ARMS[5]:
        score = -_increment_mean(prior, final, "raw_mean")
    else:
        raise O1C112FullBankSignAlignmentError("reader arm differs")
    if not math.isfinite(score):
        raise O1C112FullBankSignAlignmentError("reader score differs")
    return 0.0 if score == 0.0 else score


def _freeze_arm(
    arm: str,
    prior: Sequence[BankRecord],
    final: Sequence[BankRecord],
) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    bit_1 = 0
    bit_0 = 0
    abstentions = 0
    for old, new in zip(prior, final, strict=True):
        if old.variable != new.variable or new.count < old.count:
            raise O1C112FullBankSignAlignmentError("bank transition differs")
        score = _arm_score(arm, old, new)
        prediction = 1 if score > 0.0 else 0 if score < 0.0 else None
        bit_1 += prediction == 1
        bit_0 += prediction == 0
        abstentions += prediction is None
        rows.append(
            {
                "abstained": prediction is None,
                "coordinate_index": new.variable - 1,
                "final_count": new.count,
                "increment_count": new.count - old.count,
                "prediction_bit": prediction,
                "prior_count": old.count,
                "score": score,
                "score_f64le_hex": struct.pack("<d", score).hex(),
                "variable": new.variable,
            }
        )
    prediction_census = {"bit_1": bit_1, "bit_0": bit_0, "abstain": abstentions}
    return {
        "arm": arm,
        "role": "primary" if arm == PRIMARY_ARM else "secondary_diagnostic",
        "formula": ARM_FORMULAS[arm],
        "secondary_can_change_primary": False,
        "coordinate_scores": rows,
        "coordinate_score_sha256": _sha256(canonical_json_bytes(rows)),
        "evaluated_coordinate_count": bit_1 + bit_0,
        "abstention_count": abstentions,
        "prediction_census": prediction_census,
    }


def _authenticate_parent_and_banks(
    root: Path, config: Mapping[str, object]
) -> tuple[Mapping[str, object], bytes, bytes, dict[str, str]]:
    parent = _mapping(config["parent"], "parent")
    capsule_candidate = root / cast(str, parent["capsule"])
    try:
        capsule_status = capsule_candidate.lstat()
    except OSError as exc:
        raise O1C112FullBankSignAlignmentError("parent capsule is absent") from exc
    if stat.S_ISLNK(capsule_status.st_mode) or not stat.S_ISDIR(
        capsule_status.st_mode
    ):
        raise O1C112FullBankSignAlignmentError("parent capsule type differs")
    capsule = capsule_candidate.resolve(strict=True)
    if not capsule.is_relative_to(root):
        raise O1C112FullBankSignAlignmentError("parent capsule escapes the lab")

    manifest_path, manifest_payload = _sealed_payload(
        root,
        _mapping(parent["capsule_manifest"], "capsule manifest"),
        "parent capsule manifest",
    )
    result_path, result_payload = _sealed_payload(
        root,
        _mapping(parent["capsule_result"], "capsule result"),
        "parent capsule result",
    )
    authoritative_path, authoritative_payload = _sealed_payload(
        root,
        _mapping(parent["authoritative_result"], "authoritative result"),
        "authoritative parent result",
    )
    if (
        manifest_path != capsule / "artifacts.sha256"
        or result_path != capsule / "result.json"
        or authoritative_path != root / AUTHORITATIVE_RESULT_RELATIVE
        or authoritative_payload != result_payload
    ):
        raise O1C112FullBankSignAlignmentError("parent result linkage differs")

    try:
        parent_config = _o1c109.load_config(
            root / _o1c109.CONFIG_RELATIVE, root=root
        )
        verifier = _o1c109._public_verifier(root=root, config=parent_config)
        result, authenticated_payload = _o1c109._validated_capsule_result(
            root, capsule, public_verifier=verifier
        )
    except Exception as exc:
        raise O1C112FullBankSignAlignmentError(
            "O1C109 capsule authentication differs"
        ) from exc
    if (
        authenticated_payload != result_payload
        or result.get("attempt_id") != "O1C-0109"
        or result.get("classification") != PARENT_CLASSIFICATION
        or result.get("science_gain") is not True
    ):
        raise O1C112FullBankSignAlignmentError("authenticated parent differs")

    inputs = _mapping(config["inputs"], "inputs")
    final_path, final_payload = _sealed_payload(
        root, _mapping(inputs["final_bank"], "final bank"), "final living bank"
    )
    prior_path, prior_payload = _sealed_payload(
        root, _mapping(inputs["prior_bank"], "prior bank"), "O1C108 prior bank"
    )
    initial_path = _regular_file(
        root / PARENT_INITIAL_BANK_RELATIVE, "O1C109 initial prior bank"
    ).resolve(strict=True)
    initial_payload = initial_path.read_bytes()
    if (
        final_path != root / FINAL_BANK_RELATIVE
        or prior_path != root / PRIOR_BANK_RELATIVE
        or initial_path != root / PARENT_INITIAL_BANK_RELATIVE
        or initial_payload != prior_payload
    ):
        raise O1C112FullBankSignAlignmentError("bank provenance differs")

    episodes = _sequence(result.get("episodes"), "parent episodes")
    if len(episodes) != 1:
        raise O1C112FullBankSignAlignmentError("parent episode count differs")
    episode = _mapping(episodes[0], "parent episode")
    final_row = {
        "path": "final-parent-centered-priority-bank.bin",
        "serialized_bytes": BANK_BYTES,
        "sha256": FINAL_BANK_SHA256,
    }
    claim = _mapping(result.get("claim_boundary"), "parent claim boundary")
    operational = _mapping(episode.get("operational"), "parent operational")
    if (
        episode.get("completed") is not True
        or episode.get("final_priority_bank") != final_row
        or episode.get("lineage_call_ordinal") != 35
        or operational.get("probe_count") != 33_569
        or claim.get("input_continuation_bank_sha256") != PRIOR_BANK_SHA256
        or claim.get("truth_key_bytes_read") is not False
        or claim.get("fresh_reveal_calls") != 0
    ):
        raise O1C112FullBankSignAlignmentError("parent bank contract differs")

    seals = {
        "capsule_manifest": _sha256(manifest_payload),
        "parent_result": _sha256(result_payload),
        "authoritative_result": _sha256(authoritative_payload),
        "final_bank": _sha256(final_payload),
        "prior_bank": _sha256(prior_payload),
        "parent_initial_prior_bank": _sha256(initial_payload),
    }
    return result, prior_payload, final_payload, seals


def _authenticate_and_freeze(
    root: Path, config: Mapping[str, object], config_sha256: str
) -> Mapping[str, object]:
    parent, prior_payload, final_payload, seals = _authenticate_parent_and_banks(
        root, config
    )
    prior = decode_priority_bank(prior_payload, expected_sha256=PRIOR_BANK_SHA256)
    final = decode_priority_bank(final_payload, expected_sha256=FINAL_BANK_SHA256)
    if any(
        old.variable != new.variable or new.count < old.count
        for old, new in zip(prior, final, strict=True)
    ):
        raise O1C112FullBankSignAlignmentError("bank count monotonicity differs")

    census = {
        "final": _bank_census(final_payload, final),
        "prior": _bank_census(prior_payload, prior),
        "increment": _increment_census(prior, final),
    }
    arms = [
        _freeze_arm(arm, prior, final) for arm in (PRIMARY_ARM, *SECONDARY_ARMS)
    ]
    census["arm_predictions"] = {
        cast(str, arm["arm"]): arm["prediction_census"] for arm in arms
    }
    if census != EXPECTED_CENSUS or census != config.get("expected_census"):
        raise O1C112FullBankSignAlignmentError("observed bank census differs")

    source = _mapping(config["source"], "source")
    design = _mapping(config["design"], "design")
    claim = _mapping(parent.get("claim_boundary"), "parent claim boundary")
    return {
        "schema": SCORE_FREEZE_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "claim_level": "RETROSPECTIVE_FULL_BANK_DIAGNOSTIC",
        "config_sha256": config_sha256,
        "design_sha256": design["sha256"],
        "source_sha256": {
            name: _mapping(source[name], f"source {name}")["sha256"]
            for name in ("module", "tests")
        },
        "authenticated_input_sha256": seals,
        "parent": {
            "attempt_id": parent.get("attempt_id"),
            "classification": parent.get("classification"),
            "science_gain": parent.get("science_gain"),
            "truth_key_bytes_read": claim.get("truth_key_bytes_read"),
        },
        "bank_census": census,
        "primary_arm": PRIMARY_ARM,
        "secondary_arms": list(SECONDARY_ARMS),
        "arms": arms,
        "arms_sha256": _sha256(canonical_json_bytes(arms)),
        "reader": config["reader"],
        "controls": config["controls"],
        "gates": config["gates"],
        "truth_source_commitment": dict(
            _mapping(
                _mapping(config["inputs"], "inputs")["historical_reveal"],
                "historical reveal",
            )
        ),
        "truth_lifecycle": {
            "fresh_reveal_calls_before_freeze": 0,
            "historical_reveal_file_reads_before_freeze": 0,
            "score_and_control_state_frozen_before_truth": True,
            "truth_key_bytes_read_before_freeze": 0,
        },
    }


def prepare_full_bank_sign_alignment(
    config_path: str | Path = DEFAULT_CONFIG_RELATIVE,
    *,
    root: Path | None = None,
) -> PreparedFullBankAnalysis:
    """Authenticate both banks and return a canonical truth-free score freeze."""

    base = (root or lab_root()).resolve(strict=True)
    config, config_sha256 = load_config(config_path, root=base)
    score_freeze = _authenticate_and_freeze(base, config, config_sha256)
    score_freeze_bytes = canonical_json_bytes(score_freeze)
    truth_source = _mapping(
        _mapping(config["inputs"], "inputs")["historical_reveal"],
        "historical reveal",
    )
    # Deliberately do not stat, open, or hash the truth-bearing file here.
    reveal_path = _future_relative_file(
        base, truth_source.get("path"), "historical reveal"
    )
    return PreparedFullBankAnalysis(
        root=base,
        config=config,
        config_sha256=config_sha256,
        score_freeze=score_freeze,
        score_freeze_bytes=score_freeze_bytes,
        score_freeze_sha256=_sha256(score_freeze_bytes),
        reveal_path=reveal_path,
        reveal_serialized_bytes=_integer(
            truth_source.get("serialized_bytes"), "historical reveal bytes"
        ),
        reveal_file_sha256=_validate_sha(
            truth_source.get("sha256"), "historical reveal"
        ),
    )


def _read_historical_truth(
    path: Path,
    expected_bytes: int,
    expected_sha256: str,
    frozen_score_sha256: str,
) -> HistoricalTruth:
    """Read and broker-verify O1C-0057 only after a valid score-freeze seal."""

    _validate_sha(frozen_score_sha256, "score freeze")
    payload = _regular_file(path, "historical reveal").read_bytes()
    if len(payload) != expected_bytes or _sha256(payload) != expected_sha256:
        raise O1C112FullBankSignAlignmentError("historical reveal seal differs")
    try:
        raw = json.loads(payload.decode("ascii"))
        reveal = verify_reveal(raw)
        preimage = _mapping(reveal["commitment_preimage"], "commitment preimage")
        key = bytes.fromhex(str(preimage["key_hex"]))
        reveal_sha256 = _validate_sha(reveal.get("reveal_sha256"), "reveal")
    except (UnicodeError, json.JSONDecodeError, ValueError, KeyError) as exc:
        raise O1C112FullBankSignAlignmentError(
            "historical reveal verification differs"
        ) from exc
    if reveal_sha256 != HISTORICAL_REVEAL_INNER_SHA256:
        raise O1C112FullBankSignAlignmentError("historical reveal identity differs")
    return HistoricalTruth(
        key=key,
        source_file_sha256=expected_sha256,
        reveal_sha256=reveal_sha256,
    )


def _binomial_upper_tail(correct: int, total: int) -> Fraction:
    if correct < 0 or total < 0 or correct > total:
        raise O1C112FullBankSignAlignmentError("binomial counts differ")
    return Fraction(
        sum(math.comb(total, value) for value in range(correct, total + 1)),
        2**total,
    )


def _fraction_row(value: Fraction) -> dict[str, object]:
    return {
        "decimal": float(value),
        "denominator": value.denominator,
        "numerator": value.numerator,
    }


def _configured_fraction(value: object, label: str) -> Fraction:
    row = _mapping(value, label)
    if set(row) != {"numerator", "denominator"}:
        raise O1C112FullBankSignAlignmentError(f"{label} fields differ")
    numerator = _integer(row.get("numerator"), f"{label} numerator")
    denominator = _integer(row.get("denominator"), f"{label} denominator")
    if numerator < 0 or denominator <= 0:
        raise O1C112FullBankSignAlignmentError(f"{label} differs")
    return Fraction(numerator, denominator)


def _group_accuracy(
    predictions: Sequence[int | None],
    truth: Sequence[int],
    *,
    width: int,
) -> dict[str, object]:
    if KEY_BITS % width:
        raise O1C112FullBankSignAlignmentError("group width differs")
    exact_indices: list[int] = []
    excluded_indices: list[int] = []
    for group in range(KEY_BITS // width):
        start = group * width
        predicted = predictions[start : start + width]
        if any(value is None for value in predicted):
            excluded_indices.append(group)
            continue
        prediction_value = sum(
            cast(int, value) << offset for offset, value in enumerate(predicted)
        )
        truth_value = sum(truth[start + offset] << offset for offset in range(width))
        if prediction_value == truth_value:
            exact_indices.append(group)
    return {
        "group_width_bits": width,
        "fully_predicted_count": KEY_BITS // width - len(excluded_indices),
        "exact_count": len(exact_indices),
        "exact_indices": exact_indices,
        "excluded_indices": excluded_indices,
    }


def _evaluate_arm(
    frozen_arm: Mapping[str, object], truth: Sequence[int]
) -> dict[str, object]:
    if len(truth) != KEY_BITS or any(value not in (0, 1) for value in truth):
        raise O1C112FullBankSignAlignmentError("truth bit geometry differs")
    rows = _sequence(frozen_arm.get("coordinate_scores"), "coordinate scores")
    if len(rows) != KEY_BITS:
        raise O1C112FullBankSignAlignmentError("coordinate score count differs")

    predictions: list[int | None] = [None] * KEY_BITS
    score_pairs: list[tuple[int, float]] = []
    correct = 0
    abstentions = 0
    for expected_coordinate, value in enumerate(rows):
        row = _mapping(value, "coordinate score")
        coordinate = _integer(row.get("coordinate_index"), "coordinate")
        score = _number(row.get("score"), "coordinate score")
        prediction = row.get("prediction_bit")
        if (
            coordinate != expected_coordinate
            or row.get("variable") != coordinate + 1
            or prediction not in (0, 1, None)
            or row.get("abstained") is not (prediction is None)
            or struct.pack("<d", score).hex() != row.get("score_f64le_hex")
            or prediction != (1 if score > 0.0 else 0 if score < 0.0 else None)
        ):
            raise O1C112FullBankSignAlignmentError("coordinate prediction differs")
        predictions[coordinate] = cast(int | None, prediction)
        if prediction is None:
            abstentions += 1
        else:
            correct += prediction == truth[coordinate]
            score_pairs.append((coordinate, score))

    evaluated = len(score_pairs)
    tail = _binomial_upper_tail(correct, evaluated)
    truth_spins = [1 if value else -1 for value in truth]
    controls: list[dict[str, object]] = []
    for offset in range(KEY_BITS):
        alignment = math.fsum(
            truth_spins[(coordinate + offset) % KEY_BITS] * score
            for coordinate, score in score_pairs
        )
        controls.append({"alignment": alignment, "offset": offset})
    identity = _number(controls[0]["alignment"], "identity alignment")
    conservative_rank = sum(
        _number(row["alignment"], "control alignment") >= identity
        for row in controls
    )
    sign_flip = -identity
    margin = math.fsum([identity, -sign_flip])
    byte_accuracy = _group_accuracy(predictions, truth, width=8)
    word_accuracy = _group_accuracy(predictions, truth, width=16)
    if (
        byte_accuracy["fully_predicted_count"] != 31
        or byte_accuracy["excluded_indices"] != [30]
        or word_accuracy["fully_predicted_count"] != 15
        or word_accuracy["excluded_indices"] != [15]
    ):
        raise O1C112FullBankSignAlignmentError(
            "fully predicted byte/word geometry differs"
        )
    return {
        "arm": frozen_arm.get("arm"),
        "role": frozen_arm.get("role"),
        "abstention_count": abstentions,
        "evaluated_coordinate_count": evaluated,
        "correct_count": correct,
        "binomial_tail": _fraction_row(tail),
        "identity_alignment": identity,
        "cyclic_control_count": len(controls),
        "cyclic_controls": controls,
        "control_ledger_sha256": _sha256(canonical_json_bytes(controls)),
        "cyclic_rank_count_conservative": conservative_rank,
        "cyclic_rank_fraction": conservative_rank / KEY_BITS,
        "cyclic_rank_fraction_exact": _fraction_row(
            Fraction(conservative_rank, KEY_BITS)
        ),
        "global_sign_flip_alignment": sign_flip,
        "identity_over_sign_flip_margin": margin,
        "strict_positive_sign_flip_margin": margin > 0.0,
        "byte_accuracy": byte_accuracy,
        "word16_accuracy": word_accuracy,
    }


def _find_arm(
    score_freeze: Mapping[str, object], arm_name: str
) -> Mapping[str, object]:
    matches = [
        _mapping(value, "frozen arm")
        for value in _sequence(score_freeze.get("arms"), "frozen arms")
        if _mapping(value, "frozen arm").get("arm") == arm_name
    ]
    if len(matches) != 1:
        raise O1C112FullBankSignAlignmentError(f"frozen arm {arm_name} differs")
    return matches[0]


def _classification(
    primary: Mapping[str, object], gates: Mapping[str, object]
) -> tuple[str, dict[str, object]]:
    strong = _mapping(gates.get("strong"), "strong gate")
    breadcrumb = _mapping(gates.get("breadcrumb"), "breadcrumb gate")
    tail_row = _mapping(primary.get("binomial_tail"), "primary binomial tail")
    tail = Fraction(
        _integer(tail_row.get("numerator"), "tail numerator"),
        _integer(tail_row.get("denominator"), "tail denominator"),
    )
    rank_count = _integer(
        primary.get("cyclic_rank_count_conservative"), "cyclic rank count"
    )
    rank = Fraction(rank_count, KEY_BITS)
    evaluated = _integer(
        primary.get("evaluated_coordinate_count"), "evaluated coordinates"
    )
    margin_pass = primary.get("strict_positive_sign_flip_margin") is True

    strong_checks = {
        "coverage_pass": evaluated
        >= _integer(
            strong.get("minimum_evaluated_coordinates"), "strong coverage"
        ),
        "binomial_tail_pass": tail
        <= _configured_fraction(
            strong.get("maximum_binomial_tail"), "strong binomial threshold"
        ),
        "cyclic_rank_fraction_pass": rank
        <= _configured_fraction(
            strong.get("maximum_cyclic_rank_fraction"), "strong rank threshold"
        ),
        "positive_sign_flip_margin_pass": margin_pass,
    }
    strong_pass = all(strong_checks.values())
    breadcrumb_checks = {
        "coverage_pass": evaluated
        >= _integer(
            breadcrumb.get("minimum_evaluated_coordinates"), "breadcrumb coverage"
        ),
        "binomial_tail_pass": tail
        <= _configured_fraction(
            breadcrumb.get("maximum_binomial_tail"),
            "breadcrumb binomial threshold",
        ),
        "positive_sign_flip_margin_pass": margin_pass,
        "strong_gate_failed": not strong_pass,
    }
    breadcrumb_pass = all(breadcrumb_checks.values())
    if strong_pass:
        classification = STRONG_CLASSIFICATION
    elif breadcrumb_pass:
        classification = BREADCRUMB_CLASSIFICATION
    else:
        classification = NULL_CLASSIFICATION
    return classification, {
        "strong": {**strong_checks, "passed": strong_pass},
        "breadcrumb": {**breadcrumb_checks, "passed": breadcrumb_pass},
        "selected_classification": classification,
    }


def _attach_result_sha(unsigned: Mapping[str, object]) -> dict[str, object]:
    if "result_sha256" in unsigned:
        raise O1C112FullBankSignAlignmentError("unsigned result already has SHA")
    return {**unsigned, "result_sha256": _sha256(canonical_json_bytes(unsigned))}


def finalize_full_bank_sign_alignment(
    prepared: PreparedFullBankAnalysis,
    *,
    truth_reader: TruthReader = _read_historical_truth,
) -> dict[str, object]:
    """Read historical truth after freeze and evaluate all seven frozen arms."""

    if not isinstance(prepared, PreparedFullBankAnalysis):
        raise O1C112FullBankSignAlignmentError("prepared analysis differs")
    if _sha256(prepared.score_freeze_bytes) != prepared.score_freeze_sha256:
        raise O1C112FullBankSignAlignmentError("score freeze seal differs")
    historical = truth_reader(
        prepared.reveal_path,
        prepared.reveal_serialized_bytes,
        prepared.reveal_file_sha256,
        prepared.score_freeze_sha256,
    )
    if historical.source_file_sha256 != prepared.reveal_file_sha256:
        raise O1C112FullBankSignAlignmentError(
            "historical truth source linkage differs"
        )
    truth = [int(value) for value in key_bits(historical.key)]

    primary_freeze = _find_arm(prepared.score_freeze, PRIMARY_ARM)
    primary = _evaluate_arm(primary_freeze, truth)
    secondary = [
        _evaluate_arm(_find_arm(prepared.score_freeze, arm), truth)
        for arm in SECONDARY_ARMS
    ]
    gates = _mapping(prepared.config["gates"], "gates")
    classification, classification_gates = _classification(primary, gates)
    unsigned = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "claim_level": "RETROSPECTIVE_FULL_BANK_DIAGNOSTIC",
        "classification": classification,
        "result_identity_rule": RESULT_IDENTITY_RULE,
        "score_freeze": dict(prepared.score_freeze),
        "score_freeze_sha256": prepared.score_freeze_sha256,
        "primary": primary,
        "secondary": secondary,
        "secondary_arm_count": len(secondary),
        "secondary_can_change_primary_classification": False,
        "classification_gates": classification_gates,
        "truth_source": {
            "fresh_reveal_calls": 0,
            "historical_reveal_file_reads": 1,
            "historical_reveal_sha256": historical.source_file_sha256,
            "reveal_sha256": historical.reveal_sha256,
            "score_freeze_existed_before_read": True,
            "score_freeze_sha256": prepared.score_freeze_sha256,
            "truth_key_sha256": _sha256(historical.key),
        },
        "resources": {
            "fresh_reveal_calls": 0,
            "fresh_targets": 0,
            "gpu_calls": 0,
            "historical_reveal_file_reads": 1,
            "mps_calls": 0,
            "native_solver_calls": 0,
            "refits": 0,
            "science_solver_calls": 0,
            "target_generation_calls": 0,
        },
        "claim_boundary": {
            "attacker_valid_entropy_gain_bits": 0.0,
            "beam_hit": False,
            "calibrated_nll_authorized": False,
            "fresh_attacker_valid_claim": False,
            "fresh_replication_required": True,
            "historical_target_continuation_authorized": False,
            "independent_key_recovery": False,
            "o1c109_truth_key_bytes_read": 0,
            "posterior_authorized": False,
            "result_is_retrospective": True,
            "secondary_rescue_authorized": False,
            "sota_recovery_claim": False,
        },
        "next_action": prepared.config["next_action"],
    }
    return _attach_result_sha(unsigned)


def generate_full_bank_sign_alignment(
    config_path: str | Path = DEFAULT_CONFIG_RELATIVE,
    *,
    root: Path | None = None,
    truth_reader: TruthReader = _read_historical_truth,
) -> dict[str, object]:
    """Run the enforced prepare-then-finalize historical diagnostic."""

    prepared = prepare_full_bank_sign_alignment(config_path, root=root)
    return finalize_full_bank_sign_alignment(prepared, truth_reader=truth_reader)


def serialize_score_freeze(prepared: PreparedFullBankAnalysis) -> bytes:
    envelope = {
        "schema": SCORE_FREEZE_ENVELOPE_SCHEMA,
        "score_freeze": dict(prepared.score_freeze),
        "score_freeze_sha256": prepared.score_freeze_sha256,
    }
    return canonical_json_bytes(envelope)


def serialize_result(result: Mapping[str, object]) -> bytes:
    row = dict(result)
    observed = row.pop("result_sha256", None)
    if observed != _sha256(canonical_json_bytes(row)):
        raise O1C112FullBankSignAlignmentError("result SHA-256 differs")
    if result.get("schema") != RESULT_SCHEMA:
        raise O1C112FullBankSignAlignmentError("result schema differs")
    return canonical_json_bytes(result)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_RELATIVE))
    parser.add_argument(
        "--prepare-only",
        action="store_true",
        help="authenticate and emit only the pre-truth score freeze",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    prepared = prepare_full_bank_sign_alignment(args.config)
    payload = (
        serialize_score_freeze(prepared)
        if args.prepare_only
        else serialize_result(finalize_full_bank_sign_alignment(prepared))
    )
    os.write(1, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ATTEMPT_ID",
    "BREADCRUMB_CLASSIFICATION",
    "CONFIG_SCHEMA",
    "DEFAULT_CONFIG_RELATIVE",
    "HistoricalTruth",
    "NULL_CLASSIFICATION",
    "O1C112FullBankSignAlignmentError",
    "PRIMARY_ARM",
    "PreparedFullBankAnalysis",
    "RESULT_SCHEMA",
    "SCORE_FREEZE_SCHEMA",
    "SECONDARY_ARMS",
    "STRONG_CLASSIFICATION",
    "decode_priority_bank",
    "finalize_full_bank_sign_alignment",
    "generate_full_bank_sign_alignment",
    "load_config",
    "main",
    "prepare_full_bank_sign_alignment",
    "serialize_result",
    "serialize_score_freeze",
]
