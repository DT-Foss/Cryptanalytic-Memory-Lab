"""Sealed retrospective sign alignment for O1C-0109 breadcrumbs.

O1C-0111 is deliberately a zero-solver analysis.  It authenticates the exact
O1C-0109 capsule, freezes its score and control state, and only then permits a
single read of the already-sealed O1C-0057 historical reveal.  The two observed
coordinates can produce a retrospective directional diagnostic, never a
posterior, entropy-reduction, recovery, or fresh-target claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import stat
import struct
import tempfile
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import cast

from . import joint_score_sieve_v36 as _native_v36
from . import o1c109_apple8_parent_centered_continuation_run as _o1c109
from .causal_attic_v1 import canonical_json_bytes, parse_vault_telemetry
from .full256_broker import verify_reveal
from .living_inverse import KEY_BITS, key_bits


ATTEMPT_ID = "O1C-0111"
CONFIG_SCHEMA = "o1-256-o1c111-breadcrumb-sign-alignment-config-v1"
SCORE_FREEZE_SCHEMA = "o1-256-o1c111-breadcrumb-sign-score-freeze-v1"
SCORE_FREEZE_ENVELOPE_SCHEMA = "o1-256-o1c111-breadcrumb-sign-score-freeze-envelope-v1"
RESULT_SCHEMA = "o1-256-o1c111-breadcrumb-sign-alignment-result-v1"
DEFAULT_CONFIG_RELATIVE = Path("configs/o1c111_breadcrumb_sign_alignment_v1.json")

PRIMARY_CLASS = "ONE_PRUNABLE"
SECONDARY_CLASS = "BOTH_PRUNABLE"
PRIMARY_ARM = "one_prunable_primary"
SECONDARY_ARM = "both_prunable_secondary"
CONTROL_DOMAIN = "o1c111-cyclic-truth-coordinate-rotation-v1"
RESULT_IDENTITY_RULE = "sha256(canonical-json(result-without-result_sha256))"


class O1C111BreadcrumbSignAlignmentError(ValueError):
    """A frozen input, lifecycle boundary, or result invariant differs."""


@dataclass(frozen=True)
class HistoricalTruth:
    """A broker-verified historical truth, returned only after score freeze."""

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
            raise O1C111BreadcrumbSignAlignmentError(
                "historical truth evidence differs"
            )


@dataclass(frozen=True)
class PreparedBreadcrumbAnalysis:
    """Authenticated pre-truth state and its canonical score freeze."""

    root: Path
    config: Mapping[str, object]
    config_sha256: str
    score_freeze: Mapping[str, object]
    score_freeze_bytes: bytes
    score_freeze_sha256: str
    reveal_path: Path
    reveal_sha256: str


TruthReader = Callable[[Path, str, str], HistoricalTruth]


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
        raise O1C111BreadcrumbSignAlignmentError(f"{label} is not an object")
    return cast(Mapping[str, object], value)


def _sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise O1C111BreadcrumbSignAlignmentError(f"{label} is not an array")
    return value


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise O1C111BreadcrumbSignAlignmentError(f"{label} is not an integer")
    return value


def _number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise O1C111BreadcrumbSignAlignmentError(f"{label} is not numeric")
    result = float(value)
    if not math.isfinite(result):
        raise O1C111BreadcrumbSignAlignmentError(f"{label} is not finite")
    return result


def _regular_file(path: Path, label: str) -> Path:
    try:
        status = path.lstat()
    except OSError as exc:
        raise O1C111BreadcrumbSignAlignmentError(f"{label} is absent") from exc
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
        raise O1C111BreadcrumbSignAlignmentError(
            f"{label} is not a sealed regular file"
        )
    return path


def _relative_file(root: Path, value: object, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise O1C111BreadcrumbSignAlignmentError(f"{label} path differs")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise O1C111BreadcrumbSignAlignmentError(f"{label} escapes the lab")
    path = _regular_file(root / relative, label).resolve(strict=True)
    if not path.is_relative_to(root):
        raise O1C111BreadcrumbSignAlignmentError(f"{label} escapes the lab")
    return path


def _read_canonical_json(path: Path, label: str) -> tuple[dict[str, object], bytes]:
    payload = _regular_file(path, label).read_bytes()
    try:
        raw = json.loads(payload.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C111BreadcrumbSignAlignmentError(f"{label} JSON differs") from exc
    document = dict(_mapping(raw, label))
    if canonical_json_bytes(document) != payload:
        raise O1C111BreadcrumbSignAlignmentError(f"{label} is not canonical JSON")
    return document, payload


def _validate_sha(value: object, label: str) -> str:
    if not _is_sha256(value):
        raise O1C111BreadcrumbSignAlignmentError(f"{label} SHA-256 differs")
    return cast(str, value)


def _sealed_payload(
    root: Path,
    row: Mapping[str, object],
    label: str,
    *,
    expected_keys: set[str] = {"path", "serialized_bytes", "sha256"},
) -> tuple[Path, bytes]:
    if set(row) != expected_keys:
        raise O1C111BreadcrumbSignAlignmentError(f"{label} seal fields differ")
    path = _relative_file(root, row.get("path"), label)
    payload = path.read_bytes()
    expected_bytes = _integer(row.get("serialized_bytes"), f"{label} bytes")
    expected_sha = _validate_sha(row.get("sha256"), label)
    if len(payload) != expected_bytes or _sha256(payload) != expected_sha:
        raise O1C111BreadcrumbSignAlignmentError(f"{label} seal differs")
    return path, payload


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
        or config.get("claim_level") != "RETROSPECTIVE_DIAGNOSTIC"
        or config.get("next_action")
        != "Replicate the unchanged frozen reader on fresh targets; never continue the historical target from this diagnostic."
    ):
        raise O1C111BreadcrumbSignAlignmentError("frozen config header differs")

    design = _mapping(config.get("design"), "design")
    if (
        set(design) != {"path", "serialized_bytes", "sha256", "git_commit"}
        or design.get("path")
        != "research/O1C0111_BREADCRUMB_SIGN_ALIGNMENT_DESIGN_20260721.md"
        or design.get("serialized_bytes") != 3_498
        or design.get("sha256")
        != "a17ba0c73ba37f6c11e5a99e3112ef26738ceb09c3cffb7ec61f146051dde3a1"
        or design.get("git_commit") != "619410e"
    ):
        raise O1C111BreadcrumbSignAlignmentError("frozen design differs")

    reader = _mapping(config.get("reader"), "reader")
    if reader != {
        "abstention_rule": "S_v == 0.0",
        "aggregation": "S_v=math.fsum(d_in_canonical_probe_order)",
        "differential": "d=upper_one-upper_zero",
        "primary_classification": PRIMARY_CLASS,
        "prediction_rule": "bit1-if-S_v-positive;bit0-if-S_v-negative",
        "required_consumed_before": True,
        "required_crossing_eligible": False,
        "secondary_classification": SECONDARY_CLASS,
        "secondary_cannot_change_primary": True,
    }:
        raise O1C111BreadcrumbSignAlignmentError("frozen reader differs")

    controls = _mapping(config.get("controls"), "controls")
    if controls != {
        "conservative_ties": True,
        "cyclic_offset_count": 256,
        "domain": CONTROL_DOMAIN,
        "global_sign_flip": True,
        "identity_offset": 0,
        "rotation_formula": "truth_spin[(coordinate_index+offset)%256]",
    }:
        raise O1C111BreadcrumbSignAlignmentError("frozen controls differ")

    gates = _mapping(config.get("gates"), "gates")
    if gates != {
        "broad_posterior": {
            "maximum_one_sided_binomial_tail": 0.05,
            "maximum_primary_cyclic_rank_fraction": 0.25,
            "minimum_unique_nonzero_coordinates": 32,
            "require_strict_positive_sign_flip_margin": True,
        },
        "two_coordinate_diagnostic": {
            "correct_classification": (
                "RETROSPECTIVE_TWO_COORDINATE_DIRECTIONAL_BREADCRUMB"
            ),
            "expected_unique_nonzero_coordinates": 2,
            "mixed_or_wrong_classification": (
                "RETROSPECTIVE_TWO_COORDINATE_MIXED_OR_WRONG"
            ),
        },
    }:
        raise O1C111BreadcrumbSignAlignmentError("frozen gates differ")

    budgets = _mapping(config.get("budgets"), "budgets")
    if budgets != {
        "maximum_fresh_reveal_calls": 0,
        "maximum_fresh_targets": 0,
        "maximum_gpu_calls": 0,
        "maximum_historical_reveal_file_reads": 1,
        "maximum_mps_calls": 0,
        "maximum_native_solver_calls": 0,
        "maximum_refits": 0,
        "maximum_science_solver_calls": 0,
    }:
        raise O1C111BreadcrumbSignAlignmentError("frozen budgets differ")


def load_config(
    path: str | Path = DEFAULT_CONFIG_RELATIVE,
    *,
    root: Path | None = None,
) -> tuple[dict[str, object], str]:
    """Load the canonical config and authenticate its source/design seals."""

    base = (root or lab_root()).resolve(strict=True)
    config_path = Path(path)
    if not config_path.is_absolute():
        config_path = base / config_path
    config_path = _regular_file(config_path.resolve(strict=True), "O1C111 config")
    if not config_path.is_relative_to(base):
        raise O1C111BreadcrumbSignAlignmentError("config escapes the lab")
    config, payload = _read_canonical_json(config_path, "O1C111 config")
    _validate_frozen_contract(config)

    design = _mapping(config["design"], "design")
    _sealed_payload(base, design, "frozen design", expected_keys=set(design))
    source = _mapping(config["source"], "source")
    if set(source) != {"module", "tests"}:
        raise O1C111BreadcrumbSignAlignmentError("source seal fields differ")
    for name in ("module", "tests"):
        _sealed_payload(base, _mapping(source[name], name), f"O1C111 {name}")
    return config, _sha256(payload)


def _observed_breadcrumb_census(
    sidecar: Mapping[str, object],
) -> dict[str, object]:
    rows = _sequence(sidecar.get("breadcrumbs"), "breadcrumb rows")
    coordinates: dict[int, list[Mapping[str, object]]] = {}
    parents: set[str] = set()
    consumed = 0
    crossing = 0
    for value in rows:
        row = _mapping(value, "breadcrumb row")
        coordinate = _integer(row.get("coordinate_index"), "coordinate index")
        coordinates.setdefault(coordinate, []).append(row)
        parent = row.get("parent_assignment_sha256")
        if not isinstance(parent, str):
            raise O1C111BreadcrumbSignAlignmentError(
                "breadcrumb parent assignment differs"
            )
        parents.add(parent)
        consumed += row.get("consumed_before") is True
        crossing += row.get("crossing_eligible") is True

    by_coordinate: list[dict[str, object]] = []
    for coordinate, values in sorted(coordinates.items()):
        classes = Counter(str(row["classification"]) for row in values)
        variables = {row["variable"] for row in values}
        if len(variables) != 1:
            raise O1C111BreadcrumbSignAlignmentError(
                "breadcrumb coordinate variable differs"
            )
        by_coordinate.append(
            {
                "class_counts": {
                    PRIMARY_CLASS: classes[PRIMARY_CLASS],
                    SECONDARY_CLASS: classes[SECONDARY_CLASS],
                },
                "coordinate_index": coordinate,
                "row_count": len(values),
                "variable": next(iter(variables)),
            }
        )

    digest = _mapping(sidecar.get("canonical_digest"), "breadcrumb digest")
    all_matches = _mapping(digest.get("all_matches"), "all breadcrumb digest")
    overflow = _mapping(digest.get("overflow"), "overflow breadcrumb digest")
    return {
        "all_consumed_before": consumed == len(rows),
        "any_crossing_eligible": crossing > 0,
        "by_coordinate": by_coordinate,
        "canonical_all_records_bytes": all_matches.get("bytes"),
        "canonical_all_records_sha256": all_matches.get("sha256"),
        "canonical_overflow_records_bytes": overflow.get("bytes"),
        "canonical_overflow_records_sha256": overflow.get("sha256"),
        "class_counts": dict(
            _mapping(sidecar["class_counts"], "breadcrumb class counts")
        ),
        "complete": sidecar.get("complete"),
        "consumed_before_count": consumed,
        "crossing_eligible_count": crossing,
        "overflow_count": sidecar.get("overflow_count"),
        "retained_count": sidecar.get("retained_count"),
        "total_match_count": sidecar.get("total_match_count"),
        "unique_coordinate_count": len(coordinates),
        "unique_parent_count": len(parents),
    }


def _observed_clause_census(
    result: Mapping[str, object],
    vault_document: Mapping[str, object],
    clause_hashes: Sequence[str],
) -> dict[str, object]:
    episodes = _sequence(result.get("episodes"), "parent result episodes")
    if len(episodes) != 1:
        raise O1C111BreadcrumbSignAlignmentError("parent episode count differs")
    science = _mapping(_mapping(episodes[0], "parent episode")["science"], "science")
    return {
        "active_page22_new_clauses": science.get("active_page22_new_clauses"),
        "clause_inventory_sha256": _sha256(canonical_json_bytes(clause_hashes)),
        "emitted_current_duplicate_clause_count": vault_document.get(
            "emitted_current_duplicate_clause_count"
        ),
        "emitted_current_duplicate_literal_count": vault_document.get(
            "emitted_current_duplicate_literal_count"
        ),
        "emitted_input_duplicate_clause_count": vault_document.get(
            "emitted_input_duplicate_clause_count"
        ),
        "emitted_input_duplicate_literal_count": vault_document.get(
            "emitted_input_duplicate_literal_count"
        ),
        "emitted_new_clause_count": vault_document.get("emitted_new_clause_count"),
        "emitted_new_literal_count": vault_document.get("emitted_new_literal_count"),
        "fully_emitted_aggregate_sha256": vault_document.get(
            "fully_emitted_aggregate_sha256"
        ),
        "fully_emitted_clause_count": vault_document.get("fully_emitted_clause_count"),
        "fully_emitted_literal_count": vault_document.get(
            "fully_emitted_literal_count"
        ),
        "globally_novel_clauses": science.get("globally_novel_clauses"),
        "next_vault_available": vault_document.get("next_vault_available"),
        "next_vault_terminal_reason": vault_document.get("next_vault_terminal_reason"),
        "pending_clause_exported": vault_document.get("pending_clause_exported"),
        "preloaded_clause_count": vault_document.get("preloaded_clause_count"),
        "preloaded_literal_count": vault_document.get("preloaded_literal_count"),
        "terminal_empty_clause_count": vault_document.get(
            "terminal_empty_clause_count"
        ),
        "threshold_prunes": science.get("threshold_prunes"),
        "unique_clause_count": len(set(clause_hashes)),
    }


def _arm_score_freeze(
    sidecar: Mapping[str, object],
    *,
    arm: str,
    classification: str,
) -> dict[str, object]:
    selected: list[Mapping[str, object]] = []
    for value in _sequence(sidecar.get("breadcrumbs"), "breadcrumb rows"):
        row = _mapping(value, "breadcrumb row")
        if row.get("classification") == classification:
            if (
                row.get("consumed_before") is not True
                or row.get("crossing_eligible") is not False
            ):
                raise O1C111BreadcrumbSignAlignmentError(
                    f"{arm} lifecycle filter differs"
                )
            selected.append(row)

    ledgers: list[dict[str, object]] = []
    by_coordinate: dict[int, list[tuple[float, Mapping[str, object]]]] = {}
    previous_sequence = 0
    for row in selected:
        sequence = _integer(row.get("sequence"), f"{arm} sequence")
        if sequence <= previous_sequence:
            raise O1C111BreadcrumbSignAlignmentError(f"{arm} order differs")
        previous_sequence = sequence
        coordinate = _integer(row.get("coordinate_index"), f"{arm} coordinate")
        differential = _number(row.get("upper_one"), f"{arm} U1") - _number(
            row.get("upper_zero"), f"{arm} U0"
        )
        by_coordinate.setdefault(coordinate, []).append((differential, row))
        ledgers.append(
            {
                "call": row.get("call"),
                "coordinate_index": coordinate,
                "d_f64le_hex": struct.pack("<d", differential).hex(),
                "parent_assignment_sha256": row.get("parent_assignment_sha256"),
                "probe": row.get("probe"),
                "sequence": sequence,
                "variable": row.get("variable"),
            }
        )

    aggregates: list[dict[str, object]] = []
    for coordinate, values in sorted(by_coordinate.items()):
        score = math.fsum(differential for differential, _ in values)
        variable_values = {row.get("variable") for _, row in values}
        if len(variable_values) != 1 or not math.isfinite(score):
            raise O1C111BreadcrumbSignAlignmentError(f"{arm} aggregate differs")
        prediction = 1 if score > 0.0 else 0 if score < 0.0 else None
        aggregates.append(
            {
                "abstained": prediction is None,
                "coordinate_index": coordinate,
                "prediction_bit": prediction,
                "row_count": len(values),
                "score_f64le_hex": struct.pack("<d", score).hex(),
                "score_sum": score,
                "unique_parent_count": len(
                    {row.get("parent_assignment_sha256") for _, row in values}
                ),
                "variable": next(iter(variable_values)),
            }
        )

    nonzero = sum(row["prediction_bit"] is not None for row in aggregates)
    return {
        "aggregate_sha256": _sha256(canonical_json_bytes(aggregates)),
        "arm": arm,
        "classification_filter": classification,
        "coordinate_aggregates": aggregates,
        "input_row_ledger_sha256": _sha256(canonical_json_bytes(ledgers)),
        "nonzero_unique_coordinate_count": nonzero,
        "repeated_row_count": len(selected) - len(aggregates),
        "row_count": len(selected),
        "unique_coordinate_count": len(aggregates),
    }


def _authenticate_and_freeze(
    root: Path,
    config: Mapping[str, object],
    config_sha256: str,
) -> Mapping[str, object]:
    parent = _mapping(config["parent"], "parent")
    if set(parent) != {
        "capsule",
        "capsule_manifest",
        "result",
        "classification",
    }:
        raise O1C111BreadcrumbSignAlignmentError("parent fields differ")
    capsule_value = parent.get("capsule")
    if not isinstance(capsule_value, str):
        raise O1C111BreadcrumbSignAlignmentError("parent capsule path differs")
    capsule = (root / capsule_value).resolve(strict=True)
    if not capsule.is_dir() or not capsule.is_relative_to(root):
        raise O1C111BreadcrumbSignAlignmentError("parent capsule differs")
    manifest_path, manifest_payload = _sealed_payload(
        root,
        _mapping(parent["capsule_manifest"], "capsule manifest"),
        "parent capsule manifest",
    )
    result_path, result_payload = _sealed_payload(
        root, _mapping(parent["result"], "parent result"), "parent result"
    )
    if (
        manifest_path != capsule / "artifacts.sha256"
        or result_path != capsule / "result.json"
    ):
        raise O1C111BreadcrumbSignAlignmentError("parent sealed paths differ")

    parent_config = _o1c109.load_config(root / _o1c109.CONFIG_RELATIVE, root=root)
    verifier = _o1c109._public_verifier(root=root, config=parent_config)
    result, authenticated_payload = _o1c109._validated_capsule_result(
        root, capsule, public_verifier=verifier
    )
    if (
        authenticated_payload != result_payload
        or result.get("attempt_id") != "O1C-0109"
        or result.get("classification") != parent.get("classification")
        or result.get("science_gain") is not True
    ):
        raise O1C111BreadcrumbSignAlignmentError("authenticated parent differs")

    inputs = _mapping(config["inputs"], "inputs")
    if set(inputs) != {"breadcrumbs", "vault", "historical_reveal"}:
        raise O1C111BreadcrumbSignAlignmentError("input fields differ")
    sidecar_path, sidecar_payload = _sealed_payload(
        root, _mapping(inputs["breadcrumbs"], "breadcrumbs"), "breadcrumb sidecar"
    )
    vault_path, vault_payload = _sealed_payload(
        root, _mapping(inputs["vault"], "vault"), "clause vault telemetry"
    )
    episode = capsule / "episodes" / "00"
    if (
        sidecar_path != episode / "local-prunable-breadcrumbs.json"
        or vault_path != episode / "vault.json"
    ):
        raise O1C111BreadcrumbSignAlignmentError("parent episode paths differ")

    try:
        sidecar_raw = json.loads(sidecar_payload.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C111BreadcrumbSignAlignmentError(
            "breadcrumb sidecar JSON differs"
        ) from exc
    if canonical_json_bytes(sidecar_raw) != sidecar_payload:
        raise O1C111BreadcrumbSignAlignmentError(
            "breadcrumb sidecar is not canonical JSON"
        )
    try:
        sidecar = _native_v36._validate_local_prunable_breadcrumbs(sidecar_raw)
    except Exception as exc:
        raise O1C111BreadcrumbSignAlignmentError(
            "breadcrumb sidecar authentication failed"
        ) from exc
    if sidecar.get("complete") is not True or sidecar.get("overflow_count") != 0:
        raise O1C111BreadcrumbSignAlignmentError(
            "incomplete breadcrumbs forbid sign analysis"
        )

    vault_row = _mapping(inputs["vault"], "vault")
    vault = parse_vault_telemetry(
        vault_payload,
        stream_id="o1c109-lineage35-native",
        expected_sha256=cast(str, vault_row["sha256"]),
    )
    try:
        vault_raw = json.loads(vault_payload.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C111BreadcrumbSignAlignmentError("vault JSON differs") from exc
    vault_document = _mapping(vault_raw, "vault")
    clause_hashes = [occurrence.clause_sha256 for occurrence in vault.occurrences]
    breadcrumb_census = _observed_breadcrumb_census(sidecar)
    clause_census = _observed_clause_census(result, vault_document, clause_hashes)
    census = {
        "breadcrumbs": breadcrumb_census,
        "clauses": clause_census,
        "parent_classification": result.get("classification"),
        "parent_science_gain": result.get("science_gain"),
        "parent_truth_key_bytes_read": _mapping(
            result.get("claim_boundary"), "parent claim boundary"
        ).get("truth_key_bytes_read"),
    }
    if census != config.get("expected_census"):
        raise O1C111BreadcrumbSignAlignmentError("frozen parent census differs")

    primary = _arm_score_freeze(sidecar, arm=PRIMARY_ARM, classification=PRIMARY_CLASS)
    secondary = _arm_score_freeze(
        sidecar, arm=SECONDARY_ARM, classification=SECONDARY_CLASS
    )
    gates = _mapping(config["gates"], "gates")
    broad = _mapping(gates["broad_posterior"], "broad gate")
    coverage_required = _integer(
        broad["minimum_unique_nonzero_coordinates"], "coverage gate"
    )
    observed_nonzero = _integer(
        primary["nonzero_unique_coordinate_count"], "primary coverage"
    )
    pretruth_gate = {
        "broad_posterior_promotion_possible": observed_nonzero >= coverage_required,
        "minimum_unique_nonzero_coordinates": coverage_required,
        "observed_unique_nonzero_coordinates": observed_nonzero,
        "status": (
            "ELIGIBLE_FOR_POST_TRUTH_GATES"
            if observed_nonzero >= coverage_required
            else "FAILED_INSUFFICIENT_UNIQUE_COORDINATES"
        ),
    }
    if pretruth_gate["broad_posterior_promotion_possible"] is not False:
        raise O1C111BreadcrumbSignAlignmentError(
            "frozen two-coordinate coverage unexpectedly passes broad gate"
        )

    controls = _mapping(config["controls"], "controls")
    control_definition = {
        **controls,
        "alignment_formula": "M_offset=math.fsum(truth_spin[(v+offset)%256]*S_v)",
        "rank_rule": "count(alignment>=identity_alignment)/256",
        "sign_flip_formula": "M_sign_flip=-M0",
    }
    source = _mapping(config["source"], "source")
    design = _mapping(config["design"], "design")
    return {
        "schema": SCORE_FREEZE_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "claim_level": "RETROSPECTIVE_DIAGNOSTIC",
        "config_sha256": config_sha256,
        "design_sha256": design["sha256"],
        "source_sha256": {
            name: _mapping(source[name], name)["sha256"] for name in ("module", "tests")
        },
        "authenticated_input_sha256": {
            "capsule_manifest": _sha256(manifest_payload),
            "parent_result": _sha256(result_payload),
            "breadcrumbs": _sha256(sidecar_payload),
            "vault": _sha256(vault_payload),
        },
        "parent_census": census,
        "primary_score_freeze": primary,
        "secondary_score_freeze": secondary,
        "pretruth_broad_gate": pretruth_gate,
        "control_definition": control_definition,
        "control_definition_sha256": _sha256(canonical_json_bytes(control_definition)),
        "truth_source_commitment": dict(
            _mapping(inputs["historical_reveal"], "historical reveal")
        ),
        "truth_lifecycle": {
            "fresh_reveal_calls_before_freeze": 0,
            "historical_reveal_file_reads_before_freeze": 0,
            "score_and_control_state_frozen_before_truth": True,
            "truth_key_bytes_read_before_freeze": 0,
        },
    }


def prepare_breadcrumb_sign_alignment(
    config_path: str | Path = DEFAULT_CONFIG_RELATIVE,
    *,
    root: Path | None = None,
) -> PreparedBreadcrumbAnalysis:
    """Authenticate O1C-0109 and return a canonical, truth-free score freeze."""

    base = (root or lab_root()).resolve(strict=True)
    config, config_sha256 = load_config(config_path, root=base)
    score_freeze = _authenticate_and_freeze(base, config, config_sha256)
    score_freeze_bytes = canonical_json_bytes(score_freeze)
    truth_source = _mapping(
        _mapping(config["inputs"], "inputs")["historical_reveal"],
        "historical reveal",
    )
    if set(truth_source) != {"path", "serialized_bytes", "sha256"}:
        raise O1C111BreadcrumbSignAlignmentError(
            "historical reveal commitment fields differ"
        )
    reveal_path_value = truth_source.get("path")
    if not isinstance(reveal_path_value, str):
        raise O1C111BreadcrumbSignAlignmentError("historical reveal path differs")
    # Deliberately do not stat, open, or hash the truth-bearing file here.
    reveal_path = base / reveal_path_value
    return PreparedBreadcrumbAnalysis(
        root=base,
        config=config,
        config_sha256=config_sha256,
        score_freeze=score_freeze,
        score_freeze_bytes=score_freeze_bytes,
        score_freeze_sha256=_sha256(score_freeze_bytes),
        reveal_path=reveal_path,
        reveal_sha256=_validate_sha(truth_source.get("sha256"), "historical reveal"),
    )


def _read_historical_truth(
    path: Path,
    expected_sha256: str,
    frozen_score_sha256: str,
) -> HistoricalTruth:
    """Read one historical reveal only after receiving a valid freeze digest."""

    _validate_sha(frozen_score_sha256, "score freeze")
    payload = _regular_file(path, "historical reveal").read_bytes()
    if _sha256(payload) != expected_sha256:
        raise O1C111BreadcrumbSignAlignmentError("historical reveal seal differs")
    try:
        raw = json.loads(payload.decode("ascii"))
        reveal = verify_reveal(raw)
        preimage = _mapping(reveal["commitment_preimage"], "commitment preimage")
        key = bytes.fromhex(str(preimage["key_hex"]))
    except (UnicodeError, json.JSONDecodeError, ValueError, KeyError) as exc:
        raise O1C111BreadcrumbSignAlignmentError(
            "historical reveal verification differs"
        ) from exc
    return HistoricalTruth(
        key=key,
        source_file_sha256=expected_sha256,
        reveal_sha256=_validate_sha(reveal.get("reveal_sha256"), "reveal"),
    )


def _decode_score(value: object, label: str) -> float:
    score = _number(value, label)
    return score


def _binomial_upper_tail(correct: int, total: int) -> Fraction:
    if correct < 0 or total < 0 or correct > total:
        raise O1C111BreadcrumbSignAlignmentError("binomial counts differ")
    return Fraction(
        sum(math.comb(total, value) for value in range(correct, total + 1)), 2**total
    )


def _evaluate_arm(
    frozen_arm: Mapping[str, object], truth: Sequence[int]
) -> dict[str, object]:
    if len(truth) != KEY_BITS or any(value not in (0, 1) for value in truth):
        raise O1C111BreadcrumbSignAlignmentError("truth bit geometry differs")
    coordinates = _sequence(
        frozen_arm.get("coordinate_aggregates"), "coordinate aggregates"
    )
    scored: list[dict[str, object]] = []
    score_pairs: list[tuple[int, float]] = []
    correct = 0
    abstentions = 0
    for value in coordinates:
        row = _mapping(value, "coordinate aggregate")
        coordinate = _integer(row.get("coordinate_index"), "coordinate")
        prediction = row.get("prediction_bit")
        score = _decode_score(row.get("score_sum"), "coordinate score")
        if not 0 <= coordinate < KEY_BITS or prediction not in (0, 1, None):
            raise O1C111BreadcrumbSignAlignmentError("coordinate prediction differs")
        truth_bit = truth[coordinate]
        is_correct = prediction is not None and prediction == truth_bit
        correct += is_correct
        abstentions += prediction is None
        if prediction is not None:
            score_pairs.append((coordinate, score))
        scored.append(
            {
                "abstained": prediction is None,
                "coordinate_index": coordinate,
                "correct": is_correct if prediction is not None else None,
                "prediction_bit": prediction,
                "row_count": row.get("row_count"),
                "score_sum": score,
                "truth_bit": truth_bit,
                "variable": row.get("variable"),
            }
        )

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
        _number(row["alignment"], "control alignment") >= identity for row in controls
    )
    sign_flip = -identity
    return {
        "abstention_count": abstentions,
        "arm": frozen_arm.get("arm"),
        "binomial_tail": {
            "decimal": float(tail),
            "denominator": tail.denominator,
            "numerator": tail.numerator,
        },
        "control_ledger_sha256": _sha256(canonical_json_bytes(controls)),
        "coordinate_results": scored,
        "correct_count": correct,
        "cyclic_control_count": len(controls),
        "cyclic_controls": controls,
        "cyclic_rank_count_conservative": conservative_rank,
        "cyclic_rank_fraction": conservative_rank / KEY_BITS,
        "evaluated_coordinate_count": evaluated,
        "global_sign_flip_alignment": sign_flip,
        "identity_alignment": identity,
        "strict_positive_sign_flip_margin": identity > sign_flip,
    }


def _attach_result_sha(unsigned: Mapping[str, object]) -> dict[str, object]:
    if "result_sha256" in unsigned:
        raise O1C111BreadcrumbSignAlignmentError("unsigned result already has SHA")
    return {**unsigned, "result_sha256": _sha256(canonical_json_bytes(unsigned))}


def finalize_breadcrumb_sign_alignment(
    prepared: PreparedBreadcrumbAnalysis,
    *,
    truth_reader: TruthReader = _read_historical_truth,
) -> dict[str, object]:
    """Read the historical truth after freeze and produce the bounded result."""

    if not isinstance(prepared, PreparedBreadcrumbAnalysis):
        raise O1C111BreadcrumbSignAlignmentError("prepared analysis differs")
    if _sha256(prepared.score_freeze_bytes) != prepared.score_freeze_sha256:
        raise O1C111BreadcrumbSignAlignmentError("score freeze seal differs")
    historical = truth_reader(
        prepared.reveal_path,
        prepared.reveal_sha256,
        prepared.score_freeze_sha256,
    )
    if historical.source_file_sha256 != prepared.reveal_sha256:
        raise O1C111BreadcrumbSignAlignmentError(
            "historical truth source linkage differs"
        )
    truth = [int(value) for value in key_bits(historical.key)]
    primary_freeze = _mapping(
        prepared.score_freeze["primary_score_freeze"], "primary score freeze"
    )
    secondary_freeze = _mapping(
        prepared.score_freeze["secondary_score_freeze"], "secondary score freeze"
    )
    primary = _evaluate_arm(primary_freeze, truth)
    secondary = _evaluate_arm(secondary_freeze, truth)

    gates = _mapping(prepared.config["gates"], "gates")
    broad_config = _mapping(gates["broad_posterior"], "broad gate")
    observed_unique = _integer(
        primary_freeze["nonzero_unique_coordinate_count"], "primary coverage"
    )
    coverage_pass = observed_unique >= _integer(
        broad_config["minimum_unique_nonzero_coordinates"], "coverage gate"
    )
    binomial_pass = _number(
        _mapping(primary["binomial_tail"], "binomial tail")["decimal"],
        "binomial tail",
    ) <= _number(broad_config["maximum_one_sided_binomial_tail"], "binomial gate")
    rank_pass = _number(primary["cyclic_rank_fraction"], "rank fraction") <= _number(
        broad_config["maximum_primary_cyclic_rank_fraction"], "rank gate"
    )
    sign_flip_pass = primary["strict_positive_sign_flip_margin"] is True
    broad_gate = {
        "binomial_tail_pass": binomial_pass,
        "coverage_pass": coverage_pass,
        "passed": coverage_pass and binomial_pass and rank_pass and sign_flip_pass,
        "promotion": "BROAD_POSTERIOR",
        "rank_fraction_pass": rank_pass,
        "strict_positive_sign_flip_margin_pass": sign_flip_pass,
    }
    if broad_gate["passed"] is not False or coverage_pass is not False:
        raise O1C111BreadcrumbSignAlignmentError(
            "two-coordinate result unexpectedly passes broad promotion"
        )

    diagnostic = _mapping(gates["two_coordinate_diagnostic"], "diagnostic gate")
    expected_unique = _integer(
        diagnostic["expected_unique_nonzero_coordinates"], "diagnostic coverage"
    )
    all_correct = (
        primary["evaluated_coordinate_count"] == expected_unique
        and primary["abstention_count"] == 0
        and primary["correct_count"] == expected_unique
    )
    classification = cast(
        str,
        diagnostic[
            "correct_classification" if all_correct else "mixed_or_wrong_classification"
        ],
    )
    unsigned = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "claim_level": "RETROSPECTIVE_DIAGNOSTIC",
        "classification": classification,
        "result_identity_rule": RESULT_IDENTITY_RULE,
        "score_freeze": dict(prepared.score_freeze),
        "score_freeze_sha256": prepared.score_freeze_sha256,
        "parent_census": prepared.score_freeze["parent_census"],
        "primary": primary,
        "secondary": secondary,
        "secondary_can_change_primary_classification": False,
        "broad_posterior_gate": broad_gate,
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
            "fresh_targets": 0,
            "gpu_calls": 0,
            "historical_reveal_file_reads": 1,
            "mps_calls": 0,
            "native_solver_calls": 0,
            "refits": 0,
            "science_solver_calls": 0,
        },
        "claim_boundary": {
            "attacker_valid_entropy_gain_bits": 0.0,
            "broad_posterior_authorized": False,
            "fresh_attacker_valid_claim": False,
            "fresh_replication_required": True,
            "historical_target_continuation_authorized": False,
            "independent_key_recovery": False,
            "o1c109_truth_key_bytes_read": 0,
            "posterior_bits_authorized": 0,
            "result_is_retrospective": True,
            "sota_claim": False,
            "two_coordinate_result_is_entropy_claim": False,
        },
        "next_action": prepared.config["next_action"],
    }
    return _attach_result_sha(unsigned)


def generate_breadcrumb_sign_alignment(
    config_path: str | Path = DEFAULT_CONFIG_RELATIVE,
    *,
    root: Path | None = None,
    truth_reader: TruthReader = _read_historical_truth,
) -> dict[str, object]:
    """Run the zero-solver historical diagnostic with enforced phase order."""

    prepared = prepare_breadcrumb_sign_alignment(config_path, root=root)
    return finalize_breadcrumb_sign_alignment(prepared, truth_reader=truth_reader)


def serialize_score_freeze(prepared: PreparedBreadcrumbAnalysis) -> bytes:
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
        raise O1C111BreadcrumbSignAlignmentError("result SHA-256 differs")
    if result.get("schema") != RESULT_SCHEMA:
        raise O1C111BreadcrumbSignAlignmentError("result schema differs")
    return canonical_json_bytes(result)


def _write_fresh(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = -1
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary = Path(name)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if path.exists():
            raise O1C111BreadcrumbSignAlignmentError(
                "refusing to overwrite an O1C111 artifact"
            )
        os.rename(temporary, path)
        temporary = None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_RELATIVE))
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--prepare-only",
        action="store_true",
        help="authenticate and serialize the pre-truth score freeze only",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    prepared = prepare_breadcrumb_sign_alignment(args.config)
    payload = (
        serialize_score_freeze(prepared)
        if args.prepare_only
        else serialize_result(finalize_breadcrumb_sign_alignment(prepared))
    )
    if args.output is None:
        os.write(1, payload)
    else:
        _write_fresh(args.output, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ATTEMPT_ID",
    "CONFIG_SCHEMA",
    "DEFAULT_CONFIG_RELATIVE",
    "HistoricalTruth",
    "O1C111BreadcrumbSignAlignmentError",
    "PreparedBreadcrumbAnalysis",
    "RESULT_SCHEMA",
    "SCORE_FREEZE_SCHEMA",
    "finalize_breadcrumb_sign_alignment",
    "generate_breadcrumb_sign_alignment",
    "load_config",
    "main",
    "prepare_breadcrumb_sign_alignment",
    "serialize_result",
    "serialize_score_freeze",
]
