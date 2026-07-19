#!/usr/bin/env python3
"""One-shot matched O1C61 versus APPLE-VIEW-0008 science lifecycle.

The runnable configuration is intentionally not self-authorizing.  A terminal,
successful O1C61 capsule must first be bound into the checked-in template with
the ``bind`` command.  Before the single native call this runner reads only the
O1C57 public view and O1C61's pre-call artifacts.  Baseline outcome telemetry
and committed truth bytes are opened only after the augmented native model has
received its independent eight-block public diagnostic.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import resource
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TypedDict, cast

from o1_crypto_lab.chacha_trace import chacha20_blocks
from o1_crypto_lab.criticality_potential import CriticalityPotentialField
from o1_crypto_lab.full256_broker import verify_reveal
from o1_crypto_lab.full256_cnf import (
    InstanceWriteReport,
    write_full256_instance,
)
from o1_crypto_lab.joint_score_sieve_v3 import (
    JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA,
    JOINT_SCORE_SIEVE_DECISION_RULE,
    JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS,
    JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT,
    JointScoreSieveResult,
    build_native_joint_score_sieve,
    run_joint_score_sieve,
    validate_soft_conflict_ledger,
)
from o1_crypto_lab.o1_relational_search import sha256_file

from apple_view_8_crossblock_consequences import (
    AppleView8Error,
    CrossblockConsequenceReport,
    preflight_o1c57_consumed_public_build,
    verify_crossblock_consequence_cnf,
    write_crossblock_consequence_cnf,
)


CONFIG_SCHEMA = "apple-view-0008-matched-joint-score-sieve-config-v1"
RESULT_SCHEMA = "apple-view-0008-matched-joint-score-sieve-result-v1"
PREFLIGHT_SCHEMA = "apple-view-0008-matched-joint-score-sieve-preflight-v1"
INTENT_SCHEMA = "apple-view-0008-matched-native-call-intent-v1"
BASELINE_ATTEMPT_ID = "O1C-0061"
BASELINE_RESULT_SCHEMA = "o1-256-multiblock-joint-score-sieve-soft-stop-result-v1"
BASELINE_INTENT_SCHEMA = (
    "o1-256-multiblock-joint-score-sieve-soft-stop-native-call-intent-v1"
)
BASELINE_PREFLIGHT_SCHEMA = (
    "o1-256-multiblock-joint-score-sieve-soft-stop-preflight-v1"
)
BASELINE_NATIVE_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v2"
ATTEMPT_ID = "APPLE-VIEW-0008-MATCHED"
CAPSULE_SUFFIX = "APPLE-VIEW-0008-MATCHED_crossblock-consequence-sieve-v1"
TEMPLATE_RELATIVE = Path(
    "research/apple_view_8/apple_view_8_matched_config.template.json"
)
AUTHORITATIVE_RELATIVE = Path(
    "research/apple_view_8/apple_view_8_matched_result.json"
)
O1C57_RELATIVE = Path(
    "runs/20260719_062932_O1C-0057_multiblock-parent-criticality-rank-v1"
)
BASELINE_CNF_RELATIVE = Path("artifacts/cnf/full256-eight-block.cnf")
BASELINE_CNF_REPORT_RELATIVE = Path(
    "artifacts/cnf/full256-eight-block.report.json"
)
BASELINE_SOURCE_REPORTS_RELATIVE = Path(
    "artifacts/cnf/source-block-reports.json"
)
BASELINE_POTENTIAL_RELATIVE = Path(
    "artifacts/potential/primary-eight-block.potential"
)
BASELINE_POTENTIAL_REPORT_RELATIVE = Path(
    "artifacts/potential/primary-eight-block.report.json"
)
BASELINE_NATIVE_RESULT_RELATIVE = Path("native_result.json")
BASELINE_NATIVE_BUILD_RELATIVE = Path("native_build.json")
BASELINE_INTENT_RELATIVE = Path("native_call_intent.json")
BASELINE_PREFLIGHT_RELATIVE = Path("preflight.json")
BASELINE_CONFLICT_LEDGER_RELATIVE = Path("conflict_ledger.json")
CONFLICT_LIMIT = 512
SEED = 0
TIMEOUT_SECONDS = 180.0
MEMORY_LIMIT_BYTES = 805_306_368
MAXIMUM_PERSISTENT_BYTES = 134_217_728
BOUND_TOLERANCE = 1e-12
BASELINE_THRESHOLD = 14.606178797892962
BASELINE_ROOT_UPPER_BOUND = 292.30611344510277
BASELINE_MINIMUM_UPPER_BOUND = 24.794446661138302
BASELINE_REMAINING_GAP = 10.18826786324534
BASELINE_ROOT_TO_MINIMUM_DROP = 267.5116667839645
BASELINE_REQUESTED_CONFLICTS = 512
BASELINE_CONFLICTS_BEFORE_SOLVE = 0
BASELINE_SOLVE_CONFLICTS = 513
BASELINE_CUMULATIVE_CONFLICTS = 513
BASELINE_UNUSED_REQUESTED_CONFLICTS = 0
BASELINE_CONFLICT_LIMIT_OVERSHOOT = 1
BASELINE_BILLED_CONFLICTS = 513
EXPECTED_CONSEQUENCE_COUNTS = {
    "direct_unit_clause_count": 2_048,
    "crossblock_relation_count": 56,
    "constant_lsb_one_relation_count": 24,
    "ripple_carry_variable_count": 1_792,
    "ripple_clause_count": 12_344,
    "augmentation_clause_count": 14_392,
    "variable_count": 257_024,
    "clause_count": 1_518_472,
}
EXPECTED_CONSEQUENCE_HASHES = {
    "final_wire_sha256": "be7191a42edb348b961c380c9b1cd2372d1d9c3feecd571840ad23a6d58adfec",
    "direct_unit_clause_sha256": "0c95981455808a8a85325f54149902698ff4684723c7ce460c937ea227302c0b",
    "ripple_clause_sha256": "175b89272348045c4dded0bc656021bf22b4f28795a8a9ca025a0d9ff814e8a8",
    "augmentation_sha256": "82a102d5a2f6edae3d5d7b674e93e7c120e069f5f638491e1e206d8ae57c2f68",
}
FROZEN_BASELINE_SOURCE_HASHES = {
    "broker_source": "1929006561400bb4091b39955a4b15cc73e492ab5b0bd56788afd58e6a28ea7e",
    "consumed_result": "bae7899503ec0d349dd7da51ebaca3cef2982c4e53d1ca560adcffe7bff47971",
    "criticality_potential": "343a0f62f4af8eebdfcfde4dfd2395055011a354698207f04ba02dc9fe57ad93",
    "full256_cnf": "76572366adbcadf1525cb25f4c84f5b78ff99be9b63acd721530e53532d9a0e0",
    "full256_forward_assignment": "d6793de3edec6cf1fb4b921f13f52cc072156c05aada7b9a3df37fe81b9f75a7",
    "full256_multiblock_cnf": "6501f9fc23b06462a178689c4470b1ce2218ee5d3154f459178df6bd1c9f58fb",
    "native_source": "c9ddc07d8d5ae22852ad7302ba9f8888cc86d3c04cf5fabf8c79a9eb8b28e91b",
    "native_base_source": "307e728e33ac1816119ace74ed2c2fa39616c48a93a78102adef8dbc5d4be5ac",
    "joint_score_sieve": "edf3e1d6d2571f4b8aa3c177f3beb68bf80cff5026a7f30a88d3a6bb05041d20",
    "joint_score_sieve_v2": "fcb02f28d9a391855d7650e3db24ad3814296a14f0a4b22f0f4af8ab41939366",
    "joint_score_sieve_base": "7d9428a99b1faa6bf83351c5e8a2e87a98accdb041d7861edcf0ec8a31c2fc7a",
    "runner": "5664b4adfccde50808a51b61dcaaf2ef5642d5c373251ecd423b60fa22a909d1",
    "mechanism_base_runner": "186b43a4e99ddf182d7a4af88c29984a6485021fb2d2964adc53c927a9385e04",
    "mechanism_transitive_base_runner": "ae6d3c60ce1b1eaf3f49767afad63bed7a8f618b43b57d45ff5d0598d7106c88",
    "multiblock_criticality_potential": "23239da9fa3e04781388afc35f249382291f490b9ec2abeb2e8043795e49ebc0",
    "proof_parent_criticality": "e142e0aceb621a87345baad801a456b7d3451613d98308e937f2c990dd1db056",
    "semantic_map": "7f7438a6277086787ff2cf9b6d7468367b4edd82a65b9cfc4f9249f7ecda3318",
    "template": "c293d36cab270b28ab2e89c073227fd50b75a6b357b9994d27c3acf7c01a0d52",
}
FROZEN_BASELINE_BINDING = {
    "attempt_id": BASELINE_ATTEMPT_ID,
    "required_result_schema": BASELINE_RESULT_SCHEMA,
    "native_result_schema": BASELINE_NATIVE_SCHEMA,
    "authoritative_result": "research/O1C0061_MULTIBLOCK_JOINT_SCORE_SIEVE_SOFT_STOP_RESULT_20260719.json",
    "capsule": "runs/20260719_091954_O1C-0061_multiblock-joint-score-sieve-soft-stop-v1",
    "source_commit": "6cc4397b3600232bd361db1777edc4a696eb0d31",
    "result_sha256": "100cde7911d9297170b63b2a095a4f0b7710b241bf25f1c8964fccca76758d7c",
    "manifest_sha256": "d37f58d70ddc99d4d0f7d6e1cf1dfe667b580397562f22bc517209e23b28c958",
    "cnf_sha256": "7d99d86b64fe1fdbf377f840260aeace79a35ef9ea703b2fb7fb36d4b5918a11",
    "cnf_bytes": 39_241_825,
    "cnf_report_sha256": "223dac499b54ef838d13bb9e2a0786c5756941bb51304b41451e27e096218f1d",
    "source_block_reports_sha256": "62e85e9367d252472491becf9767e679437a92e1e8d5391175534839525fb2e4",
    "potential_sha256": "8c6101b49c7050caf895bd9c496c05bcea9f43a2b27f378d7306be38b00d5390",
    "potential_bytes": 2_263_844,
    "potential_report_sha256": "200a52207e2b6040cc525cfb89393ec7a7fe6c166e88a3f7aa094cca84b0fa7b",
    "native_result_sha256": "acfe9bf0ace3bd6878d05281942e19afc6147150002017aced15894b5e2b4895",
    "native_build_sha256": "03eecfdb8fb61322db90b5fa80046e255b5c325ff5b9877d63e37b05a9bc0b3a",
    "native_call_intent_sha256": "ec3c98c36cc5a768b662206825988c849e04a5d2d2c9833e8d998caebd2ea748",
    "preflight_sha256": "580aaeb16e198e2186a486643de41a7d7b54114557d32e0ba9ebb1baf1258b77",
    "conflict_ledger_sha256": "81a7f6061439846690c9daa4546378a1a61fb8e873e730f0e435e373ea14dca1",
    "native_source_sha256": FROZEN_BASELINE_SOURCE_HASHES["native_source"],
    "native_executable_sha256": "07b132949ec11737b6de8004acb1ee48874812b975604f030865aad6a13b7024",
    "threshold": BASELINE_THRESHOLD,
    "requested_conflicts": BASELINE_REQUESTED_CONFLICTS,
    "maximum_conflict_limit_overshoot": 1,
    "maximum_billed_conflicts": 513,
    "seed": SEED,
    "timeout_seconds": TIMEOUT_SECONDS,
    "memory_limit_bytes": MEMORY_LIMIT_BYTES,
    "memory_limit_mechanism": "proc_pid_rusage-physical-footprint-process-group-watchdog",
    "conflicts_before_solve": BASELINE_CONFLICTS_BEFORE_SOLVE,
    "solve_conflicts": BASELINE_SOLVE_CONFLICTS,
    "cumulative_conflicts": BASELINE_CUMULATIVE_CONFLICTS,
    "unused_requested_conflicts": BASELINE_UNUSED_REQUESTED_CONFLICTS,
    "conflict_limit_overshoot": BASELINE_CONFLICT_LIMIT_OVERSHOOT,
    "billed_conflicts": BASELINE_BILLED_CONFLICTS,
    "root_upper_bound": BASELINE_ROOT_UPPER_BOUND,
    "minimum_upper_bound": BASELINE_MINIMUM_UPPER_BOUND,
    "remaining_gap": BASELINE_REMAINING_GAP,
    "root_to_minimum_bound_drop": BASELINE_ROOT_TO_MINIMUM_DROP,
    "trail_threshold_prunes": 0,
}
SOURCE_NAMES = (
    "runner",
    "compiler",
    "config_template",
    "native_source",
    "native_base_source",
    "joint_score_sieve",
    "joint_score_sieve_v2",
    "joint_score_sieve_base",
    "baseline_runner",
    "mechanism_base_runner",
    "mechanism_transitive_base_runner",
    "full256_cnf",
    "full256_multiblock_cnf",
    "full256_forward_assignment",
    "full256_broker",
    "chacha_trace",
    "criticality_potential",
)
SCIENCE_CLASSIFICATIONS = {
    "EXACT_CONSUMED_FULL256_RECOVERY",
    "EXACT_JOINT_SCORE_SIEVE_ACTIVE_NO_RECOVERY",
    "EXACT_JOINT_SCORE_SIEVE_NO_USEFUL_PRUNE",
}
_MANIFEST_ROW = re.compile(r"^([0-9a-f]{64})  ([^\n]+)$")


class AppleView8MatchedError(RuntimeError):
    """A frozen match, lifecycle boundary, or terminal artifact differs."""


@dataclass(frozen=True)
class BaselineArtifacts:
    capsule: Path
    authoritative_result: Path
    inventory: Mapping[str, str]
    cnf: Path
    cnf_report: Mapping[str, object]
    source_block_reports: tuple[Mapping[str, object], ...]
    potential: Path
    potential_report: Mapping[str, object]
    native_result: Path
    native_build: Mapping[str, object]
    intent: Mapping[str, object]
    preflight: Mapping[str, object]
    conflict_ledger: Path


@dataclass(frozen=True)
class PreparedRun:
    public_preflight: Mapping[str, object]
    source_instances: tuple[tuple[Path, InstanceWriteReport], ...]
    augmented_cnf: Path
    consequence_report_path: Path
    consequence_report: CrossblockConsequenceReport
    potential: CriticalityPotentialField
    native_executable: Path
    native_build: Mapping[str, object]


class _EffectMetrics(TypedDict):
    native_status: int
    trail_threshold_prunes: int
    model_threshold_prunes: int
    threshold_prunes: int
    maximum_assigned_observed_variables: int
    root_upper_bound: float
    minimum_upper_bound: float
    root_to_minimum_bound_drop: float
    remaining_gap_above_threshold: float


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise AppleView8MatchedError(f"{field} must be an object")
    return value


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise AppleView8MatchedError(f"{field} must be an array")
    return value


def _validate_frozen_baseline_source_hashes(
    value: object,
) -> Mapping[str, object]:
    source_hashes = _mapping(value, "baseline source hashes")
    if dict(source_hashes) != FROZEN_BASELINE_SOURCE_HASHES:
        raise AppleView8MatchedError("complete O1C61 source hash map differs")
    return source_hashes


def _read_json(path: Path, field: str) -> object:
    raw = path.read_bytes()

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise AppleView8MatchedError(f"duplicate {field} JSON key")
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AppleView8MatchedError(f"{field} is not valid JSON") from exc


def _read_mapping(path: Path, field: str) -> Mapping[str, object]:
    return _mapping(_read_json(path, field), field)


def _pretty_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            indent=2,
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _atomic_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(path)
    descriptor, raw = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(raw)
    linked = False
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path, follow_symlinks=False)
        linked = True
        temporary.unlink()
        parent = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        if linked:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        raise


def _atomic_json(path: Path, value: object) -> None:
    _atomic_bytes(path, _pretty_json_bytes(value))


def _replace_owned_bytes(path: Path, payload: bytes) -> None:
    descriptor, raw = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(raw)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def _replace_owned_json(path: Path, value: object) -> None:
    _replace_owned_bytes(path, _pretty_json_bytes(value))


def _copy_exclusive(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise FileExistsError(destination)
    descriptor, raw = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    os.close(descriptor)
    temporary = Path(raw)
    try:
        shutil.copyfile(source, temporary)
        if sha256_file(source) != sha256_file(temporary):
            raise AppleView8MatchedError("exclusive copy hash differs")
        os.link(temporary, destination, follow_symlinks=False)
        temporary.unlink()
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def _relative(root: Path, value: object, field: str, *, must_exist: bool = True) -> Path:
    if not isinstance(value, str) or not value:
        raise AppleView8MatchedError(f"{field} path differs")
    candidate = (root / value).resolve(strict=must_exist)
    if not candidate.is_relative_to(root):
        raise AppleView8MatchedError(f"{field} escapes the lab")
    return candidate


def _git_commit(root: Path) -> str:
    completed = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    value = completed.stdout.strip()
    if len(value) != 40 or any(character not in "0123456789abcdef" for character in value):
        raise AppleView8MatchedError("source commit differs")
    return value


def _commit_bound(root: Path, commit: str, path: Path, field: str) -> None:
    relative = path.relative_to(root).as_posix()
    completed = subprocess.run(
        ("git", "show", f"{commit}:{relative}"),
        cwd=root,
        check=False,
        capture_output=True,
    )
    if completed.returncode or completed.stdout != path.read_bytes():
        raise AppleView8MatchedError(f"{field} differs from required source commit")


def _require_ancestor(root: Path, ancestor: str, descendant: str) -> None:
    completed = subprocess.run(
        ("git", "merge-base", "--is-ancestor", ancestor, descendant),
        cwd=root,
        check=False,
        capture_output=True,
    )
    if completed.returncode:
        raise AppleView8MatchedError("required source commit is not an ancestor")


def _manifest_inventory(capsule: Path, expected_sha256: str) -> dict[str, str]:
    manifest = capsule / "artifacts.sha256"
    if sha256_file(manifest) != expected_sha256:
        raise AppleView8MatchedError("terminal baseline manifest hash differs")
    inventory: dict[str, str] = {}
    for row in manifest.read_text("ascii").splitlines():
        matched = _MANIFEST_ROW.fullmatch(row)
        if matched is None:
            raise AppleView8MatchedError("terminal baseline manifest row differs")
        digest, relative = matched.groups()
        relative_path = Path(relative)
        if (
            relative in inventory
            or relative_path.is_absolute()
            or ".." in relative_path.parts
            or relative == "artifacts.sha256"
        ):
            raise AppleView8MatchedError("terminal baseline manifest inventory differs")
        path = (capsule / relative_path).resolve(strict=True)
        if (
            not path.is_relative_to(capsule)
            or not path.is_file()
            or path.is_symlink()
            or sha256_file(path) != digest
        ):
            raise AppleView8MatchedError(f"terminal baseline artifact differs: {relative}")
        inventory[relative] = digest
    observed = {
        path.relative_to(capsule).as_posix()
        for path in capsule.rglob("*")
        if path.is_file()
    }
    if observed != {*inventory, "artifacts.sha256"}:
        raise AppleView8MatchedError("terminal baseline inventory has unbound files")
    return inventory


def _assert_immutable_capsule(capsule: Path) -> None:
    for path in (capsule, *capsule.rglob("*")):
        if path.stat(follow_symlinks=False).st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
            raise AppleView8MatchedError("terminal baseline capsule is writable")


def _artifact(
    capsule: Path,
    inventory: Mapping[str, str],
    relative: Path,
    expected: object,
) -> Path:
    name = relative.as_posix()
    path = (capsule / relative).resolve(strict=True)
    if inventory.get(name) != expected or sha256_file(path) != expected:
        raise AppleView8MatchedError(f"baseline artifact binding differs: {name}")
    return path


def _baseline_artifacts(
    root: Path, config: Mapping[str, object]
) -> BaselineArtifacts:
    baseline = _mapping(config.get("baseline"), "baseline")
    capsule = _relative(root, baseline.get("capsule"), "baseline.capsule")
    authoritative = _relative(
        root, baseline.get("authoritative_result"), "baseline.authoritative_result"
    )
    if not capsule.is_dir() or not _is_sha256(baseline.get("manifest_sha256")):
        raise AppleView8MatchedError("terminal baseline binding differs")
    inventory = _manifest_inventory(capsule, str(baseline["manifest_sha256"]))
    _assert_immutable_capsule(capsule)
    capsule_result = _artifact(
        capsule, inventory, Path("result.json"), baseline.get("result_sha256")
    )
    if (
        sha256_file(authoritative) != baseline.get("result_sha256")
        or authoritative.read_bytes() != capsule_result.read_bytes()
        or "native_failure.json" in inventory
    ):
        raise AppleView8MatchedError("successful terminal baseline result differs")
    cnf = _artifact(
        capsule, inventory, BASELINE_CNF_RELATIVE, baseline.get("cnf_sha256")
    )
    cnf_report_path = _artifact(
        capsule,
        inventory,
        BASELINE_CNF_REPORT_RELATIVE,
        baseline.get("cnf_report_sha256"),
    )
    source_reports_path = _artifact(
        capsule,
        inventory,
        BASELINE_SOURCE_REPORTS_RELATIVE,
        baseline.get("source_block_reports_sha256"),
    )
    potential = _artifact(
        capsule,
        inventory,
        BASELINE_POTENTIAL_RELATIVE,
        baseline.get("potential_sha256"),
    )
    potential_report_path = _artifact(
        capsule,
        inventory,
        BASELINE_POTENTIAL_REPORT_RELATIVE,
        baseline.get("potential_report_sha256"),
    )
    native_result = _artifact(
        capsule,
        inventory,
        BASELINE_NATIVE_RESULT_RELATIVE,
        baseline.get("native_result_sha256"),
    )
    native_build_path = _artifact(
        capsule,
        inventory,
        BASELINE_NATIVE_BUILD_RELATIVE,
        baseline.get("native_build_sha256"),
    )
    intent_path = _artifact(
        capsule,
        inventory,
        BASELINE_INTENT_RELATIVE,
        baseline.get("native_call_intent_sha256"),
    )
    preflight_path = _artifact(
        capsule,
        inventory,
        BASELINE_PREFLIGHT_RELATIVE,
        baseline.get("preflight_sha256"),
    )
    conflict_ledger = _artifact(
        capsule,
        inventory,
        BASELINE_CONFLICT_LEDGER_RELATIVE,
        baseline.get("conflict_ledger_sha256"),
    )
    cnf_report = _read_mapping(cnf_report_path, "baseline CNF report")
    source_rows = _sequence(
        _read_json(source_reports_path, "baseline source reports"),
        "baseline source reports",
    )
    source_reports = tuple(
        _mapping(row, f"baseline source report {index}")
        for index, row in enumerate(source_rows)
    )
    potential_report = _read_mapping(
        potential_report_path, "baseline potential report"
    )
    native_build = _read_mapping(native_build_path, "baseline native build")
    intent = _read_mapping(intent_path, "baseline native intent")
    preflight = _read_mapping(preflight_path, "baseline preflight")
    if (
        len(source_reports) != 8
        or cnf_report.get("instance_sha256") != baseline.get("cnf_sha256")
        or cnf_report.get("variable_count") != 255_232
        or cnf_report.get("clause_count") != 1_504_080
        or cnf_report.get("key_unit_clause_count") != 0
        or cnf_report.get("assumption_unit_clause_count") != 0
        or potential_report.get("state_sha256") != baseline.get("potential_sha256")
        or native_build.get("source_sha256") != baseline.get("native_source_sha256")
        or native_build.get("executable_sha256")
        != baseline.get("native_executable_sha256")
        or intent.get("schema") != BASELINE_INTENT_SCHEMA
        or intent.get("attempt_id") != BASELINE_ATTEMPT_ID
        or intent.get("cnf_sha256") != baseline.get("cnf_sha256")
        or intent.get("potential_sha256") != baseline.get("potential_sha256")
        or intent.get("native_executable_sha256")
        != baseline.get("native_executable_sha256")
        or intent.get("threshold") != baseline.get("threshold")
        or intent.get("requested_conflicts")
        != baseline.get("requested_conflicts")
        or intent.get("maximum_conflict_limit_overshoot")
        != baseline.get("maximum_conflict_limit_overshoot")
        or intent.get("maximum_billed_conflicts")
        != baseline.get("maximum_billed_conflicts")
        or intent.get("seed") != baseline.get("seed")
        or intent.get("timeout_seconds") != baseline.get("timeout_seconds")
        or intent.get("memory_limit_bytes") != baseline.get("memory_limit_bytes")
        or preflight.get("schema") != BASELINE_PREFLIGHT_SCHEMA
        or preflight.get("native_memory_enforcement")
        != baseline.get("memory_limit_mechanism")
    ):
        raise AppleView8MatchedError("baseline pre-call contract differs")
    return BaselineArtifacts(
        capsule=capsule,
        authoritative_result=authoritative,
        inventory=inventory,
        cnf=cnf,
        cnf_report=cnf_report,
        source_block_reports=source_reports,
        potential=potential,
        potential_report=potential_report,
        native_result=native_result,
        native_build=native_build,
        intent=intent,
        preflight=preflight,
        conflict_ledger=conflict_ledger,
    )


def _validate_template_contract(config: Mapping[str, object]) -> None:
    baseline = _mapping(config.get("baseline"), "baseline")
    public = _mapping(config.get("consumed_public"), "consumed_public")
    consequences = _mapping(config.get("consequences"), "consequences")
    native = _mapping(config.get("matched_native"), "matched_native")
    classification = _mapping(config.get("classification"), "classification")
    lifecycle = _mapping(config.get("lifecycle"), "lifecycle")
    budgets = _mapping(config.get("budgets"), "budgets")
    source = _mapping(config.get("source"), "source")
    if (
        config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or config.get("slug") != "crossblock-consequence-matched-joint-score-sieve-v1"
        or config.get("claim_level") != "TEST"
        or any(
            baseline.get(name) != value
            for name, value in FROZEN_BASELINE_BINDING.items()
        )
        or set(baseline) != {*FROZEN_BASELINE_BINDING, "source_sha256"}
        or _mapping(
            baseline.get("source_sha256"), "baseline.source_sha256"
        )
        != FROZEN_BASELINE_SOURCE_HASHES
        or public.get("attempt_id") != "O1C-0057"
        or public.get("capsule") != O1C57_RELATIVE.as_posix()
        or public.get("manifest_sha256")
        != "008b985868b18160711be70cc9fa2a7697d5888c5515702caef72228ea2a742e"
        or public.get("block_count") != 8
        or public.get("unknown_key_bits") != 256
        or any(public.get(name) != 0 for name in ("fresh_targets", "scientific_entropy_calls", "fresh_reveal_calls", "refits"))
        or any(consequences.get(name) != value for name, value in EXPECTED_CONSEQUENCE_COUNTS.items())
        or any(consequences.get(name) != value for name, value in EXPECTED_CONSEQUENCE_HASHES.items())
        or consequences.get("append_only_after_byte_identical_baseline_body") is not True
        or consequences.get("key_unit_clause_count") != 0
        or consequences.get("assumption_unit_clause_count") != 0
        or consequences.get("target_key_included") is not False
        or consequences.get("target_trace_included") is not False
        or native.get("calls") != 1
        or native.get("requested_conflicts") != CONFLICT_LIMIT
        or native.get("maximum_conflict_limit_overshoot")
        != JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT
        or native.get("maximum_billed_conflicts")
        != JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS
        or native.get("soft_conflict_ledger_schema")
        != JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA
        or native.get("seed") != SEED
        or native.get("timeout_seconds") != TIMEOUT_SECONDS
        or native.get("memory_limit_bytes") != MEMORY_LIMIT_BYTES
        or any(
            native.get(name) is not True
            for name in (
                "same_baseline_cnf_body_bytes",
                "same_potential_bytes",
                "same_threshold_bits",
                "same_native_source_and_executable",
                "same_memory_enforcement",
                "solver_owned_decisions",
                "cumulative_conflicts_are_not_requested_budget",
                "conflicts_before_solve_may_differ",
                "end_to_end_time_is_contextual_not_causal",
                "bound_effect_requires_matched_billed_work",
            )
        )
        or classification.get("exact")
        != "APPLE_VIEW_0008_EXACT_PUBLIC_FULL256_RECOVERY"
        or classification.get("incremental")
        != "APPLE_VIEW_0008_STRICT_INCREMENTAL_EFFECT_NO_RECOVERY"
        or classification.get("none") != "APPLE_VIEW_0008_NO_INCREMENTAL_EFFECT"
        or classification.get("operational_failure")
        != "APPLE_VIEW_0008_OPERATIONAL_FAILURE_NO_SCIENCE_RESULT"
        or classification.get("bound_comparison_absolute_tolerance")
        != BOUND_TOLERANCE
        or classification.get("baseline_remaining_gap")
        != BASELINE_REMAINING_GAP
        or classification.get("baseline_root_to_minimum_bound_drop")
        != BASELINE_ROOT_TO_MINIMUM_DROP
        or classification.get("safe_trail_prune_gate")
        != "trail_threshold_prunes>0; count only, not earlier-without-telemetry"
        or any(
            lifecycle.get(name) is not True
            for name in (
                "terminal_baseline_required",
                "baseline_operational_failure_rejected",
                "persist_intent_before_native_call",
                "post_intent_failures_are_terminal",
                "public_model_diagnostic_before_truth_read",
                "immutable_capsule",
            )
        )
        or lifecycle.get("retry_after_consumed_call") is not False
        or budgets.get("maximum_native_solver_calls") != 1
        or budgets.get("maximum_requested_conflicts") != CONFLICT_LIMIT
        or budgets.get("maximum_billed_conflicts")
        != JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS
        or budgets.get("maximum_native_wall_seconds") != TIMEOUT_SECONDS
        or budgets.get("maximum_peak_rss_bytes") != MEMORY_LIMIT_BYTES
        or budgets.get("minimum_memory_pressure_free_percent") != 15
        or budgets.get("maximum_fresh_targets") != 0
        or budgets.get("maximum_scientific_entropy_calls") != 0
        or budgets.get("maximum_fresh_reveal_calls") != 0
        or budgets.get("maximum_refits") != 0
        or budgets.get("maximum_mps_calls") != 0
        or budgets.get("maximum_gpu_calls") != 0
        or budgets.get("maximum_persistent_artifact_bytes")
        != MAXIMUM_PERSISTENT_BYTES
        or tuple(name for name in SOURCE_NAMES if source.get(name) is None)
        or config.get("authoritative_result") != AUTHORITATIVE_RELATIVE.as_posix()
    ):
        raise AppleView8MatchedError("matched config template contract differs")


def load_config(path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_path = Path(path).resolve(strict=True)
    if not config_path.is_relative_to(root):
        raise AppleView8MatchedError("matched config escapes lab")
    config = dict(_read_mapping(config_path, "matched config"))
    _validate_template_contract(config)
    if config.get("ready_for_science") is not True:
        raise AppleView8MatchedError("matched config awaits immutable O1C61 binding")
    baseline = _mapping(config.get("baseline"), "baseline")
    source = _mapping(config.get("source"), "source")
    expected = _mapping(source.get("expected_sha256"), "source.expected_sha256")
    dynamic_hashes = (
        "result_sha256",
        "manifest_sha256",
        "cnf_sha256",
        "cnf_report_sha256",
        "source_block_reports_sha256",
        "potential_sha256",
        "potential_report_sha256",
        "native_result_sha256",
        "native_build_sha256",
        "native_call_intent_sha256",
        "preflight_sha256",
        "conflict_ledger_sha256",
        "native_source_sha256",
        "native_executable_sha256",
    )
    if (
        baseline.get("attempt_id") != BASELINE_ATTEMPT_ID
        or baseline.get("required_result_schema") != BASELINE_RESULT_SCHEMA
        or baseline.get("native_result_schema") != BASELINE_NATIVE_SCHEMA
        or any(not _is_sha256(baseline.get(name)) for name in dynamic_hashes)
        or not _is_int(baseline.get("cnf_bytes"))
        or cast(int, baseline["cnf_bytes"]) <= 0
        or not _is_int(baseline.get("potential_bytes"))
        or cast(int, baseline["potential_bytes"]) <= 0
        or not isinstance(baseline.get("threshold"), (int, float))
        or isinstance(baseline.get("threshold"), bool)
        or not math.isfinite(float(cast(float, baseline["threshold"])))
        or baseline.get("requested_conflicts") != CONFLICT_LIMIT
        or baseline.get("maximum_conflict_limit_overshoot")
        != JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT
        or baseline.get("maximum_billed_conflicts")
        != JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS
        or baseline.get("seed") != SEED
        or baseline.get("timeout_seconds") != TIMEOUT_SECONDS
        or baseline.get("memory_limit_bytes") != MEMORY_LIMIT_BYTES
        or baseline.get("memory_limit_mechanism")
        not in (
            "child-RLIMIT_AS-before-exec",
            "proc_pid_rusage-physical-footprint-process-group-watchdog",
        )
        or set(expected) != set(SOURCE_NAMES)
        or any(not _is_sha256(value) for value in expected.values())
        or not isinstance(source.get("required_source_commit"), str)
        or len(str(source.get("required_source_commit"))) != 40
    ):
        raise AppleView8MatchedError("terminal baseline binding fields differ")
    commit = str(source["required_source_commit"])
    current_commit = _git_commit(root)
    _require_ancestor(root, commit, current_commit)
    for name in SOURCE_NAMES:
        source_path = _relative(root, source[name], f"source.{name}")
        if sha256_file(source_path) != expected[name]:
            raise AppleView8MatchedError(f"matched source hash differs: {name}")
        _commit_bound(root, commit, source_path, name)
    _commit_bound(root, current_commit, config_path, "bound config")
    return config


def config_preflight(path: str | Path) -> dict[str, object]:
    config_path = Path(path).resolve(strict=True)
    config = dict(_read_mapping(config_path, "matched config"))
    _validate_template_contract(config)
    if config.get("ready_for_science") is not True:
        return {
            "schema": PREFLIGHT_SCHEMA,
            "ok": False,
            "status": "WAITING_FOR_IMMUTABLE_O1C61_SOURCE_BINDING",
            "ready_for_science": False,
            "native_solver_calls": 0,
            "fresh_targets": 0,
            "scientific_entropy_calls": 0,
            "fresh_reveal_calls": 0,
            "files_written": 0,
        }
    loaded = load_config(config_path)
    baseline = _baseline_artifacts(lab_root().resolve(strict=True), loaded)
    return {
        "schema": PREFLIGHT_SCHEMA,
        "ok": True,
        "status": "TERMINAL_O1C61_BOUND_BUILD_NOT_STARTED",
        "ready_for_science": True,
        "baseline_manifest_sha256": loaded["baseline"]["manifest_sha256"],  # type: ignore[index]
        "baseline_cnf_sha256": sha256_file(baseline.cnf),
        "baseline_potential_sha256": sha256_file(baseline.potential),
        "native_solver_calls": 0,
        "fresh_targets": 0,
        "scientific_entropy_calls": 0,
        "fresh_reveal_calls": 0,
        "files_written": 0,
    }


def _terminal_baseline_binding(
    root: Path, authoritative_result: Path, capsule: Path
) -> dict[str, object]:
    if not authoritative_result.is_relative_to(root) or not capsule.is_relative_to(root):
        raise AppleView8MatchedError("baseline binding escapes lab")
    manifest = capsule / "artifacts.sha256"
    manifest_sha = sha256_file(manifest)
    inventory = _manifest_inventory(capsule, manifest_sha)
    _assert_immutable_capsule(capsule)
    result = _read_mapping(authoritative_result, "authoritative O1C61 result")
    capsule_result = capsule / "result.json"
    result_sha = sha256_file(authoritative_result)
    if (
        result.get("schema") != BASELINE_RESULT_SCHEMA
        or result.get("attempt_id") != BASELINE_ATTEMPT_ID
        or result.get("classification") not in SCIENCE_CLASSIFICATIONS
        or result.get("capsule") != capsule.relative_to(root).as_posix()
        or sha256_file(capsule_result) != result_sha
        or capsule_result.read_bytes() != authoritative_result.read_bytes()
        or inventory.get("result.json") != result_sha
        or "native_failure.json" in inventory
        or BASELINE_NATIVE_RESULT_RELATIVE.as_posix() not in inventory
    ):
        raise AppleView8MatchedError(
            "O1C61 is not the successful terminal science baseline"
        )
    intent_path = capsule / BASELINE_INTENT_RELATIVE
    native_build_path = capsule / BASELINE_NATIVE_BUILD_RELATIVE
    preflight_path = capsule / BASELINE_PREFLIGHT_RELATIVE
    cnf_path = capsule / BASELINE_CNF_RELATIVE
    cnf_report_path = capsule / BASELINE_CNF_REPORT_RELATIVE
    source_reports_path = capsule / BASELINE_SOURCE_REPORTS_RELATIVE
    potential_path = capsule / BASELINE_POTENTIAL_RELATIVE
    potential_report_path = capsule / BASELINE_POTENTIAL_REPORT_RELATIVE
    native_result_path = capsule / BASELINE_NATIVE_RESULT_RELATIVE
    conflict_ledger_path = capsule / BASELINE_CONFLICT_LEDGER_RELATIVE
    intent = _read_mapping(intent_path, "baseline intent")
    native_build = _read_mapping(native_build_path, "baseline native build")
    preflight = _read_mapping(preflight_path, "baseline preflight")
    native_result = _read_mapping(native_result_path, "baseline native result")
    persisted_ledger = _read_mapping(
        conflict_ledger_path, "baseline soft conflict ledger"
    )
    source_sha = _validate_frozen_baseline_source_hashes(
        result.get("source_sha256")
    )
    resources = _mapping(result.get("resources"), "baseline resources")
    sieve = _mapping(native_result.get("sieve"), "baseline native sieve")
    try:
        ledger = validate_soft_conflict_ledger(
            {key: value for key, value in persisted_ledger.items() if key != "schema"}
        )
    except Exception as exc:
        raise AppleView8MatchedError("O1C61 soft conflict ledger differs") from exc
    remaining_gap = float(cast(float, sieve.get("minimum_upper_bound"))) - float(
        cast(float, intent.get("threshold"))
    )
    bound_drop = float(cast(float, sieve.get("root_upper_bound"))) - float(
        cast(float, sieve.get("minimum_upper_bound"))
    )
    if (
        intent.get("schema") != BASELINE_INTENT_SCHEMA
        or intent.get("attempt_id") != BASELINE_ATTEMPT_ID
        or intent.get("requested_conflicts") != CONFLICT_LIMIT
        or intent.get("maximum_conflict_limit_overshoot")
        != JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT
        or intent.get("maximum_billed_conflicts")
        != JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS
        or intent.get("seed") != SEED
        or intent.get("timeout_seconds") != TIMEOUT_SECONDS
        or intent.get("memory_limit_bytes") != MEMORY_LIMIT_BYTES
        or intent.get("cnf_sha256") != sha256_file(cnf_path)
        or intent.get("potential_sha256") != sha256_file(potential_path)
        or intent.get("native_executable_sha256")
        != native_build.get("executable_sha256")
        or source_sha.get("native_source") != native_build.get("source_sha256")
        or preflight.get("schema") != BASELINE_PREFLIGHT_SCHEMA
        or preflight.get("native_memory_limit_bytes") != MEMORY_LIMIT_BYTES
        or native_result.get("schema") != BASELINE_NATIVE_SCHEMA
        or persisted_ledger.get("schema")
        != JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA
        or result.get("native") != native_result
        or result.get("conflict_ledger") != persisted_ledger
        or resources.get("native_solver_calls") != 1
        or resources.get("native_memory_limit_bytes") != MEMORY_LIMIT_BYTES
        or ledger["requested_conflicts"] != BASELINE_REQUESTED_CONFLICTS
        or ledger["conflicts_before_solve"] != BASELINE_CONFLICTS_BEFORE_SOLVE
        or ledger["solve_conflicts"] != BASELINE_SOLVE_CONFLICTS
        or ledger["conflicts"] != BASELINE_CUMULATIVE_CONFLICTS
        or ledger["unused_requested_conflicts"]
        != BASELINE_UNUSED_REQUESTED_CONFLICTS
        or ledger["conflict_limit_overshoot"]
        != BASELINE_CONFLICT_LIMIT_OVERSHOOT
        or ledger["billed_conflicts"] != BASELINE_BILLED_CONFLICTS
        or sieve.get("root_upper_bound") != BASELINE_ROOT_UPPER_BOUND
        or sieve.get("minimum_upper_bound") != BASELINE_MINIMUM_UPPER_BOUND
        or sieve.get("trail_threshold_prunes") != 0
        or remaining_gap != BASELINE_REMAINING_GAP
        or bound_drop != BASELINE_ROOT_TO_MINIMUM_DROP
    ):
        raise AppleView8MatchedError("O1C61 matched native contract differs")
    binding: dict[str, object] = {
        "attempt_id": BASELINE_ATTEMPT_ID,
        "required_result_schema": BASELINE_RESULT_SCHEMA,
        "native_result_schema": BASELINE_NATIVE_SCHEMA,
        "authoritative_result": authoritative_result.relative_to(root).as_posix(),
        "capsule": capsule.relative_to(root).as_posix(),
        "source_commit": result.get("source_commit"),
        "result_sha256": result_sha,
        "manifest_sha256": manifest_sha,
        "cnf_sha256": sha256_file(cnf_path),
        "cnf_bytes": cnf_path.stat().st_size,
        "cnf_report_sha256": sha256_file(cnf_report_path),
        "source_block_reports_sha256": sha256_file(source_reports_path),
        "potential_sha256": sha256_file(potential_path),
        "potential_bytes": potential_path.stat().st_size,
        "potential_report_sha256": sha256_file(potential_report_path),
        "native_result_sha256": sha256_file(native_result_path),
        "native_build_sha256": sha256_file(native_build_path),
        "native_call_intent_sha256": sha256_file(intent_path),
        "preflight_sha256": sha256_file(preflight_path),
        "conflict_ledger_sha256": sha256_file(conflict_ledger_path),
        "native_source_sha256": native_build.get("source_sha256"),
        "native_executable_sha256": native_build.get("executable_sha256"),
        "threshold": intent.get("threshold"),
        "requested_conflicts": intent.get("requested_conflicts"),
        "maximum_conflict_limit_overshoot": intent.get(
            "maximum_conflict_limit_overshoot"
        ),
        "maximum_billed_conflicts": intent.get("maximum_billed_conflicts"),
        "seed": intent.get("seed"),
        "timeout_seconds": intent.get("timeout_seconds"),
        "memory_limit_bytes": intent.get("memory_limit_bytes"),
        "memory_limit_mechanism": preflight.get("native_memory_enforcement"),
        "conflicts_before_solve": ledger["conflicts_before_solve"],
        "solve_conflicts": ledger["solve_conflicts"],
        "cumulative_conflicts": ledger["conflicts"],
        "unused_requested_conflicts": ledger["unused_requested_conflicts"],
        "conflict_limit_overshoot": ledger["conflict_limit_overshoot"],
        "billed_conflicts": ledger["billed_conflicts"],
        "root_upper_bound": sieve["root_upper_bound"],
        "minimum_upper_bound": sieve["minimum_upper_bound"],
        "remaining_gap": remaining_gap,
        "root_to_minimum_bound_drop": bound_drop,
        "trail_threshold_prunes": sieve["trail_threshold_prunes"],
        "source_sha256": dict(FROZEN_BASELINE_SOURCE_HASHES),
    }
    if any(binding.get(name) != value for name, value in FROZEN_BASELINE_BINDING.items()):
        raise AppleView8MatchedError("O1C61 frozen baseline binding differs")
    return binding


def bind_terminal_o1c61(
    template_path: str | Path,
    authoritative_result_path: str | Path,
    capsule_path: str | Path,
    destination_path: str | Path,
) -> dict[str, object]:
    """Materialize the runnable config from the one frozen terminal O1C61."""

    root = lab_root().resolve(strict=True)
    template = Path(template_path).resolve(strict=True)
    result = Path(authoritative_result_path).resolve(strict=True)
    capsule = Path(capsule_path).resolve(strict=True)
    destination = Path(destination_path).resolve()
    if not all(path.is_relative_to(root) for path in (template, result, capsule, destination)):
        raise AppleView8MatchedError("binding path escapes lab")
    if destination in (template, result) or destination.exists():
        raise AppleView8MatchedError("binding destination differs")
    document = dict(_read_mapping(template, "matched config template"))
    _validate_template_contract(document)
    if document.get("ready_for_science") is not False:
        raise AppleView8MatchedError("matched template is already bound")
    binding = _terminal_baseline_binding(root, result, capsule)
    if binding != dict(_mapping(document["baseline"], "baseline")):
        raise AppleView8MatchedError("template is not pinned to this exact O1C61")
    source = dict(_mapping(document["source"], "source"))
    commit = _git_commit(root)
    expected: dict[str, str] = {}
    for name in SOURCE_NAMES:
        path = _relative(root, source[name], f"source.{name}")
        _commit_bound(root, commit, path, name)
        expected[name] = sha256_file(path)
    baseline_sources = _mapping(binding["source_sha256"], "baseline source hashes")
    source_correspondence = {
        "native_source": "native_source",
        "native_base_source": "native_base_source",
        "joint_score_sieve": "joint_score_sieve",
        "joint_score_sieve_v2": "joint_score_sieve_v2",
        "joint_score_sieve_base": "joint_score_sieve_base",
        "baseline_runner": "runner",
        "mechanism_base_runner": "mechanism_base_runner",
        "mechanism_transitive_base_runner": "mechanism_transitive_base_runner",
        "full256_cnf": "full256_cnf",
        "full256_multiblock_cnf": "full256_multiblock_cnf",
        "full256_forward_assignment": "full256_forward_assignment",
        "criticality_potential": "criticality_potential",
        "full256_broker": "broker_source",
    }
    if any(
        expected[local] != baseline_sources[upstream]
        for local, upstream in source_correspondence.items()
    ):
        raise AppleView8MatchedError("current transitive source differs from O1C61")
    source["required_source_commit"] = commit
    source["expected_sha256"] = expected
    document["source"] = source
    document["baseline"] = binding
    document["ready_for_science"] = True
    _atomic_json(destination, document)
    return document


def _memory_free_percent() -> int | None:
    executable = Path("/usr/bin/memory_pressure")
    if not executable.is_file():
        return None
    completed = subprocess.run(
        (str(executable), "-Q"),
        check=False,
        capture_output=True,
        text=True,
        timeout=10.0,
    )
    matched = re.search(
        r"System-wide memory free percentage:\s*([0-9]{1,3})%",
        completed.stdout,
    )
    if completed.returncode or matched is None:
        raise AppleView8MatchedError("memory-pressure preflight differs")
    value = int(matched.group(1))
    if not 0 <= value <= 100:
        raise AppleView8MatchedError("memory-pressure percentage differs")
    return value


def _peak_rss_bytes() -> int:
    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(raw if sys.platform == "darwin" else raw * 1024)


def _prepare_run(
    root: Path,
    config: Mapping[str, object],
    baseline: BaselineArtifacts,
    workspace: Path,
) -> PreparedRun:
    public_preflight = preflight_o1c57_consumed_public_build(root / O1C57_RELATIVE)
    template = Path(str(public_preflight["template_path"])).resolve(strict=True)
    semantic_map = Path(str(public_preflight["semantic_map_path"])).resolve(strict=True)
    outputs = tuple(
        bytes.fromhex(str(value))
        for value in _sequence(public_preflight["output_blocks_hex"], "public outputs")
    )
    counters = tuple(
        cast(int, value)
        for value in _sequence(public_preflight["counters"], "public counters")
    )
    nonce = bytes.fromhex(str(public_preflight["nonce_hex"]))
    instances: list[tuple[Path, InstanceWriteReport]] = []
    for index, expected_report in enumerate(baseline.source_block_reports):
        path = workspace / f"source-block-{index:02d}.cnf"
        report = write_full256_instance(
            template,
            semantic_map,
            path,
            counter=counters[index],
            nonce=nonce,
            output=outputs[index],
        )
        if report.describe() != dict(expected_report):
            raise AppleView8MatchedError("rebuilt public block differs from O1C61")
        instances.append((path, report))
    augmented = workspace / "full256-eight-block-apple-view-0008.cnf"
    consequence_report_path = workspace / "full256-eight-block-apple-view-0008.report.json"
    try:
        consequence_report = write_crossblock_consequence_cnf(
            baseline.cnf,
            baseline.cnf_report,
            template,
            semantic_map,
            tuple(instances),
            augmented,
            output_blocks=outputs,
            counters=counters,
            nonce=nonce,
            report_path=consequence_report_path,
        )
        verification = verify_crossblock_consequence_cnf(
            augmented,
            baseline.cnf,
            baseline.cnf_report,
            template,
            semantic_map,
            tuple(instances),
            consequence_report_path,
            output_blocks=outputs,
            counters=counters,
            nonce=nonce,
        )
    except AppleView8Error as exc:
        raise AppleView8MatchedError("cross-block consequence build differs") from exc
    consequences = _mapping(config["consequences"], "consequences")
    report_values = consequence_report.describe()
    if (
        verification.get("ok") is not True
        or consequence_report.source_instance_sha256 != sha256_file(baseline.cnf)
        or any(report_values.get(name) != consequences.get(name) for name in EXPECTED_CONSEQUENCE_COUNTS)
        or any(report_values.get(name) != consequences.get(name) for name in EXPECTED_CONSEQUENCE_HASHES)
        or consequence_report.key_unit_clause_count != 0
        or consequence_report.assumption_unit_clause_count != 0
    ):
        raise AppleView8MatchedError("frozen consequence counts or hashes differ")
    potential = CriticalityPotentialField.from_bytes(baseline.potential.read_bytes())
    if (
        potential.describe() != dict(baseline.potential_report)
        or potential.state_sha256 != sha256_file(baseline.potential)
    ):
        raise AppleView8MatchedError("baseline potential bytes differ")
    source = _mapping(config["source"], "source")
    native_source = _relative(root, source["native_source"], "native source")
    native = build_native_joint_score_sieve(
        source=native_source, output=workspace / "cadical-o1-joint-score-sieve-v2"
    )
    expected_baseline = _mapping(config["baseline"], "baseline")
    if (
        native.source_sha256 != expected_baseline["native_source_sha256"]
        or native.executable_sha256 != expected_baseline["native_executable_sha256"]
        or native.describe() != dict(baseline.native_build)
    ):
        raise AppleView8MatchedError("native build differs from O1C61")
    return PreparedRun(
        public_preflight=public_preflight,
        source_instances=tuple(instances),
        augmented_cnf=augmented,
        consequence_report_path=consequence_report_path,
        consequence_report=consequence_report,
        potential=potential,
        native_executable=native.executable,
        native_build=native.describe(),
    )


def invoke_native_once(
    *,
    executable: Path,
    cnf: Path,
    potential: Path,
    threshold: float,
    conflict_limit: int,
    seed: int,
    timeout_seconds: float,
    memory_limit_bytes: int,
    runner: Callable[..., JointScoreSieveResult] = run_joint_score_sieve,
) -> JointScoreSieveResult:
    return runner(
        executable=executable,
        cnf_path=cnf,
        potential_path=potential,
        threshold=threshold,
        conflict_limit=conflict_limit,
        seed=seed,
        timeout_seconds=timeout_seconds,
        memory_limit_bytes=memory_limit_bytes,
    )


def invoke_native_once_terminal(
    **kwargs: object,
) -> tuple[JointScoreSieveResult | None, dict[str, object] | None]:
    try:
        result = invoke_native_once(**kwargs)  # type: ignore[arg-type]
    except Exception as exc:
        return None, {
            "classification": "APPLE_VIEW_0008_OPERATIONAL_FAILURE_NO_SCIENCE_RESULT",
            "error_type": type(exc).__name__,
            "error_message": str(exc),
            "occurred_after_persisted_intent": True,
            "native_calls_consumed": 1,
            "retry_authorized": False,
            "public_model_diagnostic_complete": False,
            "truth_key_bytes_read": False,
        }
    return result, None


def _effect_metrics(
    raw: Mapping[str, object], field: str, *, threshold: float
) -> _EffectMetrics:
    sieve = _mapping(raw.get("sieve"), f"{field}.sieve")
    status = raw.get("status")
    required_integers = (
        "trail_threshold_prunes",
        "model_threshold_prunes",
        "threshold_prunes",
        "maximum_assigned_variables",
    )
    if (
        raw.get("schema") != BASELINE_NATIVE_SCHEMA
        or not _is_int(status)
        or status not in (0, 10, 20)
        or any(not _is_int(sieve.get(name)) or cast(int, sieve[name]) < 0 for name in required_integers)
    ):
        raise AppleView8MatchedError(f"{field} effect telemetry differs")
    try:
        root = float(cast(float, sieve["root_upper_bound"]))
        minimum = float(cast(float, sieve["minimum_upper_bound"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise AppleView8MatchedError(f"{field} bound telemetry differs") from exc
    if not math.isfinite(root) or not math.isfinite(minimum) or minimum > root:
        raise AppleView8MatchedError(f"{field} bound telemetry differs")
    return {
        "native_status": cast(int, status),
        "trail_threshold_prunes": cast(int, sieve["trail_threshold_prunes"]),
        "model_threshold_prunes": cast(int, sieve["model_threshold_prunes"]),
        "threshold_prunes": cast(int, sieve["threshold_prunes"]),
        "maximum_assigned_observed_variables": cast(
            int, sieve["maximum_assigned_variables"]
        ),
        "root_upper_bound": root,
        "minimum_upper_bound": minimum,
        "root_to_minimum_bound_drop": root - minimum,
        "remaining_gap_above_threshold": minimum - threshold,
    }


def classify_incremental_effect(
    *,
    baseline_native: Mapping[str, object],
    augmented_native: Mapping[str, object],
    baseline_ledger: Mapping[str, object],
    augmented_ledger: Mapping[str, object],
    baseline_exact_public_recovery: bool,
    augmented_public_model_verified: bool,
    threshold: float = BASELINE_THRESHOLD,
    bound_tolerance: float = BOUND_TOLERANCE,
) -> tuple[str, dict[str, object]]:
    """Classify exact recovery or a strict semantic improvement, never volume."""

    if (
        not isinstance(baseline_exact_public_recovery, bool)
        or not isinstance(augmented_public_model_verified, bool)
        or isinstance(threshold, bool)
        or not isinstance(threshold, (int, float))
        or not math.isfinite(float(threshold))
        or isinstance(bound_tolerance, bool)
        or not isinstance(bound_tolerance, (int, float))
        or not math.isfinite(float(bound_tolerance))
        or bound_tolerance < 0.0
    ):
        raise AppleView8MatchedError("incremental classification input differs")
    try:
        baseline_work = validate_soft_conflict_ledger(baseline_ledger)
        augmented_work = validate_soft_conflict_ledger(augmented_ledger)
    except Exception as exc:
        raise AppleView8MatchedError("soft conflict comparison ledger differs") from exc
    baseline = _effect_metrics(
        baseline_native, "baseline native", threshold=float(threshold)
    )
    augmented = _effect_metrics(
        augmented_native, "augmented native", threshold=float(threshold)
    )
    if not math.isclose(
        baseline["root_upper_bound"],
        augmented["root_upper_bound"],
        rel_tol=0.0,
        abs_tol=float(bound_tolerance),
    ):
        raise AppleView8MatchedError("matched root upper bounds differ")
    trail_delta = (
        augmented["trail_threshold_prunes"] - baseline["trail_threshold_prunes"]
    )
    bound_delta = (
        augmented["root_to_minimum_bound_drop"]
        - baseline["root_to_minimum_bound_drop"]
    )
    assigned_delta = (
        augmented["maximum_assigned_observed_variables"]
        - baseline["maximum_assigned_observed_variables"]
    )
    remaining_gap_improvement = (
        baseline["remaining_gap_above_threshold"]
        - augmented["remaining_gap_above_threshold"]
    )
    requested_work_matched = (
        baseline_work["requested_conflicts"]
        == augmented_work["requested_conflicts"]
        == CONFLICT_LIMIT
    )
    billed_work_matched = (
        baseline_work["billed_conflicts"] == augmented_work["billed_conflicts"]
    )
    matched_work = requested_work_matched and billed_work_matched
    strict = {
        "positive_additional_safe_trail_prunes_at_matched_work": matched_work
        and trail_delta > 0,
        "smaller_remaining_gap_at_matched_work": matched_work
        and remaining_gap_improvement > float(bound_tolerance),
    }
    if augmented_public_model_verified:
        classification = "APPLE_VIEW_0008_EXACT_PUBLIC_FULL256_RECOVERY"
    elif baseline_exact_public_recovery:
        classification = "APPLE_VIEW_0008_NO_INCREMENTAL_EFFECT"
    elif any(strict.values()):
        classification = "APPLE_VIEW_0008_STRICT_INCREMENTAL_EFFECT_NO_RECOVERY"
    else:
        classification = "APPLE_VIEW_0008_NO_INCREMENTAL_EFFECT"
    return classification, {
        "baseline": baseline,
        "augmented": augmented,
        "deltas": {
            "trail_threshold_prunes": trail_delta,
            "root_to_minimum_bound_drop": bound_delta,
            "remaining_gap_improvement": remaining_gap_improvement,
            "maximum_assigned_observed_variables": assigned_delta,
        },
        "work": {
            "baseline": baseline_work,
            "augmented": augmented_work,
            "requested_work_matched": requested_work_matched,
            "billed_work_matched": billed_work_matched,
            "conflicts_before_solve_matched": baseline_work[
                "conflicts_before_solve"
            ]
            == augmented_work["conflicts_before_solve"],
            "conflicts_before_solve_required_to_match": False,
            "end_to_end_time_is_contextual_not_causal": True,
        },
        "strict_effect_gates": strict,
        "baseline_exact_public_recovery": baseline_exact_public_recovery,
        "augmented_public_model_verified": augmented_public_model_verified,
        "lost_baseline_exact_recovery": baseline_exact_public_recovery
        and not augmented_public_model_verified,
        "event_volume_used_for_promotion": False,
        "trail_threshold_prunes_called_earlier": False,
        "maximum_assigned_observed_progress_used_for_promotion": False,
    }


def public_model_then_truth_diagnostic(
    native: JointScoreSieveResult,
    *,
    verify_public_model: Callable[[bytes], bool],
    read_truth_key: Callable[[], bytes],
    public_diagnostic_ledger: list[bool] | None = None,
) -> tuple[bool, bytes | None, bool | None]:
    """Read truth only to diagnose a present, independently verified model."""

    if not isinstance(native, JointScoreSieveResult):
        raise AppleView8MatchedError("native diagnostic input differs")
    if public_diagnostic_ledger is not None and public_diagnostic_ledger != [False]:
        raise AppleView8MatchedError("public-diagnostic ledger differs")

    def mark_public_diagnostic_complete() -> None:
        if public_diagnostic_ledger is not None:
            public_diagnostic_ledger[0] = True

    if native.key_model is None:
        mark_public_diagnostic_complete()
        if native.status != 10:
            return False, None, None
        raise AppleView8MatchedError("SAT result lacks a native key model")
    try:
        public_verified = bool(verify_public_model(native.key_model))
    finally:
        mark_public_diagnostic_complete()
    if not public_verified:
        raise AppleView8MatchedError("native model fails eight public blocks")
    truth = read_truth_key()
    if not isinstance(truth, bytes) or len(truth) != 32:
        raise AppleView8MatchedError("post-native truth key differs")
    return (
        public_verified,
        truth,
        None if native.key_model is None else native.key_model == truth,
    )


def _capsule_manifest(capsule: Path) -> tuple[bytes, int]:
    rows: list[str] = []
    total = 0
    for path in sorted(capsule.rglob("*")):
        if not path.is_file() or path.name == "artifacts.sha256":
            continue
        relative = path.relative_to(capsule).as_posix()
        rows.append(f"{sha256_file(path)}  {relative}\n")
        total += path.stat().st_size
    payload = "".join(rows).encode("ascii")
    return payload, total + len(payload)


def _markdown(result: Mapping[str, object]) -> str:
    return (
        "# APPLE-VIEW-0008 matched run\n\n"
        f"- Classification: `{result['classification']}`\n"
        f"- Native calls: `{result['resources']['native_solver_calls']}`\n"  # type: ignore[index]
        f"- Truth bytes read: `{result['claim_boundary']['truth_key_bytes_read_after_public_diagnostic']}`\n\n"  # type: ignore[index]
        "The O1C61 CNF body, potential, threshold, native build, seed, "
        "requested-conflict soft-stop ledger, timeout, and memory mechanism "
        "were frozen before the "
        "single call. Only the 14,392 APPLE-VIEW-0008 clauses differ.\n"
    )


def _restore_owned_capsule_for_recovery(capsule: Path) -> None:
    capsule.chmod(0o755)
    for path in sorted(capsule.rglob("*"), key=lambda item: len(item.parts)):
        path.chmod(0o755 if path.is_dir() else 0o644)


def _unlink_owned_exact(path: Path, payload: bytes, field: str) -> None:
    if not path.exists():
        return
    if not path.is_file() or path.is_symlink() or path.read_bytes() != payload:
        raise AppleView8MatchedError(f"{field} recovery ownership differs")
    path.chmod(0o644)
    path.unlink()
    parent = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def finalize_capsule(
    *,
    capsule: Path,
    authoritative_result: Path,
    result: dict[str, object],
    maximum_persistent_bytes: int,
    _after_capsule_seal: Callable[[], None] | None = None,
) -> None:
    if (capsule / "artifacts.sha256").exists() or authoritative_result.exists():
        raise AppleView8MatchedError("matched terminal output already exists")
    _replace_owned_bytes(capsule / "RUN.md", _markdown(result).encode("utf-8"))
    resources = cast(dict[str, object], result["resources"])
    result_path = capsule / "result.json"
    for _ in range(8):
        _replace_owned_json(result_path, result)
        manifest, persistent = _capsule_manifest(capsule)
        if resources.get("persistent_artifact_bytes") == persistent:
            break
        resources["persistent_artifact_bytes"] = persistent
    else:
        raise AppleView8MatchedError("matched persistent byte ledger did not converge")
    if persistent > maximum_persistent_bytes:
        raise AppleView8MatchedError("matched persistent byte budget exceeded")
    result_payload = _pretty_json_bytes(result)
    if result_path.read_bytes() != result_payload:
        raise AppleView8MatchedError("capsule result serialization differs")
    manifest_path = capsule / "artifacts.sha256"
    authoritative_published = False
    manifest_published = False
    try:
        _atomic_bytes(authoritative_result, result_payload)
        authoritative_published = True
        _atomic_bytes(manifest_path, manifest)
        manifest_published = True
        for path in sorted(
            capsule.rglob("*"), key=lambda item: len(item.parts), reverse=True
        ):
            path.chmod(0o444 if path.is_file() else 0o555)
        capsule.chmod(0o555)
        if _after_capsule_seal is not None:
            _after_capsule_seal()
        if (
            authoritative_result.read_bytes() != result_payload
            or result_path.read_bytes() != result_payload
        ):
            raise AppleView8MatchedError(
                "authoritative and capsule result bytes differ"
            )
    except Exception:
        _restore_owned_capsule_for_recovery(capsule)
        if manifest_published:
            _unlink_owned_exact(manifest_path, manifest, "capsule manifest")
        if authoritative_published:
            _unlink_owned_exact(
                authoritative_result, result_payload, "authoritative publication"
            )
        raise


def _post_native_truth(
    root: Path,
    baseline: BaselineArtifacts,
    native: JointScoreSieveResult,
    public_preflight: Mapping[str, object],
    public_diagnostic_ledger: list[bool],
    truth_read_ledger: list[bool],
) -> tuple[
    bool,
    bytes | None,
    bool | None,
    Mapping[str, object],
    Mapping[str, object],
    Mapping[str, object] | None,
]:
    if truth_read_ledger != [False]:
        raise AppleView8MatchedError("truth-read ledger differs")
    outputs = tuple(
        bytes.fromhex(str(value))
        for value in _sequence(public_preflight["output_blocks_hex"], "public outputs")
    )
    counters = tuple(
        cast(int, value)
        for value in _sequence(public_preflight["counters"], "public counters")
    )
    nonce = bytes.fromhex(str(public_preflight["nonce_hex"]))

    def verify_public(key: bytes) -> bool:
        observed = tuple(
            chacha20_blocks(key, counter, nonce, 1)[0] for counter in counters
        )
        return observed == outputs

    reveal_holder: dict[str, Mapping[str, object]] = {}

    def read_truth() -> bytes:
        truth_read_ledger[0] = True
        reveal_path = root / O1C57_RELATIVE / "reveal.json"
        reveal = verify_reveal(_read_mapping(reveal_path, "O1C57 reveal"))
        reveal_holder["value"] = reveal
        preimage = _mapping(reveal["commitment_preimage"], "commitment preimage")
        return bytes.fromhex(str(preimage["key_hex"]))

    public_verified, truth, equals = public_model_then_truth_diagnostic(
        native,
        verify_public_model=verify_public,
        read_truth_key=read_truth,
        public_diagnostic_ledger=public_diagnostic_ledger,
    )
    baseline_result = _read_mapping(
        baseline.authoritative_result, "post-native baseline result"
    )
    baseline_native = _mapping(
        _read_mapping(baseline.native_result, "post-native baseline native result"),
        "post-native baseline native result",
    )
    baseline_ledger = _read_mapping(
        baseline.conflict_ledger, "post-native baseline soft conflict ledger"
    )
    if (
        baseline_result.get("schema") != BASELINE_RESULT_SCHEMA
        or baseline_result.get("classification") not in SCIENCE_CLASSIFICATIONS
        or baseline_result.get("native") != baseline_native
        or baseline_result.get("conflict_ledger") != baseline_ledger
    ):
        raise AppleView8MatchedError("post-native baseline outcome differs")
    return (
        public_verified,
        truth,
        equals,
        baseline_result,
        baseline_ledger,
        reveal_holder.get("value"),
    )


def _failure_result(
    *,
    started_at: str,
    started: float,
    cpu_started: float,
    child_started: resource.struct_rusage,
    capsule_relative: str,
    baseline: BaselineArtifacts,
    config: Mapping[str, object],
    preflight: Mapping[str, object],
    failure: Mapping[str, object],
    public_diagnostic_complete: bool,
    truth_read: bool,
) -> dict[str, object]:
    child = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "started_at": started_at,
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "classification": "APPLE_VIEW_0008_OPERATIONAL_FAILURE_NO_SCIENCE_RESULT",
        "capsule": capsule_relative,
        "claim_boundary": {
            "native_solver_calls": 1,
            "persisted_intent_consumed": True,
            "retry_authorized": False,
            "fresh_targets": 0,
            "scientific_entropy_calls": 0,
            "fresh_reveal_calls": 0,
            "refits": 0,
            "truth_key_bytes_read_after_public_diagnostic": truth_read,
            "public_model_diagnostic_complete": public_diagnostic_complete,
            "validated_science_result": False,
        },
        "operational_failure": dict(failure),
        "baseline": {
            "capsule": baseline.capsule.relative_to(lab_root()).as_posix(),
            "manifest_sha256": config["baseline"]["manifest_sha256"],  # type: ignore[index]
            "result_sha256": config["baseline"]["result_sha256"],  # type: ignore[index]
            "outcome_semantics_read_before_native_call": False,
        },
        "preflight": dict(preflight),
        "metrics": {"native_status": "OPERATIONAL_FAILURE"},
        "resources": {
            "elapsed_seconds": time.perf_counter() - started,
            "parent_cpu_seconds": time.process_time() - cpu_started,
            "child_cpu_seconds": child.ru_utime
            + child.ru_stime
            - child_started.ru_utime
            - child_started.ru_stime,
            "peak_rss_bytes": _peak_rss_bytes(),
            "native_solver_calls": 1,
            "requested_conflicts": CONFLICT_LIMIT,
            "maximum_billed_conflicts": JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS,
            "fresh_targets": 0,
            "scientific_entropy_calls": 0,
            "fresh_reveal_calls": 0,
            "refits": 0,
            "MPS_or_GPU": False,
            "persistent_artifact_bytes": 0,
        },
        "next_action": "Do not retry this attempt ID; diagnose the immutable terminal capsule.",
    }


def run(config_path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    authoritative = root / AUTHORITATIVE_RELATIVE
    if authoritative.exists() or tuple(root.glob(f"runs/*_{CAPSULE_SUFFIX}")):
        raise AppleView8MatchedError("matched attempt already exists")
    config_file = Path(config_path).resolve(strict=True)
    config = load_config(config_file)
    baseline = _baseline_artifacts(root, config)
    baseline_binding = _mapping(config["baseline"], "baseline")
    budgets = _mapping(config["budgets"], "budgets")
    memory_free = _memory_free_percent()
    if memory_free is not None and memory_free < cast(
        int, budgets["minimum_memory_pressure_free_percent"]
    ):
        raise AppleView8MatchedError("memory-pressure preflight is below frozen gate")
    memory_mechanism = (
        "proc_pid_rusage-physical-footprint-process-group-watchdog"
        if sys.platform == "darwin"
        else "child-RLIMIT_AS-before-exec"
    )
    if memory_mechanism != baseline_binding["memory_limit_mechanism"]:
        raise AppleView8MatchedError("current memory mechanism differs from O1C61")
    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    cpu_started = time.process_time()
    child_started = resource.getrusage(resource.RUSAGE_CHILDREN)
    with tempfile.TemporaryDirectory(prefix="apple-view-0008-matched-") as raw_workspace:
        workspace = Path(raw_workspace)
        prepared = _prepare_run(root, config, baseline, workspace)
        stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
        capsule_relative = Path("runs") / f"{stamp}_{CAPSULE_SUFFIX}"
        capsule = root / capsule_relative
        capsule.mkdir(parents=True, exist_ok=False)
        augmented_path = capsule / "artifacts/cnf/full256-eight-block-apple-view-0008.cnf"
        potential_path = capsule / "artifacts/potential/primary-eight-block.potential"
        _copy_exclusive(prepared.augmented_cnf, augmented_path)
        _copy_exclusive(baseline.potential, potential_path)
        _atomic_bytes(
            capsule / "artifacts/cnf/full256-eight-block-apple-view-0008.report.json",
            prepared.consequence_report_path.read_bytes(),
        )
        preflight = {
            "schema": PREFLIGHT_SCHEMA,
            "observed_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "source_commit": config["source"]["required_source_commit"],  # type: ignore[index]
            "terminal_baseline_manifest_sha256": baseline_binding["manifest_sha256"],
            "baseline_outcome_semantics_read_before_native_call": False,
            "baseline_cnf_sha256": sha256_file(baseline.cnf),
            "baseline_cnf_bytes": baseline.cnf.stat().st_size,
            "augmented_cnf_sha256": sha256_file(augmented_path),
            "baseline_cnf_body_byte_identical": prepared.consequence_report.source_instance_sha256
            == sha256_file(baseline.cnf),
            "potential_sha256": sha256_file(potential_path),
            "threshold": baseline_binding["threshold"],
            "requested_conflicts": CONFLICT_LIMIT,
            "maximum_conflict_limit_overshoot": JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT,
            "maximum_billed_conflicts": JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS,
            "soft_conflict_ledger_schema": JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA,
            "native_build": prepared.native_build,
            "memory_pressure_free_percent": memory_free,
            "minimum_memory_pressure_free_percent": budgets[
                "minimum_memory_pressure_free_percent"
            ],
            "memory_limit_bytes": MEMORY_LIMIT_BYTES,
            "memory_limit_mechanism": memory_mechanism,
            "public_o1c57_preflight": dict(prepared.public_preflight),
            "consequence_report": prepared.consequence_report.describe(),
            "native_solver_calls_before_intent": 0,
            "fresh_targets": 0,
            "scientific_entropy_calls": 0,
            "fresh_reveal_calls": 0,
            "truth_key_bytes_read": False,
            "MPS_or_GPU": False,
        }
        if (
            preflight["baseline_cnf_body_byte_identical"] is not True
            or sha256_file(potential_path) != baseline_binding["potential_sha256"]
            or prepared.native_build["executable_sha256"]
            != baseline_binding["native_executable_sha256"]
        ):
            raise AppleView8MatchedError("matched preflight differs")
        _atomic_json(capsule / "preflight.json", preflight)
        _atomic_json(capsule / "native_build.json", prepared.native_build)
        _atomic_json(
            capsule / "baseline_binding.json",
            {
                "capsule": baseline_binding["capsule"],
                "manifest_sha256": baseline_binding["manifest_sha256"],
                "result_sha256": baseline_binding["result_sha256"],
                "cnf_sha256": baseline_binding["cnf_sha256"],
                "potential_sha256": baseline_binding["potential_sha256"],
                "native_result_sha256": baseline_binding["native_result_sha256"],
                "conflict_ledger_sha256": baseline_binding[
                    "conflict_ledger_sha256"
                ],
                "outcome_semantics_deferred_until_after_augmented_public_model_diagnostic": True,
            },
        )
        _atomic_bytes(capsule / "config.json", config_file.read_bytes())
        _atomic_bytes(
            capsule / "command.txt",
            (
                "nice -n 10 env PYTHONPATH=src:research/apple_view_8 python3 "
                "research/apple_view_8/apple_view_8_matched_science.py run "
                f"--config {config_file.relative_to(root).as_posix()}\n"
            ).encode("utf-8"),
        )
        intent = {
            "schema": INTENT_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "calls_before": 0,
            "calls_authorized": 1,
            "requested_conflicts": CONFLICT_LIMIT,
            "maximum_conflict_limit_overshoot": JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT,
            "maximum_billed_conflicts": JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS,
            "soft_conflict_ledger_schema": JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA,
            "seed": SEED,
            "timeout_seconds": TIMEOUT_SECONDS,
            "memory_limit_bytes": MEMORY_LIMIT_BYTES,
            "memory_limit_mechanism": memory_mechanism,
            "threshold": baseline_binding["threshold"],
            "cnf_sha256": sha256_file(augmented_path),
            "baseline_cnf_sha256": baseline_binding["cnf_sha256"],
            "appended_augmentation_sha256": prepared.consequence_report.augmentation_sha256,
            "appended_clause_count": prepared.consequence_report.augmentation_clause_count,
            "potential_sha256": sha256_file(potential_path),
            "native_source_sha256": baseline_binding["native_source_sha256"],
            "native_executable_sha256": prepared.native_build["executable_sha256"],
            "baseline_outcome_semantics_read": False,
            "truth_key_bytes_read": False,
            "fresh_entropy_calls": 0,
            "fresh_reveal_calls": 0,
        }
        _atomic_json(capsule / "native_call_intent.json", intent)
        native, immediate_failure = invoke_native_once_terminal(
            executable=prepared.native_executable,
            cnf=augmented_path,
            potential=potential_path,
            threshold=float(cast(float, baseline_binding["threshold"])),
            conflict_limit=CONFLICT_LIMIT,
            seed=SEED,
            timeout_seconds=TIMEOUT_SECONDS,
            memory_limit_bytes=MEMORY_LIMIT_BYTES,
        )
        public_diagnostic_ledger = [False]
        truth_read_ledger = [False]
        try:
            if immediate_failure is not None:
                raise AppleView8MatchedError(str(immediate_failure["error_message"]))
            if native is None:
                raise AppleView8MatchedError("native call returned no result")
            _atomic_json(capsule / "native_result.json", native.raw)
            try:
                augmented_ledger = validate_soft_conflict_ledger(native.stats)
            except Exception as exc:
                raise AppleView8MatchedError(
                    "augmented soft conflict ledger differs"
                ) from exc
            _atomic_json(
                capsule / "conflict_ledger.json",
                {
                    "schema": JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA,
                    **augmented_ledger,
                },
            )
            if (
                native.conflict_limit != CONFLICT_LIMIT
                or augmented_ledger["requested_conflicts"] != CONFLICT_LIMIT
                or augmented_ledger["conflict_limit_overshoot"]
                > JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT
                or augmented_ledger["billed_conflicts"]
                > JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS
                or native.threshold != float(cast(float, baseline_binding["threshold"]))
                or native.sieve.get("decision_rule") != JOINT_SCORE_SIEVE_DECISION_RULE
                or int(native.resources["wall_microseconds"]) / 1_000_000.0
                > TIMEOUT_SECONDS
                or int(native.resources["peak_rss_bytes"]) > MEMORY_LIMIT_BYTES
            ):
                raise AppleView8MatchedError("augmented native resource contract differs")
            (
                public_verified,
                truth,
                equals_truth,
                baseline_result,
                baseline_ledger,
                reveal,
            ) = _post_native_truth(
                root,
                baseline,
                native,
                prepared.public_preflight,
                public_diagnostic_ledger,
                truth_read_ledger,
            )
            truth_read = truth_read_ledger[0]
            if native.status == 20:
                raise AppleView8MatchedError(
                    "augmented UNSAT contradicts the frozen satisfiable public target"
                )
            baseline_native = _mapping(
                baseline_result["native"], "post-native baseline native"
            )
            baseline_exact = (
                baseline_result["classification"]
                == "EXACT_CONSUMED_FULL256_RECOVERY"
            )
            classification, comparison = classify_incremental_effect(
                baseline_native=baseline_native,
                augmented_native=native.raw,
                baseline_ledger={
                    key: value
                    for key, value in baseline_ledger.items()
                    if key != "schema"
                },
                augmented_ledger=augmented_ledger,
                baseline_exact_public_recovery=baseline_exact,
                augmented_public_model_verified=public_verified,
                threshold=float(cast(float, baseline_binding["threshold"])),
                bound_tolerance=BOUND_TOLERANCE,
            )
            child = resource.getrusage(resource.RUSAGE_CHILDREN)
            result: dict[str, object] = {
                "schema": RESULT_SCHEMA,
                "attempt_id": ATTEMPT_ID,
                "started_at": started_at,
                "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
                "source_commit": config["source"]["required_source_commit"],  # type: ignore[index]
                "classification": classification,
                "capsule": capsule_relative.as_posix(),
                "claim_boundary": {
                    "consumed_o1c61_terminal_baseline": True,
                    "consumed_o1c57_public_target": True,
                    "baseline_outcome_semantics_read_before_native_call": False,
                    "fresh_targets": 0,
                    "scientific_entropy_calls": 0,
                    "fresh_reveal_calls": 0,
                    "refits": 0,
                    "new_score_arms": 0,
                    "native_solver_calls": 1,
                    "public_model_diagnostic_before_truth_read": True,
                    "public_model_diagnostic_complete": public_diagnostic_ledger[0],
                    "truth_key_bytes_read_after_public_diagnostic": truth_read,
                    "public_collision_counts_as_exact_recovery": True,
                    "exact_public_recovery": public_verified,
                    "conflicts_before_solve_required_to_match": False,
                    "end_to_end_time_is_contextual_not_causal": True,
                    "trail_threshold_prunes_called_earlier": False,
                },
                "baseline": {
                    "capsule": baseline_binding["capsule"],
                    "manifest_sha256": baseline_binding["manifest_sha256"],
                    "result_sha256": baseline_binding["result_sha256"],
                    "classification": baseline_result["classification"],
                    "cnf_sha256": baseline_binding["cnf_sha256"],
                    "potential_sha256": baseline_binding["potential_sha256"],
                    "threshold": baseline_binding["threshold"],
                    "requested_conflicts": baseline_binding[
                        "requested_conflicts"
                    ],
                    "billed_conflicts": baseline_binding["billed_conflicts"],
                    "remaining_gap": baseline_binding["remaining_gap"],
                    "root_to_minimum_bound_drop": baseline_binding[
                        "root_to_minimum_bound_drop"
                    ],
                },
                "composition": {
                    "consequence_report": prepared.consequence_report.describe(),
                    "baseline_cnf_body_byte_identical": True,
                    "potential_byte_identical_to_baseline": True,
                    "threshold_bit_identical_to_baseline": True,
                    "native_executable_identical_to_baseline": True,
                    "only_difference_is_14392_apple_clauses": True,
                },
                "native": native.raw,
                "comparison": comparison,
                "metrics": {
                    "native_status": native.status_name,
                    "public_model_verified_8_of_8": public_verified,
                    "native_model_sha256": None
                    if native.key_model is None
                    else hashlib.sha256(native.key_model).hexdigest(),
                    "native_model_equals_committed_truth": equals_truth,
                    "collision_recovery": public_verified and equals_truth is False,
                    "truth_key_sha256": None
                    if truth is None
                    else hashlib.sha256(truth).hexdigest(),
                    "reveal_sha256": None
                    if reveal is None
                    else reveal["reveal_sha256"],
                },
                "resources": {
                    "elapsed_seconds": time.perf_counter() - started,
                    "parent_cpu_seconds": time.process_time() - cpu_started,
                    "child_cpu_seconds": child.ru_utime
                    + child.ru_stime
                    - child_started.ru_utime
                    - child_started.ru_stime,
                    "peak_rss_bytes": _peak_rss_bytes(),
                    "native_wall_seconds": int(native.resources["wall_microseconds"])
                    / 1_000_000.0,
                    "native_cpu_seconds": int(native.resources["cpu_microseconds"])
                    / 1_000_000.0,
                    "native_peak_rss_bytes": int(native.resources["peak_rss_bytes"]),
                    "native_memory_limit_bytes": MEMORY_LIMIT_BYTES,
                    "native_memory_enforcement": memory_mechanism,
                    "native_solver_calls": 1,
                    "requested_conflicts": augmented_ledger[
                        "requested_conflicts"
                    ],
                    "unused_requested_conflicts": augmented_ledger[
                        "unused_requested_conflicts"
                    ],
                    "cumulative_conflicts": augmented_ledger["conflicts"],
                    "conflicts_before_solve": augmented_ledger[
                        "conflicts_before_solve"
                    ],
                    "solve_conflicts": augmented_ledger["solve_conflicts"],
                    "conflict_limit_overshoot": augmented_ledger[
                        "conflict_limit_overshoot"
                    ],
                    "billed_conflicts": augmented_ledger["billed_conflicts"],
                    "maximum_billed_conflicts": JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS,
                    "fresh_targets": 0,
                    "scientific_entropy_calls": 0,
                    "fresh_reveal_calls": 0,
                    "refits": 0,
                    "MPS_or_GPU": False,
                    "persistent_artifact_bytes": 0,
                },
                "preflight": preflight,
                "next_action": config["next_action"],
            }
            _atomic_json(
                capsule / "truth_diagnostic.json",
                {
                    "public_model_diagnostic_complete": public_diagnostic_ledger[0],
                    "truth_read_after_verified_public_model": truth_read,
                    "truth_key_sha256": None
                    if truth is None
                    else hashlib.sha256(truth).hexdigest(),
                    "native_model_equals_committed_truth": equals_truth,
                    "collision_recovery": public_verified and equals_truth is False,
                },
            )
            finalize_capsule(
                capsule=capsule,
                authoritative_result=authoritative,
                result=result,
                maximum_persistent_bytes=MAXIMUM_PERSISTENT_BYTES,
            )
            return result
        except Exception as exc:
            truth_read = truth_read_ledger[0]
            if immediate_failure is not None:
                failure = dict(immediate_failure)
            else:
                failure = {
                    "classification": "APPLE_VIEW_0008_OPERATIONAL_FAILURE_NO_SCIENCE_RESULT",
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                    "occurred_after_persisted_intent": True,
                    "native_calls_consumed": 1,
                    "retry_authorized": False,
                    "public_model_diagnostic_complete": public_diagnostic_ledger[0],
                    "truth_key_bytes_read": truth_read,
                }
            if not (capsule / "native_failure.json").exists():
                _atomic_json(capsule / "native_failure.json", failure)
            failure_result = _failure_result(
                started_at=started_at,
                started=started,
                cpu_started=cpu_started,
                child_started=child_started,
                capsule_relative=capsule_relative.as_posix(),
                baseline=baseline,
                config=config,
                preflight=preflight,
                failure=failure,
                public_diagnostic_complete=public_diagnostic_ledger[0],
                truth_read=truth_read,
            )
            finalize_capsule(
                capsule=capsule,
                authoritative_result=authoritative,
                result=failure_result,
                maximum_persistent_bytes=MAXIMUM_PERSISTENT_BYTES,
            )
            return failure_result


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    preflight_parser = commands.add_parser("preflight")
    preflight_parser.add_argument("--config", required=True)
    bind_parser = commands.add_parser("bind")
    bind_parser.add_argument("--template", default=TEMPLATE_RELATIVE.as_posix())
    bind_parser.add_argument("--baseline-result", required=True)
    bind_parser.add_argument("--baseline-capsule", required=True)
    bind_parser.add_argument("--output", required=True)
    run_parser = commands.add_parser("run")
    run_parser.add_argument("--config", required=True)
    arguments = parser.parse_args()
    if arguments.command == "preflight":
        result = config_preflight(arguments.config)
    elif arguments.command == "bind":
        result = bind_terminal_o1c61(
            arguments.template,
            arguments.baseline_result,
            arguments.baseline_capsule,
            arguments.output,
        )
    else:
        result = run(arguments.config)
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "AppleView8MatchedError",
    "bind_terminal_o1c61",
    "classify_incremental_effect",
    "config_preflight",
    "finalize_capsule",
    "invoke_native_once",
    "invoke_native_once_terminal",
    "load_config",
    "main",
    "public_model_then_truth_diagnostic",
    "run",
]
