"""O1C-0011 deterministic full-256 CNF foundation experiment."""

from __future__ import annotations

import hashlib
import json
import shutil
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from .chacha_trace import chacha20_block
from .full256_cnf import (
    KEY_FIRST_VARIABLE,
    PUBLIC_UNIT_CLAUSES,
    InstanceWriteReport,
    SolverReport,
    load_full256_template_map,
    run_cadical,
    verify_full256_template,
    write_full256_instance,
    write_full256_template,
)
from .living_inverse import canonical_sha256


FOUNDATION_CONFIG_SCHEMA = "o1-256-full-cnf-foundation-config-v1"
FOUNDATION_RESULT_SCHEMA = "o1-256-full-cnf-foundation-result-v1"


class Full256CNFFoundationError(ValueError):
    """Raised when the frozen O1C-0011 protocol or a mandatory gate differs."""


def _integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise Full256CNFFoundationError(
            f"{field} must be an integer in [{minimum}, {maximum}]"
        )
    return value


def _positive_float(value: object, field: str, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not 0 < float(value) <= maximum
    ):
        raise Full256CNFFoundationError(f"{field} must be in (0, {maximum}]")
    return float(value)


def _sha(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise Full256CNFFoundationError(f"{field} must be a lowercase SHA-256")
    return value


def _hex_bytes(value: object, field: str, length: int) -> bytes:
    if not isinstance(value, str) or len(value) != 2 * length:
        raise Full256CNFFoundationError(
            f"{field} must encode exactly {length} bytes"
        )
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise Full256CNFFoundationError(f"{field} is not hexadecimal") from exc
    if decoded.hex() != value:
        raise Full256CNFFoundationError(f"{field} must be lowercase canonical hex")
    return decoded


@dataclass(frozen=True)
class Full256CNFFoundationConfig:
    expected_variable_count: int
    expected_clause_count: int
    expected_operation_count: int
    expected_dimacs_bytes: int
    expected_dimacs_sha256: str
    expected_map_sha256: str
    expected_map_file_sha256: str
    expected_clause_length_histogram: dict[str, int]
    solver_timeout_seconds: float
    maximum_working_bytes: int
    paired_assumption_bit: int
    rfc_key: bytes
    rfc_counter: int
    rfc_nonce: bytes
    rfc_output: bytes
    second_key: bytes
    second_counter: int
    second_nonce: bytes

    @classmethod
    def from_mapping(cls, value: object) -> "Full256CNFFoundationConfig":
        if not isinstance(value, dict):
            raise Full256CNFFoundationError("foundation must be an object")
        expected = {
            "expected_variable_count",
            "expected_clause_count",
            "expected_operation_count",
            "expected_dimacs_bytes",
            "expected_dimacs_sha256",
            "expected_map_sha256",
            "expected_map_file_sha256",
            "expected_clause_length_histogram",
            "solver_timeout_seconds",
            "maximum_working_bytes",
            "paired_assumption_bit",
            "rfc_key_hex",
            "rfc_counter",
            "rfc_nonce_hex",
            "rfc_output_hex",
            "second_key_hex",
            "second_counter",
            "second_nonce_hex",
        }
        if set(value) != expected:
            raise Full256CNFFoundationError("foundation fields differ")
        histogram = value["expected_clause_length_histogram"]
        if (
            not isinstance(histogram, dict)
            or set(histogram) != {"1", "2", "3", "4"}
            or any(
                isinstance(count, bool) or not isinstance(count, int) or count < 0
                for count in histogram.values()
            )
        ):
            raise Full256CNFFoundationError("expected clause histogram differs")
        return cls(
            expected_variable_count=_integer(
                value["expected_variable_count"],
                "expected_variable_count",
                897,
                1_000_000,
            ),
            expected_clause_count=_integer(
                value["expected_clause_count"],
                "expected_clause_count",
                1,
                10_000_000,
            ),
            expected_operation_count=_integer(
                value["expected_operation_count"],
                "expected_operation_count",
                1,
                10_000,
            ),
            expected_dimacs_bytes=_integer(
                value["expected_dimacs_bytes"],
                "expected_dimacs_bytes",
                1,
                100_000_000,
            ),
            expected_dimacs_sha256=_sha(
                value["expected_dimacs_sha256"], "expected_dimacs_sha256"
            ),
            expected_map_sha256=_sha(
                value["expected_map_sha256"], "expected_map_sha256"
            ),
            expected_map_file_sha256=_sha(
                value["expected_map_file_sha256"], "expected_map_file_sha256"
            ),
            expected_clause_length_histogram={
                str(length): int(count) for length, count in histogram.items()
            },
            solver_timeout_seconds=_positive_float(
                value["solver_timeout_seconds"], "solver_timeout_seconds", 300.0
            ),
            maximum_working_bytes=_integer(
                value["maximum_working_bytes"],
                "maximum_working_bytes",
                1,
                1_000_000_000,
            ),
            paired_assumption_bit=_integer(
                value["paired_assumption_bit"], "paired_assumption_bit", 0, 255
            ),
            rfc_key=_hex_bytes(value["rfc_key_hex"], "rfc_key_hex", 32),
            rfc_counter=_integer(
                value["rfc_counter"], "rfc_counter", 0, (1 << 32) - 1
            ),
            rfc_nonce=_hex_bytes(value["rfc_nonce_hex"], "rfc_nonce_hex", 12),
            rfc_output=_hex_bytes(value["rfc_output_hex"], "rfc_output_hex", 64),
            second_key=_hex_bytes(value["second_key_hex"], "second_key_hex", 32),
            second_counter=_integer(
                value["second_counter"], "second_counter", 0, (1 << 32) - 1
            ),
            second_nonce=_hex_bytes(
                value["second_nonce_hex"], "second_nonce_hex", 12
            ),
        )


def load_full256_cnf_foundation_config(
    path: str | Path,
) -> tuple[dict[str, object], Full256CNFFoundationConfig]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Full256CNFFoundationError("could not load foundation config") from exc
    if not isinstance(value, dict) or value.get("schema") != FOUNDATION_CONFIG_SCHEMA:
        raise Full256CNFFoundationError("foundation config schema differs")
    expected = {
        "schema",
        "attempt_id",
        "slug",
        "claim_level",
        "hypothesis",
        "prediction",
        "controls",
        "budgets",
        "next_action",
        "foundation",
    }
    if set(value) != expected:
        raise Full256CNFFoundationError("top-level foundation config fields differ")
    if any(
        not isinstance(value[field], str) or not value[field]
        for field in (
            "attempt_id",
            "slug",
            "claim_level",
            "hypothesis",
            "prediction",
            "next_action",
        )
    ):
        raise Full256CNFFoundationError("top-level string field is invalid")
    if (
        not isinstance(value["controls"], list)
        or not value["controls"]
        or any(not isinstance(item, str) or not item for item in value["controls"])
        or not isinstance(value["budgets"], dict)
    ):
        raise Full256CNFFoundationError("controls or budgets are invalid")
    return value, Full256CNFFoundationConfig.from_mapping(value["foundation"])


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _files_equal(left: Path, right: Path) -> bool:
    if left.stat().st_size != right.stat().st_size:
        return False
    with left.open("rb") as first, right.open("rb") as second:
        while True:
            first_chunk = first.read(1 << 20)
            second_chunk = second.read(1 << 20)
            if first_chunk != second_chunk:
                return False
            if not first_chunk:
                return True


def _workspace_bytes(root: Path) -> int:
    return sum(path.stat().st_size for path in root.rglob("*") if path.is_file())


def _instance_header(path: Path) -> tuple[int, int]:
    with path.open("r", encoding="ascii") as handle:
        fields = handle.readline().strip().split()
    if len(fields) != 4 or fields[:2] != ["p", "cnf"]:
        raise Full256CNFFoundationError("instance DIMACS header differs")
    try:
        return int(fields[2]), int(fields[3])
    except ValueError as exc:
        raise Full256CNFFoundationError("instance DIMACS counts are invalid") from exc


def _tail_units(path: Path, count: int) -> tuple[int, ...]:
    rows: deque[bytes] = deque(maxlen=count)
    with path.open("rb") as handle:
        for raw in handle:
            rows.append(raw)
    if len(rows) != count:
        raise Full256CNFFoundationError("instance contains too few unit rows")
    literals = []
    for raw in rows:
        fields = raw.decode("ascii").strip().split()
        if len(fields) != 2 or fields[1] != "0":
            raise Full256CNFFoundationError("instance tail is not unit clauses")
        literals.append(int(fields[0]))
    return tuple(literals)


def _instance_description(report: InstanceWriteReport) -> dict[str, object]:
    return report.describe()


def _solver_description(report: SolverReport) -> dict[str, object]:
    return {
        "solver_name": Path(report.solver).name,
        "status": report.status,
        "returncode": report.returncode,
        "wall_seconds": report.wall_seconds,
        "stdout_sha256": hashlib.sha256(report.stdout.encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256(report.stderr.encode()).hexdigest(),
        "stdout": report.stdout,
        "stderr": report.stderr,
    }


@dataclass(frozen=True)
class Full256CNFFoundationResult:
    report: dict[str, object]
    artifact_paths: dict[str, Path]

    @property
    def success_gate_passed(self) -> bool:
        gates = self.report["gates"]
        return isinstance(gates, dict) and bool(gates.get("all_passed"))

    def metrics(self) -> dict[str, object]:
        formula = self.report["formula"]
        instances = self.report["instances"]
        self_tests = self.report["self_tests"]
        resources = self.report["resources"]
        if not all(
            isinstance(value, dict)
            for value in (formula, instances, self_tests, resources)
        ):
            raise AssertionError("foundation result sections differ")
        return {
            "schema": "o1-256-full-cnf-foundation-metrics-v1",
            "success_gate_passed": self.success_gate_passed,
            "result_sha256": self.report["result_sha256"],
            "unknown_target_key_bits": 256,
            "rounds": 20,
            "variable_count": formula["variable_count"],
            "template_clause_count": formula["clause_count"],
            "public_instance_clause_count": instances["public"]["instance_report"][
                "clause_count"
            ],
            "semantic_operation_count": formula["operation_count"],
            "template_sha256": formula["dimacs_sha256"],
            "map_sha256": formula["map_sha256"],
            "byte_identical_double_compile": self.report["determinism"][
                "byte_identical_double_compile"
            ],
            "rfc_fixed_key_status": self_tests["rfc_fixed_key"]["status"],
            "flipped_output_status": self_tests["rfc_flipped_output"]["status"],
            "second_fixed_key_status": self_tests["second_fixed_key"]["status"],
            "public_key_unit_clauses": instances["public"]["key_unit_clauses"],
            "paired_assumption_instances": 2,
            "solver_formula_calls": 3,
            "maximum_working_bytes": resources["peak_working_bytes"],
            "sibling_reads": 0,
            "sibling_writes": 0,
            "mps_calls": 0,
            "gpu_calls": 0,
            "fresh_random_targets": 0,
            "scientific_inverse_signal_claimed": False,
        }


def run_full256_cnf_foundation(
    config: Full256CNFFoundationConfig, workspace: str | Path
) -> Full256CNFFoundationResult:
    """Compile, self-test, and stage the exact O1C-0011 artifacts."""

    root = Path(workspace).resolve()
    root.mkdir(parents=True, exist_ok=True)
    if any(root.iterdir()):
        raise Full256CNFFoundationError("foundation workspace must be empty")
    solver = shutil.which("cadical")
    if solver is None:
        raise FileNotFoundError("cadical")
    solver_sha256 = _sha256_file(Path(solver))
    peak_working_bytes = 0

    def account() -> None:
        nonlocal peak_working_bytes
        peak_working_bytes = max(peak_working_bytes, _workspace_bytes(root))
        if peak_working_bytes > config.maximum_working_bytes:
            raise Full256CNFFoundationError("foundation exceeded working-byte budget")

    template = root / "full256_chacha20.cnf"
    map_path = root / "full256_chacha20.map.json"
    compiled = write_full256_template(template, map_path)
    verification = verify_full256_template(template, map_path)
    document = load_full256_template_map(map_path)
    account()

    expected_formula = (
        compiled.variable_count == config.expected_variable_count
        and compiled.clause_count == config.expected_clause_count
        and compiled.operation_count == config.expected_operation_count
        and compiled.dimacs_bytes == config.expected_dimacs_bytes
        and compiled.dimacs_sha256 == config.expected_dimacs_sha256
        and compiled.map_sha256 == config.expected_map_sha256
        and compiled.map_file_sha256 == config.expected_map_file_sha256
        and document["clause_length_histogram"]
        == config.expected_clause_length_histogram
    )

    second_root = root / "determinism_recompile"
    recompiled_template = second_root / template.name
    recompiled_map = second_root / map_path.name
    recompiled = write_full256_template(recompiled_template, recompiled_map)
    account()
    byte_identical = _files_equal(template, recompiled_template) and _files_equal(
        map_path, recompiled_map
    )
    hash_identical = (
        compiled.dimacs_sha256 == recompiled.dimacs_sha256
        and compiled.map_sha256 == recompiled.map_sha256
        and compiled.map_file_sha256 == recompiled.map_file_sha256
    )
    recompiled_template.unlink()
    recompiled_map.unlink()
    second_root.rmdir()

    if chacha20_block(config.rfc_key, config.rfc_counter, config.rfc_nonce) != config.rfc_output:
        raise Full256CNFFoundationError("local ChaCha20 differs from frozen RFC vector")
    public_path = root / "public_attacker_instance.cnf"
    public = write_full256_instance(
        template,
        map_path,
        public_path,
        counter=config.rfc_counter,
        nonce=config.rfc_nonce,
        output=config.rfc_output,
    )
    account()
    public_units = _tail_units(public_path, PUBLIC_UNIT_CLAUSES)
    public_unit_contract = (
        {abs(literal) for literal in public_units} == set(range(257, 897))
        and all(abs(literal) > 256 for literal in public_units)
        and public.key_fixed_for_self_test is False
        and public.assumption_unit_clause_count == 0
    )

    pair_reports: dict[str, dict[str, object]] = {}
    pair_contract = True
    for value in (0, 1):
        pair_path = root / f"paired_keybit_{config.paired_assumption_bit:03d}_eq_{value}.cnf"
        pair = write_full256_instance(
            template,
            map_path,
            pair_path,
            counter=config.rfc_counter,
            nonce=config.rfc_nonce,
            output=config.rfc_output,
            assumptions=((config.paired_assumption_bit, value),),
        )
        account()
        tail = _tail_units(pair_path, PUBLIC_UNIT_CLAUSES + 1)
        expected_literal = KEY_FIRST_VARIABLE + config.paired_assumption_bit
        if value == 0:
            expected_literal = -expected_literal
        pair_contract = pair_contract and (
            {abs(literal) for literal in tail[:-1]} == set(range(257, 897))
            and tail[-1] == expected_literal
            and pair.assumption_unit_clause_count == 1
            and pair.key_fixed_for_self_test is False
        )
        pair_reports[str(value)] = _instance_description(pair)

    def fixed_self_test(
        name: str, *, key: bytes, counter: int, nonce: bytes, output: bytes
    ) -> tuple[dict[str, object], int]:
        path = root / f"selftest_{name}.cnf"
        instance = write_full256_instance(
            template,
            map_path,
            path,
            counter=counter,
            nonce=nonce,
            output=output,
            key_for_self_test=key,
        )
        account()
        solver_result = run_cadical(
            path, executable=solver, timeout_seconds=config.solver_timeout_seconds
        )
        variables, clauses = _instance_header(path)
        description = {
            **_solver_description(solver_result),
            "instance_sha256": instance.instance_sha256,
            "instance_bytes": instance.instance_bytes,
            "variables": variables,
            "clauses": clauses,
            "key_fixed_for_self_test": True,
        }
        path.unlink()
        return description, solver_result.returncode

    rfc_test, rfc_code = fixed_self_test(
        "rfc_sat",
        key=config.rfc_key,
        counter=config.rfc_counter,
        nonce=config.rfc_nonce,
        output=config.rfc_output,
    )
    flipped_output = bytes((config.rfc_output[0] ^ 1,)) + config.rfc_output[1:]
    flipped_test, flipped_code = fixed_self_test(
        "rfc_flipped_unsat",
        key=config.rfc_key,
        counter=config.rfc_counter,
        nonce=config.rfc_nonce,
        output=flipped_output,
    )
    second_output = chacha20_block(
        config.second_key, config.second_counter, config.second_nonce
    )
    second_test, second_code = fixed_self_test(
        "second_sat",
        key=config.second_key,
        counter=config.second_counter,
        nonce=config.second_nonce,
        output=second_output,
    )
    account()

    gates = {
        "frozen_formula_bytes": expected_formula,
        "streaming_template_verification": verification["ok"] is True,
        "byte_identical_double_compile": byte_identical and hash_identical,
        "public_instance_has_zero_key_units": public_unit_contract,
        "paired_assumptions_change_only_one_key_unit": pair_contract,
        "rfc_fixed_key_sat": rfc_code == 10,
        "rfc_one_output_bit_flip_unsat": flipped_code == 20,
        "second_full256_fixed_key_sat": second_code == 10,
        "working_byte_budget": peak_working_bytes <= config.maximum_working_bytes,
    }
    gates["all_passed"] = all(gates.values())
    if not gates["all_passed"]:
        failed = sorted(name for name, passed in gates.items() if not passed)
        raise Full256CNFFoundationError(
            "mandatory full-256 CNF gates failed: " + ", ".join(failed)
        )

    persistent_paths = {
        "cnf/full256_chacha20.cnf": template,
        "cnf/full256_chacha20.map.json": map_path,
        "cnf/public_attacker_instance.cnf": public_path,
        (
            f"cnf/paired_keybit_{config.paired_assumption_bit:03d}_eq_0.cnf"
        ): root / f"paired_keybit_{config.paired_assumption_bit:03d}_eq_0.cnf",
        (
            f"cnf/paired_keybit_{config.paired_assumption_bit:03d}_eq_1.cnf"
        ): root / f"paired_keybit_{config.paired_assumption_bit:03d}_eq_1.cnf",
    }
    artifact_inventory = {
        name: {
            "sha256": _sha256_file(path),
            "bytes": path.stat().st_size,
        }
        for name, path in sorted(persistent_paths.items())
    }
    formula = {
        "variable_count": compiled.variable_count,
        "clause_count": compiled.clause_count,
        "clause_length_histogram": document["clause_length_histogram"],
        "operation_count": compiled.operation_count,
        "add32_operations": sum(
            row["kind"] == "add32" for row in document["operations"]
        ),
        "xor32_operations": sum(
            row["kind"] == "xor32" for row in document["operations"]
        ),
        "dimacs_bytes": compiled.dimacs_bytes,
        "dimacs_sha256": compiled.dimacs_sha256,
        "map_sha256": compiled.map_sha256,
        "map_file_sha256": compiled.map_file_sha256,
        "interface": document["interface"],
        "range_semantics": "one-based inclusive; null only for zero-allocation ranges",
        "symmetric_explicit_full_adder_wires": True,
        "final_overflow_carry_constrained": True,
    }
    unsigned_report: dict[str, object] = {
        "schema": FOUNDATION_RESULT_SCHEMA,
        "attacker_contract": {
            "cipher": "ChaCha20",
            "rounds": 20,
            "feed_forward": True,
            "unknown_key_bits": 256,
            "known_inputs": ["counter", "nonce", "512-bit output block"],
            "target_key_units": 0,
            "target_internal_state_inputs": 0,
            "target_internal_trace_inputs": 0,
        },
        "formula": formula,
        "determinism": {
            "two_pass_compile": True,
            "byte_identical_double_compile": byte_identical,
            "hash_identical_double_compile": hash_identical,
            "template_verification": verification,
        },
        "instances": {
            "public": {
                "instance_report": _instance_description(public),
                "key_unit_clauses": 0,
                "public_units_cover_variables_257_through_896_once": True,
            },
            "paired_key_bit": config.paired_assumption_bit,
            "paired": pair_reports,
            "pair_differs_only_by_final_assumption_literal": True,
        },
        "self_tests": {
            "solver_binary_sha256": solver_sha256,
            "rfc_fixed_key": rfc_test,
            "rfc_flipped_output": flipped_test,
            "second_fixed_key": second_test,
        },
        "gates": gates,
        "resources": {
            "peak_working_bytes": peak_working_bytes,
            "maximum_working_bytes": config.maximum_working_bytes,
            "persistent_artifact_bytes": sum(
                row["bytes"] for row in artifact_inventory.values()
            ),
            "solver_formula_calls": 3,
            "mps_calls": 0,
            "gpu_calls": 0,
            "sibling_reads": 0,
            "sibling_writes": 0,
        },
        "artifact_inventory": artifact_inventory,
        "scientific_claim_boundary": {
            "full256_relation_validated": True,
            "unknown_key_inversion_performed": False,
            "inverse_signal_claimed": False,
            "next_mechanism": (
                "paired key-bit assumptions -> bounded solver telemetry -> "
                "coordinate-bound O1 evidence state"
            ),
        },
    }
    report = {**unsigned_report, "result_sha256": canonical_sha256(unsigned_report)}
    return Full256CNFFoundationResult(
        report=report,
        artifact_paths=persistent_paths,
    )
