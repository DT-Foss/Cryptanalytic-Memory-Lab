"""Source-frozen O1C-0023 post-result composition capsule runner.

The runner starts only after the reserved O1C-0022 capsule is finalized and
manifest-valid.  It verifies the complete O1C-0022 artifact index, derives
quantization diagnostics from exactly four held-out K256 execution ledgers and
352-byte states, then asks native O1-O to select and assemble one data-only
operator marker twice in disposable directories.  Generated code is never
compiled or executed.
"""

from __future__ import annotations

import argparse
import ast
import base64
import fcntl
import hashlib
import json
import math
import os
import resource
import stat
import subprocess
import sys
import sysconfig
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Mapping, Sequence

from .living_inverse import canonical_json_bytes
from .o1c22_postresult_composer import (
    ATTEMPT_ID,
    O1O_FRAGMENT_FILENAME,
    O1O_KNOWLEDGE_FILENAME,
    OPERATOR_GRAPH_SCHEMA,
    UPSTREAM_ATTEMPT_ID,
    UPSTREAM_METRICS_SCHEMA,
    UPSTREAM_RESULT_SCHEMA,
    compose_postresult_decision,
    decision_policy,
    decision_policy_sha256,
    empty_failure_memory,
    encode_o1o_fragment_document,
    encode_o1o_route,
    next_operator_graph,
    summarize_quantization_artifacts,
    verify_decision,
)
from .run_capsule import ClaimLevel, FinalizedRun, RunCapsuleManager


RUN_CONFIG_SCHEMA = "o1-256-o1c22-postresult-composer-run-config-v1"
EXPERIMENT_SCHEMA = "o1-256-o1c22-postresult-composer-config-v1"
PREFLIGHT_SCHEMA = "o1-256-o1c22-postresult-composer-preflight-v1"
RUN_METRICS_SCHEMA = "o1-256-o1c22-postresult-composer-cli-result-v1"
SOURCE_INDEX_SCHEMA = "o1-256-o1c22-postresult-source-index-v1"
NATIVE_RECEIPT_SCHEMA = "o1-256-o1c22-native-o1o-double-assembly-v1"
ARTIFACT_INDEX_SCHEMA = "o1-256-o1c23-artifact-index-v1"
UPSTREAM_ARTIFACT_INDEX_SCHEMA = "o1-256-o1c19-causal-vault-artifact-index-v1"
UPSTREAM_EXECUTION_SCHEMA = "o1-256-o1c22-causal-vault-execution-v1"
UPSTREAM_CALIBRATION_FREEZE_SCHEMA = "o1-256-o1c22-calibration-prediction-freeze-v1"
UPSTREAM_PREDICTION_FREEZE_SCHEMA = "o1-256-o1c22-heldout-prediction-freeze-v1"
FORMAL_SLUG = "o1c22-postresult-native-composer-v1"
FORMAL_VAULT_BYTES = 352
EXPECTED_FOLDS = 4
EXPECTED_NATIVE_RUNS = 2
EXPECTED_UPSTREAM_ARTIFACTS = 384
EXPECTED_UPSTREAM_READER_REPLAYS = 32
EXPECTED_UPSTREAM_PACKET_SLOTS = 17_664
EXPECTED_UPSTREAM_PUBLIC_WORK = 1_130_496
EXPECTED_UPSTREAM_CALIBRATION_EVALUATIONS = 7_391_232
O1C22_SOURCE_FREEZE_COMMIT = "ce56ba44ef9fe8583c0603ab145afa6133849954"
_HEX = frozenset("0123456789abcdef")
_NATIVE_RESULT_PREFIX = b"O1C23_NATIVE_RESULT="

_UPSTREAM_MODULE_PATHS = {
    "module_causal_evidence_stream": "src/o1_crypto_lab/causal_evidence_stream.py",
    "module_causal_evidence_stream_run": (
        "src/o1_crypto_lab/causal_evidence_stream_run.py"
    ),
    "module_full256_action_pool": "src/o1_crypto_lab/full256_action_pool.py",
    "module_full256_multiresolution_build_loo": (
        "src/o1_crypto_lab/full256_multiresolution_build_loo.py"
    ),
    "module_full256_multiresolution_build_loo_run": (
        "src/o1_crypto_lab/full256_multiresolution_build_loo_run.py"
    ),
    "module_living_inverse": "src/o1_crypto_lab/living_inverse.py",
    "module_o1_streaming_core": "src/o1_crypto_lab/o1_streaming_core.py",
    "module_o1c19_causal_vault_bridge": (
        "src/o1_crypto_lab/o1c19_causal_vault_bridge.py"
    ),
    "module_o1c19_causal_vault_bridge_run": (
        "src/o1_crypto_lab/o1c19_causal_vault_bridge_run.py"
    ),
    "module_online_causal_controller": (
        "src/o1_crypto_lab/online_causal_controller.py"
    ),
    "module_online_multiresolution_controller": (
        "src/o1_crypto_lab/online_multiresolution_controller.py"
    ),
    "module_run_capsule": "src/o1_crypto_lab/run_capsule.py",
}

_UPSTREAM_EXECUTION_FILES = frozenset(
    {
        "causal_vault_bridge_execution.json",
        "causal_vault_bridge_ledger.json",
        "causal_vault_state.bin",
        "raw_float_control.f64le",
        "normalized_float_control.f64le",
        "unit_sign_control.i8",
        "last_only_control.i8",
        "shuffled_control.i8",
        "shuffled_destinations.u16le",
    }
)

_UPSTREAM_SCORED_FILES = frozenset(
    {
        "o1c19_causal_vault_bridge.json",
        "labels.bitpack",
        "raw_predictions.f64le",
        "calibrated_predictions.f64le",
        "calibration_scales.f64le",
        "nll_bits.f64le",
        "compression_bits.f64le",
        "upstream_o1c19_anchor.f32le",
    }
)

_UPSTREAM_BUDGET_CHECKS = frozenset(
    {
        "cpu",
        "wall",
        "resident_memory",
        "persistent_artifacts",
        "source_artifact_bytes_read",
        "existing_build_pools",
        "reader_replays",
        "packet_slots",
        "public_work",
        "calibration_value_evaluations",
        "physical_public_pools_generated",
        "native_solver_branches",
        "scientific_entropy",
        "sibling_reads",
        "sibling_writes",
        "mps",
        "gpu",
        "live_state",
    }
)

_EXPECTED_NATIVE_DEPENDENCIES = frozenset(
    {
        "jellyfish/__init__.py",
        "jellyfish/_jellyfish.py",
        "jellyfish/_rustyfish.cpython-313-darwin.so",
        "msgpack/__init__.py",
        "msgpack/_cmsgpack.cpython-313-darwin.so",
        "msgpack/exceptions.py",
        "msgpack/ext.py",
    }
)

_FORMAL_CONTROLS = (
    "O1C-0023 resolves only the verified finalized O1C-0022 attempt and checks its exact frozen config, artifact index, scored result, capsule metrics and four held-out K256 ledgers plus 352-byte states before reservation.",
    "The decision policy consumes the complete hash-bound post-reveal O1C-0022 result surface with an empty immutable failure memory; it is a proposal for a successor attempt, never evidence on a fresh target.",
    "O1-O receives exactly one opaque decision-token triplet, one data-only fragment and a byte-exact clone of the eight pinned core files in two independent disposable directories; the original sibling path is never disclosed to the child, assembly uses raw empty intent and generated code is neither compiled nor executed.",
    "Both native O1-O runs must select one identical fragment and emit byte-identical generated source under Python -I -B -S with a sanitized environment and exact imported-module origin/hash attestation.",
    "The exact O1-O KnowledgeEngine, CodeAssembler and imported assembler core source hashes are verified before and after both native runs, and the complete sibling tree metadata snapshot must remain unchanged.",
    "No fresh target, solver branch, scientific entropy, MPS or GPU call is permitted; sibling writes are exactly zero.",
)

_EXPECTED_CORE_FILES = frozenset(
    {
        "core/__init__.py",
        "core/c_renderer.py",
        "core/code_assembler.py",
        "core/color_assembler.py",
        "core/color_checker.py",
        "core/color_types.py",
        "core/fragment_registry.py",
        "core/knowledge_engine.py",
    }
)

_NATIVE_CHILD = r"""
import ast
import base64
import hashlib
import json
import resource
import signal
import sys
import sysconfig
import time
from pathlib import Path

native_cpu_started = time.process_time()
signal.alarm(35)

forge = Path(sys.argv[1]).resolve(strict=True)
knowledge_dir = Path(sys.argv[2]).resolve(strict=True)
fragment_dir = Path(sys.argv[3]).resolve(strict=True)
token = sys.argv[4]
expected_fragment = sys.argv[5]
expected_core = json.loads(base64.b64decode(sys.argv[6], validate=True))
expected_dependencies = json.loads(base64.b64decode(sys.argv[7], validate=True))
expected_marker = base64.b64decode(sys.argv[8], validate=True)
dependency_root = Path(sys.argv[9]).resolve(strict=True)
if not all((sys.flags.isolated, sys.flags.ignore_environment, sys.flags.no_site,
            sys.flags.no_user_site, sys.flags.safe_path, sys.dont_write_bytecode)):
    raise RuntimeError("native Python isolation flags differ")
if any(name in sys.modules for name in ("site", "sitecustomize", "usercustomize")):
    raise RuntimeError("site bootstrap entered isolated child")
startup_paths = list(sys.path)
site_roots = []
for key in ("purelib", "platlib"):
    value = str(Path(sysconfig.get_paths()[key]).resolve(strict=True))
    if value not in site_roots:
        site_roots.append(value)
if str(dependency_root) not in site_roots:
    raise RuntimeError("native dependency root differs")
sys.path[:] = [str(forge), *startup_paths, *site_roots]

from core.code_assembler import CodeAssembler
from core.knowledge_engine import KnowledgeEngine

core_module_names = {
    "core/__init__.py": "core",
    **{
        relative: "core." + Path(relative).stem
        for relative in expected_core
        if relative != "core/__init__.py"
    },
}
loaded_core = {
    name for name in sys.modules if name == "core" or name.startswith("core.")
}
if loaded_core != set(core_module_names.values()):
    raise RuntimeError("native imported core inventory differs")
core_attestation = {}
for relative, expected_sha in sorted(expected_core.items()):
    module_name = core_module_names[relative]
    origin = Path(sys.modules[module_name].__spec__.origin).resolve(strict=True)
    expected_origin = (forge / relative).resolve(strict=True)
    digest = hashlib.sha256(origin.read_bytes()).hexdigest()
    if origin != expected_origin or digest != expected_sha:
        raise RuntimeError("native imported core origin/hash differs")
    core_attestation[module_name] = {
        "relative": relative,
        "sha256": digest,
    }
dependency_attestation = {}
for name, module in sorted(sys.modules.items()):
    if not (name == "msgpack" or name.startswith("msgpack.") or
            name == "jellyfish" or name.startswith("jellyfish.")):
        continue
    origin_value = getattr(getattr(module, "__spec__", None), "origin", None)
    if not isinstance(origin_value, str):
        raise RuntimeError("native dependency origin is unavailable")
    origin = Path(origin_value).resolve(strict=True)
    relative = origin.relative_to(dependency_root).as_posix()
    digest = hashlib.sha256(origin.read_bytes()).hexdigest()
    if expected_dependencies.get(relative) != digest:
        raise RuntimeError("native dependency origin/hash differs")
    dependency_attestation[name] = {"relative": relative, "sha256": digest}
if {row["relative"] for row in dependency_attestation.values()} != set(expected_dependencies):
    raise RuntimeError("native dependency inventory differs")

knowledge = KnowledgeEngine(knowledge_dir)
knowledge.zero_shot = True
if set(knowledge.graphs) != {"bridge_intents"}:
    raise RuntimeError("native graph inventory differs")
graph = knowledge.graphs["bridge_intents"]
if not isinstance(graph, dict) or len(graph.get("triplets", [])) != 1:
    raise RuntimeError("native source graph must contain exactly one triplet")
selection_intent = {
    "raw": token,
    "entities": [],
    "tokens": [],
    "params": {},
    "mode": "BUILD",
    "confidence": 1.0,
    "requires_output": False,
}
paths = knowledge.infer(selection_intent, top_k=1)
if len(paths) != 1 or len(paths[0]) != 1:
    raise RuntimeError("native route is not exactly one path and one triplet")
triplet = paths[0][0]["triplet"]
if (
    triplet.get("trigger") != token
    or triplet.get("outcome") != expected_fragment
    or triplet.get("mechanism") != "pipeline"
    or triplet.get("_source_graph") != "bridge_intents"
):
    raise RuntimeError("native selected triplet differs")
assembler = CodeAssembler(fragment_dir, knowledge)
if set(assembler.fragments) != {expected_fragment}:
    raise RuntimeError("native fragment inventory is not exactly one")
assembly_intent = {
    "raw": "",
    "entities": [],
    "tokens": [],
    "params": {},
    "mode": "BUILD",
    "confidence": 1.0,
    "requires_output": False,
}
generated = assembler.assemble(paths[0], assembly_intent)
if assembler.last_used_fragments != [expected_fragment]:
    raise RuntimeError("native assembler used a different fragment set")
payload = generated.encode("utf-8")
tree = ast.parse(generated, filename="native_o1c23_generated.py", mode="exec")
assignments = [
    node for node in ast.walk(tree)
    if isinstance(node, ast.Assign)
    and len(node.targets) == 1
    and isinstance(node.targets[0], ast.Name)
    and node.targets[0].id == "NEXT_OPERATOR_JSON"
]
stores = [
    node for node in ast.walk(tree)
    if isinstance(node, ast.Name)
    and isinstance(node.ctx, ast.Store)
    and node.id == "NEXT_OPERATOR_JSON"
]
functions = [
    node for node in ast.walk(tree)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    and node.name == "selected_o1c22_operator"
]
if len(assignments) != 1 or len(stores) != 1 or len(functions) != 1:
    raise RuntimeError("native operator marker structure differs")
marker_value = ast.literal_eval(assignments[0].value)
function = functions[0]
if (
    type(marker_value) is not str
    or marker_value.encode("ascii") != expected_marker
    or function.args.args
    or function.args.posonlyargs
    or function.args.kwonlyargs
    or function.args.vararg is not None
    or function.args.kwarg is not None
    or len(function.body) != 1
    or not isinstance(function.body[0], ast.Return)
    or not isinstance(function.body[0].value, ast.Name)
    or function.body[0].value.id != "NEXT_OPERATOR_JSON"
):
    raise RuntimeError("native operator marker semantics differ")
marker = json.loads(marker_value)
print("O1C23_NATIVE_RESULT=" + json.dumps({
    "assembly_intent_raw": assembly_intent["raw"],
    "core_attestation": core_attestation,
    "dependency_attestation": dependency_attestation,
    "fragment_count": len(assembler.fragments),
    "generated_base64": base64.b64encode(payload).decode("ascii"),
    "generated_code_compiled": False,
    "generated_code_executed": False,
    "generated_sha256": hashlib.sha256(payload).hexdigest(),
    "generated_syntax_parsed": True,
    "graph_count": len(knowledge.graphs),
    "hash_determinism": "two-independent-byte-identical-native-runs",
    "isolation": {
        "dont_write_bytecode": True,
        "ignore_environment": True,
        "isolated": True,
        "no_site": True,
        "no_user_site": True,
        "safe_path": True,
        "site_modules_loaded": [],
    },
    "marker": marker,
    "marker_sha256": hashlib.sha256(expected_marker).hexdigest(),
    "outcome": triplet["outcome"],
    "python_flags": ["-I", "-B", "-S"],
    "resource_usage": {
        "cpu_seconds": time.process_time() - native_cpu_started,
        "peak_rss_raw": int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss),
        "peak_rss_unit": "bytes" if sys.platform == "darwin" else "kibibytes",
    },
    "source_graph": triplet["_source_graph"],
    "self_timeout_seconds": 35,
    "triplet_count": len(graph["triplets"]),
    "used_fragments": assembler.last_used_fragments,
}, sort_keys=True, separators=(",", ":")))
"""


class O1C22PostResultComposerRunError(ValueError):
    """A frozen config, prerequisite, native route, or budget differs."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _HEX for character in value)
    ):
        raise O1C22PostResultComposerRunError(f"{field} must be lowercase SHA-256")
    return value


def _mapping(
    value: object,
    field: str,
    expected: set[str] | frozenset[str] | None = None,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise O1C22PostResultComposerRunError(f"{field} must be an object")
    if expected is not None and set(value) != set(expected):
        raise O1C22PostResultComposerRunError(f"{field} fields differ")
    return value


def _sequence(value: object, field: str) -> Sequence[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise O1C22PostResultComposerRunError(f"{field} must be a sequence")
    return value


def _integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise O1C22PostResultComposerRunError(
            f"{field} must be an integer in [{minimum},{maximum}]"
        )
    return value


def _number(value: object, field: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise O1C22PostResultComposerRunError(f"{field} must be numeric")
    result = float(value)
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise O1C22PostResultComposerRunError(f"{field} differs")
    return result


def _read_json_payload(payload: bytes, field: str) -> Mapping[str, object]:
    try:
        value = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise O1C22PostResultComposerRunError(f"{field} is invalid JSON") from exc
    return _mapping(value, field)


def _read_json(path: Path, field: str) -> tuple[Mapping[str, object], bytes]:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise O1C22PostResultComposerRunError(f"{field} is unreadable") from exc
    return _read_json_payload(payload, field), payload


def _safe_relative(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise O1C22PostResultComposerRunError(f"{field} must be a relative path")
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise O1C22PostResultComposerRunError(f"{field} is unsafe")
    return value


def _rss_raw_to_bytes(value: int) -> int:
    return value if sys.platform == "darwin" else value * 1024


def _process_peak_rss_bytes() -> int:
    return _rss_raw_to_bytes(int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss))


@dataclass(frozen=True)
class RunResourceBaseline:
    parent_cpu_seconds: float
    children_cpu_seconds: float
    wall_seconds: float

    @classmethod
    def capture(cls) -> "RunResourceBaseline":
        children = resource.getrusage(resource.RUSAGE_CHILDREN)
        return cls(
            parent_cpu_seconds=time.process_time(),
            children_cpu_seconds=children.ru_utime + children.ru_stime,
            wall_seconds=time.monotonic(),
        )


def _measure_run_resources(
    baseline: RunResourceBaseline,
    native_rows: Sequence[Mapping[str, object]],
) -> dict[str, float | int]:
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    native_child_cpu_seconds = max(
        0.0,
        children.ru_utime + children.ru_stime - baseline.children_cpu_seconds,
    )
    parent_cpu_seconds = max(0.0, time.process_time() - baseline.parent_cpu_seconds)
    native_reported_cpu_seconds = sum(
        _number(
            row.get("native_cpu_seconds"),
            "native receipt CPU seconds",
            0.0,
            30.0,
        )
        for row in native_rows
    )
    native_peak_rss_bytes = max(
        (
            _integer(
                row.get("native_peak_rss_bytes"),
                "native receipt peak RSS",
                1,
                1 << 60,
            )
            for row in native_rows
        ),
        default=0,
    )
    child_rusage_peak_rss_bytes = _rss_raw_to_bytes(int(children.ru_maxrss))
    return {
        "parent_cpu_seconds": parent_cpu_seconds,
        "native_child_cpu_seconds": native_child_cpu_seconds,
        "native_reported_cpu_seconds": native_reported_cpu_seconds,
        "cpu_seconds": parent_cpu_seconds + native_child_cpu_seconds,
        "wall_seconds": max(0.0, time.monotonic() - baseline.wall_seconds),
        "native_peak_rss_bytes": native_peak_rss_bytes,
        "child_rusage_peak_rss_bytes": child_rusage_peak_rss_bytes,
        "peak_rss_bytes": max(
            _process_peak_rss_bytes(),
            child_rusage_peak_rss_bytes,
            native_peak_rss_bytes,
        ),
    }


@dataclass(frozen=True)
class O1C23Budgets:
    maximum_cpu_seconds: float
    maximum_wall_seconds: float
    maximum_resident_memory_mib: int
    maximum_persistent_artifact_bytes: int
    maximum_source_artifact_bytes_read: int
    expected_k256_heldout_folds: int
    required_primary_live_state_bytes: int
    maximum_native_o1o_invocations: int
    maximum_generated_source_bytes: int
    maximum_fresh_targets_consumed: int
    maximum_native_solver_branches: int
    maximum_scientific_entropy_calls: int
    maximum_sibling_writes: int
    maximum_mps_calls: int
    maximum_gpu_calls: int

    @classmethod
    def from_mapping(cls, value: object) -> "O1C23Budgets":
        row = _mapping(value, "budgets", set(cls.__dataclass_fields__))
        result = cls(
            maximum_cpu_seconds=_number(
                row["maximum_cpu_seconds"], "maximum_cpu_seconds", 0.001, 3600.0
            ),
            maximum_wall_seconds=_number(
                row["maximum_wall_seconds"], "maximum_wall_seconds", 0.001, 3600.0
            ),
            **{
                field: _integer(row[field], field, 0, 1 << 40)
                for field in cls.__dataclass_fields__
                if field not in {"maximum_cpu_seconds", "maximum_wall_seconds"}
            },
        )
        exact = {
            "maximum_cpu_seconds": 30.0,
            "maximum_wall_seconds": 60.0,
            "maximum_resident_memory_mib": 512,
            "maximum_persistent_artifact_bytes": 2_097_152,
            "maximum_source_artifact_bytes_read": 67_108_864,
            "expected_k256_heldout_folds": EXPECTED_FOLDS,
            "required_primary_live_state_bytes": FORMAL_VAULT_BYTES,
            "maximum_native_o1o_invocations": EXPECTED_NATIVE_RUNS,
            "maximum_generated_source_bytes": 65_536,
            "maximum_fresh_targets_consumed": 0,
            "maximum_native_solver_branches": 0,
            "maximum_scientific_entropy_calls": 0,
            "maximum_sibling_writes": 0,
            "maximum_mps_calls": 0,
            "maximum_gpu_calls": 0,
        }
        if any(getattr(result, name) != expected for name, expected in exact.items()):
            raise O1C22PostResultComposerRunError("budgets differ from frozen work")
        return result


@dataclass
class StructuralWorkLedger:
    native_o1o_invocations_started: int = 0
    native_o1o_invocations_returned: int = 0
    native_o1o_invocations_validated: int = 0
    generated_source_ast_parses: int = 0
    generated_source_bytecode_compilations: int = 0
    generated_source_executions: int = 0
    fresh_targets_consumed: int = 0
    native_solver_branches: int = 0
    scientific_entropy_calls: int = 0
    mps_calls: int = 0
    gpu_calls: int = 0
    sibling_mutations_observed_lower_bound: int = 0
    sibling_write_free_proven: bool = False

    @classmethod
    def from_document(cls, value: object) -> "StructuralWorkLedger":
        fields = set(cls.__dataclass_fields__)
        document = _mapping(
            value,
            "structural work ledger",
            fields | {"schema", "attempt_id", "work_ledger_sha256"},
        )
        if (
            document["schema"] != "o1-256-o1c23-structural-work-ledger-v1"
            or document["attempt_id"] != ATTEMPT_ID
        ):
            raise O1C22PostResultComposerRunError(
                "structural work ledger identity differs"
            )
        unsigned = {
            name: document[name] for name in document if name != "work_ledger_sha256"
        }
        if document["work_ledger_sha256"] != _sha256_bytes(
            canonical_json_bytes(unsigned)
        ):
            raise O1C22PostResultComposerRunError(
                "structural work ledger commitment differs"
            )
        counters = {
            name: _integer(document[name], name, 0, 1 << 30)
            for name in fields
            if name != "sibling_write_free_proven"
        }
        proof = document["sibling_write_free_proven"]
        if type(proof) is not bool:
            raise O1C22PostResultComposerRunError(
                "sibling_write_free_proven must be boolean"
            )
        return cls(**counters, sibling_write_free_proven=proof)

    def document(self) -> dict[str, object]:
        unsigned = {
            "schema": "o1-256-o1c23-structural-work-ledger-v1",
            "attempt_id": ATTEMPT_ID,
            **{name: getattr(self, name) for name in self.__dataclass_fields__},
        }
        return {
            **unsigned,
            "work_ledger_sha256": _sha256_bytes(canonical_json_bytes(unsigned)),
        }

    def validate_success(self, budgets: O1C23Budgets) -> None:
        expected = {
            "native_o1o_invocations_started": EXPECTED_NATIVE_RUNS,
            "native_o1o_invocations_returned": EXPECTED_NATIVE_RUNS,
            "native_o1o_invocations_validated": EXPECTED_NATIVE_RUNS,
            "generated_source_ast_parses": EXPECTED_NATIVE_RUNS,
            "generated_source_bytecode_compilations": 0,
            "generated_source_executions": 0,
            "fresh_targets_consumed": budgets.maximum_fresh_targets_consumed,
            "native_solver_branches": budgets.maximum_native_solver_branches,
            "scientific_entropy_calls": budgets.maximum_scientific_entropy_calls,
            "mps_calls": budgets.maximum_mps_calls,
            "gpu_calls": budgets.maximum_gpu_calls,
            "sibling_mutations_observed_lower_bound": 0,
            "sibling_write_free_proven": True,
        }
        if any(getattr(self, name) != value for name, value in expected.items()):
            raise O1C22PostResultComposerRunError(
                "observed structural work differs from frozen zero-authority contract"
            )


@dataclass(frozen=True)
class O1C23RunConfig:
    top: Mapping[str, object]
    config_path: Path
    root: Path
    budgets: O1C23Budgets
    upstream_top: Mapping[str, object]
    upstream_config_path: Path
    upstream_config_sha256: str
    upstream_static_source_sha256: Mapping[str, str]
    local_source_sha256: Mapping[str, str]
    composer_path: Path
    composer_sha256: str
    codec_path: Path
    codec_sha256: str
    o1o_repository: Path
    o1o_forge: Path
    o1o_core_sha256: Mapping[str, str]
    o1o_dependency_root: Path
    o1o_dependency_sha256: Mapping[str, str]


def load_o1c22_postresult_composer_run_config(
    path: str | Path,
    *,
    root: str | Path | None = None,
) -> O1C23RunConfig:
    config_path = Path(path).resolve(strict=True)
    lab_root = (
        Path(root).resolve(strict=True) if root is not None else config_path.parents[1]
    )
    if not config_path.is_relative_to(lab_root):
        raise O1C22PostResultComposerRunError("config escapes lab root")
    top, _payload = _read_json(config_path, "O1C-0023 config")
    expected_top = {
        "schema",
        "attempt_id",
        "slug",
        "claim_level",
        "hypothesis",
        "prediction",
        "controls",
        "budgets",
        "next_action",
        "experiment",
        "prerequisite",
        "source",
        "o1o",
    }
    _mapping(top, "O1C-0023 config", expected_top)
    if (
        top["schema"] != RUN_CONFIG_SCHEMA
        or top["attempt_id"] != ATTEMPT_ID
        or top["slug"] != FORMAL_SLUG
        or top["claim_level"] != ClaimLevel.RETROSPECTIVE.value
        or tuple(_sequence(top["controls"], "controls")) != _FORMAL_CONTROLS
        or any(
            not isinstance(top[field], str) or not str(top[field]).strip()
            for field in ("hypothesis", "prediction", "next_action")
        )
    ):
        raise O1C22PostResultComposerRunError("top-level frozen config differs")
    budgets = O1C23Budgets.from_mapping(top["budgets"])

    experiment = _mapping(
        top["experiment"],
        "experiment",
        {
            "schema",
            "assembly_intent_raw",
            "failure_memory",
            "generated_code_compiled",
            "generated_code_executed",
            "information_boundary",
            "native_o1o_runs",
            "native_selection",
            "required_fragment_count",
            "required_k256_fold_count",
            "required_triplet_count",
        },
    )
    expected_experiment = {
        "schema": EXPERIMENT_SCHEMA,
        "assembly_intent_raw": "",
        "failure_memory": "EMPTY_FIRST_DECISION",
        "generated_code_compiled": False,
        "generated_code_executed": False,
        "information_boundary": "POST_REVEAL_PROPOSAL_FOR_NEXT_ATTEMPT_ONLY",
        "native_o1o_runs": EXPECTED_NATIVE_RUNS,
        "native_selection": "single-opaque-token-exact-route",
        "required_fragment_count": 1,
        "required_k256_fold_count": EXPECTED_FOLDS,
        "required_triplet_count": 1,
    }
    if dict(experiment) != expected_experiment:
        raise O1C22PostResultComposerRunError("experiment differs")

    prerequisite = _mapping(
        top["prerequisite"],
        "prerequisite",
        {
            "attempt_id",
            "source_selection",
            "source_freeze_commit",
            "source_sha256",
            "config_path",
            "config_sha256",
            "artifact_index_schema",
            "result_schema",
            "metrics_schema",
        },
    )
    if (
        prerequisite["attempt_id"] != UPSTREAM_ATTEMPT_ID
        or prerequisite["source_selection"] != "reserved-finalized-attempt-only"
        or prerequisite["source_freeze_commit"] != O1C22_SOURCE_FREEZE_COMMIT
        or prerequisite["artifact_index_schema"] != UPSTREAM_ARTIFACT_INDEX_SCHEMA
        or prerequisite["result_schema"] != UPSTREAM_RESULT_SCHEMA
        or prerequisite["metrics_schema"] != UPSTREAM_METRICS_SCHEMA
    ):
        raise O1C22PostResultComposerRunError("prerequisite identity differs")
    upstream_relative = _safe_relative(
        prerequisite["config_path"], "prerequisite.config_path"
    )
    upstream_path = (lab_root / upstream_relative).resolve(strict=True)
    if not upstream_path.is_relative_to(lab_root):
        raise O1C22PostResultComposerRunError("upstream config escapes lab")
    upstream_sha = _sha256(prerequisite["config_sha256"], "prerequisite.config_sha256")
    if _sha256_file(upstream_path) != upstream_sha:
        raise O1C22PostResultComposerRunError("upstream config hash differs")
    upstream_top, _ = _read_json(upstream_path, "O1C-0022 source config")
    raw_upstream_sources = _mapping(
        prerequisite["source_sha256"], "prerequisite.source_sha256"
    )
    expected_upstream_source_labels = {"pyproject", *_UPSTREAM_MODULE_PATHS}
    if set(raw_upstream_sources) != expected_upstream_source_labels:
        raise O1C22PostResultComposerRunError(
            "O1C-0022 static source inventory differs"
        )
    upstream_static_sources = {
        label: _sha256(digest, f"prerequisite.source_sha256.{label}")
        for label, digest in raw_upstream_sources.items()
    }
    upstream_source_paths = {
        "pyproject": lab_root / "pyproject.toml",
        **{
            label: lab_root / relative
            for label, relative in _UPSTREAM_MODULE_PATHS.items()
        },
    }
    if any(
        _sha256_file(upstream_source_paths[label]) != digest
        for label, digest in upstream_static_sources.items()
    ):
        raise O1C22PostResultComposerRunError("O1C-0022 static source bytes differ")

    source = _mapping(
        top["source"],
        "source",
        {
            "composer_path",
            "composer_sha256",
            "o1o_codec_path",
            "o1o_codec_sha256",
            "runner_path",
            "runner_sha256",
            "run_capsule_path",
            "run_capsule_sha256",
            "living_inverse_path",
            "living_inverse_sha256",
            "pyproject_path",
            "pyproject_sha256",
            "policy_sha256",
        },
    )
    source_specs = {
        "composer": ("composer_path", "composer_sha256"),
        "o1o_codec": ("o1o_codec_path", "o1o_codec_sha256"),
        "runner": ("runner_path", "runner_sha256"),
        "run_capsule": ("run_capsule_path", "run_capsule_sha256"),
        "living_inverse": ("living_inverse_path", "living_inverse_sha256"),
        "pyproject": ("pyproject_path", "pyproject_sha256"),
    }
    local_paths: dict[str, Path] = {}
    local_hashes: dict[str, str] = {}
    for label, (path_field, sha_field) in source_specs.items():
        candidate = (lab_root / _safe_relative(source[path_field], path_field)).resolve(
            strict=True
        )
        if not candidate.is_relative_to(lab_root):
            raise O1C22PostResultComposerRunError("source path escapes lab")
        digest = _sha256(source[sha_field], sha_field)
        if _sha256_file(candidate) != digest:
            raise O1C22PostResultComposerRunError(
                f"local source freeze differs: {label}"
            )
        local_paths[label] = candidate
        local_hashes[label] = digest
    composer_path = local_paths["composer"]
    codec_path = local_paths["o1o_codec"]
    composer_sha = local_hashes["composer"]
    codec_sha = local_hashes["o1o_codec"]
    if source["policy_sha256"] != decision_policy_sha256():
        raise O1C22PostResultComposerRunError("composer source freeze differs")

    o1o = _mapping(
        top["o1o"],
        "o1o",
        {
            "repository_path",
            "forge_relative_path",
            "core_source_sha256",
            "dependency_root",
            "dependency_source_sha256",
            "python_flags",
            "hash_determinism",
        },
    )
    if (
        o1o["repository_path"] != "../O1-O"
        or o1o["forge_relative_path"] != "forge"
        or o1o["dependency_root"] != "sysconfig.purelib"
        or o1o["python_flags"] != ["-I", "-B", "-S"]
        or o1o["hash_determinism"] != "two-independent-byte-identical-native-runs"
    ):
        raise O1C22PostResultComposerRunError("O1-O execution freeze differs")
    repository = (lab_root / str(o1o["repository_path"])).resolve(strict=True)
    if repository != (lab_root.parent / "O1-O").resolve(strict=True):
        raise O1C22PostResultComposerRunError("O1-O repository identity differs")
    forge = (repository / str(o1o["forge_relative_path"])).resolve(strict=True)
    if not (forge / "core").is_dir():
        raise O1C22PostResultComposerRunError("O1-O forge core is unavailable")
    raw_core = _mapping(o1o["core_source_sha256"], "core_source_sha256")
    if set(raw_core) != _EXPECTED_CORE_FILES:
        raise O1C22PostResultComposerRunError("O1-O core source inventory differs")
    core_sha = {
        relative: _sha256(digest, f"core_source_sha256.{relative}")
        for relative, digest in raw_core.items()
    }
    dependency_root = Path(sysconfig.get_paths()["purelib"]).resolve(strict=True)
    raw_dependencies = _mapping(
        o1o["dependency_source_sha256"], "dependency_source_sha256"
    )
    if set(raw_dependencies) != _EXPECTED_NATIVE_DEPENDENCIES:
        raise O1C22PostResultComposerRunError(
            "native dependency source inventory differs"
        )
    dependency_sha = {
        relative: _sha256(digest, f"dependency_source_sha256.{relative}")
        for relative, digest in raw_dependencies.items()
    }
    for relative, digest in dependency_sha.items():
        path = (dependency_root / relative).resolve(strict=True)
        if not path.is_relative_to(dependency_root) or _sha256_file(path) != digest:
            raise O1C22PostResultComposerRunError(
                f"native dependency source differs: {relative}"
            )
    result = O1C23RunConfig(
        top=top,
        config_path=config_path,
        root=lab_root,
        budgets=budgets,
        upstream_top=upstream_top,
        upstream_config_path=upstream_path,
        upstream_config_sha256=upstream_sha,
        upstream_static_source_sha256=dict(sorted(upstream_static_sources.items())),
        local_source_sha256=dict(sorted(local_hashes.items())),
        composer_path=composer_path,
        composer_sha256=composer_sha,
        codec_path=codec_path,
        codec_sha256=codec_sha,
        o1o_repository=repository,
        o1o_forge=forge,
        o1o_core_sha256=dict(sorted(core_sha.items())),
        o1o_dependency_root=dependency_root,
        o1o_dependency_sha256=dict(sorted(dependency_sha.items())),
    )
    _verify_o1o_core_sources(result)
    return result


@dataclass(frozen=True)
class O1C22K256FoldArtifacts:
    fold_index: int
    target_id: str
    ledger_relative: str
    ledger_payload: bytes
    ledger_sha256: str
    state_relative: str
    state_payload: bytes
    state_sha256: str
    execution_relative: str
    execution_sha256: str

    def describe(self) -> dict[str, object]:
        return {
            "fold_index": self.fold_index,
            "target_id": self.target_id,
            "ledger": {
                "path": self.ledger_relative,
                "bytes": len(self.ledger_payload),
                "sha256": self.ledger_sha256,
            },
            "state": {
                "path": self.state_relative,
                "bytes": len(self.state_payload),
                "sha256": self.state_sha256,
            },
            "execution": {
                "path": self.execution_relative,
                "sha256": self.execution_sha256,
            },
        }


@dataclass(frozen=True)
class O1C22PostResultSource:
    finalized: FinalizedRun
    result: Mapping[str, object]
    metrics: Mapping[str, object]
    folds: tuple[O1C22K256FoldArtifacts, ...]
    diagnostics: Mapping[str, object]
    artifact_index_sha256: str
    result_file_sha256: str
    metrics_file_sha256: str
    config_file_sha256: str
    source_artifact_bytes_read: int


def _indexed_entry(
    artifacts: Mapping[str, object],
    relative: str,
    payload: bytes,
) -> Mapping[str, object]:
    entry = _mapping(
        artifacts.get(relative),
        f"artifact index entry {relative}",
        {"sha256", "bytes", "phase"},
    )
    if (
        _sha256(entry["sha256"], f"artifact {relative} sha256")
        != _sha256_bytes(payload)
        or entry["bytes"] != len(payload)
        or not isinstance(entry["phase"], str)
        or not entry["phase"]
    ):
        raise O1C22PostResultComposerRunError(
            f"artifact index entry differs: {relative}"
        )
    return entry


def _git_commit_descends_from_source_freeze(root: Path, commit: str) -> bool:
    if (
        len(commit) != 40
        or any(character not in _HEX for character in commit)
        or commit == "0" * 40
    ):
        return False
    probe = subprocess.run(
        (
            "git",
            "merge-base",
            "--is-ancestor",
            O1C22_SOURCE_FREEZE_COMMIT,
            commit,
        ),
        cwd=root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
        check=False,
    )
    return probe.returncode == 0


def _validate_upstream_source_hashes(
    config: O1C23RunConfig,
    source_hashes: object,
) -> Mapping[str, str]:
    sources = _mapping(source_hashes, "O1C-0022 source hashes")
    dynamic = {
        "o1c19_capsule_manifest",
        "o1c19_artifact_index",
        "o1c19_result",
        *{
            f"o1c19_fold_{fold_index:02d}_{suffix}"
            for fold_index in range(EXPECTED_FOLDS)
            for suffix in (
                "reader",
                "slow_state",
                "learning_freeze",
                "prediction_freeze",
            )
        },
    }
    fixed = {
        "config",
        "pyproject",
        "o1c18_capsule_manifest",
        "o1c18_artifact_index",
        "o1c18_artifact_corpus",
        "o1c19_source_config",
        "o1c21_source_config",
        *_UPSTREAM_MODULE_PATHS,
    }
    if set(sources) != fixed | dynamic:
        raise O1C22PostResultComposerRunError("O1C-0022 source hash inventory differs")
    normalized = {
        label: _sha256(value, f"O1C-0022 source hash {label}")
        for label, value in sources.items()
    }
    upstream_source = _mapping(config.upstream_top.get("source"), "upstream source")
    prerequisites = _mapping(
        config.upstream_top.get("prerequisites"), "upstream prerequisites"
    )
    o1c19 = _mapping(prerequisites.get("o1c19"), "upstream O1C-0019")
    o1c21 = _mapping(prerequisites.get("o1c21_state"), "upstream O1C-0021")
    expected_fixed = {
        "config": config.upstream_config_sha256,
        "pyproject": config.upstream_static_source_sha256["pyproject"],
        "o1c18_capsule_manifest": upstream_source.get("o1c18_manifest_sha256"),
        "o1c18_artifact_index": upstream_source.get("o1c18_artifact_index_sha256"),
        "o1c18_artifact_corpus": upstream_source.get(
            "o1c18_public_build_corpus_sha256"
        ),
        "o1c19_source_config": o1c19.get("config_sha256"),
        "o1c21_source_config": o1c21.get("config_sha256"),
        **{
            label: config.upstream_static_source_sha256[label]
            for label in _UPSTREAM_MODULE_PATHS
        },
    }
    if any(normalized[label] != expected for label, expected in expected_fixed.items()):
        raise O1C22PostResultComposerRunError("O1C-0022 fixed source hash differs")
    return dict(sorted(normalized.items()))


def _authoritative_finalized_o1c22(
    config: O1C23RunConfig,
    candidate: FinalizedRun,
) -> FinalizedRun:
    manager = RunCapsuleManager(config.root)
    authoritative = manager.finalized_attempt(UPSTREAM_ATTEMPT_ID)
    if authoritative is None:
        raise O1C22PostResultComposerRunError(
            "authoritative finalized O1C-0022 capsule is unavailable"
        )
    fresh = manager.verify(authoritative.path)
    try:
        candidate_path = candidate.path.resolve(strict=True)
        authoritative_path = authoritative.path.resolve(strict=True)
    except OSError as exc:
        raise O1C22PostResultComposerRunError(
            "O1C-0022 finalized path is unavailable"
        ) from exc
    if (
        candidate.attempt_id != UPSTREAM_ATTEMPT_ID
        or candidate_path != authoritative_path
        or candidate.manifest_sha256 != authoritative.manifest_sha256
        or authoritative.verification.schema != "o1c-capsule-verification-v1"
        or fresh.schema != "o1c-capsule-verification-v1"
        or fresh.path.resolve(strict=True) != authoritative_path
        or fresh.manifest_sha256 != authoritative.manifest_sha256
        or not authoritative.verification.ok
        or not fresh.ok
    ):
        raise O1C22PostResultComposerRunError(
            "O1C-0022 capsule is not the authoritative manager-verified publication"
        )
    return authoritative


def _validate_upstream_resource_metrics(
    config: O1C23RunConfig,
    outer_metrics: Mapping[str, object],
    metrics: Mapping[str, object],
    *,
    indexed_artifact_bytes: int,
    artifact_index_bytes: int,
) -> None:
    upstream_budgets = _mapping(config.upstream_top.get("budgets"), "upstream budgets")
    cpu_seconds = _number(metrics.get("cpu_seconds"), "O1C-0022 cpu", 0.0, 1e12)
    wall_seconds = _number(metrics.get("wall_seconds"), "O1C-0022 wall", 0.0, 1e12)
    peak_rss = _integer(metrics.get("peak_rss_bytes"), "O1C-0022 RSS", 0, 1 << 60)
    persistent = _integer(
        metrics.get("persistent_artifact_bytes"),
        "O1C-0022 persistent bytes",
        0,
        1 << 60,
    )
    source_bytes = _integer(
        metrics.get("source_artifact_bytes_read"),
        "O1C-0022 source bytes",
        0,
        1 << 60,
    )
    maximum_cpu = _number(
        upstream_budgets.get("maximum_cpu_seconds"),
        "upstream maximum CPU",
        0.0,
        1e12,
    )
    maximum_wall = _number(
        upstream_budgets.get("maximum_wall_seconds"),
        "upstream maximum wall",
        0.0,
        1e12,
    )
    maximum_rss_mib = _integer(
        upstream_budgets.get("maximum_resident_memory_mib"),
        "upstream maximum RSS",
        1,
        1 << 30,
    )
    maximum_persistent = _integer(
        upstream_budgets.get("maximum_persistent_artifact_bytes"),
        "upstream maximum persistent bytes",
        1,
        1 << 60,
    )
    maximum_source = _integer(
        upstream_budgets.get("maximum_source_artifact_bytes_read"),
        "upstream maximum source bytes",
        1,
        1 << 60,
    )
    if (
        persistent != indexed_artifact_bytes + artifact_index_bytes
        or metrics.get("reader_replays") != EXPECTED_UPSTREAM_READER_REPLAYS
        or metrics.get("packet_slots") != EXPECTED_UPSTREAM_PACKET_SLOTS
        or metrics.get("physical_public_work_units") != EXPECTED_UPSTREAM_PUBLIC_WORK
        or metrics.get("calibration_value_evaluations")
        != EXPECTED_UPSTREAM_CALIBRATION_EVALUATIONS
    ):
        raise O1C22PostResultComposerRunError("O1C-0022 exact resource counters differ")
    expected_checks = {
        "cpu": cpu_seconds <= maximum_cpu,
        "wall": wall_seconds <= maximum_wall,
        "resident_memory": peak_rss <= maximum_rss_mib * 1024 * 1024,
        "persistent_artifacts": persistent <= maximum_persistent,
        "source_artifact_bytes_read": source_bytes <= maximum_source,
        "existing_build_pools": upstream_budgets["expected_existing_build_pools"]
        == EXPECTED_FOLDS,
        "reader_replays": metrics.get("reader_replays")
        == upstream_budgets["maximum_o1c19_reader_replays"],
        "packet_slots": metrics.get("packet_slots")
        == upstream_budgets["maximum_packet_slot_observations"],
        "public_work": metrics.get("physical_public_work_units")
        == upstream_budgets["maximum_physical_public_work_units"],
        "calibration_value_evaluations": metrics.get("calibration_value_evaluations")
        == upstream_budgets["maximum_calibration_value_evaluations"],
        "physical_public_pools_generated": upstream_budgets[
            "maximum_physical_public_pools_generated"
        ]
        == 0,
        "native_solver_branches": upstream_budgets["maximum_native_solver_branches"]
        == 0,
        "scientific_entropy": upstream_budgets["maximum_scientific_entropy_calls"] == 0,
        "sibling_reads": upstream_budgets["maximum_sibling_reads"] == 0,
        "sibling_writes": upstream_budgets["maximum_sibling_writes"] == 0,
        "mps": upstream_budgets["maximum_mps_calls"] == 0,
        "gpu": upstream_budgets["maximum_gpu_calls"] == 0,
        "live_state": upstream_budgets["maximum_accumulator_live_state_bytes"]
        == FORMAL_VAULT_BYTES,
    }
    supplied_checks = _mapping(metrics.get("budget_checks"), "O1C-0022 budgets")
    if (
        set(supplied_checks) != _UPSTREAM_BUDGET_CHECKS
        or any(not isinstance(value, bool) for value in supplied_checks.values())
        or dict(supplied_checks) != expected_checks
    ):
        raise O1C22PostResultComposerRunError(
            "O1C-0022 budget checks are not recomputable"
        )
    expected_failed = sorted(
        name for name, passed in expected_checks.items() if not passed
    )
    failed = list(_sequence(metrics.get("failed_budgets"), "failed_budgets"))
    operational = metrics.get("operationally_complete")
    if (
        failed != expected_failed
        or not isinstance(operational, bool)
        or operational is not (not expected_failed)
        or outer_metrics.get("status") != ("completed" if operational else "failed")
    ):
        raise O1C22PostResultComposerRunError("O1C-0022 operational metrics differ")


def _expected_upstream_fold_artifacts(
    target_id: str,
    training_target_ids: Sequence[str],
) -> tuple[set[str], set[str]]:
    prefix = f"folds/{target_id}"
    calibration: set[str] = {
        f"{prefix}/calibration/quantizer.json",
        f"{prefix}/calibration/raw_predictions.f64le",
        f"{prefix}/calibration/prediction_freeze.json",
    }
    for training_target in training_target_ids:
        source = f"{prefix}/calibration/source-{training_target}"
        calibration.update(
            {
                f"{source}/active_coordinates.json",
                f"{source}/packet_deltas.json",
                *{f"{source}/execution/{name}" for name in _UPSTREAM_EXECUTION_FILES},
            }
        )
    heldout: set[str] = {
        f"{prefix}/heldout/active_coordinates.json",
        f"{prefix}/heldout/quantizer.json",
        f"{prefix}/heldout/calibration_scales.f64le",
        f"{prefix}/heldout/upstream_o1c19_learned_reader_exhaustive.f32le",
        f"{prefix}/heldout/pre_oracle_controls.json",
        f"{prefix}/heldout/raw_predictions.f64le",
        f"{prefix}/heldout/calibrated_predictions.f64le",
        f"{prefix}/heldout/prediction_freeze.json",
    }
    for width in (12, 52, 128, 256):
        source = f"{prefix}/heldout/k{width:03d}"
        heldout.add(f"{source}/packet_deltas.json")
        heldout.update(
            f"{source}/execution/{name}" for name in _UPSTREAM_EXECUTION_FILES
        )
    swap = f"{prefix}/heldout/polarity_swap"
    heldout.add(f"{swap}/packet_deltas.json")
    heldout.update(f"{swap}/execution/{name}" for name in _UPSTREAM_EXECUTION_FILES)
    if len(calibration) != 36 or len(heldout) != 58:
        raise AssertionError("frozen upstream fold inventory is internally invalid")
    return calibration, heldout


def _validate_freeze_commitments(
    document: Mapping[str, object],
    *,
    payloads: Mapping[str, bytes],
    artifacts: Mapping[str, object],
    phase: str,
    freeze_relative: str,
    expected_phase_names: set[str],
) -> None:
    unsigned = dict(document)
    supplied = _sha256(unsigned.pop("freeze_sha256", None), "freeze_sha256")
    if supplied != _sha256_bytes(canonical_json_bytes(unsigned)):
        raise O1C22PostResultComposerRunError("O1C-0022 freeze digest differs")
    commitments = _mapping(document.get("artifacts"), "freeze artifacts")
    if set(commitments) != expected_phase_names - {freeze_relative}:
        raise O1C22PostResultComposerRunError(
            "O1C-0022 freeze artifact inventory differs"
        )
    actual_phase_names = {
        name
        for name, raw_entry in artifacts.items()
        if _mapping(raw_entry, f"artifact {name}").get("phase") == phase
    }
    if actual_phase_names != expected_phase_names:
        raise O1C22PostResultComposerRunError("O1C-0022 artifact phase differs")
    for relative, raw_commitment in commitments.items():
        commitment = _mapping(
            raw_commitment,
            f"freeze commitment {relative}",
            {"sha256", "bytes"},
        )
        payload = payloads.get(relative)
        if (
            payload is None
            or commitment.get("sha256") != _sha256_bytes(payload)
            or commitment.get("bytes") != len(payload)
        ):
            raise O1C22PostResultComposerRunError(
                f"O1C-0022 freeze commitment differs: {relative}"
            )


def _validate_upstream_lifecycle_inventory(
    payloads: Mapping[str, bytes],
    artifacts: Mapping[str, object],
    capsule_sources: Mapping[str, str],
) -> None:
    expected_all = set(_UPSTREAM_SCORED_FILES)
    for fold_index in range(EXPECTED_FOLDS):
        target_id = f"build-{fold_index:04d}"
        training_ordinals = [
            (fold_index + offset) % EXPECTED_FOLDS
            for offset in range(1, EXPECTED_FOLDS)
        ]
        training_targets = [f"build-{index:04d}" for index in training_ordinals]
        calibration_names, heldout_names = _expected_upstream_fold_artifacts(
            target_id, training_targets
        )
        expected_all.update(calibration_names)
        expected_all.update(heldout_names)
        calibration_relative = f"folds/{target_id}/calibration/prediction_freeze.json"
        heldout_relative = f"folds/{target_id}/heldout/prediction_freeze.json"
        calibration_payload = payloads.get(calibration_relative)
        if calibration_payload is None:
            raise O1C22PostResultComposerRunError(
                f"O1C-0022 calibration freeze {fold_index} is missing"
            )
        calibration = _read_json_payload(
            calibration_payload, f"calibration freeze {fold_index}"
        )
        calibration_fields = {
            "schema",
            "phase",
            "fold_index",
            "held_out_ordinal",
            "held_out_target_id",
            "training_ordinals",
            "training_target_ids",
            "reader_state_sha256",
            "slow_state_sha256",
            "quantizer_sha256",
            "labels_used_by_this_fold_before_calibration_freeze",
            "held_out_label_used_for_this_fold",
            "previously_opened_build_label_ordinals",
            "build_labels_may_have_been_opened_in_other_folds",
            "reader_updates",
            "solver_calls",
            "artifacts",
            "freeze_sha256",
        }
        if set(calibration) != calibration_fields or (
            calibration.get("schema") != UPSTREAM_CALIBRATION_FREEZE_SCHEMA
            or calibration.get("phase")
            != "THIS_FOLD_TRAINING_PUBLIC_DELTAS_STATES_AND_PREDICTIONS_FROZEN_BEFORE_THIS_FOLD_CALIBRATION_LABEL_USE"
            or calibration.get("fold_index") != fold_index
            or calibration.get("held_out_ordinal") != fold_index
            or calibration.get("held_out_target_id") != target_id
            or calibration.get("training_ordinals") != training_ordinals
            or calibration.get("training_target_ids") != training_targets
            or calibration.get("labels_used_by_this_fold_before_calibration_freeze")
            != []
            or calibration.get("held_out_label_used_for_this_fold") is not False
            or calibration.get("reader_updates") != 0
            or calibration.get("solver_calls") != 0
            or calibration.get("reader_state_sha256")
            != capsule_sources[f"o1c19_fold_{fold_index:02d}_reader"]
            or calibration.get("slow_state_sha256")
            != capsule_sources[f"o1c19_fold_{fold_index:02d}_slow_state"]
        ):
            raise O1C22PostResultComposerRunError(
                f"O1C-0022 calibration freeze {fold_index} differs"
            )
        _sha256(calibration.get("quantizer_sha256"), "quantizer_sha256")
        _validate_freeze_commitments(
            calibration,
            payloads=payloads,
            artifacts=artifacts,
            phase=f"CALIBRATION_PREDICTIONS_FROZEN_FOLD_{fold_index}",
            freeze_relative=calibration_relative,
            expected_phase_names=calibration_names,
        )

        heldout_payload = payloads.get(heldout_relative)
        if heldout_payload is None:
            raise O1C22PostResultComposerRunError(
                f"O1C-0022 held-out freeze {fold_index} is missing"
            )
        heldout = _read_json_payload(heldout_payload, f"held-out freeze {fold_index}")
        heldout_fields = {
            "schema",
            "phase",
            "fold_index",
            "held_out_ordinal",
            "held_out_target_id",
            "held_out_action_pool_sha256",
            "reader_state_sha256",
            "slow_state_sha256",
            "upstream_prediction_freeze_sha256",
            "quantizer_sha256",
            "calibration_scales",
            "active_coordinate_plan_sha256",
            "active_coordinate_counts",
            "prediction_arms",
            "calibration_label_ordinals_used_for_this_fold",
            "held_out_label_used_for_this_fold",
            "previously_opened_build_label_ordinals",
            "held_out_label_may_have_been_opened_in_other_fold",
            "held_out_reader_updates",
            "solver_calls",
            "artifacts",
            "freeze_sha256",
        }
        if set(heldout) != heldout_fields or (
            heldout.get("schema") != UPSTREAM_PREDICTION_FREEZE_SCHEMA
            or heldout.get("phase")
            != "ALL_HELDOUT_DELTAS_SCALES_STATES_CONTROLS_AND_PREDICTIONS_FROZEN_BEFORE_LABEL_ORACLE"
            or heldout.get("fold_index") != fold_index
            or heldout.get("held_out_ordinal") != fold_index
            or heldout.get("held_out_target_id") != target_id
            or heldout.get("reader_state_sha256")
            != capsule_sources[f"o1c19_fold_{fold_index:02d}_reader"]
            or heldout.get("slow_state_sha256")
            != capsule_sources[f"o1c19_fold_{fold_index:02d}_slow_state"]
            or heldout.get("upstream_prediction_freeze_sha256")
            != capsule_sources[f"o1c19_fold_{fold_index:02d}_prediction_freeze"]
            or heldout.get("quantizer_sha256") != calibration.get("quantizer_sha256")
            or heldout.get("active_coordinate_counts") != [12, 52, 128, 256]
            or heldout.get("prediction_arms")
            != [
                "raw_float_delta_sum",
                "normalized_float_delta_sum",
                "quantized_int8_vault",
                "last_horizon_only",
                "unit_sign_sum",
                "coordinate_shuffled_vault",
                "zero_prior",
            ]
            or heldout.get("calibration_label_ordinals_used_for_this_fold")
            != training_ordinals
            or heldout.get("held_out_label_used_for_this_fold") is not False
            or heldout.get("held_out_reader_updates") != 0
            or heldout.get("solver_calls") != 0
        ):
            raise O1C22PostResultComposerRunError(
                f"O1C-0022 held-out freeze {fold_index} differs"
            )
        _sha256(heldout.get("held_out_action_pool_sha256"), "action pool SHA")
        _sha256(heldout.get("active_coordinate_plan_sha256"), "active plan SHA")
        calibration_scales = _sequence(
            heldout.get("calibration_scales"), "calibration scales"
        )
        if len(calibration_scales) != 7 or any(
            not 0.0 <= _number(value, "calibration scale", 0.0, 2.0) <= 2.0
            for value in calibration_scales
        ):
            raise O1C22PostResultComposerRunError("calibration scale inventory differs")
        _validate_freeze_commitments(
            heldout,
            payloads=payloads,
            artifacts=artifacts,
            phase=f"HELDOUT_PREDICTIONS_FROZEN_FOLD_{fold_index}",
            freeze_relative=heldout_relative,
            expected_phase_names=heldout_names,
        )
    scored_phase_names = {
        name
        for name, raw_entry in artifacts.items()
        if _mapping(raw_entry, f"artifact {name}").get("phase")
        == "POST_FREEZE_SCORED_RESULT"
    }
    if (
        scored_phase_names != set(_UPSTREAM_SCORED_FILES)
        or set(payloads) != expected_all
    ):
        raise O1C22PostResultComposerRunError(
            "O1C-0022 exact 384-artifact lifecycle inventory differs"
        )


def _load_verified_o1c22_source(
    config: O1C23RunConfig,
    finalized: FinalizedRun,
) -> O1C22PostResultSource:
    authoritative = _authoritative_finalized_o1c22(config, finalized)
    return _load_bound_o1c22_source(config, authoritative)


def _load_bound_o1c22_source(
    config: O1C23RunConfig,
    finalized: FinalizedRun,
) -> O1C22PostResultSource:
    """Validate payload semantics after an authoritative manager lookup."""

    if finalized.attempt_id != UPSTREAM_ATTEMPT_ID or not finalized.verification.ok:
        raise O1C22PostResultComposerRunError("O1C-0022 capsule identity differs")
    capsule = finalized.path
    capsule_config, config_payload = _read_json(
        capsule / "config.json", "O1C-0022 capsule config"
    )
    expected_capsule_config_fields = {
        "schema",
        "publication_protocol",
        "attempt_id",
        "commit",
        "hypothesis",
        "prediction",
        "controls",
        "budgets",
        "source_hashes",
        "claim_level",
        "next_action",
        "config",
    }
    if set(capsule_config) != expected_capsule_config_fields or (
        capsule_config.get("schema") != "o1c-run-config-v1"
        or capsule_config.get("publication_protocol") != "manifested-prepared-state-v1"
        or capsule_config.get("attempt_id") != UPSTREAM_ATTEMPT_ID
        or capsule_config.get("claim_level") != ClaimLevel.RETROSPECTIVE.value
        or capsule_config.get("config") != config.upstream_top
        or capsule_config.get("hypothesis") != config.upstream_top.get("hypothesis")
        or capsule_config.get("prediction") != config.upstream_top.get("prediction")
        or capsule_config.get("controls") != config.upstream_top.get("controls")
        or capsule_config.get("budgets") != config.upstream_top.get("budgets")
        or capsule_config.get("next_action") != config.upstream_top.get("next_action")
    ):
        raise O1C22PostResultComposerRunError("O1C-0022 frozen capsule config differs")
    commit = capsule_config.get("commit")
    if not isinstance(commit, str) or not _git_commit_descends_from_source_freeze(
        config.root, commit
    ):
        raise O1C22PostResultComposerRunError("O1C-0022 capsule commit differs")
    capsule_sources = _validate_upstream_source_hashes(
        config, capsule_config.get("source_hashes")
    )

    outer_metrics, metrics_payload = _read_json(
        capsule / "metrics.json", "O1C-0022 metrics"
    )
    if set(outer_metrics) != {
        "schema",
        "attempt_id",
        "status",
        "claim_level",
        "started_at",
        "ended_at",
        "elapsed_seconds",
        "next_action",
        "values",
    } or (
        outer_metrics.get("schema") != "o1c-run-metrics-v1"
        or outer_metrics.get("attempt_id") != UPSTREAM_ATTEMPT_ID
        or outer_metrics.get("claim_level") != ClaimLevel.RETROSPECTIVE.value
    ):
        raise O1C22PostResultComposerRunError("O1C-0022 capsule metrics differ")
    metrics = _mapping(
        outer_metrics.get("values"),
        "O1C-0022 metric values",
        {
            "schema",
            "classification",
            "scientific_success_gate_passed",
            "result_sha256",
            "margins",
            "gates",
            "failed_gates",
            "cpu_seconds",
            "wall_seconds",
            "peak_rss_bytes",
            "persistent_artifact_bytes",
            "source_artifact_bytes_read",
            "reader_replays",
            "packet_slots",
            "physical_public_work_units",
            "calibration_value_evaluations",
            "budget_checks",
            "failed_budgets",
            "operationally_complete",
        },
    )
    if (
        metrics.get("schema") != UPSTREAM_METRICS_SCHEMA
        or not isinstance(metrics.get("scientific_success_gate_passed"), bool)
        or not isinstance(metrics.get("operationally_complete"), bool)
    ):
        raise O1C22PostResultComposerRunError("O1C-0022 metric schema differs")

    artifacts_root = capsule / "artifacts"
    artifact_index, index_payload = _read_json(
        artifacts_root / "artifact_index.json", "O1C-0022 artifact index"
    )
    if set(artifact_index) != {
        "schema",
        "attempt_id",
        "o1c19_manifest_sha256",
        "o1c19_artifact_index_sha256",
        "artifacts",
        "indexed_artifact_count",
        "indexed_artifact_bytes",
    } or (
        artifact_index.get("schema") != UPSTREAM_ARTIFACT_INDEX_SCHEMA
        or artifact_index.get("attempt_id") != UPSTREAM_ATTEMPT_ID
    ):
        raise O1C22PostResultComposerRunError("O1C-0022 artifact index differs")
    if (
        _sha256(artifact_index["o1c19_manifest_sha256"], "o1c19 manifest")
        != capsule_sources["o1c19_capsule_manifest"]
        or _sha256(artifact_index["o1c19_artifact_index_sha256"], "o1c19 index")
        != capsule_sources["o1c19_artifact_index"]
    ):
        raise O1C22PostResultComposerRunError(
            "O1C-0019 source anchors differ from O1C-0022 source hashes"
        )
    artifacts = _mapping(artifact_index.get("artifacts"), "indexed artifacts")
    if (
        len(artifacts) != EXPECTED_UPSTREAM_ARTIFACTS
        or artifact_index.get("indexed_artifact_count") != len(artifacts)
        or artifact_index.get("indexed_artifact_bytes")
        != sum(
            _integer(
                _mapping(entry, "artifact entry").get("bytes"),
                "artifact bytes",
                0,
                1 << 40,
            )
            for entry in artifacts.values()
        )
    ):
        raise O1C22PostResultComposerRunError("artifact index totals differ")
    actual_relatives = {
        path.relative_to(artifacts_root).as_posix()
        for path in artifacts_root.rglob("*")
        if path.is_file() and path.name != "artifact_index.json"
    }
    if actual_relatives != set(artifacts):
        raise O1C22PostResultComposerRunError("artifact index inventory differs")
    indexed_bytes = _integer(
        artifact_index.get("indexed_artifact_bytes"),
        "indexed artifact bytes",
        0,
        1 << 40,
    )
    _validate_upstream_resource_metrics(
        config,
        outer_metrics,
        metrics,
        indexed_artifact_bytes=indexed_bytes,
        artifact_index_bytes=len(index_payload),
    )

    ledger_suffix = "/heldout/k256/execution/causal_vault_bridge_ledger.json"
    state_suffix = "/heldout/k256/execution/causal_vault_state.bin"
    execution_suffix = "/heldout/k256/execution/causal_vault_bridge_execution.json"
    ledger_names = sorted(name for name in artifacts if name.endswith(ledger_suffix))
    state_names = sorted(name for name in artifacts if name.endswith(state_suffix))
    execution_names = sorted(
        name for name in artifacts if name.endswith(execution_suffix)
    )
    if not (
        len(ledger_names) == len(state_names) == len(execution_names) == EXPECTED_FOLDS
    ):
        raise O1C22PostResultComposerRunError(
            "O1C-0022 must contain exactly four held-out K256 ledger/state executions"
        )
    artifact_payloads: dict[str, bytes] = {}
    bytes_read = len(config_payload) + len(metrics_payload) + len(index_payload)
    for relative, raw_entry in sorted(artifacts.items()):
        safe = _safe_relative(relative, "indexed artifact path")
        path = (artifacts_root / safe).resolve(strict=True)
        if not path.is_relative_to(artifacts_root.resolve()):
            raise O1C22PostResultComposerRunError("indexed artifact escapes capsule")
        payload = path.read_bytes()
        bytes_read += len(payload)
        _indexed_entry(artifacts, relative, payload)
        artifact_payloads[relative] = payload
        # The exact full-index pass above is intentional.  It prevents an
        # otherwise unused corrupt entry from becoming a future breadcrumb.
        del raw_entry
    if bytes_read > config.budgets.maximum_source_artifact_bytes_read:
        raise O1C22PostResultComposerRunError("source artifact read budget exceeded")

    _validate_upstream_lifecycle_inventory(
        artifact_payloads,
        artifacts,
        capsule_sources,
    )

    result_payload = artifact_payloads["o1c19_causal_vault_bridge.json"]
    result = _read_json_payload(result_payload, "O1C-0022 result")
    result_entry = _mapping(artifacts["o1c19_causal_vault_bridge.json"], "result entry")
    expected_result_fields = {
        "schema",
        "classification",
        "claim_boundary",
        "active_coordinate_counts",
        "prediction_arms",
        "calibration_scales",
        "arms",
        "source_anchor",
        "margins",
        "gates",
        "failed_gates",
        "calibration_orientation_flip_allowed",
        "calibration_scale_grid",
        "integrity_diagnostics",
        "resources",
        "source",
        "result_sha256",
    }
    if set(result) != expected_result_fields or (
        result.get("schema") != UPSTREAM_RESULT_SCHEMA
        or result_entry.get("phase") != "POST_FREEZE_SCORED_RESULT"
        or metrics.get("result_sha256") != result.get("result_sha256")
        or metrics.get("classification") != result.get("classification")
        or metrics.get("margins") != result.get("margins")
        or metrics.get("gates") != result.get("gates")
        or metrics.get("failed_gates") != result.get("failed_gates")
    ):
        raise O1C22PostResultComposerRunError("O1C-0022 result/metrics binding differs")
    result_source = _mapping(
        result.get("source"),
        "O1C-0022 result source",
        {
            "o1c18_artifact_corpus_sha256",
            "o1c19_manifest_sha256",
            "o1c19_artifact_index_sha256",
            "o1c19_result_sha256",
            "o1c21_config_sha256",
        },
    )
    expected_result_source = {
        "o1c18_artifact_corpus_sha256": capsule_sources["o1c18_artifact_corpus"],
        "o1c19_manifest_sha256": capsule_sources["o1c19_capsule_manifest"],
        "o1c19_artifact_index_sha256": capsule_sources["o1c19_artifact_index"],
        "o1c19_result_sha256": capsule_sources["o1c19_result"],
        "o1c21_config_sha256": capsule_sources["o1c21_source_config"],
    }
    resources = _mapping(
        result.get("resources"),
        "O1C-0022 result resources",
        {
            "existing_build_pools_loaded",
            "o1c19_reader_replays",
            "packet_slot_observations",
            "physical_public_work_units",
            "calibration_value_evaluations",
            "physical_public_pools_generated",
            "native_solver_branches",
            "scientific_entropy_calls",
            "sibling_reads",
            "sibling_writes",
            "mps_calls",
            "gpu_calls",
            "maximum_accumulator_live_state_bytes",
            "upstream_reader_state_billed_separately",
            "source_artifact_bytes_read",
        },
    )
    expected_resources = {
        "existing_build_pools_loaded": EXPECTED_FOLDS,
        "o1c19_reader_replays": EXPECTED_UPSTREAM_READER_REPLAYS,
        "packet_slot_observations": EXPECTED_UPSTREAM_PACKET_SLOTS,
        "physical_public_work_units": EXPECTED_UPSTREAM_PUBLIC_WORK,
        "calibration_value_evaluations": EXPECTED_UPSTREAM_CALIBRATION_EVALUATIONS,
        "physical_public_pools_generated": 0,
        "native_solver_branches": 0,
        "scientific_entropy_calls": 0,
        "sibling_reads": 0,
        "sibling_writes": 0,
        "mps_calls": 0,
        "gpu_calls": 0,
        "maximum_accumulator_live_state_bytes": FORMAL_VAULT_BYTES,
        "upstream_reader_state_billed_separately": True,
        "source_artifact_bytes_read": metrics["source_artifact_bytes_read"],
    }
    if (
        dict(result_source) != expected_result_source
        or dict(resources) != expected_resources
        or metrics.get("scientific_success_gate_passed")
        is not (result.get("classification") == "REAL_CAUSAL_VAULT_BUILD_LOO_PASS")
    ):
        raise O1C22PostResultComposerRunError(
            "O1C-0022 result source or resources differ"
        )
    expected_scored_sizes = {
        "labels.bitpack": 128,
        "raw_predictions.f64le": 229_376,
        "calibrated_predictions.f64le": 229_376,
        "calibration_scales.f64le": 224,
        "nll_bits.f64le": 896,
        "compression_bits.f64le": 896,
        "upstream_o1c19_anchor.f32le": 4_096,
    }
    if any(
        len(artifact_payloads[name]) != size
        for name, size in expected_scored_sizes.items()
    ):
        raise O1C22PostResultComposerRunError("O1C-0022 scored artifact shape differs")

    folds: list[O1C22K256FoldArtifacts] = []
    seen_targets: set[str] = set()
    seen_fold_indices: set[int] = set()
    for ledger_relative in ledger_names:
        prefix = ledger_relative[: -len("causal_vault_bridge_ledger.json")]
        state_relative = prefix + "causal_vault_state.bin"
        execution_relative = prefix + "causal_vault_bridge_execution.json"
        if (
            state_relative not in state_names
            or execution_relative not in execution_names
        ):
            raise O1C22PostResultComposerRunError("K256 execution siblings differ")
        parts = PurePosixPath(ledger_relative).parts
        if (
            len(parts) != 6
            or parts[0] != "folds"
            or parts[2:5] != ("heldout", "k256", "execution")
            or not parts[1]
        ):
            raise O1C22PostResultComposerRunError("K256 fold path differs")
        target_id = parts[1]
        if target_id in seen_targets:
            raise O1C22PostResultComposerRunError("duplicate K256 target ID")
        seen_targets.add(target_id)
        ledger_payload = artifact_payloads[ledger_relative]
        state_payload = artifact_payloads[state_relative]
        execution_payload = artifact_payloads[execution_relative]
        ledger_entry = _mapping(artifacts[ledger_relative], "ledger entry")
        phase = ledger_entry.get("phase")
        if not isinstance(phase, str) or not phase.startswith(
            "HELDOUT_PREDICTIONS_FROZEN_FOLD_"
        ):
            raise O1C22PostResultComposerRunError("held-out K256 phase differs")
        try:
            fold_index = int(phase.rsplit("_", 1)[1])
        except ValueError as exc:
            raise O1C22PostResultComposerRunError(
                "held-out fold index differs"
            ) from exc
        if fold_index not in range(EXPECTED_FOLDS) or fold_index in seen_fold_indices:
            raise O1C22PostResultComposerRunError("held-out fold inventory differs")
        seen_fold_indices.add(fold_index)
        if (
            _mapping(artifacts[state_relative], "state entry").get("phase") != phase
            or _mapping(artifacts[execution_relative], "execution entry").get("phase")
            != phase
            or len(state_payload) != FORMAL_VAULT_BYTES
        ):
            raise O1C22PostResultComposerRunError("K256 state phase/width differs")
        execution = _read_json_payload(execution_payload, "K256 execution")
        execution_fields = {
            "schema",
            "bridge_schema",
            "quantizer_sha256",
            "groups_offered",
            "groups_accepted",
            "groups_duplicate",
            "slots_offered",
            "slots_accepted",
            "physical_work_offered",
            "physical_work_accepted",
            "nonzero_vault_updates_accepted",
            "zero_quantized_slots_accepted",
            "zero_updates_are_skipped",
            "primary_live_state_bytes",
            "control_live_state_bytes",
            "static_control_plan_bytes",
            "upstream_reader_billed_separately",
            "primary_state_sha256",
            "control_state_sha256",
            "static_control_plan_sha256",
            "ledger_sha256",
            "duplicate_acceptance_rule",
            "duplicate_primary_state_byte_invariant",
            "controls",
            "zero_prior_representation",
            "current_target_supervised_updates",
            "label_accesses",
            "solver_calls",
        }
        if set(execution) != execution_fields or (
            execution.get("schema") != UPSTREAM_EXECUTION_SCHEMA
            or execution.get("groups_offered") != 256
            or execution.get("groups_accepted") != 256
            or execution.get("groups_duplicate") != 0
            or execution.get("slots_offered") != 768
            or execution.get("slots_accepted") != 768
            or execution.get("physical_work_offered") != 49_152
            or execution.get("physical_work_accepted") != 49_152
            or execution.get("zero_updates_are_skipped") is not True
            or execution.get("primary_live_state_bytes") != FORMAL_VAULT_BYTES
            or execution.get("upstream_reader_billed_separately") is not True
            or execution.get("primary_state_sha256") != _sha256_bytes(state_payload)
            or execution.get("ledger_sha256") != _sha256_bytes(ledger_payload)
            or execution.get("duplicate_primary_state_byte_invariant") is not True
            or execution.get("current_target_supervised_updates") != 0
            or execution.get("label_accesses") != 0
            or execution.get("solver_calls") != 0
        ):
            raise O1C22PostResultComposerRunError("K256 execution commitment differs")
        folds.append(
            O1C22K256FoldArtifacts(
                fold_index=fold_index,
                target_id=target_id,
                ledger_relative=ledger_relative,
                ledger_payload=ledger_payload,
                ledger_sha256=_sha256_bytes(ledger_payload),
                state_relative=state_relative,
                state_payload=state_payload,
                state_sha256=_sha256_bytes(state_payload),
                execution_relative=execution_relative,
                execution_sha256=_sha256_bytes(execution_payload),
            )
        )
    folds.sort(key=lambda row: row.fold_index)
    if tuple(row.fold_index for row in folds) != tuple(range(EXPECTED_FOLDS)):
        raise O1C22PostResultComposerRunError("K256 fold order differs")
    diagnostics = summarize_quantization_artifacts(
        tuple(row.ledger_payload for row in folds),
        tuple(row.state_payload for row in folds),
    )
    # This validates every result and metrics field consumed by the frozen
    # policy before a downstream attempt can be reserved.
    decision = compose_postresult_decision(
        result,
        metrics,
        capsule_manifest_sha256=finalized.manifest_sha256,
        quantization_diagnostics=diagnostics,
        failure_memory=empty_failure_memory(),
    )
    verify_decision(decision)
    return O1C22PostResultSource(
        finalized=finalized,
        result=result,
        metrics=metrics,
        folds=tuple(folds),
        diagnostics=diagnostics,
        artifact_index_sha256=_sha256_bytes(index_payload),
        result_file_sha256=_sha256_bytes(result_payload),
        metrics_file_sha256=_sha256_bytes(metrics_payload),
        config_file_sha256=_sha256_bytes(config_payload),
        source_artifact_bytes_read=bytes_read,
    )


@dataclass(frozen=True)
class O1C23Preflight:
    report: Mapping[str, object]
    config: O1C23RunConfig
    source: O1C22PostResultSource | None

    @property
    def ready(self) -> bool:
        return self.source is not None and self.report.get("status") == "ready"


def preflight_o1c22_postresult_composer(
    path: str | Path,
    *,
    root: str | Path | None = None,
) -> O1C23Preflight:
    """Validate O1C-0022 without reserving O1C-0023."""

    config = load_o1c22_postresult_composer_run_config(path, root=root)
    manager = RunCapsuleManager(config.root)
    recoverable = manager.recoverable_attempt_ids()
    existing = manager.finalized_attempt(ATTEMPT_ID)
    upstream = manager.finalized_attempt(UPSTREAM_ATTEMPT_ID)
    base = {
        "schema": PREFLIGHT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "prerequisite_attempt_id": UPSTREAM_ATTEMPT_ID,
        "o1c23_reserved_by_this_preflight": False,
        "o1c23_existing_finalized": existing is not None,
        "o1c23_existing_recoverable": ATTEMPT_ID in recoverable,
        "o1c22_existing_recoverable": UPSTREAM_ATTEMPT_ID in recoverable,
        "decision_policy_sha256": decision_policy_sha256(),
        "o1o_core_source_hashes_verified": True,
    }
    if upstream is None:
        return O1C23Preflight(
            {
                **base,
                "status": "prerequisite-pending",
                "reason": "reserved finalized O1C-0022 capsule is not available",
            },
            config,
            None,
        )
    try:
        source = _load_verified_o1c22_source(config, upstream)
    except Exception as exc:
        return O1C23Preflight(
            {
                **base,
                "status": "prerequisite-invalid",
                "o1c22_manifest_sha256": upstream.manifest_sha256,
                "reason": f"{type(exc).__name__}: {exc}",
            },
            config,
            None,
        )
    decision = compose_postresult_decision(
        source.result,
        source.metrics,
        capsule_manifest_sha256=source.finalized.manifest_sha256,
        quantization_diagnostics=source.diagnostics,
        failure_memory=empty_failure_memory(),
    )
    operator = _mapping(decision["operator"], "decision.operator")
    return O1C23Preflight(
        {
            **base,
            "status": "ready",
            "o1c22_manifest_sha256": source.finalized.manifest_sha256,
            "o1c22_artifact_index_sha256": source.artifact_index_sha256,
            "o1c22_result_sha256": source.result["result_sha256"],
            "o1c22_reported_classification": source.result["classification"],
            "k256_heldout_fold_count": len(source.folds),
            "all_primary_states_exactly_352_bytes": all(
                len(row.state_payload) == FORMAL_VAULT_BYTES for row in source.folds
            ),
            "quantization_diagnostics_sha256": source.diagnostics["diagnostics_sha256"],
            "empty_memory_operator_id": operator["operator_id"],
            "empty_memory_operator_fingerprint": operator["operator_fingerprint"],
            "source_artifact_bytes_read": source.source_artifact_bytes_read,
        },
        config,
        source,
    )


def _read_o1o_core_sources(config: O1C23RunConfig) -> dict[str, str]:
    actual: dict[str, str] = {}
    for relative in sorted(config.o1o_core_sha256):
        safe = _safe_relative(relative, "O1-O core relative path")
        path = (config.o1o_forge / safe).resolve(strict=True)
        if not path.is_relative_to(config.o1o_forge):
            raise O1C22PostResultComposerRunError("O1-O core source escapes forge")
        actual[relative] = _sha256_file(path)
    return actual


def _verify_o1o_core_sources(config: O1C23RunConfig) -> dict[str, str]:
    actual = _read_o1o_core_sources(config)
    if actual != dict(config.o1o_core_sha256):
        raise O1C22PostResultComposerRunError("O1-O core source hashes differ")
    return actual


def _tree_snapshot(root: Path) -> tuple[str, int]:
    rows: list[dict[str, object]] = []

    def row_for(path: Path, relative: str) -> tuple[dict[str, object], bool]:
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            kind = "directory"
        elif stat.S_ISREG(metadata.st_mode):
            kind = "file"
        elif stat.S_ISLNK(metadata.st_mode):
            kind = "symlink"
        else:
            kind = "other"
        row: dict[str, object] = {
            "path": relative,
            "kind": kind,
            "mode": stat.S_IMODE(metadata.st_mode),
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "links": metadata.st_nlink,
            "size": metadata.st_size,
            "mtime_ns": metadata.st_mtime_ns,
            "ctime_ns": metadata.st_ctime_ns,
        }
        if kind == "symlink":
            row["target"] = os.readlink(path)
        return row, kind == "directory"

    root_row, _ = row_for(root, ".")
    rows.append(root_row)
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise O1C22PostResultComposerRunError(
                "O1-O sibling tree cannot be snapshotted"
            ) from exc
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            row, is_directory = row_for(path, relative)
            if is_directory:
                pending.append(path)
            rows.append(row)
    rows.sort(key=lambda row: str(row["path"]))
    return _sha256_bytes(canonical_json_bytes(rows)), len(rows)


def _interruption_recovery_metrics(
    config: O1C23RunConfig | None,
    interrupted: object,
) -> dict[str, object]:
    """Recover only claims that are committed by the last durable checkpoint."""

    staging_path = getattr(interrupted, "staging_path", None)
    base: dict[str, object] = {
        "schema": RUN_METRICS_SCHEMA,
        "operationally_complete": False,
        "hard_interruption_recovered": True,
        "operator_decision_claimed": False,
        "checkpoint_recovered": False,
        "checkpoint_phase": None,
        "structural_work_recovered": False,
        "structural_work_counter_semantics": "checkpoint-bounds",
        "sibling_write_free_proven": False,
        "sibling_mutations_observed_lower_bound": 0,
        "sibling_writes": None,
    }
    if not isinstance(staging_path, Path):
        return base
    try:
        checkpoint, _ = _read_json(
            staging_path / "checkpoint.json", "interrupted checkpoint"
        )
        checkpoint = _mapping(
            checkpoint,
            "interrupted checkpoint",
            {"schema", "attempt_id", "updated_at", "sequence", "payload"},
        )
        if (
            checkpoint["schema"] != "o1c-run-checkpoint-v1"
            or checkpoint["attempt_id"] != ATTEMPT_ID
            or not isinstance(checkpoint["updated_at"], str)
        ):
            raise O1C22PostResultComposerRunError(
                "interrupted checkpoint identity differs"
            )
        sequence = _integer(checkpoint["sequence"], "checkpoint sequence", 1, 1 << 30)
        payload = _mapping(checkpoint["payload"], "interrupted checkpoint payload")
        phase = payload.get("phase")
        if not isinstance(phase, str) or not phase:
            raise O1C22PostResultComposerRunError(
                "interrupted checkpoint phase differs"
            )
    except Exception as exc:
        return {
            **base,
            "checkpoint_error": f"{type(exc).__name__}: {exc}",
        }

    result = {
        **base,
        "checkpoint_recovered": True,
        "checkpoint_sequence": sequence,
        "checkpoint_phase": phase,
    }
    work: StructuralWorkLedger | None = None
    if "structural_work" in payload:
        try:
            work = StructuralWorkLedger.from_document(payload["structural_work"])
        except Exception as exc:
            result["structural_work_error"] = f"{type(exc).__name__}: {exc}"
    elif phase == "O1C0023_RESERVED_AFTER_VALID_O1C0022_PREFLIGHT":
        zero_fields = (
            "native_o1o_invocations",
            "fresh_targets_consumed",
            "native_solver_branches",
            "scientific_entropy_calls",
            "sibling_writes",
            "mps_calls",
            "gpu_calls",
        )
        if all(payload.get(name) == 0 for name in zero_fields):
            work = StructuralWorkLedger(sibling_write_free_proven=True)

    native_phase_index: int | None = None
    native_checkpoint_valid = False
    if phase in {"O1C0023_NATIVE_GUARD_RUN_0", "O1C0023_NATIVE_GUARD_RUN_1"}:
        native_phase_index = int(phase.rsplit("_", 1)[1])
        if work is None:
            result["structural_work_error"] = (
                "native checkpoint lacks a valid structural work ledger"
            )
        elif (
            payload.get("native_core_execution_source") != "disposable-byte-exact-clone"
            or payload.get("original_o1o_repository_path_disclosed_to_child")
            is not False
            or payload.get("native_child_launch_requires_inherited_execution_lease")
            is not True
            or work.native_o1o_invocations_started != native_phase_index + 1
            or work.native_o1o_invocations_returned != native_phase_index
            or work.native_o1o_invocations_validated != native_phase_index
            or work.generated_source_ast_parses != native_phase_index
            or work.generated_source_bytecode_compilations != 0
            or work.generated_source_executions != 0
            or work.fresh_targets_consumed != 0
            or work.native_solver_branches != 0
            or work.scientific_entropy_calls != 0
            or work.mps_calls != 0
            or work.gpu_calls != 0
            or work.sibling_mutations_observed_lower_bound != 0
            or work.sibling_write_free_proven is not False
        ):
            result["structural_work_error"] = (
                "native checkpoint ledger/phase relation differs"
            )
            work = None
        else:
            native_checkpoint_valid = True

    if work is not None:
        result.update(
            {
                "structural_work_recovered": True,
                "structural_work": work.document(),
                "native_o1o_invocations_entered_upper_bound": (
                    work.native_o1o_invocations_started
                ),
                "native_o1o_invocations_returned_lower_bound": (
                    work.native_o1o_invocations_returned
                ),
                "native_o1o_invocations_validated_lower_bound": (
                    work.native_o1o_invocations_validated
                ),
                "generated_source_ast_parses_lower_bound": (
                    work.generated_source_ast_parses
                ),
                "generated_source_bytecode_compilations": (
                    work.generated_source_bytecode_compilations
                ),
                "generated_source_executions": work.generated_source_executions,
                "fresh_targets_consumed": work.fresh_targets_consumed,
                "native_solver_branches": work.native_solver_branches,
                "scientific_entropy_calls": work.scientific_entropy_calls,
                "mps_calls": work.mps_calls,
                "gpu_calls": work.gpu_calls,
            }
        )

    if phase == "O1C0023_RESERVED_AFTER_VALID_O1C0022_PREFLIGHT" and work is not None:
        result.update(
            {
                "structural_work_counter_semantics": "exact-at-reservation-checkpoint",
                "sibling_write_free_proven": True,
                "sibling_writes": 0,
            }
        )
        return result

    if native_phase_index is not None:
        if config is None:
            result["sibling_audit_error"] = (
                "strict frozen config unavailable during recovery"
            )
            return result
        try:
            expected_core = _mapping(
                payload["o1o_core_source_sha256_before"],
                "checkpoint O1-O core hashes",
                set(config.o1o_core_sha256),
            )
            expected_core_sha = {
                relative: _sha256(digest, f"checkpoint core {relative}")
                for relative, digest in expected_core.items()
            }
            expected_tree = _sha256(
                payload["sibling_snapshot_sha256_before"],
                "checkpoint sibling snapshot",
            )
            expected_entries = _integer(
                payload["sibling_snapshot_entries_before"],
                "checkpoint sibling entries",
                1,
                1 << 30,
            )
            actual_core = _read_o1o_core_sources(config)
            actual_tree, actual_entries = _tree_snapshot(config.o1o_repository)
            tree_matches = (
                expected_core_sha == actual_core == dict(config.o1o_core_sha256)
                and expected_tree == actual_tree
                and expected_entries == actual_entries
            )
            write_free_proven = native_checkpoint_valid and tree_matches
            observed_mutation = native_checkpoint_valid and not tree_matches
            result.update(
                {
                    "recovery_o1o_core_sha256": actual_core,
                    "recovery_sibling_snapshot_sha256": actual_tree,
                    "recovery_sibling_snapshot_entries": actual_entries,
                    "sibling_tree_matches_checkpoint": tree_matches,
                    "sibling_write_free_proven": write_free_proven,
                    "sibling_mutations_observed_lower_bound": (
                        1 if observed_mutation else 0
                    ),
                    "sibling_writes": 0 if write_free_proven else None,
                }
            )
        except Exception as exc:
            result["sibling_audit_error"] = f"{type(exc).__name__}: {exc}"
    return result


def _staging_snapshot(root: Path) -> tuple[str, int]:
    rows: list[dict[str, object]] = []
    for path in [root, *sorted(root.rglob("*"))]:
        metadata = path.lstat()
        relative = "." if path == root else path.relative_to(root).as_posix()
        if stat.S_ISLNK(metadata.st_mode):
            raise O1C22PostResultComposerRunError(
                "native staging fixture contains a symlink"
            )
        if stat.S_ISDIR(metadata.st_mode):
            kind = "directory"
        elif stat.S_ISREG(metadata.st_mode):
            kind = "file"
        else:
            raise O1C22PostResultComposerRunError(
                "native staging fixture contains a special file"
            )
        row: dict[str, object] = {
            "path": relative,
            "kind": kind,
            "mode": stat.S_IMODE(metadata.st_mode),
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "links": metadata.st_nlink,
            "size": metadata.st_size,
            "mtime_ns": metadata.st_mtime_ns,
            "ctime_ns": metadata.st_ctime_ns,
        }
        if kind == "file":
            row["sha256"] = _sha256_file(path)
        rows.append(row)
    return _sha256_bytes(canonical_json_bytes(rows)), len(rows)


def _expected_operator_marker(decision: Mapping[str, object]) -> bytes:
    operator = _mapping(decision["operator"], "decision.operator")
    return canonical_json_bytes(
        {
            "schema": OPERATOR_GRAPH_SCHEMA,
            "decision_sha256": decision["decision_sha256"],
            "operator_id": operator["operator_id"],
            "operator_fingerprint": operator["operator_fingerprint"],
            "information_boundary": decision["information_boundary"],
        }
    )


def _extract_exact_operator_marker(
    generated: bytes,
    expected: bytes,
) -> Mapping[str, object]:
    try:
        source = generated.decode("utf-8")
        tree = ast.parse(source, filename="native_o1c23_generated.py", mode="exec")
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise O1C22PostResultComposerRunError(
            "native generated source is invalid"
        ) from exc
    assignments = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "NEXT_OPERATOR_JSON"
    ]
    stores = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Store)
        and node.id == "NEXT_OPERATOR_JSON"
    ]
    functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "selected_o1c22_operator"
    ]
    if len(assignments) != 1 or len(stores) != 1 or len(functions) != 1:
        raise O1C22PostResultComposerRunError(
            "native operator marker structure differs"
        )
    try:
        marker_value = ast.literal_eval(assignments[0].value)
    except (ValueError, TypeError) as exc:
        raise O1C22PostResultComposerRunError(
            "native operator marker is not literal"
        ) from exc
    function = functions[0]
    if (
        type(marker_value) is not str
        or function.args.args
        or function.args.posonlyargs
        or function.args.kwonlyargs
        or function.args.vararg is not None
        or function.args.kwarg is not None
        or len(function.body) != 1
        or not isinstance(function.body[0], ast.Return)
        or not isinstance(function.body[0].value, ast.Name)
        or function.body[0].value.id != "NEXT_OPERATOR_JSON"
    ):
        raise O1C22PostResultComposerRunError("native operator marker semantics differ")
    try:
        raw = marker_value.encode("ascii")
        document = json.loads(raw)
    except (UnicodeEncodeError, json.JSONDecodeError) as exc:
        raise O1C22PostResultComposerRunError(
            "native operator marker payload is invalid"
        ) from exc
    if raw != expected or canonical_json_bytes(document) != raw:
        raise O1C22PostResultComposerRunError("native operator marker payload differs")
    return _mapping(
        document,
        "native operator marker",
        {
            "schema",
            "decision_sha256",
            "operator_id",
            "operator_fingerprint",
            "information_boundary",
        },
    )


def _run_native_o1o_once(
    config: O1C23RunConfig,
    decision: Mapping[str, object],
    causal_payload: bytes,
    fragment_payload: bytes,
    work: StructuralWorkLedger,
    *,
    run_index: int,
    lease_fd: int | None = None,
) -> tuple[dict[str, object], bytes]:
    operator = _mapping(decision["operator"], "decision.operator")
    with tempfile.TemporaryDirectory(prefix=f"o1c23-native-{run_index:02d}-") as tmp:
        staging = Path(tmp)
        native_forge = staging / "forge"
        knowledge = staging / "knowledge"
        fragments = staging / "fragments"
        native_forge.mkdir(mode=0o700)
        knowledge.mkdir(mode=0o700)
        fragments.mkdir(mode=0o700)
        for relative, expected_sha in sorted(config.o1o_core_sha256.items()):
            safe = _safe_relative(relative, "O1-O core clone path")
            source = (config.o1o_forge / safe).resolve(strict=True)
            if not source.is_relative_to(config.o1o_forge):
                raise O1C22PostResultComposerRunError(
                    "O1-O core clone source escapes forge"
                )
            payload = source.read_bytes()
            if _sha256_bytes(payload) != expected_sha:
                raise O1C22PostResultComposerRunError(
                    f"O1-O core changed before disposable clone: {relative}"
                )
            destination = native_forge / safe
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            destination.write_bytes(payload)
        (knowledge / O1O_KNOWLEDGE_FILENAME).write_bytes(causal_payload)
        (fragments / O1O_FRAGMENT_FILENAME).write_bytes(fragment_payload)
        before, before_entries = _staging_snapshot(staging)
        expected_marker = _expected_operator_marker(decision)
        core_argument = base64.b64encode(
            canonical_json_bytes(config.o1o_core_sha256)
        ).decode("ascii")
        dependency_argument = base64.b64encode(
            canonical_json_bytes(config.o1o_dependency_sha256)
        ).decode("ascii")
        marker_argument = base64.b64encode(expected_marker).decode("ascii")
        environment = {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
        completed: subprocess.CompletedProcess[bytes] | None = None
        launch_error: Exception | None = None
        try:
            completed = subprocess.run(
                (
                    sys.executable,
                    "-I",
                    "-B",
                    "-S",
                    "-c",
                    _NATIVE_CHILD,
                    str(native_forge),
                    str(knowledge),
                    str(fragments),
                    str(operator["decision_token"]),
                    str(operator["fragment_key"]),
                    core_argument,
                    dependency_argument,
                    marker_argument,
                    str(config.o1o_dependency_root),
                ),
                cwd=staging,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                pass_fds=() if lease_fd is None else (lease_fd,),
                timeout=30,
                check=False,
            )
            work.native_o1o_invocations_returned += 1
        except Exception as exc:  # preserve fixture audit on timeout/launch failure
            launch_error = exc
        after, after_entries = _staging_snapshot(staging)
        fixture_unchanged = before == after and before_entries == after_entries
        if not fixture_unchanged:
            detail = ""
            if completed is not None:
                detail = completed.stderr.decode("utf-8", errors="replace")[-2000:]
            raise O1C22PostResultComposerRunError(
                f"native O1-O run {run_index} mutated its fixture; {detail}"
            )
        if launch_error is not None:
            raise O1C22PostResultComposerRunError(
                f"native O1-O run {run_index} launch failed: {launch_error}"
            ) from launch_error
        if completed is None:
            raise AssertionError("native subprocess result is unavailable")
        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", errors="replace")[-4000:]
            raise O1C22PostResultComposerRunError(
                f"native O1-O run {run_index} failed: {detail}"
            )
        matching = [
            line[len(_NATIVE_RESULT_PREFIX) :]
            for line in completed.stdout.splitlines()
            if line.startswith(_NATIVE_RESULT_PREFIX)
        ]
        if len(matching) != 1:
            raise O1C22PostResultComposerRunError("native O1-O receipt differs")
        try:
            child = json.loads(matching[0].decode("ascii"))
            generated = base64.b64decode(child.pop("generated_base64"), validate=True)
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, ValueError) as exc:
            raise O1C22PostResultComposerRunError(
                "native O1-O output is invalid"
            ) from exc
        native_resource = _mapping(
            child.pop("resource_usage", None),
            "native O1-O resource usage",
            {"cpu_seconds", "peak_rss_raw", "peak_rss_unit"},
        )
        native_cpu_seconds = _number(
            native_resource["cpu_seconds"], "native O1-O CPU seconds", 0.0, 30.0
        )
        native_peak_rss_raw = _integer(
            native_resource["peak_rss_raw"], "native O1-O peak RSS", 1, 1 << 60
        )
        expected_rss_unit = "bytes" if sys.platform == "darwin" else "kibibytes"
        if native_resource["peak_rss_unit"] != expected_rss_unit:
            raise O1C22PostResultComposerRunError("native O1-O peak RSS unit differs")
        native_peak_rss_bytes = (
            native_peak_rss_raw
            if expected_rss_unit == "bytes"
            else native_peak_rss_raw * 1024
        )
        marker = _extract_exact_operator_marker(generated, expected_marker)
        expected_core_attestation = {
            (
                "core"
                if relative == "core/__init__.py"
                else f"core.{Path(relative).stem}"
            ): {
                "relative": relative,
                "sha256": digest,
            }
            for relative, digest in config.o1o_core_sha256.items()
        }
        expected_dependency_attestation = {}
        for relative, digest in config.o1o_dependency_sha256.items():
            package, filename = relative.split("/", 1)
            module = (
                package
                if filename == "__init__.py"
                else f"{package}.{filename.split('.', 1)[0]}"
            )
            expected_dependency_attestation[module] = {
                "relative": relative,
                "sha256": digest,
            }
        expected_child = {
            "assembly_intent_raw": "",
            "core_attestation": expected_core_attestation,
            "dependency_attestation": expected_dependency_attestation,
            "fragment_count": 1,
            "generated_code_compiled": False,
            "generated_code_executed": False,
            "generated_sha256": _sha256_bytes(generated),
            "generated_syntax_parsed": True,
            "graph_count": 1,
            "hash_determinism": "two-independent-byte-identical-native-runs",
            "isolation": {
                "dont_write_bytecode": True,
                "ignore_environment": True,
                "isolated": True,
                "no_site": True,
                "no_user_site": True,
                "safe_path": True,
                "site_modules_loaded": [],
            },
            "marker": dict(marker),
            "marker_sha256": _sha256_bytes(expected_marker),
            "outcome": operator["fragment_key"],
            "python_flags": ["-I", "-B", "-S"],
            "self_timeout_seconds": 35,
            "source_graph": "bridge_intents",
            "triplet_count": 1,
            "used_fragments": [operator["fragment_key"]],
        }
        if child != expected_child:
            raise O1C22PostResultComposerRunError(
                "native O1-O selection or generated source differs"
            )
        work.native_o1o_invocations_validated += 1
        work.generated_source_ast_parses += 1
        receipt = {
            "run_index": run_index,
            **child,
            "fixture_snapshot_sha256_before": before,
            "fixture_snapshot_sha256_after": after,
            "fixture_snapshot_entries_before": before_entries,
            "fixture_snapshot_entries_after": after_entries,
            "fixture_mutations": 0,
            "o1o_core_execution_source": "disposable-byte-exact-clone",
            "original_o1o_repository_path_disclosed_to_child": False,
            "python_hash_seed_fixed": False,
            "native_cpu_seconds": native_cpu_seconds,
            "native_peak_rss_bytes": native_peak_rss_bytes,
        }
        return receipt, generated


def _git_clean_commit(root: Path) -> str:
    status = subprocess.run(
        ("git", "status", "--porcelain=v1", "--untracked-files=all"),
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=15,
        check=False,
    )
    if status.returncode != 0 or status.stdout.strip():
        raise O1C22PostResultComposerRunError(
            "O1C-0023 requires a clean committed lab worktree"
        )
    commit = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=15,
        check=False,
    )
    value = commit.stdout.strip()
    if (
        commit.returncode != 0
        or len(value) != 40
        or any(character not in _HEX for character in value)
    ):
        raise O1C22PostResultComposerRunError("lab commit is unavailable")
    return value


def _source_hashes(
    config: O1C23RunConfig,
    source: O1C22PostResultSource,
) -> dict[str, str]:
    actual_local_sources = {
        "composer": _sha256_file(config.composer_path),
        "o1o_codec": _sha256_file(config.codec_path),
        "runner": _sha256_file(Path(__file__)),
        "run_capsule": _sha256_file(config.root / "src/o1_crypto_lab/run_capsule.py"),
        "living_inverse": _sha256_file(
            config.root / "src/o1_crypto_lab/living_inverse.py"
        ),
        "pyproject": _sha256_file(config.root / "pyproject.toml"),
    }
    if actual_local_sources != dict(config.local_source_sha256):
        raise O1C22PostResultComposerRunError(
            "O1C-0023 local source changed after config load"
        )
    if _verify_o1o_core_sources(config) != dict(config.o1o_core_sha256):
        raise O1C22PostResultComposerRunError("O1-O core changed after config load")
    for relative, expected in config.o1o_dependency_sha256.items():
        if _sha256_file(config.o1o_dependency_root / relative) != expected:
            raise O1C22PostResultComposerRunError(
                f"native dependency changed after config load: {relative}"
            )
    hashes = {
        "config": _sha256_file(config.config_path),
        "pyproject": config.local_source_sha256["pyproject"],
        "module_composer": config.local_source_sha256["composer"],
        "module_o1o_codec": config.local_source_sha256["o1o_codec"],
        "module_runner": config.local_source_sha256["runner"],
        "module_run_capsule": config.local_source_sha256["run_capsule"],
        "module_living_inverse": config.local_source_sha256["living_inverse"],
        "o1c22_capsule_manifest": source.finalized.manifest_sha256,
        "o1c22_config_file": source.config_file_sha256,
        "o1c22_artifact_index": source.artifact_index_sha256,
        "o1c22_result_file": source.result_file_sha256,
        "o1c22_metrics_file": source.metrics_file_sha256,
        "decision_policy": decision_policy_sha256(),
    }
    for fold in source.folds:
        prefix = f"o1c22_k256_fold_{fold.fold_index:02d}"
        hashes[f"{prefix}_ledger"] = fold.ledger_sha256
        hashes[f"{prefix}_state"] = fold.state_sha256
        hashes[f"{prefix}_execution"] = fold.execution_sha256
    for relative, digest in config.o1o_core_sha256.items():
        label = relative.removeprefix("core/").removesuffix(".py")
        hashes[f"o1o_core_{label}"] = digest
    for relative, digest in config.o1o_dependency_sha256.items():
        label = relative.replace("/", "_").replace(".", "_").replace("-", "_")
        hashes[f"o1o_dependency_{label}"] = digest
    return dict(sorted(hashes.items()))


def _source_index(
    config: O1C23RunConfig,
    source: O1C22PostResultSource,
    *,
    core_before: Mapping[str, str],
    core_after: Mapping[str, str],
    sibling_snapshot_sha256_before: str,
    sibling_snapshot_sha256_after: str,
    sibling_snapshot_entries: int,
) -> dict[str, object]:
    unsigned = {
        "schema": SOURCE_INDEX_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "source_attempt_id": UPSTREAM_ATTEMPT_ID,
        "o1c22": {
            "capsule_path": str(source.finalized.path),
            "capsule_manifest_sha256": source.finalized.manifest_sha256,
            "config_file_sha256": source.config_file_sha256,
            "frozen_config_sha256": config.upstream_config_sha256,
            "artifact_index_sha256": source.artifact_index_sha256,
            "result_file_sha256": source.result_file_sha256,
            "result_sha256": source.result["result_sha256"],
            "metrics_file_sha256": source.metrics_file_sha256,
            "k256_folds": [row.describe() for row in source.folds],
            "source_artifact_bytes_read": source.source_artifact_bytes_read,
        },
        "lab": {
            "source_sha256": dict(config.local_source_sha256),
            "policy_sha256": decision_policy_sha256(),
        },
        "o1o": {
            "repository": str(config.o1o_repository),
            "forge": str(config.o1o_forge),
            "core_source_sha256_before": dict(core_before),
            "core_source_sha256_after": dict(core_after),
            "dependency_source_sha256": dict(config.o1o_dependency_sha256),
            "sibling_snapshot_sha256_before": sibling_snapshot_sha256_before,
            "sibling_snapshot_sha256_after": sibling_snapshot_sha256_after,
            "sibling_snapshot_entries": sibling_snapshot_entries,
            "sibling_writes": 0,
        },
    }
    return {
        **unsigned,
        "source_index_sha256": _sha256_bytes(canonical_json_bytes(unsigned)),
    }


def _resolve_lab_root_for_lifecycle(
    path: str | Path,
    *,
    root: str | Path | None = None,
) -> tuple[Path, Path]:
    config_path = Path(path).resolve(strict=False)
    lab_root = (
        Path(root).resolve(strict=True) if root is not None else config_path.parents[1]
    )
    if not config_path.is_relative_to(lab_root):
        raise O1C22PostResultComposerRunError("config escapes lab root")
    return config_path, lab_root


def run_capsule_from_config(
    path: str | Path,
    *,
    root: str | Path | None = None,
) -> int:
    """Serialize lifecycle ownership before recovery or new execution."""

    config_path, lab_root = _resolve_lab_root_for_lifecycle(path, root=root)
    manager = RunCapsuleManager(lab_root)
    lease_path = manager.output_root / ".attempt_ids" / f"{ATTEMPT_ID}.execution.lock"
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    lease_fd = os.open(lease_path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(lease_fd).st_mode):
            raise O1C22PostResultComposerRunError(
                "O1C-0023 execution lease is not a regular file"
            )
        try:
            fcntl.flock(lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(
                json.dumps(
                    {
                        "schema": PREFLIGHT_SCHEMA,
                        "attempt_id": ATTEMPT_ID,
                        "status": "active-execution-lease-held",
                        "reason": (
                            "another O1C-0023 owner or its bounded native child "
                            "is still active"
                        ),
                    },
                    indent=2,
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
            return 2
        resource_baseline = RunResourceBaseline.capture()
        return _run_capsule_from_config_under_lease(
            config_path,
            lab_root=lab_root,
            lease_fd=lease_fd,
            resource_baseline=resource_baseline,
        )
    finally:
        # Do not issue LOCK_UN: the native child inherits this open-file
        # description so an orphan keeps lifecycle ownership until its alarm
        # terminates it.  The lock releases when the final descriptor closes.
        os.close(lease_fd)


def _run_capsule_from_config_under_lease(
    config_path: Path,
    *,
    lab_root: Path,
    lease_fd: int,
    resource_baseline: RunResourceBaseline,
) -> int:
    manager = RunCapsuleManager(lab_root)
    published = manager.finalized_attempt(ATTEMPT_ID)
    if published is not None:
        metrics, _ = _read_json(published.path / "metrics.json", "O1C-0023 metrics")
        print(
            json.dumps(
                {
                    "attempt_id": ATTEMPT_ID,
                    "path": str(published.path),
                    "manifest_sha256": published.manifest_sha256,
                    "verified": published.verification.ok,
                    "status": "already-finalized-no-replay",
                    "capsule_status": metrics.get("status"),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0 if metrics.get("status") == "completed" else 2

    if ATTEMPT_ID in manager.recoverable_attempt_ids():
        interrupted = manager.recover(ATTEMPT_ID)
        if interrupted.publication_prepared:
            finalized = interrupted.finalize(metrics={})
            metrics, _ = _read_json(
                finalized.path / "metrics.json", "recovered O1C-0023 metrics"
            )
            status = metrics.get("status")
            print(
                json.dumps(
                    {
                        "attempt_id": ATTEMPT_ID,
                        "path": str(finalized.path),
                        "manifest_sha256": finalized.manifest_sha256,
                        "verified": finalized.verification.ok,
                        "status": "publication-completed-no-replay",
                        "capsule_status": status,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0 if status == "completed" else 2
        recovery_config: O1C23RunConfig | None = None
        recovery_config_error: str | None = None
        try:
            recovery_config = load_o1c22_postresult_composer_run_config(
                config_path, root=lab_root
            )
        except Exception as exc:
            recovery_config_error = f"{type(exc).__name__}: {exc}"
        recovery_metrics = _interruption_recovery_metrics(recovery_config, interrupted)
        if recovery_config_error is not None:
            recovery_metrics["strict_config_error"] = recovery_config_error
        finalized = interrupted.finalize(
            metrics=recovery_metrics,
            status="stopped",
            next_action=(
                "Preserve this interrupted composer capsule and repeat under a new "
                "attempt identity after diagnosing its last checkpoint."
            ),
        )
        print(f"stopped capsule: {finalized.path}", file=sys.stderr)
        return 2

    config = load_o1c22_postresult_composer_run_config(config_path, root=lab_root)
    preflight = preflight_o1c22_postresult_composer(
        config.config_path, root=config.root
    )
    if not preflight.ready or preflight.source is None:
        print(json.dumps(preflight.report, indent=2, sort_keys=True), file=sys.stderr)
        return 2
    source = preflight.source

    commit = _git_clean_commit(config.root)
    hashes = _source_hashes(config, source)
    run = manager.start(
        attempt_id=ATTEMPT_ID,
        slug=FORMAL_SLUG,
        commit=commit,
        hypothesis=str(config.top["hypothesis"]),
        prediction=str(config.top["prediction"]),
        controls=tuple(
            str(value) for value in _sequence(config.top["controls"], "controls")
        ),
        budgets=dict(_mapping(config.top["budgets"], "budgets")),
        source_hashes=hashes,
        claim_level=ClaimLevel.RETROSPECTIVE,
        next_action=str(config.top["next_action"]),
        config=config.top,
        command=(
            sys.executable,
            "-m",
            "o1_crypto_lab.o1c22_postresult_composer_run",
            "--config",
            str(config.config_path),
        ),
        environment={
            "information_boundary": "POST_REVEAL_PROPOSAL_FOR_NEXT_ATTEMPT_ONLY",
            "o1c22_capsule": str(source.finalized.path),
            "o1c22_capsule_manifest_sha256": source.finalized.manifest_sha256,
            "native_o1o_runs": EXPECTED_NATIVE_RUNS,
            "generated_code_compiled": False,
            "generated_code_executed": False,
            "fresh_targets_consumed": 0,
            "native_solver_branches": 0,
            "scientific_entropy_calls": 0,
            "sibling_write_authority": "denied-and-audited",
            "mps_calls": 0,
            "gpu_calls": 0,
        },
    )
    persistent_bytes = 0
    persisted: dict[str, dict[str, object]] = {}
    work = StructuralWorkLedger()
    native_rows: list[dict[str, object]] = []
    generated_rows: list[bytes] = []

    def persist(relative: str, payload: bytes, phase: str) -> None:
        nonlocal persistent_bytes
        if relative in persisted or not payload:
            raise O1C22PostResultComposerRunError("artifact inventory differs")
        if (
            persistent_bytes + len(payload)
            > config.budgets.maximum_persistent_artifact_bytes
        ):
            raise O1C22PostResultComposerRunError("persistent artifact budget exceeded")
        output = run.write_artifact(relative, payload)
        digest = _sha256_bytes(payload)
        if _sha256_file(output) != digest:
            raise O1C22PostResultComposerRunError("persisted artifact differs")
        persisted[relative] = {
            "sha256": digest,
            "bytes": len(payload),
            "phase": phase,
        }
        persistent_bytes += len(payload)

    try:
        run.checkpoint(
            {
                "phase": "O1C0023_RESERVED_AFTER_VALID_O1C0022_PREFLIGHT",
                "o1c22_manifest_sha256": source.finalized.manifest_sha256,
                "k256_heldout_folds": len(source.folds),
                "source_artifact_bytes_read": source.source_artifact_bytes_read,
                "native_o1o_invocations": 0,
                "fresh_targets_consumed": 0,
                "native_solver_branches": 0,
                "scientific_entropy_calls": 0,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            }
        )
        memory = empty_failure_memory()
        if memory["entries"] != [] or memory["source_capsule_manifests"] != []:
            raise O1C22PostResultComposerRunError("first-decision memory is not empty")
        decision = compose_postresult_decision(
            source.result,
            source.metrics,
            capsule_manifest_sha256=source.finalized.manifest_sha256,
            quantization_diagnostics=source.diagnostics,
            failure_memory=memory,
        )
        verify_decision(decision)
        causal_payload = encode_o1o_route(decision)
        fragment_payload = encode_o1o_fragment_document(decision)

        core_before = _verify_o1o_core_sources(config)
        sibling_before, sibling_entries = _tree_snapshot(config.o1o_repository)
        native_error: Exception | None = None
        core_after: dict[str, str] = {}
        sibling_after = ""
        sibling_entries_after = -1
        sibling_audit_completed = False
        try:
            for run_index in range(EXPECTED_NATIVE_RUNS):
                work.native_o1o_invocations_started += 1
                run.checkpoint(
                    {
                        "phase": f"O1C0023_NATIVE_GUARD_RUN_{run_index}",
                        "o1o_core_source_sha256_before": dict(core_before),
                        "sibling_snapshot_sha256_before": sibling_before,
                        "sibling_snapshot_entries_before": sibling_entries,
                        "native_core_execution_source": ("disposable-byte-exact-clone"),
                        "original_o1o_repository_path_disclosed_to_child": False,
                        "native_child_launch_requires_inherited_execution_lease": True,
                        "structural_work": work.document(),
                    }
                )
                receipt, generated = _run_native_o1o_once(
                    config,
                    decision,
                    causal_payload,
                    fragment_payload,
                    work,
                    run_index=run_index,
                    lease_fd=lease_fd,
                )
                native_rows.append(receipt)
                generated_rows.append(generated)
        except Exception as exc:
            native_error = exc
        try:
            core_after = _read_o1o_core_sources(config)
            sibling_after, sibling_entries_after = _tree_snapshot(config.o1o_repository)
            sibling_audit_completed = True
        except Exception as exc:
            if native_error is None:
                native_error = exc
        sibling_unchanged = (
            sibling_audit_completed
            and core_before == core_after == dict(config.o1o_core_sha256)
            and sibling_before == sibling_after
            and sibling_entries == sibling_entries_after
        )
        work.sibling_write_free_proven = sibling_unchanged
        if sibling_audit_completed and not sibling_unchanged:
            work.sibling_mutations_observed_lower_bound = 1
        if not sibling_unchanged:
            raise O1C22PostResultComposerRunError(
                "O1-O source/sibling audit failed or observed a mutation"
            ) from native_error
        if native_error is not None:
            raise native_error
        work.validate_success(config.budgets)
        if generated_rows[0] != generated_rows[1]:
            raise O1C22PostResultComposerRunError(
                "native O1-O generated bytes are not deterministic"
            )
        generated = generated_rows[0]
        if len(generated) > config.budgets.maximum_generated_source_bytes:
            raise O1C22PostResultComposerRunError("generated source budget exceeded")
        generated_sha = _sha256_bytes(generated)
        native_receipt_unsigned = {
            "schema": NATIVE_RECEIPT_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "native_invocations": EXPECTED_NATIVE_RUNS,
            "byte_identical_generated_source": True,
            "generated_sha256": generated_sha,
            "generated_bytes": len(generated),
            "generated_code_compiled": False,
            "generated_code_executed": False,
            "runs": native_rows,
            "o1o_core_source_sha256_before": dict(core_before),
            "o1o_core_source_sha256_after": dict(core_after),
            "sibling_snapshot_sha256_before": sibling_before,
            "sibling_snapshot_sha256_after": sibling_after,
            "sibling_snapshot_entries": sibling_entries,
            "sibling_write_free_proven": work.sibling_write_free_proven,
            "sibling_writes": 0,
        }
        native_receipt = {
            **native_receipt_unsigned,
            "native_receipt_sha256": _sha256_bytes(
                canonical_json_bytes(native_receipt_unsigned)
            ),
        }
        operator_graph = next_operator_graph(
            decision,
            causal_sha256=_sha256_bytes(causal_payload),
            fragment_sha256=_sha256_bytes(fragment_payload),
            native_generated_sha256=generated_sha,
        )
        source_index = _source_index(
            config,
            source,
            core_before=core_before,
            core_after=core_after,
            sibling_snapshot_sha256_before=sibling_before,
            sibling_snapshot_sha256_after=sibling_after,
            sibling_snapshot_entries=sibling_entries,
        )

        artifacts = (
            ("decision_policy.json", canonical_json_bytes(decision_policy()), "POLICY"),
            ("failure_memory.json", canonical_json_bytes(memory), "FAILURE_MEMORY"),
            (
                "quantization_diagnostics.json",
                canonical_json_bytes(source.diagnostics),
                "DIAGNOSTICS",
            ),
            ("decision.json", canonical_json_bytes(decision), "DECISION"),
            (O1O_KNOWLEDGE_FILENAME, causal_payload, "O1O_ROUTE"),
            (O1O_FRAGMENT_FILENAME, fragment_payload, "O1O_FRAGMENT"),
            (
                "native_o1o_receipt.json",
                canonical_json_bytes(native_receipt),
                "NATIVE_DOUBLE_ASSEMBLY",
            ),
            ("native_generated_source.py", generated, "NATIVE_GENERATED_SOURCE"),
            (
                "next_operator_graph.json",
                canonical_json_bytes(operator_graph),
                "OPERATOR_GRAPH",
            ),
            (
                "structural_work_ledger.json",
                canonical_json_bytes(work.document()),
                "STRUCTURAL_WORK",
            ),
            ("source_index.json", canonical_json_bytes(source_index), "SOURCE_INDEX"),
        )
        for relative, payload, phase in artifacts:
            persist(relative, payload, phase)
        artifact_index = {
            "schema": ARTIFACT_INDEX_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "source_capsule_manifest_sha256": source.finalized.manifest_sha256,
            "decision_sha256": decision["decision_sha256"],
            "operator_graph_sha256": operator_graph["operator_graph_sha256"],
            "artifacts": dict(sorted(persisted.items())),
            "indexed_artifact_count": len(persisted),
            "indexed_artifact_bytes": persistent_bytes,
        }
        persist(
            "artifact_index.json",
            canonical_json_bytes(artifact_index),
            "ARTIFACT_INDEX",
        )
        if _source_hashes(config, source) != hashes:
            raise O1C22PostResultComposerRunError("source changed during execution")

        resources = _measure_run_resources(resource_baseline, native_rows)
        cpu_seconds = float(resources["cpu_seconds"])
        wall_seconds = float(resources["wall_seconds"])
        peak_rss_bytes = int(resources["peak_rss_bytes"])
        budget_checks = {
            "cpu": cpu_seconds <= config.budgets.maximum_cpu_seconds,
            "wall": wall_seconds <= config.budgets.maximum_wall_seconds,
            "resident_memory": peak_rss_bytes
            <= config.budgets.maximum_resident_memory_mib * 1024 * 1024,
            "persistent_artifacts": persistent_bytes
            <= config.budgets.maximum_persistent_artifact_bytes,
            "source_artifact_bytes_read": source.source_artifact_bytes_read
            <= config.budgets.maximum_source_artifact_bytes_read,
            "k256_heldout_folds": len(source.folds)
            == config.budgets.expected_k256_heldout_folds,
            "primary_state_bytes": all(
                len(row.state_payload)
                == config.budgets.required_primary_live_state_bytes
                for row in source.folds
            ),
            "native_o1o_invocations": len(native_rows)
            == config.budgets.maximum_native_o1o_invocations
            == work.native_o1o_invocations_validated,
            "generated_source_bytes": len(generated)
            <= config.budgets.maximum_generated_source_bytes,
            "fresh_targets": work.fresh_targets_consumed
            == config.budgets.maximum_fresh_targets_consumed,
            "native_solver_branches": work.native_solver_branches
            == config.budgets.maximum_native_solver_branches,
            "scientific_entropy": work.scientific_entropy_calls
            == config.budgets.maximum_scientific_entropy_calls,
            "sibling_writes": work.sibling_write_free_proven
            and work.sibling_mutations_observed_lower_bound
            <= config.budgets.maximum_sibling_writes,
            "mps": work.mps_calls == config.budgets.maximum_mps_calls,
            "gpu": work.gpu_calls == config.budgets.maximum_gpu_calls,
        }
        failed_budgets = sorted(
            name for name, passed in budget_checks.items() if not passed
        )
        operationally_complete = not failed_budgets
        operator = _mapping(decision["operator"], "decision.operator")
        metrics = {
            "schema": RUN_METRICS_SCHEMA,
            "source_attempt_id": UPSTREAM_ATTEMPT_ID,
            "source_capsule_manifest_sha256": source.finalized.manifest_sha256,
            "source_result_sha256": source.result["result_sha256"],
            "source_classification": source.result["classification"],
            "decision_policy_sha256": decision_policy_sha256(),
            "quantization_diagnostics_sha256": source.diagnostics["diagnostics_sha256"],
            "decision_sha256": decision["decision_sha256"],
            "operator_id": operator["operator_id"],
            "operator_fingerprint": operator["operator_fingerprint"],
            "fresh_target_authorized": decision["fresh_target_authorized"],
            "operator_graph_sha256": operator_graph["operator_graph_sha256"],
            "native_receipt_sha256": native_receipt["native_receipt_sha256"],
            "native_generated_sha256": generated_sha,
            "native_generated_bytes": len(generated),
            "native_invocations": len(native_rows),
            "structural_work_ledger_sha256": work.document()["work_ledger_sha256"],
            "native_generated_bytes_identical": True,
            "generated_code_compiled": False,
            "generated_code_executed": False,
            "source_artifact_bytes_read": source.source_artifact_bytes_read,
            "persistent_artifact_bytes": persistent_bytes,
            **resources,
            "fresh_targets_consumed": work.fresh_targets_consumed,
            "native_solver_branches": work.native_solver_branches,
            "scientific_entropy_calls": work.scientific_entropy_calls,
            "sibling_write_free_proven": work.sibling_write_free_proven,
            "sibling_mutations_observed_lower_bound": (
                work.sibling_mutations_observed_lower_bound
            ),
            "sibling_writes": (0 if work.sibling_write_free_proven else None),
            "mps_calls": work.mps_calls,
            "gpu_calls": work.gpu_calls,
            "budget_checks": budget_checks,
            "failed_budgets": failed_budgets,
            "operationally_complete": operationally_complete,
        }
        run.append_stdout(json.dumps(metrics, sort_keys=True) + "\n")
        finalized = run.finalize(
            metrics=metrics,
            status="completed" if operationally_complete else "failed",
        )
    except Exception as exc:
        if work.native_o1o_invocations_started == 0:
            work.sibling_write_free_proven = True
        failure_resources = _measure_run_resources(resource_baseline, native_rows)
        failure_resource_budget_checks = {
            "cpu": float(failure_resources["cpu_seconds"])
            <= config.budgets.maximum_cpu_seconds,
            "wall": float(failure_resources["wall_seconds"])
            <= config.budgets.maximum_wall_seconds,
            "resident_memory": int(failure_resources["peak_rss_bytes"])
            <= config.budgets.maximum_resident_memory_mib * 1024 * 1024,
            "persistent_artifacts": persistent_bytes
            <= config.budgets.maximum_persistent_artifact_bytes,
            "source_artifact_bytes_read": source.source_artifact_bytes_read
            <= config.budgets.maximum_source_artifact_bytes_read,
        }
        run.append_stderr(f"{type(exc).__name__}: {exc}\n")
        finalized = run.finalize(
            metrics={
                "schema": RUN_METRICS_SCHEMA,
                "operationally_complete": False,
                "operator_decision_claimed": False,
                "error_type": type(exc).__name__,
                "error": str(exc),
                "source_artifact_bytes_read": source.source_artifact_bytes_read,
                "persistent_artifact_bytes": persistent_bytes,
                **failure_resources,
                "resource_budget_checks": failure_resource_budget_checks,
                "structural_work": work.document(),
                "fresh_targets_consumed": work.fresh_targets_consumed,
                "native_solver_branches": work.native_solver_branches,
                "scientific_entropy_calls": work.scientific_entropy_calls,
                "sibling_write_free_proven": work.sibling_write_free_proven,
                "sibling_mutations_observed_lower_bound": (
                    work.sibling_mutations_observed_lower_bound
                ),
                "sibling_writes": (0 if work.sibling_write_free_proven else None),
                "mps_calls": work.mps_calls,
                "gpu_calls": work.gpu_calls,
            },
            status="failed",
            next_action=(
                "Preserve this operational failure and fix its exact frozen "
                "lifecycle under a new attempt identity."
            ),
        )
        print(f"failed capsule: {finalized.path}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "attempt_id": finalized.attempt_id,
                "path": str(finalized.path),
                "manifest_sha256": finalized.manifest_sha256,
                "verified": finalized.verification.ok,
                "status": "completed" if operationally_complete else "failed",
                "operator_id": metrics["operator_id"],
                "operator_fingerprint": metrics["operator_fingerprint"],
                "native_generated_sha256": metrics["native_generated_sha256"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if operationally_complete else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run or preflight O1C-0023 frozen O1C-0022 post-result composer"
    )
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--preflight", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.preflight:
        preflight = preflight_o1c22_postresult_composer(args.config)
        print(json.dumps(preflight.report, indent=2, sort_keys=True))
        return 0 if preflight.ready else 2
    return run_capsule_from_config(args.config)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "ARTIFACT_INDEX_SCHEMA",
    "NATIVE_RECEIPT_SCHEMA",
    "O1C22PostResultComposerRunError",
    "O1C22PostResultSource",
    "O1C23Preflight",
    "O1C23RunConfig",
    "PREFLIGHT_SCHEMA",
    "RUN_CONFIG_SCHEMA",
    "RUN_METRICS_SCHEMA",
    "SOURCE_INDEX_SCHEMA",
    "_load_verified_o1c22_source",
    "load_o1c22_postresult_composer_run_config",
    "main",
    "preflight_o1c22_postresult_composer",
    "run_capsule_from_config",
]
