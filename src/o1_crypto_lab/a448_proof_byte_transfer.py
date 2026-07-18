"""Exact one-pass A448 proof-antecedent transfer onto a full-256 byte cube.

The sibling A448 reader is reused without refitting.  Its antecedent helper also
emits the H1/2/4/8 identity telemetry from which the A442 Borda tie backbone was
built, so one native pass supplies both components.  Only the public ChaCha20
relation and one candidate-byte coordinate enter measurement; the other 248 key
bits remain unassigned.
"""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import json
import math
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import numpy as np

from .a296_shallow_byte_cube import _stage_to_raw, key_byte_reader_mapping
from .a291_a296_fap_transfer import A291_HORIZONS
from .full256_cnf import write_full256_instance
from .living_inverse import PublicTargetView, canonical_json_bytes, canonical_sha256
from .shape532 import FEATURE_NAMES, RawCell


A448_CANDIDATES = 256
A448_STAGES = A448_CANDIDATES * len(A291_HORIZONS)
A448_OPERATOR = "hybrid_proof_top4_equal"
A442_OPERATOR = "borda_sum"
A448_MODEL_ROLES = (
    "wide_vote",
    "sparse_reciprocal",
    "broad_quantile",
    "broad_intersection",
)
A448_TOP4_FEATURE_INDICES = (2097, 2592, 2094, 2589)
A448_TOP4_FEATURE_NAMES = (
    "h8::all::ancestry_assumption_position_union::position5::ascending",
    "h8::redundant::ancestry_assumption_position_union::position5::ascending",
    "h8::all::ancestry_assumption_position_union::position4::ascending",
    "h8::redundant::ancestry_assumption_position_union::position4::ascending",
)
A448_FROZEN_MODEL_SHA256 = (
    "0d058bd1dc145b85f80d8ec7d11eaa071dfad8f689ad67bd38f3749a57ab4c38"
)
A375_RESULT_SHA256 = (
    "fc7135af9e001eb8cd83a55902e48f5776dc24a4eb86a162d7d783a115b38ef1"
)
A442_RESULT_SHA256 = (
    "8c8222528dc3ef12ffc0fbda513061b39243daade51a70a17f0bd89c65b53b1d"
)
A447_RESULT_SHA256 = (
    "09836abe6618d42d544a327f009d7840e00bb9bfbf2e99eea296a7ed70cc6051"
)
A448_HELPER_SHA256 = (
    "9d0d5cbd6e523e248023fb080c206fa14d8bbb2c89d3cd8f1273eaaa1a99de67"
)
A448_WRAPPER_SHA256 = (
    "bf2798e72e1c2ff7872ea262335d4500cf82e1e46cbdf110f9628f713d4af61b"
)
A448_IDENTITY_WRAPPER_SHA256 = (
    "3a1d63d223712997519f72143ebcc3e5725a8f8659eadbd9389465dd0fe654f6"
)
A448_MULTIHORIZON_WRAPPER_SHA256 = (
    "55e1722d8478bf0aea95a544e5942fa6f6a3b17e8c9c54906e2ba34ddc2be386"
)
A448_FEATURE_SOURCE_SHA256 = (
    "52700bb0a2442caf24ef123c745915fd7b2e2a27ca2f797886b141a640fc4c05"
)
A448_SHAPE_SOURCE_SHA256 = (
    "44056b27937c1b4f1ab9af2dfaf904ad3b5f239deda05519c2e9a16f9f1e8160"
)

A375_RESULT_RELATIVE = Path(
    "research/results/v1/chacha20_round20_w46_wide_consensus_reader_a375_v1.json"
)
A442_RESULT_RELATIVE = Path(
    "research/results/v1/chacha20_round20_w52_knownkey_meta_reader_transfer_a442_v1.json"
)
A447_RESULT_RELATIVE = Path(
    "research/results/v1/chacha20_round20_w46_proof_antecedent_calibration_a447_v1.json"
)
A448_WRAPPER_RELATIVE = Path(
    "research/experiments/chacha20_fresh_clause_antecedents.py"
)
A448_IDENTITY_WRAPPER_RELATIVE = Path(
    "research/experiments/chacha20_fresh_clause_identity.py"
)
A448_MULTIHORIZON_WRAPPER_RELATIVE = Path(
    "research/experiments/chacha20_fresh_multihorizon.py"
)
A448_FEATURE_SOURCE_RELATIVE = Path("src/arx_carry_leak/proof_antecedent_features.py")
A448_SHAPE_SOURCE_RELATIVE = Path("src/arx_carry_leak/solver_trajectory_shape.py")
A448_HELPER_RELATIVE = Path(
    "research/native/build/"
    "cadical_fresh_clause_antecedents-"
    "a445c0839699f9cd43b4dadd344ca888ecf5df0e3f171c8440af35ec342c22bb-"
    "9d0d5cbd6e523e248023fb080c206fa14d8bbb2c89d3cd8f1273eaaa1a99de67"
)


class A448TransferError(RuntimeError):
    """The exact sibling source, cube, reader, or public boundary differs."""


@dataclass(frozen=True)
class A375ReaderDefinition:
    aggregator: str
    member_feature_indices: tuple[int, ...]


@dataclass(frozen=True)
class FrozenA448Model:
    sibling_root: Path
    definitions: Mapping[str, A375ReaderDefinition]
    complete_feature_order: tuple[int, ...]
    top4_feature_indices: tuple[int, ...]
    top4_feature_names: tuple[str, ...]
    model_sha256: str


@dataclass(frozen=True)
class A448RankField:
    baseline_ranks: np.ndarray
    proof_ranks: np.ndarray
    final_ranks: np.ndarray
    feature_matrix_sha256: str
    directional_rank_sha256: str

    def __post_init__(self) -> None:
        exact = set(range(1, A448_CANDIDATES + 1))
        for field in (self.baseline_ranks, self.proof_ranks, self.final_ranks):
            if field.shape != (A448_CANDIDATES,) or set(field.tolist()) != exact:
                raise A448TransferError("A448 rank field must be an exact permutation")
            field.setflags(write=False)


@dataclass(frozen=True)
class A448ByteCubeMeasurement:
    byte_index: int
    ranks: A448RankField
    public_view_sha256: str
    instance_sha256: str
    helper_sha256: str
    stdout_sha256: str
    stable_run_sha256: str
    raw_artifact_gzip: bytes | None
    raw_artifact_sha256: str | None
    wall_seconds: float

    def __post_init__(self) -> None:
        if not 0 <= self.byte_index < 32:
            raise A448TransferError("byte_index must be in 0..31")
        if not math.isfinite(self.wall_seconds) or self.wall_seconds <= 0.0:
            raise A448TransferError("wall_seconds must be finite and positive")

    def candidate_order(self) -> list[int]:
        return np.argsort(self.ranks.final_ranks, kind="stable").astype(int).tolist()

    def describe(self) -> dict[str, object]:
        order = self.candidate_order()
        return {
            "schema": "o1-256-a448-proof-byte-cube-measurement-v1",
            "byte_index": self.byte_index,
            "candidate_count": A448_CANDIDATES,
            "horizons": list(A291_HORIZONS),
            "other_key_bits_assigned": 0,
            "target_key_inputs": 0,
            "operator": A448_OPERATOR,
            "A442_tie_operator": A442_OPERATOR,
            "frozen_model_sha256": A448_FROZEN_MODEL_SHA256,
            "top4_feature_indices": list(A448_TOP4_FEATURE_INDICES),
            "top4_feature_names": list(A448_TOP4_FEATURE_NAMES),
            "baseline_ranks": self.ranks.baseline_ranks.astype(int).tolist(),
            "proof_ranks": self.ranks.proof_ranks.astype(int).tolist(),
            "final_ranks": self.ranks.final_ranks.astype(int).tolist(),
            "candidate_order": order,
            "candidate_order_uint8_sha256": hashlib.sha256(bytes(order)).hexdigest(),
            "feature_matrix_sha256": self.ranks.feature_matrix_sha256,
            "directional_rank_sha256": self.ranks.directional_rank_sha256,
            "public_view_sha256": self.public_view_sha256,
            "instance_sha256": self.instance_sha256,
            "helper_sha256": self.helper_sha256,
            "stdout_sha256": self.stdout_sha256,
            "stable_run_sha256": self.stable_run_sha256,
            "raw_artifact_bytes": (
                None
                if self.raw_artifact_gzip is None
                else len(self.raw_artifact_gzip)
            ),
            "raw_artifact_sha256": self.raw_artifact_sha256,
            "wall_seconds": self.wall_seconds,
        }


def default_sibling_root() -> Path:
    return Path(__file__).resolve().parents[3] / "arx-carry-leak"


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _anchored(root: Path, relative: Path, expected_sha256: str) -> Path:
    path = (root / relative).resolve(strict=True)
    if _file_sha256(path) != expected_sha256:
        raise A448TransferError(f"A448 sibling anchor differs: {relative}")
    return path


def _json_object(path: Path) -> Mapping[str, object]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise A448TransferError(f"A448 JSON source is not an object: {path.name}")
    return cast(Mapping[str, object], value)


def load_frozen_a448_model(
    sibling_root: str | Path | None = None,
) -> FrozenA448Model:
    root = (
        default_sibling_root()
        if sibling_root is None
        else Path(sibling_root).resolve(strict=True)
    )
    a375 = _json_object(_anchored(root, A375_RESULT_RELATIVE, A375_RESULT_SHA256))
    a442 = _json_object(_anchored(root, A442_RESULT_RELATIVE, A442_RESULT_SHA256))
    a447 = _json_object(_anchored(root, A447_RESULT_RELATIVE, A447_RESULT_SHA256))
    if (
        a375.get("attempt_id") != "A375"
        or a442.get("attempt_id") != "A442"
        or a442.get("selected_operator") != A442_OPERATOR
        or a447.get("attempt_id") != "A447"
        or a447.get("selected_operator") != A448_OPERATOR
        or a447.get("selected_full_model_sha256") != A448_FROZEN_MODEL_SHA256
    ):
        raise A448TransferError("A375/A442/A447 frozen selection semantics differ")

    definitions_raw = a375.get("model_definitions")
    selected_raw = a447.get("selected_full_model")
    if not isinstance(definitions_raw, dict) or not isinstance(selected_raw, dict):
        raise A448TransferError("A448 frozen model sources differ")
    definitions: dict[str, A375ReaderDefinition] = {}
    for role in A448_MODEL_ROLES:
        raw = definitions_raw.get(role)
        if not isinstance(raw, dict):
            raise A448TransferError(f"A375 reader definition missing: {role}")
        aggregator = raw.get("aggregator")
        members = raw.get("member_feature_indices")
        if (
            not isinstance(aggregator, str)
            or not isinstance(members, list)
            or not members
            or any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 <= value < len(FEATURE_NAMES)
                for value in members
            )
            or len(set(members)) != len(members)
        ):
            raise A448TransferError(f"A375 reader definition invalid: {role}")
        definitions[role] = A375ReaderDefinition(aggregator, tuple(members))

    order = selected_raw.get("complete_feature_order")
    names = selected_raw.get("top64_feature_names")
    if (
        selected_raw.get("model_sha256") != A448_FROZEN_MODEL_SHA256
        or selected_raw.get("selected_operator") != A448_OPERATOR
        or selected_raw.get("feature_count") != 3051
        or not isinstance(order, list)
        or len(order) != 3051
        or len(set(order)) != 3051
        or tuple(order[:4]) != A448_TOP4_FEATURE_INDICES
        or not isinstance(names, list)
        or tuple(names[:4]) != A448_TOP4_FEATURE_NAMES
    ):
        raise A448TransferError("A447 selected full model differs")
    return FrozenA448Model(
        sibling_root=root,
        definitions=definitions,
        complete_feature_order=tuple(order),
        top4_feature_indices=A448_TOP4_FEATURE_INDICES,
        top4_feature_names=A448_TOP4_FEATURE_NAMES,
        model_sha256=A448_FROZEN_MODEL_SHA256,
    )


def _exact_ranks(order: Sequence[int]) -> np.ndarray:
    values = np.asarray(order, dtype=np.int64)
    if values.shape != (A448_CANDIDATES,) or set(values.tolist()) != set(
        range(A448_CANDIDATES)
    ):
        raise A448TransferError("A448 candidate order is not exact")
    ranks = np.empty(A448_CANDIDATES, dtype=np.int16)
    ranks[values] = np.arange(1, A448_CANDIDATES + 1, dtype=np.int16)
    return ranks


def target_normalize_shape532(matrix: np.ndarray) -> np.ndarray:
    values = np.asarray(matrix, dtype=np.float64)
    if values.shape != (A448_CANDIDATES, len(FEATURE_NAMES)) or not np.isfinite(
        values
    ).all():
        raise A448TransferError("A375 target feature matrix differs")
    means = values.mean(axis=0)
    scales = values.std(axis=0)
    constant = scales <= np.maximum(1e-12, np.abs(means) * 1e-12)
    scales[constant] = 1.0
    result = (values - means) / scales
    result[:, constant] = 0.0
    if not np.isfinite(result).all():
        raise A448TransferError("A375 target normalization is non-finite")
    return result


def _absolute_feature_rank_fields(matrix: np.ndarray) -> np.ndarray:
    values = target_normalize_shape532(matrix)
    cells = np.arange(A448_CANDIDATES, dtype=np.int16)
    result = np.empty(
        (len(FEATURE_NAMES), A448_CANDIDATES), dtype=np.int16
    )
    for feature in range(len(FEATURE_NAMES)):
        result[feature] = _exact_ranks(
            np.lexsort((cells, -np.abs(values[:, feature])))
        )
    return result


def _aggregate_a375_reader(
    absolute: np.ndarray, definition: A375ReaderDefinition
) -> np.ndarray:
    selected = absolute[np.asarray(definition.member_feature_indices)].astype(
        np.float64
    )
    mean_rank = selected.mean(axis=0)
    if definition.aggregator == "maximum_member_rank":
        primary = selected.max(axis=0)
        descending = False
    elif definition.aggregator == "member_rank_quantile_0.75":
        primary = np.quantile(selected, 0.75, axis=0, method="linear")
        descending = False
    elif definition.aggregator == "reciprocal_rank_sum":
        primary = (1.0 / selected).sum(axis=0)
        descending = True
    elif definition.aggregator == "top64_vote_then_mean_rank":
        primary = (selected <= 64).sum(axis=0).astype(np.float64)
        descending = True
    else:
        raise A448TransferError(
            f"unknown A375 aggregator: {definition.aggregator}"
        )
    signed = -primary if descending else primary
    cells = np.arange(A448_CANDIDATES, dtype=np.int16)
    return _exact_ranks(np.lexsort((cells, mean_rank, signed)))


def a442_borda_ranks_from_shape532(
    matrix: np.ndarray, model: FrozenA448Model
) -> np.ndarray:
    """Reconstruct the exact frozen A442 Borda rank field for one cube."""

    absolute = _absolute_feature_rank_fields(matrix)
    sources = np.stack(
        [
            _aggregate_a375_reader(absolute, model.definitions[role])
            for role in A448_MODEL_ROLES
        ]
    ).astype(np.int64)
    minimum = sources.min(axis=0)
    maximum = sources.max(axis=0)
    rank_sum = sources.sum(axis=0)
    cells = np.arange(A448_CANDIDATES, dtype=np.int64)
    secondary = (maximum, minimum, *tuple(sources))
    keys: list[np.ndarray] = [cells]
    keys.extend(np.asarray(value) for value in reversed(secondary))
    keys.append(rank_sum)
    return _exact_ranks(np.lexsort(tuple(keys)))


def raw_cells_from_antecedent_run(run: Mapping[str, object]) -> tuple[RawCell, ...]:
    stages = run.get("stages")
    if (
        run.get("proof_antecedent_identity_complete") is not True
        or run.get("proof_missing_antecedent_total") != 0
        or not isinstance(stages, list)
        or len(stages) != A448_STAGES
    ):
        raise A448TransferError("complete A448 proof-antecedent run required")
    cells: list[dict[int, Mapping[str, float]]] = [
        {} for _ in range(A448_CANDIDATES)
    ]
    for raw in stages:
        if not isinstance(raw, dict):
            raise A448TransferError("A448 proof stage is not an object")
        candidate = raw.get("cell_index")
        horizon = raw.get("horizon")
        if (
            isinstance(candidate, bool)
            or not isinstance(candidate, int)
            or not 0 <= candidate < A448_CANDIDATES
            or horizon not in A291_HORIZONS
            or raw.get("prefix8") != f"{candidate:08b}"
            or raw.get("status") != "unknown"
            or raw.get("terminal") is not False
            or horizon in cells[candidate]
        ):
            raise A448TransferError("A448 proof stage cover differs")
        cells[candidate][cast(int, horizon)] = _stage_to_raw(raw)
    if any(set(cell) != set(A291_HORIZONS) for cell in cells):
        raise A448TransferError("A448 raw cube is incomplete")
    return tuple(cast(RawCell, cell) for cell in cells)


def _load_sibling_module(
    *, root: Path, relative: Path, expected_sha256: str, name: str
) -> Any:
    path = _anchored(root, relative, expected_sha256)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise A448TransferError(f"cannot import exact sibling module: {relative}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    sibling_src = str(root / "src")
    inserted = sibling_src not in sys.path
    if inserted:
        sys.path.insert(0, sibling_src)
    sys.dont_write_bytecode = True
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    finally:
        sys.dont_write_bytecode = previous
        if inserted:
            sys.path.remove(sibling_src)
    return module


def _require_wrapper_anchors(root: Path) -> None:
    _anchored(
        root, A448_IDENTITY_WRAPPER_RELATIVE, A448_IDENTITY_WRAPPER_SHA256
    )
    _anchored(
        root,
        A448_MULTIHORIZON_WRAPPER_RELATIVE,
        A448_MULTIHORIZON_WRAPPER_SHA256,
    )


def exact_a275_shape532_from_run(
    run: Mapping[str, object], model: FrozenA448Model
) -> np.ndarray:
    """Build A275's byte-exact NumPy 256x532 field from the proof run."""

    source = _load_sibling_module(
        root=model.sibling_root,
        relative=A448_SHAPE_SOURCE_RELATIVE,
        expected_sha256=A448_SHAPE_SOURCE_SHA256,
        name="o1c31_exact_a275_solver_trajectory_shape",
    )
    if tuple(source.FEATURE_NAMES) != FEATURE_NAMES:
        raise A448TransferError("A275 trajectory feature-name ledger differs")
    rows = source._stage_rows({"run": run})  # noqa: SLF001
    base = np.empty((A448_CANDIDATES, len(source.BASE_FEATURE_NAMES)), dtype=np.float64)
    for candidate in range(A448_CANDIDATES):
        channel_values = {
            channel: np.asarray(
                [
                    source._channel_value(  # noqa: SLF001
                        rows[(candidate, horizon)], channel
                    )
                    for horizon in A291_HORIZONS
                ],
                dtype=np.float64,
            )
            for channel in source.CHANNELS
        }
        base[candidate] = source._shape_vector(channel_values)  # noqa: SLF001
    result = np.asarray(source._orbit_matrix(base), dtype=np.float64)  # noqa: SLF001
    if result.shape != (A448_CANDIDATES, len(FEATURE_NAMES)) or not np.isfinite(
        result
    ).all():
        raise A448TransferError("A275 exact trajectory-shape matrix differs")
    return result


def a448_rank_field_from_run(
    run: Mapping[str, object],
    *,
    model: FrozenA448Model | None = None,
) -> A448RankField:
    frozen = load_frozen_a448_model() if model is None else model
    shape = exact_a275_shape532_from_run(run, frozen)
    baseline = a442_borda_ranks_from_shape532(shape, frozen)
    feature_source = _load_sibling_module(
        root=frozen.sibling_root,
        relative=A448_FEATURE_SOURCE_RELATIVE,
        expected_sha256=A448_FEATURE_SOURCE_SHA256,
        name="o1c31_exact_a448_proof_features",
    )
    feature_matrix, base_names = feature_source.extract_proof_feature_matrix(run)
    normalized = feature_source.target_normalize(feature_matrix)
    directional, _generic_names = feature_source.exact_directional_rank_fields(
        normalized, baseline
    )
    directional_names = feature_source.directional_feature_names(base_names)
    if (
        directional.shape != (3051, A448_CANDIDATES)
        or len(directional_names) != 3051
        or tuple(directional_names[index] for index in frozen.top4_feature_indices)
        != frozen.top4_feature_names
    ):
        raise A448TransferError("A447 directional proof feature ledger differs")
    selected = directional[np.asarray(frozen.top4_feature_indices)].astype(np.int64)
    proof_primary = selected.sum(axis=0)
    cells_index = np.arange(A448_CANDIDATES, dtype=np.int64)
    proof = _exact_ranks(np.lexsort((cells_index, baseline, proof_primary)))
    final_primary = baseline.astype(np.int64) + proof.astype(np.int64)
    final = _exact_ranks(np.lexsort((cells_index, baseline, final_primary)))
    return A448RankField(
        baseline_ranks=baseline,
        proof_ranks=proof,
        final_ranks=final,
        feature_matrix_sha256=hashlib.sha256(
            np.asarray(feature_matrix, dtype="<f8").tobytes()
        ).hexdigest(),
        directional_rank_sha256=hashlib.sha256(
            np.asarray(directional, dtype="<i2").tobytes()
        ).hexdigest(),
    )


def _stable_run(run: Mapping[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in run.items()
        if key not in {"command", "process_elapsed_seconds"}
    }


def _deterministic_gzip(value: object) -> bytes:
    raw = canonical_json_bytes(value)
    return gzip.compress(raw, compresslevel=9, mtime=0)


def measure_public_a448_byte_cube(
    *,
    public: PublicTargetView,
    byte_index: int,
    template: str | Path,
    semantic_map: str | Path,
    workspace: str | Path,
    sibling_root: str | Path | None = None,
    capture_raw_artifact: bool = False,
    watchdog_seconds: float = 2.0,
    external_timeout_seconds: float = 1800.0,
) -> A448ByteCubeMeasurement:
    """Measure the unchanged A448 reader with no unknown-key labels as input."""

    if not isinstance(public, PublicTargetView):
        raise TypeError("public must be PublicTargetView")
    public.validate()
    if public.block_count != 1 or not 0 <= byte_index < 32:
        raise A448TransferError("A448 requires one public block and byte_index 0..31")
    if (
        not math.isfinite(watchdog_seconds)
        or watchdog_seconds <= 0.0
        or not math.isfinite(external_timeout_seconds)
        or external_timeout_seconds <= 0.0
    ):
        raise A448TransferError("A448 timeouts must be finite and positive")
    frozen = load_frozen_a448_model(sibling_root)
    root = frozen.sibling_root
    _require_wrapper_anchors(root)
    helper = _anchored(root, A448_HELPER_RELATIVE, A448_HELPER_SHA256)
    wrapper = _load_sibling_module(
        root=root,
        relative=A448_WRAPPER_RELATIVE,
        expected_sha256=A448_WRAPPER_SHA256,
        name="o1c31_exact_a448_wrapper",
    )
    template_path = Path(template).resolve(strict=True)
    map_path = Path(semantic_map).resolve(strict=True)
    workspace_path = Path(workspace).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="a448-byte-cube-", dir=workspace_path) as raw:
        instance_path = Path(raw) / "public.cnf"
        instance = write_full256_instance(
            template_path,
            map_path,
            instance_path,
            counter=public.counter_schedule[0],
            nonce=public.nonce,
            output=public.output_blocks[0],
            verify_template=False,
        )
        if (
            instance.key_unit_clause_count != 0
            or instance.assumption_unit_clause_count != 0
            or instance.public_unit_clause_count != 640
        ):
            raise A448TransferError("A448 public CNF contains target-key input")
        started = time.perf_counter()
        previous_bytecode = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        try:
            run = wrapper.run_fresh_clause_antecedents(
                helper=helper,
                cnf=instance_path,
                mode=f"O1C31_A448_FULL256_BYTE_{byte_index:02d}",
                order=[
                    f"{candidate:08b}" for candidate in range(A448_CANDIDATES)
                ],
                key_one_literals_bit0_through_bit19=key_byte_reader_mapping(
                    byte_index
                ),
                conflict_horizons=A291_HORIZONS,
                watchdog_seconds=watchdog_seconds,
                external_timeout_seconds=external_timeout_seconds,
            )
        finally:
            sys.dont_write_bytecode = previous_bytecode
        wall_seconds = time.perf_counter() - started
        stable = _stable_run(cast(Mapping[str, object], run))
        ranks = a448_rank_field_from_run(stable, model=frozen)
        stable_sha = canonical_sha256(stable)
        artifact_payload = _deterministic_gzip(stable) if capture_raw_artifact else None
        artifact_sha = (
            None
            if artifact_payload is None
            else hashlib.sha256(artifact_payload).hexdigest()
        )
    return A448ByteCubeMeasurement(
        byte_index=byte_index,
        ranks=ranks,
        public_view_sha256=public.digest(),
        instance_sha256=instance.instance_sha256,
        helper_sha256=A448_HELPER_SHA256,
        stdout_sha256=str(stable["stdout_sha256"]),
        stable_run_sha256=stable_sha,
        raw_artifact_gzip=artifact_payload,
        raw_artifact_sha256=artifact_sha,
        wall_seconds=wall_seconds,
    )


def revealed_byte_rank(field: A448RankField, target_byte: int) -> int:
    if (
        isinstance(target_byte, bool)
        or not isinstance(target_byte, int)
        or not 0 <= target_byte < A448_CANDIDATES
    ):
        raise A448TransferError("target_byte must be in 0..255")
    return int(field.final_ranks[target_byte])


__all__ = [
    "A375ReaderDefinition",
    "A448ByteCubeMeasurement",
    "A448RankField",
    "A448TransferError",
    "A448_CANDIDATES",
    "A448_FROZEN_MODEL_SHA256",
    "A448_HELPER_RELATIVE",
    "A448_HELPER_SHA256",
    "A448_OPERATOR",
    "A448_TOP4_FEATURE_INDICES",
    "A448_TOP4_FEATURE_NAMES",
    "FrozenA448Model",
    "a442_borda_ranks_from_shape532",
    "a448_rank_field_from_run",
    "default_sibling_root",
    "exact_a275_shape532_from_run",
    "load_frozen_a448_model",
    "measure_public_a448_byte_cube",
    "raw_cells_from_antecedent_run",
    "revealed_byte_rank",
    "target_normalize_shape532",
]
