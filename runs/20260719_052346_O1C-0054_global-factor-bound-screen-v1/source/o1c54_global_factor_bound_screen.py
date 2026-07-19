"""Full256-first global factor-bound screen over the frozen O1C-0048 pairs."""

from __future__ import annotations

import argparse
import hashlib
import json
import resource
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Mapping, Sequence

from .criticality_pair_groups import compile_primary_pair_groups
from .criticality_potential import (
    CriticalityPotentialField,
    score_potential_assignment,
)
from .full256_broker import public_view_from_publication, verify_reveal
from .full256_forward_assignment import compile_full256_forward_read_plan
from .global_factor_bound_scout import (
    compile_factor_bound_index,
    compile_pair_order,
    run_certified_bound_queue,
    run_full256_bound_beam,
)
from .living_inverse import PublicTargetView, key_bits
from .o1_relational_search import model_matches_public
from .o1c37_relational_guided_search_run import (
    _atomic_json,
    _git_commit,
    _relative_path,
    lab_root,
)
from .o1c48_pair_envelope_search_run import load_config as load_o1c48_config
from .proof_parent_criticality import ParentCriticalityField


ATTEMPT_ID = "O1C-0054"
RESULT_SCHEMA = "o1-256-global-factor-bound-screen-result-v1"
RESULT_RELATIVE = Path(
    "research/O1C0054_GLOBAL_FACTOR_BOUND_SCREEN_RESULT_20260719.json"
)
DEFAULT_CONFIG = Path("configs/o1c48_pair_envelope_search_v1.json")
CORE_SOURCE = Path("src/o1_crypto_lab/global_factor_bound_scout.py")
RUNNER_SOURCE = Path("src/o1_crypto_lab/o1c54_global_factor_bound_screen.py")
O1C47_RESULT = Path(
    "research/O1C0047_GLOBAL_CRITICALITY_RESIDUAL_BEAM_RESULT_20260719.json"
)
O1C47_RESULT_SHA256 = "91709eb6c7a0f378e8ef0046a81d4211a428d75fa6636553c218c023cab3380d"
O1C53_RESULT = Path(
    "research/O1C0053_DEEPEST_SURVIVOR_SUPPORT_SCREEN_RESULT_20260719.json"
)
O1C53_RESULT_SHA256 = "ab616087ec4aaf5862dbda0b0139146ea845b9a1cbe3cff0881e9a596e00f16a"

FULL256_BEAM_WIDTH = 256
PAIR_COUNT = 128
FROZEN_PAIR_COUNT = 63
COMPLETION_PAIR_COUNT = 65
W11_CERTIFIED_LEAVES = 5
W11_MAXIMUM_UNSCORED_POPS = 1024
W11_MAXIMUM_FORWARD_EVALUATIONS = 256
W11_MAXIMUM_LIVE_NODES = 2048
W11_TIMEOUT_SECONDS = 120.0
MAXIMUM_FORWARD_EVALUATIONS = 512
MAXIMUM_PEAK_RSS_BYTES = 512 * 1024 * 1024
MAXIMUM_NATIVE_SOLVER_CALLS = 0

EXPECTED_PUBLIC_VIEW_SHA256 = (
    "3f7841b5080200307564c9cb1956db6a48b2129afd21e85c3e76806735f464a0"
)
EXPECTED_TRUTH_KEY_SHA256 = (
    "722380bf59f57c52b258aebbd423cb8b188ea89bcdb85df114828a9c7fd37246"
)
EXPECTED_REVEAL_SHA256 = (
    "7caf9b1f83465138be80b28677207bf4a5e274b809ec65d55845168d21da0707"
)
EXPECTED_PRIMARY_POTENTIAL_SHA256 = (
    "307a0aeac84ee5efa4e6900f2105727bedbaa3a32b941102960a0257554cdf1e"
)
EXPECTED_PRIMARY_PAIR_ORDER_SHA256 = (
    "51d13c06c6640efc6b0439efa7a85900d30aea79698d18ae58202a33d03fdbd1"
)
EXPECTED_W11_VARIABLES = (
    173,
    174,
    175,
    184,
    59,
    143,
    176,
    9,
    60,
    144,
    177,
)

FULL256_RECOVERY_CLASSIFICATION = "ATTACKER_VALID_GLOBAL_FACTOR_BOUND_FULL256_RECOVERY"
W11_TOP5_CLASSIFICATION = (
    "POST_REVEAL_GLOBAL_FACTOR_BOUND_W11_PUBLIC_RECOVERY_TOP5_PASS"
)
W11_INCOMPLETE_RECOVERY_CLASSIFICATION = (
    "POST_REVEAL_GLOBAL_FACTOR_BOUND_W11_PUBLIC_RECOVERY_INCOMPLETE_TOP5"
)
W11_BOUND_FAILURE_CLASSIFICATION = "GLOBAL_FACTOR_BOUND_NO_FULL256_W11_BOUND_FAILURE"


class O1C54ScreenError(RuntimeError):
    """The frozen Full256-first factor-bound screen boundary was violated."""


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise O1C54ScreenError(f"{field} differs")
    return value


def _integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise O1C54ScreenError(f"{field} differs")
    return value


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _json_bytes(path: Path, expected_sha256: str, field: str) -> dict[str, object]:
    try:
        payload = path.read_bytes()
        value = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise O1C54ScreenError(f"{field} differs") from exc
    if _sha256_bytes(payload) != expected_sha256 or not isinstance(value, dict):
        raise O1C54ScreenError(f"{field} differs")
    return value


def _commit_bound_bytes(
    root: Path, commit: str, path: Path, payload: bytes, field: str
) -> None:
    try:
        relative = path.relative_to(root).as_posix()
        completed = subprocess.run(
            ["git", "show", f"{commit}:{relative}"],
            cwd=root,
            check=True,
            capture_output=True,
        )
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        raise O1C54ScreenError(f"{field} is not bound to source commit") from exc
    if completed.stdout != payload:
        raise O1C54ScreenError(f"{field} differs from source commit")


def _peak_rss_bytes() -> int:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(peak if sys.platform == "darwin" else peak * 1024)


def _pair_bytes(pairs: Sequence[tuple[int, int]]) -> bytes:
    return "".join(f"{left} {right}\n" for left, right in pairs).encode("ascii")


def complete_pair_order(
    frozen_pairs: Sequence[tuple[int, int]],
) -> tuple[tuple[int, int], ...]:
    """Append the 130 unused key variables in ascending deterministic pairs."""

    normalized: list[tuple[int, int]] = []
    for pair in frozen_pairs:
        if len(pair) != 2:
            raise O1C54ScreenError("frozen O1C-0048 pair order differs")
        normalized.append((pair[0], pair[1]))
    pairs = tuple(normalized)
    flattened = tuple(variable for pair in pairs for variable in pair)
    if (
        len(pairs) != FROZEN_PAIR_COUNT
        or len(flattened) != 2 * FROZEN_PAIR_COUNT
        or len(set(flattened)) != len(flattened)
        or any(variable not in range(1, 257) for variable in flattened)
        or _sha256_bytes(_pair_bytes(pairs)) != EXPECTED_PRIMARY_PAIR_ORDER_SHA256
    ):
        raise O1C54ScreenError("frozen O1C-0048 pair order differs")
    remaining = tuple(sorted(set(range(1, 257)).difference(flattened)))
    completion = tuple(zip(remaining[::2], remaining[1::2], strict=True))
    complete = pairs + completion
    all_variables = tuple(variable for pair in complete for variable in pair)
    if (
        len(remaining) != 130
        or len(completion) != COMPLETION_PAIR_COUNT
        or len(complete) != PAIR_COUNT
        or all_variables != tuple(dict.fromkeys(all_variables))
        or set(all_variables) != set(range(1, 257))
    ):
        raise O1C54ScreenError("complete pair order differs")
    return complete


def validate_o1c47_boundary(result: Mapping[str, object]) -> dict[str, object]:
    """Validate the exact W12 rank-five fact and unchanged score provenance."""

    rank = _mapping(result.get("rank"), "O1C47.rank")
    width12 = _mapping(rank.get("12"), "O1C47.rank.12")
    primary = _mapping(width12.get("primary"), "O1C47.rank.12.primary")
    architecture = _mapping(result.get("architecture"), "O1C47.architecture")
    potential_sha = _mapping(
        architecture.get("potential_sha256"), "O1C47.potential_sha256"
    )
    source_sha = _mapping(result.get("source_sha256"), "O1C47.source_sha256")
    target = _mapping(result.get("target"), "O1C47.target")
    truth_checks = _mapping(
        architecture.get("truth_score_checks"), "O1C47.truth_score_checks"
    )
    truth_primary = _mapping(truth_checks.get("primary"), "O1C47.truth.primary")
    if (
        result.get("schema") != "o1-256-global-criticality-residual-beam-result-v1"
        or result.get("attempt_id") != "O1C-0047"
        or architecture.get("score_mode")
        != "complete-forward-assignment-global-potential"
        or primary.get("candidate_count") != 4096
        or primary.get("deterministic_rank") != 5
        or primary.get("strict_rank") != 5
        or primary.get("top16") is not True
        or potential_sha.get("primary") != EXPECTED_PRIMARY_POTENTIAL_SHA256
        or source_sha.get("primary_potential") != EXPECTED_PRIMARY_POTENTIAL_SHA256
        or truth_primary.get("actual") != primary.get("truth_score")
        or target.get("public_view_sha256") != EXPECTED_PUBLIC_VIEW_SHA256
        or target.get("truth_key_sha256") != EXPECTED_TRUTH_KEY_SHA256
    ):
        raise O1C54ScreenError("frozen O1C-0047 W12 boundary differs")
    residual = architecture.get("residual_variables")
    if not isinstance(residual, list) or residual[:11] != list(EXPECTED_W11_VARIABLES):
        raise O1C54ScreenError("frozen O1C-0047 W11 coordinates differ")
    return {
        "primary_w12_candidate_count": 4096,
        "primary_w12_deterministic_truth_rank": 5,
        "primary_w12_strict_truth_rank": 5,
        "primary_truth_score": primary["truth_score"],
        "primary_potential_sha256": EXPECTED_PRIMARY_POTENTIAL_SHA256,
        "score_mode": architecture["score_mode"],
        "w11_variables": list(EXPECTED_W11_VARIABLES),
    }


def validate_o1c53_boundary(result: Mapping[str, object]) -> dict[str, object]:
    """Bind O1C54 to the immediately preceding consumed-target boundary."""

    target = _mapping(result.get("target"), "O1C53.target")
    ledger = _mapping(result.get("call_ledger"), "O1C53.call_ledger")
    if (
        result.get("schema") != "o1-256-deepest-survivor-support-screen-result-v1"
        or result.get("attempt_id") != "O1C-0053"
        or result.get("classification") != "SURVIVOR_SUPPORT_NO_EXACT_W11_CLOSE"
        or ledger.get("native_solver_calls") != 1
        or target.get("target_id") != "o1c-0044-fresh-0000"
        or target.get("public_view_sha256") != EXPECTED_PUBLIC_VIEW_SHA256
        or target.get("truth_key_sha256") != EXPECTED_TRUTH_KEY_SHA256
    ):
        raise O1C54ScreenError("frozen O1C-0053 boundary differs")
    return {
        "classification": result["classification"],
        "native_solver_calls": 1,
        "public_view_sha256": target["public_view_sha256"],
        "truth_key_sha256": target["truth_key_sha256"],
    }


def classify_result(
    *,
    full256_public_recovery: bool,
    w11_public_recovery: bool,
    w11_top5_complete: bool,
) -> str:
    """Classify only exact public recovery or the frozen W11 top-five outcome."""

    if not all(
        isinstance(value, bool)
        for value in (
            full256_public_recovery,
            w11_public_recovery,
            w11_top5_complete,
        )
    ):
        raise O1C54ScreenError("classification inputs differ")
    if full256_public_recovery:
        return FULL256_RECOVERY_CLASSIFICATION
    if w11_public_recovery and w11_top5_complete:
        return W11_TOP5_CLASSIFICATION
    if w11_public_recovery:
        return W11_INCOMPLETE_RECOVERY_CLASSIFICATION
    return W11_BOUND_FAILURE_CLASSIFICATION


class _PostFull256Gate:
    """Prevent every reveal/consumed-truth read until Full256 has executed."""

    def __init__(self) -> None:
        self._full256_receipt: str | None = None
        self._reads = 0

    def seal(self, receipt_sha256: str) -> None:
        if (
            self._full256_receipt is not None
            or not isinstance(receipt_sha256, str)
            or len(receipt_sha256) != 64
            or any(character not in "0123456789abcdef" for character in receipt_sha256)
        ):
            raise O1C54ScreenError("Full256 execution receipt differs")
        self._full256_receipt = receipt_sha256

    def read_json(
        self, path: Path, expected_sha256: str, field: str
    ) -> dict[str, object]:
        if self._full256_receipt is None:
            raise O1C54ScreenError("post-Full256 source read attempted before Full256")
        self._reads += 1
        return _json_bytes(path, expected_sha256, field)

    def describe(self) -> dict[str, object]:
        return {
            "full256_executed_before_post_reveal_reads": (
                self._full256_receipt is not None
            ),
            "full256_execution_receipt_sha256": self._full256_receipt,
            "post_full256_reads": self._reads,
        }


def _key_integer(key: bytes) -> int:
    if not isinstance(key, bytes) or len(key) != 32:
        raise O1C54ScreenError("key bytes differ")
    return sum(int(bit) << index for index, bit in enumerate(key_bits(key)))


def _key_from_integer(value: int) -> bytes:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value < 1 << 256
    ):
        raise O1C54ScreenError("candidate key integer differs")
    return value.to_bytes(32, "little")


def post_reveal_beam_diagnostics(
    *,
    retained_masks_by_stage: Sequence[Sequence[int]],
    pair_order: Sequence[tuple[int, int]],
    final_candidates: Sequence[int],
    truth_key: bytes,
) -> dict[str, object]:
    """Measure truth-prefix survival only after the public Full256 beam froze."""

    pairs = tuple(pair_order)
    stages = tuple(tuple(stage) for stage in retained_masks_by_stage)
    candidates = tuple(final_candidates)
    if len(pairs) != PAIR_COUNT or len(stages) != PAIR_COUNT or not candidates:
        raise O1C54ScreenError("Full256 retained-stage ledger differs")
    truth = _key_integer(truth_key)
    assigned = 0
    survival: list[dict[str, object]] = []
    first_lost_stage: int | None = None
    first_lost_pair: tuple[int, int] | None = None
    for stage_index, (pair, retained) in enumerate(zip(pairs, stages, strict=True), 1):
        if not retained or len(retained) > FULL256_BEAM_WIDTH:
            raise O1C54ScreenError("Full256 retained beam width differs")
        assigned |= 1 << (pair[0] - 1)
        assigned |= 1 << (pair[1] - 1)
        truth_prefix = truth & assigned
        survives = any(
            isinstance(mask, int)
            and not isinstance(mask, bool)
            and 0 <= mask < 1 << 256
            and mask & assigned == truth_prefix
            for mask in retained
        )
        if not survives and first_lost_stage is None:
            first_lost_stage = stage_index
            first_lost_pair = pair
        survival.append(
            {
                "stage": stage_index,
                "pair": list(pair),
                "retained": len(retained),
                "truth_prefix_survives": survives,
            }
        )
    if any(
        isinstance(candidate, bool)
        or not isinstance(candidate, int)
        or not 0 <= candidate < 1 << 256
        for candidate in candidates
    ):
        raise O1C54ScreenError("Full256 final candidate differs")
    hamming = tuple((candidate ^ truth).bit_count() for candidate in candidates)
    return {
        "truth_prefix_survival": survival,
        "truth_prefix_survived_every_stage": first_lost_stage is None,
        "first_lost_stage": first_lost_stage,
        "first_lost_pair": (None if first_lost_pair is None else list(first_lost_pair)),
        "final_beam_candidates": len(candidates),
        "final_beam_truth_present": truth in candidates,
        "final_beam_top_hamming": hamming[0],
        "final_beam_minimum_hamming": min(hamming),
        "final_beam_hamming_sha256": _sha256_bytes(
            "".join(f"{value}\n" for value in hamming).encode("ascii")
        ),
    }


@dataclass(frozen=True)
class _PublicFull256Outcome:
    final_candidates: tuple[int, ...]
    retained_masks_by_stage: tuple[tuple[int, ...], ...]
    public_match_indices: tuple[int, ...]
    core: Mapping[str, object]


@dataclass(frozen=True)
class _W11Outcome:
    certified_candidates: tuple[int, ...]
    completed_top5: bool
    public_match_indices: tuple[int, ...]
    core: Mapping[str, object]


@dataclass(frozen=True)
class _PublicInputs:
    root: Path
    public: PublicTargetView
    publication_sha256: str
    primary_potential_payload: bytes
    primary_potential_sha256: str
    semantic_map_path: Path
    pair_order: tuple[tuple[int, int], ...]
    source_commit: str
    source_sha256: Mapping[str, str]
    reveal_path: Path
    reveal_sha256: str
    o1c47_path: Path


@dataclass(frozen=True)
class _PostRevealInputs:
    truth_key: bytes
    reveal: Mapping[str, object]
    o1c47_boundary: Mapping[str, object]
    o1c53_boundary: Mapping[str, object]


def _canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")
    return _sha256_bytes(payload)


def _prepare_public_inputs(config_path: str | Path) -> _PublicInputs:
    """Read only public/frozen implementation inputs before Full256 execution."""

    root = lab_root().resolve(strict=True)
    config_file = Path(config_path).resolve(strict=True)
    if not config_file.is_relative_to(root):
        raise O1C54ScreenError("O1C-0048 config escapes lab")
    try:
        config_payload = config_file.read_bytes()
        config = load_o1c48_config(config_file)
    except (OSError, ValueError, RuntimeError) as exc:
        raise O1C54ScreenError("frozen O1C-0048 config differs") from exc
    source = _mapping(config.get("source"), "config.source")
    expected = _mapping(source.get("expected_sha256"), "config.expected_sha256")
    source_names = (
        "publication",
        "semantic_map",
        "field",
        "reveal",
        "o1c47_result",
        "primary_potential",
        "pair_group_source",
    )
    paths = {
        name: _relative_path(root, source.get(name), f"config.source.{name}")
        for name in source_names
    }
    if paths["o1c47_result"] != (root / O1C47_RESULT).resolve(strict=True):
        raise O1C54ScreenError("O1C-0047 result path differs")
    public_payload = paths["publication"].read_bytes()
    semantic_map_payload = paths["semantic_map"].read_bytes()
    field_payload = paths["field"].read_bytes()
    potential_payload = paths["primary_potential"].read_bytes()
    pair_source_payload = paths["pair_group_source"].read_bytes()
    public_hash = _sha256_bytes(public_payload)
    semantic_map_hash = _sha256_bytes(semantic_map_payload)
    field_hash = _sha256_bytes(field_payload)
    potential_hash = _sha256_bytes(potential_payload)
    pair_source_hash = _sha256_bytes(pair_source_payload)
    if (
        public_hash != expected.get("publication")
        or semantic_map_hash != expected.get("semantic_map")
        or field_hash != expected.get("field")
        or potential_hash != expected.get("primary_potential")
        or potential_hash != EXPECTED_PRIMARY_POTENTIAL_SHA256
        or pair_source_hash != expected.get("pair_group_source")
        or expected.get("reveal") != EXPECTED_REVEAL_SHA256
        or expected.get("o1c47_result") != O1C47_RESULT_SHA256
    ):
        raise O1C54ScreenError("frozen public source hash differs")
    try:
        publication_value = json.loads(public_payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C54ScreenError("public target JSON differs") from exc
    public = public_view_from_publication(publication_value)
    if public.digest() != EXPECTED_PUBLIC_VIEW_SHA256:
        raise O1C54ScreenError("public target identity differs")
    natural = ParentCriticalityField.from_bytes(field_payload)
    potential = CriticalityPotentialField.from_bytes(potential_payload)
    frozen_plan = compile_primary_pair_groups(natural, potential)
    pairs = complete_pair_order(frozen_plan.groups)
    if compile_pair_order(frozen_plan.ordered_variables) != pairs:
        raise O1C54ScreenError("core and runner complete pair orders differ")

    core_path = (root / CORE_SOURCE).resolve(strict=True)
    runner_path = (root / RUNNER_SOURCE).resolve(strict=True)
    core_payload = core_path.read_bytes()
    runner_payload = runner_path.read_bytes()
    source_commit = _git_commit(root)
    _commit_bound_bytes(root, source_commit, config_file, config_payload, "config")
    _commit_bound_bytes(root, source_commit, core_path, core_payload, "core")
    _commit_bound_bytes(root, source_commit, runner_path, runner_payload, "runner")
    reveal_sha = expected.get("reveal")
    if not isinstance(reveal_sha, str) or reveal_sha != EXPECTED_REVEAL_SHA256:
        raise O1C54ScreenError("reveal hash contract differs")
    return _PublicInputs(
        root=root,
        public=public,
        publication_sha256=public_hash,
        primary_potential_payload=potential_payload,
        primary_potential_sha256=potential_hash,
        semantic_map_path=paths["semantic_map"],
        pair_order=pairs,
        source_commit=source_commit,
        source_sha256={
            "config": _sha256_bytes(config_payload),
            "publication": public_hash,
            "semantic_map": semantic_map_hash,
            "field": field_hash,
            "primary_potential": potential_hash,
            "pair_group_source": pair_source_hash,
            "core": _sha256_bytes(core_payload),
            "runner": _sha256_bytes(runner_payload),
        },
        reveal_path=paths["reveal"],
        reveal_sha256=reveal_sha,
        o1c47_path=paths["o1c47_result"],
    )


def _read_post_reveal_inputs(
    public_inputs: _PublicInputs, gate: _PostFull256Gate
) -> _PostRevealInputs:
    """Open target truth and consumed truth-bearing results only after Full256."""

    reveal = gate.read_json(
        public_inputs.reveal_path, public_inputs.reveal_sha256, "reveal"
    )
    o1c47 = gate.read_json(
        public_inputs.o1c47_path, O1C47_RESULT_SHA256, "O1C47 result"
    )
    o1c53 = gate.read_json(
        public_inputs.root / O1C53_RESULT, O1C53_RESULT_SHA256, "O1C53 result"
    )
    verified_reveal = verify_reveal(reveal)
    preimage = _mapping(
        verified_reveal.get("commitment_preimage"), "reveal.commitment_preimage"
    )
    try:
        truth_key = bytes.fromhex(str(preimage.get("key_hex")))
    except ValueError as exc:
        raise O1C54ScreenError("revealed key encoding differs") from exc
    if (
        len(truth_key) != 32
        or hashlib.sha256(truth_key).hexdigest() != EXPECTED_TRUTH_KEY_SHA256
        or preimage.get("public_view_sha256") != public_inputs.public.digest()
    ):
        raise O1C54ScreenError("revealed key does not verify frozen public target")
    return _PostRevealInputs(
        truth_key=truth_key,
        reveal=verified_reveal,
        o1c47_boundary=validate_o1c47_boundary(o1c47),
        o1c53_boundary=validate_o1c53_boundary(o1c53),
    )


def _fixed_w11_spins(truth_key: bytes) -> dict[int, int]:
    bits = tuple(int(value) for value in key_bits(truth_key))
    residual = set(EXPECTED_W11_VARIABLES)
    fixed = {
        variable: (1 if bits[variable - 1] else -1)
        for variable in range(1, 257)
        if variable not in residual
    }
    if len(fixed) != 245:
        raise O1C54ScreenError("W11 fixed truth prefix differs")
    return fixed


# The adapters isolate the core API so its data layout cannot drift the
# Full256-before-reveal lifecycle in ``run``.
def _execute_public_full256(
    *,
    potential_payload: bytes,
    pair_order: Sequence[tuple[int, int]],
    public: PublicTargetView,
    semantic_map_path: Path,
) -> _PublicFull256Outcome:
    """Local adapter from frozen lab artifacts to the truth-free core API."""

    potential = CriticalityPotentialField.from_bytes(potential_payload)
    index = compile_factor_bound_index(potential)
    pairs = tuple(pair_order)
    forward_plan = compile_full256_forward_read_plan(
        semantic_map_path, potential.observed_variables
    )

    def evaluate_exact(candidate: bytes) -> float:
        assignment = forward_plan.evaluate(
            key=candidate,
            counter=public.counter_schedule[0],
            nonce=public.nonce,
        )
        return score_potential_assignment(potential, assignment)

    result = run_full256_bound_beam(
        index,
        pairs,
        evaluate_exact,
        lambda candidate: model_matches_public(candidate, public),
        width=FULL256_BEAM_WIDTH,
    )
    if result.pairs != pairs:
        raise O1C54ScreenError("Full256 core pair order differs")
    description = result.describe()
    core = {
        **description,
        "stage_count": len(result.stages),
        "maximum_retained_nodes": max(stage.retained_count for stage in result.stages),
        "conditional_factor_bound_index": index.describe(),
        "forward_plan": {
            "requested_variables": len(forward_plan.requested_variables),
            "semantic_sha256": forward_plan.semantic_sha256,
            "operations": len(forward_plan.operations),
        },
    }
    return _PublicFull256Outcome(
        final_candidates=tuple(
            int.from_bytes(candidate.key, "little") for candidate in result.candidates
        ),
        retained_masks_by_stage=result.retained_masks_by_stage,
        public_match_indices=tuple(
            index
            for index, candidate in enumerate(result.candidates)
            if candidate.publicly_verified
        ),
        core=core,
    )


def _execute_w11(
    *,
    potential_payload: bytes,
    pair_order: Sequence[tuple[int, int]],
    fixed_spins: Mapping[int, int],
    public: PublicTargetView,
    semantic_map_path: Path,
) -> _W11Outcome:
    """Run the separately bounded post-reveal certified W11 queue."""

    potential = CriticalityPotentialField.from_bytes(potential_payload)
    index = compile_factor_bound_index(potential)
    if len(tuple(pair_order)) != PAIR_COUNT:
        raise O1C54ScreenError("W11 pair provenance differs")
    forward_plan = compile_full256_forward_read_plan(
        semantic_map_path, potential.observed_variables
    )

    def evaluate_exact(candidate: bytes) -> float:
        assignment = forward_plan.evaluate(
            key=candidate,
            counter=public.counter_schedule[0],
            nonce=public.nonce,
        )
        return score_potential_assignment(potential, assignment)

    result = run_certified_bound_queue(
        index,
        EXPECTED_W11_VARIABLES,
        dict(fixed_spins),
        evaluate_exact,
        lambda candidate: model_matches_public(candidate, public),
        target_leaves=W11_CERTIFIED_LEAVES,
        maximum_unscored_pops=W11_MAXIMUM_UNSCORED_POPS,
        maximum_forward_evaluations=W11_MAXIMUM_FORWARD_EVALUATIONS,
        maximum_live_nodes=W11_MAXIMUM_LIVE_NODES,
        timeout_seconds=W11_TIMEOUT_SECONDS,
    )
    core = {
        **result.describe(),
        "conditional_factor_bound_index": index.describe(),
        "forward_plan": {
            "requested_variables": len(forward_plan.requested_variables),
            "semantic_sha256": forward_plan.semantic_sha256,
            "operations": len(forward_plan.operations),
        },
    }
    return _W11Outcome(
        certified_candidates=tuple(
            int.from_bytes(leaf.key, "little") for leaf in result.leaves
        ),
        completed_top5=result.completed,
        public_match_indices=tuple(
            index for index, leaf in enumerate(result.leaves) if leaf.publicly_verified
        ),
        core=core,
    )


def _validate_public_full256_outcome(
    outcome: _PublicFull256Outcome,
) -> dict[str, object]:
    core = _mapping(outcome.core, "Full256 core ledger")
    forward = _integer(core.get("forward_evaluations"), "Full256 forward evaluations")
    maximum_retained = _integer(
        core.get("maximum_retained_nodes"), "Full256 maximum retained nodes"
    )
    public_verifications = _integer(
        core.get("public_verifications"), "Full256 public verifications"
    )
    parent_expansions = _integer(
        core.get("parent_expansions"), "Full256 parent expansions"
    )
    child_bounds = _integer(
        core.get("child_bound_evaluations"), "Full256 child bound evaluations"
    )
    if (
        len(outcome.final_candidates) != FULL256_BEAM_WIDTH
        or len(set(outcome.final_candidates)) != FULL256_BEAM_WIDTH
        or len(outcome.retained_masks_by_stage) != PAIR_COUNT
        or core.get("beam_width") != FULL256_BEAM_WIDTH
        or core.get("pair_count") != PAIR_COUNT
        or core.get("stage_count") != PAIR_COUNT
        or forward != FULL256_BEAM_WIDTH
        or public_verifications != FULL256_BEAM_WIDTH
        or parent_expansions != 31829
        or child_bounds != 127316
        or maximum_retained != FULL256_BEAM_WIDTH
        or tuple(len(stage) for stage in outcome.retained_masks_by_stage[:4])
        != (4, 16, 64, 256)
        or any(
            len(stage) != FULL256_BEAM_WIDTH
            for stage in outcome.retained_masks_by_stage[4:]
        )
        or any(
            isinstance(index, bool)
            or not isinstance(index, int)
            or not 0 <= index < len(outcome.final_candidates)
            for index in outcome.public_match_indices
        )
        or len(set(outcome.public_match_indices)) != len(outcome.public_match_indices)
    ):
        raise O1C54ScreenError("Full256 core work ledger differs")
    return {
        **dict(core),
        "forward_evaluations": forward,
        "public_verifications": public_verifications,
        "parent_expansions": parent_expansions,
        "child_bound_evaluations": child_bounds,
        "maximum_retained_nodes": maximum_retained,
    }


def _validate_w11_outcome(outcome: _W11Outcome) -> dict[str, object]:
    core = _mapping(outcome.core, "W11 core ledger")
    pops = _integer(core.get("unscored_pops"), "W11 unscored pops")
    forward = _integer(core.get("forward_evaluations"), "W11 forward evaluations")
    public_verifications = _integer(
        core.get("public_verifications"), "W11 public verifications"
    )
    live = _integer(core.get("maximum_live_nodes"), "W11 maximum live nodes")
    elapsed = core.get("elapsed_seconds")
    if (
        not isinstance(elapsed, (int, float))
        or isinstance(elapsed, bool)
        or not 0.0 <= float(elapsed) <= W11_TIMEOUT_SECONDS
        or not 0 <= pops <= W11_MAXIMUM_UNSCORED_POPS
        or not 0 <= forward <= W11_MAXIMUM_FORWARD_EVALUATIONS
        or public_verifications != forward
        or not 0 <= live <= W11_MAXIMUM_LIVE_NODES
        or core.get("residual_variables") != list(EXPECTED_W11_VARIABLES)
        or core.get("target_leaves") != W11_CERTIFIED_LEAVES
        or core.get("certified_leaves") != len(outcome.certified_candidates)
        or core.get("completed") is not outcome.completed_top5
        or len(outcome.certified_candidates) > W11_CERTIFIED_LEAVES
        or outcome.completed_top5
        != (len(outcome.certified_candidates) == W11_CERTIFIED_LEAVES)
        or any(
            isinstance(index, bool)
            or not isinstance(index, int)
            or not 0 <= index < len(outcome.certified_candidates)
            for index in outcome.public_match_indices
        )
        or len(set(outcome.public_match_indices)) != len(outcome.public_match_indices)
    ):
        raise O1C54ScreenError("W11 core work ledger differs")
    return {
        **dict(core),
        "unscored_pops": pops,
        "forward_evaluations": forward,
        "public_verifications": public_verifications,
        "maximum_live_nodes": live,
        "elapsed_seconds": float(elapsed),
    }


def run(
    config_path: str | Path = DEFAULT_CONFIG,
    *,
    output_path: str | Path = RESULT_RELATIVE,
) -> dict[str, object]:
    """Execute Full256 unconditionally, then open reveal and run W11 diagnostics."""

    root = lab_root().resolve(strict=True)
    output = (root / Path(output_path)).resolve()
    authoritative = (root / RESULT_RELATIVE).resolve()
    if output != authoritative or output.exists():
        raise O1C54ScreenError("authoritative result path differs or already exists")
    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    cpu_started = time.process_time()
    public_inputs = _prepare_public_inputs(config_path)

    # Non-negotiable lifecycle: this is the first efficacy call and the reveal gate
    # has no receipt with which to authorize a truth-bearing read yet.
    reveal_gate = _PostFull256Gate()
    full256_started = time.perf_counter()
    full256 = _execute_public_full256(
        potential_payload=public_inputs.primary_potential_payload,
        pair_order=public_inputs.pair_order,
        public=public_inputs.public,
        semantic_map_path=public_inputs.semantic_map_path,
    )
    full256_elapsed = time.perf_counter() - full256_started
    full256_core = _validate_public_full256_outcome(full256)
    full256_receipt = _canonical_sha256(
        {
            "attempt_id": ATTEMPT_ID,
            "phase": "attacker-valid-public-full256",
            "source_commit": public_inputs.source_commit,
            "pair_order_sha256": _sha256_bytes(_pair_bytes(public_inputs.pair_order)),
            "final_candidates_sha256": _sha256_bytes(
                b"".join(
                    candidate.to_bytes(32, "little")
                    for candidate in full256.final_candidates
                )
            ),
            "retained_stage_sha256": _canonical_sha256(
                [list(stage) for stage in full256.retained_masks_by_stage]
            ),
            "public_match_indices": list(full256.public_match_indices),
            "core": full256_core,
        }
    )
    reveal_gate.seal(full256_receipt)

    post = _read_post_reveal_inputs(public_inputs, reveal_gate)
    full256_diagnostic = post_reveal_beam_diagnostics(
        retained_masks_by_stage=full256.retained_masks_by_stage,
        pair_order=public_inputs.pair_order,
        final_candidates=full256.final_candidates,
        truth_key=post.truth_key,
    )
    public_match_models = tuple(
        _key_from_integer(full256.final_candidates[index])
        for index in full256.public_match_indices
    )
    truth_integer = _key_integer(post.truth_key)
    if any(_key_integer(model) != truth_integer for model in public_match_models):
        raise O1C54ScreenError("Full256 public match differs from revealed truth")

    # W11 is a separate post-reveal diagnostic and can neither authorize nor
    # suppress the already-completed Full256 execution.
    w11_started = time.perf_counter()
    w11 = _execute_w11(
        potential_payload=public_inputs.primary_potential_payload,
        pair_order=public_inputs.pair_order,
        fixed_spins=_fixed_w11_spins(post.truth_key),
        public=public_inputs.public,
        semantic_map_path=public_inputs.semantic_map_path,
    )
    w11_adapter_elapsed = time.perf_counter() - w11_started
    w11_core = _validate_w11_outcome(w11)
    w11_models = tuple(_key_from_integer(value) for value in w11.certified_candidates)
    w11_public_matches = w11.public_match_indices
    if any(
        _key_integer(w11_models[index]) != truth_integer for index in w11_public_matches
    ):
        raise O1C54ScreenError("W11 public match differs from revealed truth")
    full256_recovery = bool(full256.public_match_indices)
    w11_public_recovery = bool(w11_public_matches)
    classification = classify_result(
        full256_public_recovery=full256_recovery,
        w11_public_recovery=w11_public_recovery,
        w11_top5_complete=w11.completed_top5,
    )
    forward_evaluations = _integer(
        full256_core["forward_evaluations"], "Full256 final forward evaluations"
    ) + _integer(w11_core["forward_evaluations"], "W11 final forward evaluations")
    public_verifications = _integer(
        full256_core["public_verifications"], "Full256 final public verifications"
    ) + _integer(w11_core["public_verifications"], "W11 final public verifications")
    peak_rss = _peak_rss_bytes()
    elapsed = time.perf_counter() - started
    cpu_seconds = time.process_time() - cpu_started
    if (
        forward_evaluations > MAXIMUM_FORWARD_EVALUATIONS
        or public_verifications > MAXIMUM_FORWARD_EVALUATIONS
        or peak_rss > MAXIMUM_PEAK_RSS_BYTES
    ):
        raise O1C54ScreenError("whole-run resource ledger exceeded")

    pair_order_sha = _sha256_bytes(_pair_bytes(public_inputs.pair_order))
    result: dict[str, object] = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "started_at": started_at,
        "source_commit": public_inputs.source_commit,
        "classification": classification,
        "claim_level": (
            "ATTACKER_VALID_PUBLIC_FULL256_RECOVERY"
            if full256_recovery
            else "CONSUMED_POST_REVEAL_GLOBAL_BOUND_SCREEN"
        ),
        "baseline_sha256": {
            "O1C-0047": O1C47_RESULT_SHA256,
            "O1C-0053": O1C53_RESULT_SHA256,
        },
        "boundary": {
            "attacker_valid_full256_executed_first": True,
            "full256_unconditional": True,
            "full256_public_only": True,
            "reveal_key_or_prefix_entered_full256_core": False,
            "w11_post_reveal_only": True,
            "w11_authorized_or_suppressed_full256": False,
            "rotations": 0,
            "sweeps": 0,
            "parameter_tuning": 0,
            "native_solver_calls": 0,
            "fresh_targets": 0,
            "sibling_reads": 0,
            "sibling_writes": 0,
            "MPS_or_GPU": False,
            **reveal_gate.describe(),
        },
        "architecture": {
            "primary_potential_sha256": public_inputs.primary_potential_sha256,
            "frozen_o1c48_pair_count": FROZEN_PAIR_COUNT,
            "ascending_completion_pair_count": COMPLETION_PAIR_COUNT,
            "pair_count": PAIR_COUNT,
            "pair_order_sha256": pair_order_sha,
            "full256_beam_width": FULL256_BEAM_WIDTH,
            "w11_variables": list(EXPECTED_W11_VARIABLES),
            "w11_truth_fixed_bits": 245,
            "o1c47_boundary": dict(post.o1c47_boundary),
            "o1c53_boundary": dict(post.o1c53_boundary),
        },
        "call_ledger": {
            "executed_calls": [
                {
                    "ordinal": 1,
                    "phase": "attacker-valid-public-full256",
                    "authorization": "unconditional-first-call",
                    "truth_bearing_inputs": 0,
                    "beam_width": FULL256_BEAM_WIDTH,
                    "forward_evaluations": full256_core["forward_evaluations"],
                    "public_verifications": full256_core["public_verifications"],
                    "elapsed_seconds": full256_elapsed,
                },
                {
                    "ordinal": 2,
                    "phase": "post-reveal-w11-diagnostic",
                    "authorization": "unconditional-after-full256",
                    "truth_fixed_bits": 245,
                    "certified_leaf_limit": W11_CERTIFIED_LEAVES,
                    "forward_evaluations": w11_core["forward_evaluations"],
                    "public_verifications": w11_core["public_verifications"],
                    "elapsed_seconds": w11_adapter_elapsed,
                },
            ],
            "full256_calls": 1,
            "post_reveal_w11_calls": 1,
            "native_solver_calls": 0,
            "rotation_calls": 0,
            "tuning_calls": 0,
            "forward_evaluations": forward_evaluations,
            "maximum_forward_evaluations": MAXIMUM_FORWARD_EVALUATIONS,
            "public_verifications": public_verifications,
            "maximum_public_verifications": MAXIMUM_FORWARD_EVALUATIONS,
        },
        "attacker_valid_full256": {
            "executed_before_reveal": True,
            "execution_receipt_sha256": full256_receipt,
            "public_recovery": full256_recovery,
            "public_match_indices": list(full256.public_match_indices),
            "public_match_model_sha256": [
                hashlib.sha256(model).hexdigest() for model in public_match_models
            ],
            "elapsed_seconds": full256_elapsed,
            "final_beam_sha256": _sha256_bytes(
                b"".join(
                    candidate.to_bytes(32, "little")
                    for candidate in full256.final_candidates
                )
            ),
            "core": full256_core,
        },
        "post_reveal_full256_diagnostic": full256_diagnostic,
        "post_reveal_w11": {
            "completed_certified_top5": w11.completed_top5,
            "certified_candidates": len(w11.certified_candidates),
            "public_recovery": w11_public_recovery,
            "public_match_indices": list(w11_public_matches),
            "public_match_model_sha256": [
                hashlib.sha256(w11_models[index]).hexdigest()
                for index in w11_public_matches
            ],
            "truth_rank_within_certified_leaves": next(
                (
                    index + 1
                    for index, candidate in enumerate(w11.certified_candidates)
                    if candidate == truth_integer
                ),
                None,
            ),
            "core": w11_core,
            "adapter_elapsed_seconds": w11_adapter_elapsed,
        },
        "target": {
            "target_id": "o1c-0044-fresh-0000",
            "public_view_sha256": public_inputs.public.digest(),
            "truth_key_sha256": hashlib.sha256(post.truth_key).hexdigest(),
            "consumed_target": True,
        },
        "resources": {
            "elapsed_seconds": elapsed,
            "cpu_seconds": cpu_seconds,
            "peak_rss_bytes": peak_rss,
            "maximum_peak_rss_bytes": MAXIMUM_PEAK_RSS_BYTES,
            "forward_evaluations": forward_evaluations,
            "maximum_forward_evaluations": MAXIMUM_FORWARD_EVALUATIONS,
            "public_verifications": public_verifications,
            "maximum_public_verifications": MAXIMUM_FORWARD_EVALUATIONS,
            "post_reveal_truth_public_verifications": 1,
            "native_solver_calls": 0,
            "fresh_targets": 0,
            "sibling_reads": 0,
            "sibling_writes": 0,
            "MPS_or_GPU": False,
        },
        "source_sha256": {
            **dict(public_inputs.source_sha256),
            "reveal": public_inputs.reveal_sha256,
            "o1c47_result": O1C47_RESULT_SHA256,
            "o1c53_result": O1C53_RESULT_SHA256,
        },
    }
    # Recheck the hard lifecycle/resource invariants before the sole atomic write.
    boundary = _mapping(result["boundary"], "result.boundary")
    if (
        boundary.get("attacker_valid_full256_executed_first") is not True
        or boundary.get("reveal_key_or_prefix_entered_full256_core") is not False
        or boundary.get("w11_authorized_or_suppressed_full256") is not False
        or result["classification"] != classification
    ):
        raise O1C54ScreenError("final lifecycle ledger differs")
    _atomic_json(output, result)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--output", default=str(RESULT_RELATIVE))
    arguments = parser.parse_args(argv)
    result = run(arguments.config, output_path=arguments.output)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
