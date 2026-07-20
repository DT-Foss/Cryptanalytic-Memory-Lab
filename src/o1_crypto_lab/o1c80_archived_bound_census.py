"""Reproducible, target-free O1C-0080 archived one-bit bound census.

The exact population in this module is deliberately narrow: immutable terminal
v6-compatible states whose assignment and group-cache bytes were archived.
O1C-0079 proposal markers are reported separately as a monotone lower envelope.
They are not solver-state snapshots because most backtrack targets were never
serialized.  No solver, science, reveal, refit, target, or truth-key call is
made here.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import math
import os
import stat
import struct
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence, cast

from .causal_attic_v1 import canonical_json_bytes
from .criticality_potential import (
    CriticalityPotentialError,
    CriticalityPotentialField,
)
from .joint_score_grouping_v1 import (
    COMPATIBILITY_GROUPING_BOUND_RULE,
    JointScoreCompatibilityGroup,
    JointScoreCompatibilityGrouping,
    JointScoreGroupingError,
    _binary64_scaled_integer,
    _scaled_integer_to_upward_binary64,
)
from .joint_score_sieve_v7 import (
    APPLE_VIEW_0009_GROUPING_SHA256,
    APPLE_VIEW_0009_POTENTIAL_SHA256,
    _decode_state,
    grouped_joint_score_cache,
    joint_score_upper_bound,
    validate_joint_score_sieve_grouping,
)
from .o1_relational_search import O1RelationalSearchError


ATTEMPT_ID = "O1C-0080"
CENSUS_SCHEMA = "o1-256-o1c80-archived-one-bit-bound-census-v1"
THRESHOLD = 14.606178797892962
THRESHOLD_F64LE_HEX = "2ef540115d362d40"
KEY_VARIABLES = tuple(range(1, 257))
MISSING_KEY_VARIABLES = (241,)
POTENTIAL_SOURCE_SHA256 = (
    "b0ef8533128cbfdbb618c46b686bff0bc20f6b2389251b1ae5a2109729d34f26"
)
OBSERVED_VARIABLES_SHA256 = (
    "86b80faf204a81015a16e14ce695f3becdb6b06967b5a987c1537d03711e9fc5"
)

POTENTIAL_RELATIVE = Path(
    "runs/20260719_095509_APPLE-VIEW-0008-MATCHED_"
    "crossblock-consequence-sieve-v1/artifacts/potential/"
    "primary-eight-block.potential"
)
POTENTIAL_BYTES = 2_263_844
GROUPING_RELATIVE = Path(
    "runs/20260719_123602_O1C-0065_apple8-width6-grouped-sieve-v1/"
    "apple9-width6.grouping"
)
GROUPING_BYTES = 115_700

O1C79_CENTRAL_READER_RELATIVE = Path(
    "runs/20260720_085738_O1C-0079_apple8-decision-ownership-v1/"
    "episodes/00/central-reader.json.gz"
)
O1C79_OWNERSHIP_RELATIVE = Path(
    "runs/20260720_085738_O1C-0079_apple8-decision-ownership-v1/"
    "episodes/00/decision-ownership.json.gz"
)


class O1C80ArchivedBoundCensusError(ValueError):
    """A sealed input, reconstructed state, or exact bound differs."""


@dataclass(frozen=True)
class SealedJsonSpec:
    """Byte identity for one immutable JSON or canonical-gzip input."""

    label: str
    relative: Path
    result_schema: str
    compressed: bool
    file_bytes: int
    file_sha256: str
    raw_bytes: int
    raw_sha256: str


ARCHIVED_SNAPSHOT_SPECS = (
    SealedJsonSpec(
        "O1C-0065/terminal",
        Path(
            "runs/20260719_123602_O1C-0065_apple8-width6-grouped-sieve-v1/"
            "native_result.json"
        ),
        "o1-256-cadical-joint-score-sieve-result-v5",
        False,
        63_654,
        "f55bc10cad54e8c7847776c2e7fa2ea34101abce21435af8542ebc2abd2e542b",
        63_654,
        "f55bc10cad54e8c7847776c2e7fa2ea34101abce21435af8542ebc2abd2e542b",
    ),
    SealedJsonSpec(
        "O1C-0066/episode-00/terminal",
        Path(
            "runs/20260719_135856_O1C-0066_apple8-episodic-vault-v1/"
            "episodes/00/native_result.json"
        ),
        "o1-256-cadical-joint-score-sieve-result-v6",
        False,
        387_548,
        "8597288b7daa976e09efc42bcd368c2dae572179b1a73b129e5fcbdccb6a82b2",
        387_548,
        "8597288b7daa976e09efc42bcd368c2dae572179b1a73b129e5fcbdccb6a82b2",
    ),
    SealedJsonSpec(
        "O1C-0066/episode-01/terminal",
        Path(
            "runs/20260719_135856_O1C-0066_apple8-episodic-vault-v1/"
            "episodes/01/native_result.json"
        ),
        "o1-256-cadical-joint-score-sieve-result-v6",
        False,
        463_645,
        "efa67c4200fb96975a788aecb6113322e48ae2bbd3667c45d07708eb333467f8",
        463_645,
        "efa67c4200fb96975a788aecb6113322e48ae2bbd3667c45d07708eb333467f8",
    ),
    SealedJsonSpec(
        "O1C-0067/episode-00/terminal",
        Path(
            "runs/20260719_152601_O1C-0067_apple8-vault-continuation-v1/"
            "episodes/00/native_result.json"
        ),
        "o1-256-cadical-joint-score-sieve-result-v6",
        False,
        125_888,
        "31881074b35ae3cd7819c3fb0b54c862bd9c3dcd3de256c7d218522088bdd55d",
        125_888,
        "31881074b35ae3cd7819c3fb0b54c862bd9c3dcd3de256c7d218522088bdd55d",
    ),
    SealedJsonSpec(
        "O1C-0068/episode-00/terminal",
        Path(
            "runs/20260719_161838_O1C-0068_apple8-complementary-phase-v1/"
            "episodes/00/native_result.json"
        ),
        "o1-256-cadical-joint-score-sieve-result-v7",
        False,
        10_443_297,
        "599e03fd433e4d9743bc2d0588ed03137e859de45147b0c5a55064c4885d9738",
        10_443_297,
        "599e03fd433e4d9743bc2d0588ed03137e859de45147b0c5a55064c4885d9738",
    ),
    SealedJsonSpec(
        "O1C-0069/episode-00/terminal",
        Path(
            "runs/20260719_170824_O1C-0069_apple8-alternating-reader-v1/"
            "episodes/00/native_result.json"
        ),
        "o1-256-cadical-joint-score-sieve-result-v8",
        False,
        126_382,
        "f71bf359625904e7d8367f0861710751fe3ba8c29fe47549cfbde38641752172",
        126_382,
        "f71bf359625904e7d8367f0861710751fe3ba8c29fe47549cfbde38641752172",
    ),
    SealedJsonSpec(
        "O1C-0070/episode-00/terminal",
        Path(
            "runs/20260719_181048_O1C-0070_apple8-vault-phase-reader-v1/"
            "episodes/00/native_result.json"
        ),
        "o1-256-cadical-joint-score-sieve-result-v9",
        False,
        65_881,
        "9955174a65e7c27d9d69074af01eddeeea8e3ced7b3fafa316e93e4e8f3580f0",
        65_881,
        "9955174a65e7c27d9d69074af01eddeeea8e3ced7b3fafa316e93e4e8f3580f0",
    ),
    SealedJsonSpec(
        "O1C-0071/episode-00/terminal",
        Path(
            "runs/20260719_192742_O1C-0071_apple8-vault-ranked-decision-v1/"
            "episodes/00/native_result.json"
        ),
        "o1-256-cadical-joint-score-sieve-result-v10",
        False,
        119_884,
        "783611cf8819a5412c34de9aa8b827ccbfc9381bdd9785d586ae4baa1046798a",
        119_884,
        "783611cf8819a5412c34de9aa8b827ccbfc9381bdd9785d586ae4baa1046798a",
    ),
    SealedJsonSpec(
        "O1C-0072/episode-00/terminal",
        Path(
            "runs/20260719_204421_O1C-0072_apple8-vault-backtrack-release-v1/"
            "episodes/00/native_result.json"
        ),
        "o1-256-cadical-joint-score-sieve-result-v11",
        False,
        94_472,
        "0ea7584d7cac1a7e365bcebe638f3e23526532e83da129d01af4bfc6f9b5d0cf",
        94_472,
        "0ea7584d7cac1a7e365bcebe638f3e23526532e83da129d01af4bfc6f9b5d0cf",
    ),
    SealedJsonSpec(
        "O1C-0073/episode-00/terminal",
        Path(
            "runs/20260719_215617_O1C-0073_apple8-vault-release-contrast-v1/"
            "episodes/00/native_result.json"
        ),
        "o1-256-cadical-joint-score-sieve-result-v12",
        False,
        15_052_684,
        "bf5f0ce2f72b9d86b5bb6a7fa08e44f777a0980c0bbbd2e0ed9aaa1bca20410a",
        15_052_684,
        "bf5f0ce2f72b9d86b5bb6a7fa08e44f777a0980c0bbbd2e0ed9aaa1bca20410a",
    ),
    SealedJsonSpec(
        "O1C-0074/episode-00/terminal",
        Path(
            "runs/20260719_231823_O1C-0074_apple8-causal-attic-stream-v1/"
            "episodes/00/native-result.json.gz"
        ),
        "o1-256-cadical-joint-score-sieve-result-v13",
        True,
        47_779,
        "71234ac78b3cde63fc4d17a8d12a5077456f5ff7595c46bfb20ec4120779f3f9",
        365_836,
        "5d471fce454575b94b52b35b10cbf4f6342bfa5d4220dc25a6478f1cda959af2",
    ),
    SealedJsonSpec(
        "O1C-0074/episode-01/terminal",
        Path(
            "runs/20260719_231823_O1C-0074_apple8-causal-attic-stream-v1/"
            "episodes/01/native-result.json.gz"
        ),
        "o1-256-cadical-joint-score-sieve-result-v13",
        True,
        57_563,
        "86c1907fef8613b0a2f7876d82849c6aa55a8408c1bd8aaaa803bb5975b5f80a",
        908_622,
        "1d23f9bbc40a35af44a8853bf9b2ba510a7dcd6ca9e75de69a2d96bc0cf8da58",
    ),
    SealedJsonSpec(
        "O1C-0074/episode-02/terminal",
        Path(
            "runs/20260719_231823_O1C-0074_apple8-causal-attic-stream-v1/"
            "episodes/02/native-result.json.gz"
        ),
        "o1-256-cadical-joint-score-sieve-result-v13",
        True,
        37_888,
        "5049cb36ea52eb41f077ef5962fb7bd8fb0e6c575b451cd18a8f4077f8ad2d13",
        245_933,
        "c2d418ffb2b70702f149b577309e1a7fafda64aa0e29f4bb295397be4b5e86e1",
    ),
    SealedJsonSpec(
        "O1C-0074/episode-03/terminal",
        Path(
            "runs/20260719_231823_O1C-0074_apple8-causal-attic-stream-v1/"
            "episodes/03/native-result.json.gz"
        ),
        "o1-256-cadical-joint-score-sieve-result-v13",
        True,
        37_888,
        "15dff32a1d705470dbd812dba13b03e52476e21bf4007118aedd28af704305ac",
        245_933,
        "2b43b2f84c90d3292eef0c0934b1804737cd404d71e67940c0e42b0c2d8b5692",
    ),
    SealedJsonSpec(
        "O1C-0075/episode-00/terminal",
        Path(
            "runs/20260720_002724_O1C-0075_apple8-causal-residency-stream-v1/"
            "episodes/00/native-result.json.gz"
        ),
        "o1-256-cadical-joint-score-sieve-result-v13",
        True,
        37_886,
        "cd7c513ab73900287a13d960af1f2566936a8f51924408a71f0c67fc97e2cd3c",
        245_933,
        "524c5aa6e75cbddbb49dc0eb9ad028f9372ed5e098f8509de3967dc1f49b729e",
    ),
    SealedJsonSpec(
        "O1C-0075/episode-01/terminal",
        Path(
            "runs/20260720_002724_O1C-0075_apple8-causal-residency-stream-v1/"
            "episodes/01/native-result.json.gz"
        ),
        "o1-256-cadical-joint-score-sieve-result-v13",
        True,
        37_884,
        "d377c552e60b96a01479012e2c6eee536550a8b9839f1957f17f605b0ada149e",
        245_933,
        "b1f97d0735f1704dbef8e634b7df57e1c65b895b3a0da10da13a6eea72aa1ed5",
    ),
    SealedJsonSpec(
        "O1C-0076/episode-00/terminal",
        Path(
            "runs/20260720_013632_O1C-0076_apple8-causal-frontier-v1/"
            "episodes/00/native-result.json.gz"
        ),
        "o1-256-cadical-joint-score-sieve-result-v14",
        True,
        39_569,
        "0ca67f629bfc62f62d3705c74f3fef44aff3d5e4646048798a7006c722d02658",
        252_812,
        "5cee812cc99b824b43b345f20b2eed253a09090a69866de2f3c4fa074c95e198",
    ),
    SealedJsonSpec(
        "O1C-0077/episode-00/terminal",
        Path(
            "runs/20260720_025550_O1C-0077_apple8-residual-polarity-staging-v1/"
            "episodes/00/native-result.json.gz"
        ),
        "o1-256-cadical-joint-score-sieve-result-v15",
        True,
        41_134,
        "e13e98d14af49978a8afaeebb36d4d854f21f92ffa29efcbec323e7a20ec5a15",
        361_499,
        "8980046510cd80417260436d73fdbe3cb24da6d233e136aff616972f92aadfd0",
    ),
    SealedJsonSpec(
        "O1C-0079/episode-00/terminal",
        Path(
            "runs/20260720_085738_O1C-0079_apple8-decision-ownership-v1/"
            "episodes/00/native-result.json.gz"
        ),
        "o1-256-cadical-joint-score-sieve-result-v17",
        True,
        159_220,
        "ec75d6c336d9dbfeb243f9992f624c8c3a71cdb0b1322bc0a713076911aa0f65",
        1_928_031,
        "acda128d4a4ebc32376de7fce3ef40de72e20539befebe56eaea4276a43fd283",
    ),
)

CENTRAL_READER_SPEC = SealedJsonSpec(
    "O1C-0079/central-reader",
    O1C79_CENTRAL_READER_RELATIVE,
    "o1-256-central-composed-reader-v1",
    True,
    11_627,
    "0e2b017a52199ab5e0150d5302f5f195b88bdb1006189674482c93bc00a03a4d",
    64_879,
    "dab5a338d2f6f46c00af114c23989b15a4f81c015db73ba0283a3a375c018f31",
)

OWNERSHIP_SPEC = SealedJsonSpec(
    "O1C-0079/decision-ownership",
    O1C79_OWNERSHIP_RELATIVE,
    "o1-256-central-decision-ownership-v1",
    True,
    132_920,
    "6403d8a674a5c563eb8e30fdcaabb5745122654a234dd1cb0b2ef77f90de34e3",
    1_791_935,
    "87e6476486fa02624fab9b6b6f84c00dded60fbcefef871475201439849d4a0b",
)


@dataclass(frozen=True)
class PublicBoundInputs:
    field: CriticalityPotentialField
    grouping: JointScoreCompatibilityGrouping
    incidents: Mapping[int, tuple[int, ...]]


@dataclass(frozen=True)
class ArchivedParentState:
    label: str
    assignment_sha256: str
    group_cache_sha256: str
    persistent_sha256: str
    assignments: Mapping[int, int]
    maxima: tuple[float, ...]
    parent_upper_bound: float


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _f64le_hex(value: float) -> str:
    if not math.isfinite(value):
        raise O1C80ArchivedBoundCensusError("bound is not finite")
    return struct.pack("<d", value).hex()


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise O1C80ArchivedBoundCensusError(f"{field} differs")
    return cast(Mapping[str, object], value)


def _sequence(value: object, field: str) -> Sequence[object]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise O1C80ArchivedBoundCensusError(f"{field} differs")
    return cast(Sequence[object], value)


def _integer(value: object, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise O1C80ArchivedBoundCensusError(f"{field} differs")
    return value


def _regular_file(path: Path, field: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise O1C80ArchivedBoundCensusError(f"{field} is unreadable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise O1C80ArchivedBoundCensusError(
            f"{field} is not a sealed regular file"
        )
    return path


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise O1C80ArchivedBoundCensusError("JSON contains a duplicate key")
        result[key] = value
    return result


def _read_json_payload(root: Path, spec: SealedJsonSpec) -> Mapping[str, object]:
    path = _regular_file(root / spec.relative, spec.label)
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise O1C80ArchivedBoundCensusError(f"{spec.label} is unreadable") from exc
    if len(payload) != spec.file_bytes or _sha256(payload) != spec.file_sha256:
        raise O1C80ArchivedBoundCensusError(f"{spec.label} file digest differs")
    if spec.compressed:
        try:
            raw = gzip.decompress(payload)
        except (EOFError, OSError) as exc:
            raise O1C80ArchivedBoundCensusError(
                f"{spec.label} gzip differs"
            ) from exc
    else:
        raw = payload
    if len(raw) != spec.raw_bytes or _sha256(raw) != spec.raw_sha256:
        raise O1C80ArchivedBoundCensusError(f"{spec.label} raw digest differs")
    try:
        document = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(
                O1C80ArchivedBoundCensusError("JSON contains a non-finite number")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C80ArchivedBoundCensusError(f"{spec.label} JSON differs") from exc
    parsed = _mapping(document, spec.label)
    if parsed.get("schema") != spec.result_schema:
        raise O1C80ArchivedBoundCensusError(f"{spec.label} schema differs")
    return parsed


def load_public_bound_inputs(root: str | Path | None = None) -> PublicBoundInputs:
    """Load and byte-validate the frozen potential and deterministic grouping."""

    base = lab_root() if root is None else Path(root)
    potential_path = _regular_file(base / POTENTIAL_RELATIVE, "public potential")
    grouping_path = _regular_file(base / GROUPING_RELATIVE, "width-6 grouping")
    try:
        potential_payload = potential_path.read_bytes()
        grouping_payload = grouping_path.read_bytes()
    except OSError as exc:
        raise O1C80ArchivedBoundCensusError("public bound input is unreadable") from exc
    if (
        len(potential_payload) != POTENTIAL_BYTES
        or _sha256(potential_payload) != APPLE_VIEW_0009_POTENTIAL_SHA256
        or len(grouping_payload) != GROUPING_BYTES
        or _sha256(grouping_payload) != APPLE_VIEW_0009_GROUPING_SHA256
    ):
        raise O1C80ArchivedBoundCensusError("public bound input digest differs")
    try:
        field = CriticalityPotentialField.from_bytes(potential_payload)
        grouping = validate_joint_score_sieve_grouping(field, grouping_payload)
    except (CriticalityPotentialError, JointScoreGroupingError, O1RelationalSearchError) as exc:
        raise O1C80ArchivedBoundCensusError("public bound input differs") from exc
    observed = field.observed_variables
    observed_payload = b"".join(struct.pack("<I", variable) for variable in observed)
    if (
        field.to_bytes() != potential_payload
        or field.state_sha256 != APPLE_VIEW_0009_POTENTIAL_SHA256
        or field.source_sha256 != POTENTIAL_SOURCE_SHA256
        or len(field.factors) != 7_557
        or len(observed) != 2_981
        or _sha256(observed_payload) != OBSERVED_VARIABLES_SHA256
        or tuple(variable for variable in KEY_VARIABLES if variable not in observed)
        != MISSING_KEY_VARIABLES
        or grouping.width_cap != 6
        or grouping.group_count != 2_885
        or grouping.table_rows != 176_912
        or grouping.variable_group_incidences != 17_025
        or grouping.serialized != grouping_payload
    ):
        raise O1C80ArchivedBoundCensusError("public bound shape differs")
    incidents: dict[int, list[int]] = {variable: [] for variable in observed}
    for group_index, group in enumerate(grouping.groups):
        for variable in group.variables:
            incidents[variable].append(group_index)
    if any(not group_indices for group_indices in incidents.values()):
        raise O1C80ArchivedBoundCensusError("group incident index differs")
    return PublicBoundInputs(
        field=field,
        grouping=grouping,
        incidents={
            variable: tuple(group_indices)
            for variable, group_indices in incidents.items()
        },
    )


@dataclass(frozen=True)
class OneBitBounds:
    u0: float
    u1: float
    incident_group_count: int
    incident_row_evaluations: int


def _group_maximum(
    group: JointScoreCompatibilityGroup, assignments: Mapping[int, int]
) -> float:
    best = -math.inf
    for row, energy in enumerate(group.energies):
        consistent = True
        for local, variable in enumerate(group.variables):
            spin = assignments.get(variable)
            if spin is not None and bool(row & (1 << local)) != (spin > 0):
                consistent = False
                break
        if consistent and energy > best:
            best = energy
    if best == -math.inf:
        raise O1C80ArchivedBoundCensusError("group maximum has no consistent row")
    return best


def _group_child_maxima(
    group: JointScoreCompatibilityGroup,
    assignments: Mapping[int, int],
    variable: int,
) -> tuple[float, float]:
    try:
        variable_local = group.variables.index(variable)
    except ValueError as exc:
        raise O1C80ArchivedBoundCensusError("incident group index differs") from exc
    best0 = -math.inf
    best1 = -math.inf
    for row, energy in enumerate(group.energies):
        consistent = True
        for local, group_variable in enumerate(group.variables):
            if group_variable == variable:
                continue
            spin = assignments.get(group_variable)
            if spin is not None and bool(row & (1 << local)) != (spin > 0):
                consistent = False
                break
        if not consistent:
            continue
        if row & (1 << variable_local):
            best1 = max(best1, energy)
        else:
            best0 = max(best0, energy)
    if best0 == -math.inf or best1 == -math.inf:
        raise O1C80ArchivedBoundCensusError(
            "one-bit child group maximum has no consistent row"
        )
    return best0, best1


def _exact_total(field: CriticalityPotentialField, maxima: Sequence[float]) -> int:
    if any(not math.isfinite(maximum) for maximum in maxima):
        raise O1C80ArchivedBoundCensusError("group cache contains a non-finite value")
    return _binary64_scaled_integer(field.offset) + sum(
        _binary64_scaled_integer(maximum) for maximum in maxima
    )


def _bound_from_exact_total(total: int) -> float:
    value = _scaled_integer_to_upward_binary64(total)
    if not math.isfinite(value):
        raise O1C80ArchivedBoundCensusError("exact bound is not finite")
    return value


def _child_bounds_from_validated_cache(
    inputs: PublicBoundInputs,
    assignments: Mapping[int, int],
    maxima: Sequence[float],
    parent_exact_total: int,
    variable: int,
) -> OneBitBounds:
    if (
        variable not in KEY_VARIABLES
        or variable not in inputs.incidents
        or variable in assignments
        or len(maxima) != inputs.grouping.group_count
    ):
        raise O1C80ArchivedBoundCensusError("one-bit child input differs")
    total0 = parent_exact_total
    total1 = parent_exact_total
    row_evaluations = 0
    group_indices = inputs.incidents[variable]
    for group_index in group_indices:
        group = inputs.grouping.groups[group_index]
        best0, best1 = _group_child_maxima(group, assignments, variable)
        old_scaled = _binary64_scaled_integer(maxima[group_index])
        total0 += _binary64_scaled_integer(best0) - old_scaled
        total1 += _binary64_scaled_integer(best1) - old_scaled
        row_evaluations += len(group.energies)
    return OneBitBounds(
        u0=_bound_from_exact_total(total0),
        u1=_bound_from_exact_total(total1),
        incident_group_count=len(group_indices),
        incident_row_evaluations=row_evaluations,
    )


def exact_one_bit_child_bounds(
    inputs: PublicBoundInputs,
    assignments: Mapping[int, int],
    parent_cache: bytes,
    variable: int,
    *,
    verify_full_scan: bool = True,
) -> OneBitBounds:
    """Evaluate one exact key pair after validating the supplied parent cache."""

    try:
        expected_cache = grouped_joint_score_cache(
            inputs.field, assignments, grouping=inputs.grouping
        )
    except O1RelationalSearchError as exc:
        raise O1C80ArchivedBoundCensusError("parent assignment differs") from exc
    if not isinstance(parent_cache, bytes) or parent_cache != expected_cache:
        raise O1C80ArchivedBoundCensusError("parent group cache differs")
    maxima = tuple(value for (value,) in struct.iter_unpack("<d", parent_cache))
    result = _child_bounds_from_validated_cache(
        inputs,
        assignments,
        maxima,
        _exact_total(inputs.field, maxima),
        variable,
    )
    if verify_full_scan:
        child0 = dict(assignments)
        child1 = dict(assignments)
        child0[variable] = -1
        child1[variable] = 1
        full0 = joint_score_upper_bound(
            inputs.field, child0, grouping=inputs.grouping
        )
        full1 = joint_score_upper_bound(
            inputs.field, child1, grouping=inputs.grouping
        )
        if _f64le_hex(result.u0) != _f64le_hex(full0) or _f64le_hex(
            result.u1
        ) != _f64le_hex(full1):
            raise O1C80ArchivedBoundCensusError(
                "incident-cache and full-scan child bounds differ"
            )
    return result


_SIEVE_IDENTITY = {
    "source_sha256": POTENTIAL_SOURCE_SHA256,
    "grouping_sha256": APPLE_VIEW_0009_GROUPING_SHA256,
    "grouping_input_sha256": APPLE_VIEW_0009_GROUPING_SHA256,
    "observed_variables": 2_981,
    "observed_variables_sha256": OBSERVED_VARIABLES_SHA256,
    "group_count": 2_885,
    "group_table_rows": 176_912,
    "group_incident_edges": 17_025,
    "bound_rule": COMPATIBILITY_GROUPING_BOUND_RULE,
    "threshold": THRESHOLD,
    "pending_clause_count": 0,
    "root_upper_bound": 262.68644197084643,
    "root_upper_bound_f64le_hex": "327693aafb6a7040",
}


def _validate_snapshot_document(
    document: Mapping[str, object],
    spec: SealedJsonSpec,
    inputs: PublicBoundInputs,
) -> ArchivedParentState:
    if (
        document.get("schema") != spec.result_schema
        or document.get("potential_sha256") != APPLE_VIEW_0009_POTENTIAL_SHA256
        or document.get("threshold") != THRESHOLD
    ):
        raise O1C80ArchivedBoundCensusError(f"{spec.label} bound identity differs")
    sieve = _mapping(document.get("sieve"), f"{spec.label}.sieve")
    if any(sieve.get(name) != value for name, value in _SIEVE_IDENTITY.items()):
        raise O1C80ArchivedBoundCensusError(f"{spec.label} sieve identity differs")
    try:
        decoded = _decode_state(
            sieve.get("state"),
            field=inputs.field,
            grouping=inputs.grouping,
            pending_clause_count=0,
        )
    except O1RelationalSearchError as exc:
        raise O1C80ArchivedBoundCensusError(
            f"{spec.label} terminal state differs"
        ) from exc
    try:
        assignment_bytes = bytes.fromhex(cast(str, decoded["assignment_hex"]))
        cache_bytes = bytes.fromhex(cast(str, decoded["group_cache_hex"]))
    except (TypeError, ValueError) as exc:
        raise O1C80ArchivedBoundCensusError(
            f"{spec.label} terminal encoding differs"
        ) from exc
    assignments = {
        variable: 1 if assignment_bytes[local] == 1 else -1
        for local, variable in enumerate(inputs.field.observed_variables)
        if assignment_bytes[local] != 0
    }
    maxima = tuple(value for (value,) in struct.iter_unpack("<d", cache_bytes))
    parent_upper = _bound_from_exact_total(_exact_total(inputs.field, maxima))
    full_parent = joint_score_upper_bound(
        inputs.field, assignments, grouping=inputs.grouping
    )
    if _f64le_hex(parent_upper) != _f64le_hex(full_parent):
        raise O1C80ArchivedBoundCensusError(
            f"{spec.label} cached and full parent bounds differ"
        )
    return ArchivedParentState(
        label=spec.label,
        assignment_sha256=cast(str, decoded["assignment_sha256"]),
        group_cache_sha256=cast(str, decoded["group_cache_sha256"]),
        persistent_sha256=cast(str, decoded["persistent_sha256"]),
        assignments=assignments,
        maxima=maxima,
        parent_upper_bound=parent_upper,
    )


def _load_archived_parents(
    root: Path, inputs: PublicBoundInputs
) -> tuple[
    tuple[ArchivedParentState, ...],
    Mapping[str, tuple[str, ...]],
    list[dict[str, object]],
]:
    unique: dict[str, ArchivedParentState] = {}
    labels: dict[str, list[str]] = {}
    input_rows: list[dict[str, object]] = []
    for spec in ARCHIVED_SNAPSHOT_SPECS:
        document = _read_json_payload(root, spec)
        parent = _validate_snapshot_document(document, spec, inputs)
        prior = unique.get(parent.assignment_sha256)
        if prior is None:
            unique[parent.assignment_sha256] = parent
            labels[parent.assignment_sha256] = [spec.label]
        else:
            if (
                dict(prior.assignments) != dict(parent.assignments)
                or prior.maxima != parent.maxima
                or prior.group_cache_sha256 != parent.group_cache_sha256
                or prior.persistent_sha256 != parent.persistent_sha256
            ):
                raise O1C80ArchivedBoundCensusError(
                    "duplicate terminal assignment state differs"
                )
            labels[parent.assignment_sha256].append(spec.label)
        input_rows.append(
            {
                "compression": "gzip" if spec.compressed else "none",
                "file_bytes": spec.file_bytes,
                "file_sha256": spec.file_sha256,
                "label": spec.label,
                "raw_bytes": spec.raw_bytes,
                "raw_sha256": spec.raw_sha256,
                "relative_path": spec.relative.as_posix(),
                "result_schema": spec.result_schema,
                "terminal_assignment_sha256": parent.assignment_sha256,
                "terminal_group_cache_sha256": parent.group_cache_sha256,
            }
        )
    if len(ARCHIVED_SNAPSHOT_SPECS) != 19 or len(unique) != 13:
        raise O1C80ArchivedBoundCensusError("terminal census population differs")
    return (
        tuple(unique.values()),
        {digest: tuple(values) for digest, values in labels.items()},
        input_rows,
    )


def _pair_record(
    *,
    parent_identity: str,
    parent_upper: float,
    variable: int,
    bounds: OneBitBounds,
    extra: Mapping[str, object] | None = None,
) -> dict[str, object]:
    prunable0 = bounds.u0 < THRESHOLD
    prunable1 = bounds.u1 < THRESHOLD
    minimum_bit = 0 if bounds.u0 <= bounds.u1 else 1
    minimum_child = bounds.u0 if minimum_bit == 0 else bounds.u1
    row: dict[str, object] = {
        "both_children_strict_prunable": prunable0 and prunable1,
        "crosses_strict_threshold": prunable0 != prunable1,
        "incident_group_count": bounds.incident_group_count,
        "incident_row_evaluations": bounds.incident_row_evaluations,
        "minimum_child_bit": minimum_bit,
        "minimum_child_margin_above_threshold": minimum_child - THRESHOLD,
        "minimum_child_upper_bound": minimum_child,
        "minimum_child_upper_bound_f64le_hex": _f64le_hex(minimum_child),
        "parent_identity": parent_identity,
        "parent_to_minimum_child_drop": parent_upper - minimum_child,
        "parent_upper_bound": parent_upper,
        "parent_upper_bound_f64le_hex": _f64le_hex(parent_upper),
        "u0": bounds.u0,
        "u0_f64le_hex": _f64le_hex(bounds.u0),
        "u1": bounds.u1,
        "u1_f64le_hex": _f64le_hex(bounds.u1),
        "variable": variable,
    }
    if extra is not None:
        row.update(extra)
    return row


def _terminal_census(
    inputs: PublicBoundInputs,
    parents: Sequence[ArchivedParentState],
    aliases: Mapping[str, tuple[str, ...]],
) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    parent_rows: list[dict[str, object]] = []
    incident_groups = 0
    incident_row_evaluations = 0
    crossing_count = 0
    both_prunable_count = 0
    full_scan_child_bound_count = 0
    closest: dict[str, object] | None = None
    closest_key: tuple[float, str, int] | None = None
    for parent in parents:
        parent_exact = _exact_total(inputs.field, parent.maxima)
        eligible = [
            variable
            for variable in KEY_VARIABLES
            if variable in inputs.incidents and variable not in parent.assignments
        ]
        parent_closest: dict[str, object] | None = None
        for variable in eligible:
            bounds = _child_bounds_from_validated_cache(
                inputs,
                parent.assignments,
                parent.maxima,
                parent_exact,
                variable,
            )
            row = _pair_record(
                parent_identity=parent.assignment_sha256,
                parent_upper=parent.parent_upper_bound,
                variable=variable,
                bounds=bounds,
            )
            rows.append(row)
            incident_groups += bounds.incident_group_count
            incident_row_evaluations += bounds.incident_row_evaluations
            crossing_count += int(cast(bool, row["crosses_strict_threshold"]))
            both_prunable_count += int(
                cast(bool, row["both_children_strict_prunable"])
            )
            key = (
                cast(float, row["minimum_child_upper_bound"]),
                parent.assignment_sha256,
                variable,
            )
            if closest_key is None or key < closest_key:
                closest_key = key
                closest = row
            if parent_closest is None or cast(
                float, row["minimum_child_upper_bound"]
            ) < cast(float, parent_closest["minimum_child_upper_bound"]):
                parent_closest = row
        if parent_closest is not None:
            _validate_extreme_full_scan(inputs, parent.assignments, parent_closest)
            full_scan_child_bound_count += 2
        parent_rows.append(
            {
                "archive_labels": list(aliases[parent.assignment_sha256]),
                "assigned_observed_variables": len(parent.assignments),
                "eligible_unassigned_observed_key_variables": len(eligible),
                "group_cache_sha256": parent.group_cache_sha256,
                "parent_assignment_sha256": parent.assignment_sha256,
                "parent_upper_bound": parent.parent_upper_bound,
                "parent_upper_bound_f64le_hex": _f64le_hex(
                    parent.parent_upper_bound
                ),
                "persistent_state_sha256": parent.persistent_sha256,
                "closest_child": parent_closest,
            }
        )
    if closest is None:
        raise O1C80ArchivedBoundCensusError("terminal census is empty")
    if (
        len(rows) != 1_580
        or crossing_count != 0
        or both_prunable_count != 0
        or closest["parent_identity"]
        != "013c0b079127aead78625330b4932e71c0efa4fdc8cf1758f1fd8605f29239d2"
        or closest["variable"] != 105
        or closest["parent_upper_bound_f64le_hex"] != "0bf2b0c9e60f2f40"
        or closest["u0_f64le_hex"] != "9907f485f9722e40"
        or closest["u1_f64le_hex"] != "573a81246aaf2d40"
    ):
        raise O1C80ArchivedBoundCensusError("terminal census result differs")
    ledger_payload = b"".join(canonical_json_bytes(row) for row in rows)
    return {
        "both_children_strict_prunable_pair_count": both_prunable_count,
        "child_bound_count": 2 * len(rows),
        "closest_child": closest,
        "crossing_pair_count": crossing_count,
        "exact_parent_population": True,
        "incident_cache_full_scan_equivalence": {
            "checked_child_bound_count": full_scan_child_bound_count,
            "checked_parent_bound_count": len(parents),
            "f64le_mismatch_count": 0,
            "scope": (
                "every-deduplicated terminal parent and both children of each "
                "parent's deterministic minimum-child pair; exhaustive child "
                "equivalence is covered by the finite fixture test"
            ),
        },
        "operation_counts": {
            "full_scan_child_group_row_evaluations": full_scan_child_bound_count
            * inputs.grouping.table_rows,
            "incident_child_group_recomputations": incident_groups,
            "incident_child_group_row_evaluations": incident_row_evaluations,
        },
        "pair_count": len(rows),
        "pair_ledger": rows,
        "pair_ledger_serialized_bytes": len(ledger_payload),
        "pair_ledger_sha256": _sha256(ledger_payload),
        "parent_count": len(parents),
        "parents": parent_rows,
        "snapshot_count": len(ARCHIVED_SNAPSHOT_SPECS),
        "strict_threshold_rule": "child-upper-bound < threshold; equality-is-live",
    }


_OWNERSHIP_EVENT_FIELDS = {
    "callback",
    "kind",
    "level",
    "literal",
    "observed_literal",
    "origin",
    "row",
    "sequence",
    "token",
}
_OWNERSHIP_EVENT_KINDS = {
    "CONFIRMED",
    "FOREIGN_ASSIGNMENT",
    "LEVEL_BOUND",
    "LEVEL_BOUND_UNOBSERVED_RELEASE",
    "PROPOSED",
    "RELEASED",
}
_ASSIGNMENT_EVENT_KINDS = {"CONFIRMED", "FOREIGN_ASSIGNMENT"}
_RELEASE_EVENT_KINDS = {"LEVEL_BOUND_UNOBSERVED_RELEASE", "RELEASED"}


def _decode_i32_sequence(
    document: Mapping[str, object], prefix: str, field: str
) -> tuple[int, ...]:
    encoding = document.get(f"{prefix}_encoding")
    count = _integer(document.get(f"{prefix}_count"), f"{field}.{prefix}_count")
    byte_count = _integer(
        document.get(f"{prefix}_bytes"), f"{field}.{prefix}_bytes"
    )
    encoded = document.get(f"{prefix}_hex")
    expected_sha = document.get(f"{prefix}_sha256")
    if (
        encoding != "concatenated-signed-i32le-literals"
        or not isinstance(encoded, str)
        or not isinstance(expected_sha, str)
        or len(expected_sha) != 64
    ):
        raise O1C80ArchivedBoundCensusError(f"{field}.{prefix} differs")
    try:
        payload = bytes.fromhex(encoded)
    except ValueError as exc:
        raise O1C80ArchivedBoundCensusError(f"{field}.{prefix} differs") from exc
    if (
        len(payload) != byte_count
        or byte_count != 4 * count
        or _sha256(payload) != expected_sha
    ):
        raise O1C80ArchivedBoundCensusError(f"{field}.{prefix} digest differs")
    return tuple(value for (value,) in struct.iter_unpack("<i", payload))


def _validate_o1c79_event_inputs(
    root: Path,
) -> tuple[
    Mapping[str, object],
    tuple[Mapping[str, object], ...],
    Mapping[str, object],
]:
    central = _read_json_payload(root, CENTRAL_READER_SPEC)
    ownership = _read_json_payload(root, OWNERSHIP_SPEC)
    native_spec = ARCHIVED_SNAPSHOT_SPECS[-1]
    native = _read_json_payload(root, native_spec)
    if (
        native.get("central_reader") != central
        or native.get("decision_ownership") != ownership
    ):
        raise O1C80ArchivedBoundCensusError("O1C-0079 embedded evidence differs")
    if (
        central.get("potential_sha256") != APPLE_VIEW_0009_POTENTIAL_SHA256
        or central.get("grouping_sha256") != APPLE_VIEW_0009_GROUPING_SHA256
        or central.get("callback_calls") != 1_587
        or central.get("nonzero_returns") != 549
        or central.get("zero_returns") != 1_038
        or central.get("assignment_literals_observed") != 10_453
    ):
        raise O1C80ArchivedBoundCensusError("O1C-0079 central-reader ledger differs")
    returned = _decode_i32_sequence(
        central, "returned_sequence", "O1C-0079 central reader"
    )
    proposed = _decode_i32_sequence(
        central, "proposal_sequence", "O1C-0079 central reader"
    )
    released = _decode_i32_sequence(
        central, "release_sequence", "O1C-0079 central reader"
    )
    if (
        len(returned) != 1_587
        or sum(literal == 0 for literal in returned) != 1_038
        or tuple(literal for literal in returned if literal != 0) != proposed
        or len(proposed) != 549
        or len(released) != 549
    ):
        raise O1C80ArchivedBoundCensusError("O1C-0079 return sequence differs")
    raw_events = _sequence(ownership.get("events"), "O1C-0079 ownership.events")
    events: list[Mapping[str, object]] = []
    kinds: Counter[str] = Counter()
    for expected_sequence, raw_event in enumerate(raw_events, start=1):
        event = _mapping(raw_event, "O1C-0079 ownership event")
        if set(event) != _OWNERSHIP_EVENT_FIELDS:
            raise O1C80ArchivedBoundCensusError(
                "O1C-0079 ownership event fields differ"
            )
        kind = event.get("kind")
        if not isinstance(kind, str) or kind not in _OWNERSHIP_EVENT_KINDS:
            raise O1C80ArchivedBoundCensusError(
                "O1C-0079 ownership event kind differs"
            )
        for name in ("callback", "level", "row", "sequence", "token"):
            _integer(event.get(name), f"O1C-0079 ownership event.{name}")
        for name in ("literal", "observed_literal"):
            value = event.get(name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise O1C80ArchivedBoundCensusError(
                    f"O1C-0079 ownership event.{name} differs"
                )
        if event["sequence"] != expected_sequence:
            raise O1C80ArchivedBoundCensusError(
                "O1C-0079 ownership event sequence differs"
            )
        events.append(event)
        kinds[kind] += 1
    if (
        ownership.get("event_count") != 12_160
        or ownership.get("recorded_event_count") != 12_160
        or ownership.get("omitted_event_count") != 0
        or len(events) != 12_160
        or kinds
        != Counter(
            {
                "CONFIRMED": 547,
                "FOREIGN_ASSIGNMENT": 9_966,
                "LEVEL_BOUND": 549,
                "LEVEL_BOUND_UNOBSERVED_RELEASE": 2,
                "PROPOSED": 549,
                "RELEASED": 547,
            }
        )
        or ownership.get("proposals") != 549
        or ownership.get("releases") != 549
        or ownership.get("foreign_assignments") != 9_966
        or ownership.get("confirmed_interventions") != 547
        or ownership.get("current_level") != 123
        or ownership.get("live_tokens") != 0
    ):
        raise O1C80ArchivedBoundCensusError("O1C-0079 ownership counters differ")
    proposal_events = tuple(event for event in events if event["kind"] == "PROPOSED")
    return_events = _sequence(
        central.get("return_events"), "O1C-0079 central return events"
    )
    if len(return_events) != len(proposal_events):
        raise O1C80ArchivedBoundCensusError("O1C-0079 proposal marker count differs")
    for proposal_event, raw_return in zip(proposal_events, return_events, strict=True):
        returned_event = _mapping(raw_return, "O1C-0079 return event")
        if returned_event != {
            "call": proposal_event["callback"],
            "literal": proposal_event["literal"],
            "origin": proposal_event["origin"],
            "row": proposal_event["row"],
            "token": proposal_event["token"],
        }:
            raise O1C80ArchivedBoundCensusError(
                "O1C-0079 proposal marker identity differs"
            )
    sieve = _mapping(native.get("sieve"), "O1C-0079 native sieve")
    stats = _mapping(native.get("stats"), "O1C-0079 native stats")
    if (
        stats.get("decisions") != 1_587
        or sieve.get("new_decision_levels") != 1_587
        or sieve.get("assignment_callbacks") != 1_227
        or sieve.get("assignment_literals") != 10_453
        or sieve.get("backtracks") != 138
        or sieve.get("backtracked_assignments") != 9_756
        or sieve.get("maximum_decision_level") != 331
    ):
        raise O1C80ArchivedBoundCensusError("O1C-0079 native counters differ")
    return central, tuple(events), native


class _VisibleEventReplay:
    def __init__(self, inputs: PublicBoundInputs) -> None:
        self.inputs = inputs
        self.assignments: dict[int, int] = {}
        self.levels: dict[int, int] = {}
        self.maxima = [max(group.energies) for group in inputs.grouping.groups]
        self.exact_total = _exact_total(inputs.field, self.maxima)
        self.group_recomputations = 0
        self.group_row_evaluations = 0
        root = _bound_from_exact_total(self.exact_total)
        full_root = joint_score_upper_bound(
            inputs.field, {}, grouping=inputs.grouping
        )
        if _f64le_hex(root) != "327693aafb6a7040" or _f64le_hex(
            root
        ) != _f64le_hex(full_root):
            raise O1C80ArchivedBoundCensusError("visible replay root differs")

    @property
    def upper_bound(self) -> float:
        return _bound_from_exact_total(self.exact_total)

    @property
    def cache_bytes(self) -> bytes:
        return b"".join(struct.pack("<d", value) for value in self.maxima)

    def _refresh(self, group_indices: Sequence[int]) -> None:
        for group_index in sorted(set(group_indices)):
            group = self.inputs.grouping.groups[group_index]
            old = self.maxima[group_index]
            new = _group_maximum(group, self.assignments)
            self.maxima[group_index] = new
            self.exact_total += _binary64_scaled_integer(
                new
            ) - _binary64_scaled_integer(old)
            self.group_recomputations += 1
            self.group_row_evaluations += len(group.energies)

    def notify_assignment(self, literal: int, level: int) -> None:
        variable = abs(literal)
        spin = 1 if literal > 0 else -1
        if variable not in self.inputs.incidents:
            raise O1C80ArchivedBoundCensusError(
                "ownership assignment is outside the observed potential"
            )
        if self.assignments.get(variable) == spin:
            return
        self.assignments[variable] = spin
        self.levels[variable] = level
        self._refresh(self.inputs.incidents[variable])

    def notify_visible_release(self, target_level: int) -> None:
        removed = [
            variable
            for variable, level in self.levels.items()
            if level > target_level
        ]
        affected = tuple(
            group_index
            for variable in removed
            for group_index in self.inputs.incidents[variable]
        )
        for variable in removed:
            del self.assignments[variable]
            del self.levels[variable]
        self._refresh(affected)

    def child_bounds(self, variable: int) -> OneBitBounds:
        return _child_bounds_from_validated_cache(
            self.inputs,
            self.assignments,
            self.maxima,
            self.exact_total,
            variable,
        )


def _validate_extreme_full_scan(
    inputs: PublicBoundInputs,
    assignments: Mapping[int, int],
    row: Mapping[str, object],
) -> None:
    cache = grouped_joint_score_cache(
        inputs.field, assignments, grouping=inputs.grouping
    )
    verified = exact_one_bit_child_bounds(
        inputs,
        assignments,
        cache,
        cast(int, row["variable"]),
        verify_full_scan=True,
    )
    parent_full = joint_score_upper_bound(
        inputs.field, assignments, grouping=inputs.grouping
    )
    if (
        _f64le_hex(parent_full) != row["parent_upper_bound_f64le_hex"]
        or _f64le_hex(verified.u0) != row["u0_f64le_hex"]
        or _f64le_hex(verified.u1) != row["u1_f64le_hex"]
    ):
        raise O1C80ArchivedBoundCensusError(
            "visible-envelope extreme full scan differs"
        )


def _visible_event_lower_envelope(
    root: Path,
    inputs: PublicBoundInputs,
    parents: Sequence[ArchivedParentState],
) -> dict[str, object]:
    central, events, native = _validate_o1c79_event_inputs(root)
    replay = _VisibleEventReplay(inputs)
    ledger_digest = hashlib.sha256()
    pair_count = 0
    crossing_count = 0
    both_prunable_count = 0
    proposal_count = 0
    release_batch_targets: list[int] = []
    in_release_batch = False
    closest: dict[str, object] | None = None
    closest_assignments: dict[int, int] | None = None
    closest_key: tuple[float, int, int] | None = None
    maximum_drop: dict[str, object] | None = None
    maximum_drop_assignments: dict[int, int] | None = None
    maximum_drop_key: tuple[float, int, int] | None = None
    child_incident_groups = 0
    child_incident_rows = 0
    for event in events:
        kind = cast(str, event["kind"])
        if kind in _ASSIGNMENT_EVENT_KINDS:
            replay.notify_assignment(
                cast(int, event["observed_literal"]), cast(int, event["level"])
            )
            in_release_batch = False
        elif kind in _RELEASE_EVENT_KINDS:
            target = cast(int, event["level"])
            if not in_release_batch:
                release_batch_targets.append(target)
            elif release_batch_targets[-1] != target:
                raise O1C80ArchivedBoundCensusError(
                    "ownership release batch target differs"
                )
            replay.notify_visible_release(target)
            in_release_batch = True
        elif kind == "PROPOSED":
            in_release_batch = False
            proposal_count += 1
            callback = cast(int, event["callback"])
            event_sequence = cast(int, event["sequence"])
            level = cast(int, event["level"])
            parent_upper = replay.upper_bound
            parent_identity = f"visible-event-callback-{callback:04d}"
            for variable in KEY_VARIABLES:
                if variable not in inputs.incidents or variable in replay.assignments:
                    continue
                bounds = replay.child_bounds(variable)
                row = _pair_record(
                    parent_identity=parent_identity,
                    parent_upper=parent_upper,
                    variable=variable,
                    bounds=bounds,
                    extra={
                        "assignment_count_in_visible_replay": len(replay.assignments),
                        "callback": callback,
                        "event_sequence": event_sequence,
                        "reported_level": level,
                    },
                )
                pair_count += 1
                child_incident_groups += bounds.incident_group_count
                child_incident_rows += bounds.incident_row_evaluations
                crossing_count += int(cast(bool, row["crosses_strict_threshold"]))
                both_prunable_count += int(
                    cast(bool, row["both_children_strict_prunable"])
                )
                ledger_digest.update(canonical_json_bytes(row))
                minimum = cast(float, row["minimum_child_upper_bound"])
                minimum_key = (minimum, callback, variable)
                if closest_key is None or minimum_key < closest_key:
                    closest_key = minimum_key
                    closest = row
                    closest_assignments = dict(replay.assignments)
                drop = cast(float, row["parent_to_minimum_child_drop"])
                drop_key = (drop, -callback, -variable)
                if maximum_drop_key is None or drop_key > maximum_drop_key:
                    maximum_drop_key = drop_key
                    maximum_drop = row
                    maximum_drop_assignments = dict(replay.assignments)
        else:
            in_release_batch = False
    terminal = next(
        (
            parent
            for parent in parents
            if parent.assignment_sha256
            == "8927fe918cde62299730a80921eaec484e96692df4728c8e7030266af9f3009d"
        ),
        None,
    )
    if terminal is None:
        raise O1C80ArchivedBoundCensusError("O1C-0079 terminal parent is absent")
    if (
        dict(terminal.assignments) != replay.assignments
        or terminal.maxima != tuple(replay.maxima)
        or terminal.group_cache_sha256 != _sha256(replay.cache_bytes)
    ):
        raise O1C80ArchivedBoundCensusError(
            "visible replay does not converge to the archived terminal state"
        )
    if (
        closest is None
        or closest_assignments is None
        or maximum_drop is None
        or maximum_drop_assignments is None
    ):
        raise O1C80ArchivedBoundCensusError("visible-event census is empty")
    _validate_extreme_full_scan(inputs, closest_assignments, closest)
    _validate_extreme_full_scan(inputs, maximum_drop_assignments, maximum_drop)
    sieve = _mapping(native.get("sieve"), "O1C-0079 native sieve")
    native_backtracks = cast(int, sieve["backtracks"])
    observed_result = {
        "both_prunable_count": both_prunable_count,
        "closest_callback": closest["callback"],
        "closest_level": closest["reported_level"],
        "closest_parent_hex": closest["parent_upper_bound_f64le_hex"],
        "closest_u0_hex": closest["u0_f64le_hex"],
        "closest_u1_hex": closest["u1_f64le_hex"],
        "closest_variable": closest["variable"],
        "crossing_count": crossing_count,
        "maximum_drop_callback": maximum_drop["callback"],
        "maximum_drop_parent_hex": maximum_drop["parent_upper_bound_f64le_hex"],
        "maximum_drop_u0_hex": maximum_drop["u0_f64le_hex"],
        "maximum_drop_u1_hex": maximum_drop["u1_f64le_hex"],
        "maximum_drop_variable": maximum_drop["variable"],
        "pair_count": pair_count,
        "proposal_count": proposal_count,
        "release_batch_count": len(release_batch_targets),
        "terminal_upper_hex": _f64le_hex(replay.upper_bound),
    }
    expected_result = {
        "both_prunable_count": 0,
        "closest_callback": 667,
        "closest_level": 253,
        "closest_parent_hex": "e34e2e097f674040",
        "closest_u0_hex": "c7e8e244286d3d40",
        "closest_u1_hex": "f7410720155c3f40",
        "closest_variable": 158,
        "crossing_count": 0,
        "maximum_drop_callback": 541,
        "maximum_drop_parent_hex": "c4b1b61a7f5d6c40",
        "maximum_drop_u0_hex": "5f639675c0d26b40",
        "maximum_drop_u1_hex": "1165475de7236c40",
        "maximum_drop_variable": 188,
        "pair_count": 81_632,
        "proposal_count": 549,
        "release_batch_count": 8,
        "terminal_upper_hex": _f64le_hex(terminal.parent_upper_bound),
    }
    if observed_result != expected_result:
        differences = ", ".join(
            f"{name}={observed_result[name]!r}"
            for name in sorted(expected_result)
            if observed_result[name] != expected_result[name]
        )
        raise O1C80ArchivedBoundCensusError(
            f"visible-event lower-envelope result differs: {differences}"
        )
    return {
        "both_children_strict_prunable_pair_count": both_prunable_count,
        "callback_parent_state_exact": False,
        "closest_lower_envelope_child": closest,
        "crossing_pair_count": crossing_count,
        "exact_parent_population": 0,
        "incident_cache_full_scan_equivalence": {
            "checked_child_bound_count": 4,
            "checked_parent_bound_count": 2,
            "f64le_mismatch_count": 0,
            "scope": "global-minimum-child-and-maximum-drop-extrema-only",
        },
        "marker_count": proposal_count,
        "maximum_drop_breadcrumb": {
            "certifies_crossing": False,
            "reason": (
                "a difference of two lower-envelope values has no monotonic "
                "relationship to the unavailable native-state drop"
            ),
            "row": maximum_drop,
        },
        "monotonic_no_crossing_scope": {
            "certificate": True,
            "lower_envelope_minimum_exceeds_threshold": cast(
                float, closest["minimum_child_upper_bound"]
            )
            > THRESHOLD,
            "reason": (
                "omitted backtrack removals retain stale observed assignments; "
                "extra assignments cannot increase a grouped upper bound, so "
                "U_visible_envelope <= U_native for the same child under the "
                "archived complete-assignment-notification contract"
            ),
            "scope": (
                "549 serialized nonzero proposal markers from O1C-0079 only; "
                "not the 1038 zero-return callbacks and not the future Page-7 run"
            ),
        },
        "operation_counts": {
            "child_incident_group_recomputations": child_incident_groups,
            "child_incident_group_row_evaluations": child_incident_rows,
            "replay_group_recomputations": replay.group_recomputations,
            "replay_group_row_evaluations": replay.group_row_evaluations,
        },
        "pair_count": pair_count,
        "pair_ledger_persisted": False,
        "pair_ledger_sha256": ledger_digest.hexdigest(),
        "pair_ledger_storage_rule": (
            "canonical rows hashed in event/callback then ascending-key order; "
            "only extrema and aggregate counters persisted to keep the artifact bounded"
        ),
        "release_evidence": {
            "missing_backtrack_target_count_at_least": native_backtracks
            - len(release_batch_targets),
            "native_backtrack_count": native_backtracks,
            "serialized_release_batch_count": len(release_batch_targets),
            "serialized_release_batch_target_levels": release_batch_targets,
        },
        "state_rule": (
            "replay assignment notifications; ignore same-sign renotifications as v6; "
            "replace an incompatible stale sign on its later notification; unwind only "
            "the eight serialized release batches; validate convergence to terminal cache"
        ),
        "terminal_convergence": {
            "assignment_sha256": terminal.assignment_sha256,
            "group_cache_sha256": terminal.group_cache_sha256,
            "matches_archived_terminal": True,
            "upper_bound": terminal.parent_upper_bound,
            "upper_bound_f64le_hex": _f64le_hex(terminal.parent_upper_bound),
        },
        "warning": (
            "The 549 replay states are lower-envelope reconstructions, not exact "
            "same-parent callback assignments. Missing backtrack targets prevent exact replay."
        ),
        "zero_return_reconstruction": {
            "assignment_callback_count": 1_227,
            "callback_count": cast(int, central["callback_calls"]),
            "decision_levels_without_assignment_callback_at_least": 360,
            "exact_zero_return_parent_count": 0,
            "nonzero_marker_count": cast(int, central["nonzero_returns"]),
            "zero_return_count": cast(int, central["zero_returns"]),
        },
    }


def generate_archived_bound_census(
    root: str | Path | None = None,
) -> dict[str, object]:
    """Generate the deterministic terminal and visible-envelope census."""

    base = lab_root() if root is None else Path(root)
    inputs = load_public_bound_inputs(base)
    parents, aliases, snapshot_inputs = _load_archived_parents(base, inputs)
    terminal = _terminal_census(inputs, parents, aliases)
    visible = _visible_event_lower_envelope(base, inputs, parents)
    return {
        "attempt_id": ATTEMPT_ID,
        "bound_contract": {
            "bit0_spin": -1,
            "bit1_spin": 1,
            "bound_rule": COMPATIBILITY_GROUPING_BOUND_RULE,
            "candidate_order": "ascending-key-variable-1-through-256",
            "missing_unobserved_key_variables": list(MISSING_KEY_VARIABLES),
            "strict_threshold_rule": "upper-bound < threshold; equality-is-live",
            "threshold": THRESHOLD,
            "threshold_f64le_hex": THRESHOLD_F64LE_HEX,
        },
        "conclusion": {
            "future_page7_oracle_population_measured": False,
            "o1c79_zero_return_exact_parent_population": 0,
            "terminal_crossings": 0,
            "terminal_scope_only": True,
            "visible_event_lower_envelope_crossings": 0,
        },
        "inputs": {
            "grouping": {
                "bytes": GROUPING_BYTES,
                "group_count": inputs.grouping.group_count,
                "relative_path": GROUPING_RELATIVE.as_posix(),
                "sha256": inputs.grouping.sha256,
                "table_rows": inputs.grouping.table_rows,
                "variable_group_incidences": inputs.grouping.variable_group_incidences,
                "width_cap": inputs.grouping.width_cap,
            },
            "o1c79_auxiliary_evidence": [
                {
                    "file_bytes": spec.file_bytes,
                    "file_sha256": spec.file_sha256,
                    "label": spec.label,
                    "raw_bytes": spec.raw_bytes,
                    "raw_sha256": spec.raw_sha256,
                    "relative_path": spec.relative.as_posix(),
                }
                for spec in (CENTRAL_READER_SPEC, OWNERSHIP_SPEC)
            ],
            "potential": {
                "bytes": POTENTIAL_BYTES,
                "factor_count": len(inputs.field.factors),
                "observed_variable_count": len(inputs.field.observed_variables),
                "relative_path": POTENTIAL_RELATIVE.as_posix(),
                "sha256": inputs.field.state_sha256,
                "source_sha256": inputs.field.source_sha256,
            },
            "terminal_snapshots": snapshot_inputs,
        },
        "resource_reporting": {
            "live_runtime_or_rss_in_deterministic_json": False,
            "reason": (
                "wall time and RSS are host-dependent; exact operation counts are "
                "persisted in each census and external profiling does not alter output"
            ),
        },
        "schema": CENSUS_SCHEMA,
        "scope": {
            "fresh_targets": 0,
            "mps_or_gpu_calls": 0,
            "native_solver_calls": 0,
            "public_verification_calls": 0,
            "refits": 0,
            "reveal_calls": 0,
            "science_calls": 0,
            "truth_key_bytes_read": False,
        },
        "terminal_exact_census": terminal,
        "visible_event_lower_envelope": visible,
    }


def serialize_archived_bound_census(report: Mapping[str, object]) -> bytes:
    try:
        return canonical_json_bytes(report)
    except (TypeError, ValueError) as exc:
        raise O1C80ArchivedBoundCensusError("census JSON differs") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Recompute O1C-0080's target-free archived one-bit bound census "
            "without a solver call"
        )
    )
    parser.add_argument("--root", default=lab_root().as_posix())
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--output", help="write canonical census JSON to this file")
    mode.add_argument("--check", help="fail unless this file equals the fresh census")
    return parser


def _write_output(path: Path, payload: bytes) -> None:
    if path.exists():
        _regular_file(path, "output")
    if not path.parent.is_dir():
        raise O1C80ArchivedBoundCensusError("output parent directory is absent")
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        temporary.write_bytes(payload)
        os.replace(temporary, path)
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise O1C80ArchivedBoundCensusError("output write failed") from exc


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        report = generate_archived_bound_census(args.root)
        payload = serialize_archived_bound_census(report)
        if args.check:
            checked_path = _regular_file(Path(args.check), "checked census")
            if checked_path.read_bytes() != payload:
                raise O1C80ArchivedBoundCensusError(
                    "checked census differs from fresh deterministic output"
                )
            receipt = {
                "bytes": len(payload),
                "checked": checked_path.as_posix(),
                "matches": True,
                "sha256": _sha256(payload),
            }
            sys.stdout.buffer.write(canonical_json_bytes(receipt))
        elif args.output:
            output_path = Path(args.output)
            _write_output(output_path, payload)
            receipt = {
                "bytes": len(payload),
                "output": output_path.as_posix(),
                "sha256": _sha256(payload),
            }
            sys.stdout.buffer.write(canonical_json_bytes(receipt))
        else:
            sys.stdout.buffer.write(payload)
    except (O1C80ArchivedBoundCensusError, OSError) as exc:
        print(f"{ATTEMPT_ID} archived bound census: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ARCHIVED_SNAPSHOT_SPECS",
    "ATTEMPT_ID",
    "CENSUS_SCHEMA",
    "CENTRAL_READER_SPEC",
    "GROUPING_RELATIVE",
    "KEY_VARIABLES",
    "MISSING_KEY_VARIABLES",
    "O1C80ArchivedBoundCensusError",
    "OWNERSHIP_SPEC",
    "POTENTIAL_RELATIVE",
    "PublicBoundInputs",
    "SealedJsonSpec",
    "THRESHOLD",
    "exact_one_bit_child_bounds",
    "generate_archived_bound_census",
    "lab_root",
    "load_public_bound_inputs",
    "main",
    "serialize_archived_bound_census",
]
