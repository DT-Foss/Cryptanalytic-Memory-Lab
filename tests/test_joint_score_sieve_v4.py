from __future__ import annotations

import copy
import hashlib
import itertools
import json
import math
import shutil
import struct
from fractions import Fraction
from pathlib import Path
from types import SimpleNamespace

import pytest

import o1_crypto_lab.joint_score_sieve as independent_sieve
import o1_crypto_lab.joint_score_sieve_v4 as grouped_sieve
from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.joint_score_sieve_v4 import (
    JointScoreCompatibilityGrouping,
    build_compatibility_grouping,
    build_native_joint_score_sieve,
    grouped_joint_score_cache,
    grouped_upper_bound_prunes,
    joint_score_complete,
    joint_score_upper_bound,
    run_joint_score_sieve,
    serialize_compatibility_grouping,
    write_joint_score_sieve_potential,
)
from o1_crypto_lab.o1_relational_search import O1RelationalSearchError

ROOT = Path(__file__).resolve().parents[1]
NATIVE_SOURCE = ROOT / "native/cadical_o1_joint_score_sieve_v3.cpp"
O1C61_POTENTIAL = (
    ROOT
    / "runs/20260719_091954_O1C-0061_multiblock-joint-score-sieve-soft-stop-v1"
    / "artifacts/potential/primary-eight-block.potential"
)
CADICAL_INCLUDE = Path("/opt/homebrew/opt/cadical/include")
CADICAL_LIBRARY = Path("/opt/homebrew/opt/cadical/lib/libcadical.a")
O1C61_GROUPING_SHA256 = (
    "c7cc0d745848e45b92239782429fed737cc06d3cafc7ad510d6738af721adaf6"
)
O1C61_POTENTIAL_SHA256 = (
    "8c6101b49c7050caf895bd9c496c05bcea9f43a2b27f378d7306be38b00d5390"
)


def _native_available() -> bool:
    return bool(
        shutil.which("c++")
        and (CADICAL_INCLUDE / "cadical.hpp").is_file()
        and CADICAL_LIBRARY.is_file()
    )


def _factor(
    variables: tuple[int, ...], *, start: float = 0.0
) -> CriticalityPotentialFactor:
    return CriticalityPotentialFactor(
        variables,
        tuple(start + float(mask) for mask in range(1 << len(variables))),
    )


def _greedy_field() -> CriticalityPotentialField:
    return CriticalityPotentialField(
        offset=0.0,
        source_sha256="41" * 32,
        factors=(
            _factor((1, 2, 3, 4, 5, 6, 7, 8)),
            _factor((1, 9), start=1_000.0),
            _factor((1, 9, 10), start=2_000.0),
            _factor((2,), start=3_000.0),
            _factor((20,), start=4_000.0),
        ),
    )


def _bound_field() -> CriticalityPotentialField:
    return CriticalityPotentialField(
        offset=0.0,
        source_sha256="42" * 32,
        factors=(
            CriticalityPotentialFactor((1,), (-3.0, 4.0)),
            CriticalityPotentialFactor((1, 2), (7.0, -2.0, 1.0, 6.0)),
            CriticalityPotentialFactor((2,), (5.0, -8.0)),
        ),
    )


def _negative_zero_field() -> CriticalityPotentialField:
    normal = 2.0**-1022
    return CriticalityPotentialField(
        offset=0.0,
        source_sha256="45" * 32,
        factors=(
            CriticalityPotentialFactor((1,), (normal, normal)),
            CriticalityPotentialFactor(
                (1, 2),
                (-math.nextafter(normal, math.inf),) * 4,
            ),
        ),
    )


@pytest.fixture(scope="module")
def native_build(tmp_path_factory: pytest.TempPathFactory):
    if not _native_available():
        pytest.skip("CaDiCaL development files absent")
    output = tmp_path_factory.mktemp("joint-score-v4-native") / "joint-score-v4"
    return build_native_joint_score_sieve(source=NATIVE_SOURCE, output=output)


def test_greedy_partition_uses_smallest_compatible_earlier_factor_once() -> None:
    grouping = build_compatibility_grouping(_greedy_field())
    assert tuple(group.factor_indices for group in grouping.groups) == (
        (0, 3),
        (1, 2),
        (4,),
    )
    members = [
        factor_index
        for group in grouping.groups
        for factor_index in group.factor_indices
    ]
    assert sorted(members) == list(range(grouping.factor_count))
    assert len(members) == len(set(members))
    assert grouping.pair_group_count == 2
    assert grouping.singleton_group_count == 1


def test_grouping_contract_rejects_out_of_order_groups() -> None:
    grouping = build_compatibility_grouping(_greedy_field())
    groups = tuple(reversed(grouping.groups))
    serialized = serialize_compatibility_grouping(groups)
    with pytest.raises(O1RelationalSearchError, match="grouping differs"):
        JointScoreCompatibilityGrouping(
            factor_count=grouping.factor_count,
            groups=groups,
            serialized=serialized,
            sha256=hashlib.sha256(serialized).hexdigest(),
        )


def test_pair_table_projects_union_rows_into_both_original_scopes() -> None:
    field = CriticalityPotentialField(
        offset=0.0,
        source_sha256="43" * 32,
        factors=(
            CriticalityPotentialFactor((1, 3), (1.0, 2.0, 4.0, 8.0)),
            CriticalityPotentialFactor((3, 4), (10.0, 20.0, 40.0, 80.0)),
        ),
    )
    (group,) = build_compatibility_grouping(field).groups
    assert group.factor_indices == (0, 1)
    assert group.variables == (1, 3, 4)
    expected = (11.0, 12.0, 24.0, 28.0, 41.0, 42.0, 84.0, 88.0)
    assert group.energies == expected


def test_pair_cell_rounding_is_safe_for_half_ulp_adversary() -> None:
    tiny = 2.0**-53
    field = CriticalityPotentialField(
        offset=0.0,
        source_sha256="44" * 32,
        factors=(
            CriticalityPotentialFactor((1,), (1.0, 1.0)),
            CriticalityPotentialFactor((1, 2), (tiny, tiny, tiny, tiny)),
        ),
    )
    (group,) = build_compatibility_grouping(field).groups
    exact = Fraction.from_float(1.0) + Fraction.from_float(tiny)
    for energy in group.energies:
        assert Fraction.from_float(energy) >= exact
        assert energy == math.nextafter(1.0, math.inf)


def test_grouped_bound_tightens_independent_bound_and_covers_completions() -> None:
    field = _bound_field()
    variables = field.observed_variables
    for states in itertools.product((None, -1, 1), repeat=len(variables)):
        partial = {
            variable: spin
            for variable, spin in zip(variables, states, strict=True)
            if spin is not None
        }
        grouped = joint_score_upper_bound(field, partial)
        independent = independent_sieve.joint_score_upper_bound(field, partial)
        assert grouped <= independent
        missing = tuple(variable for variable in variables if variable not in partial)
        for spins in itertools.product((-1, 1), repeat=len(missing)):
            complete = dict(partial)
            complete.update(zip(missing, spins, strict=True))
            assert grouped >= joint_score_complete(field, complete)


def test_threshold_equality_is_not_pruned() -> None:
    upper = joint_score_upper_bound(_bound_field(), {1: 1})
    assert not grouped_upper_bound_prunes(upper, upper)
    assert grouped_upper_bound_prunes(math.nextafter(upper, -math.inf), upper)


def test_negative_zero_root_has_an_explicit_bit_ledger() -> None:
    root = joint_score_upper_bound(_negative_zero_field(), {})
    assert root == 0.0
    assert math.copysign(1.0, root) < 0.0
    assert root.hex() == "-0x0.0p+0"


def test_native_negative_zero_root_roundtrips_through_explicit_bits(
    tmp_path: Path, native_build
) -> None:
    cnf = tmp_path / "negative-zero.cnf"
    cnf.write_text("p cnf 256 1\n1 0\n", encoding="ascii")
    potential = tmp_path / "negative-zero.potential"
    write_joint_score_sieve_potential(potential, _negative_zero_field())
    result = run_joint_score_sieve(
        executable=native_build.executable,
        cnf_path=cnf,
        potential_path=potential,
        threshold=-1.0,
        conflict_limit=1,
    )
    assert result.sieve["root_upper_bound"] == 0.0
    assert result.sieve["root_upper_bound_f64le_hex"] == "0000000000000080"


def test_persisted_o1c61_grouping_shape_and_hash_are_frozen() -> None:
    if not O1C61_POTENTIAL.is_file():
        pytest.skip("persisted O1C61 potential is absent from this checkout")
    payload = O1C61_POTENTIAL.read_bytes()
    assert hashlib.sha256(payload).hexdigest() == O1C61_POTENTIAL_SHA256
    field = CriticalityPotentialField.from_bytes(payload)
    grouping = build_compatibility_grouping(field)
    assert grouping.factor_count == 7_557
    assert grouping.pair_group_count == 3_752
    assert grouping.singleton_group_count == 53
    assert grouping.group_count == 3_805
    assert grouping.table_rows == 265_256
    assert grouping.incident_edges == 22_345
    assert grouping.sha256 == O1C61_GROUPING_SHA256
    assert hashlib.sha256(grouping.serialized).hexdigest() == grouping.sha256


def _run_native(tmp_path: Path, executable: Path):
    cnf = tmp_path / "case.cnf"
    cnf.write_text("p cnf 256 1\n1 0\n", encoding="ascii")
    potential = tmp_path / "case.potential"
    field = _bound_field()
    write_joint_score_sieve_potential(potential, field)
    result = run_joint_score_sieve(
        executable=executable,
        cnf_path=cnf,
        potential_path=potential,
        threshold=-1_000.0,
        conflict_limit=1,
    )
    return result, field, cnf, potential


def test_native_and_python_grouping_root_and_cache_are_byte_exact(
    tmp_path: Path, native_build
) -> None:
    result, field, _, _ = _run_native(tmp_path, native_build.executable)
    grouping = build_compatibility_grouping(field)
    sieve = result.sieve
    state = sieve["state"]
    assert sieve["grouping_sha256"] == grouping.sha256
    assert sieve["group_count"] == grouping.group_count
    assert sieve["pair_group_count"] == grouping.pair_group_count
    assert sieve["singleton_group_count"] == grouping.singleton_group_count
    assert sieve["group_table_rows"] == grouping.table_rows
    assert sieve["group_incident_edges"] == grouping.incident_edges
    assert sieve["root_upper_bound"] == joint_score_upper_bound(field, {})
    assert (
        sieve["root_upper_bound_f64le_hex"]
        == struct.pack("<d", joint_score_upper_bound(field, {})).hex()
    )
    assignments = bytes.fromhex(state["assignment_hex"])  # type: ignore[index]
    partial = {
        variable: (1 if assignments[local] == 1 else -1)
        for local, variable in enumerate(field.observed_variables)
        if assignments[local]
    }
    assert bytes.fromhex(state["group_cache_hex"]) == grouped_joint_score_cache(  # type: ignore[index]
        field, partial
    )


def test_parser_fail_closes_grouping_root_and_self_consistent_wrong_cache(
    tmp_path: Path, native_build, monkeypatch: pytest.MonkeyPatch
) -> None:
    result, _, cnf, potential = _run_native(tmp_path, native_build.executable)
    valid = result.raw

    def install(payload: object) -> None:
        monkeypatch.setattr(
            grouped_sieve.subprocess,
            "run",
            lambda *args, **kwargs: SimpleNamespace(
                returncode=0, stdout=json.dumps(payload), stderr=""
            ),
        )

    def parse() -> None:
        run_joint_score_sieve(
            executable=native_build.executable,
            cnf_path=cnf,
            potential_path=potential,
            threshold=-1_000.0,
            conflict_limit=1,
        )

    wrong_cache = copy.deepcopy(valid)
    state = wrong_cache["sieve"]["state"]
    cache = bytearray.fromhex(state["group_cache_hex"])
    cache[0] ^= 1
    state["group_cache_hex"] = cache.hex()
    state["group_cache_sha256"] = hashlib.sha256(cache).hexdigest()
    canonical = (
        bytes.fromhex(state["assignment_hex"])
        + bytes.fromhex(state["trail_hex"])
        + bytes.fromhex(state["pending_hex"])
    )
    state["persistent_sha256"] = hashlib.sha256(canonical + cache).hexdigest()
    install(wrong_cache)
    with pytest.raises(O1RelationalSearchError, match="grouped cache"):
        parse()

    wrong_grouping = copy.deepcopy(valid)
    wrong_grouping["sieve"]["grouping_sha256"] = "00" * 32
    install(wrong_grouping)
    with pytest.raises(O1RelationalSearchError, match="telemetry contract"):
        parse()

    wrong_root = copy.deepcopy(valid)
    wrong_root["sieve"]["root_upper_bound_f64le_hex"] = "00" * 8
    install(wrong_root)
    with pytest.raises(O1RelationalSearchError, match="telemetry contract"):
        parse()
