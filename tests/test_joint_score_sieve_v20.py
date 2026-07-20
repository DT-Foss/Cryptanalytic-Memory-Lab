from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
from typing import Any, cast

import pytest

import o1_crypto_lab.joint_score_sieve_v20 as sieve_v20
from o1_crypto_lab.causal_frontier_v1 import (
    CausalFrontierPlan,
    derive_causal_frontier_plan,
    write_causal_frontier_plan,
)
from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.joint_score_grouping_v1 import (
    JointScoreCompatibilityGrouping,
    build_compatibility_grouping,
)
from o1_crypto_lab.o1_relational_search import O1RelationalSearchError
from o1_crypto_lab.rescue_prefix_preemption_v1 import (
    O1C78_PREFIX_LITERALS,
    RescuePrefixPreemptionPlan,
    write_rescue_prefix_preemption_plan,
)
from o1_crypto_lab.residual_polarity_staging_v1 import (
    ResidualPolarityStagingPlan,
    derive_residual_polarity_staging_plan,
    write_residual_polarity_staging_plan,
)
from o1_crypto_lab.threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    VaultCaps,
    vault_identity_from_sources,
    write_threshold_no_good_vault,
)
from o1_crypto_lab.vault_phase_field_v1 import derive_vault_phase_field
from o1_crypto_lab.vault_ranked_decision_v1 import (
    VaultRankedDecision,
    derive_vault_ranked_decision,
)


ROOT = Path(__file__).resolve().parents[1]
NATIVE_SOURCE = ROOT / "native/cadical_o1_joint_score_sieve_v17.cpp"
OWNERSHIP_HEADER = ROOT / "native/o1c79_decision_ownership.hpp"
CADICAL_INCLUDE = Path("/opt/homebrew/opt/cadical/include")
CADICAL_LIBRARY = Path("/opt/homebrew/opt/cadical/lib/libcadical.a")


@pytest.fixture(scope="module")
def ownership_fixture(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if not shutil.which("c++"):
        pytest.skip("C++ compiler absent")
    build = tmp_path_factory.mktemp("o1c79-ownership")
    source = build / "ownership.cpp"
    source.write_text(
        r"""
#include "o1c79_decision_ownership.hpp"
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

using namespace o1c79;

std::string json(const DecisionOwnershipLedger &ledger) {
  std::ostringstream out;
  out << '{';
  ledger.write_json(out);
  out << '}';
  return out.str();
}

int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  const std::string mode = argv[1];
  DecisionOwnershipLedger ledger;
  if (mode == "alias") {
    ledger.propose(DecisionOrigin::PREFIX, 0, 130, 1);
    ledger.notify_new_decision_level(1);
    bool blocked = false;
    try { ledger.propose(DecisionOrigin::RANK_ORIGINAL, 224, 130, 2); }
    catch (const std::runtime_error &) { blocked = true; }
    ledger.notify_backtrack(0);
    ledger.notify_assignment(-130);
    ledger.propose(DecisionOrigin::RANK_ORIGINAL, 224, 130, 2);
    ledger.notify_new_decision_level(1);
    ledger.notify_backtrack(0);
    ledger.propose(DecisionOrigin::FRONTIER_INITIAL, 226, 130, 3);
    ledger.notify_new_decision_level(1);
    ledger.notify_backtrack(0);
    std::cout << "{\"blocked_while_live\":"
              << (blocked ? "true" : "false") << ",\"ledger\":"
              << json(ledger) << "}\n";
  } else if (mode == "confirmed") {
    ledger.propose(DecisionOrigin::RANK_ORIGINAL, 224, 130, 1);
    ledger.notify_new_decision_level(1);
    ledger.notify_assignment(130);
    ledger.notify_assignment(130);
    ledger.notify_backtrack(0);
    std::cout << json(ledger) << '\n';
  } else if (mode == "deep") {
    ledger.propose(DecisionOrigin::RANK_ORIGINAL, 1, 130, 1);
    ledger.notify_new_decision_level(1);
    ledger.notify_assignment(130);
    ledger.propose(DecisionOrigin::FRONTIER_INITIAL, 2, 131, 2);
    ledger.notify_new_decision_level(2);
    const auto released = ledger.notify_backtrack(0);
    std::cout << "{\"released_tokens\":[" << released[0].token << ','
              << released[1].token << "],\"ledger\":" << json(ledger)
              << "}\n";
  } else if (mode == "invalid") {
    const std::string before = json(ledger);
    bool none_blocked = false;
    try { ledger.propose(DecisionOrigin::NONE, 0, 130, 1); }
    catch (const std::runtime_error &) { none_blocked = true; }
    const bool unchanged = before == json(ledger);
    ledger.propose(DecisionOrigin::PREFIX, 0, 130, 1);
    bool double_blocked = false;
    try { ledger.propose(DecisionOrigin::RANK_ORIGINAL, 1, 131, 2); }
    catch (const std::runtime_error &) { double_blocked = true; }
    std::cout << "{\"none_blocked\":" << (none_blocked ? "true" : "false")
              << ",\"none_atomic\":" << (unchanged ? "true" : "false")
              << ",\"double_blocked\":"
              << (double_blocked ? "true" : "false") << "}\n";
  } else if (mode == "cap") {
    for (size_t index = 0;
         index < DecisionOwnershipLedger::kMaximumRecordedEvents; ++index)
      ledger.notify_assignment(130);
    const std::string before = json(ledger);
    bool blocked = false;
    try { ledger.notify_assignment(131); }
    catch (const std::runtime_error &) { blocked = true; }
    std::cout << "{\"blocked\":" << (blocked ? "true" : "false")
              << ",\"atomic\":" << (before == json(ledger) ? "true" : "false")
              << "}\n";
  } else {
    return 3;
  }
  return 0;
}
""",
        encoding="utf-8",
    )
    executable = build / "ownership"
    completed = subprocess.run(
        [
            "c++",
            "-std=c++17",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            f"-I{OWNERSHIP_HEADER.parent}",
            str(source),
            "-o",
            str(executable),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return executable


def _ownership(executable: Path, mode: str) -> dict[str, Any]:
    completed = subprocess.run(
        [str(executable), mode], capture_output=True, text=True, check=False
    )
    assert completed.returncode == 0, completed.stderr
    value = json.loads(completed.stdout)
    assert isinstance(value, dict)
    return value


def test_alias_is_owned_by_origin_row_level_not_historical_sign(
    ownership_fixture: Path,
) -> None:
    result = _ownership(ownership_fixture, "alias")
    ledger = result["ledger"]
    assert result["blocked_while_live"] is True
    assert ledger["level_bound_unobserved_releases"] == 3
    assert ledger["confirmed_releases"] == 0
    assert ledger["foreign_assignments"] == 1
    assert [
        event["origin"] for event in ledger["events"] if event["kind"] == "PROPOSED"
    ] == ["PREFIX", "RANK_ORIGINAL", "FRONTIER_INITIAL"]
    assert [
        event["kind"] for event in ledger["events"] if event["observed_literal"]
    ] == ["FOREIGN_ASSIGNMENT"]
    assert sieve_v20._replay_ownership(ledger) == ledger


def test_same_sign_confirmation_renotify_and_release(
    ownership_fixture: Path,
) -> None:
    result = _ownership(ownership_fixture, "confirmed")
    assert result["confirmed_interventions"] == 1
    assert result["renotifications"] == 1
    assert result["confirmed_releases"] == 1
    assert result["level_bound_unobserved_releases"] == 0
    assert sieve_v20._replay_ownership(result) == result


def test_multilevel_release_is_deepest_newest_first(
    ownership_fixture: Path,
) -> None:
    result = _ownership(ownership_fixture, "deep")
    assert result["released_tokens"] == [2, 1]
    releases = [
        event
        for event in result["ledger"]["events"]
        if event["kind"] in {"RELEASED", "LEVEL_BOUND_UNOBSERVED_RELEASE"}
    ]
    assert [(event["token"], event["level"]) for event in releases] == [(2, 0), (1, 0)]
    assert sieve_v20._replay_ownership(result["ledger"]) == result["ledger"]


def test_replay_accepts_opposite_observation_without_changing_confirmation(
    ownership_fixture: Path,
) -> None:
    ledger = _ownership(ownership_fixture, "confirmed")
    events = cast(list[dict[str, Any]], ledger["events"])
    confirmed_index = next(
        index for index, event in enumerate(events) if event["kind"] == "CONFIRMED"
    )
    opposite = dict(events[confirmed_index])
    opposite["kind"] = "OPPOSITE_ASSIGNMENT"
    opposite["observed_literal"] = -cast(int, opposite["literal"])
    events.insert(confirmed_index + 1, opposite)
    for sequence, event in enumerate(events, start=1):
        event["sequence"] = sequence
    ledger["opposite_assignments"] += 1
    ledger["event_count"] += 1
    ledger["recorded_event_count"] += 1
    assert sieve_v20._replay_ownership(ledger) == ledger


def test_replay_rejects_malformed_deepest_newest_release_batch(
    ownership_fixture: Path,
) -> None:
    ledger = copy.deepcopy(_ownership(ownership_fixture, "deep")["ledger"])
    events = cast(list[dict[str, Any]], ledger["events"])
    release_indices = [
        index
        for index, event in enumerate(events)
        if event["kind"] in {"RELEASED", "LEVEL_BOUND_UNOBSERVED_RELEASE"}
    ]
    assert len(release_indices) == 2
    first, second = release_indices
    events[first], events[second] = events[second], events[first]
    for sequence, event in enumerate(events, start=1):
        event["sequence"] = sequence
    with pytest.raises(O1RelationalSearchError, match="release batch"):
        sieve_v20._replay_ownership(ledger)


def test_invalid_transitions_and_event_cap_are_atomic(
    ownership_fixture: Path,
) -> None:
    invalid = _ownership(ownership_fixture, "invalid")
    assert invalid == {
        "none_blocked": True,
        "none_atomic": True,
        "double_blocked": True,
    }
    cap = _ownership(ownership_fixture, "cap")
    assert cap == {"blocked": True, "atomic": True}


def _field() -> CriticalityPotentialField:
    factors = [
        CriticalityPotentialFactor((1,), (8.0, 0.0)),
        CriticalityPotentialFactor((2,), (6.0, 0.0)),
        CriticalityPotentialFactor((3,), (0.0, 10.0)),
        CriticalityPotentialFactor((6,), (1.0, 0.0)),
        CriticalityPotentialFactor((7,), (0.5, 0.0)),
    ]
    factors.extend(
        CriticalityPotentialFactor((abs(literal),), (0.0, 0.0))
        for literal in O1C78_PREFIX_LITERALS
        if abs(literal) not in {1, 2, 3, 6, 7}
    )
    return CriticalityPotentialField(
        offset=0.0, source_sha256="79" * 32, factors=tuple(factors)
    )


@dataclass(frozen=True)
class PublicArtifacts:
    cnf: Path
    potential: Path
    grouping_path: Path
    rank_vault_path: Path
    active_vault_path: Path
    rank_table_path: Path
    frontier_plan_path: Path
    staging_plan_path: Path
    prefix_plan_path: Path
    field: CriticalityPotentialField
    grouping: JointScoreCompatibilityGrouping
    rank_vault: ThresholdNoGoodVault
    active_vault: ThresholdNoGoodVault
    decision: VaultRankedDecision
    frontier_plan: CausalFrontierPlan
    staging_plan: ResidualPolarityStagingPlan
    prefix_plan: RescuePrefixPreemptionPlan


def _source_result(count: int) -> tuple[dict[str, object], str]:
    assignment = bytes(count)
    source: dict[str, object] = {
        "schema": "public-o1c79-source-v1",
        "sieve": {
            "state": {
                "schema": "o1-256-cadical-joint-score-sieve-grouped-state-v2",
                "encoding": "observed-ascending-i8-sign;fixture",
                "assignment_bytes": count,
                "assignment_hex": assignment.hex(),
                "assignment_sha256": hashlib.sha256(assignment).hexdigest(),
                "current_assigned_variables": 0,
            }
        },
    }
    payload = json.dumps(source, sort_keys=True, separators=(",", ":")).encode()
    return source, hashlib.sha256(payload).hexdigest()


def _artifacts(tmp_path: Path) -> PublicArtifacts:
    field = _field()
    cnf = tmp_path / "public.cnf"
    cnf.write_text(
        "p cnf 191234 11\n"
        "6 0\n"
        "-130 11 0\n-130 -11 0\n"
        "2 4 5 0\n2 4 -5 0\n2 -4 5 0\n2 -4 -5 0\n"
        "8 9 0\n8 -9 0\n-8 10 0\n-8 -10 0\n",
        encoding="ascii",
    )
    potential = tmp_path / "public.potential"
    grouping_path = tmp_path / "public.grouping"
    sieve_v20.write_joint_score_sieve_potential(potential, field)
    sieve_v20.write_joint_score_sieve_grouping(grouping_path, field)
    grouping = build_compatibility_grouping(field, width_cap=6)
    identity = vault_identity_from_sources(
        cnf_sha256=hashlib.sha256(cnf.read_bytes()).hexdigest(),
        potential_sha256=hashlib.sha256(potential.read_bytes()).hexdigest(),
        grouping_sha256=hashlib.sha256(grouping_path.read_bytes()).hexdigest(),
        observed_variables=field.observed_variables,
        bound_rule=sieve_v20.JOINT_SCORE_SIEVE_BOUND_RULE,
        threshold=12.0,
    )
    rank_vault = ThresholdNoGoodVault(
        identity,
        field.observed_variables,
        (
            ThresholdNoGoodClause((-1, 3)),
            ThresholdNoGoodClause((-2, 3)),
            ThresholdNoGoodClause((-1, 3, -6)),
            ThresholdNoGoodClause((-1, 3, 7)),
            ThresholdNoGoodClause((-1, -2, 3, -6, -130)),
        ),
    )
    active_vault = ThresholdNoGoodVault(
        identity,
        field.observed_variables,
        (ThresholdNoGoodClause((-1, -2, 3, -6, -130)),),
    )
    rank_vault_path = tmp_path / "rank.vault"
    active_vault_path = tmp_path / "active.vault"
    write_threshold_no_good_vault(rank_vault_path, rank_vault, caps=O1C66_VAULT_CAPS)
    write_threshold_no_good_vault(
        active_vault_path, active_vault, caps=O1C66_VAULT_CAPS
    )
    phase = derive_vault_phase_field(
        rank_vault.serialized, key_variable_count=256, clause_start=0
    )
    decision = derive_vault_ranked_decision(phase, field, grouping)
    assert 130 in map(abs, decision.ranked_literals)
    rank_table_path = tmp_path / "rank.table"
    rank_table_path.write_bytes(decision.rank_table_bytes)

    source, source_sha = _source_result(len(field.observed_variables))
    frontier_plan = derive_causal_frontier_plan(
        source_result=source,
        source_result_sha256=source_sha,
        active_vault=active_vault,
        selected_union_indices=(79,),
    )
    assert 130 in frontier_plan.falsifying_decision_literals
    frontier_plan_path = tmp_path / "frontier.plan"
    write_causal_frontier_plan(frontier_plan_path, frontier_plan)
    overlay_indices = tuple(
        sorted(
            index
            for index, literal in enumerate(decision.ranked_literals)
            if abs(literal) in (1, 2)
        )
    )
    staging_plan = derive_residual_polarity_staging_plan(
        source_result=source,
        source_result_sha256=source_sha,
        active_vault=active_vault,
        rank_decision=decision,
        parent_frontier_plan_sha256=frontier_plan.sha256,
        selected_active_index=0,
        selected_union_index=79,
        overlay_rank_indices=overlay_indices,
    )
    staging_plan_path = tmp_path / "staging.plan"
    write_residual_polarity_staging_plan(staging_plan_path, staging_plan)
    prefix_plan = RescuePrefixPreemptionPlan(O1C78_PREFIX_LITERALS)
    prefix_plan_path = tmp_path / "prefix.plan"
    write_rescue_prefix_preemption_plan(prefix_plan_path, prefix_plan)
    return PublicArtifacts(
        cnf,
        potential,
        grouping_path,
        rank_vault_path,
        active_vault_path,
        rank_table_path,
        frontier_plan_path,
        staging_plan_path,
        prefix_plan_path,
        field,
        grouping,
        rank_vault,
        active_vault,
        decision,
        frontier_plan,
        staging_plan,
        prefix_plan,
    )


@pytest.fixture(scope="module")
def native_fixture(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if not (
        shutil.which("c++")
        and (CADICAL_INCLUDE / "cadical.hpp").is_file()
        and CADICAL_LIBRARY.is_file()
    ):
        pytest.skip("CaDiCaL 3.0.0 development files absent")
    executable = tmp_path_factory.mktemp("o1c79-native") / "native-v17"
    completed = subprocess.run(
        [
            "c++",
            "-std=c++17",
            "-O3",
            "-DNDEBUG",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-DO1_CRYPTO_LAB_O1C79_PUBLIC_FIXTURE",
            f"-I{CADICAL_INCLUDE}",
            str(NATIVE_SOURCE),
            str(CADICAL_LIBRARY),
            "-o",
            str(executable),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return executable


def _command(executable: Path, artifacts: PublicArtifacts) -> list[str]:
    return [
        str(executable),
        "--cnf",
        str(artifacts.cnf),
        "--potential",
        str(artifacts.potential),
        "--grouping",
        str(artifacts.grouping_path),
        "--rank-vault",
        str(artifacts.rank_vault_path),
        "--vault-in",
        str(artifacts.active_vault_path),
        "--rank-table",
        str(artifacts.rank_table_path),
        "--frontier-plan",
        str(artifacts.frontier_plan_path),
        "--staging-plan",
        str(artifacts.staging_plan_path),
        "--prefix-plan",
        str(artifacts.prefix_plan_path),
        "--threshold",
        "12",
        "--conflict-limit",
        "64",
        "--seed",
        "0",
    ]


def _native_payload(executable: Path, artifacts: PublicArtifacts) -> dict[str, Any]:
    completed = subprocess.run(
        _command(executable, artifacts), capture_output=True, text=True, check=False
    )
    assert completed.returncode == 0, completed.stderr
    value = json.loads(completed.stdout)
    assert isinstance(value, dict)
    return value


def _parse(
    payload: object, artifacts: PublicArtifacts
) -> sieve_v20.JointScoreSieveV20Result:
    return sieve_v20._parse_native_payload(
        payload,
        input_vault=artifacts.active_vault,
        rank_source_vault=artifacts.rank_vault,
        frontier_plan=artifacts.frontier_plan,
        staging_plan=artifacts.staging_plan,
        prefix_preemption_plan=artifacts.prefix_plan,
        vault_caps=O1C66_VAULT_CAPS,
        field=artifacts.field,
        grouping=artifacts.grouping,
        grouping_sha256=artifacts.active_vault.identity.grouping_sha256,
        cnf_sha256=artifacts.active_vault.identity.cnf_sha256,
        potential_sha256=artifacts.active_vault.identity.potential_sha256,
        threshold=12.0,
        requested_conflicts=64,
        seed=0,
        memory_limit_bytes=None,
        memory_samples=(),
        expected_decision=artifacts.decision,
    )


def _renumber_ownership_events(ownership: dict[str, Any]) -> None:
    events = cast(list[dict[str, Any]], ownership["events"])
    for sequence, event in enumerate(events, start=1):
        event["sequence"] = sequence
    ownership["event_count"] = len(events)
    ownership["recorded_event_count"] = len(events)


def _insert_proposal(
    ownership: dict[str, Any], *, index: int, proposal: dict[str, Any]
) -> None:
    cast(list[dict[str, Any]], ownership["events"]).insert(index, proposal)
    ownership["proposals"] += 1
    ownership["origin_counts"][proposal["origin"]]["proposals"] += 1
    _renumber_ownership_events(ownership)


def test_public_cadical_alias_stack_has_real_backtrack_and_validates(
    native_fixture: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = _artifacts(tmp_path)
    monkeypatch.setattr(
        sieve_v20,
        "derive_production_vault_ranked_decision",
        lambda *_args: artifacts.decision,
    )

    stable_fields: list[str] = []
    io_v1 = sieve_v20._v9._v8._v1
    original_verify = io_v1._verify_stable_input

    def track_stable_input(
        original: str | Path,
        resolved: Path,
        before: bytes,
        *,
        field: str,
    ) -> None:
        stable_fields.append(field)
        original_verify(original, resolved, before, field=field)

    monkeypatch.setattr(io_v1, "_verify_stable_input", track_stable_input)
    io_v8 = sieve_v20._v9._v8
    original_vault_verify = io_v8._verify_stable_vault_input
    stable_vault_calls = 0

    def track_stable_vault(
        original: str | Path,
        resolved: Path,
        before: bytes,
        *,
        caps: VaultCaps,
    ) -> None:
        nonlocal stable_vault_calls
        stable_vault_calls += 1
        original_vault_verify(original, resolved, before, caps=caps)

    monkeypatch.setattr(io_v8, "_verify_stable_vault_input", track_stable_vault)
    rank_module = sieve_v20._v19._v18._v17._v16._v15._v14._v13
    original_rank_temp = rank_module._rank_table_temp
    rank_paths: list[Path] = []

    def track_rank_temp(decision: VaultRankedDecision) -> tuple[Path, bytes]:
        path, payload = original_rank_temp(decision)
        rank_paths.append(path)
        return path, payload

    monkeypatch.setattr(rank_module, "_rank_table_temp", track_rank_temp)
    result = sieve_v20.run_joint_score_sieve(
        executable=native_fixture,
        cnf_path=artifacts.cnf,
        potential_path=artifacts.potential,
        grouping_path=artifacts.grouping_path,
        rank_vault_path=artifacts.rank_vault_path,
        vault_path=artifacts.active_vault_path,
        frontier_plan_path=artifacts.frontier_plan_path,
        staging_plan_path=artifacts.staging_plan_path,
        prefix_plan_path=artifacts.prefix_plan_path,
        vault_caps=O1C66_VAULT_CAPS,
        threshold=12.0,
        conflict_limit=64,
        seed=0,
        timeout_seconds=10.0,
        memory_limit_bytes=1 << 30,
    )
    payload = cast(dict[str, Any], result.raw)
    assert payload["sieve"]["backtracks"] >= 1
    assert payload["central_reader"]["prefix"]["cursor"] == 11
    assert (
        payload["sieve"]["cb_decide_calls"]
        == payload["central_reader"]["callback_calls"]
    )
    assert stable_fields == [
        "executable",
        "CNF",
        "potential",
        "grouping",
        "frontier plan",
        "staging plan",
        "prefix plan",
    ]
    assert stable_vault_calls == 2
    assert len(rank_paths) == 1 and not rank_paths[0].exists()
    assert cast(int, result.adapter_memory["memory_sample_count"]) >= 1

    ownership = cast(dict[str, Any], result.decision_ownership)
    assert {
        name: ownership[name]
        for name in (
            "proposals",
            "level_bound_interventions",
            "confirmed_interventions",
            "releases",
            "confirmed_releases",
            "level_bound_unobserved_releases",
            "opposite_assignments",
            "foreign_assignments",
            "renotifications",
            "live_tokens",
            "omitted_event_count",
        )
    } == {
        "proposals": 15,
        "level_bound_interventions": 15,
        "confirmed_interventions": 14,
        "releases": 15,
        "confirmed_releases": 14,
        "level_bound_unobserved_releases": 1,
        "opposite_assignments": 0,
        "foreign_assignments": 4,
        "renotifications": 0,
        "live_tokens": 0,
        "omitted_event_count": 0,
    }
    assert ownership["origin_counts"] == {
        "PREFIX": {"proposals": 11, "level_bound": 11, "confirmed": 10, "releases": 11},
        "RANK_ORIGINAL": {
            "proposals": 4,
            "level_bound": 4,
            "confirmed": 4,
            "releases": 4,
        },
        "RANK_CONTRAST": {
            "proposals": 0,
            "level_bound": 0,
            "confirmed": 0,
            "releases": 0,
        },
        "FRONTIER_INITIAL": {
            "proposals": 0,
            "level_bound": 0,
            "confirmed": 0,
            "releases": 0,
        },
        "FRONTIER_CONTRAST": {
            "proposals": 0,
            "level_bound": 0,
            "confirmed": 0,
            "releases": 0,
        },
    }
    variable_130_events = [
        (
            event["kind"],
            event["token"],
            event["origin"],
            event["literal"],
            event["level"],
            event["observed_literal"],
        )
        for event in ownership["events"]
        if abs(event["literal"]) == 130 or abs(event["observed_literal"]) == 130
    ]
    assert variable_130_events == [
        ("PROPOSED", 1, "PREFIX", 130, 0, 0),
        ("LEVEL_BOUND", 1, "PREFIX", 130, 1, 0),
        ("LEVEL_BOUND_UNOBSERVED_RELEASE", 1, "PREFIX", 130, 0, 0),
        ("FOREIGN_ASSIGNMENT", 0, "NONE", -130, 0, -130),
    ]
    assert (
        cast(
            int,
            sieve_v20.validate_native_lifecycle(payload)["central_callback_calls"],
        )
        >= 1
    )


def test_complete_replay_rejects_coherent_genuine_payload_adversaries(
    native_fixture: Path,
    tmp_path: Path,
) -> None:
    artifacts = _artifacts(tmp_path)
    payload = _native_payload(native_fixture, artifacts)
    original = cast(dict[str, Any], payload["decision_ownership"])
    events = cast(list[dict[str, Any]], original["events"])

    orphan = copy.deepcopy(payload)
    orphan_ownership = cast(dict[str, Any], orphan["decision_ownership"])
    orphan_events = cast(list[dict[str, Any]], orphan_ownership["events"])
    removed = [
        event
        for event in orphan_events
        if event["token"] == 15 and event["kind"] != "PROPOSED"
    ]
    assert [event["kind"] for event in removed] == [
        "LEVEL_BOUND",
        "CONFIRMED",
        "RELEASED",
    ]
    orphan_ownership["events"] = [
        event
        for event in orphan_events
        if not (event["token"] == 15 and event["kind"] != "PROPOSED")
    ]
    orphan_ownership["level_bound_interventions"] -= 1
    orphan_ownership["confirmed_interventions"] -= 1
    orphan_ownership["releases"] -= 1
    orphan_ownership["confirmed_releases"] -= 1
    origin = cast(str, removed[0]["origin"])
    orphan_ownership["origin_counts"][origin]["level_bound"] -= 1
    orphan_ownership["origin_counts"][origin]["confirmed"] -= 1
    orphan_ownership["origin_counts"][origin]["releases"] -= 1
    _renumber_ownership_events(orphan_ownership)

    overlap = copy.deepcopy(payload)
    overlap_ownership = cast(dict[str, Any], overlap["decision_ownership"])
    overlap_events = cast(list[dict[str, Any]], overlap_ownership["events"])
    first_proposal = next(
        index
        for index, event in enumerate(overlap_events)
        if event["kind"] == "PROPOSED"
    )
    second_proposal = next(
        dict(event)
        for event in events
        if event["kind"] == "PROPOSED" and event["token"] == 2
    )
    _insert_proposal(
        overlap_ownership,
        index=first_proposal + 1,
        proposal=second_proposal,
    )

    pending_release = copy.deepcopy(payload)
    pending_ownership = cast(dict[str, Any], pending_release["decision_ownership"])
    pending_events = cast(list[dict[str, Any]], pending_ownership["events"])
    first_release = next(
        index
        for index, event in enumerate(pending_events)
        if event["kind"] in {"RELEASED", "LEVEL_BOUND_UNOBSERVED_RELEASE"}
    )
    _insert_proposal(
        pending_ownership,
        index=first_release,
        proposal=dict(second_proposal),
    )

    foreign_live = copy.deepcopy(payload)
    foreign_ownership = cast(dict[str, Any], foreign_live["decision_ownership"])
    foreign_events = cast(list[dict[str, Any]], foreign_ownership["events"])
    first_bound = next(
        index
        for index, event in enumerate(foreign_events)
        if event["kind"] == "LEVEL_BOUND" and event["token"] == 1
    )
    forged_foreign = {
        "sequence": 0,
        "kind": "FOREIGN_ASSIGNMENT",
        "token": 0,
        "callback": 0,
        "origin": "NONE",
        "row": 0,
        "literal": -130,
        "level": 1,
        "observed_literal": -130,
    }
    foreign_events.insert(first_bound + 1, forged_foreign)
    foreign_ownership["foreign_assignments"] += 1
    _renumber_ownership_events(foreign_ownership)

    zero_literal = copy.deepcopy(payload)
    zero_events = cast(
        list[dict[str, Any]], zero_literal["decision_ownership"]["events"]
    )
    next(event for event in zero_events if event["kind"] == "PROPOSED")["literal"] = 0

    origin_mismatch = copy.deepcopy(payload)
    mismatch_ownership = cast(dict[str, Any], origin_mismatch["decision_ownership"])
    mismatch_events = cast(list[dict[str, Any]], mismatch_ownership["events"])
    source_origin = next(
        cast(str, event["origin"]) for event in mismatch_events if event["token"] == 15
    )
    target_origin = "FRONTIER_INITIAL"
    origin_field = {
        "PROPOSED": "proposals",
        "LEVEL_BOUND": "level_bound",
        "CONFIRMED": "confirmed",
        "RELEASED": "releases",
        "LEVEL_BOUND_UNOBSERVED_RELEASE": "releases",
    }
    for event in mismatch_events:
        if event["token"] != 15:
            continue
        field = origin_field.get(cast(str, event["kind"]))
        if field is not None:
            mismatch_ownership["origin_counts"][source_origin][field] -= 1
            mismatch_ownership["origin_counts"][target_origin][field] += 1
        event["origin"] = target_origin

    release_mismatch = copy.deepcopy(payload)
    mismatch_central = cast(dict[str, Any], release_mismatch["central_reader"])
    release_payload = bytes.fromhex(cast(str, mismatch_central["release_sequence_hex"]))
    release_literals = list(
        struct.unpack(f"<{len(release_payload) // 4}i", release_payload)
    )
    assert release_literals and release_literals[0]
    release_literals[0] = -release_literals[0]
    forged_release_payload = struct.pack(
        f"<{len(release_literals)}i", *release_literals
    )
    mismatch_central["release_sequence_hex"] = forged_release_payload.hex()
    mismatch_central["release_sequence_sha256"] = hashlib.sha256(
        forged_release_payload
    ).hexdigest()

    for mutated in (
        orphan,
        overlap,
        pending_release,
        foreign_live,
        zero_literal,
        origin_mismatch,
        release_mismatch,
    ):
        with pytest.raises(O1RelationalSearchError):
            _parse(mutated, artifacts)
        with pytest.raises(O1RelationalSearchError):
            sieve_v20.validate_native_lifecycle(mutated)


def test_public_runner_retains_parser_failure_telemetry(
    native_fixture: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = _artifacts(tmp_path)
    monkeypatch.setattr(
        sieve_v20,
        "derive_production_vault_ranked_decision",
        lambda *_args: artifacts.decision,
    )
    executor = sieve_v20._v9._v8._v7
    original_execute = executor._execute_native
    forged_stdout = ""

    def execute_then_forge(
        command: list[str],
        *,
        timeout_seconds: float,
        memory_limit_bytes: int | None,
    ) -> object:
        nonlocal forged_stdout
        execution = original_execute(
            command,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
        )
        payload = json.loads(execution.completed.stdout)
        payload["central_reader"]["potential_source_sha256"] = "00" * 32
        forged_stdout = json.dumps(payload)
        completed = subprocess.CompletedProcess(
            execution.completed.args,
            execution.completed.returncode,
            forged_stdout,
            execution.completed.stderr,
        )
        return executor._NativeExecution(completed, execution.memory_samples)

    monkeypatch.setattr(executor, "_execute_native", execute_then_forge)
    with pytest.raises(sieve_v20.JointScoreSieveExecutionError) as raised:
        sieve_v20.run_joint_score_sieve(
            executable=native_fixture,
            cnf_path=artifacts.cnf,
            potential_path=artifacts.potential,
            grouping_path=artifacts.grouping_path,
            rank_vault_path=artifacts.rank_vault_path,
            vault_path=artifacts.active_vault_path,
            frontier_plan_path=artifacts.frontier_plan_path,
            staging_plan_path=artifacts.staging_plan_path,
            prefix_plan_path=artifacts.prefix_plan_path,
            vault_caps=O1C66_VAULT_CAPS,
            threshold=12.0,
            conflict_limit=64,
            seed=0,
            timeout_seconds=10.0,
        )
    telemetry = raised.value.failure_telemetry
    assert telemetry["classification_kind"] == "adapter_or_parser"
    assert telemetry["phase"] == "adapter_validation"
    assert telemetry["returncode"] == 0
    assert telemetry["stdout"] == forged_stdout
    assert "--rank-table" in cast(list[str], telemetry["command"])


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("decision_ownership", "omitted_event_count"), 1),
        (("decision_ownership", "origin_counts", "PREFIX", "releases"), 99),
        (("central_reader", "prefix", "cursor"), 10),
        (("central_reader", "potential_source_sha256"), "00" * 32),
    ],
)
def test_adapter_rejects_ownership_or_stage_mutation(
    native_fixture: Path,
    tmp_path: Path,
    path: tuple[str, ...],
    value: object,
) -> None:
    artifacts = _artifacts(tmp_path)
    payload = _native_payload(native_fixture, artifacts)
    mutated = copy.deepcopy(payload)
    target: dict[str, Any] = mutated
    for name in path[:-1]:
        target = target[name]
    target[path[-1]] = value
    with pytest.raises(O1RelationalSearchError):
        _parse(mutated, artifacts)


def test_production_seal_is_page6_only() -> None:
    source = NATIVE_SOURCE.read_text(encoding="utf-8")
    assert "69bde6adc23e9e89f97581175ecb85dc9f1d94cddc6d162dfb2f93f9d60f3846" in source
    assert "785cae9e32912e1d45858d046b36a7c7b9e4cf51799f233a7b3246aa6756ad65" in source
    assert "c536a94483467ee1197d52e0e3f81ad2f728a36ad3982124e1b9966e0011f927" in source
    assert (
        "8a263e555b4b5a69d3c9a937cac3e7702a1f8e3de27db4feffc2d21563a24da1" not in source
    )
    assert (
        "ecbca2bd3ab2e5196d4cae76a968c7957909ada49e4d225d28841a4c21d2e023" not in source
    )
