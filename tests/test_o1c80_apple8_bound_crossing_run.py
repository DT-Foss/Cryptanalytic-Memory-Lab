from __future__ import annotations

import copy
import gzip
import hashlib
import json
import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Mapping, cast

import pytest

import o1_crypto_lab.o1c80_apple8_bound_crossing_run as crossing_run
from o1_crypto_lab.causal_attic_v1 import canonical_json_bytes
from o1_crypto_lab.o1c80_apple8_bound_crossing_prepare import (
    EXPECTED_PREPARED_MANIFEST_SHA256,
    PreparedBoundCrossing,
    load_prepared_bound_crossing,
)
from o1_crypto_lab.threshold_no_good_vault_v1 import (
    THRESHOLD_NO_GOOD_VAULT_MAGIC,
    ThresholdNoGoodClause,
)

import test_joint_score_sieve_v21 as v21_fixtures


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / crossing_run.CONFIG_RELATIVE
CHECKED_PREPARATION = ROOT / crossing_run.PREPARATION_DIRECTORY_RELATIVE


@pytest.fixture(scope="module")
def prepared() -> PreparedBoundCrossing:
    return load_prepared_bound_crossing(
        CHECKED_PREPARATION,
        expected_manifest_sha256=EXPECTED_PREPARED_MANIFEST_SHA256,
    )


def _f64(value: float) -> str:
    return struct.pack("<d", value).hex()


def _clause_sha(literals: tuple[int, ...]) -> str:
    payload = struct.pack("<I", len(literals)) + b"".join(
        struct.pack("<i", literal) for literal in literals
    )
    return hashlib.sha256(payload).hexdigest()


def _novel_no_good(prepared: PreparedBoundCrossing, variable: int) -> tuple[int, ...]:
    known = {clause.serialized for clause in prepared.state.attic.union_vault.clauses}
    for other in range(1, 257):
        if other == variable:
            continue
        literals = tuple(sorted((variable, other), key=abs))
        clause = ThresholdNoGoodClause(literals)
        if clause.serialized not in known:
            return literals
    raise AssertionError("synthetic novel no-good unavailable")


def _telemetry(
    prepared: PreparedBoundCrossing, literals: tuple[int, ...] | None
) -> dict[str, object]:
    active = prepared.state.active_projection
    rows: list[dict[str, object]] = []
    aggregate = b""
    if literals is not None:
        clause = ThresholdNoGoodClause(literals)
        witness = struct.pack("<d", crossing_run.THRESHOLD - 1.0)
        aggregate = clause.serialized
        rows.append(
            {
                "classification": "new",
                "clause_sha256": clause.sha256,
                "index": 0,
                "literal_count": clause.literal_count,
                "literals": list(literals),
                "source": "trail_upper_bound",
                "witness_score": crossing_run.THRESHOLD - 1.0,
                "witness_score_f64le_hex": witness.hex(),
                "witness_sha256": hashlib.sha256(
                    b"\x01" + witness + clause.serialized
                ).hexdigest(),
            }
        )
    literal_count = sum(len(cast(list[int], row["literals"])) for row in rows)
    return {
        "schema": "o1-256-cadical-score-threshold-no-good-vault-telemetry-v1",
        "binary_magic_hex": THRESHOLD_NO_GOOD_VAULT_MAGIC.hex(),
        "input_cnf_sha256": active.identity.cnf_sha256,
        "input_potential_sha256": active.identity.potential_sha256,
        "input_grouping_sha256": active.identity.grouping_sha256,
        "input_observed_variables_sha256": active.identity.observed_variables_sha256,
        "input_bound_rule_sha256": active.identity.bound_rule_sha256,
        "input_threshold_f64le_hex": active.identity.threshold_f64le_hex,
        "input_sha256": active.sha256,
        "input_clause_count": active.clause_count,
        "input_literal_count": active.literal_count,
        "input_serialized_bytes": active.serialized_bytes,
        "input_clause_aggregate_sha256": active.clause_aggregate_sha256,
        "fully_emitted_clauses": rows,
        "fully_emitted_clause_count": len(rows),
        "fully_emitted_literal_count": literal_count,
        "fully_emitted_aggregate_sha256": hashlib.sha256(aggregate).hexdigest(),
        "emitted_new_clause_count": len(rows),
        "emitted_new_literal_count": literal_count,
        "emitted_input_duplicate_clause_count": 0,
        "emitted_input_duplicate_literal_count": 0,
        "emitted_current_duplicate_clause_count": 0,
        "emitted_current_duplicate_literal_count": 0,
        "terminal_empty_clause_count": 0,
    }


def _native_result(
    prepared: PreparedBoundCrossing,
    *,
    both: bool = False,
    realized: bool = True,
) -> SimpleNamespace:
    reader, ownership, sieve, _ = copy.deepcopy(v21_fixtures._payload())
    candidates, ranked = crossing_run._candidate_order(prepared)
    variable = candidates[0]
    zero = crossing_run.THRESHOLD - 1.0
    one = crossing_run.THRESHOLD - 1.0 if both else crossing_run.THRESHOLD + 1.0
    selection = "BOTH_PRUNABLE" if both else "ZERO_PRUNABLE"
    candidate_payload = b"".join(struct.pack("<i", item) for item in candidates)

    reader.update(
        threshold=crossing_run.THRESHOLD,
        threshold_f64le_hex=_f64(crossing_run.THRESHOLD),
        candidate_count=len(candidates),
        ranked_candidate_count=ranked,
        omitted_candidate_count=len(candidates) - ranked,
        minimum_child_upper=zero,
        minimum_child_upper_f64le_hex=_f64(zero),
        minimum_child_margin=-1.0,
        minimum_child_variable=variable,
        minimum_upper_zero=zero,
        minimum_upper_zero_f64le_hex=_f64(zero),
        minimum_upper_one=one,
        minimum_upper_one_f64le_hex=_f64(one),
        candidate_order_count=len(candidates),
        candidate_order_bytes=len(candidate_payload),
        candidate_order_hex=candidate_payload.hex(),
        candidate_order_sha256=hashlib.sha256(candidate_payload).hexdigest(),
    )
    reader["class_counts"] = {
        "NEITHER_PRUNABLE": 0,
        "ZERO_PRUNABLE": int(not both),
        "ONE_PRUNABLE": 0,
        "BOTH_PRUNABLE": int(both),
    }
    probe = cast(dict[str, object], reader["probe_events"][0])
    intervention = cast(dict[str, object], reader["interventions"][0])
    for row in (probe, intervention):
        row.update(
            variable=variable,
            upper_zero=zero,
            upper_zero_f64le_hex=_f64(zero),
            upper_one=one,
            upper_one_f64le_hex=_f64(one),
            threshold=crossing_run.THRESHOLD,
            threshold_f64le_hex=_f64(crossing_run.THRESHOLD),
            selection_class=selection,
            losing_bit=0,
            losing_spin=-1,
            losing_literal=-variable,
        )
    witness = {
        name: copy.deepcopy(value)
        for name, value in probe.items()
        if name != "proposal_token"
    }
    reader["minimum_witness"] = witness
    trace = b"".join(
        (
            struct.pack("<Q", cast(int, probe["call"])),
            struct.pack("<Q", cast(int, probe["probe"])),
            struct.pack("<I", cast(int, probe["coordinate_index"])),
            struct.pack("<I", cast(int, probe["parent_level"])),
            struct.pack("<i", variable),
            struct.pack("<d", zero),
            struct.pack("<d", one),
            struct.pack("<d", crossing_run.THRESHOLD),
            bytes((3 if both else 1,)),
            struct.pack("<i", -variable),
        )
    )
    reader["probe_trace_bytes"] = len(trace)
    reader["probe_trace_sha256"] = hashlib.sha256(trace).hexdigest()
    for event in cast(list[dict[str, object]], ownership["events"]):
        event["literal"] = -variable
        if event["kind"] == "CONFIRMED":
            event["observed_literal"] = -variable

    no_good = _novel_no_good(prepared, variable)
    no_good_sha = _clause_sha(no_good)
    intervention["observed_literal"] = -variable
    intervention["no_good_literals"] = list(no_good)
    intervention["no_good_clause_sha256"] = no_good_sha
    intervention["v6_pending_clause_sha256_after"] = no_good_sha
    if not realized:
        intervention.update(
            matching_assignment_observed=False,
            observed_literal=None,
            v6_threshold_prunes_after=4,
            v6_trail_threshold_prunes_after=4,
            v6_external_clauses_queued_after=4,
            v6_pending_clause_count_after=0,
            v6_pending_clause_sha256_after=None,
            v6_trace_sha256_after=intervention["v6_trace_sha256_before"],
            no_good_literals=[],
            no_good_clause_sha256=None,
            fully_emitted=False,
            fully_emitted_index=None,
            realized_prune=False,
            unobserved_release=True,
        )
        reader.update(
            matching_assignments_observed=0,
            realized_prunes=0,
            fully_emitted_prunes=0,
            unobserved_releases=1,
        )
        events = cast(list[dict[str, object]], ownership["events"])
        ownership["events"] = [
            events[0],
            events[1],
            {**events[3], "sequence": 3, "kind": "LEVEL_BOUND_UNOBSERVED_RELEASE"},
        ]
        ownership["confirmed_interventions"] = 0
        ownership["confirmed_releases"] = 0
        ownership["level_bound_unobserved_releases"] = 1
        ownership["confirmed_activated"] = False
        ownership["event_count"] = 3
        ownership["recorded_event_count"] = 3
        origin_counts = cast(dict[str, dict[str, object]], ownership["origin_counts"])
        origin_counts["BOUND_LOSING_CHILD"]["confirmed"] = 0
    telemetry = _telemetry(prepared, no_good if realized else None)
    sieve["pending_clause_count"] = 0
    raw = {
        "schema": "synthetic-v18",
        "central_reader": {"schema": crossing_run._native_v21.CENTRAL_READER_SCHEMA},
        "decision_ownership": ownership,
        "one_bit_bound_reader": reader,
        "vault": telemetry,
        "sieve": sieve,
    }
    stdout = json.dumps(raw, separators=(",", ":"), ensure_ascii=True) + " \n"
    active = prepared.state.active_projection
    return SimpleNamespace(
        raw=raw,
        native_stdout=stdout,
        native_stdout_sha256=hashlib.sha256(stdout.encode()).hexdigest(),
        central_reader=raw["central_reader"],
        decision_ownership=ownership,
        one_bit_bound_reader=reader,
        vault_telemetry=telemetry,
        stats={
            "conflicts": 128,
            "conflicts_before_solve": 0,
            "solve_conflicts": 128,
            "decisions": 64,
            "propagations": 1024,
            "requested_conflicts": 128,
            "unused_requested_conflicts": 0,
            "conflict_limit_overshoot": 0,
            "billed_conflicts": 128,
        },
        resources={
            "peak_rss_bytes": 1_000_000,
            "wall_microseconds": 1_000,
            "cpu_microseconds": 900,
        },
        sieve=sieve,
        status=0,
        key_model=None,
        conflict_limit=128,
        threshold=crossing_run.THRESHOLD,
        rank_source_vault=crossing_run._prepared_rank_source(prepared),
        input_vault=active,
        frontier_plan=prepared.frontier_plan,
        staging_plan=prepared.staging_plan,
        prefix_preemption_plan=prepared.prefix_plan,
    )


def _validated(
    *,
    probe: bool = True,
    crossing: bool = False,
    science: bool = False,
    realized: int = 0,
    emitted: int = 0,
    both: int = 0,
    novel: int = 0,
) -> dict[str, object]:
    central = {"schema": "synthetic-central"}
    ownership = {"schema": "synthetic-ownership"}
    reader = {"schema": "synthetic-reader"}
    telemetry = {"schema": "synthetic-telemetry"}
    raw = {
        "schema": "synthetic-v18",
        "central_reader": central,
        "decision_ownership": ownership,
        "one_bit_bound_reader": reader,
        "vault": telemetry,
    }
    stdout = json.dumps(raw, separators=(",", ":"), sort_keys=False).encode() + b" \n"
    return {
        "raw": raw,
        "raw_stdout": stdout,
        "central_reader": central,
        "decision_ownership": ownership,
        "one_bit_bound_reader": reader,
        "telemetry": telemetry,
        "stats": {
            "conflicts": 128,
            "conflicts_before_solve": 0,
            "solve_conflicts": 128,
            "decisions": 64,
            "propagations": 1024,
            "requested_conflicts": 128,
            "unused_requested_conflicts": 0,
            "conflict_limit_overshoot": 0,
            "billed_conflicts": 128,
        },
        "resources": {
            "peak_rss_bytes": 1_000_000,
            "wall_microseconds": 1_000,
            "cpu_microseconds": 900,
        },
        "status": 0,
        "key_model": None,
        "globally_novel_clause_sha256": [f"{index + 1:064x}" for index in range(novel)],
        "realized_prunes": realized,
        "fully_emitted_prunes": emitted,
        "both_child_closures": both,
        "exact_probe": {
            "exact_probe_operation": probe,
            "probe_count": int(probe),
            "minimum_child_upper_alone_is_science_gain": False,
        },
        "crossing": {
            "crossing_activation": crossing,
            "crossing_count": int(crossing),
        },
        "science": {
            "science_gain": science,
            "lower_minimum_alone_is_science_gain": False,
        },
    }


def _execute(
    capsule: Path,
    prepared: PreparedBoundCrossing,
    invoke: crossing_run.EpisodeInvoker,
) -> crossing_run.BoundCrossingOutcome:
    capsule.mkdir()
    return crossing_run.execute_episode(
        capsule=capsule,
        prepared=prepared,
        invoke_episode=invoke,
        verify_public_model=lambda model: model == b"k" * 32,
        bindings={"test_fixture": "synthetic-target-free"},
    )


def test_checked_config_is_canonical_and_production_rejects_pending_before_io(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = crossing_run.load_config(CONFIG)
    assert config["schema"] == crossing_run.CONFIG_SCHEMA
    assert config["budgets"] == {
        "active_clause_limit": 256,
        "lineage_call_ordinals": [20],
        "local_episode_ordinals": [0],
        "maximum_fresh_reveal_calls": 0,
        "maximum_fresh_targets": 0,
        "maximum_gpu_calls": 0,
        "maximum_mps_calls": 0,
        "maximum_native_solver_calls": 1,
        "maximum_persistent_artifact_bytes": 134_217_728,
        "maximum_refits": 0,
        "maximum_scientific_entropy_calls": 0,
        "maximum_total_requested_conflicts": 128,
        "memory_limit_bytes": 536_870_912,
        "minimum_disk_free_bytes": 1_073_741_824,
        "replay_authorized": False,
        "requested_conflicts_per_episode": 128,
        "retry_authorized": False,
        "sweep_authorized": False,
        "timeout_seconds": 45.0,
    }
    pending = copy.deepcopy(config)
    cast(dict[str, object], pending["source"])["expected_commit"] = "PENDING"
    pending_path = tmp_path / "pending-config.json"
    pending_path.write_bytes(canonical_json_bytes(pending))
    assert crossing_run._pending_fields(pending)
    monkeypatch.setattr(
        crossing_run,
        "_relative",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("PENDING preflight touched a sealed input")
        ),
    )
    with pytest.raises(crossing_run.O1C80RunError, match="contains PENDING"):
        crossing_run.preflight(pending_path, root=tmp_path)


def test_pending_target_free_receipt_authorizes_nothing() -> None:
    path = ROOT / crossing_run.TARGET_FREE_PREFLIGHT_RELATIVE
    payload = path.read_bytes()
    receipt = json.loads(payload)
    assert canonical_json_bytes(receipt) == payload
    assert receipt["status"] in {"PENDING", "PASS"}
    assert receipt["native_solver_calls"] == 0
    assert receipt["truth_key_bytes_read"] is False
    expected_authorization = {
        "intent_created": False,
        "lineage20_burned": False,
        "page7_burned": False,
        "production_call_authorized": receipt["status"] == "PASS",
        "retry_sweep_or_replay_authorized": False,
    }
    assert receipt["authorization"] == expected_authorization


@pytest.mark.parametrize(
    "mutated",
    ("config", "cnf", "potential", "grouping", "o1c73_config", "gate"),
)
def test_call_window_rejects_every_post_preflight_path_mutation_before_invoke(
    tmp_path: Path, mutated: str
) -> None:
    config_file = tmp_path / "config.json"
    config_file.write_bytes(canonical_json_bytes({"frozen": True}))
    input_rows: dict[str, object] = {}
    approved: dict[str, str] = {}
    for name in ("cnf", "potential", "grouping", "o1c73_config"):
        path = tmp_path / name
        path.write_bytes(f"sealed-{name}".encode())
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        input_rows[name] = name
        input_rows[f"{name}_sha256"] = digest
        approved[name] = digest
    gate = tmp_path / "gate.json"
    gate.write_bytes(canonical_json_bytes({"status": "PASS"}))
    gate_sha256 = hashlib.sha256(gate.read_bytes()).hexdigest()
    gate_row = {"path": gate.name, "sha256": gate_sha256}
    preflight_row = {
        "config_sha256": hashlib.sha256(config_file.read_bytes()).hexdigest(),
        "input_sha256": approved,
        "target_free_preflight_sha256": gate_sha256,
    }
    crossing_run._validate_frozen_call_inputs(
        root=tmp_path,
        config_file=config_file,
        inputs=input_rows,
        target_free_gate=gate_row,
        preflight_row=preflight_row,
        when="before capsule",
    )
    changed = (
        config_file
        if mutated == "config"
        else gate
        if mutated == "gate"
        else tmp_path / mutated
    )
    changed.write_bytes(changed.read_bytes() + b"x")
    native_calls: list[int] = []
    with pytest.raises(crossing_run.O1C80RunError, match="changed"):
        crossing_run._validate_frozen_call_inputs(
            root=tmp_path,
            config_file=config_file,
            inputs=input_rows,
            target_free_gate=gate_row,
            preflight_row=preflight_row,
            when="before capsule",
        )
        native_calls.append(1)
    assert native_calls == []


def test_sibling_gate_matches_production_argv_without_search_false_positives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = "\n".join(
        (
            "111 /tmp/build/o1c80/native-joint-score-sieve --cnf input.cnf",
            "112 /tmp/cadical_o1_joint_score_sieve_v18 --cnf fixture.cnf",
            "113 rg native-joint-score-sieve",
            "114 pytest -k cadical_o1_joint_score_sieve",
            "115 /usr/bin/python test_native-joint-score-sieve.py",
            "116 /tmp/build/o1c80/native-joint-score-sieve --cnf current.cnf",
        )
    )
    monkeypatch.setattr(crossing_run.os, "getpid", lambda: 116)
    monkeypatch.setattr(
        crossing_run.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout=output),
    )
    assert crossing_run._sibling_solver_pids() == (111, 112)


def test_real_page7_preparation_and_candidate_census_are_exact(
    prepared: PreparedBoundCrossing,
) -> None:
    crossing_run._validate_prepared_contract(prepared)
    candidates, ranked = crossing_run._candidate_order(prepared)
    assert len(candidates) == 255
    assert ranked == 255
    assert candidates[0] == 158
    assert 241 not in candidates
    assert len(set(candidates)) == len(candidates)


@pytest.mark.parametrize(
    (
        "status",
        "both",
        "realized",
        "emitted",
        "novel",
        "crossing",
        "probe",
        "classification",
    ),
    (
        (10, 0, 0, 0, 0, False, False, crossing_run.PUBLIC_EXACT_RECOVERY),
        (20, 0, 0, 0, 0, False, False, crossing_run.THRESHOLD_REGION_EXHAUSTED),
        (0, 1, 0, 0, 0, True, True, crossing_run.BOTH_CHILD_CLOSURE_GAIN),
        (0, 0, 1, 1, 0, True, True, crossing_run.REALIZED_PRUNE_GAIN),
        (0, 0, 0, 0, 1, False, True, crossing_run.NOVEL_CLAUSE_GAIN),
        (0, 0, 0, 0, 0, True, True, crossing_run.CROSSING_MECHANISM_ONLY),
        (0, 0, 0, 0, 0, False, True, crossing_run.PROBE_OPERATION_ONLY),
        (0, 0, 0, 0, 0, False, False, crossing_run.NO_OPERATION),
    ),
)
def test_classification_precedence_preserves_independent_axes(
    status: int,
    both: int,
    realized: int,
    emitted: int,
    novel: int,
    crossing: bool,
    probe: bool,
    classification: str,
) -> None:
    observed, _ = crossing_run._classify_completed_episode(
        status=status,
        both_child_closures=both,
        realized_prunes=realized,
        fully_emitted_prunes=emitted,
        globally_novel_clauses=novel,
        crossing_activation=crossing,
        exact_probe_operation=probe,
    )
    assert observed == classification


def test_lower_minimum_and_crossing_alone_are_not_science() -> None:
    only_minimum = crossing_run._science_gain_evidence(
        status=0,
        public_model_verified=False,
        realized_prunes=0,
        fully_emitted_prunes=0,
        both_child_closures=0,
        globally_novel_clauses=0,
        minimum_child_upper=-1_000.0,
    )
    assert only_minimum["science_gain"] is False
    assert only_minimum["lower_minimum_alone_is_science_gain"] is False
    assert only_minimum["crossing_proposal_alone_is_science_gain"] is False


@pytest.mark.parametrize(
    ("both", "realized", "probe", "crossing", "science"),
    (
        (False, True, True, True, True),
        (False, False, True, True, False),
        (True, False, True, True, True),
    ),
)
def test_full_v21_validation_distinguishes_crossing_from_science(
    prepared: PreparedBoundCrossing,
    both: bool,
    realized: bool,
    probe: bool,
    crossing: bool,
    science: bool,
) -> None:
    native = _native_result(prepared, both=both, realized=realized)
    validated = crossing_run._validated_episode_result(
        native,
        prepared=prepared,
        active=prepared.state.active_projection,
        stream_id="o1c80-runner-fixture",
        verify_public_model=lambda _model: False,
        require_concrete_result=False,
    )
    probe_axis = cast(Mapping[str, object], validated["exact_probe"])
    crossing_axis = cast(Mapping[str, object], validated["crossing"])
    science_axis = cast(Mapping[str, object], validated["science"])
    assert probe_axis["exact_probe_operation"] is probe
    assert crossing_axis["crossing_activation"] is crossing
    assert science_axis["science_gain"] is science
    assert validated["raw_stdout"] == native.native_stdout.encode()
    if both and not realized:
        assert validated["both_child_closures"] == 1
        assert validated["realized_prunes"] == 0
    if not both and not realized:
        assert validated["globally_novel_clause_sha256"] == []


def test_adapter_stdout_digest_and_projection_tamper_are_rejected(
    prepared: PreparedBoundCrossing,
) -> None:
    native = _native_result(prepared)
    native.native_stdout_sha256 = "00" * 32
    with pytest.raises(crossing_run.O1C80RunError, match="stdout digest"):
        crossing_run._validated_episode_result(
            native,
            prepared=prepared,
            active=prepared.state.active_projection,
            stream_id="tamper",
            verify_public_model=lambda _model: False,
            require_concrete_result=False,
        )


def test_one_call_intent_and_raw_stdout_are_durable_before_claim(
    tmp_path: Path,
    prepared: PreparedBoundCrossing,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validated = _validated(probe=True, crossing=True, science=False)
    monkeypatch.setattr(
        crossing_run, "_validated_episode_result", lambda *_args, **_kwargs: validated
    )
    calls: list[tuple[int, int]] = []

    def invoke(
        local: int,
        lineage: int,
        _rank: Path,
        active: Path,
        _frontier: Path,
        _staging: Path,
        _prefix: Path,
    ) -> object:
        intent = active.parent / "intent.json"
        assert intent.is_file()
        assert intent.stat().st_mode & 0o222 == 0
        assert json.loads(intent.read_bytes())["requested_conflicts"] == 128
        calls.append((local, lineage))
        return object()

    outcome = _execute(tmp_path / "straight", prepared, invoke)
    assert calls == [(0, 20)]
    assert outcome.classification == crossing_run.CROSSING_MECHANISM_ONLY
    assert outcome.native_calls == 1
    assert outcome.requested_conflicts == 128
    assert outcome.actual_conflicts == 128
    assert outcome.billed_conflicts == 128
    assert outcome.exact_probe_operation is True
    assert outcome.crossing_activation is True
    assert outcome.science_gain is False
    evidence = cast(Mapping[str, object], outcome.episodes[0]["native_stdout_evidence"])
    compressed = tmp_path / "straight/episodes/00" / cast(str, evidence["path"])
    assert gzip.decompress(compressed.read_bytes()) == validated["raw_stdout"]
    assert not (tmp_path / "straight/episodes/01").exists()


def test_pre_call_and_call_failures_burn_without_false_work_claims(
    tmp_path: Path,
    prepared: PreparedBoundCrossing,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, int]] = []

    def reject(_binding: object, *, when: str) -> None:
        assert when == "before"
        raise crossing_run.O1C80RunError("synthetic pre-call seal")

    monkeypatch.setattr(crossing_run, "_validate_call_window_executable", reject)
    before = _execute(
        tmp_path / "pre-call",
        prepared,
        cast(
            crossing_run.EpisodeInvoker,
            lambda local, lineage, *_args: calls.append((local, lineage)),
        ),
    )
    assert calls == []
    assert before.native_calls == 0
    assert before.requested_conflicts == 0
    assert before.actual_conflicts is None
    failure = cast(Mapping[str, object], before.episodes[0]["terminal_failure"])
    assert failure["phase"] == "PRE_CALL"
    assert failure["page7_burned"] is True
    assert failure["lineage_burned"] is True

    monkeypatch.setattr(
        crossing_run,
        "_validate_call_window_executable",
        lambda _binding, *, when: None,
    )

    def fail(local: int, lineage: int, *_args: object) -> object:
        calls.append((local, lineage))
        raise RuntimeError("synthetic native failure")

    during = _execute(
        tmp_path / "call", prepared, cast(crossing_run.EpisodeInvoker, fail)
    )
    assert calls == [(0, 20)]
    assert during.native_calls == 1
    assert during.requested_conflicts == 128
    assert during.actual_conflicts is None
    assert during.billed_conflicts is None
    failure = cast(Mapping[str, object], during.episodes[0]["terminal_failure"])
    assert failure["phase"] == "CALL"


def test_invalid_post_call_result_suppresses_axes_and_actual_work(
    tmp_path: Path,
    prepared: PreparedBoundCrossing,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        crossing_run,
        "_validated_episode_result",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            crossing_run.O1C80RunError("invalid returned evidence")
        ),
    )
    outcome = _execute(
        tmp_path / "post-call",
        prepared,
        cast(crossing_run.EpisodeInvoker, lambda *_args: object()),
    )
    assert outcome.native_calls == 1
    assert outcome.requested_conflicts == 128
    assert outcome.actual_conflicts is None
    assert outcome.billed_conflicts is None
    assert outcome.exact_probe_operation is False
    assert outcome.crossing_activation is False
    assert outcome.science_gain is False
    failure = cast(Mapping[str, object], outcome.episodes[0]["terminal_failure"])
    assert failure["phase"] == "POST_CALL"
    assert failure["native_result_returned"] is True


def test_recovery_revalidates_exact_stdout_and_issues_no_callbacks(
    tmp_path: Path,
    prepared: PreparedBoundCrossing,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validated = _validated(probe=True, crossing=False, science=False)
    monkeypatch.setattr(
        crossing_run, "_validated_episode_result", lambda *_args, **_kwargs: validated
    )
    capsule = tmp_path / "recover"
    outcome = _execute(
        capsule,
        prepared,
        cast(crossing_run.EpisodeInvoker, lambda *_args: object()),
    )
    result = crossing_run.build_result(
        outcome=outcome,
        capsule_relative="runs/synthetic-o1c80",
        source_commit="ab" * 20,
        started_at="2026-07-20T00:00:00+02:00",
    )
    crossing_run.write_recovery_source(capsule, result)
    monkeypatch.setattr(
        crossing_run._native_v21,
        "run_joint_score_sieve",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("recovery issued a native call")
        ),
    )
    recovered = crossing_run.recover_publication(capsule)
    proof = cast(Mapping[str, object], recovered["publication_recovery"])
    assert proof["native_calls_issued_during_recovery"] == 0
    assert proof["public_verification_calls_issued_during_recovery"] == 0
    assert proof["raw_native_stdout_revalidated_byte_exact"] is True
    crossing_run.write_recovered_publication_source(capsule, recovered)
    assert crossing_run._read_recovered_publication_source(capsule) == recovered


def test_recovery_rejects_raw_stdout_mutation(
    tmp_path: Path,
    prepared: PreparedBoundCrossing,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        crossing_run,
        "_validated_episode_result",
        lambda *_args, **_kwargs: _validated(),
    )
    capsule = tmp_path / "tamper-recover"
    outcome = _execute(
        capsule,
        prepared,
        cast(crossing_run.EpisodeInvoker, lambda *_args: object()),
    )
    result = crossing_run.build_result(
        outcome=outcome,
        capsule_relative="runs/tampered-o1c80",
        source_commit="cd" * 20,
    )
    crossing_run.write_recovery_source(capsule, result)
    episode = cast(Mapping[str, object], outcome.episodes[0])
    evidence = cast(Mapping[str, object], episode["native_stdout_evidence"])
    path = capsule / "episodes/00" / cast(str, evidence["path"])
    path.chmod(0o644)
    original = path.read_bytes()
    path.write_bytes(original[:-1] + bytes((original[-1] ^ 1,)))
    with pytest.raises(crossing_run.O1C80RunError, match="compressed seal"):
        crossing_run.recover_publication(capsule)


def test_recovery_rederives_classification_and_rejects_internal_promotion(
    tmp_path: Path,
    prepared: PreparedBoundCrossing,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        crossing_run,
        "_validated_episode_result",
        lambda *_args, **_kwargs: _validated(probe=True, crossing=False, science=False),
    )
    capsule = tmp_path / "classification-tamper"
    outcome = _execute(
        capsule,
        prepared,
        cast(crossing_run.EpisodeInvoker, lambda *_args: object()),
    )
    result = crossing_run.build_result(
        outcome=outcome,
        capsule_relative="runs/classification-tamper",
        source_commit="ef" * 20,
    )
    source_path = crossing_run.write_recovery_source(capsule, result)
    source = dict(json.loads(source_path.read_bytes()))
    promoted = dict(cast(Mapping[str, object], source["pre_finalization_result"]))
    promoted["classification"] = crossing_run.PUBLIC_EXACT_RECOVERY
    promoted["stop_reason"] = "public-complete-model-exactly-verified"
    promoted_payload = canonical_json_bytes(promoted)
    source["pre_finalization_result"] = promoted
    source["result_sha256"] = hashlib.sha256(promoted_payload).hexdigest()
    source["result_serialized_bytes"] = len(promoted_payload)
    source_path.chmod(0o644)
    source_path.write_bytes(canonical_json_bytes(source))
    with pytest.raises(crossing_run.O1C80RunError, match="conclusion differs"):
        crossing_run.recover_publication(capsule)


def test_result_claim_boundary_has_zero_forbidden_surfaces() -> None:
    outcome = crossing_run.BoundCrossingOutcome(
        crossing_run.PROBE_OPERATION_ONLY,
        "synthetic",
        ({"synthetic": True},),
        1,
        128,
        4,
        4,
        True,
        False,
        False,
        0,
        0,
        0,
        0,
        None,
    )
    result = crossing_run.build_result(
        outcome=outcome,
        capsule_relative="runs/synthetic",
        source_commit="ef" * 20,
    )
    boundary = cast(Mapping[str, object], result["claim_boundary"])
    assert boundary["page7_sha256"] == crossing_run.PAGE7_SHA256
    assert boundary["lineage20_only"] is True
    assert boundary["page6_replayed"] is False
    assert boundary["retry_sweep_or_replay"] is False
    assert boundary["truth_key_bytes_read"] is False
    assert boundary["fresh_targets"] == 0
    assert boundary["fresh_reveal_calls"] == 0
    assert boundary["refits"] == 0
    assert boundary["MPS_or_GPU"] is False
    assert boundary["lower_minimum_alone_is_science_gain"] is False
