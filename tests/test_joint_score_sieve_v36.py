from __future__ import annotations

import copy
import hashlib
import inspect
import shutil
from pathlib import Path
from typing import Mapping, cast

import pytest

import o1_crypto_lab.joint_score_sieve_v36 as sieve
from o1_crypto_lab.o1_relational_search import O1RelationalSearchError


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / sieve.NATIVE_SOURCE_RELATIVE
BUNDLE = ROOT / sieve.O1C108_BUNDLE_RELATIVE
MANIFEST = ROOT / sieve.O1C108_MANIFEST_RELATIVE
PAGE22 = ROOT / sieve.O1C108_PAGE22_RELATIVE
AUDIT = ROOT / sieve.O1C108_CERTIFICATION_AUDIT_RELATIVE
RECEIPT = ROOT / sieve.O1C103_PRIORITY_RECEIPT_RELATIVE
INHERITED_RECEIPT = ROOT / sieve.INHERITED_DERIVED_RECEIPT_RELATIVE
INHERITED_CLOSURE = ROOT / sieve.INHERITED_DERIVED_CLOSURE_RELATIVE
INHERITED_OVERLAY = ROOT / sieve.INHERITED_DERIVED_OVERLAY_RELATIVE
NEW_RECEIPT = ROOT / sieve.NEW_DERIVED_RECEIPT_RELATIVE
NEW_CLOSURE = ROOT / sieve.NEW_DERIVED_CLOSURE_RELATIVE
NEW_OVERLAY = ROOT / sieve.NEW_DERIVED_OVERLAY_RELATIVE
LIVE_BANK = ROOT / sieve.O1C108_LIVE_BANK_RELATIVE
CNF = ROOT / sieve._o1c106.CNF_RELATIVE
POTENTIAL = ROOT / sieve._o1c106.POTENTIAL_RELATIVE
GROUPING = ROOT / sieve._o1c106.GROUPING_RELATIVE


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _action(
    *,
    confirmed: bool = True,
    released: bool = True,
    unobserved_release: bool = False,
) -> dict[str, object]:
    return {
        "token": 1,
        "call": 7,
        "coordinate_index": 12,
        "literal": -13,
        "bound_level": 1,
        "confirmed": confirmed,
        "released": released,
        "unobserved_release": unobserved_release,
    }


def _ownership_fixture() -> tuple[
    dict[str, object], tuple[Mapping[str, object], ...], dict[str, int]
]:
    events = [
        {
            "sequence": 1,
            "kind": "PROPOSED",
            "token": 1,
            "callback": 7,
            "origin": "BOUND_LOSING_CHILD",
            "row": 12,
            "literal": -13,
            "level": 0,
            "observed_literal": 0,
        },
        {
            "sequence": 3,
            "kind": "LEVEL_BOUND",
            "token": 1,
            "callback": 7,
            "origin": "BOUND_LOSING_CHILD",
            "row": 12,
            "literal": -13,
            "level": 1,
            "observed_literal": 0,
        },
        {
            "sequence": 5,
            "kind": "CONFIRMED",
            "token": 1,
            "callback": 7,
            "origin": "BOUND_LOSING_CHILD",
            "row": 12,
            "literal": -13,
            "level": 1,
            "observed_literal": -13,
        },
        {
            "sequence": 6,
            "kind": "RELEASED",
            "token": 1,
            "callback": 7,
            "origin": "BOUND_LOSING_CHILD",
            "row": 12,
            "literal": -13,
            "level": 0,
            "observed_literal": 0,
        },
    ]
    zero_origin = {
        "proposals": 0,
        "level_bound": 0,
        "confirmed": 0,
        "releases": 0,
    }
    origin_counts = {origin: dict(zero_origin) for origin in sieve.OWNERSHIP_ORIGINS}
    origin_counts["BOUND_LOSING_CHILD"] = {
        "proposals": 1,
        "level_bound": 1,
        "confirmed": 1,
        "releases": 1,
    }
    ownership: dict[str, object] = {
        "schema": sieve.OWNERSHIP_SCHEMA,
        "lifecycle": sieve.OWNERSHIP_LIFECYCLE,
        "event_retention": sieve.OWNERSHIP_EVENT_RETENTION,
        "eligibility_rule": sieve.OWNERSHIP_ELIGIBILITY_RULE,
        "assignment_notification_rule": sieve.OWNERSHIP_ASSIGNMENT_RULE,
        "current_level": 0,
        "proposals": 1,
        "level_bound_interventions": 1,
        "confirmed_interventions": 1,
        "releases": 1,
        "confirmed_releases": 1,
        "level_bound_unobserved_releases": 0,
        "opposite_assignments": 1,
        "foreign_assignments": 1,
        "renotifications": 0,
        "live_tokens": 0,
        "pending_tokens": 0,
        "maximum_live_tokens": 1,
        "maximum_tokens": 256,
        "maximum_recorded_lifecycle_events": 1_024,
        "event_count": 6,
        "total_event_count": 6,
        "lifecycle_event_count": 4,
        "recorded_event_count": 4,
        "recorded_lifecycle_event_count": 4,
        "omitted_event_count": 2,
        "compacted_nonclaim_count": 2,
        "events_are_lifecycle_only": True,
        "events_have_global_sequence": True,
        "proposal_activated": True,
        "level_bound_activated": True,
        "confirmed_activated": True,
        "nonclaim_kind_counts": {
            "OPPOSITE_ASSIGNMENT": 1,
            "FOREIGN_ASSIGNMENT": 1,
            "RENOTIFIED": 0,
        },
        "nonclaim_stream_digest": {
            "algorithm": "SHA-256",
            "encoding": sieve.NONCLAIM_DIGEST_ENCODING,
            "record_bytes": sieve.NONCLAIM_DIGEST_RECORD_BYTES,
            "field_layout": sieve.NONCLAIM_DIGEST_LAYOUT,
            "record_count": 2,
            "sha256": "ab" * 32,
        },
        "events": events,
        "origin_counts": origin_counts,
    }
    counts = {
        "action_count": 1,
        "level_bindings": 1,
        "confirmed_actions": 1,
        "releases": 1,
        "unobserved_releases": 0,
    }
    return ownership, (_action(),), counts


def _seed_report() -> dict[str, object]:
    return {
        "magic": sieve.PRIORITY_SEED_MAGIC,
        "schema": sieve.PRIORITY_SEED_SCHEMA,
        "payload_bytes": 24_576,
        "payload_sha256": sieve.LIVE_BANK_SHA256,
        "production_seal_enforced": True,
        "expected_production_sha256": sieve.LIVE_BANK_SHA256,
        "source_priority_state_receipt_sha256": (
            sieve.O1C103_PRIORITY_RECEIPT_SHA256
        ),
        "source_priority_state_receipt_bytes": sieve.O1C103_PRIORITY_RECEIPT_BYTES,
        "source_preparation_manifest_sha256": sieve.O1C108_MANIFEST_SHA256,
        "source_preparation_manifest_bytes": sieve.O1C108_MANIFEST_BYTES,
        "source_derived_resolution_receipt_sha256": (
            sieve.NEW_DERIVED_RECEIPT_SHA256
        ),
        "source_derived_resolution_receipt_bytes": (
            sieve.NEW_DERIVED_RECEIPT_BYTES
        ),
        "seed_source": sieve.PRIORITY_SEED_SOURCE,
        "live_continuation_bank_identity": True,
        "fresh_seed_parser_used": False,
        "import_roundtrip_exact": True,
        "initial_eligible_coordinate_count": 255,
    }


def _empty_breadcrumbs() -> dict[str, object]:
    empty = hashlib.sha256(b"").hexdigest()
    return {
        "schema": sieve.LOCAL_PRUNABLE_BREADCRUMB_SCHEMA,
        "selection_filter": ["ONE_PRUNABLE", "BOTH_PRUNABLE"],
        "observation_point": "immediately-after-probe-trace-before-crossing-branch",
        "retention_rule": "first-256-matches-in-probe-order",
        "capacity": 256,
        "total_match_count": 0,
        "retained_count": 0,
        "overflow_count": 0,
        "complete": True,
        "class_counts": {"ONE_PRUNABLE": 0, "BOTH_PRUNABLE": 0},
        "canonical_digest": {
            "algorithm": "SHA-256",
            "encoding": sieve.LOCAL_PRUNABLE_BREADCRUMB_ENCODING,
            "record_bytes": sieve.LOCAL_PRUNABLE_BREADCRUMB_RECORD_BYTES,
            "field_layout": sieve.LOCAL_PRUNABLE_BREADCRUMB_LAYOUT,
            "all_matches": {"record_count": 0, "bytes": 0, "sha256": empty},
            "overflow": {"record_count": 0, "bytes": 0, "sha256": empty},
        },
        "breadcrumbs": [],
    }


def test_o1c109_production_bindings_and_native_source_are_exact() -> None:
    assert sieve.JOINT_SCORE_SIEVE_ADAPTER_SCHEMA.endswith("v36-adapter-v1")
    assert sieve.JOINT_SCORE_SIEVE_RESULT_SCHEMA.endswith("result-v33")
    assert "o1c109" in sieve.PRIORITY_STATE_SCHEMA
    assert "o1c109" in sieve.PRIORITY_ACTION_SCHEMA
    assert sieve.NATIVE_SOURCE_BYTES == SOURCE.stat().st_size
    assert sieve.NATIVE_SOURCE_SHA256 == _sha(SOURCE.read_bytes())
    assert sieve.PRODUCTION_PAGE22_LINEAGE_ORDINAL == 35
    assert sieve.PRODUCTION_PAGE22_BYTES == 2_756_507
    assert sieve.PRODUCTION_PAGE22_LITERAL_COUNT == 688_833
    assert sieve.PRODUCTION_PAGE22_HEADROOM == {
        "clauses": 266,
        "literals": 911_167,
        "serialized_bytes": 5_632_101,
    }
    assert sieve.PURE_EMITTED_CANDIDATE_SHA256 == (
        "97623323579d56de5034caf107627c939a991be0e00e6aee192d60a0bcf56f88"
    )
    assert sieve.PURE_EMITTED_CANDIDATE_SHA256 != sieve.PRODUCTION_PAGE22_SHA256
    assert sieve.GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT == 3_111
    assert sieve.O1C108_MANIFEST_BYTES == 12_468
    assert sieve.O1C108_CERTIFICATION_AUDIT_BYTES == 227_369
    assert sieve.INHERITED_DERIVED_RECEIPT_BYTES == 326_232
    assert sieve.O1C104_DERIVED_RECEIPT_BYTES == 428_520
    assert sieve.NEW_DERIVED_RECEIPT_BYTES == 361_008


def test_priority_seed_report_requires_exact_17_field_provenance() -> None:
    report = _seed_report()
    assert len(report) == 17
    assert (
        sieve._validate_seed_report(
            report,
            seed_sha256=sieve.LIVE_BANK_SHA256,
            production_seal=True,
        )
        == report
    )
    for field in tuple(report):
        forged = dict(report)
        forged.pop(field)
        with pytest.raises(O1RelationalSearchError, match="priority seed fields"):
            sieve._validate_seed_report(
                forged,
                seed_sha256=sieve.LIVE_BANK_SHA256,
                production_seal=True,
            )


def test_breadcrumb_sidecar_accepts_empty_and_rejects_missing_extra_mutation() -> None:
    sidecar = _empty_breadcrumbs()
    assert sieve._validate_local_prunable_breadcrumbs(sidecar) == sidecar
    for forged in (
        {key: value for key, value in sidecar.items() if key != "capacity"},
        {**sidecar, "unexpected": 1},
        {**sidecar, "capacity": 255},
    ):
        with pytest.raises(O1RelationalSearchError, match="breadcrumb"):
            sieve._validate_local_prunable_breadcrumbs(forged)
    forged_digest = copy.deepcopy(sidecar)
    canonical = cast(dict[str, object], forged_digest["canonical_digest"])
    all_matches = cast(dict[str, object], canonical["all_matches"])
    all_matches["sha256"] = "ab" * 32
    with pytest.raises(O1RelationalSearchError, match="canonical digest"):
        sieve._validate_local_prunable_breadcrumbs(forged_digest)


def test_breadcrumb_sidecar_rejects_forged_empty_population_against_probes() -> None:
    sidecar = _empty_breadcrumbs()
    matching_state = {
        "probe_counters": {"ONE_PRUNABLE": 0, "BOTH_PRUNABLE": 0}
    }
    sieve._validate_breadcrumb_probe_linkage(sidecar, matching_state)
    forged_state = {
        "probe_counters": {"ONE_PRUNABLE": 1, "BOTH_PRUNABLE": 0}
    }
    with pytest.raises(O1RelationalSearchError, match="breadcrumb probe linkage"):
        sieve._validate_breadcrumb_probe_linkage(sidecar, forged_state)


def test_v3_ownership_replays_global_sequence_gaps_and_action_linkage() -> None:
    ownership, actions, counts = _ownership_fixture()
    assert (
        sieve._validate_ownership_v3(
            ownership,
            actions=actions,
            counts=counts,
        )
        == ownership
    )
    sequences = [event["sequence"] for event in ownership["events"]]  # type: ignore[index]
    assert sequences == [1, 3, 5, 6]
    assert cast(int, ownership["total_event_count"]) == (
        cast(int, ownership["lifecycle_event_count"])
        + cast(int, ownership["compacted_nonclaim_count"])
    )


@pytest.mark.parametrize(
    ("path", "value", "pattern"),
    (
        (("events", 1, "sequence"), 1, "chronology"),
        (("events", 3, "sequence"), 7, "chronology"),
        (("events", 0, "row"), 11, "token binding"),
        (("total_event_count",), 7, "arithmetic"),
        (("nonclaim_kind_counts", "FOREIGN_ASSIGNMENT"), 2, "arithmetic"),
        (("origin_counts", "BOUND_LOSING_CHILD", "proposals"), 0, "origin totals"),
    ),
)
def test_v3_ownership_rejects_gap_counter_origin_and_linkage_tamper(
    path: tuple[object, ...], value: object, pattern: str
) -> None:
    ownership, actions, counts = _ownership_fixture()
    forged: object = copy.deepcopy(ownership)
    cursor = forged
    for part in path[:-1]:
        if isinstance(part, int):
            cursor = cursor[part]  # type: ignore[index]
        else:
            cursor = cursor[part]  # type: ignore[index]
    cursor[path[-1]] = value  # type: ignore[index]
    with pytest.raises(O1RelationalSearchError, match=pattern):
        sieve._validate_ownership_v3(
            forged,
            actions=actions,
            counts=counts,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("algorithm", "SHA-512"),
        ("encoding", "legacy"),
        ("record_bytes", 41),
        ("field_layout", "opaque"),
        ("record_count", 3),
        ("sha256", "g" * 64),
    ),
)
def test_v3_ownership_validates_commitment_envelope_without_hidden_recompute(
    field: str, value: object
) -> None:
    ownership, actions, counts = _ownership_fixture()
    digest = ownership["nonclaim_stream_digest"]
    assert isinstance(digest, dict)
    digest[field] = value
    with pytest.raises(O1RelationalSearchError, match="nonclaim"):
        sieve._validate_ownership_v3(
            ownership,
            actions=actions,
            counts=counts,
        )


def test_v3_zero_nonclaim_commitment_requires_empty_sha256() -> None:
    ownership, actions, counts = _ownership_fixture()
    ownership["opposite_assignments"] = 0
    ownership["foreign_assignments"] = 0
    ownership["omitted_event_count"] = 0
    ownership["compacted_nonclaim_count"] = 0
    ownership["event_count"] = 4
    ownership["total_event_count"] = 4
    ownership["nonclaim_kind_counts"] = {
        "OPPOSITE_ASSIGNMENT": 0,
        "FOREIGN_ASSIGNMENT": 0,
        "RENOTIFIED": 0,
    }
    digest = ownership["nonclaim_stream_digest"]
    assert isinstance(digest, dict)
    digest["record_count"] = 0
    digest["sha256"] = hashlib.sha256(b"").hexdigest()
    events = ownership["events"]
    assert isinstance(events, list)
    for sequence, event in enumerate(events, start=1):
        event["sequence"] = sequence
    sieve._validate_ownership_v3(ownership, actions=actions, counts=counts)
    digest["sha256"] = "ab" * 32
    with pytest.raises(O1RelationalSearchError, match="commitment envelope"):
        sieve._validate_ownership_v3(ownership, actions=actions, counts=counts)


def test_v3_ownership_rejects_action_to_lifecycle_linkage_tamper() -> None:
    ownership, actions, counts = _ownership_fixture()
    forged_action = dict(actions[0])
    forged_action["coordinate_index"] = 11
    with pytest.raises(O1RelationalSearchError, match="action event linkage"):
        sieve._validate_ownership_v3(
            ownership,
            actions=(forged_action,),
            counts=counts,
        )


@pytest.mark.parametrize(
    ("serialized_bytes", "digest", "pattern"),
    (
        (sieve.BURNED_PAGE21_BYTES, sieve.BURNED_PAGE21_SHA256, "burned Page21"),
        (sieve.BURNED_PAGE20_BYTES, sieve.BURNED_PAGE20_SHA256, "burned Page20"),
        (sieve.BURNED_PAGE19_BYTES, sieve.BURNED_PAGE19_SHA256, "burned Page19"),
        (sieve.BURNED_PAGE18_BYTES, sieve.BURNED_PAGE18_SHA256, "burned Page18"),
        (sieve.BURNED_PAGE9_BYTES, sieve.BURNED_PAGE9_SHA256, "burned Page9"),
    ),
)
def test_page22_reader_rejects_burned_pages_before_acceptance(
    monkeypatch: pytest.MonkeyPatch,
    serialized_bytes: int,
    digest: str,
    pattern: str,
) -> None:
    payload = b"\0" * serialized_bytes
    monkeypatch.setattr(
        sieve._v9._v8._v7._v1,
        "_read_input",
        lambda *_args, **_kwargs: (Path("/sealed"), payload, digest),
    )
    with pytest.raises(O1RelationalSearchError, match=pattern):
        sieve._read_page22("ignored")


def test_published_o1c108_bundle_manifest_and_audit_are_exact() -> None:
    assert BUNDLE.is_dir()
    assert {path.name for path in BUNDLE.iterdir()} == (
        sieve.O1C108_PUBLISHED_ARTIFACTS
    )
    assert MANIFEST.stat().st_size == sieve.O1C108_MANIFEST_BYTES
    assert _sha(MANIFEST.read_bytes()) == sieve.O1C108_MANIFEST_SHA256
    assert AUDIT.stat().st_size == sieve.O1C108_CERTIFICATION_AUDIT_BYTES
    assert _sha(AUDIT.read_bytes()) == sieve.O1C108_CERTIFICATION_AUDIT_SHA256
    assert PAGE22.stat().st_size == sieve.PRODUCTION_PAGE22_BYTES
    assert _sha(PAGE22.read_bytes()) == sieve.PRODUCTION_PAGE22_SHA256
    manifest = sieve._validate_o1c108_manifest(MANIFEST.read_bytes())
    assert manifest["attempt_id"] == "O1C-0108"


def test_o1c108_registry_order_and_type_exclusions_are_exact() -> None:
    manifest = sieve._validate_o1c108_manifest(MANIFEST.read_bytes())
    logical = cast(Mapping[str, object], manifest["logical_known_registry"])
    assert logical["registry_segment_order"] == [
        "o1c106-logical-known-registry-byte-order",
        "new-o1c107-native-emission",
        "new-o1c108-derived-resolution",
    ]
    assert [row["clause_count"] for row in logical["registry_segments"]] == [  # type: ignore[index]
        2_692,
        266,
        153,
    ]
    namespaces = cast(
        Mapping[str, object], manifest["derived_resolution_namespaces"]
    )
    newest = cast(Mapping[str, object], namespaces["new_o1c108"])
    assert newest["active_only_excluded_closure_indices"] == [1, 2, 32, 55]
    assert newest["closure_clause_count"] == 153
    assert newest["overlay_clause_count"] == 153
    assert newest["resident_clause_count"] == 149
    assert NEW_CLOSURE.read_bytes() == NEW_OVERLAY.read_bytes()


@pytest.mark.parametrize(
    "artifact_name",
    (
        sieve._o1c108.INHERITED_DERIVED_RECEIPT_NAME,
        sieve._o1c108.INHERITED_DERIVED_CLOSURE_NAME,
        sieve._o1c108.INHERITED_DERIVED_OVERLAY_NAME,
        sieve._o1c108.O1C104_DERIVED_RECEIPT_NAME,
        sieve._o1c108.O1C104_DERIVED_CLOSURE_NAME,
        sieve._o1c108.O1C104_DERIVED_OVERLAY_NAME,
        sieve._o1c108.DERIVED_RECEIPT_NAME,
        sieve._o1c108.DERIVED_CLOSURE_NAME,
        sieve._o1c108.DERIVED_OVERLAY_NAME,
    ),
)
def test_zero_launch_gate_rejects_each_triplet_artifact_tamper(
    tmp_path: Path, artifact_name: str
) -> None:
    forged_bundle = tmp_path / "bundle"
    shutil.copytree(BUNDLE, forged_bundle)
    target = forged_bundle / artifact_name
    payload = target.read_bytes()
    target.write_bytes(bytes((payload[0] ^ 1,)) + payload[1:])
    with pytest.raises(O1RelationalSearchError, match="artifact.*seal"):
        sieve.validate_o1c109_page22_inputs(
            bundle_dir=forged_bundle,
            cnf_path=CNF,
            potential_path=POTENTIAL,
            grouping_path=GROUPING,
            vault_path=PAGE22,
            vault_caps=sieve.O1C66_VAULT_CAPS,
            threshold=sieve.O1C108_THRESHOLD,
        )


def test_real_production_page22_gate_certifies_246_without_monkeypatch() -> None:
    validated = sieve.validate_o1c109_page22_inputs(
        bundle_dir=BUNDLE,
        cnf_path=CNF,
        potential_path=POTENTIAL,
        grouping_path=GROUPING,
        vault_path=PAGE22,
        vault_caps=sieve.O1C66_VAULT_CAPS,
        threshold=sieve.O1C108_THRESHOLD,
    )
    assert validated.input_vault.clause_count == 246
    assert validated.input_vault.literal_count == 688_833
    assert validated.input_vault.sha256 == sieve.PRODUCTION_PAGE22_SHA256
    assert validated.input_vault.clause_aggregate_sha256 == (
        sieve.PRODUCTION_PAGE22_CLAUSE_AGGREGATE_SHA256
    )
    page = cast(Mapping[str, object], validated.certification_audit["page22"])
    assert page["active_pass_count"] == 246
    assert page["active_fail_count"] == 0


@pytest.mark.parametrize(
    ("artifact_name", "pattern"),
    (
        (sieve._o1c108.PREPARATION_MANIFEST_NAME, "manifest seal"),
        (sieve._o1c108.CERTIFICATION_AUDIT_NAME, "artifact.*seal"),
    ),
)
def test_zero_launch_gate_rejects_manifest_and_audit_tamper(
    tmp_path: Path,
    artifact_name: str,
    pattern: str,
) -> None:
    forged_bundle = tmp_path / "bundle"
    shutil.copytree(BUNDLE, forged_bundle)
    target = forged_bundle / artifact_name
    payload = target.read_bytes()
    target.write_bytes(bytes((payload[0] ^ 1,)) + payload[1:])
    with pytest.raises(O1RelationalSearchError, match=pattern):
        sieve.validate_o1c109_page22_inputs(
            bundle_dir=forged_bundle,
            cnf_path=CNF,
            potential_path=POTENTIAL,
            grouping_path=GROUPING,
            vault_path=PAGE22,
            vault_caps=sieve.O1C66_VAULT_CAPS,
            threshold=sieve.O1C108_THRESHOLD,
        )


def test_v36_run_uses_the_same_gate_before_its_only_native_launch() -> None:
    signature = inspect.signature(sieve.validate_o1c109_page22_inputs)
    assert tuple(signature.parameters) == (
        "bundle_dir",
        "cnf_path",
        "potential_path",
        "grouping_path",
        "vault_path",
        "vault_caps",
        "threshold",
    )
    run_signature = inspect.signature(sieve.run_joint_score_sieve)
    assert "rollover_bundle_dir" in run_signature.parameters
    assert "sealed_page20_path" not in run_signature.parameters
    source = Path(sieve.__file__).read_text(encoding="utf-8")
    helper_source = inspect.getsource(sieve.validate_o1c109_page22_inputs)
    assert "_execute_native" not in helper_source
    assert "subprocess" not in helper_source
    run_source = source[source.index("def run_joint_score_sieve(") :]
    assert run_source.count("validate_o1c109_page22_inputs(") == 1
    assert run_source.count("_execute_native(") == 1
    assert run_source.index("validate_o1c109_page22_inputs(") < run_source.index(
        "_execute_native("
    )
    assert "_v22._validate_priority_state(" in source
    assert "_v22._validate_actions(" in source
    assert "_validate_ownership_v3(" in source
    assert "_v9._parse_native_payload(" in source
    assert "truth_key_path" not in source
    assert "target_path" not in run_signature.parameters
