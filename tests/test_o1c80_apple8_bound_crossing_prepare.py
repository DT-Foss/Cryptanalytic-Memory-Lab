from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any, Mapping, cast

import pytest

import o1_crypto_lab.o1c80_apple8_bound_crossing_prepare as prepare


ROOT = Path(__file__).resolve().parents[1]
CHECKED_SEED = ROOT / "research/o1c80_bound_crossing_seed_20260720"


def _python_environment() -> dict[str, str]:
    environment = dict(os.environ)
    source = (ROOT / "src").as_posix()
    prior = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = f"{source}{os.pathsep}{prior}" if prior else source
    return environment


def _run_python(source: str, *arguments: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-c",
            textwrap.dedent(source),
            *(str(path) for path in arguments),
        ],
        cwd=ROOT,
        env=_python_environment(),
        text=True,
        capture_output=True,
        check=False,
        timeout=180,
    )


def _guarded_double_prepare(first: Path, second: Path) -> dict[str, object]:
    completed = _run_python(
        """
        import hashlib
        import json
        import os
        import subprocess
        import sys
        from pathlib import Path

        def forbidden(*args, **kwargs):
            raise AssertionError("zero-call preparation launched a process")

        subprocess.run = forbidden
        subprocess.Popen = forbidden
        os.system = forbidden

        import o1_crypto_lab.o1c80_apple8_bound_crossing_prepare as p

        root = Path.cwd()
        outputs = (Path(sys.argv[1]), Path(sys.argv[2]))
        manifests = []
        snapshots = []
        for output in outputs:
            manifest = p.prepare_o1c80_bound_crossing(
                capsule_dir=root / p.DEFAULT_PARENT_CAPSULE_RELATIVE,
                parent_result_path=root / p.DEFAULT_PARENT_RESULT_RELATIVE,
                parent_erratum_path=root / p.DEFAULT_PARENT_ERRATUM_RELATIVE,
                output_dir=output,
            )
            manifests.append(hashlib.sha256(
                (output / p.MANIFEST_NAME).read_bytes()
            ).hexdigest())
            snapshots.append({
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in output.iterdir()
            })
        print(json.dumps({
            "artifact_count": manifest["artifact_set"]["artifact_count"],
            "manifest_sha256": manifests,
            "snapshots_equal": snapshots[0] == snapshots[1],
            "native_solver_calls": manifest["zero_call"]["native_solver_calls"],
            "science_calls": manifest["zero_call"]["science_calls"],
        }, sort_keys=True))
        """,
        first,
        second,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


@pytest.fixture(scope="module")
def prepared_directories(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    root = tmp_path_factory.mktemp("o1c80-zero-call")
    first = root / "first"
    second = root / "second"
    summary = _guarded_double_prepare(first, second)
    assert summary == {
        "artifact_count": 25,
        "manifest_sha256": [
            prepare.EXPECTED_PREPARED_MANIFEST_SHA256,
            prepare.EXPECTED_PREPARED_MANIFEST_SHA256,
        ],
        "native_solver_calls": 0,
        "science_calls": 0,
        "snapshots_equal": True,
    }
    return first, second


@pytest.fixture(scope="module")
def loaded(
    prepared_directories: tuple[Path, Path],
) -> prepare.PreparedBoundCrossing:
    return prepare.load_prepared_bound_crossing(
        prepared_directories[0],
        expected_manifest_sha256=prepare.EXPECTED_PREPARED_MANIFEST_SHA256,
    )


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    assert isinstance(value, dict)
    return value


def _file_sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _clone_tree(source: Path, destination: Path) -> None:
    try:
        shutil.copytree(source, destination, copy_function=os.link)
    except OSError:
        if destination.exists():
            shutil.rmtree(destination)
        shutil.copytree(source, destination)
    for directory in (
        destination,
        *(path for path in destination.rglob("*") if path.is_dir()),
    ):
        directory.chmod(directory.stat().st_mode | 0o700)


def _replace_bytes(path: Path, payload: bytes) -> None:
    path.unlink()
    path.write_bytes(payload)


def test_page7_advance_contract_is_exact(
    loaded: prepare.PreparedBoundCrossing,
) -> None:
    manifest = loaded.manifest
    assert loaded.manifest_sha256 == prepare.EXPECTED_PREPARED_MANIFEST_SHA256
    assert manifest["zero_call"] == {
        "native_solver_calls": 0,
        "science_calls": 0,
        "public_verification_calls": 0,
        "truth_key_bytes_read": False,
        "reveal_calls": 0,
        "refits": 0,
        "mps_or_gpu_calls": 0,
    }
    assert manifest["authorization"] == {
        "science_call_authorized": False,
        "intent_created": False,
        "page7_burned": False,
        "lineage20_burned": False,
        "page6_replay_authorized": False,
    }
    assert manifest["projection_contract"] == {
        "source_lineage_ordinal": 19,
        "source_active_sha256": prepare.PAGE6_SHA256,
        "next_lineage_ordinal": 20,
        "next_active_sha256": prepare.PAGE7_SHA256,
        "next_selection_order_sha256": prepare.PAGE7_SELECTION_ORDER_SHA256,
        "advance_api": "advance_causal_residency",
        "empty_rollover_sha256": prepare.EMPTY_ROLLOVER_SHA256,
        "empty_rollover_clause_count": 0,
        "empty_rollover_occurrence_count": 0,
        "empty_rollover_emission_count": 0,
        "fully_emitted_union_indices": [],
        "attic_chunk_count_before": 10,
        "attic_chunk_count_after": 11,
        "occurrence_count_before": 558,
        "occurrence_count_after": 558,
        "unchanged_union_sha256": prepare.UNCHANGED_UNION_SHA256,
        "failed_call_reprojection_used": False,
        "synthetic_evidence_created": False,
        "page6_replay_authorized": False,
    }
    state = loaded.state
    assert state.current_projection.lineage_ordinal == 20
    assert state.active_projection.sha256 == prepare.PAGE7_SHA256
    assert state.active_projection.clause_count == 256
    assert state.active_projection.literal_count == 663_409
    assert state.active_projection.serialized_bytes == 2_654_851
    assert state.current_projection.describe()["selection_order_sha256"] == (
        prepare.PAGE7_SELECTION_ORDER_SHA256
    )


def test_real_zero_emission_receipt_and_empty_rollover_are_bound(
    loaded: prepare.PreparedBoundCrossing,
) -> None:
    receipt = loaded.parent_receipt
    assert receipt["immutable_evidence_sha256"] == {
        "raw_result": prepare.PARENT_RESULT_SHA256,
        "capsule_manifest": prepare.PARENT_CAPSULE_MANIFEST_SHA256,
        "zero_call_erratum": prepare.PARENT_ERRATUM_SHA256,
        "native_gzip": prepare.PARENT_NATIVE_GZIP_SHA256,
        "native_raw": prepare.PARENT_NATIVE_RAW_SHA256,
        "ownership_gzip": prepare.PARENT_OWNERSHIP_GZIP_SHA256,
        "ownership_raw": prepare.PARENT_OWNERSHIP_RAW_SHA256,
        "vault_telemetry_gzip": prepare.PARENT_TELEMETRY_GZIP_SHA256,
        "vault_telemetry_raw": prepare.PARENT_TELEMETRY_RAW_SHA256,
    }
    assert receipt["corrected_interpretation"] == {
        "classification": prepare.PARENT_CORRECTED_CLASSIFICATION,
        "stop_reason": prepare.PARENT_CORRECTED_STOP_REASON,
        "operational_ownership_success": True,
        "qualified_prefix_activation": True,
        "science_gain": False,
        "method": "additive-zero-call-erratum",
    }
    emission = receipt["emission_import"]
    assert isinstance(emission, Mapping)
    assert emission["telemetry_parsed"] is True
    assert emission["fully_emitted_union_indices"] == []
    assert emission["fully_emitted_clause_count"] == 0
    assert emission["rollover_chunk_sha256"] == prepare.EMPTY_ROLLOVER_SHA256
    assert emission["rollover_clause_count"] == 0
    assert emission["rollover_occurrence_count"] == 0
    assert emission["rollover_emission_count"] == 0
    assert emission["advance_api"] == "advance_causal_residency"
    assert emission["failed_call_reprojection_used"] is False
    state = loaded.state
    assert len(state.attic.chunks) == 11
    assert tuple(chunk.clause_count for chunk in state.attic.chunks) == (
        prepare.EXPECTED_CHUNK_CLAUSE_COUNTS
    )
    assert state.attic.chunks[-1].sha256 == prepare.EMPTY_ROLLOVER_SHA256
    assert len(state.attic.occurrences) == 558
    assert state.attic.union_vault.sha256 == prepare.UNCHANGED_UNION_SHA256
    assert not hasattr(prepare, "reproject_causal_residency")


def test_fresh_page7_plans_and_static_prefix_contract(
    loaded: prepare.PreparedBoundCrossing,
    prepared_directories: tuple[Path, Path],
) -> None:
    directory = prepared_directories[0]
    frontier = _read_json(directory / prepare.FRONTIER_PLAN_NAME)
    staging = _read_json(directory / prepare.STAGING_PLAN_NAME)
    prefix = _read_json(directory / prepare.PREFIX_PLAN_NAME)
    assert loaded.frontier_plan.active_vault_sha256 == prepare.PAGE7_SHA256
    assert loaded.frontier_plan.sha256 == prepare.FRONTIER_PLAN_BINARY_SHA256
    assert loaded.staging_plan.active_vault_sha256 == prepare.PAGE7_SHA256
    assert loaded.staging_plan.sha256 == prepare.STAGING_PLAN_BINARY_SHA256
    assert loaded.staging_plan.parent_frontier_plan_sha256 == (
        prepare.FRONTIER_PLAN_BINARY_SHA256
    )
    assert frontier["page6_plan_bytes_copied"] is False
    assert staging["page6_plan_bytes_copied"] is False
    assert _file_sha256(directory / prepare.FRONTIER_PLAN_BINARY_NAME) != (
        "785cae9e32912e1d45858d046b36a7c7b9e4cf51799f233a7b3246aa6756ad65"
    )
    assert _file_sha256(directory / prepare.STAGING_PLAN_BINARY_NAME) != (
        "c536a94483467ee1197d52e0e3f81ad2f728a36ad3982124e1b9966e0011f927"
    )
    assert _file_sha256(directory / prepare.PREFIX_PLAN_BINARY_NAME) == (
        prepare.PREFIX_PLAN_BINARY_SHA256
    )
    assert prefix["active_vault_sha256"] == prepare.PAGE7_SHA256
    assert prefix["parent_staging_plan_sha256"] == (prepare.STAGING_PLAN_BINARY_SHA256)
    assert prefix["static_legacy_selector_required_by_native_contract"] is True
    assert prefix["content_inherited_unchanged"] is True
    assert prefix["fresh_page7_cross_binding_validated"] is True
    assert prefix["tuned_for_page7"] is False
    assert prefix["refit"] is False
    assert prefix["new_science_claim"] is False


def test_complete_history_consumes_page6_and_excludes_page7(
    loaded: prepare.PreparedBoundCrossing,
) -> None:
    history = loaded.science_input_history
    raw_values = history["science_input_sha256"]
    assert isinstance(raw_values, list)
    assert all(isinstance(value, str) for value in raw_values)
    values = tuple(cast(list[str], raw_values))
    assert values == prepare.SCIENCE_INPUT_SHA256_HISTORY
    assert len(values) == 9
    assert len(set(values)) == 9
    assert values[-1] == prepare.PAGE6_SHA256
    assert prepare.PAGE7_SHA256 not in values
    assert history["page6_replay_authorized"] is False
    science = loaded.science_input
    assert science["active_vault_sha256"] == prepare.PAGE7_SHA256
    assert science["science_call_authorized"] is False
    assert science["intent_created"] is False
    assert science["page_burned"] is False


def test_checked_seed_is_byte_identical_to_fresh_build(
    prepared_directories: tuple[Path, Path],
) -> None:
    fresh = prepared_directories[0]
    assert {path.name for path in CHECKED_SEED.iterdir()} == {
        path.name for path in fresh.iterdir()
    }
    for source in fresh.iterdir():
        assert source.read_bytes() == (CHECKED_SEED / source.name).read_bytes()


def test_prepared_inventory_mutations_and_root_symlinks_are_rejected(
    prepared_directories: tuple[Path, Path], tmp_path: Path
) -> None:
    source = prepared_directories[0]
    extra = tmp_path / "extra"
    _clone_tree(source, extra)
    (extra / "unexpected").write_bytes(b"x")
    with pytest.raises(prepare.O1C80PreparationError, match="inventory"):
        prepare.load_prepared_bound_crossing(
            extra,
            expected_manifest_sha256=prepare.EXPECTED_PREPARED_MANIFEST_SHA256,
        )

    mutated = tmp_path / "mutated"
    _clone_tree(source, mutated)
    _replace_bytes(mutated / prepare.FRONTIER_PLAN_BINARY_NAME, b"bad")
    with pytest.raises(prepare.O1C80PreparationError, match="artifact"):
        prepare.load_prepared_bound_crossing(
            mutated,
            expected_manifest_sha256=prepare.EXPECTED_PREPARED_MANIFEST_SHA256,
        )

    alias = tmp_path / "prepared-alias"
    alias.symlink_to(source, target_is_directory=True)
    with pytest.raises(prepare.O1C80PreparationError, match="sealed directory"):
        prepare.load_prepared_bound_crossing(
            alias,
            expected_manifest_sha256=prepare.EXPECTED_PREPARED_MANIFEST_SHA256,
        )


def test_parent_capsule_external_result_and_erratum_mutations_are_rejected(
    tmp_path: Path,
) -> None:
    capsule = tmp_path / "capsule"
    _clone_tree(ROOT / prepare.DEFAULT_PARENT_CAPSULE_RELATIVE, capsule)
    (capsule / "unexpected").write_bytes(b"x")
    with pytest.raises(prepare.O1C80PreparationError, match="inventory"):
        prepare._build_successor(
            capsule_dir=capsule,
            parent_result_path=ROOT / prepare.DEFAULT_PARENT_RESULT_RELATIVE,
            parent_erratum_path=ROOT / prepare.DEFAULT_PARENT_ERRATUM_RELATIVE,
        )

    bad_result = tmp_path / "result.json"
    bad_result.write_bytes(b"{}\n")
    with pytest.raises(prepare.O1C80PreparationError, match="result binding"):
        prepare._build_successor(
            capsule_dir=ROOT / prepare.DEFAULT_PARENT_CAPSULE_RELATIVE,
            parent_result_path=bad_result,
            parent_erratum_path=ROOT / prepare.DEFAULT_PARENT_ERRATUM_RELATIVE,
        )

    bad_erratum = tmp_path / "erratum.json"
    bad_erratum.write_bytes(b"{}\n")
    with pytest.raises(prepare.O1C80PreparationError, match="erratum"):
        prepare._build_successor(
            capsule_dir=ROOT / prepare.DEFAULT_PARENT_CAPSULE_RELATIVE,
            parent_result_path=ROOT / prepare.DEFAULT_PARENT_RESULT_RELATIVE,
            parent_erratum_path=bad_erratum,
        )


def test_release_contract_and_atomic_publisher_cannot_be_bypassed(
    tmp_path: Path,
) -> None:
    with pytest.raises(prepare.O1C80PreparationError, match="must remain true"):
        prepare.prepare_o1c80_bound_crossing(
            capsule_dir=ROOT / prepare.DEFAULT_PARENT_CAPSULE_RELATIVE,
            parent_result_path=ROOT / prepare.DEFAULT_PARENT_RESULT_RELATIVE,
            parent_erratum_path=ROOT / prepare.DEFAULT_PARENT_ERRATUM_RELATIVE,
            output_dir=tmp_path / "unused",
            enforce_release_contract=False,
        )
    existing = tmp_path / "existing"
    existing.mkdir()
    marker = existing / "marker"
    marker.write_bytes(b"preserved")
    with pytest.raises(prepare.O1C80PreparationError, match="already exists"):
        prepare._publish_directory(existing, {"artifact": b"payload"})
    assert marker.read_bytes() == b"preserved"


def test_cli_reports_one_bounded_preparation_failure(tmp_path: Path) -> None:
    completed = _run_python(
        """
        import sys
        import o1_crypto_lab.o1c80_apple8_bound_crossing_prepare as p
        raise SystemExit(p.main([
            "--capsule", sys.argv[1],
            "--output-dir", sys.argv[2],
        ]))
        """,
        tmp_path / "missing-capsule",
        tmp_path / "output",
    )
    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr.startswith("O1C-0080: ")
    assert len(completed.stderr.splitlines()) == 1
