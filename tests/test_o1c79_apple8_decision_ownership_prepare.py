from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

import o1_crypto_lab.o1c78_apple8_rescue_prefix_preemption_prepare as parent_publish
import o1_crypto_lab.o1c79_apple8_decision_ownership_prepare as prepare


ROOT = Path(__file__).resolve().parents[1]


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
        timeout=120,
    )


def _guarded_prepare(output: Path) -> dict[str, object]:
    completed = _run_python(
        """
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

        import o1_crypto_lab.o1c79_apple8_decision_ownership_prepare as p

        root = Path.cwd()
        output = Path(sys.argv[1])
        manifest = p.prepare_o1c79_decision_ownership(
            capsule_dir=root / p.DEFAULT_PARENT_CAPSULE_RELATIVE,
            parent_result_path=root / p.DEFAULT_PARENT_RESULT_RELATIVE,
            output_dir=output,
        )
        payload = (output / p.MANIFEST_NAME).read_bytes()
        print(json.dumps({
            "manifest_sha256": __import__("hashlib").sha256(payload).hexdigest(),
            "artifact_count": manifest["artifact_set"]["artifact_count"],
            "native_solver_calls": manifest["zero_call"]["native_solver_calls"],
            "science_calls": manifest["zero_call"]["science_calls"],
        }, sort_keys=True))
        """,
        output,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


@pytest.fixture(scope="module")
def prepared_directory(tmp_path_factory: pytest.TempPathFactory) -> Path:
    output = tmp_path_factory.mktemp("o1c79-zero-call") / "seed"
    summary = _guarded_prepare(output)
    assert summary == {
        "artifact_count": 24,
        "manifest_sha256": prepare.EXPECTED_PREPARED_MANIFEST_SHA256,
        "native_solver_calls": 0,
        "science_calls": 0,
    }
    return output


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    assert isinstance(value, dict)
    return value


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


def _file_sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def test_zero_call_terminal_to_page6_contract_is_exact(
    prepared_directory: Path,
) -> None:
    manifest_payload = (prepared_directory / prepare.MANIFEST_NAME).read_bytes()
    manifest = json.loads(manifest_payload)
    assert hashlib.sha256(manifest_payload).hexdigest() == (
        prepare.EXPECTED_PREPARED_MANIFEST_SHA256
    )
    assert manifest["zero_call"] == {
        "native_solver_calls": 0,
        "science_calls": 0,
        "public_verification_calls": 0,
        "truth_key_bytes_read": False,
        "reveal_calls": 0,
    }
    assert manifest["projection_contract"] == {
        "source_lineage_ordinal": 18,
        "source_active_sha256": prepare.PAGE5_SHA256,
        "next_lineage_ordinal": 19,
        "next_active_sha256": prepare.PAGE6_SHA256,
        "next_selection_order_sha256": prepare.PAGE6_SELECTION_ORDER_SHA256,
        "fully_emitted_union_indices": [],
        "unchanged_union_sha256": prepare.UNCHANGED_UNION_SHA256,
        "native_result_imported": False,
        "synthetic_output_created": False,
        "synthetic_chunk_created": False,
        "same_attic_reprojected": True,
        "page5_replay_authorized": False,
        "retry_authorized": False,
    }
    residency = _read_json(prepared_directory / prepare.RESIDENCY_NAME)
    active = residency["current_projection"]["encoding_only"]
    assert active["sha256"] == prepare.PAGE6_SHA256
    assert active["clause_count"] == 256
    assert active["literal_count"] == 723_864
    assert active["serialized_bytes"] == 2_896_671
    assert residency["current_projection"]["lineage_ordinal"] == 19
    assert residency["current_projection"]["selection_order_sha256"] == (
        prepare.PAGE6_SELECTION_ORDER_SHA256
    )
    assert (
        hashlib.sha256(
            (prepared_directory / prepare.RESIDENCY_NAME).read_bytes()
        ).hexdigest()
        == prepare.PAGE6_STATE_DOCUMENT_SHA256
    )
    assert _file_sha256(prepared_directory / prepare.ACTIVATION_LEDGER_NAME) == (
        prepare.PAGE6_ACTIVATION_LEDGER_SHA256
    )


def test_terminal_receipt_binds_exact_consumed_call(
    prepared_directory: Path,
) -> None:
    receipt_path = prepared_directory / prepare.TERMINAL_RECEIPT_NAME
    receipt = _read_json(receipt_path)
    assert _file_sha256(receipt_path) == prepare.EXPECTED_TERMINAL_RECEIPT_SHA256
    assert receipt["receipt_sha256"] == {
        "capsule_manifest": prepare.PARENT_CAPSULE_MANIFEST_SHA256,
        "result": prepare.PARENT_RESULT_SHA256,
        "invocation": prepare.PARENT_INVOCATION_SHA256,
        "intent": prepare.PARENT_INTENT_SHA256,
        "episode": prepare.PARENT_EPISODE_SHA256,
        "terminal_failure": prepare.PARENT_TERMINAL_FAILURE_SHA256,
        "prepared_manifest": prepare.PARENT_PREPARED_MANIFEST_SHA256,
    }
    assert receipt["consumption"] == {
        "local_episode_ordinal": 0,
        "lineage_call_ordinal": 18,
        "science_input_sha256": prepare.PAGE5_SHA256,
        "native_call_issued": True,
        "native_calls_consumed": 1,
        "native_result_returned": False,
        "requested_conflicts": 128,
        "billed_conflicts": None,
        "retry_authorized": False,
    }
    assert receipt["evidence_import"] == {
        "native_result_imported": False,
        "fully_emitted_occurrences_retained": False,
        "synthetic_output_created": False,
        "synthetic_chunk_created": False,
        "attic_mutated": False,
    }


def test_full_eight_sha_history_excludes_fresh_page6(
    prepared_directory: Path,
) -> None:
    path = prepared_directory / prepare.SCIENCE_HISTORY_NAME
    history = _read_json(path)
    assert _file_sha256(path) == prepare.EXPECTED_SCIENCE_HISTORY_SHA256
    assert tuple(history["science_input_sha256"]) == (
        prepare.SCIENCE_INPUT_SHA256_HISTORY
    )
    assert len(history["science_input_sha256"]) == 8
    assert len(set(history["science_input_sha256"])) == 8
    assert history["o1c78_consumed_sha256"] == prepare.PAGE5_SHA256
    assert prepare.PAGE6_SHA256 not in history["science_input_sha256"]
    assert history["next_active_absent_from_history"] is True
    assert history["page5_replay_authorized"] is False


def test_page6_plans_are_freshly_derived_and_cross_bound(
    prepared_directory: Path,
) -> None:
    frontier = _read_json(prepared_directory / prepare.FRONTIER_PLAN_NAME)
    staging = _read_json(prepared_directory / prepare.STAGING_PLAN_NAME)
    prefix = _read_json(prepared_directory / prepare.PREFIX_PLAN_NAME)
    science = _read_json(prepared_directory / prepare.SCIENCE_INPUT_NAME)
    assert _file_sha256(prepared_directory / prepare.FRONTIER_PLAN_NAME) == (
        prepare.EXPECTED_FRONTIER_PLAN_DOCUMENT_SHA256
    )
    assert _file_sha256(prepared_directory / prepare.FRONTIER_PLAN_BINARY_NAME) == (
        prepare.FRONTIER_PLAN_BINARY_SHA256
    )
    assert (
        prepared_directory / prepare.FRONTIER_PLAN_BINARY_NAME
    ).stat().st_size == 4_479
    assert frontier["active_vault_sha256"] == prepare.PAGE6_SHA256
    assert frontier["plan"]["active_vault_sha256"] == prepare.PAGE6_SHA256
    assert frontier["plan"]["selected_active_index"] == 232
    assert frontier["plan"]["selected_union_index"] == 526
    assert frontier["page5_plan_bytes_copied"] is False

    assert _file_sha256(prepared_directory / prepare.STAGING_PLAN_NAME) == (
        prepare.EXPECTED_STAGING_PLAN_DOCUMENT_SHA256
    )
    assert _file_sha256(prepared_directory / prepare.STAGING_PLAN_BINARY_NAME) == (
        prepare.STAGING_PLAN_BINARY_SHA256
    )
    assert (
        prepared_directory / prepare.STAGING_PLAN_BINARY_NAME
    ).stat().st_size == 4_477
    assert staging["active_vault_sha256"] == prepare.PAGE6_SHA256
    assert staging["parent_frontier_plan_sha256"] == (
        prepare.FRONTIER_PLAN_BINARY_SHA256
    )
    assert staging["page5_plan_bytes_copied"] is False

    assert _file_sha256(prepared_directory / prepare.PREFIX_PLAN_NAME) == (
        prepare.EXPECTED_PREFIX_PLAN_DOCUMENT_SHA256
    )
    assert _file_sha256(prepared_directory / prepare.PREFIX_PLAN_BINARY_NAME) == (
        prepare.PREFIX_PLAN_BINARY_SHA256
    )
    assert (prepared_directory / prepare.PREFIX_PLAN_BINARY_NAME).stat().st_size == 44
    assert prefix["active_vault_sha256"] == prepare.PAGE6_SHA256
    assert prefix["parent_staging_plan_sha256"] == (prepare.STAGING_PLAN_BINARY_SHA256)
    assert tuple(prefix["plan"]["prefix_literals"]) == (
        130,
        -131,
        31_874,
        63_746,
        190_565,
        190_566,
        190_569,
        191_212,
        191_213,
        191_216,
        191_234,
    )
    assert prefix["binary_rederived_from_rows"] is True
    assert prefix["page5_plan_document_copied"] is False
    assert prefix["retry_of_page5_authorized"] is False

    assert _file_sha256(prepared_directory / prepare.SCIENCE_INPUT_NAME) == (
        prepare.EXPECTED_SCIENCE_INPUT_SHA256
    )
    assert science["active_vault_sha256"] == prepare.PAGE6_SHA256
    assert science["frontier_plan_sha256"] == prepare.FRONTIER_PLAN_BINARY_SHA256
    assert science["staging_plan_sha256"] == prepare.STAGING_PLAN_BINARY_SHA256
    assert science["prefix_plan_sha256"] == prepare.PREFIX_PLAN_BINARY_SHA256
    assert science["page5_plan_bytes_reused"] is False
    assert science["page5_science_input_reused"] is False


def test_attic_is_unchanged_and_no_output_or_chunk_is_fabricated(
    prepared_directory: Path,
) -> None:
    parent_initial = ROOT / prepare.DEFAULT_PARENT_CAPSULE_RELATIVE / "initial"
    for name in prepare.CHUNK_NAMES:
        assert _file_sha256(prepared_directory / name) == _file_sha256(
            parent_initial / name
        )
    assert (prepared_directory / prepare.OCCURRENCES_NAME).read_bytes() == (
        parent_initial / "witness-occurrences.json"
    ).read_bytes()
    assert (prepared_directory / prepare.RELATIONS_NAME).read_bytes() == (
        parent_initial / "subsumption-relations.json"
    ).read_bytes()
    names = {path.name for path in prepared_directory.iterdir()}
    assert "chunk-10.vault" not in names
    assert not any("native-result" in name or "solver-output" in name for name in names)
    residency = _read_json(prepared_directory / prepare.RESIDENCY_NAME)
    assert residency["attic_evidence"]["union"]["sha256"] == (
        prepare.UNCHANGED_UNION_SHA256
    )
    assert residency["attic_evidence"]["chunk_count"] == 10


@pytest.mark.parametrize(
    "relative",
    [
        "artifacts.sha256",
        "result.json",
        "invocation.json",
        "episodes/00/intent.json",
        "episodes/00/episode.json",
        "episodes/00/terminal-failure.json",
        "initial/prepared-manifest.json",
    ],
)
def test_every_capsule_receipt_mutation_is_rejected(
    tmp_path: Path, relative: str
) -> None:
    capsule = tmp_path / "capsule"
    _clone_tree(ROOT / prepare.DEFAULT_PARENT_CAPSULE_RELATIVE, capsule)
    target = capsule / relative
    _replace_bytes(target, target.read_bytes() + b"\n")
    with pytest.raises(prepare.O1C79PreparationError, match="capsule|receipt|result"):
        prepare.prepare_o1c79_decision_ownership(
            capsule_dir=capsule,
            parent_result_path=ROOT / prepare.DEFAULT_PARENT_RESULT_RELATIVE,
            output_dir=tmp_path / "rejected",
        )


def test_external_result_mutation_is_rejected(tmp_path: Path) -> None:
    result = tmp_path / "result.json"
    result.write_bytes(
        (ROOT / prepare.DEFAULT_PARENT_RESULT_RELATIVE).read_bytes() + b"\n"
    )
    with pytest.raises(prepare.O1C79PreparationError, match="result binding"):
        prepare.prepare_o1c79_decision_ownership(
            capsule_dir=ROOT / prepare.DEFAULT_PARENT_CAPSULE_RELATIVE,
            parent_result_path=result,
            output_dir=tmp_path / "rejected",
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "extra",
        "symlink",
        "tamper-active",
        "tamper-frontier",
        "tamper-staging",
        "tamper-prefix",
    ],
)
def test_loader_rejects_inventory_plan_and_byte_mutations(
    prepared_directory: Path, tmp_path: Path, mutation: str
) -> None:
    polluted = tmp_path / mutation
    _clone_tree(prepared_directory, polluted)
    if mutation == "extra":
        (polluted / "unsealed.bin").write_bytes(b"extra")
        match = "directory inventory"
    elif mutation == "symlink":
        target = polluted / prepare.SCIENCE_INPUT_NAME
        target.unlink()
        target.symlink_to(polluted / prepare.SCIENCE_HISTORY_NAME)
        match = "directory inventory"
    else:
        names = {
            "tamper-active": prepare.ACTIVE_PROJECTION_NAME,
            "tamper-frontier": prepare.FRONTIER_PLAN_BINARY_NAME,
            "tamper-staging": prepare.STAGING_PLAN_BINARY_NAME,
            "tamper-prefix": prepare.PREFIX_PLAN_BINARY_NAME,
        }
        target = polluted / names[mutation]
        _replace_bytes(target, target.read_bytes() + b"\0")
        match = "artifact"
    with pytest.raises(prepare.O1C79PreparationError, match=match):
        prepare.load_prepared_decision_ownership(
            polluted,
            expected_manifest_sha256=prepare.EXPECTED_PREPARED_MANIFEST_SHA256,
        )


def test_bad_manifest_and_manifest_freeze_are_rejected(
    prepared_directory: Path, tmp_path: Path
) -> None:
    with pytest.raises(prepare.O1C79PreparationError, match="manifest freeze"):
        prepare.load_prepared_decision_ownership(
            prepared_directory, expected_manifest_sha256="00" * 32
        )
    polluted = tmp_path / "bad-manifest"
    _clone_tree(prepared_directory, polluted)
    manifest = polluted / prepare.MANIFEST_NAME
    _replace_bytes(manifest, manifest.read_bytes() + b"\n")
    with pytest.raises(prepare.O1C79PreparationError, match="manifest"):
        prepare.load_prepared_decision_ownership(
            polluted,
            expected_manifest_sha256=prepare.EXPECTED_PREPARED_MANIFEST_SHA256,
        )


def test_root_symlinks_are_rejected(prepared_directory: Path, tmp_path: Path) -> None:
    prepared_alias = tmp_path / "prepared-link"
    prepared_alias.symlink_to(prepared_directory, target_is_directory=True)
    with pytest.raises(prepare.O1C79PreparationError, match="sealed directory"):
        prepare.load_prepared_decision_ownership(
            prepared_alias,
            expected_manifest_sha256=prepare.EXPECTED_PREPARED_MANIFEST_SHA256,
        )

    capsule_alias = tmp_path / "capsule-link"
    capsule_alias.symlink_to(
        ROOT / prepare.DEFAULT_PARENT_CAPSULE_RELATIVE, target_is_directory=True
    )
    with pytest.raises(prepare.O1C79PreparationError, match="sealed directory"):
        prepare.prepare_o1c79_decision_ownership(
            capsule_dir=capsule_alias,
            parent_result_path=ROOT / prepare.DEFAULT_PARENT_RESULT_RELATIVE,
            output_dir=tmp_path / "capsule-rejected",
        )

    result_alias = tmp_path / "result-link"
    result_alias.symlink_to(ROOT / prepare.DEFAULT_PARENT_RESULT_RELATIVE)
    with pytest.raises(prepare.O1C79PreparationError, match="sealed regular file"):
        prepare.prepare_o1c79_decision_ownership(
            capsule_dir=ROOT / prepare.DEFAULT_PARENT_CAPSULE_RELATIVE,
            parent_result_path=result_alias,
            output_dir=tmp_path / "result-rejected",
        )


def test_source_root_symlinks_are_rejected(tmp_path: Path) -> None:
    source_alias = tmp_path / "frontier-source-link"
    source_alias.symlink_to(ROOT / prepare.FRONTIER_SOURCE_NATIVE_GZIP_RELATIVE)
    with pytest.raises(prepare.O1C79PreparationError, match="sealed regular file"):
        prepare.prepare_o1c79_decision_ownership(
            capsule_dir=ROOT / prepare.DEFAULT_PARENT_CAPSULE_RELATIVE,
            parent_result_path=ROOT / prepare.DEFAULT_PARENT_RESULT_RELATIVE,
            frontier_source_path=source_alias,
            output_dir=tmp_path / "source-rejected",
        )


def test_lineage_18_or_earlier_and_page5_reuse_are_rejected() -> None:
    completed = _run_python(
        """
        from pathlib import Path
        import o1_crypto_lab.o1c79_apple8_decision_ownership_prepare as p

        root = Path.cwd()
        capsule = p._sealed_directory(
            root / p.DEFAULT_PARENT_CAPSULE_RELATIVE, "parent capsule"
        )
        terminal = p._validate_parent_terminal(
            capsule, root / p.DEFAULT_PARENT_RESULT_RELATIVE
        )
        state = p._recover_parent_state(capsule, terminal)
        try:
            p._reproject_successor(state, next_lineage_ordinal=18)
        except p.O1C79PreparationError:
            pass
        else:
            raise AssertionError("lineage 18 was accepted")

        p.reproject_causal_residency = lambda *args, **kwargs: state
        try:
            p._reproject_successor(state, next_lineage_ordinal=19)
        except p.O1C79PreparationError as exc:
            assert "Page 5 cannot be reused" in str(exc)
        else:
            raise AssertionError("Page 5 was reused")
        print("ok")
        """
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "ok\n"


def test_page6_plan_rejects_page5_active_binding(
    prepared_directory: Path,
) -> None:
    completed = _run_python(
        """
        import sys
        from pathlib import Path
        from o1_crypto_lab.causal_attic_v1 import parse_self_scoping_vault
        from o1_crypto_lab.causal_frontier_v1 import (
            CausalFrontierError, parse_causal_frontier_plan,
        )
        from o1_crypto_lab.threshold_no_good_vault_v1 import (
            O1C66_VAULT_CAPS, parse_threshold_no_good_vault,
        )
        import o1_crypto_lab.o1c79_apple8_decision_ownership_prepare as p

        root = Path.cwd()
        output = Path(sys.argv[1])
        initial = root / p.DEFAULT_PARENT_CAPSULE_RELATIVE / "initial"
        rank = parse_self_scoping_vault((initial / "chunk-00.vault").read_bytes())
        page5 = parse_threshold_no_good_vault(
            (initial / "active-projection.bin").read_bytes(),
            observed_variables=rank.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
        try:
            parse_causal_frontier_plan(
                (output / p.FRONTIER_PLAN_BINARY_NAME).read_bytes(),
                active_vault=page5,
            )
        except CausalFrontierError:
            print("rejected")
        else:
            raise AssertionError("Page6 frontier accepted Page5")
        """,
        prepared_directory,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "rejected\n"


def test_deterministic_double_preparation(
    prepared_directory: Path, tmp_path: Path
) -> None:
    second = tmp_path / "second"
    summary = _guarded_prepare(second)
    assert summary["manifest_sha256"] == prepare.EXPECTED_PREPARED_MANIFEST_SHA256
    first_names = sorted(path.name for path in prepared_directory.iterdir())
    second_names = sorted(path.name for path in second.iterdir())
    assert first_names == second_names
    assert {name: _file_sha256(prepared_directory / name) for name in first_names} == {
        name: _file_sha256(second / name) for name in second_names
    }


def test_independent_publication_recovery_equivalence_in_short_process(
    prepared_directory: Path,
) -> None:
    completed = _run_python(
        """
        import json
        import sys
        from pathlib import Path
        import o1_crypto_lab.o1c79_apple8_decision_ownership_prepare as p

        prepared = p.load_prepared_decision_ownership(
            Path(sys.argv[1]),
            expected_manifest_sha256=p.EXPECTED_PREPARED_MANIFEST_SHA256,
        )
        print(json.dumps({
            "manifest": prepared.manifest_sha256,
            "page": prepared.active_projection.sha256,
            "lineage": prepared.state.current_projection.lineage_ordinal,
            "union": prepared.state.attic.union_vault.sha256,
            "frontier": prepared.frontier_plan.sha256,
            "staging": prepared.staging_plan.sha256,
            "prefix": prepared.prefix_plan.sha256,
            "science_input": prepared.science_input["active_vault_sha256"],
        }, sort_keys=True))
        """,
        prepared_directory,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {
        "manifest": prepare.EXPECTED_PREPARED_MANIFEST_SHA256,
        "page": prepare.PAGE6_SHA256,
        "lineage": 19,
        "union": prepare.UNCHANGED_UNION_SHA256,
        "frontier": prepare.FRONTIER_PLAN_BINARY_SHA256,
        "staging": prepare.STAGING_PLAN_BINARY_SHA256,
        "prefix": prepare.PREFIX_PLAN_BINARY_SHA256,
        "science_input": prepare.PAGE6_SHA256,
    }


def test_publication_fsync_failure_rolls_back_final_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "seed"
    real_open = parent_publish.os.open

    def fail_parent_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if not kwargs and Path(path) == tmp_path:
            raise OSError("forced parent fsync open failure")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(parent_publish.os, "open", fail_parent_open)
    with pytest.raises(prepare.O1C79PreparationError, match="publication failed"):
        prepare._publish_directory(destination, {"artifact.bin": b"sealed"})
    assert not destination.exists()


def test_atomic_publisher_refuses_existing_destination(tmp_path: Path) -> None:
    output = tmp_path / "existing"
    output.mkdir()
    sentinel = output / "sentinel"
    sentinel.write_bytes(b"sealed")
    with pytest.raises(prepare.O1C79PreparationError, match="already exists"):
        prepare._publish_directory(output, {"new": b"data"})
    assert sentinel.read_bytes() == b"sealed"
    assert tuple(output.iterdir()) == (sentinel,)


def test_release_contract_cannot_be_disabled(tmp_path: Path) -> None:
    with pytest.raises(prepare.O1C79PreparationError, match="must remain true"):
        prepare.prepare_o1c79_decision_ownership(
            capsule_dir=ROOT / prepare.DEFAULT_PARENT_CAPSULE_RELATIVE,
            parent_result_path=ROOT / prepare.DEFAULT_PARENT_RESULT_RELATIVE,
            output_dir=tmp_path / "disabled",
            enforce_release_contract=False,
        )


def test_cli_reports_bounded_preparation_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    def fail(**_kwargs: object) -> dict[str, object]:
        raise prepare.O1C79PreparationError("sealed terminal differs")

    monkeypatch.setattr(prepare, "prepare_o1c79_decision_ownership", fail)
    assert prepare.main(["--output-dir", (tmp_path / "bad").as_posix()]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "O1C-0079: sealed terminal differs\n"
