from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator, cast

import pytest

import o1_crypto_lab.o1c99_apple8_parent_centered_continuation_run as runner
from o1_crypto_lab import joint_score_sieve_v31 as v31
from o1_crypto_lab.causal_attic_v1 import canonical_json_bytes
from o1_crypto_lab.threshold_no_good_vault_v1 import ThresholdNoGoodClause


FAKE_NATIVE = b"fake-native-v28-executable\n"


class PostLaunchAdapterError(RuntimeError):
    def __init__(self, stdout: str) -> None:
        super().__init__("fixture post-launch semantic contract differs")
        self.returncode = 0
        self.stdout = stdout
        self.stderr = "fixture semantic rejection\n"
        self.cmd = ("fixture-native-v28",)
        self.memory_samples = ({"elapsed_seconds": 0.25, "rss_bytes": 1024},)
        self.failure_telemetry = {
            "schema": "fixture-native-failure-v1",
            "phase": "parse",
            "returncode": 0,
        }


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _evolve_bank(payload: bytes, variables: tuple[int, ...]) -> bytes:
    evolved = bytearray(payload)
    for variable in variables:
        offset = (variable - 1) * 96
        count = int.from_bytes(evolved[offset : offset + 8], "little")
        evolved[offset : offset + 8] = (count + 1).to_bytes(8, "little")
    return bytes(evolved)


def _writable_tree(root: Path) -> None:
    if not root.exists():
        return
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_dir():
            path.chmod(0o755)
        else:
            path.chmod(0o644)
    root.chmod(0o755)


def _write_canonical(path: Path, value: object) -> None:
    path.write_bytes(canonical_json_bytes(value))


def _reseal_forged_capsule(capsule: Path) -> None:
    result = json.loads((capsule / "result.json").read_bytes())
    (capsule / "RUN.md").write_bytes(runner._run_markdown(result))
    manifest, _ = runner._manifest_bytes(capsule)
    (capsule / "artifacts.sha256").write_bytes(manifest)
    closure = capsule / runner.NATIVE_CLOSURE_DIRECTORY
    for path in sorted(closure.rglob("*"), reverse=True):
        path.chmod(0o555 if path.is_dir() else 0o444)
    closure.chmod(0o555)


class Fixture:
    def __init__(
        self,
        root: Path,
        monkeypatch: pytest.MonkeyPatch,
        project: Path,
    ) -> None:
        self.root = root
        self.project = project
        self.adapter_calls = 0
        self.build_calls = 0
        self.smoke_calls = 0
        self.intent_seen = False
        self.fail_adapter = False
        self.adapter_exception: BaseException | None = None
        self.bad_smoke = False
        self.mutate_after_smoke: Path | None = None
        self.swap_root_include_during_compile = False
        self.tamper_staged_name: str | None = None
        self.tamper_staged_during_smoke: str | None = None
        self.compile_consumed_staged_closure = False
        self.key_model = bytes(range(32))
        self.native_override: v31.JointScoreSieveV31Result | None = None
        self.last_native_result: v31.JointScoreSieveV31Result | None = None
        self.semantic_replay_calls = 0

        monkeypatch.setattr(runner, "MINIMUM_DISK_FREE_BYTES", 1)
        monkeypatch.setattr(runner, "MAXIMUM_PERSISTENT_ARTIFACT_BYTES", 20_000_000)

        parent_capsule = root / runner.DEFAULT_PARENT_CAPSULE_RELATIVE
        parent_capsule.mkdir(parents=True)
        source_parent_capsule = project / runner.DEFAULT_PARENT_CAPSULE_RELATIVE
        shutil.copy2(
            source_parent_capsule / "artifacts.sha256",
            parent_capsule / "artifacts.sha256",
        )
        parent_result = root / runner.DEFAULT_PARENT_RESULT_RELATIVE
        parent_result.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(project / runner.DEFAULT_PARENT_RESULT_RELATIVE, parent_result)

        self.published = root / runner.PUBLISHED_PREPARATION_RELATIVE
        shutil.copytree(project / runner.PUBLISHED_PREPARATION_RELATIVE, self.published)
        _writable_tree(self.published)
        receipt = root / runner.PRIORITY_RECEIPT_RELATIVE
        self.receipt = receipt.read_bytes()
        self.page17 = (self.published / runner.ACTIVE_PROJECTION_NAME).read_bytes()
        self.bank = (self.published / runner.CONTINUATION_BANK_NAME).read_bytes()

        for index, relative in enumerate(runner.SOURCE_PATHS.values()):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.write_bytes(f"fixture-source-{index}:{relative}\n".encode())
        self.inputs = {
            "cnf": self._file("inputs/public.cnf", b"p cnf 1 0\n"),
            "potential": self._file("inputs/public.potential", b"potential\n"),
            "grouping": self._file("inputs/public.grouping", b"grouping\n"),
            "o1c73_config": self._file(
                "inputs/o1c73-config.json", canonical_json_bytes({"fixture": 73})
            ),
        }
        self.semantic_field = SimpleNamespace(observed_variables=tuple(range(1, 257)))
        self.semantic_grouping = SimpleNamespace(
            potential_sha256=_sha(self.inputs["potential"].read_bytes()),
            sha256=_sha(self.inputs["grouping"].read_bytes()),
        )
        monkeypatch.setattr(
            runner._native_v31._v9._v8._v7._v1,
            "_potential",
            lambda payload: self.semantic_field,
        )
        monkeypatch.setattr(
            runner._native_v31._v9,
            "validate_joint_score_sieve_grouping",
            lambda field, payload: self.semantic_grouping,
        )
        monkeypatch.setattr(
            runner._native_v31,
            "parse_threshold_no_good_vault",
            lambda payload, **kwargs: SimpleNamespace(
                sha256=_sha(payload), serialized=payload
            ),
        )
        monkeypatch.setattr(
            runner._native_v31,
            "vault_identity_from_sources",
            lambda **kwargs: {"fixture": "identity"},
        )
        monkeypatch.setattr(
            runner._native_v31,
            "validate_threshold_no_good_vault_identity",
            lambda vault, **kwargs: None,
        )
        monkeypatch.setattr(
            runner._native_v31._v9._v8,
            "_certify_input_vault",
            lambda vault, **kwargs: None,
        )
        monkeypatch.setattr(
            runner._native_v31,
            "_parse_native_payload",
            self.semantic_replay,
        )
        toolchain = root / "toolchain"
        toolchain.mkdir()
        self.compiler = toolchain / "c++"
        self.compiler.write_bytes(b"#!/bin/sh\nexit 1\n")
        self.compiler.chmod(0o755)
        self.include = toolchain / "include"
        self.include.mkdir()
        self.library = toolchain / "libcadical.a"
        self.library.write_bytes(b"fixture-cadical-library\n")
        self.config_path = root / runner.CONFIG_RELATIVE
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.write_config()

    def _file(self, relative: str, payload: bytes) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return path

    def system(self, root: Path) -> dict[str, object]:
        assert root == self.root
        return {
            "system": "Darwin",
            "machine": "arm64",
            "physical_memory_bytes": 16 * 1024**3,
            "available_memory_bytes": 8 * 1024**3,
            "disk_free_bytes": 8 * 1024**3,
            "sibling_solver_pids": [],
        }

    def command(self, argv: list[str], **kwargs: object) -> SimpleNamespace:
        if argv == [str(self.compiler), "--version"]:
            assert kwargs["cwd"] == self.root
            return SimpleNamespace(
                returncode=0, stdout=b"fixture clang 1\n", stderr=b""
            )
        if "-o" in argv:
            self.build_calls += 1
            assert self.build_calls == 1
            assert tuple(argv[1 : 1 + len(runner.COMPILER_FLAGS)]) == (
                runner.COMPILER_FLAGS
            )
            assert "-Wl,-no_uuid" not in argv
            assert not any("PUBLIC_FIXTURE" in argument for argument in argv)
            closure_root = Path(cast(Path, kwargs["cwd"]))
            assert closure_root.name == runner.NATIVE_CLOSURE_DIRECTORY
            assert argv[argv.index("-I") + 1] == "native"
            staged_source = closure_root / argv[-4]
            assert staged_source == closure_root / runner.SOURCE_PATHS["native_v28"]
            assert staged_source.is_file()
            transitive = runner.SOURCE_PATHS["priority_header"]
            staged_header = closure_root / transitive
            root_header = self.root / transitive
            staged_payload = staged_header.read_bytes()
            root_payload = root_header.read_bytes()
            if self.swap_root_include_during_compile:
                root_header.write_bytes(b"transient-live-root-swap\n")
                try:
                    assert staged_header.read_bytes() == staged_payload
                    assert staged_header.read_bytes() != root_header.read_bytes()
                    self.compile_consumed_staged_closure = True
                finally:
                    root_header.write_bytes(root_payload)
            if self.tamper_staged_name is not None:
                staged_tamper = (
                    closure_root / runner.SOURCE_PATHS[self.tamper_staged_name]
                )
                staged_tamper.chmod(0o644)
                staged_tamper.write_bytes(b"tampered-staged-closure\n")
            output = Path(argv[argv.index("-o") + 1])
            output.write_bytes(FAKE_NATIVE)
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        assert kwargs["cwd"] == self.root
        self.smoke_calls += 1
        assert self.smoke_calls == 1
        assert argv[1:] == ["--help"]
        output = Path(argv[0])
        assert output.read_bytes() == FAKE_NATIVE
        assert not (output.parents[1] / "episodes/00/intent.json").exists()
        if self.mutate_after_smoke is not None:
            self.mutate_after_smoke.write_bytes(b"changed-after-smoke\n")
        if self.tamper_staged_during_smoke is not None:
            staged_tamper = (
                output.parents[1]
                / runner.NATIVE_CLOSURE_DIRECTORY
                / runner.SOURCE_PATHS[self.tamper_staged_during_smoke]
            )
            staged_tamper.chmod(0o644)
            staged_tamper.write_bytes(b"tampered-during-smoke\n")
        return SimpleNamespace(
            returncode=0,
            stdout=b"bad usage\n" if self.bad_smoke else runner.NATIVE_V28_USAGE,
            stderr=b"",
        )

    def native_result(
        self,
        *,
        semantic: str = runner.PROOF_MINING_SEMANTIC,
        emitted_literal: int = 2,
        emitted: int = 0,
        active_new: int = 0,
        threshold_prunes: int = 0,
        status: int = 0,
        probe_count: int = 255,
        outcome_counts: tuple[int, int, int, int] | None = None,
        child_bound_evaluations: int | None = None,
        probed_variables: tuple[int, ...] | None = None,
    ) -> v31.JointScoreSieveV31Result:
        variables = probed_variables or tuple(
            variable for variable in range(1, 257) if variable != 241
        )
        next_bank = _evolve_bank(self.bank, variables)
        outcomes = outcome_counts or (probe_count, 0, 0, 0)
        actions: dict[str, object] = {
            "action_count": 1,
            "actions": [
                {
                    "semantic": semantic,
                    "confirmed": True,
                    "coincident_v6_pending": False,
                }
            ],
        }
        state: dict[str, object] = {
            "bank_bytes": len(self.bank),
            "bank_hex": next_bank.hex(),
            "current_bank_sha256": _sha(next_bank),
            "probe_trace": {"count": probe_count},
            "probe_counters": {
                "child_bound_evaluations": 2 * probe_count
                if child_bound_evaluations is None
                else child_bound_evaluations,
                "NEITHER_PRUNABLE": outcomes[0],
                "ZERO_PRUNABLE": outcomes[1],
                "ONE_PRUNABLE": outcomes[2],
                "BOTH_PRUNABLE": outcomes[3],
            },
        }
        priority_seed = {
            "payload_sha256": _sha(self.bank),
            "payload_bytes": len(self.bank),
            "seed_source": "sealed-live-continuation-bank",
            "live_continuation_bank_identity": True,
            "fresh_seed_parser_used": False,
        }
        vault: dict[str, object] = {
            "fully_emitted_clause_count": emitted,
            "emitted_new_clause_count": active_new,
            "fully_emitted_clauses": [
                {"classification": "new", "literals": [emitted_literal]}
                for _ in range(emitted)
            ],
        }
        base = {
            "pending_clause_count": 0,
            "threshold_prunes": threshold_prunes,
        }
        resources: dict[str, object] = {
            "peak_rss_bytes": 64 * 1024**2,
            "wall_microseconds": 50_000,
            "cpu_microseconds": 20_000,
        }
        raw_stats: dict[str, object] = {
            "conflicts": 17,
            "conflicts_before_solve": 0,
            "solve_conflicts": 17,
            "decisions": 3,
            "propagations": 9,
        }
        stats: dict[str, object] = {
            **raw_stats,
            "requested_conflicts": 128,
            "unused_requested_conflicts": 111,
            "conflict_limit_overshoot": 0,
            "billed_conflicts": 17,
        }
        adapter_memory: dict[str, object] = {
            "memory_series_schema": (v31._v9.JOINT_SCORE_SIEVE_MEMORY_SERIES_SCHEMA),
            "memory_sample_limit": v31._v9.JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES,
            "memory_sample_count": 0,
            "memory_samples": [],
            "memory_peak_bytes": None,
            "memory_last_bytes": None,
            "memory_last_elapsed_seconds": None,
        }
        raw: dict[str, object] = {
            "schema": v31.JOINT_SCORE_SIEVE_RESULT_SCHEMA,
            "seed": 0,
            "threshold": runner.THRESHOLD,
            "conflict_limit": 128,
            "status": status,
            "key_model_hex": self.key_model.hex() if status == 10 else None,
            "cnf_sha256": _sha(self.inputs["cnf"].read_bytes()),
            "potential_sha256": _sha(self.inputs["potential"].read_bytes()),
            "active_vault_sha256": _sha(self.page17),
            "priority_seed": priority_seed,
            "priority_state": state,
            "priority_actions": actions,
            "decision_ownership": {"schema": "fixture-ownership"},
            "stats": raw_stats,
            "base_sieve": base,
            "vault": vault,
            "resources": resources,
        }
        stdout = canonical_json_bytes(raw).decode("ascii")
        return v31.JointScoreSieveV31Result(
            status=status,
            conflict_limit=128,
            threshold=runner.THRESHOLD,
            key_model=self.key_model if status == 10 else None,
            stats=cast(Any, stats),
            resources=cast(Any, resources),
            base_result=cast(Any, SimpleNamespace(adapter_memory=adapter_memory)),
            priority_seed=priority_seed,
            priority_state=state,
            priority_actions=actions,
            decision_ownership=cast(dict[str, object], raw["decision_ownership"]),
            next_priority_seed=next_bank,
            normalized_summary={},
            raw=raw,
            native_stdout=stdout,
            native_stdout_sha256=_sha(stdout.encode()),
            command=(),
        )

    def adapter(self, **kwargs: object) -> object:
        self.adapter_calls += 1
        executable = Path(cast(str | Path, kwargs["executable"]))
        intent_path = executable.parents[1] / "episodes/00/intent.json"
        assert intent_path.is_file()
        intent = json.loads(intent_path.read_bytes())
        assert intent["page17_burned"] is True
        assert intent["lineage30_burned"] is True
        assert intent["page16_retry_or_replay_authorized"] is False
        assert intent["page15_retry_or_replay_authorized"] is False
        assert "page14_burned" not in intent
        assert "lineage27_burned" not in intent
        assert intent["page14_replay_authorized"] is False
        assert intent["page13_replay_authorized"] is False
        assert intent["page12_replay_authorized"] is False
        assert intent["page11_replay_authorized"] is False
        assert intent["page10_replay_authorized"] is False
        assert intent["page9_retry_or_replay_authorized"] is False
        assert intent["native_executable"] == {
            "path": f"native/{runner.NATIVE_EXECUTABLE_NAME}",
            "serialized_bytes": len(FAKE_NATIVE),
            "sha256": _sha(FAKE_NATIVE),
        }
        assert kwargs["expected_source_sha256"] == self.source_sha["native_v28"]
        assert kwargs["source_path"] == (
            executable.parents[1]
            / runner.NATIVE_CLOSURE_DIRECTORY
            / runner.SOURCE_PATHS["native_v28"]
        )
        assert kwargs["expected_executable_sha256"] == _sha(FAKE_NATIVE)
        assert kwargs["expected_executable_bytes"] == len(FAKE_NATIVE)
        assert kwargs["seed"] == 0
        assert kwargs["conflict_limit"] == 128
        assert "public_fixture" not in kwargs
        assert Path(cast(Path, kwargs["vault_path"])).read_bytes() == self.page17
        assert kwargs["sealed_page17_path"] == kwargs["vault_path"]
        assert Path(cast(Path, kwargs["priority_seed_path"])).read_bytes() == self.bank
        self.intent_seen = True
        if self.adapter_exception is not None:
            raise self.adapter_exception
        if self.fail_adapter:
            raise RuntimeError("fixture native process failed")
        result = self.native_override or self.native_result()
        self.last_native_result = result
        return result

    def semantic_replay(
        self, payload: object, **kwargs: object
    ) -> v31.JointScoreSieveV31Result:
        self.semantic_replay_calls += 1
        if self.last_native_result is None:
            raise AssertionError("semantic replay preceded native evidence")
        replayed = self.last_native_result
        if payload != replayed.raw:
            observed = cast(dict[str, Any], payload)
            expected = dict(replayed.raw)
            observed_key = observed.get("key_model_hex")
            expected["key_model_hex"] = observed_key
            assert observed == expected
            assert isinstance(observed_key, str)
            replayed = replace(
                replayed,
                raw=dict(observed),
                key_model=bytes.fromhex(observed_key),
            )
        assert kwargs["vault_caps"] == runner.O1C66_VAULT_CAPS
        assert kwargs["field"] is self.semantic_field
        assert kwargs["grouping"] is self.semantic_grouping
        assert kwargs["grouping_sha256"] == _sha(self.inputs["grouping"].read_bytes())
        assert kwargs["cnf_sha256"] == _sha(self.inputs["cnf"].read_bytes())
        assert kwargs["potential_sha256"] == _sha(self.inputs["potential"].read_bytes())
        assert kwargs["threshold"] == runner.THRESHOLD
        assert kwargs["requested_conflicts"] == runner.REQUESTED_CONFLICTS
        assert kwargs["seed"] == runner.SEED
        assert kwargs["priority_seed_sha256"] == runner.CONTINUATION_BANK_SHA256
        assert kwargs["production_seal"] is True
        assert kwargs["memory_limit_bytes"] == runner.MEMORY_LIMIT_BYTES
        assert kwargs["memory_samples"] == ()
        records = cast(Any, kwargs["priority_seed_records"])
        assert len(records) == 256
        assert sum(record.count for record in records) == runner.INPUT_BANK_TOTAL_COUNT
        input_vault = cast(Any, kwargs["input_vault"])
        assert input_vault.sha256 == _sha(self.page17)
        return replayed

    def write_config(self) -> None:
        self.source_sha = {
            name: _sha((self.root / relative).read_bytes())
            for name, relative in runner.SOURCE_PATHS.items()
        }
        config = {
            "schema": runner.CONFIG_SCHEMA,
            "attempt_id": runner.ATTEMPT_ID,
            "parent": {
                "capsule": runner.DEFAULT_PARENT_CAPSULE_RELATIVE.as_posix(),
                "capsule_manifest_sha256": runner.PARENT_CAPSULE_MANIFEST_SHA256,
                "result": runner.DEFAULT_PARENT_RESULT_RELATIVE.as_posix(),
                "result_sha256": runner.PARENT_RESULT_SHA256,
            },
            "preparation": {
                "published_directory": runner.PUBLISHED_PREPARATION_RELATIVE.as_posix(),
                "manifest": (
                    runner.PUBLISHED_PREPARATION_RELATIVE
                    / runner.PREPARATION_MANIFEST_NAME
                ).as_posix(),
                "manifest_sha256": runner.PUBLISHED_MANIFEST_SHA256,
                "manifest_bytes": runner.PUBLISHED_MANIFEST_BYTES,
                "priority_state_receipt": runner.PRIORITY_RECEIPT_RELATIVE.as_posix(),
                "priority_state_receipt_sha256": runner.PRIORITY_RECEIPT_SHA256,
                "priority_state_receipt_bytes": runner.PRIORITY_RECEIPT_BYTES,
                "candidate_order_sha256": runner.CONTINUATION_CANDIDATE_ORDER_SHA256,
            },
            "inputs": {
                **{
                    name: path.relative_to(self.root).as_posix()
                    for name, path in self.inputs.items()
                },
                **{
                    f"{name}_sha256": _sha(path.read_bytes())
                    for name, path in self.inputs.items()
                },
            },
            "native": {
                "source": runner.SOURCE_PATHS["native_v28"],
                "source_sha256": self.source_sha["native_v28"],
                "compiler": str(self.compiler),
                "compiler_flags": list(runner.COMPILER_FLAGS),
                "cadical_include": str(self.include),
                "cadical_library": str(self.library),
                "cadical_library_sha256": _sha(self.library.read_bytes()),
                "adapter_schema": v31.JOINT_SCORE_SIEVE_ADAPTER_SCHEMA,
                "result_schema": v31.JOINT_SCORE_SIEVE_RESULT_SCHEMA,
                "page17_sha256": runner.PAGE16_SHA256,
                "page17_bytes": runner.PAGE16_SERIALIZED_BYTES,
                "continuation_bank_sha256": runner.CONTINUATION_BANK_SHA256,
                "continuation_bank_bytes": runner.CONTINUATION_BANK_BYTES,
                "candidate_order_sha256": runner.CONTINUATION_CANDIDATE_ORDER_SHA256,
            },
            "source": {
                "paths": runner.SOURCE_PATHS,
                "expected_sha256": self.source_sha,
            },
            "budgets": {
                "required_system": "Darwin",
                "required_machine": "arm64",
                "lineage_call_ordinals": [30],
                "local_episode_ordinals": [0],
                "seed": 0,
                "threshold": runner.THRESHOLD,
                "requested_conflicts": 128,
                "maximum_native_solver_calls": 1,
                "timeout_seconds": 45.0,
                "memory_limit_bytes": 536_870_912,
                "minimum_available_memory_bytes": 536_870_912,
                "minimum_disk_free_bytes": 1,
                "maximum_persistent_artifact_bytes": 20_000_000,
                "maximum_fresh_targets": 0,
                "maximum_fresh_reveal_calls": 0,
                "maximum_refits": 0,
                "maximum_mps_calls": 0,
                "maximum_gpu_calls": 0,
                "retry_authorized": False,
                "replay_authorized": False,
            },
            "next_action": "Burn Page 17 / lineage 30 once; never retry or replay.",
        }
        self.config_path.write_bytes(canonical_json_bytes(config))

    def execute(self) -> dict[str, object]:
        fixed = datetime(2026, 7, 20, 17, 0, 0, tzinfo=timezone.utc)
        return runner.run(
            self.config_path,
            root=self.root,
            adapter_run=self.adapter,
            command_runner=self.command,
            system_probe=self.system,
            public_verifier=lambda key: key == self.key_model,
            now=lambda: fixed,
        )


@pytest.fixture
def fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Fixture]:
    project = Path(__file__).resolve().parents[1]
    value = Fixture(tmp_path.resolve(), monkeypatch, project)
    yield value
    _writable_tree(tmp_path)


def test_preflight_validates_published_bundle_without_regeneration(
    fixture: Fixture,
) -> None:
    row = runner.preflight(
        fixture.config_path,
        root=fixture.root,
        system_probe=fixture.system,
    )
    assert row["passed"] is True
    assert row["native_solver_calls"] == 0
    published = cast(dict[str, object], row["published_preparation"])
    assert published["all_artifact_seals_verified"] is True
    assert published["manifest_schema"] == runner.PREPARATION_SCHEMA
    assert published["native_capacity_proof_verified_before_intent"] is True
    capacity = cast(dict[str, Any], published["native_capacity_proof"])
    assert capacity["caps"] == {
        "maximum_clauses": 512,
        "maximum_literals": 1_600_000,
        "maximum_serialized_bytes": 8_388_608,
    }
    clause = cast(dict[str, Any], capacity["clause_headroom_guarantee"])
    assert clause == {
        "native_vault_maximum_clauses": 512,
        "page17_input_clauses": 249,
        "maximum_additional_clauses_before_capacity_terminal": 263,
        "parent_centered_action_capacity": 256,
        "spare_clause_slots_beyond_action_capacity": 7,
        "proved_sufficient": True,
    }
    assert (
        clause["page17_input_clauses"]
        + clause["maximum_additional_clauses_before_capacity_terminal"]
        == clause["native_vault_maximum_clauses"]
    )
    assert (
        clause["maximum_additional_clauses_before_capacity_terminal"]
        >= clause["parent_centered_action_capacity"]
    )
    assert capacity["literal_future_emission_safety_claimed"] is False
    assert capacity["serialized_byte_future_emission_safety_claimed"] is False
    assert len(cast(dict[str, object], row["prepared_artifacts"])) == 10
    assert fixture.adapter_calls == fixture.build_calls == fixture.smoke_calls == 0


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("clause_count",), 250),
        (("headroom", "clauses"), 262),
        (("headroom", "literals"), 906_816),
        (("headroom", "serialized_bytes"), 5_614_688),
    ],
)
def test_preflight_rejects_capacity_proof_mutation_before_intent(
    fixture: Fixture,
    path: tuple[str, ...],
    replacement: object,
) -> None:
    manifest = cast(
        dict[str, Any],
        json.loads((fixture.published / runner.PREPARATION_MANIFEST_NAME).read_bytes()),
    )
    target = cast(dict[str, Any], manifest["page17"])
    for field in path[:-1]:
        target = cast(dict[str, Any], target)[field]
    cast(dict[str, Any], target)[path[-1]] = replacement
    with pytest.raises(
        runner.O1C99RunError, match="Page-17 native capacity proof differs"
    ):
        runner._validate_native_capacity_proof(manifest["page17"])
    assert fixture.adapter_calls == fixture.build_calls == fixture.smoke_calls == 0
    assert not list((fixture.root / "runs").glob(f"*_{runner.CAPSULE_SUFFIX}"))


def test_preflight_rejects_published_mutation_without_build_or_call(
    fixture: Fixture,
) -> None:
    (fixture.published / runner.OCCURRENCES_NAME).write_bytes(b"mutated\n")
    with pytest.raises(runner.O1C99RunError, match="artifact seal differs"):
        runner.preflight(
            fixture.config_path,
            root=fixture.root,
            system_probe=fixture.system,
        )
    assert fixture.adapter_calls == fixture.build_calls == fixture.smoke_calls == 0


def test_one_build_smoke_and_observed_identity_precede_intent(
    fixture: Fixture,
) -> None:
    result = fixture.execute()
    assert fixture.intent_seen is True
    assert (fixture.build_calls, fixture.smoke_calls, fixture.adapter_calls) == (
        1,
        1,
        1,
    )
    assert result["classification"] == runner.ACTIVATION_ONLY
    capsule = fixture.root / cast(str, result["capsule"])
    build = json.loads((capsule / "native-build.json").read_bytes())
    invocation = json.loads((capsule / "invocation.json").read_bytes())
    intent = json.loads((capsule / "episodes/00/intent.json").read_bytes())
    identity = {
        "path": f"native/{runner.NATIVE_EXECUTABLE_NAME}",
        "serialized_bytes": len(FAKE_NATIVE),
        "sha256": _sha(FAKE_NATIVE),
    }
    assert build["build_invocations"] == 1
    assert build["working_directory"] == (
        f"<capsule>/{runner.NATIVE_CLOSURE_DIRECTORY}"
    )
    assert [row["name"] for row in build["include_closure"]] == list(
        runner.NATIVE_CLOSURE_NAMES
    )
    for row in build["include_closure"]:
        staged = capsule / row["path"]
        assert (
            staged.read_bytes() == (fixture.root / row["configured_path"]).read_bytes()
        )
        assert staged.stat().st_mode & 0o777 == 0o444
    assert build["executable"] == invocation["native_executable"] == identity
    assert intent["native_executable"] == identity
    assert build["smoke"] == invocation["native_smoke"]
    assert build["smoke"]["stdout"] == {
        "serialized_bytes": len(runner.NATIVE_V28_USAGE),
        "sha256": _sha(runner.NATIVE_V28_USAGE),
    }
    assert build["smoke"]["stderr"] == {
        "serialized_bytes": 0,
        "sha256": _sha(b""),
    }
    assert fixture.execute() == result
    assert (fixture.build_calls, fixture.smoke_calls, fixture.adapter_calls) == (
        1,
        1,
        1,
    )


def test_compile_consumes_snapshot_during_transient_live_root_swap(
    fixture: Fixture,
) -> None:
    fixture.swap_root_include_during_compile = True
    result = fixture.execute()
    assert result["classification"] == runner.ACTIVATION_ONLY
    assert fixture.compile_consumed_staged_closure is True
    assert fixture.adapter_calls == fixture.build_calls == fixture.smoke_calls == 1


def test_publicly_verified_sat_capsule_recovers_without_a_second_call(
    fixture: Fixture,
) -> None:
    fixture.native_override = fixture.native_result(status=10)
    result = fixture.execute()
    assert result["classification"] == runner.SCIENCE_MODEL
    episode = cast(list[dict[str, Any]], result["episodes"])[0]
    assert episode["key_model_sha256"] == _sha(fixture.key_model)
    assert fixture.execute() == result
    assert fixture.adapter_calls == fixture.build_calls == fixture.smoke_calls == 1


@pytest.mark.parametrize(
    ("phase", "expected_smoke_calls"),
    [("compile", 0), ("smoke", 1)],
)
def test_staged_closure_tamper_is_rejected_before_intent(
    fixture: Fixture, phase: str, expected_smoke_calls: int
) -> None:
    if phase == "compile":
        fixture.tamper_staged_name = "priority_header"
    else:
        fixture.tamper_staged_during_smoke = "priority_header"
    with pytest.raises(runner.O1C99RunError, match="staged native closure"):
        fixture.execute()
    assert fixture.build_calls == 1
    assert fixture.smoke_calls == expected_smoke_calls
    assert fixture.adapter_calls == 0
    assert not list((fixture.root / "runs").glob(f"*_{runner.CAPSULE_SUFFIX}"))


def test_bad_help_smoke_is_preintent_and_leaves_no_capsule(fixture: Fixture) -> None:
    fixture.bad_smoke = True
    with pytest.raises(runner.O1C99RunError, match="--help smoke seal differs"):
        fixture.execute()
    assert fixture.build_calls == fixture.smoke_calls == 1
    assert fixture.adapter_calls == 0
    assert not list((fixture.root / "runs").glob(f"*_{runner.CAPSULE_SUFFIX}"))


def test_source_mutation_after_smoke_never_burns_or_rebuilds(fixture: Fixture) -> None:
    fixture.mutate_after_smoke = fixture.inputs["potential"]
    with pytest.raises(runner.O1C99RunError, match="changed before native call"):
        fixture.execute()
    capsules = list((fixture.root / "runs").glob(f"*_{runner.CAPSULE_SUFFIX}"))
    assert len(capsules) == 1
    assert not (capsules[0] / "episodes/00/intent.json").exists()
    with pytest.raises(runner.O1C99RunError, match="pre-intent capsule"):
        fixture.execute()
    assert fixture.build_calls == fixture.smoke_calls == 1
    assert fixture.adapter_calls == 0


def test_binary_rehash_immediately_before_adapter_is_terminal(
    fixture: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = runner._atomic_json

    def mutate_after_intent(path: Path, value: object, *, mode: int = 0o444) -> None:
        original(path, value, mode=mode)
        if path.name == "intent.json":
            executable = path.parents[2] / "native" / runner.NATIVE_EXECUTABLE_NAME
            executable.chmod(0o755)
            executable.write_bytes(b"mutated-after-intent\n")

    monkeypatch.setattr(runner, "_atomic_json", mutate_after_intent)
    result = fixture.execute()
    episode = cast(list[dict[str, Any]], result["episodes"])[0]
    assert result["classification"] == runner.OPERATIONAL_TERMINAL
    assert episode["terminal_failure"]["phase"] == "PRE_CALL"
    assert episode["page17_burned"] is True
    assert episode["lineage30_burned"] is True
    assert episode["native_calls_consumed"] == 0
    assert fixture.adapter_calls == 0
    assert fixture.execute() == result
    assert fixture.build_calls == fixture.smoke_calls == 1


def test_missing_binary_after_intent_is_recoverable_terminal(
    fixture: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = runner._atomic_json

    def delete_after_intent(path: Path, value: object, *, mode: int = 0o444) -> None:
        original(path, value, mode=mode)
        if path.name == "intent.json":
            executable = path.parents[2] / "native" / runner.NATIVE_EXECUTABLE_NAME
            executable.unlink()

    monkeypatch.setattr(runner, "_atomic_json", delete_after_intent)
    result = fixture.execute()
    episode = cast(list[dict[str, Any]], result["episodes"])[0]
    failure = cast(dict[str, Any], episode["terminal_failure"])
    capsule = fixture.root / cast(str, result["capsule"])
    assert result["classification"] == runner.OPERATIONAL_TERMINAL
    assert failure["phase"] == "PRE_CALL"
    assert failure["exception_type"] == "O1C99RunError"
    assert failure["message"] == "native executable is unreadable"
    assert failure["native_calls_consumed"] == 0
    assert failure["native_process_evidence"] is None
    assert list((capsule / "native").iterdir()) == []
    assert fixture.execute() == result
    assert fixture.adapter_calls == 0
    assert fixture.build_calls == fixture.smoke_calls == 1
    assert fixture.semantic_replay_calls == 0


def test_adapter_failure_after_intent_is_terminal_and_never_retried(
    fixture: Fixture,
) -> None:
    fixture.fail_adapter = True
    result = fixture.execute()
    episode = cast(list[dict[str, Any]], result["episodes"])[0]
    assert result["classification"] == runner.OPERATIONAL_TERMINAL
    assert episode["terminal_failure"]["phase"] == "CALL"
    assert episode["native_calls_consumed"] == 1
    assert fixture.execute() == result
    assert fixture.adapter_calls == fixture.build_calls == fixture.smoke_calls == 1


def test_return_zero_adapter_contract_failure_preserves_native_stdout_in_capsule(
    fixture: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    original_create = runner._atomic_create
    original_json = runner._atomic_json

    def track_create(path: Path, payload: bytes, *, mode: int = 0o444) -> None:
        if path.name == runner.NATIVE_STDOUT_NAME:
            events.append("native-stdout")
        original_create(path, payload, mode=mode)

    def track_json(path: Path, value: object, *, mode: int = 0o444) -> None:
        if path.name == "terminal-failure.json":
            events.append("terminal-failure")
        original_json(path, value, mode=mode)

    monkeypatch.setattr(runner, "_atomic_create", track_create)
    monkeypatch.setattr(runner, "_atomic_json", track_json)
    native = fixture.native_result()
    stdout = cast(str, native.native_stdout).encode("ascii")
    fixture.adapter_exception = PostLaunchAdapterError(stdout.decode("ascii"))

    result = fixture.execute()
    episode = cast(list[dict[str, Any]], result["episodes"])[0]
    capsule = fixture.root / cast(str, result["capsule"])
    stdout_path = capsule / "episodes/00" / runner.NATIVE_STDOUT_NAME
    expected_row = {
        "path": runner.NATIVE_STDOUT_NAME,
        "serialized_bytes": len(stdout),
        "sha256": _sha(stdout),
    }

    assert result["classification"] == runner.OPERATIONAL_TERMINAL
    assert events == ["native-stdout", "terminal-failure"]
    assert episode["terminal_failure"]["phase"] == "POST_CALL"
    assert episode["native_result_returned"] is False
    assert episode["native_stdout"] == expected_row
    assert episode["terminal_failure"]["native_stdout"] == expected_row
    assert episode["terminal_failure"]["native_process_evidence"] == {
        "returncode": 0,
        "stdout_bytes": len(stdout),
        "stdout_sha256": _sha(stdout),
        "stderr_bytes": len(b"fixture semantic rejection\n"),
        "stderr_sha256": _sha(b"fixture semantic rejection\n"),
        "stderr_tail": "fixture semantic rejection\n",
        "command": ["fixture-native-v28"],
        "memory_samples": [{"elapsed_seconds": 0.25, "rss_bytes": 1024}],
        "failure_telemetry": {
            "schema": "fixture-native-failure-v1",
            "phase": "parse",
            "returncode": 0,
        },
    }
    assert stdout_path.read_bytes() == stdout
    artifact_manifest = (capsule / "artifacts.sha256").read_text()
    assert _sha(stdout) in artifact_manifest
    assert "episodes/00/native-stdout.json" in artifact_manifest
    assert fixture.execute() == result
    assert stdout_path.read_bytes() == stdout
    assert fixture.adapter_calls == fixture.build_calls == fixture.smoke_calls == 1


@pytest.mark.parametrize(
    "defect", ["bank-delta", "outcome-sum", "child-evaluations", "zero-241"]
)
def test_post_result_conservation_failure_is_terminal_and_preserves_stdout(
    fixture: Fixture, defect: str
) -> None:
    eligible = tuple(variable for variable in range(1, 257) if variable != 241)
    if defect == "bank-delta":
        fixture.native_override = fixture.native_result(probed_variables=eligible[:-1])
    elif defect == "outcome-sum":
        fixture.native_override = fixture.native_result(outcome_counts=(254, 0, 0, 0))
    elif defect == "child-evaluations":
        fixture.native_override = fixture.native_result(child_bound_evaluations=509)
    else:
        fixture.native_override = fixture.native_result(
            probed_variables=eligible[:-1] + (241,)
        )

    result = fixture.execute()
    episode = cast(list[dict[str, Any]], result["episodes"])[0]
    capsule = fixture.root / cast(str, result["capsule"])
    assert result["classification"] == runner.OPERATIONAL_TERMINAL
    assert episode["terminal_failure"]["phase"] == "POST_CALL"
    assert episode["terminal_failure"]["message"] == (
        "native post-result conservation differs"
    )
    assert episode["native_calls_consumed"] == 1
    assert episode["science"] == {"science_gain": False}
    assert episode["native_stdout"] is not None
    assert (capsule / "episodes/00" / runner.NATIVE_STDOUT_NAME).is_file()
    assert not (capsule / "episodes/00" / runner.FINAL_BANK_NAME).exists()
    assert fixture.execute() == result
    assert fixture.adapter_calls == fixture.build_calls == fixture.smoke_calls == 1


@pytest.mark.parametrize(
    "defect",
    [
        "call-ceiling",
        "burn-intent",
        "capsule-config",
        "missing-native-result",
        "stdout-result-divergence",
        "episode-inline-divergence",
        "target-read-claim",
    ],
)
def test_self_consistent_forged_completed_capsule_is_never_republished(
    fixture: Fixture, defect: str
) -> None:
    result = fixture.execute()
    capsule = fixture.root / cast(str, result["capsule"])
    authoritative = fixture.root / runner.RESULT_RELATIVE
    _writable_tree(capsule)
    authoritative.unlink()
    episode_dir = capsule / "episodes" / "00"
    episode_path = episode_dir / "episode.json"
    result_path = capsule / "result.json"
    episode = cast(dict[str, Any], json.loads(episode_path.read_bytes()))
    forged_result = cast(dict[str, Any], json.loads(result_path.read_bytes()))

    if defect == "call-ceiling":
        episode["native_calls_consumed"] = 0
        episode["requested_conflicts"] = 0
        forged_result["resources"]["native_solver_calls"] = 0
        forged_result["resources"]["requested_conflicts"] = 0
        forged_result["episodes"] = [episode]
        _write_canonical(episode_path, episode)
        _write_canonical(result_path, forged_result)
    elif defect == "burn-intent":
        intent_path = episode_dir / "intent.json"
        intent = cast(dict[str, Any], json.loads(intent_path.read_bytes()))
        intent["page17_burned"] = False
        _write_canonical(intent_path, intent)
        episode["intent_sha256"] = _sha(intent_path.read_bytes())
        forged_result["episodes"] = [episode]
        _write_canonical(episode_path, episode)
        _write_canonical(result_path, forged_result)
    elif defect == "capsule-config":
        config_path = capsule / "config.json"
        config = cast(dict[str, Any], json.loads(config_path.read_bytes()))
        config["next_action"] = "forged recovery contract"
        _write_canonical(config_path, config)
    elif defect == "missing-native-result":
        native_result = episode_dir / "native-result.json"
        native_result.unlink()
        del episode["archived_native_components"]["native-result.json"]
        forged_result["episodes"] = [episode]
        _write_canonical(episode_path, episode)
        _write_canonical(result_path, forged_result)
    elif defect == "stdout-result-divergence":
        native_result = episode_dir / "native-result.json"
        raw = cast(dict[str, Any], json.loads(native_result.read_bytes()))
        raw["forged_projection"] = True
        _write_canonical(native_result, raw)
        episode["archived_native_components"]["native-result.json"] = (
            runner._artifact_row(native_result, relative_to=episode_dir)
        )
        forged_result["episodes"] = [episode]
        _write_canonical(episode_path, episode)
        _write_canonical(result_path, forged_result)
    elif defect == "episode-inline-divergence":
        episode["stop_reason"] = "forged-stop-reason"
        _write_canonical(episode_path, episode)
    else:
        forged_result["claim_boundary"]["target_bytes_read"] = True
        _write_canonical(result_path, forged_result)

    _reseal_forged_capsule(capsule)
    with pytest.raises(runner.O1C99RunError):
        fixture.execute()
    assert not authoritative.exists()
    assert fixture.adapter_calls == fixture.build_calls == fixture.smoke_calls == 1


def test_resealed_forged_sat_key_fails_independent_public_verification(
    fixture: Fixture,
) -> None:
    fixture.native_override = fixture.native_result(status=10)
    result = fixture.execute()
    capsule = fixture.root / cast(str, result["capsule"])
    authoritative = fixture.root / runner.RESULT_RELATIVE
    _writable_tree(capsule)
    authoritative.unlink()
    episode_dir = capsule / "episodes" / "00"
    episode_path = episode_dir / "episode.json"
    result_path = capsule / "result.json"
    raw_path = episode_dir / "native-result.json"
    stdout_path = episode_dir / runner.NATIVE_STDOUT_NAME
    raw = cast(dict[str, Any], json.loads(raw_path.read_bytes()))
    forged_key = bytes(reversed(range(32)))
    raw["key_model_hex"] = forged_key.hex()
    _write_canonical(raw_path, raw)
    _write_canonical(stdout_path, raw)
    episode = cast(dict[str, Any], json.loads(episode_path.read_bytes()))
    episode["key_model_sha256"] = _sha(forged_key)
    episode["native_stdout"] = runner._artifact_row(
        stdout_path, relative_to=episode_dir
    )
    episode["archived_native_components"]["native-result.json"] = runner._artifact_row(
        raw_path, relative_to=episode_dir
    )
    forged_result = cast(dict[str, Any], json.loads(result_path.read_bytes()))
    forged_result["episodes"] = [episode]
    _write_canonical(episode_path, episode)
    _write_canonical(result_path, forged_result)
    _reseal_forged_capsule(capsule)

    with pytest.raises(runner.O1C99RunError, match="not publicly verified"):
        fixture.execute()
    assert not authoritative.exists()
    assert fixture.adapter_calls == fixture.build_calls == fixture.smoke_calls == 1


def test_resealed_self_consistent_forged_novelty_fails_v31_semantic_replay(
    fixture: Fixture,
) -> None:
    result = fixture.execute()
    capsule = fixture.root / cast(str, result["capsule"])
    authoritative = fixture.root / runner.RESULT_RELATIVE
    _writable_tree(capsule)
    authoritative.unlink()
    episode_dir = capsule / "episodes" / "00"
    raw_path = episode_dir / "native-result.json"
    stdout_path = episode_dir / runner.NATIVE_STDOUT_NAME
    vault_path = episode_dir / "vault.json"
    episode_path = episode_dir / "episode.json"
    result_path = capsule / "result.json"
    raw = cast(dict[str, Any], json.loads(raw_path.read_bytes()))
    forged_vault = cast(dict[str, Any], json.loads(vault_path.read_bytes()))
    forged_vault["fully_emitted_clause_count"] = 1
    forged_vault["emitted_new_clause_count"] = 1
    forged_vault["fully_emitted_clauses"] = [{"classification": "new", "literals": [2]}]
    raw["vault"] = forged_vault
    _write_canonical(raw_path, raw)
    _write_canonical(stdout_path, raw)
    _write_canonical(vault_path, forged_vault)
    episode = cast(dict[str, Any], json.loads(episode_path.read_bytes()))
    episode["native_stdout"] = runner._artifact_row(
        stdout_path, relative_to=episode_dir
    )
    for name, path in (
        ("native-result.json", raw_path),
        ("vault.json", vault_path),
    ):
        episode["archived_native_components"][name] = runner._artifact_row(
            path, relative_to=episode_dir
        )
    episode["science"]["science_gain"] = True
    episode["science"]["fully_emitted_clauses"] = 1
    episode["science"]["globally_novel_clauses"] = 1
    episode["science"]["active_page17_new_clauses"] = 1
    episode["classification"] = runner.SCIENCE_CLAUSE
    episode["stop_reason"] = "globally-novel-clause"
    forged_result = cast(dict[str, Any], json.loads(result_path.read_bytes()))
    forged_result["classification"] = runner.SCIENCE_CLAUSE
    forged_result["stop_reason"] = "globally-novel-clause"
    forged_result["science_gain"] = True
    forged_result["episodes"] = [episode]
    _write_canonical(episode_path, episode)
    _write_canonical(result_path, forged_result)
    _reseal_forged_capsule(capsule)

    with pytest.raises(runner.O1C99RunError, match="semantic replay"):
        fixture.execute()
    assert fixture.semantic_replay_calls == 1
    assert not authoritative.exists()
    assert fixture.adapter_calls == fixture.build_calls == fixture.smoke_calls == 1


def test_novelty_uses_complete_published_attic_digest_set(fixture: Fixture) -> None:
    clause = ThresholdNoGoodClause((1,))
    result = fixture.native_result(emitted=1, active_new=1, emitted_literal=1)
    evidence = runner._validate_native_result(
        result, cast(str, result.native_stdout).encode()
    )
    _, science, classification, _ = runner._science_and_operation(
        evidence,
        globally_known_clause_sha256=frozenset({_sha(clause.serialized)}),
    )
    assert science["globally_novel_clauses"] == 0
    assert science["active_page17_new_clauses"] == 1
    assert classification == runner.ACTIVATION_ONLY


@pytest.mark.parametrize(
    ("semantic", "threshold_prunes", "emitted", "expected"),
    [
        (runner.PROOF_MINING_SEMANTIC, 1, 0, runner.ACTIVATION_ONLY),
        (runner.CERTIFIED_CROSSING_SEMANTIC, 0, 1, runner.SCIENCE_CLAUSE),
        (runner.CERTIFIED_CROSSING_SEMANTIC, 1, 0, runner.ACTIVATION_ONLY),
        (runner.CERTIFIED_CROSSING_SEMANTIC, 1, 1, runner.SCIENCE_PRUNE),
    ],
)
def test_actual_certified_prune_is_separate_from_threshold_telemetry(
    fixture: Fixture,
    semantic: str,
    threshold_prunes: int,
    emitted: int,
    expected: str,
) -> None:
    result = fixture.native_result(
        semantic=semantic,
        threshold_prunes=threshold_prunes,
        emitted=emitted,
        active_new=emitted,
    )
    evidence = runner._validate_native_result(
        result, cast(str, result.native_stdout).encode()
    )
    _, science, classification, _ = runner._science_and_operation(
        evidence,
        globally_known_clause_sha256=frozenset(),
        public_model_verified=False,
    )
    assert science["threshold_prunes"] == threshold_prunes
    assert science["actual_certified_prunes"] == (
        1
        if semantic == runner.CERTIFIED_CROSSING_SEMANTIC
        and threshold_prunes > 0
        and emitted > 0
        else 0
    )
    assert classification == expected


def test_production_config_has_no_predicted_binary_identity() -> None:
    production = Path(__file__).parents[1] / runner.CONFIG_RELATIVE
    config = json.loads(production.read_bytes())
    source = (Path(__file__).parents[1] / runner.SOURCE_PATHS["runner"]).read_text()
    assert runner._pending(config) == ()
    assert runner.load_config(production) == config
    assert "expected_executable_sha256" not in config["native"]
    assert "expected_executable_bytes" not in config["native"]
    assert config["native"]["compiler_flags"] == list(runner.COMPILER_FLAGS)
    assert "-Wl,-no_uuid" not in config["native"]["compiler_flags"]
    assert "joint_score_sieve_v31" in source
    assert "prepare_o1c98_page17_causal_rollover" not in source
    for name, relative in runner.SOURCE_PATHS.items():
        assert config["source"]["expected_sha256"][name] == _sha(
            (Path(__file__).parents[1] / relative).read_bytes()
        )
    assert config["budgets"]["lineage_call_ordinals"] == [30]
    assert config["budgets"]["local_episode_ordinals"] == [0]
    assert config["budgets"]["maximum_native_solver_calls"] == 1
    assert config["budgets"]["retry_authorized"] is False
    assert config["budgets"]["replay_authorized"] is False
    assert "Page 16" in config["next_action"]
