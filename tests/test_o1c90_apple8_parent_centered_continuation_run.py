from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator, cast

import pytest

import o1_crypto_lab.o1c90_apple8_parent_centered_continuation_run as runner
from o1_crypto_lab import joint_score_sieve_v27 as v27
from o1_crypto_lab.causal_attic_v1 import canonical_json_bytes
from o1_crypto_lab.threshold_no_good_vault_v1 import ThresholdNoGoodClause


FAKE_NATIVE = b"fake-native-v24-executable\n"


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
        self.bad_smoke = False
        self.mutate_after_smoke: Path | None = None
        self.native_override: v27.JointScoreSieveV27Result | None = None

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
        receipt = root / runner.PRIORITY_RECEIPT_RELATIVE
        self.receipt = receipt.read_bytes()
        self.page13 = (self.published / runner.ACTIVE_PROJECTION_NAME).read_bytes()
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
        assert kwargs["cwd"] == self.root
        if argv == [str(self.compiler), "--version"]:
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
            output = Path(argv[argv.index("-o") + 1])
            output.write_bytes(FAKE_NATIVE)
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        self.smoke_calls += 1
        assert self.smoke_calls == 1
        assert argv[1:] == ["--help"]
        output = Path(argv[0])
        assert output.read_bytes() == FAKE_NATIVE
        assert not (output.parents[1] / "episodes/00/intent.json").exists()
        if self.mutate_after_smoke is not None:
            self.mutate_after_smoke.write_bytes(b"changed-after-smoke\n")
        return SimpleNamespace(
            returncode=0,
            stdout=b"bad usage\n" if self.bad_smoke else runner.NATIVE_V24_USAGE,
            stderr=b"",
        )

    def native_result(
        self,
        *,
        semantic: str = runner.PROOF_MINING_SEMANTIC,
        emitted_literal: int = 2,
        emitted: int = 0,
        active_new: int = 0,
        status: int = 0,
        probe_count: int = 255,
        outcome_counts: tuple[int, int, int, int] | None = None,
        child_bound_evaluations: int | None = None,
        probed_variables: tuple[int, ...] | None = None,
    ) -> v27.JointScoreSieveV27Result:
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
        base = {"pending_clause_count": 0, "threshold_prunes": 0}
        resources = {
            "peak_rss_bytes": 64 * 1024**2,
            "wall_microseconds": 50_000,
            "cpu_microseconds": 20_000,
        }
        stats = {
            "requested_conflicts": 128,
            "solve_conflicts": 17,
            "billed_conflicts": 17,
        }
        raw: dict[str, object] = {
            "schema": v27.JOINT_SCORE_SIEVE_RESULT_SCHEMA,
            "seed": 0,
            "active_vault_sha256": _sha(self.page13),
            "priority_state": state,
            "priority_actions": actions,
            "decision_ownership": {"schema": "fixture-ownership"},
            "base_sieve": base,
            "vault": vault,
        }
        stdout = canonical_json_bytes(raw).decode("ascii")
        return v27.JointScoreSieveV27Result(
            status=status,
            conflict_limit=128,
            threshold=runner.THRESHOLD,
            key_model=b"fixture-key" if status == 10 else None,
            stats=cast(Any, stats),
            resources=cast(Any, resources),
            base_result=cast(Any, None),
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
        assert intent["page13_burned"] is True
        assert intent["lineage26_burned"] is True
        assert intent["page12_replay_authorized"] is False
        assert intent["page11_replay_authorized"] is False
        assert intent["page10_replay_authorized"] is False
        assert intent["page9_retry_or_replay_authorized"] is False
        assert intent["native_executable"] == {
            "path": f"native/{runner.NATIVE_EXECUTABLE_NAME}",
            "serialized_bytes": len(FAKE_NATIVE),
            "sha256": _sha(FAKE_NATIVE),
        }
        assert kwargs["expected_source_sha256"] == self.source_sha["native_v24"]
        assert kwargs["expected_executable_sha256"] == _sha(FAKE_NATIVE)
        assert kwargs["expected_executable_bytes"] == len(FAKE_NATIVE)
        assert kwargs["seed"] == 0
        assert kwargs["conflict_limit"] == 128
        assert "public_fixture" not in kwargs
        assert Path(cast(Path, kwargs["vault_path"])).read_bytes() == self.page13
        assert kwargs["sealed_page13_path"] == kwargs["vault_path"]
        assert Path(cast(Path, kwargs["priority_seed_path"])).read_bytes() == self.bank
        self.intent_seen = True
        if self.fail_adapter:
            raise RuntimeError("fixture native process failed")
        return self.native_override or self.native_result()

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
                "source": runner.SOURCE_PATHS["native_v24"],
                "source_sha256": self.source_sha["native_v24"],
                "compiler": str(self.compiler),
                "compiler_flags": list(runner.COMPILER_FLAGS),
                "cadical_include": str(self.include),
                "cadical_library": str(self.library),
                "cadical_library_sha256": _sha(self.library.read_bytes()),
                "adapter_schema": v27.JOINT_SCORE_SIEVE_ADAPTER_SCHEMA,
                "result_schema": v27.JOINT_SCORE_SIEVE_RESULT_SCHEMA,
                "page13_sha256": runner.PAGE13_SHA256,
                "page13_bytes": runner.PAGE13_SERIALIZED_BYTES,
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
                "lineage_call_ordinals": [26],
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
            "next_action": "Burn Page 13 / lineage 26 once; never retry or replay.",
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
            public_verifier=lambda key: key == b"fixture-key",
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
    assert len(cast(dict[str, object], row["prepared_artifacts"])) == 10
    assert fixture.adapter_calls == fixture.build_calls == fixture.smoke_calls == 0


def test_preflight_rejects_published_mutation_without_build_or_call(
    fixture: Fixture,
) -> None:
    (fixture.published / runner.OCCURRENCES_NAME).write_bytes(b"mutated\n")
    with pytest.raises(runner.O1C90RunError, match="artifact seal differs"):
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
    assert build["executable"] == invocation["native_executable"] == identity
    assert intent["native_executable"] == identity
    assert build["smoke"] == invocation["native_smoke"]
    assert build["smoke"]["stdout"] == {
        "serialized_bytes": len(runner.NATIVE_V24_USAGE),
        "sha256": _sha(runner.NATIVE_V24_USAGE),
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


def test_bad_help_smoke_is_preintent_and_leaves_no_capsule(fixture: Fixture) -> None:
    fixture.bad_smoke = True
    with pytest.raises(runner.O1C90RunError, match="--help smoke seal differs"):
        fixture.execute()
    assert fixture.build_calls == fixture.smoke_calls == 1
    assert fixture.adapter_calls == 0
    assert not list((fixture.root / "runs").glob(f"*_{runner.CAPSULE_SUFFIX}"))


def test_source_mutation_after_smoke_never_burns_or_rebuilds(fixture: Fixture) -> None:
    fixture.mutate_after_smoke = fixture.inputs["potential"]
    with pytest.raises(runner.O1C90RunError, match="changed before native call"):
        fixture.execute()
    capsules = list((fixture.root / "runs").glob(f"*_{runner.CAPSULE_SUFFIX}"))
    assert len(capsules) == 1
    assert not (capsules[0] / "episodes/00/intent.json").exists()
    with pytest.raises(runner.O1C90RunError, match="pre-intent capsule"):
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
    assert episode["page13_burned"] is True
    assert episode["lineage26_burned"] is True
    assert episode["native_calls_consumed"] == 0
    assert fixture.adapter_calls == 0
    assert fixture.execute() == result
    assert fixture.build_calls == fixture.smoke_calls == 1


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


@pytest.mark.parametrize(
    "defect", ["bank-delta", "outcome-sum", "child-evaluations", "zero-241"]
)
def test_post_result_conservation_failure_is_terminal_and_preserves_stdout(
    fixture: Fixture, defect: str
) -> None:
    eligible = tuple(variable for variable in range(1, 257) if variable != 241)
    if defect == "bank-delta":
        fixture.native_override = fixture.native_result(
            probed_variables=eligible[:-1]
        )
    elif defect == "outcome-sum":
        fixture.native_override = fixture.native_result(
            outcome_counts=(254, 0, 0, 0)
        )
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
    assert science["active_page13_new_clauses"] == 1
    assert classification == runner.ACTIVATION_ONLY


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
    assert "joint_score_sieve_v27" in source
    assert "prepare_o1c89_page13_causal_rollover" not in source
    for name, relative in runner.SOURCE_PATHS.items():
        assert config["source"]["expected_sha256"][name] == _sha(
            (Path(__file__).parents[1] / relative).read_bytes()
        )
    assert config["budgets"]["lineage_call_ordinals"] == [26]
    assert config["budgets"]["local_episode_ordinals"] == [0]
    assert config["budgets"]["maximum_native_solver_calls"] == 1
    assert config["budgets"]["retry_authorized"] is False
    assert config["budgets"]["replay_authorized"] is False
