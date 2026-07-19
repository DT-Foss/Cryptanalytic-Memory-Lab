from __future__ import annotations

import copy
import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import o1_crypto_lab.joint_score_sieve_v5 as sieve_v5
from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.joint_score_sieve_v5 import (
    JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS,
    JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE,
    JOINT_SCORE_SIEVE_TEARDOWN_RULE,
    build_native_joint_score_sieve,
    derive_soft_conflict_ledger,
    run_joint_score_sieve,
    validate_native_lifecycle,
    write_joint_score_sieve_potential,
)
from o1_crypto_lab.o1_relational_search import O1RelationalSearchError

ROOT = Path(__file__).resolve().parents[1]
NATIVE_SOURCE = ROOT / "native/cadical_o1_joint_score_sieve_v4.cpp"
CADICAL_INCLUDE = Path("/opt/homebrew/opt/cadical/include")
CADICAL_LIBRARY = Path("/opt/homebrew/opt/cadical/lib/libcadical.a")
STRICT_FLAGS = ("-std=c++17", "-O3", "-DNDEBUG", "-Wall", "-Wextra", "-Werror")


def _native_available() -> bool:
    return bool(
        shutil.which("c++")
        and (CADICAL_INCLUDE / "cadical.hpp").is_file()
        and CADICAL_LIBRARY.is_file()
    )


def _field() -> CriticalityPotentialField:
    return CriticalityPotentialField(
        offset=0.0,
        source_sha256="42" * 32,
        factors=(CriticalityPotentialFactor((1,), (0.0, 0.0)),),
    )


@pytest.fixture(scope="module")
def native_build(tmp_path_factory: pytest.TempPathFactory):
    if not _native_available():
        pytest.skip("CaDiCaL development files absent")
    output = tmp_path_factory.mktemp("joint-score-v5-native") / "joint-score-v5"
    build = build_native_joint_score_sieve(source=NATIVE_SOURCE, output=output)
    assert {"-Wall", "-Wextra", "-Werror"}.issubset(build.command)
    return build


def _write_potential(tmp_path: Path) -> Path:
    potential = tmp_path / "case.potential"
    write_joint_score_sieve_potential(potential, _field())
    return potential


def _write_pigeonhole(tmp_path: Path, *, pigeons: int = 8, holes: int = 7) -> Path:
    def variable(pigeon: int, hole: int) -> int:
        return pigeon * holes + hole + 1

    clauses: list[tuple[int, ...]] = []
    for pigeon in range(pigeons):
        clauses.append(tuple(variable(pigeon, hole) for hole in range(holes)))
    for hole in range(holes):
        for first in range(pigeons):
            for second in range(first + 1, pigeons):
                clauses.append((-variable(first, hole), -variable(second, hole)))
    cnf = tmp_path / "pigeonhole.cnf"
    cnf.write_text(
        f"p cnf 256 {len(clauses)}\n"
        + "".join(
            " ".join(str(literal) for literal in clause) + " 0\n" for clause in clauses
        ),
        encoding="ascii",
    )
    return cnf


def _compile_harness(source: Path, output: Path) -> None:
    completed = subprocess.run(
        [
            "c++",
            *STRICT_FLAGS,
            f"-I{CADICAL_INCLUDE}",
            str(source),
            str(CADICAL_LIBRARY),
            "-o",
            str(output),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_4k_ledger_accepts_one_soft_stop_overshoot() -> None:
    ledger = derive_soft_conflict_ledger(
        {
            "conflicts": 4_100,
            "conflicts_before_solve": 3,
            "solve_conflicts": 4_097,
            "decisions": 20_000,
            "propagations": 2_000_000,
        },
        requested_conflicts=4_096,
    )
    assert ledger["requested_conflicts"] == 4_096
    assert ledger["unused_requested_conflicts"] == 0
    assert ledger["conflict_limit_overshoot"] == 1
    assert ledger["billed_conflicts"] == JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS


def test_lifecycle_contract_rejects_solving_as_success_json() -> None:
    valid: dict[str, object] = {
        "status": 0,
        "implementation_parent_schema": ("o1-256-cadical-joint-score-sieve-result-v2"),
        "post_solve_state": 256,
        "post_solve_state_name": "INCONCLUSIVE",
        "teardown_rule": JOINT_SCORE_SIEVE_TEARDOWN_RULE,
        "pending_backtrack_rule": JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE,
    }
    assert validate_native_lifecycle(valid)["post_solve_state"] == 256
    invalid = dict(valid)
    invalid.update(post_solve_state=16, post_solve_state_name="SOLVING")
    with pytest.raises(O1RelationalSearchError, match="lifecycle contract"):
        validate_native_lifecycle(invalid)


def test_terminal_sat_is_published_after_safe_teardown(
    tmp_path: Path, native_build
) -> None:
    cnf = tmp_path / "sat.cnf"
    cnf.write_text("p cnf 256 1\n1 0\n", encoding="ascii")
    result = run_joint_score_sieve(
        executable=native_build.executable,
        cnf_path=cnf,
        potential_path=_write_potential(tmp_path),
        threshold=-1.0,
        conflict_limit=4_096,
    )
    assert result.status == 10
    assert result.raw["post_solve_state"] == 32
    assert result.raw["post_solve_state_name"] == "SATISFIED"
    assert result.raw["teardown_rule"] == JOINT_SCORE_SIEVE_TEARDOWN_RULE
    assert result.key_model is not None and len(result.key_model) == 32
    assert result.stats["unused_requested_conflicts"] == 4_096


def test_conflict_limit_unknown_is_deterministic_and_destructor_safe(
    tmp_path: Path, native_build
) -> None:
    result = run_joint_score_sieve(
        executable=native_build.executable,
        cnf_path=_write_pigeonhole(tmp_path),
        potential_path=_write_potential(tmp_path),
        threshold=-1.0,
        conflict_limit=1,
    )
    assert result.status == 0
    assert result.raw["post_solve_state"] == 256
    assert result.raw["post_solve_state_name"] == "INCONCLUSIVE"
    assert result.stats["solve_conflicts"] == 1
    assert result.stats["billed_conflicts"] == 1


def test_full_parser_rejects_forged_teardown_metadata(
    tmp_path: Path, native_build, monkeypatch: pytest.MonkeyPatch
) -> None:
    cnf = tmp_path / "sat.cnf"
    cnf.write_text("p cnf 256 1\n1 0\n", encoding="ascii")
    potential = _write_potential(tmp_path)
    valid = run_joint_score_sieve(
        executable=native_build.executable,
        cnf_path=cnf,
        potential_path=potential,
        threshold=-1.0,
        conflict_limit=1,
    )
    forged = dict(copy.deepcopy(valid.raw))
    forged["teardown_rule"] = "disconnect-after-solve"
    monkeypatch.setattr(
        sieve_v5._v1.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout=json.dumps(forged), stderr=""
        ),
    )
    with pytest.raises(O1RelationalSearchError, match="lifecycle contract"):
        run_joint_score_sieve(
            executable=native_build.executable,
            cnf_path=cnf,
            potential_path=potential,
            threshold=-1.0,
            conflict_limit=1,
        )


@pytest.mark.skipif(not _native_available(), reason="CaDiCaL development files absent")
def test_pending_no_good_survives_backtrack_and_emits_once(tmp_path: Path) -> None:
    harness = tmp_path / "pending_backtrack.cpp"
    executable = tmp_path / "pending_backtrack"
    harness.write_text(
        f"""#define O1_CRYPTO_LAB_JOINT_SCORE_SIEVE_V4_NO_MAIN
#include "{NATIVE_SOURCE.as_posix()}"
#undef O1_CRYPTO_LAB_JOINT_SCORE_SIEVE_V4_NO_MAIN

int main() {{
  PotentialField field;
  field.offset = 0.0;
  field.source_sha256 = std::string(64U, '4');
  PotentialFactor factor;
  factor.variables = {{1}};
  factor.energies = {{0.0, 10.0}};
  field.factors.push_back(std::move(factor));
  JointScoreSieveV4 sieve(std::move(field), 5.0);
  sieve.notify_new_decision_level();
  sieve.notify_assignment({{-1}});
  const std::string pending = sieve.pending_state();
  if (pending.size() != 14U || pending[8] != 1 || pending[9] != 1)
    return 10;
  int literal = 0;
  std::memcpy(&literal, pending.data() + 10, sizeof(literal));
  if (literal != 1)
    return 11;
  sieve.notify_backtrack(0U);
  if (sieve.assignment_state() != std::string(1U, '\\0') ||
      sieve.pending_state() != pending)
    return 12;
  const std::string cache = sieve.factor_cache_state();
  double cached_maximum = 0.0;
  std::memcpy(&cached_maximum, cache.data(), sizeof(cached_maximum));
  if (cache.size() != sizeof(cached_maximum) || cached_maximum != 10.0)
    return 13;
  bool forgettable = true;
  if (!sieve.cb_has_external_clause(forgettable) || forgettable)
    return 14;
  if (sieve.cb_add_external_clause_lit() != 1 ||
      sieve.cb_add_external_clause_lit() != 0)
    return 15;
  if (sieve.cb_has_external_clause(forgettable))
    return 16;
  std::ostringstream telemetry;
  sieve.write_json(telemetry);
  if (telemetry.str().find("\\\"external_clauses_queued\\\":1") ==
          std::string::npos ||
      telemetry.str().find("\\\"external_clauses_emitted\\\":1") ==
          std::string::npos ||
      telemetry.str().find("\\\"pending_clause_count\\\":0") ==
          std::string::npos)
    return 17;
  return 0;
}}
""",
        encoding="utf-8",
    )
    _compile_harness(harness, executable)
    completed = subprocess.run(
        [str(executable)], capture_output=True, text=True, check=False
    )
    assert completed.returncode == 0, completed.stderr


@pytest.mark.skipif(not _native_available(), reason="CaDiCaL development files absent")
def test_solving_callback_exception_keeps_original_error_visible(
    tmp_path: Path,
) -> None:
    source_text = NATIVE_SOURCE.read_text(encoding="utf-8")
    assert "disconnect_external_propagator" not in source_text
    harness = tmp_path / "solving_exception.cpp"
    executable = tmp_path / "solving_exception"
    harness.write_text(
        """#include <cadical.hpp>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

class ThrowingPropagator final : public CaDiCaL::ExternalPropagator {
public:
  void notify_assignment(const std::vector<int> &) override {
    throw std::runtime_error("callback-sentinel");
  }
  void notify_new_decision_level() override {}
  void notify_backtrack(size_t) override {}
  bool cb_check_found_model(const std::vector<int> &) override { return true; }
  bool cb_has_external_clause(bool &) override { return false; }
  int cb_add_external_clause_lit() override { return 0; }
};

int main() {
  ThrowingPropagator propagator;
  try {
    CaDiCaL::Solver solver;
    solver.connect_external_propagator(&propagator);
    solver.add_observed_var(1);
    solver.add(1);
    solver.add(0);
    (void) solver.solve();
    return 10;
  } catch (const std::runtime_error &error) {
    if (std::string(error.what()) != "callback-sentinel")
      return 11;
    std::cout << error.what() << '\\n';
    return 0;
  }
}
""",
        encoding="utf-8",
    )
    _compile_harness(harness, executable)
    completed = subprocess.run(
        [str(executable)], capture_output=True, text=True, check=False
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "callback-sentinel"
    assert "API contract violation" not in completed.stderr
