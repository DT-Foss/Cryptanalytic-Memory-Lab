from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import textwrap
from pathlib import Path
from typing import Any

import pytest

import o1_crypto_lab.o1c82_parent_centered_seed as fresh_seed


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "native"
V20 = NATIVE / "cadical_o1_joint_score_sieve_v20.cpp"
V21 = NATIVE / "cadical_o1_joint_score_sieve_v21.cpp"
STATE_HEADER = NATIVE / "o1c82_parent_centered_priority.hpp"
LIVE_BANK = (
    ROOT
    / "research"
    / "o1c83_causal_rollover_seed_20260720"
    / "final-parent-centered-priority-bank.bin"
)
PAGE9 = (
    ROOT
    / "research"
    / "o1c83_causal_rollover_seed_20260720"
    / "page-09-active.bin"
)
LIVE_BANK_SHA256 = "05b8acf3ecd5423016e5d7ef7d649f790e758e3477a943fe7306280064a4c630"
PAGE9_SHA256 = "8c3b8cc33badd4aa23920caabc5ea3fc5006675d93805578b74b2b20788c8204"
PAGE10_SHA256 = "bf1fd3e3938bc4125e672ee94ee599e5f21881b4fc87e2bc81e8fc57fc4d3556"
FRESH_BANK_SHA256 = "86787bda89f29587525ffbc071d2229608a5bff5c3243361086794379f77e21c"
PAGE8_SHA256 = "89e085e7323ea9aaaa31ad1430c3f20ac03f9c21a49c6404374b75ddf59330f4"
FROZEN_V20_SHA256 = "910784593a207adc763dd57518a2ea850a2db3d00a167500ae5216f1aebf76ca"
CADICAL_INCLUDE = Path("/opt/homebrew/opt/cadical/include")
CADICAL_LIBRARY = Path("/opt/homebrew/opt/cadical/lib/libcadical.a")


HARNESS = r"""
#define O1_CRYPTO_LAB_O1C85_NO_MAIN
#include "cadical_o1_joint_score_sieve_v21.cpp"

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

void append_u16_le_local(std::string &payload, uint16_t value) {
  payload.push_back(static_cast<char>(value));
  payload.push_back(static_cast<char>(value >> 8U));
}

std::string raw_digest(unsigned char byte) {
  return std::string(32U, static_cast<char>(byte));
}

std::string synthetic_grouping(const std::string &potential_digest) {
  std::string result(kGroupingMagic);
  result += potential_digest;
  append_u16_le_local(result, 6U);
  append_u32_le(result, 2U);
  append_u32_le(result, 2U);
  for (uint32_t index = 0; index < 2U; ++index) {
    append_u32_le(result, 1U);
    append_u32_le(result, index);
    append_u16_le_local(result, 1U);
    append_u32_le(result, index + 1U);
  }
  return result;
}

std::string synthetic_vault(const std::string &cnf_digest,
                            const std::string &potential_digest,
                            const std::string &grouping, double threshold) {
  std::string observed;
  append_u32_le(observed, 1U);
  append_u32_le(observed, 2U);
  std::string result(kVaultMagic);
  result += cnf_digest;
  result += potential_digest;
  const auto append_hex = [&result](const std::string &hex) {
    for (size_t index = 0; index < hex.size(); index += 2U)
      result.push_back(static_cast<char>(
          std::stoul(hex.substr(index, 2U), nullptr, 16)));
  };
  append_hex(sha256(grouping));
  append_hex(sha256(observed));
  append_hex(sha256(kGroupedBoundRule));
  append_u64_le(result, f64_bits(threshold));
  append_u32_le(result, 0U);
  return result;
}

PotentialField synthetic_field() {
  PotentialField field;
  field.offset = 0.0;
  field.source_sha256 = std::string(64U, 'a');
  PotentialFactor first;
  first.variables = {1};
  first.energies = {0.0, 2.0};
  PotentialFactor second;
  second.variables = {2};
  second.energies = {0.0, 0.0};
  field.factors = {first, second};
  return field;
}

std::string read_all(const char *path) {
  std::ifstream input(path, std::ios::binary);
  if (!input)
    throw std::runtime_error("fixture bank open failed");
  return std::string(std::istreambuf_iterator<char>(input),
                     std::istreambuf_iterator<char>());
}

ParentCenteredGroupedJointScoreSieve make_operator(const std::string &bank,
                                                   double threshold) {
  const std::string potential_digest = raw_digest(0x11U);
  const std::string cnf_digest = raw_digest(0x22U);
  const std::string grouping = synthetic_grouping(potential_digest);
  const std::string vault = synthetic_vault(
      cnf_digest, potential_digest, grouping, threshold);
  return ParentCenteredGroupedJointScoreSieve(
      synthetic_field(), grouping, vault, bytes_hex(cnf_digest),
      bytes_hex(potential_digest), threshold, bank, sha256(bank), false);
}

void emit_json(ParentCenteredGroupedJointScoreSieve &operator_) {
  operator_.finalize_after_solve();
  std::ostringstream out;
  out << std::setprecision(std::numeric_limits<double>::max_digits10)
      << "{\"priority_seed\":{";
  operator_.write_priority_seed_json(out);
  out << "},\"priority_state\":{";
  operator_.write_priority_state_json(out);
  out << "},\"priority_actions\":{";
  operator_.write_priority_actions_json(out);
  out << "}}\n";
  std::cout << out.str();
}

int import_mode(const std::string &bank) {
  ParentCenteredGroupedJointScoreSieve operator_ = make_operator(bank, -1.0);
  require(operator_.current_priority_bank_sha256() ==
              kLiveContinuationBankSha256,
          "live continuation bank import differs");
  emit_json(operator_);
  return 0;
}

int proof_mode(const std::string &bank) {
  ParentCenteredGroupedJointScoreSieve operator_ = make_operator(bank, -1.0);
  const int first = operator_.cb_decide();
  require(first != 0 && operator_.action_count() == 1U,
          "first continuation action differs");
  operator_.notify_new_decision_level();
  operator_.notify_assignment({first});
  operator_.notify_backtrack(0U);
  const int second = operator_.cb_decide();
  require(second != 0 && std::abs(second) != std::abs(first) &&
              operator_.action_count() == 2U,
          "continuation one-shot release differs");
  operator_.notify_new_decision_level();
  operator_.notify_assignment({second});
  operator_.notify_backtrack(0U);
  require(operator_.cb_decide() == 0 && operator_.action_count() == 2U &&
              operator_.probe_count() == 6U,
          "continuation population exhaustion differs");
  emit_json(operator_);
  return 0;
}

int crossing_mode(const std::string &bank) {
  ParentCenteredGroupedJointScoreSieve operator_ = make_operator(bank, 1.0);
  const int literal = operator_.cb_decide();
  require(literal == -1 && operator_.action_count() == 1U,
          "continuation crossing precedence differs");
  const PriorityActionEvent event = operator_.action(0U);
  require(event.semantic ==
              PriorityActionSemantic::CERTIFIED_STRICT_BOUND_CROSSING &&
              event.lower_upper_bound == 0.0,
          "continuation crossing certification differs");
  operator_.notify_new_decision_level();
  operator_.notify_assignment({literal});
  bool forgettable = true;
  require(operator_.cb_has_external_clause(forgettable) && !forgettable,
          "continuation crossing clause differs");
  while (operator_.cb_add_external_clause_lit() != 0) {
  }
  operator_.notify_backtrack(0U);
  emit_json(operator_);
  return 0;
}

} // namespace

int main(int argc, char **argv) {
  try {
    require(argc == 3, "fixture arguments differ");
    const std::string bank = read_all(argv[2]);
    if (std::string_view(argv[1]) == "import")
      return import_mode(bank);
    if (std::string_view(argv[1]) == "proof")
      return proof_mode(bank);
    if (std::string_view(argv[1]) == "crossing")
      return crossing_mode(bank);
    throw std::runtime_error("fixture mode differs");
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
"""


def _native_available() -> bool:
    return bool(
        shutil.which("c++")
        and (CADICAL_INCLUDE / "cadical.hpp").is_file()
        and CADICAL_LIBRARY.is_file()
    )


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture(scope="module")
def frozen_inputs(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    assert LIVE_BANK.stat().st_size == 24_576
    assert _sha(LIVE_BANK) == LIVE_BANK_SHA256
    assert PAGE9.stat().st_size == 2_885_959
    assert _sha(PAGE9) == PAGE9_SHA256
    old = tmp_path_factory.mktemp("o1c85-old-bank") / "fresh-priority.seed"
    payload = fresh_seed.compile_parent_centered_seed(ROOT, verify_fresh=False)
    assert hashlib.sha256(payload).hexdigest() == FRESH_BANK_SHA256
    old.write_bytes(payload)
    return old, PAGE9


@pytest.fixture(scope="module")
def native_builds(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    if not _native_available():
        pytest.skip("CaDiCaL 3.0.0 development files absent")
    build = tmp_path_factory.mktemp("o1c85-native-continuation")
    harness_source = build / "fixture.cpp"
    harness_source.write_text(textwrap.dedent(HARNESS), encoding="utf-8")
    harness = build / "fixture"
    main = build / "cadical_o1_joint_score_sieve_v21"
    common = [
        "c++",
        "-std=c++17",
        "-O2",
        "-DNDEBUG",
        "-Wall",
        "-Wextra",
        "-Werror",
        f"-I{NATIVE}",
        f"-I{CADICAL_INCLUDE}",
    ]
    builds = (
        (
            [*common, "-DO1_CRYPTO_LAB_O1C85_PUBLIC_FIXTURE"],
            harness_source,
            harness,
        ),
        (common, V21, main),
    )
    for flags, source, executable in builds:
        completed = subprocess.run(
            [*flags, str(source), str(CADICAL_LIBRARY), "-o", str(executable)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        assert completed.returncode == 0, completed.stderr
    return harness, main


def _run(executable: Path, *arguments: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(executable), *(str(argument) for argument in arguments)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def _mapping(value: object) -> dict[str, Any]:
    assert isinstance(value, dict)
    return value


def _sealed_command(
    main: Path, directory: Path, vault: Path, bank: Path
) -> subprocess.CompletedProcess[str]:
    empty = directory / "empty"
    empty.write_bytes(b"")
    return _run(
        main,
        "--cnf",
        empty,
        "--potential",
        empty,
        "--grouping",
        empty,
        "--vault-in",
        vault,
        "--priority-seed",
        bank,
        "--threshold",
        14.606178797892962,
        "--conflict-limit",
        1,
        "--seed",
        0,
    )


def test_v21_normal_production_binary_compiles_and_help_surface(
    native_builds: tuple[Path, Path],
) -> None:
    _, main = native_builds
    completed = _run(main, "--help")
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == (
        "usage: cadical_o1_joint_score_sieve_v21 --cnf PATH --potential PATH "
        "--grouping PATH --vault-in PATH --priority-seed PATH --threshold "
        "FLOAT --conflict-limit N [--seed N]\n"
    )


def test_live_evolved_bank_import_and_machine_readable_provenance(
    native_builds: tuple[Path, Path],
) -> None:
    harness, _ = native_builds
    completed = _run(harness, "import", LIVE_BANK)
    assert completed.returncode == 0, completed.stderr
    payload: dict[str, Any] = json.loads(completed.stdout)
    seed_report = _mapping(payload["priority_seed"])
    assert seed_report["payload_sha256"] == LIVE_BANK_SHA256
    assert seed_report["expected_production_sha256"] == LIVE_BANK_SHA256
    assert seed_report["seed_source"] == "sealed-live-continuation-bank"
    assert seed_report["live_continuation_bank_identity"] is True
    assert seed_report["fresh_seed_parser_used"] is False
    assert seed_report["import_roundtrip_exact"] is True
    assert seed_report["initial_eligible_coordinate_count"] == 255
    state = _mapping(payload["priority_state"])
    assert state["schema"] == (
        "o1-256-o1c85-live-parent-centered-continuation-priority-state-v1"
    )
    assert state["current_bank_sha256"] == LIVE_BANK_SHA256
    assert state["bank_hex"] == LIVE_BANK.read_bytes().hex()


def test_live_bank_retains_failure_first_one_shot_and_seed_zero_semantics(
    native_builds: tuple[Path, Path],
) -> None:
    harness, _ = native_builds
    completed = _run(harness, "proof", LIVE_BANK)
    assert completed.returncode == 0, completed.stderr
    payload: dict[str, Any] = json.loads(completed.stdout)
    actions = _mapping(payload["priority_actions"])
    assert actions["schema"] == "o1-256-o1c85-failure-first-proof-mining-actions-v1"
    assert actions["action_count"] == 2
    assert actions["failure_first_count"] == 2
    assert actions["certified_crossing_count"] == 0
    assert actions["releases"] == 2
    assert actions["one_shot_rule"] == (
        "coordinate-consumed-on-first-return;release-does-not-rearm"
    )
    assert [row["sequence"] for row in actions["actions"]] == [1, 2]
    assert len({row["variable"] for row in actions["actions"]}) == 2
    for row in actions["actions"]:
        assert row["semantic"] == "FAILURE_FIRST_PROOF_MINING"
        assert row["literal"] == (
            -row["variable"]
            if row["upper_zero"] <= row["upper_one"]
            else row["variable"]
        )


def test_certified_strict_crossing_still_precedes_live_bank_priority(
    native_builds: tuple[Path, Path],
) -> None:
    harness, _ = native_builds
    completed = _run(harness, "crossing", LIVE_BANK)
    assert completed.returncode == 0, completed.stderr
    payload: dict[str, Any] = json.loads(completed.stdout)
    actions = _mapping(payload["priority_actions"])
    assert actions["action_count"] == 1
    assert actions["failure_first_count"] == 0
    assert actions["certified_crossing_count"] == 1
    row = actions["actions"][0]
    assert row["semantic"] == "CERTIFIED_STRICT_BOUND_CROSSING_PRUNE"
    assert row["machine_action"] == "CERTIFIED_STRICT_BOUND_CROSSING"
    assert row["certified_threshold_action"] is True
    assert row["current_lower_upper_bound"] == 0.0


def test_native_production_gate_rejects_old_fresh_bank_before_solver(
    native_builds: tuple[Path, Path],
    frozen_inputs: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    _, main = native_builds
    old_bank, page9 = frozen_inputs
    completed = _sealed_command(main, tmp_path, page9, old_bank)
    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr == (
        "cadical_o1_joint_score_sieve_v21: "
        "sealed O1C85 priority seed differs\n"
    )


def test_native_production_gate_rejects_exact_page9_before_solver(
    native_builds: tuple[Path, Path], tmp_path: Path
) -> None:
    _, main = native_builds
    completed = _sealed_command(main, tmp_path, PAGE9, LIVE_BANK)
    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr == (
        "cadical_o1_joint_score_sieve_v21: "
        "sealed O1C85 Page-10 active vault differs\n"
    )


def test_source_contract_and_historical_native_freeze() -> None:
    source = V21.read_text(encoding="utf-8")
    assert hashlib.sha256(V20.read_bytes()).hexdigest() == FROZEN_V20_SHA256
    assert '#include "cadical_o1_joint_score_sieve_v18.cpp"' in source
    assert '#include "o1c82_parent_centered_priority.hpp"' in source
    assert "O1_CRYPTO_LAB_O1C85_PUBLIC_FIXTURE" in source
    assert "O1_CRYPTO_LAB_O1C85_NO_MAIN" in source
    assert "o1-256-cadical-joint-score-sieve-result-v21" in source
    assert LIVE_BANK_SHA256 in source
    assert PAGE10_SHA256 in source
    assert "kProductionPage10ActiveVaultBytes = 2874387U" in source
    assert "sealed-live-continuation-bank" in source
    assert "fresh_seed_parser_used" in source
    assert FRESH_BANK_SHA256 not in source
    assert PAGE9_SHA256 not in source
    assert PAGE8_SHA256 not in source
    assert "LC_UUID" not in source
    crossing = source.index("if (crossing.available)")
    priority = source.index("if (!last_priority_selection_.available)")
    assert crossing < priority
    seed_gate = source.index("seed_sha256 != kLiveContinuationBankSha256")
    solver = source.index("CaDiCaL::Solver solver;")
    page_gate = source.index("vault_sha256 != kProductionPage10ActiveVaultSha256")
    assert seed_gate < page_gate < solver
    assert "arguments.seed != 0" in source
    assert "observed-key-variables-ascending" in source
    assert "FAILURE_FIRST_PROOF_MINING" in source
    assert "CERTIFIED_STRICT_BOUND_CROSSING_PRUNE" in source
    assert "growing_parent_history_bytes\\\":0" in source
    assert "kLiveStateBytes == 28672U" in STATE_HEADER.read_text(encoding="utf-8")
