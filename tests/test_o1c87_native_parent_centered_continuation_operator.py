from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import textwrap
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "native"
V22 = NATIVE / "cadical_o1_joint_score_sieve_v22.cpp"
V23 = NATIVE / "cadical_o1_joint_score_sieve_v23.cpp"
STATE_HEADER = NATIVE / "o1c82_parent_centered_priority.hpp"
LIVE_BANK = (
    ROOT
    / "runs"
    / "20260720_181212_319263_O1C-0086_apple8-parent-centered-continuation-v1"
    / "episodes"
    / "00"
    / "final-parent-centered-priority-bank.bin"
)
PRIOR_BANK = (
    ROOT
    / "runs"
    / "20260720_170426_298664_O1C-0085_apple8-parent-centered-continuation-v1"
    / "episodes"
    / "00"
    / "final-parent-centered-priority-bank.bin"
)
PAGE11 = (
    ROOT
    / "runs"
    / "20260720_181212_319263_O1C-0086_apple8-parent-centered-continuation-v1"
    / "initial"
    / "page-11-active.bin"
)
PAGE10 = (
    ROOT
    / "runs"
    / "20260720_170426_298664_O1C-0085_apple8-parent-centered-continuation-v1"
    / "initial"
    / "page-10-active.bin"
)
PAGE9 = ROOT / "research" / "o1c83_causal_rollover_seed_20260720" / "page-09-active.bin"
LIVE_BANK_SHA256 = "658fd2856b83d1a0ff8d28e92a604c99b3843a49a589811bf9b61845959ec31f"
PRIOR_BANK_SHA256 = "2c0c4ccba476bc642778b68234cc497c1776d144092ea9f1aead367559f59b07"
PAGE9_SHA256 = "8c3b8cc33badd4aa23920caabc5ea3fc5006675d93805578b74b2b20788c8204"
PAGE10_SHA256 = "bf1fd3e3938bc4125e672ee94ee599e5f21881b4fc87e2bc81e8fc57fc4d3556"
PAGE11_SHA256 = "9853f06bc882bfbb6312207bc8c20e0e9ca1500e49aad14594f6d7c66b62a04d"
PAGE12_SHA256 = "44205f81322d526c1cf7b7c96f28a3baf02b6b9bcb08a04f0bab2e66651fa660"
PAGE8_SHA256 = "89e085e7323ea9aaaa31ad1430c3f20ac03f9c21a49c6404374b75ddf59330f4"
FROZEN_V22_SHA256 = "d4fb10ad0a43e65acf7629ebcb6c87a81277494a8eec569a1723f383608fb38f"
CADICAL_INCLUDE = Path("/opt/homebrew/opt/cadical/include")
CADICAL_LIBRARY = Path("/opt/homebrew/opt/cadical/lib/libcadical.a")


HARNESS = r"""
#define O1_CRYPTO_LAB_O1C87_NO_MAIN
#include "cadical_o1_joint_score_sieve_v23.cpp"

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
def frozen_inputs() -> tuple[Path, Path, Path, Path]:
    assert LIVE_BANK.stat().st_size == 24_576
    assert _sha(LIVE_BANK) == LIVE_BANK_SHA256
    assert PRIOR_BANK.stat().st_size == 24_576
    assert _sha(PRIOR_BANK) == PRIOR_BANK_SHA256
    assert PAGE11.stat().st_size == 2_876_731
    assert _sha(PAGE11) == PAGE11_SHA256
    assert PAGE10.stat().st_size == 2_874_387
    assert _sha(PAGE10) == PAGE10_SHA256
    assert PAGE9.stat().st_size == 2_885_959
    assert _sha(PAGE9) == PAGE9_SHA256
    return PRIOR_BANK, PAGE11, PAGE10, PAGE9


@pytest.fixture(scope="module")
def native_builds(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    if not _native_available():
        pytest.skip("CaDiCaL 3.0.0 development files absent")
    build = tmp_path_factory.mktemp("o1c87-native-continuation")
    harness_source = build / "fixture.cpp"
    harness_source.write_text(textwrap.dedent(HARNESS), encoding="utf-8")
    harness = build / "fixture"
    main = build / "cadical_o1_joint_score_sieve_v23"
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
            [*common, "-DO1_CRYPTO_LAB_O1C87_PUBLIC_FIXTURE"],
            harness_source,
            harness,
        ),
        (common, V23, main),
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


def test_v23_normal_production_binary_compiles_and_help_surface(
    native_builds: tuple[Path, Path],
) -> None:
    _, main = native_builds
    completed = _run(main, "--help")
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == (
        "usage: cadical_o1_joint_score_sieve_v23 --cnf PATH --potential PATH "
        "--grouping PATH --vault-in PATH --priority-seed PATH --threshold "
        "FLOAT --conflict-limit N [--seed N]\n"
    )
    otool = shutil.which("otool")
    assert otool is not None
    load_commands = _run(Path(otool), "-l", main)
    assert load_commands.returncode == 0, load_commands.stderr
    assert "LC_UUID" in load_commands.stdout


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
        "o1-256-o1c87-live-parent-centered-continuation-priority-state-v1"
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
    assert actions["schema"] == "o1-256-o1c87-failure-first-proof-mining-actions-v1"
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


def test_native_production_gate_rejects_prior_live_bank_before_solver(
    native_builds: tuple[Path, Path],
    frozen_inputs: tuple[Path, Path, Path, Path],
    tmp_path: Path,
) -> None:
    _, main = native_builds
    old_bank, _, _, page9 = frozen_inputs
    completed = _sealed_command(main, tmp_path, page9, old_bank)
    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr == (
        "cadical_o1_joint_score_sieve_v23: sealed O1C87 priority seed differs\n"
    )


def test_native_requires_seed_zero_before_reading_solver_inputs(
    native_builds: tuple[Path, Path], tmp_path: Path
) -> None:
    _, main = native_builds
    empty = tmp_path / "absent-input"
    completed = _run(
        main,
        "--cnf",
        empty,
        "--potential",
        empty,
        "--grouping",
        empty,
        "--vault-in",
        empty,
        "--priority-seed",
        empty,
        "--threshold",
        14.606178797892962,
        "--conflict-limit",
        1,
        "--seed",
        1,
    )
    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr == (
        "cadical_o1_joint_score_sieve_v23: O1C87 priority operator requires seed zero\n"
    )


def test_native_production_gate_rejects_exact_page9_before_solver(
    native_builds: tuple[Path, Path], tmp_path: Path
) -> None:
    _, main = native_builds
    completed = _sealed_command(main, tmp_path, PAGE9, LIVE_BANK)
    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr == (
        "cadical_o1_joint_score_sieve_v23: burned O1C84 Page-9 active vault rejected\n"
    )


def test_native_production_gate_rejects_exact_page10_before_solver(
    native_builds: tuple[Path, Path], tmp_path: Path
) -> None:
    _, main = native_builds
    completed = _sealed_command(main, tmp_path, PAGE10, LIVE_BANK)
    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr == (
        "cadical_o1_joint_score_sieve_v23: burned O1C85 Page-10 active vault rejected\n"
    )


def test_native_production_gate_rejects_exact_page11_before_solver(
    native_builds: tuple[Path, Path], tmp_path: Path
) -> None:
    _, main = native_builds
    completed = _sealed_command(main, tmp_path, PAGE11, LIVE_BANK)
    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr == (
        "cadical_o1_joint_score_sieve_v23: burned O1C86 Page-11 active vault rejected\n"
    )


def test_native_production_gate_rejects_nonmatching_page12_payload(
    native_builds: tuple[Path, Path], tmp_path: Path
) -> None:
    _, main = native_builds
    forged_page12 = tmp_path / "forged-page-12-active.bin"
    forged_page12.write_bytes(bytes(2_725_423))
    completed = _sealed_command(main, tmp_path, forged_page12, LIVE_BANK)
    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr == (
        "cadical_o1_joint_score_sieve_v23: sealed O1C87 Page-12 active vault differs\n"
    )


def test_source_contract_and_historical_native_freeze() -> None:
    source = V23.read_text(encoding="utf-8")
    assert hashlib.sha256(V22.read_bytes()).hexdigest() == FROZEN_V22_SHA256
    assert '#include "cadical_o1_joint_score_sieve_v18.cpp"' in source
    assert '#include "o1c82_parent_centered_priority.hpp"' in source
    assert "O1_CRYPTO_LAB_O1C87_PUBLIC_FIXTURE" in source
    assert "O1_CRYPTO_LAB_O1C87_NO_MAIN" in source
    assert "o1-256-cadical-joint-score-sieve-result-v23" in source
    assert "o1-256-o1c87-live-parent-centered-continuation-priority-state-v1" in source
    assert "o1-256-o1c87-failure-first-proof-mining-actions-v1" in source
    assert LIVE_BANK_SHA256 in source
    assert PAGE12_SHA256 in source
    assert PAGE11_SHA256 in source
    assert PAGE10_SHA256 in source
    assert PAGE9_SHA256 in source
    assert "kProductionPage12ActiveVaultBytes = 2725423U" in source
    assert "kBurnedPage11ActiveVaultBytes = 2876731U" in source
    assert "kBurnedPage10ActiveVaultBytes = 2874387U" in source
    assert "kBurnedPage9ActiveVaultBytes = 2885959U" in source
    assert "kExpectedProductionCandidateCount = 255U" in source
    assert "sealed-live-continuation-bank" in source
    assert "fresh_seed_parser_used" in source
    assert PRIOR_BANK_SHA256 not in source
    assert PAGE8_SHA256 not in source
    assert "LC_UUID" not in source
    crossing = source.index("if (crossing.available)")
    priority = source.index("if (!last_priority_selection_.available)")
    assert crossing < priority
    seed_gate = source.index("seed_sha256 != kLiveContinuationBankSha256")
    page11_gate = source.index("vault_sha256 == kBurnedPage11ActiveVaultSha256")
    page10_gate = source.index("vault_sha256 == kBurnedPage10ActiveVaultSha256")
    page9_gate = source.index("vault_sha256 == kBurnedPage9ActiveVaultSha256")
    page12_gate = source.index("vault_sha256 != kProductionPage12ActiveVaultSha256")
    solver = source.index("CaDiCaL::Solver solver;")
    assert seed_gate < page11_gate < page10_gate < page9_gate < page12_gate < solver
    assert "arguments.seed != 0" in source
    assert "observed-key-variables-ascending" in source
    assert "FAILURE_FIRST_PROOF_MINING" in source
    assert "CERTIFIED_STRICT_BOUND_CROSSING_PRUNE" in source
    assert 'growing_parent_history_bytes\\":0' in source
    assert "-Wl,-no_uuid" not in source
    assert "kLiveStateBytes == 28672U" in STATE_HEADER.read_text(encoding="utf-8")


def test_v23_operator_body_is_byte_equivalent_to_frozen_v22() -> None:
    source = V23.read_text(encoding="utf-8")
    burned_page11_constants = """constexpr const char *kBurnedPage11ActiveVaultSha256 =
    "9853f06bc882bfbb6312207bc8c20e0e9ca1500e49aad14594f6d7c66b62a04d";
constexpr size_t kBurnedPage11ActiveVaultBytes = 2876731U;
"""
    burned_page11_gate = """    if (production_seal &&
        vault_payload.size() == kBurnedPage11ActiveVaultBytes &&
        vault_sha256 == kBurnedPage11ActiveVaultSha256)
      throw std::runtime_error("burned O1C86 Page-11 active vault rejected");
"""
    assert burned_page11_constants in source
    assert burned_page11_gate in source
    normalized = source.replace(burned_page11_constants, "").replace(
        burned_page11_gate, ""
    )
    replacements = (
        ("O1C-0087", "O1C-0086"),
        ("O1C87", "O1C86"),
        ("o1c87", "o1c86"),
        ("V23", "V22"),
        ("v23", "v22"),
        (LIVE_BANK_SHA256, PRIOR_BANK_SHA256),
        ("kProductionPage12", "kProductionPage11"),
        (PAGE12_SHA256, PAGE11_SHA256),
        ("2725423U", "2876731U"),
        ("Page-12", "Page-11"),
    )
    for current, prior in replacements:
        normalized = normalized.replace(current, prior)
    assert normalized == V22.read_text(encoding="utf-8")
