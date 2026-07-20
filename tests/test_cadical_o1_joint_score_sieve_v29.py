from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import textwrap
from pathlib import Path
from typing import Any

import pytest

import o1_crypto_lab.joint_score_sieve_v32 as adapter_v32

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "native"
V26 = NATIVE / "cadical_o1_joint_score_sieve_v26.cpp"
V29 = NATIVE / "cadical_o1_joint_score_sieve_v29.cpp"
STATE_HEADER = NATIVE / "o1c82_parent_centered_priority.hpp"
LIVE_BANK = (
    ROOT
    / "research"
    / "o1c98_page17_causal_rollover_seed_20260720"
    / "final-parent-centered-priority-bank.bin"
)
PRIOR_BANK = (
    ROOT
    / "research"
    / "o1c91_page14_causal_rollover_seed_20260720"
    / "final-parent-centered-priority-bank.bin"
)
STATE_RECEIPT = (
    ROOT
    / "research"
    / "o1c98_page17_causal_rollover_seed_20260720"
    / "o1c97-priority-state-receipt.json"
)
PAGE15 = (
    ROOT
    / "research"
    / "o1c93_page15_causal_rollover_seed_20260720"
    / "page-15-active.bin"
)
PAGE16 = (
    ROOT
    / "research"
    / "o1c96_page16_transport_recovery_seed_20260720"
    / "page-16-active.bin"
)
PAGE17 = (
    ROOT
    / "research"
    / "o1c98_page17_causal_rollover_seed_20260720"
    / "page-17-active.bin"
)
PAGE14 = (
    ROOT
    / "research"
    / "o1c91_page14_causal_rollover_seed_20260720"
    / "page-14-active.bin"
)
PAGE13 = (
    ROOT
    / "research"
    / "o1c89_page13_causal_rollover_seed_20260720"
    / "page-13-active.bin"
)
MANIFEST = (
    ROOT
    / "research"
    / "o1c100_page18_telemetry_recovery_seed_20260721"
    / "telemetry-recovery-preparation-manifest.json"
)
FAILURE_RECEIPT = (
    ROOT
    / "research"
    / "o1c100_page18_telemetry_recovery_seed_20260721"
    / "o1c99-terminal-failure-receipt.json"
)
PAGE18 = (
    ROOT
    / "research"
    / "o1c100_page18_telemetry_recovery_seed_20260721"
    / "page-18-active.bin"
)
PAGE12 = (
    ROOT
    / "runs"
    / "20260720_190040_615684_O1C-0088_apple8-parent-centered-continuation-v1"
    / "initial"
    / "page-12-active.bin"
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
LIVE_BANK_SHA256 = "8100bccf7e463c11b41d97a07017202c5e7ffc37763a76d38114c3044f9fa2fc"
PRIOR_BANK_SHA256 = "715bfbc22fa2162ec8546eed21cf609318d3c5be806092dc4fe4b07cc4d9d654"
STATE_RECEIPT_SHA256 = (
    "050551fc658de62b54b7856996fba0418194c3c2f2608e04a8e9ccc2f51fedad"
)
MANIFEST_BYTES = 6_865
MANIFEST_SHA256 = "c0050ae08738f424505a92278759702bee4fcab23139a31137e715087ae437d9"
FAILURE_RECEIPT_BYTES = 22_520
FAILURE_RECEIPT_SHA256 = (
    "fd52665283e901bb8237923efba081ee1f20d85e1070e9d5e6b2421e9ada46b4"
)
PAGE18_SHA256 = "5d89bbe07c8b988b4f1ce5dc2a31b860ab59192d3efc02854e27b8f779de417c"
PAGE9_SHA256 = "8c3b8cc33badd4aa23920caabc5ea3fc5006675d93805578b74b2b20788c8204"
PAGE10_SHA256 = "bf1fd3e3938bc4125e672ee94ee599e5f21881b4fc87e2bc81e8fc57fc4d3556"
PAGE11_SHA256 = "9853f06bc882bfbb6312207bc8c20e0e9ca1500e49aad14594f6d7c66b62a04d"
PAGE12_SHA256 = "44205f81322d526c1cf7b7c96f28a3baf02b6b9bcb08a04f0bab2e66651fa660"
PAGE13_SHA256 = "4c1b7d5a6d40fad9439d95433bcc7a60ff3e7ddc0e4542b0cf003cdf4581e546"
PAGE14_SHA256 = "00a5a4a7b33f1c09c8df24162709b17994bad5825d92476a5f5283a3bf025c7e"
PAGE15_SHA256 = "71f4b544fd74c7979386bf607d82902dc03c4fe1485404fe8fb7111e970ecfe2"
PAGE16_SHA256 = "fb3b56690ec4f50d699c2598dd4fa752376d1609d1e242ee8aa987694cdc48f5"
PAGE17_SHA256 = "0c25ce470df0945fb05914bab107ecea05531166575ec88ebf7d15bb9a22fbfd"
PAGE8_SHA256 = "89e085e7323ea9aaaa31ad1430c3f20ac03f9c21a49c6404374b75ddf59330f4"
FROZEN_V26_SHA256 = "500909839e1e6698b92b56be2208320232ea080f01da23803db74137593c2ffc"
CADICAL_INCLUDE = Path("/opt/homebrew/opt/cadical/include")
CADICAL_LIBRARY = Path("/opt/homebrew/opt/cadical/lib/libcadical.a")


HARNESS = r"""
#define O1_CRYPTO_LAB_O1C101_NO_MAIN
#include "cadical_o1_joint_score_sieve_v29.cpp"

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
  out << "},\"decision_ownership\":{";
  operator_.write_ownership_json(out);
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

int crossing_rearm_mode(const std::string &bank) {
  ParentCenteredGroupedJointScoreSieve operator_ = make_operator(bank, 1.0);
  const int first = operator_.cb_decide();
  require(first == -1 && operator_.action_count() == 1U,
          "initial crossing differs");
  operator_.notify_new_decision_level();
  operator_.notify_assignment({first});
  bool forgettable = true;
  require(operator_.cb_has_external_clause(forgettable) && !forgettable,
          "initial crossing clause differs");
  while (operator_.cb_add_external_clause_lit() != 0) {
  }
  operator_.notify_backtrack(0U);
  const int after_release = operator_.cb_decide();
  require(after_release == 0 || std::abs(after_release) != std::abs(first),
          "released crossing coordinate rearmed");
  if (after_release) {
    operator_.notify_new_decision_level();
    operator_.notify_assignment({after_release});
    bool next_forgettable = true;
    if (operator_.cb_has_external_clause(next_forgettable)) {
      require(!next_forgettable, "next crossing clause differs");
      while (operator_.cb_add_external_clause_lit() != 0) {
      }
    }
    operator_.notify_backtrack(0U);
  }
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
    if (std::string_view(argv[1]) == "crossing-rearm")
      return crossing_rearm_mode(bank);
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
def frozen_inputs() -> tuple[Path, ...]:
    exact = (
        (LIVE_BANK, 24_576, LIVE_BANK_SHA256),
        (PRIOR_BANK, 24_576, PRIOR_BANK_SHA256),
        (STATE_RECEIPT, 52_011, STATE_RECEIPT_SHA256),
        (MANIFEST, MANIFEST_BYTES, MANIFEST_SHA256),
        (PAGE17, 2_773_919, PAGE17_SHA256),
        (PAGE16, 2_831_459, PAGE16_SHA256),
        (PAGE15, 2_843_047, PAGE15_SHA256),
        (PAGE14, 2_817_779, PAGE14_SHA256),
        (PAGE13, 2_846_623, PAGE13_SHA256),
        (PAGE12, 2_725_423, PAGE12_SHA256),
        (PAGE11, 2_876_731, PAGE11_SHA256),
        (PAGE10, 2_874_387, PAGE10_SHA256),
        (PAGE9, 2_885_959, PAGE9_SHA256),
    )
    for path, size, digest in exact:
        assert path.stat().st_size == size
        assert _sha(path) == digest
    return tuple(path for path, _, _ in exact)


@pytest.fixture(scope="module")
def native_builds(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    if not _native_available():
        pytest.skip("CaDiCaL 3.0.0 development files absent")
    build = tmp_path_factory.mktemp("o1c101-native-continuation")
    harness_source = build / "fixture.cpp"
    harness_source.write_text(textwrap.dedent(HARNESS), encoding="utf-8")
    harness = build / "fixture"
    main = build / "cadical_o1_joint_score_sieve_v29"
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
    for flags, source, executable in (
        (
            [*common, "-DO1_CRYPTO_LAB_O1C101_PUBLIC_FIXTURE"],
            harness_source,
            harness,
        ),
        (common, V29, main),
    ):
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


def test_v29_normal_production_binary_compiles_help_and_uuid(
    native_builds: tuple[Path, Path],
) -> None:
    _, main = native_builds
    completed = _run(main, "--help")
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == (
        "usage: cadical_o1_joint_score_sieve_v29 --cnf PATH --potential PATH "
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
    seed = _mapping(payload["priority_seed"])
    assert seed["payload_sha256"] == LIVE_BANK_SHA256
    assert seed["expected_production_sha256"] == LIVE_BANK_SHA256
    assert seed["source_priority_state_receipt_sha256"] == STATE_RECEIPT_SHA256
    assert seed["source_priority_state_receipt_bytes"] == 52_011
    assert seed["source_preparation_manifest_sha256"] == MANIFEST_SHA256
    assert seed["source_preparation_manifest_bytes"] == MANIFEST_BYTES
    assert seed["source_terminal_failure_receipt_sha256"] == FAILURE_RECEIPT_SHA256
    assert seed["source_terminal_failure_receipt_bytes"] == FAILURE_RECEIPT_BYTES
    assert seed["seed_source"] == "sealed-live-continuation-bank"
    assert seed["live_continuation_bank_identity"] is True
    assert seed["fresh_seed_parser_used"] is False
    assert seed["import_roundtrip_exact"] is True
    assert seed["initial_eligible_coordinate_count"] == 255
    state = _mapping(payload["priority_state"])
    assert state["schema"] == (
        "o1-256-o1c101-live-parent-centered-continuation-priority-state-v1"
    )
    assert state["current_bank_sha256"] == LIVE_BANK_SHA256
    assert state["bank_hex"] == LIVE_BANK.read_bytes().hex()
    ownership = _mapping(payload["decision_ownership"])
    assert ownership["schema"] == "o1-256-bounded-decision-ownership-v3"
    assert ownership["events_are_lifecycle_only"] is True


def test_real_native_v29_priority_seed_crosses_exact_v32_adapter_seam(
    native_builds: tuple[Path, Path],
) -> None:
    harness, _ = native_builds
    completed = _run(harness, "import", LIVE_BANK)
    assert completed.returncode == 0, completed.stderr
    actual = _mapping(json.loads(completed.stdout)["priority_seed"])
    validated = adapter_v32._validate_seed_report(
        actual,
        seed_sha256=LIVE_BANK_SHA256,
        production_seal=False,
    )
    assert validated == actual
    assert set(actual) == adapter_v32._SEED_FIELDS
    assert len(actual) == 17


def test_live_bank_retains_failure_first_one_shot_semantics(
    native_builds: tuple[Path, Path],
) -> None:
    harness, _ = native_builds
    completed = _run(harness, "proof", LIVE_BANK)
    assert completed.returncode == 0, completed.stderr
    actions = _mapping(json.loads(completed.stdout)["priority_actions"])
    assert actions["action_count"] == 2
    assert actions["failure_first_count"] == 2
    assert actions["certified_crossing_count"] == 0
    assert actions["releases"] == 2
    assert actions["one_shot_rule"] == (
        "coordinate-consumed-on-first-return;release-does-not-rearm"
    )
    rows = actions["actions"]
    assert [row["sequence"] for row in rows] == [1, 2]
    assert len({row["variable"] for row in rows}) == 2
    assert all(row["semantic"] == "FAILURE_FIRST_PROOF_MINING" for row in rows)


def test_certified_crossing_precedes_priority_and_never_rearms(
    native_builds: tuple[Path, Path],
) -> None:
    harness, _ = native_builds
    crossing = _run(harness, "crossing", LIVE_BANK)
    assert crossing.returncode == 0, crossing.stderr
    actions = _mapping(json.loads(crossing.stdout)["priority_actions"])
    assert actions["action_count"] == 1
    assert actions["failure_first_count"] == 0
    assert actions["certified_crossing_count"] == 1
    assert actions["actions"][0]["semantic"] == (
        "CERTIFIED_STRICT_BOUND_CROSSING_PRUNE"
    )

    rearm = _run(harness, "crossing-rearm", LIVE_BANK)
    assert rearm.returncode == 0, rearm.stderr
    rows = _mapping(json.loads(rearm.stdout)["priority_actions"])["actions"]
    assert rows[0]["variable"] == 1
    assert all(row["variable"] != 1 for row in rows[1:])


def test_native_rejects_prior_bank_before_solver(
    native_builds: tuple[Path, Path],
    frozen_inputs: tuple[Path, ...],
    tmp_path: Path,
) -> None:
    del frozen_inputs
    _, main = native_builds
    completed = _sealed_command(main, tmp_path, PAGE9, PRIOR_BANK)
    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr == (
        "cadical_o1_joint_score_sieve_v29: sealed O1C101 priority seed differs\n"
    )


def test_native_requires_seed_zero_before_inputs(
    native_builds: tuple[Path, Path], tmp_path: Path
) -> None:
    _, main = native_builds
    absent = tmp_path / "absent"
    completed = _run(
        main,
        "--cnf",
        absent,
        "--potential",
        absent,
        "--grouping",
        absent,
        "--vault-in",
        absent,
        "--priority-seed",
        absent,
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
        "cadical_o1_joint_score_sieve_v29: O1C101 priority operator requires seed zero\n"
    )


@pytest.mark.parametrize(
    ("page", "message"),
    (
        (PAGE17, "burned O1C99 Page-17 active vault rejected"),
        (PAGE15, "burned O1C95 Page-15 active vault rejected"),
        (PAGE16, "burned O1C97 Page-16 active vault rejected"),
        (PAGE14, "burned O1C92 Page-14 active vault rejected"),
        (PAGE13, "burned O1C90 Page-13 active vault rejected"),
        (PAGE12, "burned O1C88 Page-12 active vault rejected"),
        (PAGE11, "burned O1C86 Page-11 active vault rejected"),
        (PAGE10, "burned O1C85 Page-10 active vault rejected"),
        (PAGE9, "burned O1C84 Page-9 active vault rejected"),
    ),
)
def test_native_rejects_every_burned_page_before_solver(
    native_builds: tuple[Path, Path],
    frozen_inputs: tuple[Path, ...],
    tmp_path: Path,
    page: Path,
    message: str,
) -> None:
    del frozen_inputs
    _, main = native_builds
    completed = _sealed_command(main, tmp_path, page, LIVE_BANK)
    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr == f"cadical_o1_joint_score_sieve_v29: {message}\n"


def test_native_rejects_nonmatching_page18_before_solver(
    native_builds: tuple[Path, Path], tmp_path: Path
) -> None:
    _, main = native_builds
    forged = tmp_path / "forged-page-18-active.bin"
    forged.write_bytes(bytes(2_680_827))
    completed = _sealed_command(main, tmp_path, forged, LIVE_BANK)
    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr == (
        "cadical_o1_joint_score_sieve_v29: sealed O1C101 Page-18 active vault differs\n"
    )


def test_source_contract_and_o1c100_binding() -> None:
    source = V29.read_text(encoding="utf-8")
    manifest: dict[str, Any] = json.loads(MANIFEST.read_bytes())
    assert _sha(V26) == FROZEN_V26_SHA256
    assert '#include "cadical_o1_joint_score_sieve_v18.cpp"' in source
    assert '#include "o1c82_parent_centered_priority.hpp"' in source
    assert '#include "o1c101_bounded_decision_ownership.hpp"' in source
    assert "o1c101::DecisionOwnershipLedger ownership_" in source
    assert "o1c80::ExactOneBitBoundReader one_bit_reader_" in source
    assert "O1_CRYPTO_LAB_O1C101_PUBLIC_FIXTURE" in source
    assert "O1_CRYPTO_LAB_O1C101_NO_MAIN" in source
    assert "o1-256-cadical-joint-score-sieve-result-v29" in source
    assert "o1-256-o1c101-live-parent-centered-continuation-priority-state-v1" in source
    assert "o1-256-o1c101-failure-first-proof-mining-actions-v1" in source
    assert MANIFEST_SHA256 in source
    assert LIVE_BANK_SHA256 in source
    assert STATE_RECEIPT_SHA256 in source
    assert FAILURE_RECEIPT_SHA256 in source
    assert PAGE18_SHA256 in source
    assert PAGE17_SHA256 in source
    assert PAGE16_SHA256 in source
    assert PAGE15_SHA256 in source
    assert manifest["schema"] == (
        "o1-256-o1c100-page18-telemetry-recovery-preparation-v1"
    )
    assert manifest["attic"]["union_clause_count"] == 2_074
    assert manifest["page18"]["lineage_ordinal"] == 31
    assert manifest["page18"]["clause_count"] == 249
    assert manifest["page18"]["literal_count"] == 669_910
    assert manifest["page18"]["serialized_bytes"] == 2_680_827
    assert manifest["science_boundary"]["imported_clause_count"] == 0
    assert manifest["telemetry_recovery"]["new_chunk_count"] == 0
    assert manifest["final_priority_bank"]["sha256"] == LIVE_BANK_SHA256
    assert manifest["final_priority_bank"]["receipt_sha256"] == (STATE_RECEIPT_SHA256)
    assert "kProductionPage18ActiveVaultBytes = 2680827U" in source
    assert "kBurnedPage17ActiveVaultBytes = 2773919U" in source
    assert "kBurnedPage16ActiveVaultBytes = 2831459U" in source
    assert "kBurnedPage15ActiveVaultBytes = 2843047U" in source
    assert "kProductionLineageOrdinal = 31U" in source
    assert "kProductionActiveLiteralCount = 669910U" in source
    assert "kProductionClauseHeadroom = 263U" in source
    assert "kGlobalNoveltyBaselineClauseCount = 2074U" in source
    assert "source_priority_state_receipt_sha256" in source
    assert "source_priority_state_receipt_bytes" in source
    assert "source_preparation_manifest_sha256" in source
    assert "source_terminal_failure_receipt_sha256" in source
    assert PRIOR_BANK_SHA256 not in source
    assert PAGE8_SHA256 not in source
    assert "LC_UUID" not in source
    crossing = source.index("if (crossing.available)")
    priority = source.index("if (!last_priority_selection_.available)")
    assert crossing < priority
    seed_gate = source.index("seed_sha256 != kLiveContinuationBankSha256")
    page17_burn_gate = source.index("vault_sha256 == kBurnedPage17ActiveVaultSha256")
    page16_gate = source.index("vault_sha256 == kBurnedPage16ActiveVaultSha256")
    page15_gate = source.index("vault_sha256 == kBurnedPage15ActiveVaultSha256")
    page14_gate = source.index("vault_sha256 == kBurnedPage14ActiveVaultSha256")
    page9_gate = source.index("vault_sha256 == kBurnedPage9ActiveVaultSha256")
    page17_gate = source.index("vault_sha256 != kProductionPage18ActiveVaultSha256")
    solver = source.index("CaDiCaL::Solver solver;")
    assert (
        seed_gate
        < page17_burn_gate
        < page16_gate
        < page15_gate
        < page14_gate
        < page9_gate
        < page17_gate
        < solver
    )
    assert "arguments.seed != 0" in source
    assert 'growing_parent_history_bytes\\":0' in source
    assert "-Wl,-no_uuid" not in source
    assert "kLiveStateBytes == 28672U" in STATE_HEADER.read_text(encoding="utf-8")


def _historical_v27_equivalence_recipe() -> None:
    '''Historical string-normalization recipe retained as inert provenance.
        source = V29.read_text(encoding="utf-8")
        manifest_current = """constexpr const char *kO1C96PreparationManifestSha256 =
        "68d42b0f4cfaaf8a5b03f4b61515a8032860623dd5517fc87dac87b087a1c7b7";"""
        manifest_prior = """constexpr const char *kO1C93PreparationManifestSha256 =
        "187f09309b2d866549441d713f29bfed696c140f5c5a99536001c889f5836a24";"""
        current_production = """constexpr size_t kProductionLineageOrdinal = 29U;
    constexpr size_t kProductionActiveLimit = 251U;
    constexpr size_t kProductionActiveClauseCount = 251U;
    constexpr size_t kProductionActiveLiteralCount = 707566U;
    constexpr size_t kGlobalNoveltyBaselineClauseCount = 1812U;
    constexpr size_t kProductionClauseHeadroom = 261U;
    constexpr const char *kProductionPage18ActiveVaultSha256 =
        "fb3b56690ec4f50d699c2598dd4fa752376d1609d1e242ee8aa987694cdc48f5";
    constexpr size_t kProductionPage18ActiveVaultBytes = 2831459U;
    constexpr const char *kBurnedPage15ActiveVaultSha256 =
        "71f4b544fd74c7979386bf607d82902dc03c4fe1485404fe8fb7111e970ecfe2";
    constexpr size_t kBurnedPage15ActiveVaultBytes = 2843047U;"""
        prior_production = """constexpr size_t kProductionLineageOrdinal = 28U;
    constexpr size_t kProductionActiveLimit = 251U;
    constexpr size_t kProductionActiveClauseCount = 251U;
    constexpr size_t kProductionActiveLiteralCount = 710463U;
    constexpr size_t kGlobalNoveltyBaselineClauseCount = 1812U;
    constexpr size_t kO1C93ImportedNovelClauseCount = 261U;
    constexpr const char *kProductionPage15ActiveVaultSha256 =
        "71f4b544fd74c7979386bf607d82902dc03c4fe1485404fe8fb7111e970ecfe2";
    constexpr size_t kProductionPage15ActiveVaultBytes = 2843047U;"""
        current_assertions = """static_assert(std::string_view(kO1C96PreparationManifestSha256).size() == 64U);
    static_assert(std::string_view(kO1C92PriorityStateReceiptSha256).size() == 64U);
    static_assert(kO1C92PriorityStateReceiptBytes == 52014U);
    static_assert(kProductionLineageOrdinal == 29U);
    static_assert(kProductionActiveLimit == kProductionActiveClauseCount);
    static_assert(kProductionActiveLimit + kProductionClauseHeadroom ==
                  kMaximumVaultClauses);
    static_assert(kProductionActiveLimit + kProductionClauseHeadroom == 512U);
    static_assert(kProductionActiveLimit == 251U);
    static_assert(kProductionActiveLiteralCount == 707566U);
    static_assert(kProductionClauseHeadroom == 261U);
    static_assert(kGlobalNoveltyBaselineClauseCount == 1812U);"""
        prior_assertions = """static_assert(std::string_view(kO1C93PreparationManifestSha256).size() == 64U);
    static_assert(std::string_view(kO1C92PriorityStateReceiptSha256).size() == 64U);
    static_assert(kO1C92PriorityStateReceiptBytes == 52014U);
    static_assert(kProductionLineageOrdinal == 28U);
    static_assert(kProductionActiveLimit == kProductionActiveClauseCount);
    static_assert(kProductionActiveLimit + kO1C93ImportedNovelClauseCount ==
                  kMaximumVaultClauses);
    static_assert(kProductionActiveLimit + kO1C93ImportedNovelClauseCount == 512U);
    static_assert(kProductionActiveLimit == 251U);
    static_assert(kProductionActiveLiteralCount == 710463U);
    static_assert(kO1C93ImportedNovelClauseCount == 261U);
    static_assert(kGlobalNoveltyBaselineClauseCount == 1812U);"""
        burned_gate = """    if (production_seal &&
            vault_payload.size() == kBurnedPage15ActiveVaultBytes &&
            vault_sha256 == kBurnedPage15ActiveVaultSha256)
          throw std::runtime_error("burned O1C95 Page-15 active vault rejected");
    """
        for current, prior in (
            (manifest_current, manifest_prior),
            (current_production, prior_production),
            (current_assertions, prior_assertions),
        ):
            assert current in source
            source = source.replace(current, prior)
        assert burned_gate in source
        source = source.replace(burned_gate, "")
        for current, prior in (
            ("O1C-0101", "O1C-0095"),
            ("O1C101", "O1C95"),
            ("o1c101", "o1c95"),
            ("V29", "V26"),
            ("v29", "v26"),
            ("kProductionPage18", "kProductionPage15"),
            (PAGE16_SHA256, PAGE15_SHA256),
            ("2831459U", "2843047U"),
            ("Page-16", "Page-15"),
        ):
            source = source.replace(current, prior)
        assert source == V26.read_text(encoding="utf-8")
    '''


def test_v29_preserves_the_v27_operator_boundary_and_changes_only_seals() -> None:
    current = V29.read_text(encoding="utf-8")
    previous = (NATIVE / "cadical_o1_joint_score_sieve_v27.cpp").read_text(
        encoding="utf-8"
    )
    for token in (
        "scan_and_select",
        "write_priority_seed_json",
        "write_priority_state_json",
        "write_priority_actions_json",
        "finalize_after_solve",
        "CaDiCaL::ExternalPropagator",
        "CaDiCaL::Terminator",
    ):
        assert current.count(token) == previous.count(token)
    assert "kProductionActiveLimit = 249U" in current
    assert "kProductionClauseHeadroom = 263U" in current
    assert "kBurnedPage16ActiveVaultSha256" in current
    assert "o1-256-cadical-joint-score-sieve-result-v29" in current
