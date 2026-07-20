from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import textwrap
from pathlib import Path
from typing import Any

import pytest

import o1_crypto_lab.o1c82_parent_centered_seed as seed


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "native"
V19 = NATIVE / "cadical_o1_joint_score_sieve_v19.cpp"
STATE_HEADER = NATIVE / "o1c82_parent_centered_priority.hpp"
CADICAL_INCLUDE = Path("/opt/homebrew/opt/cadical/include")
CADICAL_LIBRARY = Path("/opt/homebrew/opt/cadical/lib/libcadical.a")


HARNESS = r"""
#define O1_CRYPTO_LAB_O1C82_NO_MAIN
#include "cadical_o1_joint_score_sieve_v19.cpp"

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

PotentialField coincident_field() {
  PotentialField field = synthetic_field();
  field.factors[0].energies = {0.0, 1.0};
  field.factors[1].energies = {0.0, 1.0};
  return field;
}

std::string read_all(const char *path) {
  std::ifstream input(path, std::ios::binary);
  if (!input)
    throw std::runtime_error("fixture seed open failed");
  return std::string(std::istreambuf_iterator<char>(input),
                     std::istreambuf_iterator<char>());
}

ParentCenteredGroupedJointScoreSieve make_operator(const std::string &seed,
                                                   double threshold,
                                                   bool coincident = false) {
  const std::string potential_digest = raw_digest(0x11U);
  const std::string cnf_digest = raw_digest(0x22U);
  const std::string potential_sha256 = bytes_hex(potential_digest);
  const std::string cnf_sha256 = bytes_hex(cnf_digest);
  const std::string grouping = synthetic_grouping(potential_digest);
  const std::string vault = synthetic_vault(
      cnf_digest, potential_digest, grouping, threshold);
  return ParentCenteredGroupedJointScoreSieve(
      coincident ? coincident_field() : synthetic_field(), grouping, vault,
      cnf_sha256, potential_sha256,
      threshold, seed, sha256(seed), false);
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
  out << "},\"ownership\":{";
  operator_.write_ownership_json(out);
  out << "},\"base_sieve\":{";
  operator_.write_base_json(out);
  out << "}}\n";
  std::cout << out.str();
}

int proof_mode(const std::string &seed_payload) {
  ParentCenteredGroupedJointScoreSieve operator_ =
      make_operator(seed_payload, -1.0);
  require(operator_.current_priority_bank_sha256() == sha256(seed_payload),
          "seed import identity differs");

  const int first = operator_.cb_decide();
  require(first != 0 && operator_.action_count() == 1U,
          "first proof-mining action differs");
  const PriorityActionEvent first_event = operator_.action(0U);
  require(first_event.semantic ==
              PriorityActionSemantic::FAILURE_FIRST_PROOF_MINING &&
              first_event.literal ==
                  o1c82::ParentCenteredPriority::
                      lower_upper_bound_action_literal(
                          first_event.variable, first_event.upper_zero,
                          first_event.upper_one) &&
              first_event.lower_upper_bound >= -1.0,
          "failure-first lower-UB mapping differs");
  operator_.notify_new_decision_level();
  operator_.notify_assignment({first});
  operator_.notify_backtrack(0U);
  require(operator_.action(0U).released && operator_.consumed(std::abs(first)),
          "first one-shot release differs");

  const int second = operator_.cb_decide();
  require(second != 0 && std::abs(second) != std::abs(first) &&
              operator_.action_count() == 2U,
          "released coordinate was incorrectly rearmed");
  operator_.notify_new_decision_level();
  operator_.notify_assignment({second});
  operator_.notify_backtrack(0U);
  const int exhausted = operator_.cb_decide();
  require(exhausted == 0 && operator_.action_count() == 2U &&
              operator_.probe_count() == 6U,
          "one-shot population exhaustion differs");
  const o1c82::SeedImage continuation = operator_.export_priority_seed();
  const std::string continuation_payload(
      reinterpret_cast<const char *>(continuation.records.data()),
      continuation.records.size());
  ParentCenteredGroupedJointScoreSieve continued =
      make_operator(continuation_payload, -1.0);
  require(continued.current_priority_bank_sha256() ==
              continuation.payload_sha256,
          "next-episode priority seed import differs");
  emit_json(operator_);
  return 0;
}

int crossing_mode(const std::string &seed_payload) {
  ParentCenteredGroupedJointScoreSieve operator_ =
      make_operator(seed_payload, 1.0);
  const int literal = operator_.cb_decide();
  require(literal == -1 && operator_.action_count() == 1U,
          "certified crossing did not take precedence");
  const PriorityActionEvent event = operator_.action(0U);
  require(event.semantic ==
              PriorityActionSemantic::CERTIFIED_STRICT_BOUND_CROSSING &&
              event.lower_upper_bound == 0.0 &&
              operator_.last_priority_selection().available &&
              operator_.last_priority_selection().variable == 2,
          "synthetic crossing precedence witness differs");
  operator_.notify_new_decision_level();
  operator_.notify_assignment({literal});
  bool forgettable = true;
  require(operator_.cb_has_external_clause(forgettable) && !forgettable,
          "certified crossing did not queue a v6 prune");
  while (operator_.cb_add_external_clause_lit() != 0) {
  }
  operator_.notify_backtrack(0U);
  emit_json(operator_);
  return 0;
}

int coincident_mode(const std::string &seed_payload) {
  ParentCenteredGroupedJointScoreSieve operator_ =
      make_operator(seed_payload, 1.0, true);
  const int literal = operator_.cb_decide();
  require(literal != 0 && operator_.action(0U).semantic ==
                              PriorityActionSemantic::
                                  FAILURE_FIRST_PROOF_MINING,
          "coincident fixture did not select proof-mining action");
  const int other = std::abs(literal) == 1 ? -2 : -1;
  operator_.notify_new_decision_level();
  operator_.notify_assignment({literal, other});
  require(operator_.action(0U).coincident_v6_pending,
          "coincident v6 prune was not recorded");
  bool forgettable = true;
  require(operator_.cb_has_external_clause(forgettable) && !forgettable,
          "coincident batch did not cross tau");
  while (operator_.cb_add_external_clause_lit() != 0) {
  }
  operator_.notify_backtrack(0U);
  emit_json(operator_);
  return 0;
}

int tamper_mode(std::string seed_payload) {
  seed_payload[0] = static_cast<char>(seed_payload[0] ^ 1);
  try {
    const std::string original_sha =
        "86787bda89f29587525ffbc071d2229608a5bff5c3243361086794379f77e21c";
    const std::string potential_digest = raw_digest(0x11U);
    const std::string cnf_digest = raw_digest(0x22U);
    const std::string grouping = synthetic_grouping(potential_digest);
    const std::string vault = synthetic_vault(
        cnf_digest, potential_digest, grouping, -1.0);
    ParentCenteredGroupedJointScoreSieve operator_(
        synthetic_field(), grouping, vault, bytes_hex(cnf_digest),
        bytes_hex(potential_digest), -1.0, seed_payload, original_sha, false);
    (void)operator_;
  } catch (const std::runtime_error &error) {
    require(std::string(error.what()).find("payload digest differs") !=
                std::string::npos,
            "tampered seed rejection differs");
    std::cout << "tamper-rejected\n";
    return 0;
  }
  throw std::runtime_error("tampered seed was accepted");
}

} // namespace

int main(int argc, char **argv) {
  try {
    require(argc == 3, "fixture arguments differ");
    const std::string seed_payload = read_all(argv[2]);
    if (std::string_view(argv[1]) == "proof")
      return proof_mode(seed_payload);
    if (std::string_view(argv[1]) == "crossing")
      return crossing_mode(seed_payload);
    if (std::string_view(argv[1]) == "coincident")
      return coincident_mode(seed_payload);
    if (std::string_view(argv[1]) == "tamper")
      return tamper_mode(seed_payload);
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


@pytest.fixture(scope="module")
def seed_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("o1c82-native-seed") / "priority.seed"
    payload = seed.compile_parent_centered_seed(ROOT, verify_fresh=False)
    assert len(payload) == 24_576
    assert hashlib.sha256(payload).hexdigest() == seed.EXPECTED_BANK_SHA256
    path.write_bytes(payload)
    return path


@pytest.fixture(scope="module")
def native_builds(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    if not _native_available():
        pytest.skip("CaDiCaL 3.0.0 development files absent")
    build = tmp_path_factory.mktemp("o1c82-native-parent-centered")
    harness_source = build / "fixture.cpp"
    harness_source.write_text(textwrap.dedent(HARNESS), encoding="utf-8")
    harness = build / "fixture"
    main = build / "cadical_o1_joint_score_sieve_v19"
    common = [
        "c++",
        "-std=c++17",
        "-O2",
        "-DNDEBUG",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-DO1_CRYPTO_LAB_O1C82_PUBLIC_FIXTURE",
        f"-I{NATIVE}",
        f"-I{CADICAL_INCLUDE}",
    ]
    for source, executable in ((harness_source, harness), (V19, main)):
        completed = subprocess.run(
            [*common, str(source), str(CADICAL_LIBRARY), "-o", str(executable)],
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


def test_fixture_compiles_complete_main_and_help_surface(
    native_builds: tuple[Path, Path],
) -> None:
    _, main = native_builds
    completed = _run(main, "--help")
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == (
        "usage: cadical_o1_joint_score_sieve_v19 --cnf PATH --potential PATH "
        "--grouping PATH --vault-in PATH --priority-seed PATH --threshold "
        "FLOAT --conflict-limit N [--seed N]\n"
    )


def test_seed_identity_lower_ub_one_shot_release_and_bounded_telemetry(
    native_builds: tuple[Path, Path], seed_path: Path
) -> None:
    harness, _ = native_builds
    completed = _run(harness, "proof", seed_path)
    assert completed.returncode == 0, completed.stderr
    payload: dict[str, Any] = json.loads(completed.stdout)
    seed_report = _mapping(payload["priority_seed"])
    assert seed_report["payload_bytes"] == 24_576
    assert seed_report["payload_sha256"] == seed.EXPECTED_BANK_SHA256
    assert seed_report["import_roundtrip_exact"] is True

    state = _mapping(payload["priority_state"])
    assert state["candidate_population"] == 2
    assert state["parent_scans"] == 3
    assert state["consumed_coordinate_count"] == 2
    assert state["probe_trace"]["count"] == 6
    assert state["probe_trace"]["bytes"] == 6 * 57
    accounting = _mapping(state["state_accounting"])
    assert accounting["priority_bank_bytes"] == 24_576
    assert accounting["parent_scratch_bytes"] == 4_096
    assert accounting["priority_live_state_bytes"] == 28_672
    assert accounting["action_capacity"] == 256
    assert accounting["growing_parent_history_bytes"] == 0
    final_bank = bytes.fromhex(state["bank_hex"])
    assert state["bank_bytes"] == len(final_bank) == 24_576
    assert hashlib.sha256(final_bank).hexdigest() == state["current_bank_sha256"]

    actions = _mapping(payload["priority_actions"])
    assert actions["transport_origin"] == "BOUND_LOSING_CHILD"
    assert actions["transport_is_semantic_name"] is False
    assert actions["action_count"] == 2
    assert actions["failure_first_count"] == 2
    assert actions["certified_crossing_count"] == 0
    assert actions["confirmed_actions"] == 2
    assert actions["releases"] == 2
    assert actions["belief_orientation_authorized"] is False
    assert actions["posterior_emitted"] is False
    for action in actions["actions"]:
        assert action["semantic"] == "FAILURE_FIRST_PROOF_MINING"
        assert action["machine_action"] == "FAILURE_FIRST_PROOF_MINING"
        assert action["proof_mining_action"] is True
        assert action["certified_threshold_action"] is False
        assert action["released"] is True
        expected = (
            -action["variable"]
            if action["upper_zero"] <= action["upper_one"]
            else action["variable"]
        )
        assert action["literal"] == expected
        assert action["current_lower_upper_bound"] == min(
            action["upper_zero"], action["upper_one"]
        )

    ownership = _mapping(payload["ownership"])
    assert ownership["origin_counts"]["BOUND_LOSING_CHILD"]["proposals"] == 2
    assert ownership["origin_counts"]["BOUND_LOSING_CHILD"]["releases"] == 2
    base = _mapping(payload["base_sieve"])
    assert base["cb_decide_calls"] == 3
    assert base["cb_decide_nonzero"] == 0


def test_certified_crossing_precedes_higher_priority_proof_mining_candidate(
    native_builds: tuple[Path, Path], seed_path: Path
) -> None:
    harness, _ = native_builds
    completed = _run(harness, "crossing", seed_path)
    assert completed.returncode == 0, completed.stderr
    payload: dict[str, Any] = json.loads(completed.stdout)
    actions = _mapping(payload["priority_actions"])
    assert actions["action_count"] == 1
    assert actions["failure_first_count"] == 0
    assert actions["certified_crossing_count"] == 1
    action = actions["actions"][0]
    assert action["variable"] == 1
    assert action["literal"] == -1
    assert action["semantic"] == "CERTIFIED_STRICT_BOUND_CROSSING_PRUNE"
    assert action["machine_action"] == "CERTIFIED_STRICT_BOUND_CROSSING"
    assert action["certified_threshold_action"] is True
    assert action["current_lower_upper_bound"] == 0.0
    base = _mapping(payload["base_sieve"])
    assert base["threshold_prunes"] == 1
    assert base["trail_threshold_prunes"] == 1
    assert base["external_clauses_queued"] == 1
    assert base["external_clauses_emitted"] == 1


def test_seed_digest_tamper_is_rejected_before_import(
    native_builds: tuple[Path, Path], seed_path: Path
) -> None:
    harness, _ = native_builds
    completed = _run(harness, "tamper", seed_path)
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "tamper-rejected\n"


def test_batched_coincident_prune_is_recorded_but_not_claimed(
    native_builds: tuple[Path, Path], seed_path: Path
) -> None:
    harness, _ = native_builds
    completed = _run(harness, "coincident", seed_path)
    assert completed.returncode == 0, completed.stderr
    payload: dict[str, Any] = json.loads(completed.stdout)
    actions = _mapping(payload["priority_actions"])
    assert actions["failure_first_count"] == 1
    assert actions["certified_crossing_count"] == 0
    assert actions["coincident_v6_pending_actions"] == 1
    action = actions["actions"][0]
    assert action["semantic"] == "FAILURE_FIRST_PROOF_MINING"
    assert action["coincident_v6_pending"] is True
    assert action["certified_threshold_action"] is False
    assert actions["prune_claim_for_failure_first"] is False
    base = _mapping(payload["base_sieve"])
    assert base["threshold_prunes"] == 1


def test_source_freeze_and_semantic_separation_contract() -> None:
    source = V19.read_text(encoding="utf-8")
    state = STATE_HEADER.read_text(encoding="utf-8")
    assert '#include "cadical_o1_joint_score_sieve_v18.cpp"' in source
    assert "GroupedJointScoreSieveV6 base_;" in source
    assert "#define private" not in source
    assert "--priority-seed PATH" in source
    assert seed.EXPECTED_BANK_SHA256 in source
    assert "89e085e7323ea9aaaa31ad1430c3f20ac03f9c21a49c6404374b75ddf59330f4" in source
    assert "kProductionPage8ActiveVaultBytes = 2769351U" in source
    assert "o1-256-cadical-joint-score-sieve-result-v19" in source
    assert "FAILURE_FIRST_PROOF_MINING" in source
    assert "CERTIFIED_STRICT_BOUND_CROSSING_PRUNE" in source
    assert 'transport_is_semantic_name\\":false' in source
    crossing = source.index("if (crossing.available)")
    priority = source.index("if (!last_priority_selection_.available)")
    assert crossing < priority
    assert 'growing_parent_history_bytes\\":0' in source
    assert 'bank_hex\\":\\"' in source
    assert "kLiveStateBytes == 28672U" in state
