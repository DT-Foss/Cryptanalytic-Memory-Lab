from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import textwrap
from typing import Any

import pytest

from o1_crypto_lab.criticality_potential import CriticalityPotentialField
from o1_crypto_lab.joint_score_grouping_v1 import (
    build_compatibility_grouping,
    compatibility_grouped_upper_bound,
)


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "native"
V18 = NATIVE / "cadical_o1_joint_score_sieve_v18.cpp"
BOUND_HEADER = NATIVE / "o1c80_one_bit_bound.hpp"
OWNERSHIP_HEADER = NATIVE / "o1c80_decision_ownership.hpp"
CADICAL_INCLUDE = Path("/opt/homebrew/opt/cadical/include")
CADICAL_LIBRARY = Path("/opt/homebrew/opt/cadical/lib/libcadical.a")
ARCHIVE_POTENTIAL = (
    ROOT
    / "runs/20260719_095509_APPLE-VIEW-0008-MATCHED_crossblock-consequence-sieve-v1"
    / "artifacts/potential/primary-eight-block.potential"
)
ARCHIVE_GROUPING = (
    ROOT
    / "runs/20260719_170824_O1C-0069_apple8-alternating-reader-v1"
    / "apple8-width6.grouping"
)
ARCHIVE_NATIVE_RESULT = (
    ROOT
    / "runs/20260719_231823_O1C-0074_apple8-causal-attic-stream-v1"
    / "episodes/01/native-result.json.gz"
)


HARNESS = r"""
#define O1_CRYPTO_LAB_O1C80_NO_MAIN
#include "cadical_o1_joint_score_sieve_v18.cpp"

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
  const std::string grouping_hex = sha256(grouping);
  for (size_t index = 0; index < grouping_hex.size(); index += 2U)
    result.push_back(static_cast<char>(std::stoul(
        grouping_hex.substr(index, 2U), nullptr, 16)));
  const auto append_hex = [&result](const std::string &hex) {
    for (size_t index = 0; index < hex.size(); index += 2U)
      result.push_back(static_cast<char>(
          std::stoul(hex.substr(index, 2U), nullptr, 16)));
  };
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

void require_throws(const std::function<void()> &callback,
                    const char *fragment) {
  try {
    callback();
  } catch (const std::runtime_error &error) {
    require(std::string(error.what()).find(fragment) != std::string::npos,
            "rejection message differs");
    return;
  }
  throw std::runtime_error("expected rejection was absent");
}

int synthetic_mode() {
  const std::string potential_digest = raw_digest(0x11U);
  const std::string cnf_digest = raw_digest(0x22U);
  const std::string potential_sha256 = bytes_hex(potential_digest);
  const std::string cnf_sha256 = bytes_hex(cnf_digest);
  const std::string grouping = synthetic_grouping(potential_digest);
  const std::string vault = synthetic_vault(
      cnf_digest, potential_digest, grouping, 1.0);
  PotentialField field = synthetic_field();
  o1c80::ExactOneBitBoundReader reader = build_one_bit_bound_reader(
      field, grouping, potential_sha256);
  std::vector<int8_t> parent = {0, 0};
  const auto cache = reader.prepare_parent<ExactDoubleSum>(parent);
  const auto upward = [](ExactDoubleSum exact, const char *name) {
    return upward_exact_sum(std::move(exact), name);
  };
  const o1c80::ChildUpperBounds forward =
      reader.child_upper_bounds(cache, 1, upward);
  const o1c80::ChildUpperBounds reverse = reader.child_upper_bounds(
      cache, 1, upward, o1c80::ChildProbeOrder::ONE_THEN_ZERO);
  require(forward.zero == 0.0 && forward.one == 2.0,
          "synthetic bounds differ");
  require(f64_bits(forward.zero) == f64_bits(reverse.zero) &&
              f64_bits(forward.one) == f64_bits(reverse.one),
          "probe order changed a bound");
  require(parent == std::vector<int8_t>({0, 0}),
          "probe mutated parent assignment");

  const auto neither = o1c80::ExactOneBitBoundReader::select(
      7, {1.0, 2.0}, 1.0);
  const auto zero = o1c80::ExactOneBitBoundReader::select(
      7, {0.5, 1.0}, 1.0);
  const auto one = o1c80::ExactOneBitBoundReader::select(
      7, {1.0, 0.5}, 1.0);
  const auto both = o1c80::ExactOneBitBoundReader::select(
      7, {0.5, 0.75}, 1.0);
  const auto both_one = o1c80::ExactOneBitBoundReader::select(
      7, {0.75, 0.5}, 1.0);
  const auto tie = o1c80::ExactOneBitBoundReader::select(
      7, {0.5, 0.5}, 1.0);
  require(neither.selection ==
              o1c80::ChildSelectionClass::NEITHER_PRUNABLE &&
              neither.losing_literal == 0,
          "strict equality differs");
  require(zero.selection == o1c80::ChildSelectionClass::ZERO_PRUNABLE &&
              zero.losing_literal == -7,
          "bit-zero sign differs");
  require(one.selection == o1c80::ChildSelectionClass::ONE_PRUNABLE &&
              one.losing_literal == 7,
          "bit-one sign differs");
  require(both.selection == o1c80::ChildSelectionClass::BOTH_PRUNABLE &&
              both.losing_literal == -7 && both_one.losing_literal == 7 &&
              tie.losing_literal == -7,
          "both-prunable tie rule differs");

  require_throws(
      [&] {
        std::vector<int8_t> assigned = {1, 0};
        (void)reader.child_upper_bounds<ExactDoubleSum>(assigned, 1, upward);
      },
      "assigned");
  o1c80::ExactOneBitBoundReader wider_key_reader(
      {1, 2}, 3U, 0.0,
      {{{0}, {0.0, 2.0}}, {{1}, {0.0, 0.0}}});
  require_throws(
      [&] {
        (void)wider_key_reader.child_upper_bounds<ExactDoubleSum>(
            parent, 3, upward);
      },
      "unobserved");
  require_throws(
      [&] {
        (void)wider_key_reader.child_upper_bounds<ExactDoubleSum>(
            parent, 4, upward);
      },
      "non-key");

  GroupedJointScoreSieveV6 base(
      field, grouping, vault, cnf_sha256, potential_sha256, 1.0);
  const std::string assignment_before = base.assignment_state();
  const std::string trail_before = base.trail_state();
  const std::string pending_before = base.pending_state();
  const std::string cache_before = base.group_cache_state();
  std::ostringstream telemetry_before;
  base.write_json(telemetry_before);
  (void)reader.child_upper_bounds(cache, 1, upward);
  std::ostringstream telemetry_after_probe;
  base.write_json(telemetry_after_probe);
  require(telemetry_before.str() == telemetry_after_probe.str() &&
              assignment_before == base.assignment_state() &&
              trail_before == base.trail_state() &&
              pending_before == base.pending_state() &&
              cache_before == base.group_cache_state(),
          "probe mutated v6 state or counters");

  o1c80::DecisionOwnershipLedger ownership;
  const uint64_t unobserved_token = ownership.propose(
      o1c80::DecisionOrigin::BOUND_LOSING_CHILD, 0U, -1, 1U);
  require(unobserved_token == 1U &&
              pending_clause_literals(base.pending_state()).empty(),
          "proposal queued a pre-assignment clause");
  base.notify_new_decision_level();
  ownership.notify_new_decision_level(1U);
  require(pending_clause_literals(base.pending_state()).empty(),
          "level binding queued a pre-assignment clause");
  base.notify_backtrack(0U);
  const auto unobserved_release = ownership.notify_backtrack(0U);
  std::ostringstream unobserved_telemetry;
  base.write_json(unobserved_telemetry);
  require(unobserved_release.size() == 1U &&
              !unobserved_release.front().confirmed &&
              json_u64_field(unobserved_telemetry.str(),
                             "threshold_prunes") == 0U &&
              json_u64_field(unobserved_telemetry.str(),
                             "trail_threshold_prunes") == 0U &&
              json_u64_field(unobserved_telemetry.str(),
                             "external_clauses_queued") == 0U &&
              json_u64_field(unobserved_telemetry.str(),
                             "pending_clause_count") == 0U,
          "unobserved proposal realized a prune");

  const uint64_t realized_token = ownership.propose(
      o1c80::DecisionOrigin::BOUND_LOSING_CHILD, 0U, -1, 2U);
  require(realized_token == 2U &&
              pending_clause_literals(base.pending_state()).empty(),
          "second proposal queued a clause");
  base.notify_new_decision_level();
  ownership.notify_new_decision_level(1U);
  base.notify_assignment({-1});
  ownership.notify_assignment(-1);
  const std::vector<int> clause = pending_clause_literals(base.pending_state());
  require(clause == std::vector<int>({1}),
          "v6 canonical threshold no-good sign differs");
  std::ostringstream realized_telemetry;
  base.write_json(realized_telemetry);
  require(json_u64_field(realized_telemetry.str(), "threshold_prunes") == 1U &&
              json_u64_field(realized_telemetry.str(),
                             "trail_threshold_prunes") == 1U &&
              json_u64_field(realized_telemetry.str(),
                             "external_clauses_queued") == 1U,
          "v6 threshold-prune lifecycle differs");
  bool forgettable = true;
  require(base.cb_has_external_clause(forgettable) && !forgettable &&
              base.cb_add_external_clause_lit() == 1 &&
              base.cb_add_external_clause_lit() == 0,
          "v6 clause emission lifecycle differs");
  base.notify_backtrack(0U);
  const auto realized_release = ownership.notify_backtrack(0U);
  require(realized_release.size() == 1U &&
              realized_release.front().confirmed &&
              base.assignment_state() == assignment_before &&
              base.trail_state() == trail_before &&
              base.pending_state() == pending_before &&
              base.group_cache_state() == cache_before,
          "confirmed backtrack did not restore live state");
  std::ostringstream ownership_json;
  ownership.write_json(ownership_json);
  require(ownership_json.str().find(
              "\"schema\":\"o1-256-central-decision-ownership-v2\"") !=
              std::string::npos &&
              ownership_json.str().find("BOUND_LOSING_CHILD") !=
                  std::string::npos &&
              ownership.origin_proposals(
                  o1c80::DecisionOrigin::BOUND_LOSING_CHILD) == 2U &&
              ownership.origin_releases(
                  o1c80::DecisionOrigin::BOUND_LOSING_CHILD) == 2U,
          "typed bound ownership telemetry differs");

  // A solver may terminate at a nonzero level.  Final validation must retain
  // that truthful live token instead of manufacturing a terminal backtrack.
  o1c80::DecisionOwnershipLedger terminal_ownership;
  const uint64_t terminal_token = terminal_ownership.propose(
      o1c80::DecisionOrigin::BOUND_LOSING_CHILD, 1U, 2, 3U);
  terminal_ownership.notify_new_decision_level(1U);
  terminal_ownership.notify_assignment(2);
  terminal_ownership.validate_solve_end();
  std::ostringstream terminal_json;
  terminal_ownership.write_json(terminal_json);
  require(terminal_token == 1U && terminal_ownership.current_level() == 1U &&
              terminal_ownership.active_tokens().size() == 1U &&
              terminal_ownership.active_tokens().front().confirmed &&
              terminal_ownership.releases() == 0U &&
              terminal_json.str().find("\"live_tokens\":1") !=
                  std::string::npos &&
              terminal_json.str().find("\"releases\":0") !=
                  std::string::npos,
          "terminal live-token contract differs");
  std::cout << "synthetic-ok\n";
  return 0;
}

std::string read_all(const char *path) {
  std::ifstream input(path, std::ios::binary);
  if (!input)
    throw std::runtime_error("fixture input open failed");
  return std::string(std::istreambuf_iterator<char>(input),
                     std::istreambuf_iterator<char>());
}

int archive_mode(int argc, char **argv) {
  require(argc == 6, "archive fixture arguments differ");
  const std::string potential = read_all(argv[2]);
  const std::string grouping = read_all(argv[3]);
  const std::string assignment_payload = read_all(argv[4]);
  const int variable = std::stoi(argv[5]);
  PotentialField field = parse_potential(potential, kMaximumVariables);
  o1c80::ExactOneBitBoundReader reader = build_one_bit_bound_reader(
      field, grouping, sha256(potential));
  require(assignment_payload.size() == reader.observed().size(),
          "archive assignment width differs");
  std::vector<int8_t> assignment;
  assignment.reserve(assignment_payload.size());
  for (const unsigned char byte : assignment_payload) {
    require(byte == 0U || byte == 1U || byte == 255U,
            "archive assignment spin differs");
    assignment.push_back(byte == 255U ? int8_t{-1} :
                                         static_cast<int8_t>(byte));
  }
  const std::string assignment_before(
      reinterpret_cast<const char *>(assignment.data()), assignment.size());
  const auto cache = reader.prepare_parent<ExactDoubleSum>(assignment);
  const double parent_upper = upward_exact_sum(
      cache.exact_sum, "O1C80 archive parent upper bound");
  const auto upward = [](ExactDoubleSum exact, const char *name) {
    return upward_exact_sum(std::move(exact), name);
  };
  const auto forward = reader.child_upper_bounds(cache, variable, upward);
  const auto reverse = reader.child_upper_bounds(
      cache, variable, upward, o1c80::ChildProbeOrder::ONE_THEN_ZERO);
  require(f64_bits(forward.zero) == f64_bits(reverse.zero) &&
              f64_bits(forward.one) == f64_bits(reverse.one),
          "archive probe order differs");
  const std::string assignment_after(
      reinterpret_cast<const char *>(assignment.data()), assignment.size());
  require(assignment_before == assignment_after,
          "archive probe mutated assignment");
  std::cout << std::setprecision(std::numeric_limits<double>::max_digits10)
            << "{\"parent_upper\":" << parent_upper
            << ",\"parent_upper_f64le_hex\":\""
            << f64_le_hex(parent_upper) << "\",\"upper_zero\":"
            << forward.zero << ",\"upper_zero_f64le_hex\":\""
            << f64_le_hex(forward.zero) << "\",\"upper_one\":"
            << forward.one << ",\"upper_one_f64le_hex\":\""
            << f64_le_hex(forward.one)
            << "\",\"assignment_sha256\":\""
            << sha256(assignment_before) << "\"}\n";
  return 0;
}

} // namespace

int main(int argc, char **argv) {
  try {
    if (argc == 2 && std::string(argv[1]) == "synthetic")
      return synthetic_mode();
    if (argc >= 2 && std::string(argv[1]) == "archive")
      return archive_mode(argc, argv);
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
def native_harness(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if not _native_available():
        pytest.skip("CaDiCaL 3.0.0 development files absent")
    build = tmp_path_factory.mktemp("o1c80-native-bound")
    source = build / "fixture.cpp"
    source.write_text(textwrap.dedent(HARNESS), encoding="utf-8")
    executable = build / "fixture"
    completed = subprocess.run(
        [
            "c++",
            "-std=c++17",
            "-O2",
            "-DNDEBUG",
            "-Wall",
            "-Wextra",
            "-Werror",
            f"-I{NATIVE}",
            f"-I{CADICAL_INCLUDE}",
            str(source),
            str(CADICAL_LIBRARY),
            "-o",
            str(executable),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    return executable


def _run(executable: Path, *arguments: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(executable), *(str(argument) for argument in arguments)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def test_synthetic_exact_semantics_and_authoritative_v6_lifecycle(
    native_harness: Path,
) -> None:
    completed = _run(native_harness, "synthetic")
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "synthetic-ok\n"


def _archive_assignment(tmp_path: Path) -> tuple[bytes, Path]:
    with gzip.open(ARCHIVE_NATIVE_RESULT, "rt", encoding="utf-8") as stream:
        payload = json.load(stream)
    state = payload["sieve"]["state"]
    assignment = bytes.fromhex(state["assignment_hex"])
    assert hashlib.sha256(assignment).hexdigest() == state["assignment_sha256"]
    path = tmp_path / "o1c74-episode1-terminal.assignment"
    path.write_bytes(assignment)
    return assignment, path


def _spin(byte: int) -> int:
    assert byte in (0, 1, 255)
    return -1 if byte == 255 else byte


def test_o1c74_terminal_var105_matches_full_python_oracle_exactly(
    native_harness: Path, tmp_path: Path
) -> None:
    assignment, assignment_path = _archive_assignment(tmp_path)
    field = CriticalityPotentialField.from_bytes(ARCHIVE_POTENTIAL.read_bytes())
    grouping = build_compatibility_grouping(field, width_cap=6)
    assert grouping.sha256 == hashlib.sha256(ARCHIVE_GROUPING.read_bytes()).hexdigest()
    assert grouping.sha256 == (
        "3da85bae132d829252a68f0e3fd99220ea7d1ef365042806af810ff02f75f636"
    )
    assert len(assignment) == len(field.observed_variables) == 2_981
    parent = {
        variable: spin
        for variable, raw in zip(field.observed_variables, assignment, strict=True)
        if (spin := _spin(raw))
    }
    assert 105 not in parent
    assert 241 not in field.observed_variables
    parent_upper = compatibility_grouped_upper_bound(field, grouping, parent)
    children: dict[int, float] = {}
    for spin in (-1, 1):
        child = dict(parent)
        child[105] = spin
        children[spin] = compatibility_grouped_upper_bound(field, grouping, child)
    assert parent_upper == 15.531057646608152
    assert children == {-1: 15.224559961355952, 1: 14.842606678748025}

    completed = _run(
        native_harness,
        "archive",
        ARCHIVE_POTENTIAL,
        ARCHIVE_GROUPING,
        assignment_path,
        105,
    )
    assert completed.returncode == 0, completed.stderr
    native: dict[str, Any] = json.loads(completed.stdout)
    expected = {
        "parent_upper": parent_upper,
        "parent_upper_f64le_hex": struct.pack("<d", parent_upper).hex(),
        "upper_zero": children[-1],
        "upper_zero_f64le_hex": struct.pack("<d", children[-1]).hex(),
        "upper_one": children[1],
        "upper_one_f64le_hex": struct.pack("<d", children[1]).hex(),
        "assignment_sha256": hashlib.sha256(assignment).hexdigest(),
    }
    assert native == expected
    assert native["upper_one"] - 14.606178797892962 == 0.2364278808550626


def test_source_freeze_has_const_probe_and_bound_first_selector() -> None:
    bound = BOUND_HEADER.read_text(encoding="utf-8")
    source = V18.read_text(encoding="utf-8")
    ownership = OWNERSHIP_HEADER.read_text(encoding="utf-8")
    assert "#define private" not in bound + source
    assert "notify_assignment" not in bound
    assert "evaluate_current_bound" not in bound
    assert "ExactOneBitParentCache" in bound
    assert "incident_groups_.at(local)" in bound
    callback = source[source.index("int cb_decide() override") :]
    assert callback.index("select_bound_losing_child(call)") < callback.index(
        "select_prefix(call)"
    )
    assert callback.index("select_prefix(call)") < callback.index(
        "select_rank_original(call)"
    )
    selector_start = source.index("int select_bound_losing_child(uint64_t call)")
    selector_stop = source.index("void observe_bound_assignments", selector_start)
    selector = source[selector_start:selector_stop]
    assert "for (size_t coordinate = 0;" in selector
    assert "prefix_cursor_" not in selector
    assert "rank_cursor_" not in selector
    assert "frontier_cursor_" not in selector
    assert "bound_cursor" not in source
    assert "BOUND_LOSING_CHILD = 6" in ownership
    assert "std::array<uint64_t, 7>" in ownership
    assert "o1-256-central-decision-ownership-v2" in ownership
    assert "o1-256-cadical-joint-score-sieve-result-v18" in source
    assert "one_bit_bound_reader" in source
    assert "kMaximumRecordedBoundProbeEvents = 16384U" in source
    finalize_start = source.index("void finalize_after_solve()")
    finalize_stop = source.index("void write_json", finalize_start)
    finalize = source[finalize_start:finalize_stop]
    assert "ownership_.validate_solve_end()" in finalize
    assert "notify_backtrack" not in finalize
