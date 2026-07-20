from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import textwrap
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "native"
HEADER = NATIVE / "o1c101_bounded_decision_ownership.hpp"


HARNESS = r"""
#include "o1c101_bounded_decision_ownership.hpp"
#include "o1c80_decision_ownership.hpp"

#include <cstdint>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

static_assert(sizeof(int) == sizeof(int32_t),
              "test platform must preserve the i32le literal ABI");

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

void emit(const o1c101::DecisionOwnershipLedger &ledger) {
  std::ostringstream output;
  output << '{';
  ledger.write_json(output);
  output << '}';
  std::cout << output.str() << '\n';
}

int million_mode() {
  o1c101::DecisionOwnershipLedger ledger;
  for (uint64_t index = 0; index < 1000000U; ++index)
    ledger.notify_assignment(777);
  require(ledger.events().empty(), "foreign observations were retained");
  require(ledger.foreign_assignments() == 1000000U,
          "foreign count differs");
  require(ledger.total_event_count() == 1000000U,
          "total observation count differs");
  ledger.validate_solve_end();
  emit(ledger);
  return 0;
}

int kinds_mode() {
  o1c101::DecisionOwnershipLedger ledger;
  require(ledger.propose(o1c101::DecisionOrigin::PREFIX, 9U, 11, 77U) == 1U,
          "proposal token differs");
  ledger.notify_new_decision_level(1U);
  const o1c101::DecisionToken before = ledger.active_tokens().at(0);

  ledger.notify_assignment(-11);
  require(ledger.active_tokens().at(0).token == before.token &&
              ledger.active_tokens().at(0).literal == before.literal &&
              !ledger.active_tokens().at(0).confirmed &&
              ledger.opposite_assignments() == 1U && ledger.confirmed() == 0U,
          "opposite assignment mutated ownership");
  ledger.notify_assignment(99);
  require(ledger.active_tokens().at(0).token == before.token &&
              !ledger.active_tokens().at(0).confirmed &&
              ledger.foreign_assignments() == 1U,
          "foreign assignment mutated ownership");

  ledger.notify_assignment(11);
  require(ledger.active_tokens().at(0).confirmed && ledger.confirmed() == 1U,
          "first confirmation differs");
  ledger.notify_assignment(11);
  require(ledger.active_tokens().at(0).confirmed && ledger.confirmed() == 1U &&
              ledger.renotifications() == 1U,
          "renotification mutated ownership");
  const std::vector<o1c101::DecisionToken> released = ledger.notify_backtrack(0U);
  require(released.size() == 1U && released.at(0).confirmed,
          "confirmed release differs");
  ledger.validate_solve_end();
  emit(ledger);
  return 0;
}

int full_mode() {
  o1c101::DecisionOwnershipLedger ledger;
  for (uint32_t index = 0; index < 256U; ++index) {
    const auto origin = static_cast<o1c101::DecisionOrigin>(1U + index % 6U);
    ledger.propose(origin, index, static_cast<int>(index + 1U), index + 100U);
    ledger.notify_new_decision_level(index + 1U);
    ledger.notify_assignment(static_cast<int>(index + 1U));
  }
  require(ledger.active_tokens().size() == 256U &&
              ledger.events().size() == 768U,
          "full live lifecycle differs");
  const std::vector<o1c101::DecisionToken> released = ledger.notify_backtrack(0U);
  require(released.size() == 256U && ledger.events().size() == 1024U,
          "full release lifecycle differs");

  const uint64_t proposals = ledger.proposals();
  const uint64_t total = ledger.total_event_count();
  const size_t recorded = ledger.events().size();
  const std::string digest = ledger.nonclaim_digest_sha256();
  bool rejected = false;
  try {
    ledger.propose(o1c101::DecisionOrigin::PREFIX, 999U, 999, 999U);
  } catch (const std::runtime_error &error) {
    rejected = std::string(error.what()).find("token cap") != std::string::npos;
  }
  require(rejected && ledger.proposals() == proposals &&
              ledger.total_event_count() == total &&
              ledger.events().size() == recorded &&
              ledger.nonclaim_digest_sha256() == digest && !ledger.has_pending(),
          "token cap rejection mutated state");
  ledger.validate_solve_end();
  emit(ledger);
  return 0;
}

bool is_legacy_lifecycle(o1c80::OwnershipEventKind kind) {
  return kind == o1c80::OwnershipEventKind::PROPOSED ||
         kind == o1c80::OwnershipEventKind::LEVEL_BOUND ||
         kind == o1c80::OwnershipEventKind::CONFIRMED ||
         kind == o1c80::OwnershipEventKind::RELEASED ||
         kind == o1c80::OwnershipEventKind::LEVEL_BOUND_UNOBSERVED_RELEASE;
}

void compare_state(const o1c80::DecisionOwnershipLedger &legacy,
                   const o1c101::DecisionOwnershipLedger &bounded) {
  require(legacy.current_level() == bounded.current_level() &&
              legacy.proposals() == bounded.proposals() &&
              legacy.level_bound() == bounded.level_bound() &&
              legacy.confirmed() == bounded.confirmed() &&
              legacy.releases() == bounded.releases() &&
              legacy.confirmed_releases() == bounded.confirmed_releases() &&
              legacy.unobserved_releases() == bounded.unobserved_releases() &&
              legacy.opposite_assignments() == bounded.opposite_assignments() &&
              legacy.foreign_assignments() == bounded.foreign_assignments() &&
              legacy.renotifications() == bounded.renotifications() &&
              legacy.has_pending() == bounded.has_pending() &&
              legacy.active_tokens().size() == bounded.active_tokens().size(),
          "legacy semantic counters differ");
  for (size_t index = 0; index < legacy.active_tokens().size(); ++index) {
    const o1c80::DecisionToken &left = legacy.active_tokens().at(index);
    const o1c101::DecisionToken &right = bounded.active_tokens().at(index);
    require(left.token == right.token && left.callback == right.callback &&
                static_cast<uint8_t>(left.origin) ==
                    static_cast<uint8_t>(right.origin) &&
                left.row == right.row && left.literal == right.literal &&
                left.bound_level == right.bound_level &&
                left.confirmed == right.confirmed,
            "legacy live token differs");
  }
}

int parity_mode() {
  o1c80::DecisionOwnershipLedger legacy;
  o1c101::DecisionOwnershipLedger bounded;
  legacy.notify_assignment(90);
  bounded.notify_assignment(90);
  legacy.propose(o1c80::DecisionOrigin::PREFIX, 10U, 10, 100U);
  bounded.propose(o1c101::DecisionOrigin::PREFIX, 10U, 10, 100U);
  legacy.notify_new_decision_level(1U);
  bounded.notify_new_decision_level(1U);
  legacy.notify_assignment(-10);
  bounded.notify_assignment(-10);
  legacy.notify_assignment(10);
  bounded.notify_assignment(10);
  legacy.notify_assignment(10);
  bounded.notify_assignment(10);
  legacy.propose(o1c80::DecisionOrigin::RANK_ORIGINAL, 20U, 20, 200U);
  bounded.propose(o1c101::DecisionOrigin::RANK_ORIGINAL, 20U, 20, 200U);
  legacy.notify_new_decision_level(2U);
  bounded.notify_new_decision_level(2U);
  legacy.notify_assignment(30);
  bounded.notify_assignment(30);
  legacy.notify_backtrack(0U);
  bounded.notify_backtrack(0U);
  require(legacy.unobserved_releases() == 1U &&
              bounded.unobserved_releases() == 1U &&
              legacy.confirmed_releases() == 1U &&
              bounded.confirmed_releases() == 1U &&
              legacy.origin_releases(o1c80::DecisionOrigin::RANK_ORIGINAL) ==
                  1U &&
              bounded.origin_releases(
                  o1c101::DecisionOrigin::RANK_ORIGINAL) == 1U,
          "unconfirmed release counters or origin differ");
  compare_state(legacy, bounded);

  size_t bounded_index = 0;
  for (const o1c80::OwnershipEvent &left : legacy.events()) {
    if (!is_legacy_lifecycle(left.kind))
      continue;
    require(bounded_index < bounded.events().size(),
            "bounded lifecycle ended early");
    const o1c101::OwnershipEvent &right = bounded.events().at(bounded_index++);
    require(left.sequence == right.sequence &&
                static_cast<uint8_t>(left.kind) ==
                    static_cast<uint8_t>(right.kind) &&
                left.token == right.token && left.callback == right.callback &&
                static_cast<uint8_t>(left.origin) ==
                    static_cast<uint8_t>(right.origin) &&
                left.row == right.row && left.literal == right.literal &&
                left.level == right.level &&
                left.observed_literal == right.observed_literal,
            "legacy lifecycle transcript differs");
  }
  require(bounded_index == bounded.events().size() &&
              bounded.total_event_count() == legacy.events().size(),
          "bounded global sequence accounting differs");
  const o1c101::OwnershipEvent &unobserved = bounded.events().at(5U);
  require(unobserved.kind ==
                  o1c101::OwnershipEventKind::LEVEL_BOUND_UNOBSERVED_RELEASE &&
              unobserved.token == 2U &&
              unobserved.origin == o1c101::DecisionOrigin::RANK_ORIGINAL &&
              unobserved.sequence == 10U,
          "unconfirmed release transcript differs");
  legacy.validate_solve_end();
  bounded.validate_solve_end();
  std::cout << "parity\n";
  return 0;
}

} // namespace

int main(int argc, char **argv) {
  try {
    if (argc == 2 && std::string(argv[1]) == "million")
      return million_mode();
    if (argc == 2 && std::string(argv[1]) == "kinds")
      return kinds_mode();
    if (argc == 2 && std::string(argv[1]) == "full")
      return full_mode();
    if (argc == 2 && std::string(argv[1]) == "parity")
      return parity_mode();
    throw std::runtime_error("harness arguments differ");
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
"""


@pytest.fixture(scope="module")
def native_harness(tmp_path_factory: pytest.TempPathFactory) -> Path:
    compiler = shutil.which("c++") or shutil.which("clang++")
    if compiler is None:
        pytest.skip("C++ compiler is unavailable")
    build = tmp_path_factory.mktemp("o1c101-bounded-ownership")
    source = build / "harness.cpp"
    binary = build / "harness"
    source.write_text(textwrap.dedent(HARNESS), encoding="utf-8")
    completed = subprocess.run(
        [
            compiler,
            "-std=c++17",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pedantic",
            "-I",
            str(NATIVE),
            str(source),
            "-o",
            str(binary),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    return binary


def _run(binary: Path, mode: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(binary), mode],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def _payload(binary: Path, mode: str) -> dict[str, Any]:
    completed = _run(binary, mode)
    assert completed.returncode == 0, completed.stderr
    value = json.loads(completed.stdout)
    assert isinstance(value, dict)
    return value


def _record(
    sequence: int,
    kind: int,
    token: int,
    callback: int,
    origin: int,
    row: int,
    literal: int,
    level: int,
    observed_literal: int,
) -> bytes:
    return struct.pack(
        "<QBQQBIiIi",
        sequence,
        kind,
        token,
        callback,
        origin,
        row,
        literal,
        level,
        observed_literal,
    )


def _validate_v3(payload: dict[str, Any]) -> None:
    assert payload["schema"] == "o1-256-bounded-decision-ownership-v3"
    assert payload["events_are_lifecycle_only"] is True
    assert payload["events_have_global_sequence"] is True
    assert payload["maximum_tokens"] == 256
    assert payload["maximum_recorded_lifecycle_events"] == 1024
    lifecycle = payload["lifecycle_event_count"]
    compacted = payload["compacted_nonclaim_count"]
    assert isinstance(lifecycle, int)
    assert isinstance(compacted, int)
    assert lifecycle <= 1024
    assert payload["recorded_event_count"] == lifecycle
    assert payload["recorded_lifecycle_event_count"] == lifecycle
    assert payload["omitted_event_count"] == compacted
    assert payload["total_event_count"] == lifecycle + compacted
    assert payload["event_count"] == payload["total_event_count"]
    assert compacted == sum(payload["nonclaim_kind_counts"].values())
    digest = payload["nonclaim_stream_digest"]
    assert digest["algorithm"] == "SHA-256"
    assert digest["encoding"] == "o1c101-nonclaim-canonical-le-v1"
    assert digest["record_bytes"] == 42
    assert digest["record_count"] == compacted
    assert len(digest["sha256"]) == 64
    int(digest["sha256"], 16)
    events = payload["events"]
    assert len(events) == lifecycle
    assert all(
        event["kind"]
        in {
            "PROPOSED",
            "LEVEL_BOUND",
            "CONFIRMED",
            "RELEASED",
            "LEVEL_BOUND_UNOBSERVED_RELEASE",
        }
        for event in events
    )
    sequences = [event["sequence"] for event in events]
    assert sequences == sorted(set(sequences))
    assert all(0 < sequence <= payload["total_event_count"] for sequence in sequences)


def test_header_declares_bounded_contract() -> None:
    source = HEADER.read_text(encoding="utf-8")
    assert "namespace o1c101" in source
    assert "kMaximumTokens = 256U" in source
    assert "4U * kMaximumTokens" in source
    assert "kNonclaimRecordBytes = 42U" in source
    assert "o1-256-bounded-decision-ownership-v3" in source
    assert "sizeof(int) == sizeof(int32_t)" in source
    assert "std::numeric_limits<int>::digits" in source
    assert "kMaximumRecordedEvents = 65536" not in source


def test_million_foreign_observations_are_constant_state_and_exact_digest(
    native_harness: Path,
) -> None:
    payload = _payload(native_harness, "million")
    _validate_v3(payload)
    assert payload["foreign_assignments"] == 1_000_000
    assert payload["opposite_assignments"] == 0
    assert payload["renotifications"] == 0
    assert payload["lifecycle_event_count"] == 0
    assert payload["events"] == []

    expected = hashlib.sha256()
    for sequence in range(1, 1_000_001):
        expected.update(_record(sequence, 5, 0, 0, 0, 0, 777, 0, 777))
    assert payload["nonclaim_stream_digest"]["sha256"] == expected.hexdigest()


def test_all_compacted_kinds_preserve_ownership_and_global_gaps(
    native_harness: Path,
) -> None:
    payload = _payload(native_harness, "kinds")
    _validate_v3(payload)
    assert payload["nonclaim_kind_counts"] == {
        "OPPOSITE_ASSIGNMENT": 1,
        "FOREIGN_ASSIGNMENT": 1,
        "RENOTIFIED": 1,
    }
    assert payload["proposals"] == 1
    assert payload["level_bound_interventions"] == 1
    assert payload["confirmed_interventions"] == 1
    assert payload["releases"] == 1
    assert payload["confirmed_releases"] == 1
    assert [event["sequence"] for event in payload["events"]] == [1, 2, 5, 7]

    expected = hashlib.sha256()
    expected.update(_record(3, 4, 1, 77, 1, 9, 11, 1, -11))
    expected.update(_record(4, 5, 0, 0, 0, 0, 99, 1, 99))
    expected.update(_record(6, 6, 1, 77, 1, 9, 11, 1, 11))
    assert payload["nonclaim_stream_digest"]["sha256"] == expected.hexdigest()


def test_full_256_token_lifecycle_is_bounded_and_cap_is_atomic(
    native_harness: Path,
) -> None:
    payload = _payload(native_harness, "full")
    _validate_v3(payload)
    assert payload["proposals"] == 256
    assert payload["level_bound_interventions"] == 256
    assert payload["confirmed_interventions"] == 256
    assert payload["releases"] == 256
    assert payload["lifecycle_event_count"] == 1024
    assert payload["total_event_count"] == 1024
    assert payload["maximum_live_tokens"] == 256
    assert payload["live_tokens"] == 0
    assert payload["nonclaim_stream_digest"]["sha256"] == hashlib.sha256().hexdigest()


def test_functional_transcript_matches_legacy_below_old_cap(
    native_harness: Path,
) -> None:
    completed = _run(native_harness, "parity")
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "parity\n"


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("schema",), "tampered"),
        (("total_event_count",), 0),
        (("compacted_nonclaim_count",), 99),
        (("nonclaim_stream_digest", "record_bytes"), 41),
        (("nonclaim_stream_digest", "sha256"), "g" * 64),
        (("events", 0, "kind"), "FOREIGN_ASSIGNMENT"),
        (("events", 1, "sequence"), 1),
    ],
)
def test_schema_and_digest_tampering_is_detected(
    native_harness: Path, path: tuple[object, ...], replacement: object
) -> None:
    payload = copy.deepcopy(_payload(native_harness, "kinds"))
    target: Any = payload
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = replacement
    with pytest.raises((AssertionError, ValueError)):
        _validate_v3(payload)
