from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import shutil
import struct
import subprocess
import textwrap
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "native"
HEADER = NATIVE / "o1c82_parent_centered_priority.hpp"
O1C81_CENSUS = ROOT / "research/O1C0081_BOUND_DIFFERENTIAL_CENSUS_20260720.json"


HARNESS = r"""
#include "o1c82_parent_centered_priority.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using o1c82::BoundPair;
using o1c82::PackedCoordinateBank;
using o1c82::ParentCenteredPriority;

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

void require_close(double actual, double expected, double tolerance,
                   const char *message) {
  if (!std::isfinite(actual) || std::abs(actual - expected) > tolerance)
    throw std::runtime_error(message);
}

template <class Callback>
void require_rejected_unchanged(ParentCenteredPriority &reader,
                                Callback callback, const char *fragment) {
  const ParentCenteredPriority before = reader;
  try {
    callback();
  } catch (const std::runtime_error &error) {
    require(std::string(error.what()).find(fragment) != std::string::npos,
            "rejection reason differs");
    require(std::memcmp(&reader, &before, sizeof(reader)) == 0,
            "rejected input mutated live state");
    return;
  }
  throw std::runtime_error("expected rejection was absent");
}

std::vector<uint8_t> read_bytes(const char *path) {
  std::ifstream input(path, std::ios::binary);
  if (!input)
    throw std::runtime_error("seed input open failed");
  return std::vector<uint8_t>(std::istreambuf_iterator<char>(input),
                              std::istreambuf_iterator<char>());
}

void put_u64(PackedCoordinateBank &payload, size_t offset, uint64_t value) {
  for (unsigned index = 0; index < 8U; ++index)
    payload.at(offset + index) =
        static_cast<uint8_t>(value >> (8U * index));
}

void put_double(PackedCoordinateBank &payload, size_t offset, double value) {
  uint64_t bits = 0;
  std::memcpy(&bits, &value, sizeof(bits));
  put_u64(payload, offset, bits);
}

void put_record(PackedCoordinateBank &payload, int variable, uint64_t count,
                double robust_z_mean) {
  const size_t offset = static_cast<size_t>(variable - 1) *
                        o1c82::kPackedCoordinateBytes;
  put_u64(payload, offset + 0U, count);
  put_double(payload, offset + 8U, 1.0);
  put_double(payload, offset + 16U, 0.0);
  put_u64(payload, offset + 24U, count);
  put_u64(payload, offset + 32U, 0U);
  put_double(payload, offset + 40U, 1.0);
  put_double(payload, offset + 48U, 0.0);
  put_u64(payload, offset + 56U, count);
  put_u64(payload, offset + 64U, 0U);
  put_double(payload, offset + 72U, robust_z_mean);
  put_double(payload, offset + 80U, std::abs(robust_z_mean));
  put_double(payload, offset + 88U, std::abs(robust_z_mean));
}

void import_payload(ParentCenteredPriority &reader,
                    const PackedCoordinateBank &payload) {
  reader.import_seed(o1c82::kSeedMagic, o1c82::kSeedSchema,
                     ParentCenteredPriority::seed_payload_sha256(payload),
                     payload.data(), payload.size());
}

int synthetic_mode() {
  static_assert(sizeof(o1c82::CoordinateAccumulator) == 96U,
                "coordinate record size differs");
  static_assert(sizeof(o1c82::ParentScratchEntry) == 16U,
                "scratch record size differs");
  static_assert(sizeof(ParentCenteredPriority) == 28672U,
                "live state size differs");
  require(o1c82::kCoordinateBankBytes == 24576U &&
              o1c82::kParentScratchBytes == 4096U &&
              o1c82::kLiveStateBytes == 28672U,
          "state constants differ");

  ParentCenteredPriority forward;
  ParentCenteredPriority reverse;
  const std::vector<int> expected = {4, 2, 1, 3};
  o1c82::ParentUpdateResult last;
  for (int parent = 0; parent < 37; ++parent) {
    const double common = parent % 2 ? 20.0 : 10.0;
    std::vector<BoundPair> batch = {
        {1, common - 2.0, 0.0},
        {2, common - 1.0, 0.0},
        {3, common + 1.0, 0.0},
        {4, common + 2.0, 0.0},
    };
    last = forward.observe_parent(batch, expected);
    std::reverse(batch.begin(), batch.end());
    (void)reverse.observe_parent(batch, expected);
  }
  require(forward.export_packed_bank() == reverse.export_packed_bank(),
          "batch order changed accumulator state");
  require_close(last.parent_median, 10.0, 0.0, "parent median differs");
  require_close(last.parent_mad, 1.5, 0.0, "parent MAD differs");
  require_close(last.robust_scale, 2.2239, 1e-15,
                "parent robust scale differs");

  const auto first = forward.coordinate_report(1);
  const auto second = forward.coordinate_report(2);
  const auto fourth = forward.coordinate_report(4);
  require(first.count == 37U && first.eligible && second.eligible &&
              fourth.eligible,
          "synthetic eligibility differs");
  require_close(first.centered_mean, -2.0, 0.0,
                "common mode remained in coordinate one");
  require_close(second.centered_mean, -1.0, 0.0,
                "common mode remained in coordinate two");
  require_close(fourth.centered_mean, 2.0, 0.0,
                "common mode remained in coordinate four");
  require(first.raw_mean > 12.0 && first.raw_mean < 13.0,
          "raw common mode was unexpectedly removed");
  require_close(first.priority, fourth.priority, 0.0,
                "symmetric priorities differ");
  require(last.selection.available && last.selection.variable == 1 &&
              last.selection.action_literal == 1 &&
              last.selection.proof_mining_action &&
              !last.selection.belief_orientation_authorized,
          "deterministic synthetic selection differs");

  std::array<bool, o1c82::kCoordinateCount> excluded{};
  excluded[0] = true;
  const auto alternate = forward.select_current_parent(excluded);
  require(alternate.available && alternate.variable == 4 &&
              alternate.action_literal == 4,
          "nonmutating exclusion selection differs");
  excluded[1] = excluded[2] = excluded[3] = true;
  require(!forward.select_current_parent(excluded).available,
          "fully excluded parent produced a selection");
  require(forward.coordinate_report(1).count == 37U,
          "exclusion mutated the bank");
  require(forward.current_parent_contains(1) &&
              forward.current_parent_differential(1) == 8.0,
          "current parent scratch query differs");
  ParentCenteredPriority cleared = forward;
  const auto bank_before_clear = cleared.export_packed_bank();
  cleared.clear_current_parent();
  require(cleared.current_candidate_count() == 0U &&
              !cleared.select_current_parent().available &&
              cleared.export_packed_bank() == bank_before_clear,
          "empty-parent clear changed persistent state or left stale scratch");

  require(ParentCenteredPriority::lower_upper_bound_action_literal(7, 1.0,
                                                                   1.0) == -7 &&
              ParentCenteredPriority::lower_upper_bound_action_literal(
                  7, -0.0, 0.0) == -7 &&
              ParentCenteredPriority::lower_upper_bound_action_literal(7, 2.0,
                                                                        1.0) == 7,
          "lower-upper-bound literal sign differs");

  const auto seed = forward.export_seed();
  require(seed.magic == o1c82::kSeedMagic && seed.schema == o1c82::kSeedSchema &&
              seed.records.size() == 24576U && seed.payload_sha256.size() == 64U,
          "exported seed envelope differs");
  ParentCenteredPriority clone;
  clone.import_seed(seed);
  require(clone.export_packed_bank() == seed.records &&
              clone.coordinate_report(1).count == 37U &&
              clone.current_candidate_count() == 0U,
          "seed round trip differs");

  const std::vector<BoundPair> valid = {
      {1, 1.0, 0.0}, {2, 2.0, 0.0}, {3, 3.0, 0.0}, {4, 4.0, 0.0}};
  require_rejected_unchanged(
      forward,
      [&] {
        const std::vector<BoundPair> duplicate = {
            {1, 1.0, 0.0}, {1, 2.0, 0.0}, {3, 3.0, 0.0}, {4, 4.0, 0.0}};
        (void)forward.observe_parent(duplicate, expected);
      },
      "duplicated");
  require_rejected_unchanged(
      forward,
      [&] {
        auto nonfinite = valid;
        nonfinite[2].upper_zero = std::numeric_limits<double>::infinity();
        (void)forward.observe_parent(nonfinite, expected);
      },
      "non-finite");
  require_rejected_unchanged(
      forward,
      [&] {
        auto overflow = valid;
        overflow[2].upper_zero = std::numeric_limits<double>::max();
        overflow[2].upper_one = -std::numeric_limits<double>::max();
        (void)forward.observe_parent(overflow, expected);
      },
      "differential");
  require_rejected_unchanged(
      forward,
      [&] {
        auto out_of_range = valid;
        out_of_range[0].variable = 257;
        (void)forward.observe_parent(out_of_range, expected);
      },
      "out of range");
  require_rejected_unchanged(
      forward,
      [&] {
        const std::vector<BoundPair> missing(valid.begin(), valid.end() - 1);
        (void)forward.observe_parent(missing, expected);
      },
      "missing");
  require_rejected_unchanged(
      forward,
      [&] {
        const std::vector<int> repeated_expected = {1, 2, 2, 4};
        (void)forward.observe_parent(valid, repeated_expected);
      },
      "duplicated");
  require_rejected_unchanged(
      forward,
      [&] {
        const std::vector<int> incomplete_expected = {1, 2, 3};
        (void)forward.observe_parent(valid, incomplete_expected);
      },
      "unexpected");

  std::ostringstream telemetry;
  forward.write_json(telemetry);
  std::cout << telemetry.str() << '\n';
  return 0;
}

int tie_mode() {
  ParentCenteredPriority reader;
  PackedCoordinateBank payload{};
  put_record(payload, 1, 37U, 1.0);
  put_record(payload, 2, 37U, 1.0);
  import_payload(reader, payload);
  auto ranked = reader.ranked_priorities();
  require(ranked.size() == 2U && ranked[0].variable == 1,
          "variable-ascending tie break differs");

  payload = {};
  put_record(payload, 1, 37U, 0.0);
  put_record(payload, 2, 38U, 0.0);
  import_payload(reader, payload);
  ranked = reader.ranked_priorities();
  require(ranked.size() == 2U && ranked[0].variable == 2 &&
              ranked[0].priority == ranked[1].priority,
          "count-descending tie break differs");
  std::cout << "tie-ok\n";
  return 0;
}

int canonical_mode(const char *path, const char *digest) {
  const std::vector<uint8_t> raw = read_bytes(path);
  require(raw.size() == o1c82::kCoordinateBankBytes,
          "canonical seed byte count differs");
  PackedCoordinateBank payload{};
  std::copy(raw.begin(), raw.end(), payload.begin());

  ParentCenteredPriority reader;
  reader.import_seed(o1c82::kSeedMagic, o1c82::kSeedSchema, digest,
                     payload.data(), payload.size());
  require(reader.export_packed_bank() == payload,
          "canonical seed bytes did not round trip");
  const auto strong = reader.coordinate_report(185);
  const auto sparse = reader.coordinate_report(158);
  require(strong.count == 73U && strong.eligible && sparse.count == 10U &&
              !sparse.eligible,
          "canonical eligibility differs");
  require_close(strong.raw_mean, -2.3168323408515916, 1e-15,
                "variable 185 raw mean differs");
  require_close(strong.centered_mean, -2.752744217128212, 1e-15,
                "variable 185 centered mean differs");
  require_close(strong.robust_z_mean, -10.738855030935364, 1e-15,
                "variable 185 robust-z mean differs");
  require_close(strong.priority, 91.75281760473375, 1e-12,
                "variable 185 priority differs");
  require_close(sparse.priority, 48.780649516472025, 1e-12,
                "variable 158 raw priority differs");
  const auto ranked = reader.ranked_priorities();
  require(!ranked.empty() && ranked.front().variable == 185 &&
              std::none_of(ranked.begin(), ranked.end(), [](const auto &row) {
                return row.variable == 158;
              }),
          "canonical frozen persistence ranking differs");

  require_rejected_unchanged(
      reader,
      [&] {
        reader.import_seed("wrong", o1c82::kSeedSchema, digest, payload.data(),
                           payload.size());
      },
      "magic");
  require_rejected_unchanged(
      reader,
      [&] {
        reader.import_seed(o1c82::kSeedMagic, "wrong", digest, payload.data(),
                           payload.size());
      },
      "schema");
  require_rejected_unchanged(
      reader,
      [&] {
        reader.import_seed(o1c82::kSeedMagic, o1c82::kSeedSchema,
                           std::string(64U, '0'), payload.data(), payload.size());
      },
      "digest");
  require_rejected_unchanged(
      reader,
      [&] {
        reader.import_seed(o1c82::kSeedMagic, o1c82::kSeedSchema, digest,
                           payload.data(), payload.size() - 1U);
      },
      "byte count");
  require_rejected_unchanged(
      reader,
      [&] {
        auto tampered = payload;
        tampered[100] ^= 1U;
        reader.import_seed(o1c82::kSeedMagic, o1c82::kSeedSchema, digest,
                           tampered.data(), tampered.size());
      },
      "digest");
  require_rejected_unchanged(
      reader,
      [&] {
        auto malformed = payload;
        // Variable 241 is the canonical empty record: make a non-count field
        // nonzero and seal the altered payload to reach semantic validation.
        put_double(malformed, 240U * o1c82::kPackedCoordinateBytes + 8U, 1.0);
        reader.import_seed(
            o1c82::kSeedMagic, o1c82::kSeedSchema,
            ParentCenteredPriority::seed_payload_sha256(malformed),
            malformed.data(), malformed.size());
      },
      "empty coordinate");

  const std::vector<int> expected = {158, 185};
  const std::vector<BoundPair> current = {
      {158, 3.0, 3.0},
      {185, 1.0, 2.0},
  };
  const auto update = reader.observe_parent(current, expected);
  require(update.selection.available && update.selection.variable == 185 &&
              update.selection.action_literal == -185 &&
              update.selection.proof_mining_action &&
              !update.selection.belief_orientation_authorized,
          "canonical live lower-UB action differs");
  std::array<bool, o1c82::kCoordinateCount> excluded{};
  excluded[184] = true;
  require(!reader.select_current_parent(excluded).available,
          "ineligible sparse coordinate bypassed exclusion");

  std::ostringstream telemetry;
  reader.write_json(telemetry);
  std::cout << telemetry.str() << '\n';
  return 0;
}

} // namespace

int main(int argc, char **argv) {
  try {
    if (argc == 2 && std::string(argv[1]) == "synthetic")
      return synthetic_mode();
    if (argc == 2 && std::string(argv[1]) == "ties")
      return tie_mode();
    if (argc == 4 && std::string(argv[1]) == "canonical")
      return canonical_mode(argv[2], argv[3]);
    throw std::runtime_error("harness arguments differ");
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
"""


@pytest.fixture(scope="module")
def native_harness(tmp_path_factory: pytest.TempPathFactory) -> Path:
    compiler = shutil.which("c++")
    if compiler is None:
        pytest.skip("C++ compiler is unavailable")
    build = tmp_path_factory.mktemp("o1c82-native")
    source = build / "o1c82_harness.cpp"
    binary = build / "o1c82_harness"
    source.write_text(textwrap.dedent(HARNESS), encoding="utf-8")
    subprocess.run(
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
        check=True,
        capture_output=True,
        text=True,
    )
    return binary


def _run(binary: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(binary), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )


def _canonical_seed_payload() -> bytes:
    document = json.loads(O1C81_CENSUS.read_text(encoding="utf-8"))
    rows = document["recorded_prefix_analysis"]["coordinate_accumulators"]
    assert isinstance(rows, list) and len(rows) == 256
    records: list[bytes] = []
    for variable, value in enumerate(rows, start=1):
        assert isinstance(value, dict) and value["variable"] == variable
        row = value
        count = int(row["count"])
        if count == 0:
            records.append(bytes(96))
            continue
        raw_positive = round(float(row["raw_positive_fraction"]) * count)
        raw_zero = round(float(row["raw_zero_fraction"]) * count)
        centered_positive = round(float(row["centered_positive_fraction"]) * count)
        centered_zero = round(float(row["centered_zero_fraction"]) * count)
        record = struct.pack(
            "<QddQQddQQddd",
            count,
            float(row["raw_mean"]),
            float(row["raw_variance"]) * count,
            raw_positive,
            raw_zero,
            float(row["centered_mean"]),
            float(row["centered_variance"]) * count,
            centered_positive,
            centered_zero,
            float(row["robust_z_mean"]),
            float(row["robust_abs_z_mean"]),
            float(row["robust_abs_z_max"]),
        )
        assert len(record) == 96
        records.append(record)
    payload = b"".join(records)
    assert len(payload) == 24_576
    return payload


def test_header_is_standalone_and_synthetic_contracts(
    native_harness: Path,
) -> None:
    assert HEADER.is_file()
    completed = _run(native_harness, "synthetic")
    telemetry = json.loads(completed.stdout)
    assert telemetry["schema"] == ("o1-256-o1c82-parent-centered-priority-telemetry-v1")
    assert telemetry["minimum_eligible_count"] == 37
    assert telemetry["eligible_coordinate_count"] == 4
    assert telemetry["priority_order"] == "score-desc,count-desc,variable-asc"
    assert telemetry["proof_mining_action_only"] is True
    assert telemetry["belief_orientation_authorized"] is False
    assert telemetry["selection"]["variable"] == 1
    assert telemetry["state_accounting"] == {
        "packed_bytes_per_coordinate": 96,
        "coordinate_state_bytes": 24_576,
        "parent_scratch_bytes": 4_096,
        "live_packed_state_bytes": 28_672,
    }


def test_deterministic_priority_ties(native_harness: Path) -> None:
    completed = _run(native_harness, "ties")
    assert completed.stdout == "tie-ok\n"


def test_o1c81_seed_identity_sparse_gate_and_lower_ub_action(
    native_harness: Path, tmp_path: Path
) -> None:
    payload = _canonical_seed_payload()
    seed = tmp_path / "o1c81-coordinate-bank.bin"
    seed.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    completed = _run(native_harness, "canonical", str(seed), digest)
    telemetry: dict[str, Any] = json.loads(completed.stdout)
    selection = telemetry["selection"]
    assert selection["variable"] == 185
    assert selection["action_literal"] == -185
    assert selection["proof_mining_action"] is True
    assert selection["belief_orientation_authorized"] is False
    coordinate = selection["coordinate"]
    assert coordinate["count"] == 74
    assert coordinate["eligible"] is True
    assert math.isfinite(coordinate["priority"])
    assert telemetry["current_parent_candidate_count"] == 2
