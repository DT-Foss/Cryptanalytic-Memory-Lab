from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import math
import shutil
import struct
import subprocess
import textwrap
from pathlib import Path
from typing import Any

import pytest

import o1_crypto_lab.o1c82_parent_centered_seed as seed


ROOT = Path(__file__).resolve().parents[1]
PERSISTED_JSON = ROOT / "research/O1C0082_PARENT_CENTERED_SEED_MANIFEST_20260720.json"
PERSISTED_MARKDOWN = ROOT / "research/O1C0082_PARENT_CENTERED_SEED_MANIFEST_20260720.md"


def _mapping(value: object) -> dict[str, Any]:
    assert isinstance(value, dict)
    return value


@pytest.fixture(scope="module")
def census() -> dict[str, Any]:
    return dict(seed.load_sealed_o1c81_census(ROOT, verify_fresh=True))


@pytest.fixture(scope="module")
def records(census: dict[str, Any]) -> tuple[seed.CoordinateRecord, ...]:
    return seed.compile_coordinate_records(census)


@pytest.fixture(scope="module")
def bank(records: tuple[seed.CoordinateRecord, ...]) -> bytes:
    return seed.serialize_seed_bank(records)


@pytest.fixture(scope="module")
def manifest() -> dict[str, object]:
    return seed.generate_parent_centered_seed_manifest(ROOT)


def test_sealed_census_and_reader_reproduction_are_exact(
    census: dict[str, Any],
) -> None:
    payload = (ROOT / seed.CENSUS_RELATIVE).read_bytes()
    assert len(payload) == seed.CENSUS_BYTES == 203_761
    assert hashlib.sha256(payload).hexdigest() == seed.CENSUS_SHA256
    assert census["schema"] == seed.SEALED_CENSUS.schema
    census_input = _mapping(census["input"])
    assert census_input["gzip_sha256"] == (
        "3b8466634e35ff526dbd3fa86ee8d4ddab3383250bd7237c97f0f80ada669e48"
    )
    assert census_input["raw_sha256"] == (
        "8673b9097034d4634bb432705974b904c402862fa175ca841bf36eb1be63ebf5"
    )


def test_sealed_census_rejects_tamper_and_symlink(tmp_path: Path) -> None:
    source = ROOT / seed.SEALED_CENSUS.relative
    payload = bytearray(source.read_bytes())
    payload[len(payload) // 2] ^= 1
    tampered = tmp_path / "tampered.json"
    tampered.write_bytes(payload)
    tampered_spec = dataclasses.replace(
        seed.SEALED_CENSUS, relative=Path(tampered.name)
    )
    with pytest.raises(
        seed.O1C82ParentCenteredSeedError, match="census digest differs"
    ):
        seed._read_sealed_census_bytes(tmp_path, tampered_spec)

    linked = tmp_path / "linked.json"
    try:
        linked.symlink_to(source)
    except OSError:
        pytest.skip("symlinks are unavailable")
    linked_spec = dataclasses.replace(seed.SEALED_CENSUS, relative=Path(linked.name))
    with pytest.raises(
        seed.O1C82ParentCenteredSeedError,
        match="not a sealed regular file",
    ):
        seed._read_sealed_census_bytes(tmp_path, linked_spec)


def test_exact_256_by_96_bank_and_frozen_digest(
    records: tuple[seed.CoordinateRecord, ...], bank: bytes
) -> None:
    assert seed.RECORD_STRUCT.size == seed.RECORD_BYTES == 96
    assert len(records) == 256
    assert len(bank) == seed.BANK_BYTES == 24_576
    assert hashlib.sha256(bank).hexdigest() == seed.EXPECTED_BANK_SHA256
    assert seed.EXPECTED_BANK_SHA256 == (
        "86787bda89f29587525ffbc071d2229608a5bff5c3243361086794379f77e21c"
    )
    assert tuple(record.variable for record in records) == tuple(range(1, 257))
    assert sum(record.count for record in records) == 16_384


def test_field_order_m2_and_exact_integer_count_derivation(
    census: dict[str, Any], records: tuple[seed.CoordinateRecord, ...]
) -> None:
    assert seed.RECORD_FORMAT == "<QddQQddQQddd"
    assert seed.PACKED_FIELDS == (
        ("count", "u64", 0),
        ("raw_mean", "f64", 8),
        ("raw_M2", "f64", 16),
        ("raw_positive_count", "u64", 24),
        ("raw_zero_count", "u64", 32),
        ("centered_mean", "f64", 40),
        ("centered_M2", "f64", 48),
        ("centered_positive_count", "u64", 56),
        ("centered_zero_count", "u64", 64),
        ("robust_z_mean", "f64", 72),
        ("robust_abs_z_mean", "f64", 80),
        ("robust_abs_z_max", "f64", 88),
    )
    analysis = _mapping(census["recorded_prefix_analysis"])
    rows = analysis["coordinate_accumulators"]
    assert isinstance(rows, list)
    for variable in (1, 50, 158, 185, 206, 256):
        row = _mapping(rows[variable - 1])
        record = records[variable - 1]
        count = record.count
        assert record.raw_m2 == row["raw_variance"] * count
        assert record.centered_m2 == row["centered_variance"] * count
        assert record.raw_positive_count == row["raw_positive_fraction"] * count
        assert record.raw_zero_count == row["raw_zero_fraction"] * count
        assert record.centered_positive_count == (
            row["centered_positive_fraction"] * count
        )
        assert record.centered_zero_count == row["centered_zero_fraction"] * count


def test_fraction_counts_reject_nonintegral_values(census: dict[str, Any]) -> None:
    changed = copy.deepcopy(census)
    analysis = _mapping(changed["recorded_prefix_analysis"])
    rows = analysis["coordinate_accumulators"]
    assert isinstance(rows, list)
    row = _mapping(rows[0])
    row["raw_positive_fraction"] = 0.5
    with pytest.raises(
        seed.O1C82ParentCenteredSeedError,
        match="raw positive fraction times count is not exactly integral",
    ):
        seed.compile_coordinate_records(changed)


def test_variable_241_is_exact_all_zero_record(
    records: tuple[seed.CoordinateRecord, ...], bank: bytes
) -> None:
    record = records[240]
    assert record.variable == 241
    assert record.count == 0
    assert record.to_bytes() == bytes(96)
    assert bank[240 * 96 : 241 * 96] == bytes(96)
    assert [value.variable for value in records if value.count == 0] == [241]


def test_strict_parse_and_byte_exact_roundtrip(bank: bytes) -> None:
    parsed = seed.parse_seed_bank(bank)
    assert len(parsed) == 256
    assert seed.serialize_seed_bank(parsed) == bank

    with pytest.raises(seed.O1C82ParentCenteredSeedError, match="length differs"):
        seed.parse_seed_bank(bank[:-1], expected_sha256=None)
    with pytest.raises(seed.O1C82ParentCenteredSeedError, match="digest differs"):
        seed.parse_seed_bank(bytes([bank[0] ^ 1]) + bank[1:])

    nonfinite = bytearray(bank)
    struct.pack_into("<d", nonfinite, 8, math.nan)
    with pytest.raises(seed.O1C82ParentCenteredSeedError, match="finite f64"):
        seed.parse_seed_bank(bytes(nonfinite), expected_sha256=None)

    nonzero_missing = bytearray(bank)
    struct.pack_into("<Q", nonzero_missing, 240 * seed.RECORD_BYTES, 1)
    with pytest.raises(
        seed.O1C82ParentCenteredSeedError, match="observed coordinate count differs"
    ):
        seed.parse_seed_bank(bytes(nonzero_missing), expected_sha256=None)


def test_manifest_binds_header_provenance_lineage_and_no_orientation(
    manifest: dict[str, object],
) -> None:
    bank = _mapping(manifest["bank"])
    assert bank["sha256"] == seed.EXPECTED_BANK_SHA256
    assert bank["serialized_bytes"] == 24_576
    assert bank["record_count"] == 256
    assert bank["record_bytes"] == 96
    assert bank["roundtrip_byte_exact"] is True
    assert bank["variable_241_all_zero"] is True
    assert bank["zero_record_variables"] == [241]

    header = _mapping(manifest["header"])
    assert header["bank_is_headerless"] is True
    assert header["bank_payload_offset"] == 0
    assert header["byte_order"] == "little-endian"
    assert header["import_magic"] == "O1C82-PCP-SEED1"
    assert header["import_schema"] == ("o1-256-o1c82-parent-centered-priority-seed-v1")
    assert header["record_struct"] == seed.RECORD_FORMAT
    assert header["fields"] == [
        {"name": name, "offset": offset, "type": field_type}
        for name, field_type, offset in seed.PACKED_FIELDS
    ]
    import_contract = _mapping(manifest["import_contract"])
    assert import_contract == {
        "magic": seed.IMPORT_MAGIC,
        "native_header_relative_path": "native/o1c82_parent_centered_priority.hpp",
        "payload_bytes": 24_576,
        "payload_sha256": seed.EXPECTED_BANK_SHA256,
        "record_layout_byte_exact": True,
        "schema": seed.IMPORT_SCHEMA,
    }

    lineage = _mapping(manifest["lineage"])
    assert lineage == {
        "parent_attempt_id": "O1C-0081",
        "seed_role": "target-free-preload-for-fresh-lineage-21",
        "source_attempt_id": "O1C-0080",
        "source_lineage_call_ordinal": 20,
    }
    orientation = _mapping(manifest["orientation_contract"])
    assert orientation == {
        "belief_orientation": "DISABLED",
        "emitted_key_bits": 0,
        "signed_statistics_are_not_key_bit_beliefs": True,
    }


def test_eligibility_and_exact_live_state_accounting(
    manifest: dict[str, object], records: tuple[seed.CoordinateRecord, ...]
) -> None:
    eligibility = _mapping(manifest["eligibility"])
    assert eligibility == {
        "belief_orientation_authorized": False,
        "eligible_coordinate_count": 225,
        "minimum_count": 37,
        "priority_only_not_bit_polarity": True,
        "rule": "count>=37",
    }
    assert sum(record.count >= 37 for record in records) == 225
    accounting = _mapping(manifest["state_accounting"])
    assert accounting == {
        "asymptotic_live_state": "O(256)",
        "coordinate_bank_bytes": 24_576,
        "live_packed_state_bytes": 28_672,
        "manifest_and_offline_input_materialization_excluded": True,
        "parent_scratch_bytes": 4_096,
        "parent_scratch_capacity": 256,
        "parent_scratch_entry_bytes": 16,
    }


def test_scope_is_zero_call_and_persisted_reports_are_fresh(
    manifest: dict[str, object],
) -> None:
    assert manifest["scope"] == {
        "fresh_targets": 0,
        "mps_or_gpu_calls": 0,
        "native_solver_calls": 0,
        "network_calls": 0,
        "public_verification_calls": 0,
        "refits": 0,
        "reveal_calls": 0,
        "science_calls": 0,
        "target_bytes_read": False,
        "truth_key_bytes_read": False,
    }
    json_payload = seed.serialize_parent_centered_seed_manifest(manifest)
    markdown_payload = seed.render_parent_centered_seed_markdown(manifest)
    assert len(json_payload) == seed.EXPECTED_MANIFEST_BYTES
    assert hashlib.sha256(json_payload).hexdigest() == seed.EXPECTED_MANIFEST_SHA256
    assert PERSISTED_JSON.read_bytes() == json_payload
    assert PERSISTED_MARKDOWN.read_bytes() == markdown_payload
    markdown = markdown_payload.decode("utf-8")
    assert seed.EXPECTED_BANK_SHA256 in markdown
    assert "`24576`-byte bank" in markdown
    assert "`4096` bytes" in markdown
    assert "`28672` bytes" in markdown
    assert "Belief orientation is disabled" in markdown
    assert not (ROOT / "research/O1C0082_PARENT_CENTERED_SEED_20260720.bin").exists()


def test_api_and_cli_check_return_bytes_without_persisting_bank(
    bank: bytes, capsys: pytest.CaptureFixture[str]
) -> None:
    assert seed.compile_parent_centered_seed(ROOT, verify_fresh=False) == bank
    result = seed.main(
        [
            "--root",
            ROOT.as_posix(),
            "--format",
            "manifest",
            "--check",
            PERSISTED_JSON.as_posix(),
        ]
    )
    assert result == 0
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["matches"] is True
    assert receipt["format"] == "manifest"


def test_cpp_importer_accepts_python_bank_byte_exactly(
    bank: bytes, tmp_path: Path
) -> None:
    compiler = shutil.which("c++") or shutil.which("clang++")
    if compiler is None:
        pytest.skip("a C++17 compiler is unavailable")
    source = tmp_path / "o1c82_seed_import.cpp"
    executable = tmp_path / "o1c82_seed_import"
    bank_path = tmp_path / "seed.bank"
    bank_path.write_bytes(bank)
    source.write_text(
        textwrap.dedent(
            f"""
            #include <fstream>
            #include <string>
            #include "native/o1c82_parent_centered_priority.hpp"

            int main(int argc, char **argv) {{
              if (argc != 2)
                return 2;
              if (o1c82::kSeedMagic != "{seed.IMPORT_MAGIC}" ||
                  o1c82::kSeedSchema != "{seed.IMPORT_SCHEMA}")
                return 3;
              o1c82::SeedImage image;
              image.magic = std::string(o1c82::kSeedMagic);
              image.schema = std::string(o1c82::kSeedSchema);
              std::ifstream input(argv[1], std::ios::binary);
              input.read(reinterpret_cast<char *>(image.records.data()),
                         static_cast<std::streamsize>(image.records.size()));
              if (static_cast<size_t>(input.gcount()) != image.records.size())
                return 4;
              char trailing = 0;
              if (input.read(&trailing, 1))
                return 5;
              image.payload_sha256 =
                  o1c82::ParentCenteredPriority::seed_payload_sha256(image.records);
              if (image.payload_sha256 != "{seed.EXPECTED_BANK_SHA256}")
                return 6;
              o1c82::ParentCenteredPriority priority;
              priority.import_seed(image);
              const o1c82::SeedImage exported = priority.export_seed();
              return exported.magic == image.magic &&
                             exported.schema == image.schema &&
                             exported.payload_sha256 == image.payload_sha256 &&
                             exported.records == image.records
                         ? 0
                         : 7;
            }}
            """
        ),
        encoding="utf-8",
    )
    built = subprocess.run(
        [
            compiler,
            "-std=c++17",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            ROOT.as_posix(),
            source.as_posix(),
            "-o",
            executable.as_posix(),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=120,
    )
    assert built.returncode == 0, built.stderr
    imported = subprocess.run(
        [executable.as_posix(), bank_path.as_posix()],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert imported.returncode == 0, imported.stderr
