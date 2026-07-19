from __future__ import annotations

import copy
import itertools
import shutil
from pathlib import Path

import pytest

from o1_crypto_lab.chacha_trace import chacha20_block
from o1_crypto_lab.full256_cnf import (
    Full256CNFError,
    write_full256_instance,
    write_full256_template,
)
from o1_crypto_lab.full256_multiblock_cnf import (
    BLOCK_VARIABLE_STRIDE,
    Full256MultiblockCNFError,
    multiblock_clause_count,
    multiblock_variable_count,
    remap_full256_literal,
    remap_full256_variable,
    verify_full256_multiblock_cnf,
    write_full256_multiblock_cnf,
)


@pytest.fixture(scope="module")
def eight_public_instances(tmp_path_factory: pytest.TempPathFactory):
    root = tmp_path_factory.mktemp("full256-multiblock")
    template = root / "template.cnf"
    semantic_map = root / "template.map.json"
    write_full256_template(template, semantic_map)
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    sources = []
    for index in range(8):
        counter = 1 + index
        source = root / f"public-{index:02d}.cnf"
        report = write_full256_instance(
            template,
            semantic_map,
            source,
            counter=counter,
            nonce=nonce,
            output=chacha20_block(key, counter, nonce),
        )
        sources.append((source, report))
    return root, template, semantic_map, tuple(sources), key, nonce


def test_remap_contract_and_exact_eight_block_counts() -> None:
    assert BLOCK_VARIABLE_STRIDE == 31_872
    assert remap_full256_variable(1, 7) == 1
    assert remap_full256_variable(256, 7) == 256
    assert remap_full256_variable(257, 7) == 223_361
    assert remap_full256_variable(32_128, 7) == 255_232
    assert remap_full256_literal(-32_128, 7) == -255_232
    assert multiblock_variable_count(8) == 255_232
    assert multiblock_clause_count(8) == 1_504_080
    with pytest.raises(Full256MultiblockCNFError):
        multiblock_variable_count(0)
    with pytest.raises(Full256MultiblockCNFError):
        remap_full256_variable(32_129, 0)


def test_writer_streams_and_verifier_recomputes_all_eight_blocks(
    eight_public_instances,
) -> None:
    root, template, semantic_map, sources, _, _ = eight_public_instances
    destination = root / "eight-block.cnf"
    report_path = root / "eight-block.report.json"
    report = write_full256_multiblock_cnf(
        template,
        semantic_map,
        sources,
        destination,
        report_path=report_path,
    )
    assert report.variable_count == 255_232
    assert report.clause_count == 1_504_080
    assert report.public_unit_clause_count == 8 * 640
    assert report.key_unit_clause_count == 0
    assert report.assumption_unit_clause_count == 0
    assert report.blocks[-1].variable_count == 255_232
    assert report.blocks[-1].counter == report.blocks[0].counter + 7
    verification = verify_full256_multiblock_cnf(
        destination, template, semantic_map, sources, report_path
    )
    assert verification["ok"] is True
    assert verification["instance_sha256"] == report.instance_sha256

    with destination.open("rb") as combined, sources[0][0].open("rb") as first:
        assert combined.readline() == b"p cnf 255232 1504080\n"
        first.readline()
        for expected in itertools.islice(first, 256):
            assert combined.readline() == expected

    original = destination.read_bytes()
    with pytest.raises(FileExistsError):
        write_full256_multiblock_cnf(template, semantic_map, sources, destination)
    assert destination.read_bytes() == original


def test_fixed_key_assumptions_tamper_and_report_tamper_fail_closed(
    tmp_path: Path, eight_public_instances
) -> None:
    _, template, semantic_map, sources, key, nonce = eight_public_instances
    fixed = tmp_path / "fixed.cnf"
    fixed_report = write_full256_instance(
        template,
        semantic_map,
        fixed,
        counter=20,
        nonce=nonce,
        output=chacha20_block(key, 20, nonce),
        key_for_self_test=key,
    )
    with pytest.raises(Full256MultiblockCNFError, match="640 public units"):
        write_full256_multiblock_cnf(
            template,
            semantic_map,
            ((fixed, fixed_report),),
            tmp_path / "fixed-multiblock.cnf",
        )

    assumed = tmp_path / "assumed.cnf"
    assumed_report = write_full256_instance(
        template,
        semantic_map,
        assumed,
        counter=21,
        nonce=nonce,
        output=chacha20_block(key, 21, nonce),
        assumptions=((0, 1),),
    )
    with pytest.raises(Full256MultiblockCNFError, match="640 public units"):
        write_full256_multiblock_cnf(
            template,
            semantic_map,
            ((assumed, assumed_report),),
            tmp_path / "assumed-multiblock.cnf",
        )

    tampered = tmp_path / "tampered-source.cnf"
    shutil.copyfile(sources[0][0], tampered)
    payload = bytearray(tampered.read_bytes())
    payload[-4] = ord("1") if payload[-4] != ord("1") else ord("2")
    tampered.write_bytes(payload)
    with pytest.raises(Full256CNFError):
        write_full256_multiblock_cnf(
            template,
            semantic_map,
            ((tampered, sources[0][1]),),
            tmp_path / "tampered-multiblock.cnf",
        )

    destination = tmp_path / "valid.cnf"
    report = write_full256_multiblock_cnf(
        template,
        semantic_map,
        sources[:2],
        destination,
    )
    forged = copy.deepcopy(report.describe())
    forged["blocks"][0]["counter"] += 1
    with pytest.raises(Full256MultiblockCNFError):
        verify_full256_multiblock_cnf(
            destination, template, semantic_map, sources[:2], forged
        )


def test_noncontiguous_or_reordered_sources_are_rejected(
    tmp_path: Path, eight_public_instances
) -> None:
    _, template, semantic_map, sources, _, _ = eight_public_instances
    with pytest.raises(Full256MultiblockCNFError, match="contiguous"):
        write_full256_multiblock_cnf(
            template,
            semantic_map,
            (sources[0], sources[2]),
            tmp_path / "counter-gap.cnf",
        )
    with pytest.raises(Full256MultiblockCNFError, match="contiguous"):
        write_full256_multiblock_cnf(
            template,
            semantic_map,
            (sources[1], sources[0]),
            tmp_path / "reordered.cnf",
        )
