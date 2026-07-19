from __future__ import annotations

import copy
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import cast

from o1_crypto_lab.chacha_trace import chacha20_block
from o1_crypto_lab.full256_cnf import (
    clauses_satisfied,
    load_full256_template_map,
    write_full256_instance,
)
from o1_crypto_lab.full256_forward_assignment import (
    compile_full256_forward_read_plan,
)
from o1_crypto_lab.full256_multiblock_cnf import (
    multiblock_clause_count,
    multiblock_variable_count,
    remap_full256_variable,
    write_full256_multiblock_cnf,
)

from apple_view_8_crossblock_consequences import (
    O1C57_CAPSULE_NAME,
    AppleView8Error,
    compile_crossblock_consequences,
    crossblock_auxiliary_assignment,
    encode_constant_addition,
    preflight_o1c57_consumed_public_build,
    reconstruct_final_pre_feedforward_variables,
    verify_crossblock_consequence_cnf,
    write_crossblock_consequence_cnf,
)


LAB_ROOT = Path(__file__).resolve().parents[2]
FOUNDATION = (
    LAB_ROOT
    / "runs/20260717_054138_O1C-0011_full256-public-cnf-foundation-v1"
)
TEMPLATE = FOUNDATION / "artifacts/cnf/full256_chacha20.cnf"
SEMANTIC_MAP = FOUNDATION / "artifacts/cnf/full256_chacha20.map.json"
PUBLIC_INSTANCE = FOUNDATION / "artifacts/cnf/public_attacker_instance.cnf"
FOUNDATION_RESULT = FOUNDATION / "artifacts/full256_cnf_foundation.json"
O1C57_CAPSULE = LAB_ROOT / "runs" / O1C57_CAPSULE_NAME
KEY = bytes(range(32))
NONCE = bytes.fromhex("000000090000004a00000000")


def _clause_truth(clause: tuple[int, ...], assignment: dict[int, bool]) -> bool:
    return any(
        assignment[abs(literal)] if literal > 0 else not assignment[abs(literal)]
        for literal in clause
    )


def _retained_carries(left: int, constant: int, width: int) -> int:
    carry = 0
    packed = 0
    for bit in range(width):
        source = (left >> bit) & 1
        fixed = (constant >> bit) & 1
        carry = (source & fixed) | (source & carry) | (fixed & carry)
        packed |= carry << bit
    return packed


class AppleView8CrossblockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.final_wires = reconstruct_final_pre_feedforward_variables(SEMANTIC_MAP)
        cls.forward_plan = compile_full256_forward_read_plan(
            SEMANTIC_MAP,
            tuple(variable for word in cls.final_wires for variable in word),
        )
        cls.temporary = tempfile.TemporaryDirectory(prefix="apple-view-8-")
        cls.work = Path(cls.temporary.name)
        foundation = json.loads(FOUNDATION_RESULT.read_text("utf-8"))
        cls.first_report = cast(
            dict[str, object], foundation["instances"]["public"]["instance_report"]
        )
        cls.outputs = tuple(chacha20_block(KEY, counter, NONCE) for counter in (1, 2))
        second_path = cls.work / "public-01.cnf"
        cls.second_report = write_full256_instance(
            TEMPLATE,
            SEMANTIC_MAP,
            second_path,
            counter=2,
            nonce=NONCE,
            output=cls.outputs[1],
        )
        cls.sources = (
            (PUBLIC_INSTANCE, cls.first_report),
            (second_path, cls.second_report),
        )
        cls.base_path = cls.work / "two-block.cnf"
        cls.base_report_path = cls.work / "two-block.report.json"
        cls.base_report = write_full256_multiblock_cnf(
            TEMPLATE,
            SEMANTIC_MAP,
            cls.sources,
            cls.base_path,
            report_path=cls.base_report_path,
        )
        cls.augmented_path = cls.work / "two-block-crossblock.cnf"
        cls.augmented_report_path = cls.work / "two-block-crossblock.report.json"
        cls.augmented_report = write_crossblock_consequence_cnf(
            cls.base_path,
            cls.base_report_path,
            TEMPLATE,
            SEMANTIC_MAP,
            cls.sources,
            cls.augmented_path,
            output_blocks=cls.outputs,
            counters=(1, 2),
            nonce=NONCE,
            report_path=cls.augmented_report_path,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_semantic_map_reconstructs_exact_final_p20_wires(self) -> None:
        words = self.final_wires
        self.assertEqual(len(words), 16)
        self.assertTrue(all(len(word) == 32 for word in words))
        flattened = tuple(variable for word in words for variable in word)
        self.assertEqual(len(flattened), 512)
        self.assertEqual(len(set(flattened)), 512)
        self.assertTrue(all(897 <= variable <= 32_128 for variable in flattened))

        document = load_full256_template_map(SEMANTIC_MAP)
        operations = cast(list[dict[str, object]], document["operations"])
        independently_reconstructed: list[tuple[int, ...] | None] = [None] * 16
        for operation in operations[:640]:
            lane = cast(int, operation["destination_lane"])
            bit_ranges = cast(list[dict[str, object]], operation["bit_ranges"])
            if operation["kind"] == "add32":
                word = tuple(cast(int, row["sum_variable"]) for row in bit_ranges)
            else:
                raw = tuple(cast(int, row["output_variable"]) for row in bit_ranges)
                rotation = cast(int, operation["rotation"])
                word = raw[-rotation:] + raw[:-rotation]
            independently_reconstructed[lane] = word
        self.assertEqual(tuple(independently_reconstructed), words)
        for lane, operation in enumerate(operations[640:]):
            self.assertEqual(operation["phase"], "feed_forward")
            self.assertEqual(operation["destination_lane"], lane)
            self.assertEqual(operation["source_lane"], lane)

    def test_specialized_constant_adder_is_exhaustive_at_four_bits(self) -> None:
        left_variables = (1, 2, 3, 4)
        result_variables = (5, 6, 7, 8)
        for constant in range(16):
            encoding = encode_constant_addition(
                left_variables, result_variables, constant, 9
            )
            self.assertEqual(encoding.clause_count, 24 + (constant & 1))
            for left in range(16):
                satisfying: list[tuple[int, int]] = []
                for result in range(16):
                    for carries in range(16):
                        assignment = {
                            **{
                                variable: bool((left >> bit) & 1)
                                for bit, variable in enumerate(left_variables)
                            },
                            **{
                                variable: bool((result >> bit) & 1)
                                for bit, variable in enumerate(result_variables)
                            },
                            **{
                                variable: bool((carries >> bit) & 1)
                                for bit, variable in enumerate(
                                    encoding.carry_variables
                                )
                            },
                        }
                        if all(
                            _clause_truth(clause, assignment)
                            for clause in encoding.clauses
                        ):
                            satisfying.append((result, carries))
                self.assertEqual(
                    satisfying,
                    [
                        (
                            (left + constant) & 15,
                            _retained_carries(left, constant, 4),
                        )
                    ],
                )

    def test_known_key_forward_assignment_satisfies_one_two_and_eight_blocks(
        self,
    ) -> None:
        for block_count in (1, 2, 8):
            counters = tuple(range(17, 17 + block_count))
            outputs = tuple(
                chacha20_block(KEY, counter, NONCE) for counter in counters
            )
            plan = compile_crossblock_consequences(
                SEMANTIC_MAP,
                output_blocks=outputs,
                counters=counters,
                nonce=NONCE,
            )
            assignment: dict[int, bool] = {}
            for block_index, counter in enumerate(counters):
                values = self.forward_plan.evaluate(
                    key=KEY, counter=counter, nonce=NONCE
                )
                for variable, signed_value in values.items():
                    assignment[remap_full256_variable(variable, block_index)] = (
                        signed_value > 0
                    )
            assignment.update(crossblock_auxiliary_assignment(plan, assignment))
            self.assertTrue(clauses_satisfied(plan.clauses, assignment))
            self.assertEqual(plan.direct_unit_clause_count, block_count * 256)
            self.assertEqual(len(plan.relations), (block_count - 1) * 8)
            self.assertEqual(
                plan.ripple_carry_variable_count, (block_count - 1) * 8 * 32
            )
            self.assertEqual(
                plan.ripple_clause_count,
                (block_count - 1) * 8 * 220
                + sum(relation.delta & 1 for relation in plan.relations),
            )
            self.assertFalse(
                any(
                    len(clause) == 1 and abs(clause[0]) <= 256
                    for clause in plan.clauses
                )
            )

    def test_writer_and_verifier_have_exact_counts_and_zero_key_units(self) -> None:
        report = self.augmented_report
        lsb_ones = sum(relation.delta & 1 for relation in report.relations)
        self.assertEqual(report.base_variable_count, multiblock_variable_count(2))
        self.assertEqual(report.base_clause_count, multiblock_clause_count(2))
        self.assertEqual(report.direct_unit_clause_count, 512)
        self.assertEqual(report.crossblock_relation_count, 8)
        self.assertEqual(report.ripple_carry_variable_count, 256)
        self.assertEqual(report.ripple_clause_count, 8 * 220 + lsb_ones)
        self.assertEqual(
            report.augmentation_clause_count, 512 + 8 * 220 + lsb_ones
        )
        self.assertEqual(report.variable_count, 64_256)
        self.assertEqual(
            report.clause_count,
            multiblock_clause_count(2) + report.augmentation_clause_count,
        )
        self.assertEqual(report.key_unit_clause_count, 0)
        self.assertEqual(report.assumption_unit_clause_count, 0)
        self.assertFalse(report.target_key_included)
        self.assertFalse(report.target_trace_included)
        verification = verify_crossblock_consequence_cnf(
            self.augmented_path,
            self.base_path,
            self.base_report_path,
            TEMPLATE,
            SEMANTIC_MAP,
            self.sources,
            self.augmented_report_path,
            output_blocks=self.outputs,
            counters=(1, 2),
            nonce=NONCE,
        )
        self.assertTrue(verification["ok"])
        self.assertEqual(verification["instance_sha256"], report.instance_sha256)

    def test_tamper_report_collision_and_no_overwrite_fail_closed(self) -> None:
        original_digest = hashlib.sha256(self.augmented_path.read_bytes()).hexdigest()
        with self.assertRaises(FileExistsError):
            write_crossblock_consequence_cnf(
                self.base_path,
                self.base_report_path,
                TEMPLATE,
                SEMANTIC_MAP,
                self.sources,
                self.augmented_path,
                output_blocks=self.outputs,
                counters=(1, 2),
                nonce=NONCE,
            )
        self.assertEqual(
            hashlib.sha256(self.augmented_path.read_bytes()).hexdigest(),
            original_digest,
        )
        with self.assertRaises(AppleView8Error, msg="destination collision"):
            write_crossblock_consequence_cnf(
                self.base_path,
                self.base_report_path,
                TEMPLATE,
                SEMANTIC_MAP,
                self.sources,
                self.base_path,
                output_blocks=self.outputs,
                counters=(1, 2),
                nonce=NONCE,
            )
        with self.assertRaises(AppleView8Error, msg="report collision"):
            write_crossblock_consequence_cnf(
                self.base_path,
                self.base_report_path,
                TEMPLATE,
                SEMANTIC_MAP,
                self.sources,
                self.work / "unused.cnf",
                output_blocks=self.outputs,
                counters=(1, 2),
                nonce=NONCE,
                report_path=self.base_path,
            )

        tampered = self.work / "tampered.cnf"
        shutil.copyfile(self.augmented_path, tampered)
        with tampered.open("r+b") as handle:
            handle.seek(-1, 2)
            handle.truncate()
        with self.assertRaises(AppleView8Error):
            verify_crossblock_consequence_cnf(
                tampered,
                self.base_path,
                self.base_report_path,
                TEMPLATE,
                SEMANTIC_MAP,
                self.sources,
                self.augmented_report_path,
                output_blocks=self.outputs,
                counters=(1, 2),
                nonce=NONCE,
            )

        forged = copy.deepcopy(self.augmented_report.describe())
        forged["instance_bytes"] = cast(int, forged["instance_bytes"]) + 1
        with self.assertRaises(AppleView8Error):
            verify_crossblock_consequence_cnf(
                self.augmented_path,
                self.base_path,
                self.base_report_path,
                TEMPLATE,
                SEMANTIC_MAP,
                self.sources,
                forged,
                output_blocks=self.outputs,
                counters=(1, 2),
                nonce=NONCE,
            )

    def test_o1c57_consumed_preflight_is_public_only_and_has_exact_counts(self) -> None:
        before = tuple(
            sorted(
                (path.relative_to(O1C57_CAPSULE).as_posix(), path.stat().st_size)
                for path in O1C57_CAPSULE.rglob("*")
                if path.is_file()
            )
        )
        preflight = preflight_o1c57_consumed_public_build(O1C57_CAPSULE)
        after = tuple(
            sorted(
                (path.relative_to(O1C57_CAPSULE).as_posix(), path.stat().st_size)
                for path in O1C57_CAPSULE.rglob("*")
                if path.is_file()
            )
        )
        self.assertEqual(before, after)
        self.assertTrue(preflight["ok"])
        self.assertEqual(preflight["block_count"], 8)
        self.assertEqual(preflight["planned_direct_unit_clause_count"], 2_048)
        self.assertEqual(preflight["planned_crossblock_relation_count"], 56)
        self.assertEqual(preflight["planned_constant_lsb_one_relation_count"], 24)
        self.assertEqual(preflight["planned_ripple_carry_variable_count"], 1_792)
        self.assertEqual(preflight["planned_ripple_clause_count"], 12_344)
        self.assertEqual(preflight["planned_augmentation_clause_count"], 14_392)
        self.assertEqual(preflight["planned_variable_count"], 257_024)
        self.assertEqual(preflight["planned_clause_count"], 1_518_472)
        self.assertEqual(
            preflight["final_wire_sha256"],
            "be7191a42edb348b961c380c9b1cd2372d1d9c3feecd571840ad23a6d58adfec",
        )
        self.assertEqual(
            preflight["planned_direct_unit_clause_sha256"],
            "0c95981455808a8a85325f54149902698ff4684723c7ce460c937ea227302c0b",
        )
        self.assertEqual(
            preflight["planned_ripple_clause_sha256"],
            "175b89272348045c4dded0bc656021bf22b4f28795a8a9ca025a0d9ff814e8a8",
        )
        self.assertEqual(
            preflight["planned_augmentation_sha256"],
            "82a102d5a2f6edae3d5d7b674e93e7c120e069f5f638491e1e206d8ae57c2f68",
        )
        self.assertFalse(preflight["fresh_target_generated"])
        self.assertFalse(preflight["truth_artifacts_read"])
        self.assertFalse(preflight["large_cnf_written"])
        self.assertEqual(preflight["solver_calls"], 0)


if __name__ == "__main__":
    unittest.main()
