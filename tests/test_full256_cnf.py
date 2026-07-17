from __future__ import annotations

import itertools
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from o1_crypto_lab.chacha_trace import chacha20_block
from o1_crypto_lab.full256_cnf import (
    COUNTER_FIRST_VARIABLE,
    INTERNAL_FIRST_VARIABLE,
    KEY_FIRST_VARIABLE,
    NONCE_FIRST_VARIABLE,
    OUTPUT_FIRST_VARIABLE,
    PUBLIC_UNIT_CLAUSES,
    CNFBuilder,
    ClauseCollector,
    Full256CNFError,
    clauses_satisfied,
    load_full256_template_map,
    run_cadical,
    verify_full256_instance,
    verify_full256_template,
    write_full256_instance,
    write_full256_template,
)
from o1_crypto_lab.living_inverse import canonical_json_bytes, canonical_sha256


class GateEncodingTests(unittest.TestCase):
    def test_xor2_and_xor3_are_exact_for_every_assignment(self) -> None:
        for inputs, output in (((1, 2), 3), ((1, 2, 3), 4)):
            sink = ClauseCollector()
            builder = CNFBuilder(sink, first_internal_variable=output + 1)
            self.assertEqual(builder.xor_many(inputs, output=output), output)
            for values in itertools.product((False, True), repeat=output):
                assignment = {
                    variable: values[variable - 1]
                    for variable in range(1, output + 1)
                }
                expected = assignment[output] == (
                    sum(assignment[variable] for variable in inputs) & 1
                )
                self.assertEqual(
                    clauses_satisfied(sink.clauses, assignment),
                    expected,
                    (inputs, assignment, sink.clauses),
                )
        self.assertEqual(len(ClauseCollector().clauses), 0)

    def test_majority_is_exact_for_every_assignment(self) -> None:
        sink = ClauseCollector()
        builder = CNFBuilder(sink, first_internal_variable=5)
        self.assertEqual(builder.majority3(1, 2, 3, output=4), 4)
        self.assertEqual(sink.clause_count, 6)
        for values in itertools.product((False, True), repeat=4):
            assignment = {index + 1: value for index, value in enumerate(values)}
            expected = assignment[4] == (sum(values[:3]) >= 2)
            self.assertEqual(
                clauses_satisfied(sink.clauses, assignment),
                expected,
                (assignment, sink.clauses),
            )

    def test_signed_literal_folding_and_explicit_carry_outputs(self) -> None:
        sink = ClauseCollector()
        builder = CNFBuilder(sink, first_internal_variable=3)
        builder.xor_many((1, -1), output=2)
        self.assertEqual(sink.clauses, [(2,)])
        for first, second in itertools.product((False, True), repeat=2):
            self.assertEqual(
                clauses_satisfied(sink.clauses, {1: first, 2: second}), second
            )


class Full256TemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls._temporary.name)
        cls.template = cls.root / "full256.cnf"
        cls.map_path = cls.root / "full256.map.json"
        cls.report = write_full256_template(cls.template, cls.map_path)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temporary.cleanup()

    def test_exact_topology_interface_and_semantic_ranges(self) -> None:
        document = load_full256_template_map(self.map_path)
        self.assertEqual(self.report.variable_count, 32_128)
        self.assertEqual(self.report.clause_count, 187_370)
        self.assertEqual(self.report.operation_count, 656)
        self.assertEqual(
            document["clause_length_histogram"],
            {"1": 6, "2": 1172, "3": 104_848, "4": 81_344},
        )
        interface = document["interface"]
        self.assertEqual(interface["key"]["first_variable"], KEY_FIRST_VARIABLE)
        self.assertEqual(interface["counter"]["first_variable"], COUNTER_FIRST_VARIABLE)
        self.assertEqual(interface["nonce"]["first_variable"], NONCE_FIRST_VARIABLE)
        self.assertEqual(interface["output"]["first_variable"], OUTPUT_FIRST_VARIABLE)
        self.assertIs(interface["key"]["attacker_known"], False)
        self.assertIs(document["target_key_included"], False)
        operations = document["operations"]
        self.assertEqual(sum(row["kind"] == "add32" for row in operations), 336)
        self.assertEqual(sum(row["kind"] == "xor32" for row in operations), 320)
        self.assertEqual(operations[0]["first_internal_variable"], INTERNAL_FIRST_VARIABLE)
        self.assertEqual(operations[-1]["last_internal_variable"], 32_128)
        self.assertEqual(operations[0]["first_clause"], 1)
        self.assertEqual(operations[-1]["last_clause"], 187_370)
        self.assertTrue(all(len(row["bit_ranges"]) == 32 for row in operations))
        self.assertEqual(
            operations[0]["wire_layout"], "lsb32-interleaved-sum-carry"
        )
        self.assertEqual(
            operations[0]["bit_ranges"][0],
            {
                "bit": 0,
                "sum_variable": 897,
                "sum_variable_role": "internal",
                "carry_variable": 898,
                "first_internal_variable": 897,
                "last_internal_variable": 898,
                "first_clause": 1,
                "last_clause": 4,
            },
        )
        self.assertEqual(
            operations[-1]["bit_ranges"][-1]["sum_variable"], 896
        )
        self.assertEqual(
            operations[-1]["bit_ranges"][-1]["carry_variable"], 32_128
        )
        for previous, current in zip(operations, operations[1:], strict=False):
            self.assertEqual(
                previous["last_internal_variable"] + 1,
                current["first_internal_variable"],
            )
            self.assertEqual(previous["last_clause"] + 1, current["first_clause"])
        for operation in operations:
            for previous, current in zip(
                operation["bit_ranges"], operation["bit_ranges"][1:], strict=False
            ):
                self.assertEqual(previous["last_clause"] + 1, current["first_clause"])

    def test_template_verifies_and_double_compile_is_byte_identical(self) -> None:
        verification = verify_full256_template(self.template, self.map_path)
        self.assertTrue(verification["ok"])
        second_root = self.root / "second"
        second_template = second_root / "full256.cnf"
        second_map = second_root / "full256.map.json"
        second = write_full256_template(second_template, second_map)
        self.assertEqual(self.template.read_bytes(), second_template.read_bytes())
        self.assertEqual(self.map_path.read_bytes(), second_map.read_bytes())
        self.assertEqual(self.report.dimacs_sha256, second.dimacs_sha256)
        self.assertEqual(self.report.map_sha256, second.map_sha256)
        original_template = second_template.read_bytes()
        original_map = second_map.read_bytes()
        with self.assertRaises(FileExistsError):
            write_full256_template(second_template, second_map)
        self.assertEqual(second_template.read_bytes(), original_template)
        self.assertEqual(second_map.read_bytes(), original_map)

    def test_tampered_map_and_dimacs_are_rejected(self) -> None:
        corrupt_map = self.root / "corrupt.map.json"
        corrupt_map.write_bytes(self.map_path.read_bytes().replace(b"ChaCha20", b"ChaCha21"))
        with self.assertRaises(Full256CNFError):
            load_full256_template_map(corrupt_map)

        forged = json.loads(self.map_path.read_text(encoding="ascii"))
        forged["cipher"]["rounds"] = 12
        unsigned = {key: value for key, value in forged.items() if key != "map_sha256"}
        forged["map_sha256"] = canonical_sha256(unsigned)
        forged_map = self.root / "forged-rehashed.map.json"
        forged_map.write_bytes(canonical_json_bytes(forged) + b"\n")
        with self.assertRaisesRegex(Full256CNFError, "cipher contract"):
            load_full256_template_map(forged_map)

        corrupt_cnf = self.root / "corrupt.cnf"
        raw = bytearray(self.template.read_bytes())
        raw[-3] = ord("9") if raw[-3] != ord("9") else ord("8")
        corrupt_cnf.write_bytes(raw)
        with self.assertRaises(Full256CNFError):
            verify_full256_template(corrupt_cnf, self.map_path)

    def test_public_instance_has_only_public_units_and_one_optional_assumption(self) -> None:
        key = bytes(range(32))
        nonce = bytes.fromhex("000000090000004a00000000")
        output = chacha20_block(key, 1, nonce)
        public_path = self.root / "public.cnf"
        report = write_full256_instance(
            self.template,
            self.map_path,
            public_path,
            counter=1,
            nonce=nonce,
            output=output,
        )
        self.assertEqual(report.public_unit_clause_count, PUBLIC_UNIT_CLAUSES)
        self.assertEqual(report.clause_count, 187_370 + PUBLIC_UNIT_CLAUSES)
        self.assertFalse(report.key_fixed_for_self_test)
        self.assertEqual(report.key_unit_clause_count, 0)
        self.assertTrue(
            verify_full256_instance(
                public_path, self.template, self.map_path, report
            )["ok"]
        )
        tail = public_path.read_text(encoding="ascii").splitlines()[-PUBLIC_UNIT_CLAUSES:]
        self.assertTrue(all(abs(int(row.split()[0])) > 256 for row in tail))

        duplicate_path = self.root / "public-duplicate.cnf"
        duplicate = write_full256_instance(
            self.template,
            self.map_path,
            duplicate_path,
            counter=1,
            nonce=nonce,
            output=output,
        )
        self.assertEqual(public_path.read_bytes(), duplicate_path.read_bytes())
        self.assertEqual(report.instance_sha256, duplicate.instance_sha256)

        assumed_path = self.root / "assumed.cnf"
        assumed = write_full256_instance(
            self.template,
            self.map_path,
            assumed_path,
            counter=1,
            nonce=nonce,
            output=output,
            assumptions=((173, 1),),
        )
        self.assertEqual(assumed.assumption_unit_clause_count, 1)
        self.assertEqual(assumed.clause_count, report.clause_count + 1)
        self.assertEqual(assumed_path.read_text(encoding="ascii").splitlines()[-1], "174 0")
        self.assertTrue(
            verify_full256_instance(
                assumed_path, self.template, self.map_path, assumed
            )["ok"]
        )
        tampered_report = assumed.describe()
        tampered_report["assumptions"][0]["value"] = 0
        with self.assertRaisesRegex(Full256CNFError, "assumption literals"):
            verify_full256_instance(
                assumed_path, self.template, self.map_path, tampered_report
            )

    @unittest.skipUnless(shutil.which("cadical"), "CaDiCaL is not installed")
    def test_rfc_vector_is_sat_and_one_flipped_output_bit_is_unsat(self) -> None:
        key = bytes(range(32))
        nonce = bytes.fromhex("000000090000004a00000000")
        output = chacha20_block(key, 1, nonce)
        correct_path = self.root / "rfc-fixed-sat.cnf"
        write_full256_instance(
            self.template,
            self.map_path,
            correct_path,
            counter=1,
            nonce=nonce,
            output=output,
            key_for_self_test=key,
        )
        sat = run_cadical(correct_path, timeout_seconds=30.0)
        self.assertEqual((sat.status, sat.returncode), ("SAT", 10), sat)

        flipped = bytes((output[0] ^ 1,)) + output[1:]
        flipped_path = self.root / "rfc-fixed-unsat.cnf"
        write_full256_instance(
            self.template,
            self.map_path,
            flipped_path,
            counter=1,
            nonce=nonce,
            output=flipped,
            key_for_self_test=key,
        )
        unsat = run_cadical(flipped_path, timeout_seconds=30.0)
        self.assertEqual((unsat.status, unsat.returncode), ("UNSAT", 20), unsat)

    @unittest.skipUnless(shutil.which("cadical"), "CaDiCaL is not installed")
    def test_second_deterministic_full256_vector_is_sat(self) -> None:
        key = bytes((73 * index + 19) & 0xFF for index in range(32))
        nonce = bytes((29 * index + 5) & 0xFF for index in range(12))
        counter = 0xF1234567
        output = chacha20_block(key, counter, nonce)
        instance = self.root / "second-fixed-sat.cnf"
        write_full256_instance(
            self.template,
            self.map_path,
            instance,
            counter=counter,
            nonce=nonce,
            output=output,
            key_for_self_test=key,
        )
        sat = run_cadical(instance, timeout_seconds=30.0)
        self.assertEqual((sat.status, sat.returncode), ("SAT", 10), sat)

    def test_solver_timeout_bytes_are_normalized_to_text(self) -> None:
        expired = subprocess.TimeoutExpired(
            cmd=["cadical"], timeout=0.01, output=b"partial\xff", stderr=b"late\xfe"
        )
        with patch("o1_crypto_lab.full256_cnf.subprocess.run", side_effect=expired):
            report = run_cadical(
                self.template, executable="/synthetic/cadical", timeout_seconds=0.01
            )
        self.assertEqual(report.status, "TIMEOUT")
        self.assertIsInstance(report.stdout, str)
        self.assertIsInstance(report.stderr, str)
        self.assertIn("partial", report.stdout)


if __name__ == "__main__":
    unittest.main()
