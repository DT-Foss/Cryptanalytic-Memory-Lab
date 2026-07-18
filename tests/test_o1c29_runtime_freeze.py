from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from o1_crypto_lab.o1c29_runtime_freeze import (
    O1C29RuntimeFreezeError,
    verify_o1c29_runtime_freeze_fresh,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs" / "o1c29_stacked_hot_calibration_v1.json"
PROBE = r"""
import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve(strict=True)
mode = sys.argv[2]
contract = json.loads(
    (root / "configs/o1c29_stacked_hot_calibration_v1.json").read_text()
)["runtime"]

import o1_crypto_lab.o1c29_stacked_hot_calibration_run  # noqa: E402
from o1_crypto_lab.o1c29_runtime_freeze import (  # noqa: E402
    verify_o1c29_runtime_freeze,
)

if mode == "extra-loaded":
    import o1_crypto_lab.adaptive_dc_spectral  # noqa: F401
elif mode == "missing-loaded":
    sys.modules.pop("o1_crypto_lab.events")
elif mode == "hash-tamper":
    closure = contract["application_closure"]
    closure["modules"]["o1_crypto_lab.isolation"]["sha256"] = "0" * 64
    commitment = {
        "package": closure["package"],
        "module_count": closure["module_count"],
        "modules": closure["modules"],
    }
    encoded = json.dumps(
        commitment,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    closure["closure_sha256"] = hashlib.sha256(encoded).hexdigest()
elif mode == "python-mismatch":
    contract["python"]["version"] = [3, 13, 2]
elif mode == "numpy-version-mismatch":
    contract["numpy"]["version"] = "2.2.5"
elif mode == "numpy-abi-mismatch":
    contract["numpy"]["ndarray_c_version"] += 1
elif mode == "numpy-build-mismatch":
    contract["numpy"]["build_fingerprint_sha256"] = "0" * 64

try:
    receipt = verify_o1c29_runtime_freeze(contract, root=root)
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
    raise SystemExit(23)
print(json.dumps(receipt.receipt_document(), sort_keys=True))
"""


def _probe(mode: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        (sys.executable, "-c", PROBE, str(ROOT), mode),
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "src")},
        check=False,
        capture_output=True,
        text=True,
    )


def test_fresh_formal_process_accepts_exact_25_plus_verifier_runtime() -> None:
    completed = _probe("valid")
    assert completed.returncode == 0, completed.stdout + completed.stderr
    receipt = json.loads(completed.stdout)
    assert receipt["application_module_count"] == 25
    assert receipt["loaded_local_module_count"] == 26
    assert receipt["python"]["implementation"] == "CPython"
    assert receipt["python"]["version"] == [3, 13, 1]
    assert receipt["numpy"]["version"] == "2.2.6"
    assert receipt["numpy"]["ndarray_c_version"] == 33_554_432
    assert len(receipt["receipt_sha256"]) == 64


@pytest.mark.parametrize(
    "mode",
    [
        "extra-loaded",
        "missing-loaded",
        "hash-tamper",
        "python-mismatch",
        "numpy-version-mismatch",
        "numpy-abi-mismatch",
        "numpy-build-mismatch",
    ],
)
def test_runtime_freeze_rejects_inventory_source_and_runtime_drift(mode: str) -> None:
    completed = _probe(mode)
    assert completed.returncode == 23, completed.stdout + completed.stderr
    assert "O1C29RuntimeFreezeError" in completed.stdout


def test_config_pins_complete_named_application_closure() -> None:
    runtime = json.loads(CONFIG.read_text())["runtime"]
    closure = runtime["application_closure"]
    modules = closure["modules"]
    assert closure["module_count"] == len(modules) == 25
    assert "o1_crypto_lab" in modules
    assert "o1_crypto_lab.isolation" in modules
    assert "o1_crypto_lab.o1c29_stacked_hot_calibration_run" in modules
    assert "o1_crypto_lab.o1c29_runtime_freeze" not in modules
    assert runtime["verifier"]["module"] == "o1_crypto_lab.o1c29_runtime_freeze"
    assert all(entry["path"].endswith(".py") for entry in modules.values())


def test_fresh_api_is_independent_of_parent_process_import_pollution() -> None:
    import o1_crypto_lab.adaptive_dc_spectral  # noqa: F401

    runtime = json.loads(CONFIG.read_text())["runtime"]
    receipt = verify_o1c29_runtime_freeze_fresh(runtime, root=ROOT)
    assert len(receipt.loaded_module_names) == 26
    assert "o1_crypto_lab.adaptive_dc_spectral" not in receipt.loaded_module_names


def test_fresh_api_propagates_strict_child_rejection() -> None:
    runtime = json.loads(CONFIG.read_text())["runtime"]
    runtime["numpy"]["core_extension_sha256"] = "0" * 64
    with pytest.raises(O1C29RuntimeFreezeError, match="fresh runtime probe rejected"):
        verify_o1c29_runtime_freeze_fresh(runtime, root=ROOT)
