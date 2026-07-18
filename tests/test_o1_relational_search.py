from __future__ import annotations

import shutil
from pathlib import Path

import numpy as np
import pytest

from o1_crypto_lab.o1_relational_search import (
    O1RelationalSearchError,
    build_native_guided_search,
    repair_radius_scores,
    run_guided_search,
    write_hint_scores,
)


ROOT = Path(__file__).resolve().parents[1]
NATIVE_SOURCE = ROOT / "native/cadical_o1_guided_search.cpp"
CADICAL_INCLUDE = Path("/opt/homebrew/opt/cadical/include")
CADICAL_LIBRARY = Path("/opt/homebrew/opt/cadical/lib/libcadical.a")


def _native_available() -> bool:
    return bool(
        shutil.which("c++")
        and (CADICAL_INCLUDE / "cadical.hpp").is_file()
        and CADICAL_LIBRARY.is_file()
    )


def test_repair_radius_flips_exactly_the_weakest_truth_phases() -> None:
    scores = np.linspace(-2.0, 2.0, 256, dtype=np.float64)
    truth = np.arange(256) & 1
    repaired = repair_radius_scores(scores, truth, wrong_count=17)
    predicted = repaired >= 0.0
    assert int(np.count_nonzero(predicted != truth)) == 17
    weakest = set(np.argsort(np.abs(scores), kind="stable")[:17].tolist())
    wrong = set(np.flatnonzero(predicted != truth).tolist())
    assert wrong == weakest
    assert np.array_equal(np.abs(repaired), np.maximum(np.abs(scores), 2.0**-40))


def test_hint_writer_rejects_nonfinite_or_wrong_width(tmp_path: Path) -> None:
    with pytest.raises(O1RelationalSearchError):
        write_hint_scores(tmp_path / "bad", np.zeros(255))
    bad = np.zeros(256)
    bad[4] = np.nan
    with pytest.raises(O1RelationalSearchError):
        write_hint_scores(tmp_path / "bad", bad)


@pytest.mark.skipif(not _native_available(), reason="CaDiCaL development files absent")
def test_native_guided_search_repairs_a_wrong_soft_decision(tmp_path: Path) -> None:
    executable = tmp_path / "cadical-o1-guided-search"
    build_native_guided_search(source=NATIVE_SOURCE, output=executable)
    # The three clauses have the unique two-bit model x1=x2=true.  Remaining
    # key variables are unconstrained but still exercise the observed decision API.
    cnf = tmp_path / "tiny.cnf"
    cnf.write_text("p cnf 256 3\n1 2 0\n-1 2 0\n1 -2 0\n", encoding="ascii")
    scores = np.full(256, 0.01, dtype=np.float64)
    scores[0] = -2.0
    scores[1] = -1.0
    hints = tmp_path / "hints.txt"
    write_hint_scores(hints, scores)
    result = run_guided_search(
        executable=executable,
        cnf_path=cnf,
        mode="guided",
        conflict_limit=128,
        guided_bits=256,
        hint_path=hints,
    )
    assert result.status_name == "SAT"
    assert result.key_model is not None
    assert result.key_model[0] & 0b11 == 0b11
    assert result.guided["requested_decisions"] > 0


@pytest.mark.skipif(not _native_available(), reason="CaDiCaL development files absent")
def test_internal_mode_needs_no_hint_file(tmp_path: Path) -> None:
    executable = tmp_path / "cadical-o1-guided-search"
    build_native_guided_search(source=NATIVE_SOURCE, output=executable)
    cnf = tmp_path / "tiny.cnf"
    cnf.write_text("p cnf 256 1\n1 0\n", encoding="ascii")
    result = run_guided_search(
        executable=executable,
        cnf_path=cnf,
        mode="internal",
        conflict_limit=32,
    )
    assert result.status_name == "SAT"
    assert result.key_model is not None
    assert result.key_model[0] & 1
    assert result.guided["requested_decisions"] == 0
