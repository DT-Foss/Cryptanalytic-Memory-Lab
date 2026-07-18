from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

import pytest

from o1_crypto_lab.o1_factor_search import (
    build_native_factor_search,
    run_factor_search,
    write_factor_field,
)
from o1_crypto_lab.proof_clause_relations import (
    ClauseRelationEdge,
    ClauseRelationField,
)


ROOT = Path(__file__).resolve().parents[1]
NATIVE_SOURCE = ROOT / "native/cadical_o1_factor_search.cpp"
CADICAL_INCLUDE = Path("/opt/homebrew/opt/cadical/include")
CADICAL_LIBRARY = Path("/opt/homebrew/opt/cadical/lib/libcadical.a")


def _native_available() -> bool:
    return bool(
        shutil.which("c++")
        and (CADICAL_INCLUDE / "cadical.hpp").is_file()
        and CADICAL_LIBRARY.is_file()
    )


@pytest.mark.skipif(not _native_available(), reason="CaDiCaL development files absent")
def test_factor_propagator_uses_root_assignment_to_choose_neighbor(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "factor-search"
    build_native_factor_search(source=NATIVE_SOURCE, output=executable)
    cnf = tmp_path / "tiny.cnf"
    cnf.write_text("p cnf 256 1\n1 0\n", encoding="ascii")
    field = ClauseRelationField(
        conflict_horizon=16,
        selected_abs_units=3,
        capacity=8,
        source_sha256=hashlib.sha256(b"source").hexdigest(),
        edges=(ClauseRelationEdge(1, 2, 3),),
        metrics={"edge_count": 1},
    )
    factors = tmp_path / "factors.txt"
    write_factor_field(factors, field)
    result = run_factor_search(
        executable=executable,
        cnf_path=cnf,
        factors_path=factors,
        conflict_limit=32,
    )
    assert result.status_name == "SAT"
    assert result.key_model is not None
    assert result.key_model[0] & 0b11 == 0b11
    assert result.factor["requested_decisions"] >= 1
