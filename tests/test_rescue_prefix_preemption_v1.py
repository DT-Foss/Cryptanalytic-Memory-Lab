from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from o1_crypto_lab.rescue_prefix_preemption_v1 import (
    O1C78_PREFIX_LITERALS,
    O1C78_PREFIX_ORDER_SHA256,
    RescuePrefixPreemptionError,
    RescuePrefixPreemptionPlan,
    derive_rescue_prefix_preemption_plan,
    parse_rescue_prefix_preemption_plan,
    rescue_prefix_order_bytes,
    validate_o1c78_production_plan,
    write_rescue_prefix_preemption_plan,
)


def test_exact_o1c78_plan_is_raw_signed_i32le() -> None:
    plan = derive_rescue_prefix_preemption_plan(
        prefix_literals=O1C78_PREFIX_LITERALS
    )
    assert isinstance(plan, RescuePrefixPreemptionPlan)
    assert plan.serialized == rescue_prefix_order_bytes(O1C78_PREFIX_LITERALS)
    assert plan.serialized_bytes == 44
    assert plan.sha256 == O1C78_PREFIX_ORDER_SHA256
    assert plan.prefix_order_sha256 == O1C78_PREFIX_ORDER_SHA256
    assert parse_rescue_prefix_preemption_plan(plan.serialized) == plan
    validate_o1c78_production_plan(plan)


@pytest.mark.parametrize(
    "literals",
    [(), (0,), (-(1 << 31),), (7, -7), (True,)],
)
def test_plan_rejects_invalid_rows(literals: tuple[object, ...]) -> None:
    with pytest.raises(RescuePrefixPreemptionError):
        RescuePrefixPreemptionPlan(literals)  # type: ignore[arg-type]


def test_parser_rejects_non_i32_and_wrong_production_identity() -> None:
    with pytest.raises(RescuePrefixPreemptionError):
        parse_rescue_prefix_preemption_plan(b"\0")
    other = RescuePrefixPreemptionPlan((1, 2))
    with pytest.raises(RescuePrefixPreemptionError):
        validate_o1c78_production_plan(other)


def test_atomic_write_round_trip_and_symlink_rejection(tmp_path: Path) -> None:
    plan = RescuePrefixPreemptionPlan(O1C78_PREFIX_LITERALS)
    path = tmp_path / "prefix.plan"
    write_rescue_prefix_preemption_plan(path, plan)
    assert path.read_bytes() == plan.serialized

    link = tmp_path / "prefix.link"
    try:
        link.symlink_to(path)
    except OSError:
        pytest.skip("symlinks unavailable")
    from o1_crypto_lab.rescue_prefix_preemption_v1 import (
        read_rescue_prefix_preemption_plan,
    )

    with pytest.raises(RescuePrefixPreemptionError):
        read_rescue_prefix_preemption_plan(link)


def test_builder_validates_complete_source_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assignment = b"\0\0"
    source: dict[str, object] = {
        "sieve": {
            "trace_sha256": "cd" * 32,
            "state": {
                "schema": "o1-256-cadical-joint-score-sieve-grouped-state-v2",
                "encoding": "observed-ascending-i8-sign;fixture",
                "assignment_bytes": 2,
                "assignment_hex": assignment.hex(),
                "assignment_sha256": hashlib.sha256(assignment).hexdigest(),
                "current_assigned_variables": 0,
            }
        }
    }
    source_sha = hashlib.sha256(
        json.dumps(source, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    class _Vault:
        observed_variables = (1, 2)

    # The builder intentionally requires the concrete certified vault type.
    monkeypatch.setattr(
        "o1_crypto_lab.rescue_prefix_preemption_v1.ThresholdNoGoodVault",
        _Vault,
    )
    plan = derive_rescue_prefix_preemption_plan(
        source_result=source,
        source_result_sha256=source_sha,
        active_vault=_Vault(),  # type: ignore[arg-type]
        parent_staging_plan_sha256="ab" * 32,
        baseline_trace_sha256="cd" * 32,
        prefix_literals=(1, -2),
    )
    assert plan.prefix_literals == (1, -2)
