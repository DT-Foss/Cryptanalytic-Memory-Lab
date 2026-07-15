"""Finite typed operator composition with a monotone anti-leakage policy."""

from __future__ import annotations

import heapq
import itertools
from dataclasses import dataclass, field
from typing import FrozenSet, Iterable, Sequence

from .types import DataKind, FlowState, InformationLabel, TARGET_BLIND_FORBIDDEN


class FlowViolation(ValueError):
    """Raised when an operator violates type or information-flow constraints."""


@dataclass(frozen=True)
class Operator:
    """A deterministic unary operator signature.

    Labels are monotone: an operator may add provenance but cannot erase it. This
    prevents a cosmetic conversion from laundering post-reveal information back
    into a target-blind score or order.
    """

    name: str
    input_kind: DataKind
    output_kind: DataKind
    adds_labels: FrozenSet[InformationLabel] = field(default_factory=frozenset)
    requires_labels: FrozenSet[InformationLabel] = field(default_factory=frozenset)
    forbids_labels: FrozenSet[InformationLabel] = field(default_factory=frozenset)
    work_units: int = 1

    def apply(self, state: FlowState) -> FlowState:
        if state.kind is not self.input_kind:
            raise FlowViolation(
                f"{self.name} expects {self.input_kind.value}, got {state.kind.value}"
            )
        missing = self.requires_labels - state.labels
        if missing:
            names = ", ".join(sorted(item.value for item in missing))
            raise FlowViolation(f"{self.name} is missing required labels: {names}")
        forbidden = self.forbids_labels & state.labels
        if forbidden:
            names = ", ".join(sorted(item.value for item in forbidden))
            raise FlowViolation(f"{self.name} rejects labels: {names}")
        labels = frozenset(state.labels | self.adds_labels)
        if (
            self.output_kind is DataKind.TARGET_BLIND_ORDER
            and labels & TARGET_BLIND_FORBIDDEN
        ):
            names = ", ".join(
                sorted(item.value for item in labels & TARGET_BLIND_FORBIDDEN)
            )
            raise FlowViolation(
                f"{self.name} cannot emit TARGET_BLIND_ORDER with labels: {names}"
            )
        result = FlowState(
            kind=self.output_kind,
            labels=labels,
            history=state.history + (self.name,),
        )
        return result


@dataclass(frozen=True)
class Chain:
    operators: tuple[Operator, ...]
    final_state: FlowState

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(operator.name for operator in self.operators)

    @property
    def work_units(self) -> int:
        return sum(operator.work_units for operator in self.operators)

    def describe(self) -> dict[str, object]:
        return {
            "operators": list(self.names),
            "work_units": self.work_units,
            "final": self.final_state.describe(),
        }


class OperatorRegistry:
    def __init__(self, operators: Iterable[Operator] = ()) -> None:
        self._operators: dict[str, Operator] = {}
        for operator in operators:
            self.register(operator)

    def register(self, operator: Operator) -> None:
        if not isinstance(operator.name, str) or not operator.name:
            raise ValueError("operator name is required")
        if operator.name in self._operators:
            raise ValueError(f"duplicate operator: {operator.name}")
        if (
            not isinstance(operator.work_units, int)
            or isinstance(operator.work_units, bool)
            or operator.work_units < 0
        ):
            raise ValueError("operator work_units must be a non-negative integer")
        self._operators[operator.name] = operator

    def from_kind(self, kind: DataKind) -> tuple[Operator, ...]:
        return tuple(
            sorted(
                (op for op in self._operators.values() if op.input_kind is kind),
                key=lambda op: (op.work_units, op.name),
            )
        )

    def __iter__(self):
        return iter(self._operators.values())


class ChainComposer:
    """Enumerate legal chains in a finite operator registry."""

    def __init__(self, registry: OperatorRegistry) -> None:
        self.registry = registry

    def find_chains(
        self,
        source: FlowState,
        target_kind: DataKind,
        *,
        max_depth: int = 9,
        limit: int = 8,
        require_target_blind: bool | None = None,
    ) -> list[Chain]:
        if max_depth < 0 or limit < 1:
            raise ValueError(
                "max_depth must be non-negative and limit must be positive"
            )
        if require_target_blind is None:
            require_target_blind = target_kind is DataKind.TARGET_BLIND_ORDER

        sequence = itertools.count()
        queue: list[
            tuple[int, int, tuple[str, ...], int, FlowState, tuple[Operator, ...]]
        ] = []
        heapq.heappush(queue, (0, 0, (), next(sequence), source, ()))
        found: list[Chain] = []
        best_cost: dict[
            tuple[DataKind, FrozenSet[InformationLabel], tuple[str, ...]], int
        ] = {(source.kind, source.labels, source.history): 0}

        while queue and len(found) < limit:
            cost, _depth, _names, _serial, state, path = heapq.heappop(queue)
            if state.kind is target_kind and (
                not require_target_blind or state.target_blind
            ):
                found.append(Chain(path, state))
                continue
            if len(path) >= max_depth:
                continue

            for operator in self.registry.from_kind(state.kind):
                if operator.name in state.history:
                    continue
                try:
                    next_state = operator.apply(state)
                except FlowViolation:
                    continue
                depth = len(path) + 1
                next_path = path + (operator,)
                next_cost = cost + operator.work_units
                full_key = (next_state.kind, next_state.labels, next_state.history)
                previous = best_cost.get(full_key)
                if previous is not None and previous <= next_cost:
                    continue
                best_cost[full_key] = next_cost
                names = tuple(item.name for item in next_path)
                heapq.heappush(
                    queue,
                    (next_cost, depth, names, next(sequence), next_state, next_path),
                )

        return sorted(found, key=lambda chain: (chain.work_units, chain.names))

    @staticmethod
    def replay(source: FlowState, operators: Sequence[Operator]) -> FlowState:
        state = source
        for operator in operators:
            state = operator.apply(state)
        return state


def default_registry() -> OperatorRegistry:
    """The minimal scientific chain proposed for the integration lab."""

    public = InformationLabel.PUBLIC
    candidate = InformationLabel.CANDIDATE_ASSUMPTION
    post_reveal = frozenset(
        {InformationLabel.POST_REVEAL, InformationLabel.TARGET_SECRET}
    )
    blind_forbidden = TARGET_BLIND_FORBIDDEN

    return OperatorRegistry(
        [
            Operator(
                "align_public_blocks",
                DataKind.PUBLIC_RELATIONS,
                DataKind.ALIGNED_PUBLIC,
                requires_labels=frozenset({public}),
            ),
            Operator(
                "build_control_corrected_field",
                DataKind.ALIGNED_PUBLIC,
                DataKind.PUBLIC_FIELD,
                adds_labels=frozenset({InformationLabel.CONTROL}),
            ),
            Operator(
                "project_solver_trajectory",
                DataKind.PUBLIC_FIELD,
                DataKind.CANDIDATE_TRACE,
                adds_labels=frozenset({candidate}),
                work_units=4,
            ),
            Operator(
                "o1_stream_accumulate",
                DataKind.CANDIDATE_TRACE,
                DataKind.EVIDENCE_STATE,
            ),
            Operator(
                "calibrate_against_matched_null",
                DataKind.EVIDENCE_STATE,
                DataKind.SCORE,
                requires_labels=frozenset({InformationLabel.CONTROL}),
            ),
            Operator(
                "freeze_target_blind_order",
                DataKind.SCORE,
                DataKind.TARGET_BLIND_ORDER,
                forbids_labels=blind_forbidden,
            ),
            Operator(
                "execute_frozen_order",
                DataKind.TARGET_BLIND_ORDER,
                DataKind.MODEL,
                adds_labels=frozenset({candidate}),
                work_units=20,
            ),
            Operator(
                "exact_cipher_confirm",
                DataKind.MODEL,
                DataKind.CONFIRMED,
                adds_labels=post_reveal,
                work_units=2,
            ),
            Operator(
                "post_reveal_rank",
                DataKind.CONFIRMED,
                DataKind.TARGET_BLIND_ORDER,
                adds_labels=frozenset({InformationLabel.POST_REVEAL}),
            ),
        ]
    )
