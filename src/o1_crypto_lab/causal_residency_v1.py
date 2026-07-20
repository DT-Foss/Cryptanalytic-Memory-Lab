"""Deterministic target-free residency over an immutable causal attic.

The causal attic is the evidence store; a residency page is only a bounded
solver input.  This module never removes or rewrites attic evidence.  It keeps
an activation history, gives inherited debt priority over recycled clauses,
and rejects a page byte identity that has already been used as a science
input.

The first page has one attempt-specific exception: the inherited causal core
is pinned for the lifetime of the attempt.  Later pages retain that core,
serve the still-unseen inherited population, admit globally new debt, give the
newest fully emitted events bounded hot attention, and finally recycle by the
least-used/oldest policy.  Clauses are always serialized in attic-union order,
not priority order.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Mapping, Sequence, cast

from .causal_attic_v1 import (
    CausalAttic,
    CausalAtticError,
    ClauseOccurrence,
    canonical_json_bytes,
    reproject_causal_attic,
    sha256_bytes,
)
from .threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodVault,
    ThresholdNoGoodVaultError,
    validate_threshold_no_good_vault_caps,
)


CAUSAL_RESIDENCY_SCHEMA = "o1-score-threshold-causal-residency-v1"
RESIDENCY_PROJECTION_SCHEMA = "o1-score-threshold-residency-projection-v1"
ACTIVATION_LEDGER_SCHEMA = "o1-score-threshold-residency-activation-ledger-v1"
RESIDENCY_SELECTION_RULE = (
    "immutable-attic-union;attempt-pinned-causal-core;"
    "inherited-never-resident-debt-first;new-never-resident-debt-second;"
    "newest-fully-emitted-hot-third;remaining-by-activation-count-asc,"
    "oldest-last-active-lineage-asc,occurrence-count-desc,literal-count-asc,"
    "clause-sha256-asc,union-index-asc;deduplicate-priority-order;"
    "serialize-union-order;reject-used-active-sha256"
)

_ROLES = {"inherited-parent-final", "causal-residency-page"}
_CATEGORY_ORDER = (
    "structural_root",
    "pinned_core",
    "inherited_debt",
    "new_debt",
    "hot_event",
    "recycled",
)


class CausalResidencyError(ValueError):
    """An attic extension, page, or activation-replay invariant differs."""


def _nonnegative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CausalResidencyError(f"causal-residency {field} differs")
    return value


def _positive_int(value: object, field: str) -> int:
    normalized = _nonnegative_int(value, field)
    if normalized == 0:
        raise CausalResidencyError(f"causal-residency {field} differs")
    return normalized


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise CausalResidencyError(f"causal-residency {field} differs")
    return value


def _indices(
    values: Sequence[int], *, clause_count: int, field: str, unique: bool = True
) -> tuple[int, ...]:
    if isinstance(values, (str, bytes, bytearray)):
        raise CausalResidencyError(f"causal-residency {field} differs")
    normalized = tuple(values)
    if any(
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value < clause_count
        for value in normalized
    ):
        raise CausalResidencyError(f"causal-residency {field} differs")
    if unique and len(set(normalized)) != len(normalized):
        raise CausalResidencyError(f"causal-residency {field} is not unique")
    return normalized


def _structural_roots(attic: CausalAttic) -> tuple[int, ...]:
    """Return undominated clauses that strictly subsume at least one clause."""

    subsumers = {relation.subsumer_index for relation in attic.relations}
    subsumed = {relation.subsumed_index for relation in attic.relations}
    return tuple(sorted(subsumers - subsumed))


def _occurrence_counts(attic: CausalAttic) -> Counter[int]:
    return Counter(attic.occurrence_union_indices)


def _debt_key(attic: CausalAttic, counts: Mapping[int, int], index: int) -> tuple:
    clause = attic.union_vault.clauses[index]
    return (-counts.get(index, 0), clause.literal_count, clause.sha256, index)


def _recycle_key(
    attic: CausalAttic,
    counts: Mapping[int, int],
    activation_counts: Sequence[int],
    last_active_lineages: Sequence[int | None],
    index: int,
) -> tuple:
    clause = attic.union_vault.clauses[index]
    last = last_active_lineages[index]
    if last is None:
        raise CausalResidencyError("causal-residency recycled lineage differs")
    return (
        activation_counts[index],
        last,
        -counts.get(index, 0),
        clause.literal_count,
        clause.sha256,
        index,
    )


def _selected_vault(
    attic: CausalAttic, selected_union_indices: Sequence[int]
) -> ThresholdNoGoodVault:
    selected = tuple(sorted(selected_union_indices))
    try:
        vault = ThresholdNoGoodVault(
            attic.union_vault.identity,
            attic.union_vault.observed_variables,
            tuple(attic.union_vault.clauses[index] for index in selected),
        )
        return validate_threshold_no_good_vault_caps(vault, caps=O1C66_VAULT_CAPS)
    except (ThresholdNoGoodVaultError, IndexError) as exc:
        raise CausalResidencyError(
            "causal-residency active projection differs"
        ) from exc


def _index_digest(indices: Sequence[int]) -> str:
    return sha256_bytes(canonical_json_bytes(list(indices)))


@dataclass(frozen=True)
class ActivationLedgerEntry:
    """One replayable active-vault identity and its union-index population."""

    lineage_ordinal: int
    role: str
    active_sha256: str
    selected_union_indices: tuple[int, ...]

    def __post_init__(self) -> None:
        _nonnegative_int(self.lineage_ordinal, "activation lineage ordinal")
        if self.role not in _ROLES:
            raise CausalResidencyError("causal-residency activation role differs")
        _sha256(self.active_sha256, "activation SHA-256")
        if (
            not isinstance(self.selected_union_indices, tuple)
            or tuple(sorted(set(self.selected_union_indices)))
            != self.selected_union_indices
        ):
            raise CausalResidencyError(
                "causal-residency activation indices differ"
            )

    def describe(self) -> dict[str, object]:
        return {
            "lineage_ordinal": self.lineage_ordinal,
            "role": self.role,
            "active_sha256": self.active_sha256,
            "selected_clause_count": len(self.selected_union_indices),
            "selected_union_indices_sha256": _index_digest(
                self.selected_union_indices
            ),
            "selected_union_indices": list(self.selected_union_indices),
        }


@dataclass(frozen=True)
class ResidencyProjection:
    """One bounded page, with priority categories kept separate from encoding."""

    lineage_ordinal: int
    vault: ThresholdNoGoodVault
    selected_union_indices: tuple[int, ...]
    selection_order: tuple[int, ...]
    structural_root_indices: tuple[int, ...]
    pinned_core_indices: tuple[int, ...]
    inherited_debt_indices: tuple[int, ...]
    new_debt_indices: tuple[int, ...]
    hot_event_indices: tuple[int, ...]
    recycled_indices: tuple[int, ...]

    def __post_init__(self) -> None:
        _nonnegative_int(self.lineage_ordinal, "projection lineage ordinal")
        if not isinstance(self.vault, ThresholdNoGoodVault):
            raise CausalResidencyError("causal-residency projection vault differs")
        if tuple(sorted(set(self.selected_union_indices))) != (
            self.selected_union_indices
        ):
            raise CausalResidencyError(
                "causal-residency selected union indices differ"
            )
        if len(set(self.selection_order)) != len(self.selection_order) or set(
            self.selection_order
        ) != set(self.selected_union_indices):
            raise CausalResidencyError(
                "causal-residency projection selection order differs"
            )
        categories = (
            self.structural_root_indices,
            self.pinned_core_indices,
            self.inherited_debt_indices,
            self.new_debt_indices,
            self.hot_event_indices,
            self.recycled_indices,
        )
        flattened = tuple(index for category in categories for index in category)
        if flattened != self.selection_order:
            raise CausalResidencyError(
                "causal-residency projection categories differ"
            )

    @property
    def category_counts(self) -> dict[str, int]:
        return {
            name: len(indices)
            for name, indices in zip(
                _CATEGORY_ORDER,
                (
                    self.structural_root_indices,
                    self.pinned_core_indices,
                    self.inherited_debt_indices,
                    self.new_debt_indices,
                    self.hot_event_indices,
                    self.recycled_indices,
                ),
                strict=True,
            )
        }

    def describe(self) -> dict[str, object]:
        return {
            "schema": RESIDENCY_PROJECTION_SCHEMA,
            "lineage_ordinal": self.lineage_ordinal,
            "selection_rule": RESIDENCY_SELECTION_RULE,
            "encoding_only": self.vault.describe(),
            "selected_union_indices": list(self.selected_union_indices),
            "selection_order": list(self.selection_order),
            "selection_order_sha256": _index_digest(self.selection_order),
            "category_counts": self.category_counts,
            "categories": {
                "structural_root": list(self.structural_root_indices),
                "pinned_core": list(self.pinned_core_indices),
                "inherited_debt": list(self.inherited_debt_indices),
                "new_debt": list(self.new_debt_indices),
                "hot_event": list(self.hot_event_indices),
                "recycled": list(self.recycled_indices),
            },
            "is_cumulative_vault_v1": False,
        }


@dataclass(frozen=True)
class CausalResidencyState:
    """Immutable evidence plus the current page and replayable activation state."""

    attic: CausalAttic
    parent_union_clause_count: int
    pinned_core_indices: tuple[int, ...]
    inherited_debt_indices: tuple[int, ...]
    active_limit: int
    current_projection: ResidencyProjection
    activation_ledger: tuple[ActivationLedgerEntry, ...]
    activation_counts: tuple[int, ...]
    last_active_lineages: tuple[int | None, ...]
    used_active_sha256: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.attic, CausalAttic):
            raise CausalResidencyError("causal-residency attic differs")
        clause_count = self.attic.union_vault.clause_count
        parent_count = _positive_int(
            self.parent_union_clause_count, "parent union clause count"
        )
        if parent_count > clause_count:
            raise CausalResidencyError(
                "causal-residency parent union clause count differs"
            )
        limit = _positive_int(self.active_limit, "active limit")
        if (
            limit > O1C66_VAULT_CAPS.maximum_clauses
            or self.attic.active_limit != limit
        ):
            raise CausalResidencyError("causal-residency active limit differs")
        _indices(
            self.pinned_core_indices,
            clause_count=clause_count,
            field="pinned core indices",
        )
        _indices(
            self.inherited_debt_indices,
            clause_count=parent_count,
            field="inherited debt indices",
        )
        if (
            not isinstance(self.current_projection, ResidencyProjection)
            or self.current_projection.vault.identity
            != self.attic.union_vault.identity
            or self.current_projection.vault.observed_variables
            != self.attic.union_vault.observed_variables
            or self.current_projection.vault.clause_count > limit
        ):
            raise CausalResidencyError(
                "causal-residency current projection differs"
            )
        if len(self.activation_counts) != clause_count or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in self.activation_counts
        ):
            raise CausalResidencyError("causal-residency activation counts differ")
        if len(self.last_active_lineages) != clause_count or any(
            value is not None
            and (isinstance(value, bool) or not isinstance(value, int) or value < 0)
            for value in self.last_active_lineages
        ):
            raise CausalResidencyError(
                "causal-residency last-active lineages differ"
            )
        if any(
            (count == 0) is not (lineage is None)
            for count, lineage in zip(
                self.activation_counts, self.last_active_lineages, strict=True
            )
        ):
            raise CausalResidencyError(
                "causal-residency activation lineage state differs"
            )
        if (
            not isinstance(self.activation_ledger, tuple)
            or not self.activation_ledger
            or any(
                not isinstance(entry, ActivationLedgerEntry)
                for entry in self.activation_ledger
            )
            or tuple(entry.lineage_ordinal for entry in self.activation_ledger)
            != tuple(
                sorted(entry.lineage_ordinal for entry in self.activation_ledger)
            )
        ):
            raise CausalResidencyError("causal-residency activation ledger differs")
        if (
            not isinstance(self.used_active_sha256, tuple)
            or tuple(entry.active_sha256 for entry in self.activation_ledger)
            != self.used_active_sha256
            or len(set(self.used_active_sha256)) != len(self.used_active_sha256)
            or self.current_projection.vault.sha256 != self.used_active_sha256[-1]
        ):
            raise CausalResidencyError(
                "causal-residency used active identities differ"
            )

    @property
    def active_projection(self) -> ThresholdNoGoodVault:
        return self.current_projection.vault

    @property
    def structural_root_indices(self) -> tuple[int, ...]:
        return _structural_roots(self.attic)

    @property
    def never_resident_undominated_indices(self) -> tuple[int, ...]:
        undominated = set(self.attic.undominated_indices)
        return tuple(
            index
            for index, count in enumerate(self.activation_counts)
            if count == 0 and index in undominated
        )

    def activation_ledger_document(self) -> dict[str, object]:
        return {
            "schema": ACTIVATION_LEDGER_SCHEMA,
            "entry_count": len(self.activation_ledger),
            "used_active_sha256": list(self.used_active_sha256),
            "entries": [entry.describe() for entry in self.activation_ledger],
            "activation_counts": list(self.activation_counts),
            "last_active_lineages": list(self.last_active_lineages),
        }

    def describe(self) -> dict[str, object]:
        return {
            "schema": CAUSAL_RESIDENCY_SCHEMA,
            "selection_rule": RESIDENCY_SELECTION_RULE,
            "attic_evidence": {
                "archive_rule": (
                    "preserve-all-immutable-chunks-occurrences-and-relations"
                ),
                "chunk_count": len(self.attic.chunks),
                "chunks": [chunk.describe() for chunk in self.attic.chunks],
                "union": self.attic.union_vault.describe(),
                "occurrence_count": len(self.attic.occurrences),
                "duplicate_occurrence_count": (
                    self.attic.duplicate_occurrence_count
                ),
                "strict_subsumption_pair_count": len(self.attic.relations),
                "undominated_clause_count": len(self.attic.undominated_indices),
            },
            "parent_union_clause_count": self.parent_union_clause_count,
            "active_limit": self.active_limit,
            "pinned_core_indices": list(self.pinned_core_indices),
            "structural_root_indices": list(self.structural_root_indices),
            "inherited_debt_indices": list(self.inherited_debt_indices),
            "never_resident_undominated_indices": list(
                self.never_resident_undominated_indices
            ),
            "current_projection": self.current_projection.describe(),
            "activation_ledger": self.activation_ledger_document(),
        }


def _priority_projection(
    attic: CausalAttic,
    *,
    lineage_ordinal: int,
    active_limit: int,
    pinned_core_indices: tuple[int, ...],
    inherited_debt_indices: tuple[int, ...],
    activation_counts: tuple[int, ...],
    last_active_lineages: tuple[int | None, ...],
    fully_emitted_union_indices: tuple[int, ...],
    used_active_sha256: tuple[str, ...],
) -> ResidencyProjection:
    counts = _occurrence_counts(attic)
    undominated = set(attic.undominated_indices)
    structural = _structural_roots(attic)

    categories: dict[str, list[int]] = {name: [] for name in _CATEGORY_ORDER}
    selected: set[int] = set()

    def admit(category: str, ordered: Sequence[int]) -> None:
        for index in ordered:
            if index in selected or len(selected) >= active_limit:
                continue
            selected.add(index)
            categories[category].append(index)

    core_order = tuple(structural) + tuple(
        index for index in pinned_core_indices if index not in set(structural)
    )
    if len(set(core_order)) > active_limit:
        raise CausalResidencyError(
            "causal-residency mandatory core exceeds active limit"
        )
    admit("structural_root", structural)
    admit(
        "pinned_core",
        tuple(index for index in pinned_core_indices if index not in selected),
    )

    inherited_debt = sorted(
        (
            index
            for index in inherited_debt_indices
            if activation_counts[index] == 0 and index in undominated
        ),
        key=lambda index: _debt_key(attic, counts, index),
    )
    admit("inherited_debt", inherited_debt)

    new_debt = sorted(
        (
            index
            for index in undominated
            if activation_counts[index] == 0
            and index not in selected
            and index not in set(inherited_debt_indices)
        ),
        key=lambda index: _debt_key(attic, counts, index),
    )
    admit("new_debt", new_debt)

    # Reverse occurrence order implements "newest"; exact duplicates collapse
    # to their latest appearance.  Serialization is still ascending union order.
    hot_order: list[int] = []
    hot_seen: set[int] = set()
    for index in reversed(fully_emitted_union_indices):
        if index not in hot_seen and index in undominated:
            hot_seen.add(index)
            hot_order.append(index)
    admit("hot_event", hot_order)

    recycled = sorted(
        (
            index
            for index in undominated
            if index not in selected and activation_counts[index] > 0
        ),
        key=lambda index: _recycle_key(
            attic,
            counts,
            activation_counts,
            last_active_lineages,
            index,
        ),
    )
    admit("recycled", recycled)

    order = tuple(index for name in _CATEGORY_ORDER for index in categories[name])
    indices = tuple(sorted(selected))
    vault = _selected_vault(attic, indices)
    if vault.sha256 in used_active_sha256:
        # Reusing an input is forbidden.  If the ranked population has an
        # unused tail, deterministically exchange the lowest-priority
        # replaceable clause until a fresh byte identity is found.  Pinned core
        # and inherited debt that fit remain mandatory.
        mandatory = set(categories["structural_root"])
        mandatory.update(categories["pinned_core"])
        mandatory.update(categories["inherited_debt"])
        full_tail = [
            *new_debt,
            *hot_order,
            *recycled,
        ]
        alternatives = [index for index in full_tail if index not in selected]
        replaceable = [index for index in reversed(order) if index not in mandatory]
        replacement: tuple[int, int, ThresholdNoGoodVault] | None = None
        for dropped in replaceable:
            for added in alternatives:
                candidate_indices = tuple(sorted((selected - {dropped}) | {added}))
                candidate = _selected_vault(attic, candidate_indices)
                if candidate.sha256 not in used_active_sha256:
                    replacement = dropped, added, candidate
                    break
            if replacement is not None:
                break
        if replacement is None:
            raise CausalResidencyError(
                "causal-residency has no unused active projection"
            )
        dropped, added, vault = replacement
        for name in _CATEGORY_ORDER:
            if dropped in categories[name]:
                position = categories[name].index(dropped)
                categories[name].pop(position)
                break
        added_category = "recycled"
        if activation_counts[added] == 0:
            added_category = (
                "inherited_debt"
                if added in set(inherited_debt_indices)
                else "new_debt"
            )
        elif added in hot_seen:
            added_category = "hot_event"
        categories[added_category].append(added)
        selected.remove(dropped)
        selected.add(added)
        order = tuple(
            index for name in _CATEGORY_ORDER for index in categories[name]
        )
        indices = tuple(sorted(selected))

    return ResidencyProjection(
        lineage_ordinal=lineage_ordinal,
        vault=vault,
        selected_union_indices=indices,
        selection_order=order,
        structural_root_indices=tuple(categories["structural_root"]),
        pinned_core_indices=tuple(categories["pinned_core"]),
        inherited_debt_indices=tuple(categories["inherited_debt"]),
        new_debt_indices=tuple(categories["new_debt"]),
        hot_event_indices=tuple(categories["hot_event"]),
        recycled_indices=tuple(categories["recycled"]),
    )


def _activate(
    projection: ResidencyProjection,
    *,
    activation_counts: Sequence[int],
    last_active_lineages: Sequence[int | None],
) -> tuple[tuple[int, ...], tuple[int | None, ...]]:
    counts = list(activation_counts)
    lineages = list(last_active_lineages)
    for index in projection.selected_union_indices:
        counts[index] += 1
        lineages[index] = projection.lineage_ordinal
    return tuple(counts), tuple(lineages)


def initialize_causal_residency(
    attic: CausalAttic,
    *,
    parent_active_indices: Sequence[int],
    inherited_event_indices: Sequence[int],
    parent_lineage_ordinal: int = 13,
    first_lineage_ordinal: int = 14,
    active_limit: int = 256,
) -> CausalResidencyState:
    """Seed parent residency and construct the first target-free page."""

    if not isinstance(attic, CausalAttic):
        raise CausalResidencyError("causal-residency initial attic differs")
    clause_count = attic.union_vault.clause_count
    parent_lineage = _nonnegative_int(
        parent_lineage_ordinal, "parent lineage ordinal"
    )
    first_lineage = _nonnegative_int(first_lineage_ordinal, "first lineage ordinal")
    limit = _positive_int(active_limit, "active limit")
    if first_lineage <= parent_lineage or limit > O1C66_VAULT_CAPS.maximum_clauses:
        raise CausalResidencyError("causal-residency initial schedule differs")
    parent_indices = tuple(
        sorted(
            _indices(
                parent_active_indices,
                clause_count=clause_count,
                field="parent active indices",
            )
        )
    )
    if not parent_indices or len(parent_indices) > limit:
        raise CausalResidencyError("causal-residency parent active page differs")
    event_indices = _indices(
        inherited_event_indices,
        clause_count=clause_count,
        field="inherited event indices",
    )
    roots = _structural_roots(attic)
    pinned_core = tuple(sorted(set(roots) | set(event_indices)))
    if len(pinned_core) > limit:
        raise CausalResidencyError(
            "causal-residency inherited pinned core exceeds active limit"
        )

    parent_vault = _selected_vault(attic, parent_indices)
    activation_counts = [0] * clause_count
    last_active: list[int | None] = [None] * clause_count
    for index in parent_indices:
        activation_counts[index] = 1
        last_active[index] = parent_lineage
    inherited_debt = tuple(
        sorted(set(attic.undominated_indices) - set(parent_indices))
    )
    parent_entry = ActivationLedgerEntry(
        lineage_ordinal=parent_lineage,
        role="inherited-parent-final",
        active_sha256=parent_vault.sha256,
        selected_union_indices=parent_indices,
    )
    first = _priority_projection(
        attic,
        lineage_ordinal=first_lineage,
        active_limit=limit,
        pinned_core_indices=pinned_core,
        inherited_debt_indices=inherited_debt,
        activation_counts=tuple(activation_counts),
        last_active_lineages=tuple(last_active),
        fully_emitted_union_indices=(),
        used_active_sha256=(parent_vault.sha256,),
    )
    counts, lineages = _activate(
        first,
        activation_counts=activation_counts,
        last_active_lineages=last_active,
    )
    first_entry = ActivationLedgerEntry(
        lineage_ordinal=first_lineage,
        role="causal-residency-page",
        active_sha256=first.vault.sha256,
        selected_union_indices=first.selected_union_indices,
    )
    state = CausalResidencyState(
        attic=attic,
        parent_union_clause_count=clause_count,
        pinned_core_indices=pinned_core,
        inherited_debt_indices=inherited_debt,
        active_limit=limit,
        current_projection=first,
        activation_ledger=(parent_entry, first_entry),
        activation_counts=counts,
        last_active_lineages=lineages,
        used_active_sha256=(parent_vault.sha256, first.vault.sha256),
    )
    validate_activation_replay(state)
    return state


def _validate_attic_extension(previous: CausalAttic, current: CausalAttic) -> None:
    if (
        previous.union_vault.identity != current.union_vault.identity
        or previous.union_vault.observed_variables
        != current.union_vault.observed_variables
        or current.chunks[: len(previous.chunks)] != previous.chunks
        or current.occurrences[: len(previous.occurrences)] != previous.occurrences
        or current.union_vault.clauses[: previous.union_vault.clause_count]
        != previous.union_vault.clauses
    ):
        raise CausalResidencyError(
            "causal-residency attic extension rewrites evidence"
        )


def reproject_causal_residency(
    attic: CausalAttic,
    *,
    previous_state: CausalResidencyState,
    fully_emitted_union_indices: Sequence[int],
    next_lineage_ordinal: int,
    next_active_limit: int | None = None,
) -> CausalResidencyState:
    """Project an extended attic after one complete call and activate its page."""

    if not isinstance(previous_state, CausalResidencyState) or not isinstance(
        attic, CausalAttic
    ):
        raise CausalResidencyError("causal-residency reprojection state differs")
    limit = (
        previous_state.active_limit
        if next_active_limit is None
        else _positive_int(next_active_limit, "next active limit")
    )
    if limit > O1C66_VAULT_CAPS.maximum_clauses:
        raise CausalResidencyError("causal-residency next active limit differs")
    if attic.active_limit != limit:
        try:
            attic = reproject_causal_attic(
                attic.chunks,
                attic.occurrences,
                active_limit=limit,
            )
        except CausalAtticError as exc:
            raise CausalResidencyError(
                "causal-residency next active limit differs"
            ) from exc
    _validate_attic_extension(previous_state.attic, attic)
    next_lineage = _nonnegative_int(next_lineage_ordinal, "next lineage ordinal")
    if next_lineage <= previous_state.activation_ledger[-1].lineage_ordinal:
        raise CausalResidencyError("causal-residency next lineage differs")
    event_indices = _indices(
        fully_emitted_union_indices,
        clause_count=attic.union_vault.clause_count,
        field="fully emitted union indices",
        unique=False,
    )
    growth = attic.union_vault.clause_count - len(previous_state.activation_counts)
    counts_before = previous_state.activation_counts + (0,) * growth
    lineages_before = previous_state.last_active_lineages + (None,) * growth
    projection = _priority_projection(
        attic,
        lineage_ordinal=next_lineage,
        active_limit=limit,
        pinned_core_indices=previous_state.pinned_core_indices,
        inherited_debt_indices=previous_state.inherited_debt_indices,
        activation_counts=counts_before,
        last_active_lineages=lineages_before,
        fully_emitted_union_indices=event_indices,
        used_active_sha256=previous_state.used_active_sha256,
    )
    counts, lineages = _activate(
        projection,
        activation_counts=counts_before,
        last_active_lineages=lineages_before,
    )
    entry = ActivationLedgerEntry(
        lineage_ordinal=next_lineage,
        role="causal-residency-page",
        active_sha256=projection.vault.sha256,
        selected_union_indices=projection.selected_union_indices,
    )
    state = CausalResidencyState(
        attic=attic,
        parent_union_clause_count=previous_state.parent_union_clause_count,
        pinned_core_indices=previous_state.pinned_core_indices,
        inherited_debt_indices=previous_state.inherited_debt_indices,
        active_limit=limit,
        current_projection=projection,
        activation_ledger=(*previous_state.activation_ledger, entry),
        activation_counts=counts,
        last_active_lineages=lineages,
        used_active_sha256=(*previous_state.used_active_sha256, projection.vault.sha256),
    )
    validate_activation_replay(state)
    return state


def advance_causal_residency(
    state: CausalResidencyState,
    *,
    chunk: ThresholdNoGoodVault,
    occurrences: Sequence[ClauseOccurrence],
    next_lineage_ordinal: int,
    next_active_limit: int | None = None,
) -> CausalResidencyState:
    """Append one immutable evidence chunk and reproject in a single operation."""

    if not isinstance(state, CausalResidencyState) or not isinstance(
        chunk, ThresholdNoGoodVault
    ):
        raise CausalResidencyError("causal-residency advance input differs")
    new_occurrences = tuple(occurrences)
    if any(
        not isinstance(occurrence, ClauseOccurrence)
        for occurrence in new_occurrences
    ):
        raise CausalResidencyError("causal-residency advance occurrences differ")
    limit = (
        state.active_limit
        if next_active_limit is None
        else _positive_int(next_active_limit, "next active limit")
    )
    if limit > O1C66_VAULT_CAPS.maximum_clauses:
        raise CausalResidencyError("causal-residency next active limit differs")
    try:
        attic = reproject_causal_attic(
            (*state.attic.chunks, chunk),
            (*state.attic.occurrences, *new_occurrences),
            active_limit=limit,
        )
    except CausalAtticError as exc:
        raise CausalResidencyError(
            "causal-residency attic append differs"
        ) from exc
    event_indices = attic.occurrence_union_indices[-len(new_occurrences) :]
    if not new_occurrences:
        event_indices = ()
    return reproject_causal_residency(
        attic,
        previous_state=state,
        fully_emitted_union_indices=event_indices,
        next_lineage_ordinal=next_lineage_ordinal,
        next_active_limit=limit,
    )


def validate_activation_replay(state: CausalResidencyState) -> None:
    """Replay the compact ledger and validate counts, ages, and every page SHA."""

    if not isinstance(state, CausalResidencyState):
        raise CausalResidencyError("causal-residency replay state differs")
    clause_count = state.attic.union_vault.clause_count
    counts = [0] * clause_count
    lineages: list[int | None] = [None] * clause_count
    used: list[str] = []
    for entry in state.activation_ledger:
        indices = _indices(
            entry.selected_union_indices,
            clause_count=clause_count,
            field="replay selected indices",
        )
        vault = _selected_vault(state.attic, indices)
        if vault.sha256 != entry.active_sha256 or vault.sha256 in used:
            raise CausalResidencyError(
                "causal-residency activation replay identity differs"
            )
        used.append(vault.sha256)
        for index in indices:
            counts[index] += 1
            lineages[index] = entry.lineage_ordinal
    if (
        tuple(counts) != state.activation_counts
        or tuple(lineages) != state.last_active_lineages
        or tuple(used) != state.used_active_sha256
        or state.activation_ledger[-1].selected_union_indices
        != state.current_projection.selected_union_indices
    ):
        raise CausalResidencyError(
            "causal-residency activation replay ledger differs"
        )


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(
        isinstance(key, str) for key in value
    ):
        raise CausalResidencyError(f"causal-residency {field} differs")
    return cast(Mapping[str, object], value)


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(
        value, (str, bytes, bytearray)
    ):
        raise CausalResidencyError(f"causal-residency {field} differs")
    return cast(Sequence[object], value)


def replay_causal_residency(
    attic: CausalAttic, document: Mapping[str, object]
) -> CausalResidencyState:
    """Rebuild a residency state from its complete canonical description."""

    if not isinstance(attic, CausalAttic):
        raise CausalResidencyError("causal-residency replay attic differs")
    root = _mapping(document, "replay document")
    if (
        root.get("schema") != CAUSAL_RESIDENCY_SCHEMA
        or root.get("selection_rule") != RESIDENCY_SELECTION_RULE
    ):
        raise CausalResidencyError("causal-residency replay schema differs")
    clause_count = attic.union_vault.clause_count
    parent_count = _positive_int(
        root.get("parent_union_clause_count"), "replay parent union clause count"
    )
    limit = _positive_int(root.get("active_limit"), "replay active limit")
    if limit > O1C66_VAULT_CAPS.maximum_clauses:
        raise CausalResidencyError("causal-residency replay active limit differs")
    if attic.active_limit != limit:
        try:
            attic = reproject_causal_attic(
                attic.chunks,
                attic.occurrences,
                active_limit=limit,
            )
        except CausalAtticError as exc:
            raise CausalResidencyError(
                "causal-residency replay active limit differs"
            ) from exc
        clause_count = attic.union_vault.clause_count
    pinned = _indices(
        cast(Sequence[int], _sequence(root.get("pinned_core_indices"), "replay core")),
        clause_count=clause_count,
        field="replay core",
    )
    inherited_debt = _indices(
        cast(
            Sequence[int],
            _sequence(root.get("inherited_debt_indices"), "replay debt"),
        ),
        clause_count=parent_count,
        field="replay debt",
    )
    projection_raw = _mapping(root.get("current_projection"), "replay projection")
    if projection_raw.get("schema") != RESIDENCY_PROJECTION_SCHEMA:
        raise CausalResidencyError("causal-residency replay projection schema differs")
    categories = _mapping(
        projection_raw.get("categories"), "replay projection categories"
    )
    parsed_categories: dict[str, tuple[int, ...]] = {}
    for name in _CATEGORY_ORDER:
        parsed_categories[name] = _indices(
            cast(
                Sequence[int],
                _sequence(categories.get(name), f"replay category {name}"),
            ),
            clause_count=clause_count,
            field=f"replay category {name}",
        )
    selection_order = tuple(
        index for name in _CATEGORY_ORDER for index in parsed_categories[name]
    )
    selected = tuple(sorted(selection_order))
    vault = _selected_vault(attic, selected)
    projection = ResidencyProjection(
        lineage_ordinal=_nonnegative_int(
            projection_raw.get("lineage_ordinal"), "replay projection lineage"
        ),
        vault=vault,
        selected_union_indices=selected,
        selection_order=selection_order,
        structural_root_indices=parsed_categories["structural_root"],
        pinned_core_indices=parsed_categories["pinned_core"],
        inherited_debt_indices=parsed_categories["inherited_debt"],
        new_debt_indices=parsed_categories["new_debt"],
        hot_event_indices=parsed_categories["hot_event"],
        recycled_indices=parsed_categories["recycled"],
    )

    ledger_raw = _mapping(root.get("activation_ledger"), "replay ledger")
    if ledger_raw.get("schema") != ACTIVATION_LEDGER_SCHEMA:
        raise CausalResidencyError("causal-residency replay ledger schema differs")
    entries_raw = _sequence(ledger_raw.get("entries"), "replay ledger entries")
    entries: list[ActivationLedgerEntry] = []
    for raw in entries_raw:
        row = _mapping(raw, "replay ledger entry")
        entry_indices = tuple(
            sorted(
                _indices(
                    cast(
                        Sequence[int],
                        _sequence(
                            row.get("selected_union_indices"),
                            "replay ledger selected indices",
                        ),
                    ),
                    clause_count=clause_count,
                    field="replay ledger selected indices",
                )
            )
        )
        entry = ActivationLedgerEntry(
            lineage_ordinal=_nonnegative_int(
                row.get("lineage_ordinal"), "replay ledger lineage"
            ),
            role=cast(str, row.get("role")),
            active_sha256=_sha256(
                row.get("active_sha256"), "replay ledger active SHA-256"
            ),
            selected_union_indices=entry_indices,
        )
        if entry.describe() != dict(row):
            raise CausalResidencyError(
                "causal-residency replay ledger entry differs"
            )
        entries.append(entry)
    counts = [0] * clause_count
    lineages: list[int | None] = [None] * clause_count
    for entry in entries:
        for index in entry.selected_union_indices:
            counts[index] += 1
            lineages[index] = entry.lineage_ordinal
    state = CausalResidencyState(
        attic=attic,
        parent_union_clause_count=parent_count,
        pinned_core_indices=pinned,
        inherited_debt_indices=inherited_debt,
        active_limit=limit,
        current_projection=projection,
        activation_ledger=tuple(entries),
        activation_counts=tuple(counts),
        last_active_lineages=tuple(lineages),
        used_active_sha256=tuple(entry.active_sha256 for entry in entries),
    )
    validate_activation_replay(state)
    if state.describe() != dict(root):
        raise CausalResidencyError(
            "causal-residency replay description differs"
        )
    return state


__all__ = [
    "ACTIVATION_LEDGER_SCHEMA",
    "CAUSAL_RESIDENCY_SCHEMA",
    "RESIDENCY_PROJECTION_SCHEMA",
    "RESIDENCY_SELECTION_RULE",
    "ActivationLedgerEntry",
    "CausalResidencyError",
    "CausalResidencyState",
    "ResidencyProjection",
    "advance_causal_residency",
    "initialize_causal_residency",
    "reproject_causal_residency",
    "replay_causal_residency",
    "validate_activation_replay",
]
