"""One-shot sealed full-256 ChaCha20 targets for Living Inverse freezes."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable, Mapping

from .living_inverse import (
    BLOCK_BYTES,
    CHACHA20_ROUNDS,
    KEY_BITS,
    PublicTargetView,
    build_known_target,
    canonical_json_bytes,
    canonical_sha256,
)


ENTROPY_BYTES = 32 + 4 + 12 + 32
PUBLICATION_SCHEMA = "o1-256-sealed-publication-v1"
COMMITMENT_SCHEMA = "o1-256-sealed-commitment-preimage-v1"
RECEIPT_SCHEMA = "o1-256-freeze-receipt-v1"
REVEAL_SCHEMA = "o1-256-sealed-reveal-v1"
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,95}\Z")


class Full256BrokerError(ValueError):
    """Raised when a sealed-target lifecycle or commitment differs."""


def _clone(value: object) -> object:
    return json.loads(canonical_json_bytes(value).decode("ascii"))


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise Full256BrokerError(f"{field} must be an object")
    return value


def _exact_keys(value: Mapping[str, object], expected: set[str], field: str) -> None:
    if set(value) != expected:
        raise Full256BrokerError(f"{field} fields differ")


def _sha(value: object, field: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise Full256BrokerError(f"{field} must be a lowercase SHA-256")
    return value


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        raise Full256BrokerError(f"{field} must be a finite ASCII identifier")
    return value


def _public_view(value: object) -> PublicTargetView:
    row = _mapping(value, "public_view")
    _exact_keys(
        row,
        {
            "schema",
            "cipher",
            "rounds",
            "feed_forward",
            "unknown_key_bits",
            "counter_schedule",
            "nonce_hex",
            "output_blocks_hex",
            "target_key_included",
            "target_trace_included",
        },
        "public_view",
    )
    if (
        row.get("schema") != "o1-256-public-target-view-v1"
        or row.get("cipher") != "ChaCha20"
        or row.get("rounds") != CHACHA20_ROUNDS
        or row.get("feed_forward") is not True
        or row.get("unknown_key_bits") != KEY_BITS
        or row.get("target_key_included") is not False
        or row.get("target_trace_included") is not False
    ):
        raise Full256BrokerError("public view contract differs")
    counters = row.get("counter_schedule")
    outputs = row.get("output_blocks_hex")
    if not isinstance(counters, list) or not isinstance(outputs, list):
        raise Full256BrokerError("public schedule and outputs must be lists")
    nonce_hex = row.get("nonce_hex")
    if not isinstance(nonce_hex, str):
        raise Full256BrokerError("public nonce must be hexadecimal")
    try:
        nonce = bytes.fromhex(nonce_hex)
        output_blocks = tuple(bytes.fromhex(str(value)) for value in outputs)
    except ValueError as exc:
        raise Full256BrokerError("public hexadecimal field is invalid") from exc
    if any(len(block) != BLOCK_BYTES for block in output_blocks):
        raise Full256BrokerError("public output block length differs")
    view = PublicTargetView(
        counter_schedule=tuple(counters),  # type: ignore[arg-type]
        nonce=nonce,
        output_blocks=output_blocks,
    )
    try:
        view.validate()
    except ValueError as exc:
        raise Full256BrokerError("public view is invalid") from exc
    if view.describe() != dict(row):
        raise Full256BrokerError("public view is not canonical")
    return view


def verify_publication(value: object) -> dict[str, object]:
    row = _mapping(value, "publication")
    _exact_keys(
        row,
        {
            "schema",
            "target_id",
            "entropy_source_id",
            "public_view",
            "public_view_sha256",
            "commitment_sha256",
            "publication_sha256",
        },
        "publication",
    )
    if row.get("schema") != PUBLICATION_SCHEMA:
        raise Full256BrokerError("publication schema differs")
    _identifier(row.get("target_id"), "target_id")
    _identifier(row.get("entropy_source_id"), "entropy_source_id")
    view = _public_view(row.get("public_view"))
    if _sha(row.get("public_view_sha256"), "public_view_sha256") != view.digest():
        raise Full256BrokerError("public view SHA-256 differs")
    _sha(row.get("commitment_sha256"), "commitment_sha256")
    publication_sha = _sha(row.get("publication_sha256"), "publication_sha256")
    unsigned = {key: item for key, item in row.items() if key != "publication_sha256"}
    if canonical_sha256(unsigned) != publication_sha:
        raise Full256BrokerError("publication SHA-256 differs")
    return _clone(dict(row))  # type: ignore[return-value]


def make_freeze_receipt(
    publication: object, *, frozen_artifact_sha256: str
) -> dict[str, object]:
    public = verify_publication(publication)
    artifact_sha = _sha(frozen_artifact_sha256, "frozen_artifact_sha256")
    unsigned = {
        "schema": RECEIPT_SCHEMA,
        "target_id": public["target_id"],
        "publication_sha256": public["publication_sha256"],
        "frozen_artifact_sha256": artifact_sha,
        "freeze_complete": True,
    }
    return {**unsigned, "receipt_sha256": canonical_sha256(unsigned)}


def _verify_receipt(value: object, publication: Mapping[str, object]) -> dict[str, object]:
    row = _mapping(value, "freeze_receipt")
    _exact_keys(
        row,
        {
            "schema",
            "target_id",
            "publication_sha256",
            "frozen_artifact_sha256",
            "freeze_complete",
            "receipt_sha256",
        },
        "freeze_receipt",
    )
    if row.get("schema") != RECEIPT_SCHEMA or row.get("freeze_complete") is not True:
        raise Full256BrokerError("freeze receipt is incomplete")
    if row.get("target_id") != publication.get("target_id"):
        raise Full256BrokerError("freeze receipt target differs")
    if row.get("publication_sha256") != publication.get("publication_sha256"):
        raise Full256BrokerError("freeze receipt publication differs")
    _sha(row.get("frozen_artifact_sha256"), "frozen_artifact_sha256")
    receipt_sha = _sha(row.get("receipt_sha256"), "receipt_sha256")
    unsigned = {key: item for key, item in row.items() if key != "receipt_sha256"}
    if canonical_sha256(unsigned) != receipt_sha:
        raise Full256BrokerError("freeze receipt SHA-256 differs")
    return _clone(dict(row))  # type: ignore[return-value]


class Full256TargetBroker:
    """In-memory one-shot commitment broker with a strict reveal gate."""

    def __init__(
        self,
        *,
        block_count: int = 1,
        entropy_source: Callable[[int], bytes] = os.urandom,
        entropy_source_id: str = "os.urandom",
        target_id: str = "living-inverse-0001",
    ) -> None:
        if not isinstance(block_count, int) or isinstance(block_count, bool):
            raise Full256BrokerError("block_count must be an integer")
        if not 1 <= block_count <= 16:
            raise Full256BrokerError("block_count must be in [1, 16]")
        if not callable(entropy_source):
            raise Full256BrokerError("entropy_source must be callable")
        self._source_id = _identifier(entropy_source_id, "entropy_source_id")
        self._target_id = _identifier(target_id, "target_id")
        entropy = entropy_source(ENTROPY_BYTES)
        if not isinstance(entropy, bytes) or len(entropy) != ENTROPY_BYTES:
            raise Full256BrokerError(
                f"entropy source must return exactly {ENTROPY_BYTES} bytes"
            )
        self._key = entropy[:32]
        raw_counter = int.from_bytes(entropy[32:36], "little")
        maximum_start = (1 << 32) - block_count
        self._counter = raw_counter % (maximum_start + 1)
        self._nonce = entropy[36:48]
        self._salt = entropy[48:80]
        self._target = build_known_target(
            self._key,
            counter=self._counter,
            nonce=self._nonce,
            block_count=block_count,
        )
        self._publication: dict[str, object] | None = None
        self._revealed = False

    @property
    def phase(self) -> str:
        if self._revealed:
            return "REVEALED"
        if self._publication is not None:
            return "PUBLISHED"
        return "SEALED"

    def publish(self) -> dict[str, object]:
        if self._publication is None:
            public_view = self._target.public.describe()
            commitment_preimage = {
                "schema": COMMITMENT_SCHEMA,
                "target_id": self._target_id,
                "entropy_source_id": self._source_id,
                "key_hex": self._key.hex(),
                "salt_hex": self._salt.hex(),
                "public_view_sha256": canonical_sha256(public_view),
            }
            unsigned = {
                "schema": PUBLICATION_SCHEMA,
                "target_id": self._target_id,
                "entropy_source_id": self._source_id,
                "public_view": public_view,
                "public_view_sha256": canonical_sha256(public_view),
                "commitment_sha256": canonical_sha256(commitment_preimage),
            }
            self._publication = {
                **unsigned,
                "publication_sha256": canonical_sha256(unsigned),
            }
        return verify_publication(self._publication)

    def reveal(self, receipt: object) -> dict[str, object]:
        if self._publication is None:
            raise Full256BrokerError("target must be published before reveal")
        if self._revealed:
            raise Full256BrokerError("target has already been revealed")
        checked_receipt = _verify_receipt(receipt, self._publication)
        commitment_preimage = {
            "schema": COMMITMENT_SCHEMA,
            "target_id": self._target_id,
            "entropy_source_id": self._source_id,
            "key_hex": self._key.hex(),
            "salt_hex": self._salt.hex(),
            "public_view_sha256": self._publication["public_view_sha256"],
        }
        if canonical_sha256(commitment_preimage) != self._publication["commitment_sha256"]:
            raise Full256BrokerError("sealed commitment differs before reveal")
        unsigned = {
            "schema": REVEAL_SCHEMA,
            "publication": self._publication,
            "freeze_receipt": checked_receipt,
            "commitment_preimage": commitment_preimage,
        }
        reveal = {**unsigned, "reveal_sha256": canonical_sha256(unsigned)}
        verify_reveal(reveal)
        self._revealed = True
        return _clone(reveal)  # type: ignore[return-value]


def verify_reveal(value: object) -> dict[str, object]:
    row = _mapping(value, "reveal")
    _exact_keys(
        row,
        {
            "schema",
            "publication",
            "freeze_receipt",
            "commitment_preimage",
            "reveal_sha256",
        },
        "reveal",
    )
    if row.get("schema") != REVEAL_SCHEMA:
        raise Full256BrokerError("reveal schema differs")
    publication = verify_publication(row.get("publication"))
    _verify_receipt(row.get("freeze_receipt"), publication)
    preimage = _mapping(row.get("commitment_preimage"), "commitment_preimage")
    _exact_keys(
        preimage,
        {
            "schema",
            "target_id",
            "entropy_source_id",
            "key_hex",
            "salt_hex",
            "public_view_sha256",
        },
        "commitment_preimage",
    )
    if (
        preimage.get("schema") != COMMITMENT_SCHEMA
        or preimage.get("target_id") != publication["target_id"]
        or preimage.get("entropy_source_id") != publication["entropy_source_id"]
        or preimage.get("public_view_sha256") != publication["public_view_sha256"]
    ):
        raise Full256BrokerError("commitment preimage identity differs")
    try:
        key = bytes.fromhex(str(preimage.get("key_hex")))
        salt = bytes.fromhex(str(preimage.get("salt_hex")))
    except ValueError as exc:
        raise Full256BrokerError("reveal hexadecimal field is invalid") from exc
    if len(key) != 32 or len(salt) != 32:
        raise Full256BrokerError("reveal key or salt length differs")
    if canonical_sha256(dict(preimage)) != publication["commitment_sha256"]:
        raise Full256BrokerError("reveal does not open the commitment")
    public = _public_view(publication["public_view"])
    recomputed = build_known_target(
        key,
        counter=public.counter_schedule[0],
        nonce=public.nonce,
        block_count=public.block_count,
    )
    if recomputed.public.digest() != public.digest():
        raise Full256BrokerError("revealed key does not reproduce public output")
    reveal_sha = _sha(row.get("reveal_sha256"), "reveal_sha256")
    unsigned = {key: item for key, item in row.items() if key != "reveal_sha256"}
    if canonical_sha256(unsigned) != reveal_sha:
        raise Full256BrokerError("reveal SHA-256 differs")
    return _clone(dict(row))  # type: ignore[return-value]
