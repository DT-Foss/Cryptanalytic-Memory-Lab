"""Narrow child-process broker for post-reveal retrospective labels.

The experiment process never parses aggregate result artifacts.  It invokes this
module with an explicit target allowlist and receives only the requested cell
labels plus an access receipt.  TEST and SEALED_DEPLOYMENT labels remain denied by
the underlying registry.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .artifacts import ReadOnlyArtifactSource
from .stage3 import PostRevealLabelRegistry, Stage3Error, a296_a297_specs


_ALLOWED_RESULTS = {
    "A296": "chronology/arx-carry-leak/research/results/v1/"
    "chacha20_round20_causal_search_gain_panel_a296_v1.json",
    "A297": "chronology/arx-carry-leak/research/results/v1/"
    "chacha20_round20_w32_causal_search_gain_panel_a297_v1.json",
}


def broker(
    *,
    source_root: str | Path,
    manifest: str | Path,
    expected_manifest_sha256: str,
    result_member: str,
    target_ids: list[str],
    purpose: str,
) -> dict[str, object]:
    if not target_ids or len(target_ids) != len(set(target_ids)):
        raise Stage3Error("broker target_ids must be a non-empty unique list")
    source = ReadOnlyArtifactSource(source_root, manifest)
    if source.manifest_sha256 != expected_manifest_sha256:
        raise Stage3Error("label broker manifest hash changed")
    by_target = {spec.target_id: spec for spec in a296_a297_specs()}
    try:
        specs = tuple(by_target[target_id] for target_id in target_ids)
    except KeyError as exc:
        raise Stage3Error(f"label broker target is absent from the split ledger: {exc}") from exc
    families = {spec.family for spec in specs}
    if len(families) != 1:
        raise Stage3Error("one broker call may access only one result family")
    family = next(iter(families))
    if _ALLOWED_RESULTS.get(family) != result_member:
        raise Stage3Error("result member is not the exact allowlisted family aggregate")
    registry = PostRevealLabelRegistry(source, specs)
    labels = registry.read_panel_result(result_member, purpose=purpose)
    return {
        "schema": "o1-crypto-label-broker-response-v1",
        "manifest_sha256": source.manifest_sha256,
        "family": family,
        "labels": [label.describe() for label in labels],
        "access_log": list(registry.access_log),
        "information_boundary": {
            "requested_targets_only": True,
            "aggregate_result_bytes_returned": False,
            "test_labels_allowed": False,
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m o1_crypto_lab.label_broker",
        description="Emit only explicitly allowlisted retrospective cell labels",
    )
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--result-member", required=True)
    parser.add_argument("--target-id", action="append", required=True)
    parser.add_argument("--purpose", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    response = broker(
        source_root=args.source_root,
        manifest=args.manifest,
        expected_manifest_sha256=args.expected_manifest_sha256,
        result_member=args.result_member,
        target_ids=args.target_id,
        purpose=args.purpose,
    )
    print(json.dumps(response, sort_keys=True, separators=(",", ":"), allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
