#!/usr/bin/env python3

from __future__ import annotations

import json
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))

import bifrost_searchtools.models as models


def main() -> None:
    document = json.load(sys.stdin)
    decoded = models.CodeQueryResult.from_dict(document)

    raw_by_type = {row["result_type"]: row for row in document["results"]}
    expected_types = set(models._CODE_QUERY_RESULT_ITEM_TYPES)
    if set(raw_by_type) != expected_types:
        raise AssertionError(
            f"Rust fixture result types differ from Python decoders: "
            f"{set(raw_by_type) ^ expected_types}"
        )
    if len(decoded.results) != len(expected_types):
        raise AssertionError("Python did not decode exactly one instance of every result type")

    structural_match = decoded.results[0]
    if structural_match.captures != []:
        raise AssertionError("omitted captures did not receive their Python default")
    if structural_match.provenance != [] or structural_match.provenance_truncated:
        raise AssertionError("omitted result provenance did not receive its Python defaults")

    configuration = raw_by_type["configuration_fact"]
    if "fact_provenance" not in configuration:
        raise AssertionError("configuration facts did not serialize fact_provenance")
    if "provenance" in configuration:
        raise AssertionError("omitted result provenance unexpectedly reached the wire")

    if len(decoded.diagnostics) != 1:
        raise AssertionError("the Rust diagnostic fixture was not decoded")
    diagnostic = decoded.diagnostics[0]
    if diagnostic.code.value != "invalid_plan" or diagnostic.impact.value != "invalid":
        raise AssertionError("the Rust diagnostic vocabulary did not survive Python decoding")

    for union_name in (
        "CodeQueryFlowPortSymbol",
        "CodeQueryFlowSelectorSymbol",
        "CodeQueryFlowCarrierSymbol",
        "CodeQueryFlowFactSymbol",
        "CodeQueryFlowWitnessStepKind",
        "CodeQueryTypestateWitnessStepKind",
        "CodeQueryTypestateFindingKind",
    ):
        tag_name, tagged_variants = models._generated_query_models.TAGGED_UNION_VARIANTS[
            union_name
        ]
        for tag_value, variant_type in tagged_variants.items():
            instance = object.__new__(variant_type)
            if getattr(instance, tag_name) != tag_value:
                raise AssertionError(
                    f"{union_name} compatibility tag {tag_value!r} was attached to "
                    f"the wrong generated variant"
                )


if __name__ == "__main__":
    main()
