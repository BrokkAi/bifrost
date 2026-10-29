#!/usr/bin/env python3

from __future__ import annotations

import json
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))

import bifrost_searchtools.models as models


def _decode_result_item(row: dict) -> object:
    return models._generated_query_models.CodeQueryResultItem.from_dict(row)


def _assert_result_item_rejected(row: dict, description: str) -> None:
    try:
        _decode_result_item(row)
    except models._generated_query_models.DecoderError:
        return
    raise AssertionError(f"Python accepted invalid decorated-parameter {description}")


def _check_decorated_parameter_contract(decorated_raw: dict, decorated: object) -> None:
    # These checks cover the public wire decoder, not analyzer resolution proof.
    if decorated.annotation_status is None or decorated.annotation_status.value != "resolved":
        raise AssertionError("the Java annotation status did not survive Python decoding")
    if decorated.annotation_type is None:
        raise AssertionError("the Java annotation declaration did not survive Python decoding")
    if (
        decorated.annotation_type.id != "fixture-annotation-trace-marker"
        or decorated.annotation_type.fq_name != "fixture.annotations.TraceMarker"
        or decorated.annotation_type.kind != "annotation_type_declaration"
    ):
        raise AssertionError("the Java annotation declaration identity changed during decoding")
    if (
        decorated.annotation_fq_name != "fixture.annotations.TraceMarker"
        or decorated.annotation_route != "source_declaration"
    ):
        raise AssertionError("the Java annotation route did not survive Python decoding")

    invalid_route = dict(decorated_raw)
    invalid_route["annotation_route"] = "guessed"
    _assert_result_item_rejected(invalid_route, "route enum value")

    without_annotation_fields = dict(decorated_raw)
    without_annotation_fields.pop("annotation_type")
    without_annotation_fields.pop("annotation_status")
    decoded_without_fields = _decode_result_item(without_annotation_fields)
    if (
        decoded_without_fields.annotation_type is not None
        or decoded_without_fields.annotation_status is not None
    ):
        raise AssertionError("missing optional annotation fields did not decode as absent")

    with_null_annotation_fields = dict(decorated_raw)
    with_null_annotation_fields["annotation_type"] = None
    with_null_annotation_fields["annotation_status"] = None
    decoded_null_fields = _decode_result_item(with_null_annotation_fields)
    if (
        decoded_null_fields.annotation_type is not None
        or decoded_null_fields.annotation_status is not None
    ):
        raise AssertionError("null optional annotation fields did not decode as absent")

    invalid_enum = dict(decorated_raw)
    invalid_enum["annotation_status"] = "resolved_like"
    _assert_result_item_rejected(invalid_enum, "enum value")

    wrong_declaration_identity_type = dict(decorated_raw)
    wrong_declaration_identity_type["annotation_type"] = dict(
        decorated_raw["annotation_type"], fq_name=17
    )
    _assert_result_item_rejected(wrong_declaration_identity_type, "declaration identity type")

    wrong_declaration_shape = dict(decorated_raw)
    wrong_declaration_shape["annotation_type"] = "fixture.annotations.TraceMarker"
    _assert_result_item_rejected(wrong_declaration_shape, "declaration object type")


def _check_python_hierarchy_contract(hierarchy: object) -> None:
    # These are wire premises, not a catalog activation or member-absence proof.
    if (
        hierarchy.fact_kind != "mro"
        or hierarchy.outcome != "complete"
        or hierarchy.coverage != "complete"
        or hierarchy.mro_rank != 1
        or hierarchy.member_name is not None
    ):
        raise AssertionError("the modeled hierarchy topology/coverage changed during decoding")
    if (
        hierarchy.root is None
        or hierarchy.root.id != hierarchy.root_id
        or hierarchy.root.fq_name != "fixture.FixtureDict"
        or hierarchy.root.path != "fixture.py"
        or hierarchy.root.semantic_model is not None
    ):
        raise AssertionError("the hierarchy source root did not survive decoding")
    endpoint = hierarchy.declaration
    if (
        endpoint is None
        or endpoint.kind != "external_class"
        or endpoint.canonical_symbol_id != "fixture-builtins-dict"
        or endpoint.qualified_name != "builtins.dict"
        or hierarchy.declaration_id != endpoint.canonical_symbol_id
        or hasattr(endpoint, "declaration")
    ):
        raise AssertionError("the external hierarchy endpoint acquired a source declaration")
    claims = hierarchy.ancestry_basis.claims
    expected = [
        ("builtins.dict", "fixture-builtins-dict", ["builtins.object"]),
        ("builtins.object", "fixture-builtins-object", []),
    ]
    if len(claims) != len(expected):
        raise AssertionError("the nonempty ancestry basis or explicit empty root was lost")
    for claim, (name, symbol_id, base_names) in zip(claims, expected):
        if (
            claim.class_ is None
            or claim.class_.qualified_name != name
            or claim.class_.symbol_id != symbol_id
            or claim.declared_class != claim.class_
            or [base.qualified_name if base else None for base in claim.bases] != base_names
            or [base.name for base in claim.declared_bases] != base_names
            or any(
                base.kind != "named" or base.arguments or base.nullable
                for base in claim.declared_bases
            )
            or any(base.symbol_id != "fixture-builtins-object" for base in claim.bases)
        ):
            raise AssertionError("the ordered canonical/declared runtime ancestry changed")
        provenance = claim.provenance
        activation = provenance.activation
        evidence = activation.matched_evidence
        if (
            provenance.record_id != symbol_id
            or provenance.pack_id != "test-only-python-runtime-bases"
            or provenance.pack_version != "0.0.0"
            or provenance.producer != "query-result-fixtures"
            or provenance.producer_version != "1"
            or provenance.rule_id is not None
            or provenance.active_model_set_hash != "1" * 64
            or provenance.pack_digest != "2" * 64
            or provenance.origin.value != "declarative_model"
            or provenance.proof.value != "pack_fact"
            or provenance.completeness.value != "partial"
            or provenance.ambiguous
            or activation.status != "active"
            or activation.reason != "explicit test-only wire fixture"
            or activation.source_kind != "ephemeral_workspace"
            or activation.source_id != "fixture-python-runtime-bases"
            or evidence.language != "python"
            or evidence.ecosystem != "python"
            or evidence.toolchain is None
            or evidence.toolchain.name != "CPython"
            or evidence.toolchain.version != "3.13.5"
            or evidence.artifact_sha256 is not None
        ):
            raise AssertionError("the partial model/activation provenance was lost or strengthened")


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

    decorated_raw = raw_by_type["decorated_parameter"]
    decorated = next(
        result
        for result in decoded.results
        if isinstance(result, models.CodeQueryDecoratedParameter)
    )
    _check_decorated_parameter_contract(decorated_raw, decorated)

    hierarchy = next(
        result
        for result in decoded.results
        if isinstance(result, models.CodeQueryPythonHierarchyFact)
    )
    _check_python_hierarchy_contract(hierarchy)

    configuration = raw_by_type["configuration_fact"]
    if "fact_provenance" not in configuration:
        raise AssertionError("configuration facts did not serialize fact_provenance")
    if "provenance" in configuration:
        raise AssertionError("omitted result provenance unexpectedly reached the wire")

    # Regression from 01836c5619fe: flattened obligation and trace provenance
    # previously used the same wire key with incompatible value types.
    obligation_raw = raw_by_type["call_result_obligation"]
    obligation = _decode_result_item(obligation_raw)
    if obligation.obligation_provenance != "native_go_error":
        raise AssertionError("obligation provenance did not survive Python decoding")
    if len(obligation.provenance) != 1 or obligation.provenance[0].seed.path != "main.go":
        raise AssertionError("query trace provenance did not survive Python decoding")

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
