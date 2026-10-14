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
    raise AssertionError(f"Python accepted invalid result item {description}")


EXPECTED_EXTERNAL_CALLEE_KEY = {
    "language": "java",
    "owner": "com.acme.AcmeHttpClient",
    "member": "send",
    "has_receiver": True,
    "parameter_count": 1,
}


def _check_external_callee_key_contract(raw_by_type: dict[str, dict], decoded: object) -> None:
    dispatch = raw_by_type["dispatch_target"]
    effect = raw_by_type["procedure_effect"]
    hops = effect.get("witness_hops")
    if not isinstance(hops, list) or len(hops) != 1:
        raise AssertionError("the fixture procedure effect did not retain one witness hop")
    witness = hops[0]

    if dispatch.get("external_callee_key") != EXPECTED_EXTERNAL_CALLEE_KEY:
        raise AssertionError("the dispatch target lost its typed external callee key")
    if witness.get("external_callee_key") != EXPECTED_EXTERNAL_CALLEE_KEY:
        raise AssertionError("the procedure-effect witness lost its typed external callee key")
    if dispatch["external_callee_key"] != witness["external_callee_key"]:
        raise AssertionError("dispatch and witness external callee keys differ")
    generated = models._generated_query_models
    decoded_dispatch = next(
        result
        for result in decoded.results
        if isinstance(result, generated.CodeQueryDispatchTarget)
    )
    decoded_effect = next(
        result
        for result in decoded.results
        if isinstance(result, generated.CodeQueryProcedureEffect)
    )
    if (
        decoded_dispatch.external_callee_key is None
        or not decoded_effect.witness_hops
        or decoded_effect.witness_hops[0].external_callee_key is None
        or decoded_dispatch.external_callee_key
        != decoded_effect.witness_hops[0].external_callee_key
    ):
        raise AssertionError("decoded dispatch and witness external callee keys differ")
    if witness["target_id"] != dispatch["target_id"]:
        raise AssertionError("the witness did not retain the dispatch target identity")
    if witness["callee_procedure_id"] == dispatch["target_id"]:
        raise AssertionError("graph procedure and dispatch identities were conflated")
    if witness["dispatch_complete"] is not False:
        raise AssertionError("the unresolved witness dispatch was upgraded to complete")
    if witness["proof"] != "unproven" or dispatch["proof"] != "unproven":
        raise AssertionError("the external key changed unproven dispatch evidence")
    if dispatch["completeness"] != "partial" or dispatch["dispatch"] != "may_dispatch":
        raise AssertionError("the external key changed partial dispatch evidence")

    dispatch_without_key = dict(dispatch)
    dispatch_without_key.pop("external_callee_key")
    decoded_dispatch_without_key = _decode_result_item(dispatch_without_key)
    if decoded_dispatch_without_key.external_callee_key is not None:
        raise AssertionError("an absent dispatch external key did not decode as absent")

    dispatch_with_null_key = dict(dispatch)
    dispatch_with_null_key["external_callee_key"] = None
    decoded_dispatch_with_null_key = _decode_result_item(dispatch_with_null_key)
    if decoded_dispatch_with_null_key.external_callee_key is not None:
        raise AssertionError("a null dispatch external key did not decode as absent")

    effect_without_key = dict(effect)
    effect_without_key["witness_hops"] = [dict(witness)]
    effect_without_key["witness_hops"][0].pop("external_callee_key")
    decoded_effect_without_key = _decode_result_item(effect_without_key)
    if decoded_effect_without_key.witness_hops[0].external_callee_key is not None:
        raise AssertionError("an absent witness external key did not decode as absent")

    effect_with_null_key = dict(effect)
    effect_with_null_key["witness_hops"] = [dict(witness)]
    effect_with_null_key["witness_hops"][0]["external_callee_key"] = None
    decoded_effect_with_null_key = _decode_result_item(effect_with_null_key)
    if decoded_effect_with_null_key.witness_hops[0].external_callee_key is not None:
        raise AssertionError("a null witness external key did not decode as absent")

    malformed_dispatch = dict(dispatch)
    malformed_dispatch["external_callee_key"] = dict(EXPECTED_EXTERNAL_CALLEE_KEY)
    malformed_dispatch["external_callee_key"]["parameter_count"] = "one"
    _assert_result_item_rejected(malformed_dispatch, "nested external key primitive")

    malformed_witness = dict(witness)
    malformed_witness["external_callee_key"] = dict(EXPECTED_EXTERNAL_CALLEE_KEY)
    del malformed_witness["external_callee_key"]["owner"]
    malformed_effect = dict(effect)
    malformed_effect["witness_hops"] = [malformed_witness]
    _assert_result_item_rejected(malformed_effect, "nested external key required field")


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


def main() -> None:
    document = json.load(sys.stdin)
    decoded = models.CodeQueryResult.from_dict(document)

    raw_by_type = {row["result_type"]: row for row in document["results"]}
    _check_external_callee_key_contract(raw_by_type, decoded)
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
