#!/usr/bin/env python3

"""Generate deterministic typed Python models from a JSON Schema."""

from __future__ import annotations

import argparse
import json
import keyword
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA_2020_12 = "https://json-schema.org/draft/2020-12/schema"

ROOT_SCHEMA_KEYS = frozenset(
    {
        "$schema",
        "$id",
        "$comment",
        "$defs",
        "title",
        "description",
        "default",
        "deprecated",
        "examples",
        "type",
        "enum",
        "const",
        "allOf",
        "anyOf",
        "oneOf",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "prefixItems",
        "minimum",
        "maximum",
        "format",
        "$ref",
    }
)


class UnsupportedSchema(ValueError):
    """A JSON Schema construct has no faithful typed Python decoding."""


@dataclass(frozen=True)
class TypePlan:
    pointer: str
    kind: str
    schema: dict[str, Any]
    type_expression: str
    decoder_name: str
    class_name: str | None = None
    enum_values: tuple[Any, ...] = ()
    fields: tuple[tuple[str, str, str, bool, Any], ...] = ()
    item_plan: "TypePlan | None" = None
    value_plan: "TypePlan | None" = None
    element_plans: tuple["TypePlan", ...] = ()
    union_plans: tuple["TypePlan", ...] = ()
    union_variants: tuple[tuple[Any, "TypePlan"], ...] = ()
    tag: str | None = None
    tag_kind: str | None = None
    map_plan: "TypePlan | None" = None
    nullable: bool = False
    base_decoder_name: str | None = None
    minimum: int | float | None = None
    maximum: int | float | None = None


def schema_error(path: str, message: str) -> UnsupportedSchema:
    location = path or "<root>"
    return UnsupportedSchema(f"{location}: {message}")


def python_identifier(value: str) -> str:
    characters = []
    previous_separator = True
    for character in value:
        if character.isalnum():
            characters.append(character)
            previous_separator = False
        else:
            if not previous_separator:
                characters.append("_")
            previous_separator = True
    identifier = "".join(characters).strip("_")
    if not identifier:
        identifier = "value"
    if identifier[0].isdigit():
        identifier = f"_{identifier}"
    return identifier


def python_field_name(value: str, used: set[str]) -> str:
    identifier = python_identifier(value)
    if identifier[0].isupper():
        identifier = f"_{identifier}"
    if keyword.iskeyword(identifier):
        identifier = f"{identifier}_"
    candidate = identifier
    suffix = 2
    while candidate in used:
        candidate = f"{identifier}_{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate


def pascal_name(value: str) -> str:
    parts = []
    for part in python_identifier(value).split("_"):
        if not part:
            continue
        parts.append(part[0].upper() + part[1:])
    name = "".join(parts)
    return name or "Value"


def snake_name(value: str) -> str:
    name = python_identifier(value)
    words = []
    current = []
    previous_lower = False
    for character in name:
        if character.isupper() and previous_lower:
            words.append("".join(current))
            current = [character.lower()]
        else:
            current.append(character.lower())
        previous_lower = character.islower()
    if current:
        words.append("".join(current))
    return "_".join(word for word in words if word) or "value"


class SchemaDocument:
    def __init__(self, root: Any) -> None:
        if not isinstance(root, dict):
            raise UnsupportedSchema("schema root must be a JSON object")
        declared = root.get("$schema")
        if declared is not None and declared != SCHEMA_2020_12:
            raise UnsupportedSchema(
                f"unsupported $schema {declared!r}; expected {SCHEMA_2020_12!r}"
            )
        definitions = root.get("$defs")
        if definitions is not None and not isinstance(definitions, dict):
            raise UnsupportedSchema("$defs must be an object")
        self.root = root
        self.definitions = definitions or {}
        self.validate_root()

    def validate_root(self) -> None:
        self.validate_schema(self.root, "")
        for name, schema in self.definitions.items():
            self.validate_schema(schema, f"$defs/{name}")

    def validate_schema(self, schema: Any, pointer: str) -> None:
        if not isinstance(schema, dict):
            raise schema_error(pointer, "boolean and non-object schemas are unsupported")
        unsupported = sorted(set(schema) - ROOT_SCHEMA_KEYS)
        if unsupported:
            raise schema_error(pointer, f"unsupported keyword(s): {', '.join(unsupported)}")
        if "$ref" in schema and len(schema) > 4:
            allowed_with_ref = {"$ref", "title", "description", "default", "deprecated"}
            unexpected = sorted(set(schema) - allowed_with_ref)
            if unexpected:
                raise schema_error(pointer, f"$ref cannot be combined with: {', '.join(unexpected)}")
        ref = schema.get("$ref")
        if ref is not None:
            if not isinstance(ref, str) or not ref.startswith("#/$defs/"):
                raise schema_error(pointer, f"unsupported $ref {ref!r}; expected #/$defs/<name>")
            target = ref[len("#/$defs/") :]
            if target not in self.definitions:
                raise schema_error(pointer, f"unresolved $ref {ref!r}")
            return
        for keyword_name in ("properties", "$defs"):
            value = schema.get(keyword_name)
            if value is not None and not isinstance(value, dict):
                raise schema_error(pointer, f"{keyword_name} must be an object")
        for property_name, property_schema in schema.get("properties", {}).items():
            self.validate_schema(property_schema, f"{pointer}/properties/{property_name}")
        additional = schema.get("additionalProperties")
        if isinstance(additional, dict):
            self.validate_schema(additional, f"{pointer}/additionalProperties")
        elif additional is not None and not isinstance(additional, bool):
            raise schema_error(pointer, "additionalProperties must be an object or boolean")
        items = schema.get("items")
        if items is not None:
            self.validate_schema(items, f"{pointer}/items")
        prefix_items = schema.get("prefixItems")
        if prefix_items is not None:
            if not isinstance(prefix_items, list):
                raise schema_error(pointer, "prefixItems must be an array")
            for index, item_schema in enumerate(prefix_items):
                self.validate_schema(item_schema, f"{pointer}/prefixItems/{index}")
        for keyword_name in ("allOf", "anyOf", "oneOf"):
            alternatives = schema.get(keyword_name)
            if alternatives is None:
                continue
            if not isinstance(alternatives, list) or not alternatives:
                raise schema_error(pointer, f"{keyword_name} must be a non-empty array")
            for index, alternative in enumerate(alternatives):
                self.validate_schema(alternative, f"{pointer}/{keyword_name}/{index}")
        enum_values = schema.get("enum")
        if enum_values is not None:
            if not isinstance(enum_values, list) or not enum_values:
                raise schema_error(pointer, "enum must be a non-empty array")
        const = schema.get("const")
        if const is not None and "enum" in schema:
            raise schema_error(pointer, "const and enum cannot be combined")
        for keyword_name in ("minimum", "maximum"):
            bound = schema.get(keyword_name)
            if bound is not None and (isinstance(bound, bool) or not isinstance(bound, (int, float))):
                raise schema_error(pointer, f"{keyword_name} must be a number")

    def resolve(self, ref: str, pointer: str) -> tuple[dict[str, Any], str]:
        name = ref[len("#/$defs/") :]
        schema = self.definitions[name]
        if not isinstance(schema, dict):
            raise schema_error(pointer, f"$ref {ref!r} does not resolve to an object schema")
        return schema, f"$defs/{name}"


def normalize_schema(schema: dict[str, Any], pointer: str) -> dict[str, Any]:
    if "allOf" not in schema:
        return schema
    if any(keyword_name in schema for keyword_name in ("anyOf", "oneOf")):
        raise schema_error(pointer, "allOf cannot be combined with anyOf or oneOf")
    merged: dict[str, Any] = {}
    required: set[str] = set()
    properties: dict[str, Any] = {}
    additional_values: list[Any] = []
    for index, component in enumerate(schema["allOf"]):
        component_pointer = f"{pointer}/allOf/{index}"
        if set(component) - {
            "type",
            "title",
            "description",
            "deprecated",
            "properties",
            "required",
            "additionalProperties",
        }:
            unexpected = sorted(set(component) - {
                "type",
                "title",
                "description",
                "deprecated",
                "properties",
                "required",
                "additionalProperties",
            })
            raise schema_error(
                component_pointer,
                f"allOf supports only object schemas; unexpected keyword(s): {', '.join(unexpected)}",
            )
        if component.get("type") not in (None, "object"):
            raise schema_error(component_pointer, "allOf supports only object schemas")
        if "additionalProperties" in component:
            additional_values.append(component["additionalProperties"])
        for property_name, property_schema in component.get("properties", {}).items():
            if property_name in properties and property_schema != properties[property_name]:
                raise schema_error(
                    component_pointer,
                    f"conflicting allOf definition for property {property_name!r}",
                )
            properties[property_name] = property_schema
        required.update(component.get("required", ()))
    if additional_values and any(value is not True for value in additional_values):
        if any(value != additional_values[0] for value in additional_values):
            raise schema_error(pointer, "conflicting additionalProperties in allOf")
        merged["additionalProperties"] = additional_values[0]
    elif additional_values:
        merged["additionalProperties"] = True
    else:
        merged["additionalProperties"] = False
    merged["type"] = "object"
    if properties:
        merged["properties"] = properties
    if required:
        merged["required"] = sorted(required)
    for metadata_keyword in ("title", "description", "deprecated"):
        if metadata_keyword in schema:
            merged[metadata_keyword] = schema[metadata_keyword]
    if "default" in schema:
        merged["default"] = schema["default"]
    return merged


class CodeGenerator:
    def __init__(self, document: SchemaDocument, root_name: str) -> None:
        self.document = document
        self.root_name = pascal_name(root_name)
        self.plans: dict[str, TypePlan] = {}
        self.class_names: set[str] = set()
        self.function_names: set[str] = set()
        self.decoder_names: set[str] = set()
        self.root_plan = self.plan_for(document.root, "", self.root_name)

    def unique_class_name(self, preferred: str) -> str:
        name = pascal_name(preferred)
        candidate = name
        suffix = 2
        while candidate in self.class_names:
            candidate = f"{name}{suffix}"
            suffix += 1
        self.class_names.add(candidate)
        return candidate

    def unique_function_name(self, class_name: str) -> str:
        preferred = f"_decode_{snake_name(class_name)}"
        candidate = preferred
        suffix = 2
        while candidate in self.function_names:
            candidate = f"{preferred}_{suffix}"
            suffix += 1
        self.function_names.add(candidate)
        return candidate

    def unique_decoder_name(self, pointer: str) -> str:
        preferred = f"_decode_{snake_name(pointer.replace('/', '_'))}"
        candidate = preferred
        suffix = 2
        while candidate in self.decoder_names:
            candidate = f"{preferred}_{suffix}"
            suffix += 1
        self.decoder_names.add(candidate)
        return candidate

    def plan_for(self, schema: dict[str, Any], pointer: str, preferred_name: str) -> TypePlan:
        if pointer in self.plans:
            return self.plans[pointer]
        normalized = normalize_schema(schema, pointer)
        if "oneOf" in normalized and normalized.get("type") == "object":
            common_properties = normalized.get("properties", {})
            common_required = set(normalized.get("required", ()))
            merged_alternatives = []
            for index, alternative in enumerate(normalized["oneOf"]):
                if alternative.get("type") != "object":
                    raise schema_error(
                        f"{pointer}/oneOf/{index}",
                        "flattened object unions require object alternatives",
                    )
                properties = dict(alternative.get("properties", {}))
                conflicts = {
                    name
                    for name in set(properties) & set(common_properties)
                    if properties[name] != common_properties[name]
                }
                if conflicts:
                    raise schema_error(
                        f"{pointer}/oneOf/{index}",
                        f"flattened properties conflict: {sorted(conflicts)!r}",
                    )
                for name, property_schema in common_properties.items():
                    properties.setdefault(name, property_schema)
                merged = dict(alternative)
                merged["properties"] = properties
                required = set(alternative.get("required", ())) | common_required
                if required:
                    merged["required"] = sorted(required)
                merged_alternatives.append(merged)
            normalized = {
                key: value
                for key, value in normalized.items()
                if key not in {"type", "properties", "required", "additionalProperties"}
            }
            normalized["oneOf"] = merged_alternatives
        if "$ref" not in normalized and isinstance(normalized.get("title"), str) and normalized["title"]:
            preferred_name = normalized["title"]
        if "$ref" in normalized:
            target_schema, target_pointer = self.document.resolve(normalized["$ref"], pointer)
            if set(normalized) - {
                "$ref",
                "title",
                "description",
                "default",
                "deprecated",
            }:
                raise schema_error(pointer, "unsupported metadata wrapping a $ref")
            target_name = normalized["$ref"].rsplit("/", 1)[-1]
            target = self.plan_for(target_schema, target_pointer, target_name)
            self.plans[pointer] = target
            return target
        nullable, alternatives = self.type_alternatives(normalized, pointer)
        has_numeric_bounds = "minimum" in normalized or "maximum" in normalized
        if has_numeric_bounds and alternatives:
            if not nullable or len(alternatives) != 1 or alternatives[0].get("type") not in {
                "integer",
                "number",
            }:
                raise schema_error(
                    pointer,
                    "numeric bounds are supported only on a single numeric schema",
                )
            alternatives[0] = {
                **alternatives[0],
                **{
                    key: normalized[key]
                    for key in ("minimum", "maximum")
                    if key in normalized
                },
            }
        if alternatives:
            return self.union_plan(normalized, pointer, preferred_name, alternatives, nullable)
        if "enum" in normalized or "const" in normalized:
            return self.enum_plan(normalized, pointer, preferred_name)
        schema_types = normalized.get("type")
        if schema_types is None and (
            "properties" in normalized or "additionalProperties" in normalized
        ):
            schema_types = "object"
        if not isinstance(schema_types, str):
            raise schema_error(pointer, "schema must declare a type, enum, const, ref, or combinator")
        if schema_types == "object":
            return self.object_plan(normalized, pointer, preferred_name)
        if schema_types == "array":
            return self.array_plan(normalized, pointer, preferred_name)
        if schema_types not in {"string", "integer", "number", "boolean", "null"}:
            raise schema_error(pointer, f"unsupported JSON type {schema_types!r}")
        primitive_types = {
            "string": "str",
            "integer": "int",
            "number": "float",
            "boolean": "bool",
            "null": "None",
        }
        decoder = {
            "string": "_decode_string",
            "integer": "_decode_integer",
            "number": "_decode_number",
            "boolean": "_decode_boolean",
            "null": "_decode_null",
        }[schema_types]
        if has_numeric_bounds and schema_types not in {"integer", "number"}:
            raise schema_error(pointer, f"numeric bounds are unsupported for type {schema_types!r}")
        decoder_name = self.unique_decoder_name(pointer) if has_numeric_bounds else decoder
        plan = TypePlan(
            pointer,
            "primitive",
            normalized,
            primitive_types[schema_types],
            decoder_name,
            base_decoder_name=decoder,
            minimum=normalized.get("minimum"),
            maximum=normalized.get("maximum"),
        )
        self.plans[pointer] = plan
        return plan

    def type_alternatives(
        self, schema: dict[str, Any], pointer: str
    ) -> tuple[bool, list[dict[str, Any]]]:
        combinator_names = [name for name in ("anyOf", "oneOf") if name in schema]
        if len(combinator_names) > 1:
            raise schema_error(pointer, "anyOf and oneOf cannot be combined")
        if combinator_names and schema.get("type") not in (None, "null"):
            raise schema_error(pointer, f"schema type cannot be combined with {combinator_names[0]}")
        nullable = schema.get("type") == "null"
        alternatives: list[dict[str, Any]] = []
        if combinator_names:
            alternatives.extend(schema[combinator_names[0]])
        elif isinstance(schema.get("type"), list):
            type_values = schema["type"]
            seen_types: set[str] = set()
            nullable = "null" in type_values
            for type_value in type_values:
                if type_value == "null":
                    continue
                if type_value in seen_types:
                    raise schema_error(pointer, f"duplicate type {type_value!r}")
                seen_types.add(type_value)
                alternatives.append({"type": type_value})
        return nullable, alternatives

    def union_plan(
        self,
        schema: dict[str, Any],
        pointer: str,
        preferred_name: str,
        alternatives: list[dict[str, Any]],
        nullable: bool,
    ) -> TypePlan:
        plans = []
        for index, alternative in enumerate(alternatives):
            variant_name = f"{preferred_name}Variant{index + 1}"
            if isinstance(alternative, dict) and isinstance(alternative.get("title"), str):
                variant_name = alternative["title"]
            properties = alternative.get("properties", {}) if isinstance(alternative, dict) else {}
            result_tag = properties.get("result_type") if isinstance(properties, dict) else None
            if (
                "CodeQueryResultItem" in pointer
                and isinstance(result_tag, dict)
                and isinstance(result_tag.get("const"), str)
            ):
                variant_name = f"CodeQuery{pascal_name(result_tag['const'])}"
            plans.append(
                self.plan_for(
                    alternative,
                    f"{pointer}/union/{index}",
                    variant_name,
                )
            )
        type_parts = [plan.type_expression for plan in plans]
        if nullable:
            type_parts.append("None")
        type_expression = " | ".join(dict.fromkeys(type_parts))
        function_name = self.unique_decoder_name(pointer)
        plan = TypePlan(
            pointer,
            "union",
            schema,
            type_expression,
            function_name,
            class_name=preferred_name,
            union_plans=tuple(plans),
            nullable=nullable,
        )
        self.plans[pointer] = plan
        return plan

    def enum_plan(self, schema: dict[str, Any], pointer: str, preferred_name: str) -> TypePlan:
        if "const" in schema:
            values = [schema["const"]]
            kind = "const"
        else:
            values = schema["enum"]
            kind = "enum"
        seen: list[Any] = []
        for value in values:
            if isinstance(value, (list, dict)) or value is None:
                raise schema_error(pointer, f"unsupported {kind} value {value!r}")
            if value in seen:
                raise schema_error(pointer, f"duplicate {kind} value {value!r}")
            seen.append(value)
        class_name: str | None = None
        type_expression = "object"
        decoder_name = self.unique_decoder_name(pointer)
        if kind == "enum":
            class_name = self.unique_class_name(preferred_name)
            type_expression = class_name
        else:
            if isinstance(values[0], str):
                type_expression = "str"
            elif isinstance(values[0], bool):
                type_expression = "bool"
            elif isinstance(values[0], int):
                type_expression = "int"
            elif isinstance(values[0], float):
                type_expression = "float"
            else:
                raise schema_error(pointer, f"unsupported const value {values[0]!r}")
        plan = TypePlan(
            pointer,
            kind,
            schema,
            type_expression,
            decoder_name,
            class_name=class_name,
            enum_values=tuple(values),
        )
        self.plans[pointer] = plan
        return plan

    def object_plan(self, schema: dict[str, Any], pointer: str, preferred_name: str) -> TypePlan:
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties")
        if properties and isinstance(additional, dict):
            raise schema_error(
                pointer,
                "typed additionalProperties alongside declared properties is unsupported",
            )
        if not properties and isinstance(additional, dict):
            value_plan = self.plan_for(
                additional,
                f"{pointer}/additionalProperties",
                f"{preferred_name}Value",
            )
            plan = TypePlan(
                pointer,
                "map",
                schema,
                f"dict[str, {value_plan.type_expression}]",
                self.unique_decoder_name(pointer),
                map_plan=value_plan,
            )
            self.plans[pointer] = plan
            return plan
        class_name = self.unique_class_name(preferred_name)
        plan = TypePlan(pointer, "object", schema, class_name, self.unique_function_name(class_name), class_name)
        self.plans[pointer] = plan
        required = set(schema.get("required", ()))
        unknown = sorted(required - set(properties))
        if unknown:
            raise schema_error(pointer, f"required propert(y/ies) not defined: {', '.join(unknown)}")
        if schema.get("additionalProperties") is True:
            raise schema_error(pointer, "additionalProperties: true is incompatible with a typed dataclass")
        fields: list[tuple[str, str, str, bool, Any]] = []
        used_field_names: set[str] = set()
        for property_name, property_schema in properties.items():
            property_pointer = f"{pointer}/properties/{property_name}"
            property_plan = self.plan_for(
                property_schema,
                property_pointer,
                f"{class_name}{pascal_name(property_name)}",
            )
            required_property = property_name in required
            has_default = "default" in property_schema
            if not required_property and not has_default and "null" != property_plan.kind:
                nullable_type = "None" in property_plan.type_expression.split(" | ")
                if not nullable_type:
                    inferred_default: Any
                    if property_plan.kind in {"array", "tuple"}:
                        inferred_default = []
                    elif property_plan.kind == "map":
                        inferred_default = {}
                    elif property_plan.kind == "primitive" and property_plan.type_expression == "bool":
                        inferred_default = False
                    else:
                        raise schema_error(
                            property_pointer,
                            "optional property is neither nullable nor has an unambiguous wire default",
                        )
                    property_plan.schema["default"] = inferred_default
                    has_default = True
            field_name = python_field_name(property_name, used_field_names)
            fields.append(
                (
                    property_name,
                    field_name,
                    property_plan.type_expression,
                    required_property or has_default,
                    property_schema.get("default"),
                )
            )
        object_plan = TypePlan(
            pointer,
            "object",
            schema,
            class_name,
            plan.decoder_name,
            class_name=class_name,
            fields=tuple(fields),
        )
        self.plans[pointer] = object_plan
        return object_plan

    def array_plan(self, schema: dict[str, Any], pointer: str, preferred_name: str) -> TypePlan:
        prefix_items = schema.get("prefixItems")
        items = schema.get("items")
        if prefix_items is not None and items is not None:
            raise schema_error(pointer, "tuples with additional items are unsupported")
        function_name = self.unique_decoder_name(pointer)
        if prefix_items is not None:
            element_plans = tuple(
                self.plan_for(
                    item_schema,
                    f"{pointer}/prefixItems/{index}",
                    f"{preferred_name}Item{index + 1}",
                )
                for index, item_schema in enumerate(prefix_items)
            )
            type_expression = "tuple[" + ", ".join(plan.type_expression for plan in element_plans) + "]"
            kind = "tuple"
            item_plan = None
        else:
            if items is None:
                raise schema_error(pointer, "arrays must declare items")
            item_plan = self.plan_for(items, f"{pointer}/items", f"{preferred_name}Item")
            element_plans = ()
            type_expression = f"list[{item_plan.type_expression}]"
            kind = "array"
        plan = TypePlan(
            pointer,
            kind,
            schema,
            type_expression,
            function_name,
            item_plan=item_plan,
            element_plans=element_plans,
        )
        self.plans[pointer] = plan
        return plan

    @staticmethod
    def tag_on_object(schema: dict[str, Any]) -> tuple[str, Any] | None:
        tags: list[tuple[str, Any]] = []
        for property_name, property_schema in schema.get("properties", {}).items():
            if not isinstance(property_schema, dict) or "const" not in property_schema:
                continue
            tags.append((property_name, property_schema["const"]))
        if not tags:
            return None
        if len(tags) != 1:
            raise UnsupportedSchema(f"union variant has multiple const tags: {tags!r}")
        tag_name, tag_value = tags[0]
        if tag_name not in schema.get("required", ()):
            raise UnsupportedSchema(f"union discriminator {tag_name!r} is not required")
        return tag_name, tag_value

    def finish_union(self, plan: TypePlan) -> None:
        if plan.kind != "union":
            return
        variants: list[tuple[Any, TypePlan]] = []
        tags: set[str] = set()
        values: set[Any] = set()
        for variant_plan in plan.union_plans:
            if variant_plan.kind != "object":
                return
            identified = self.tag_on_object(variant_plan.schema)
            if identified is None:
                return
            tag_name, tag_value = identified
            if tags and tag_name not in tags:
                raise UnsupportedSchema(
                    f"{plan.pointer}: union variants use inconsistent discriminators {sorted(tags)!r}"
                )
            tags.add(tag_name)
            if tag_value in values:
                raise UnsupportedSchema(f"{plan.pointer}: duplicate discriminator {tag_value!r}")
            values.add(tag_value)
            variants.append((tag_value, variant_plan))
        tag_name = next(iter(tags))
        stripped_plans = []
        for variant_plan in plan.union_plans:
            fields = tuple(field for field in variant_plan.fields if field[0] != tag_name)
            stripped_plan = TypePlan(
                variant_plan.pointer,
                variant_plan.kind,
                variant_plan.schema,
                variant_plan.type_expression,
                variant_plan.decoder_name,
                class_name=variant_plan.class_name,
                enum_values=variant_plan.enum_values,
                fields=fields,
            )
            self.plans[variant_plan.pointer] = stripped_plan
            stripped_plans.append(stripped_plan)
        object_plan = TypePlan(
            plan.pointer,
            "union",
            plan.schema,
            plan.type_expression,
            plan.decoder_name,
            class_name=plan.class_name,
            union_plans=tuple(stripped_plans),
            union_variants=tuple(variants),
            tag=next(iter(tags)),
            tag_kind="internal_or_adjacent",
        )
        self.plans[plan.pointer] = object_plan


def python_literal(value: Any) -> str:
    if value is None or isinstance(value, (str, int, float, bool)):
        return repr(value)
    if isinstance(value, list):
        return "[" + ", ".join(python_literal(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{" + ", ".join(
            f"{python_literal(str(key))}: {python_literal(item)}" for key, item in value.items()
        ) + "}"
    raise UnsupportedSchema(f"unsupported default value {value!r}")


def emit_function(plan: TypePlan, generator: "CodeGenerator") -> str:
    if plan.kind == "object":
        return emit_object(plan, generator)
    if plan.kind in {"enum", "const"}:
        return emit_enum(plan)
    if plan.kind == "array":
        return emit_array(plan)
    if plan.kind == "map":
        return emit_map(plan)
    if plan.kind == "tuple":
        return emit_tuple(plan)
    if plan.kind == "union":
        canonical = generator.plans.get(plan.pointer)
        if canonical is not None and canonical is not plan and canonical.union_variants:
            return (
                f"def {plan.decoder_name}(value: Any, prefix: str = {plan.class_name!r}) -> {plan.type_expression}:\n"
                f"    return {canonical.decoder_name}(value, prefix)"
            )
        return emit_union(plan)
    if plan.kind == "primitive":
        return emit_primitive(plan)
    raise UnsupportedSchema(f"unsupported plan kind {plan.kind!r}")


def emit_object(plan: TypePlan, generator: "CodeGenerator") -> str:
    lines = [f"def {plan.decoder_name}(value: Any, prefix: str = {plan.class_name!r}) -> {plan.class_name}:"]
    lines.append("    if not isinstance(value, dict):")
    lines.append('        raise TypeDecoderError(f"{prefix}: expected object")')
    if plan.fields:
        lines.append("    expected = {")
        for property_name, _, _, _, _ in plan.fields:
            lines.append(f"        {property_name!r},")
        lines.append("    }")
    else:
        lines.append("    expected = set()")
    lines.append("    actual = set(value)")
    lines.append("    unexpected = actual - expected")
    lines.append("    if unexpected:")
    lines.append('        raise DecoderError(f"{prefix}: unexpected object keys: {sorted(unexpected)!r}")')
    required_fields = [
        field
        for field in plan.fields
        if field[3]
        and "default" not in generator.plans[f"{plan.pointer}/properties/{field[0]}"].schema
    ]
    if required_fields:
        lines.append("    required = {")
        for field in required_fields:
            lines.append(f"        {field[0]!r},")
        lines.append("    }")
    else:
        lines.append("    required = set()")
    lines.append("    missing = required - actual")
    lines.append("    if missing:")
    lines.append('        raise MissingKeyError(f"{prefix}: missing required keys: {sorted(missing)!r}")')
    arguments = []
    for property_name, field_name, _, required, default in plan.fields:
        property_plan = generator.plans[f"{plan.pointer}/properties/{property_name}"]
        if required and "default" not in property_plan.schema:
            lines.append(f"    {field_name}_value = {property_plan.decoder_name}(value[{property_name!r}], f\"{{prefix}}.{property_name}\")")
        elif "default" in property_plan.schema:
            default = python_literal(property_plan.schema["default"])
            lines.append(f"    if {property_name!r} in value:")
            lines.append(f"        {field_name}_value = {property_plan.decoder_name}(value[{property_name!r}], f\"{{prefix}}.{property_name}\")")
            lines.append("    else:")
            lines.append(f"        {field_name}_value = {property_plan.decoder_name}({default}, f\"{{prefix}}.{property_name}\")")
        else:
            lines.append(f"    if {property_name!r} in value:")
            lines.append(f"        {field_name}_value = {property_plan.decoder_name}(value[{property_name!r}], f\"{{prefix}}.{property_name}\")")
            lines.append("    else:")
            lines.append(f"        {field_name}_value = None")
        arguments.append(f"{field_name}={field_name}_value")
    lines.append(f"    return {plan.class_name}(")
    for argument in arguments:
        lines.append(f"        {argument},")
    lines.append("    )")
    return "\n".join(lines)


def emit_primitive(plan: TypePlan) -> str:
    assert plan.base_decoder_name is not None
    if plan.minimum is None and plan.maximum is None:
        return ""
    lines = [
        f"def {plan.decoder_name}(value: Any, prefix: str = {plan.type_expression!r}) -> {plan.type_expression}:",
        f"    value = {plan.base_decoder_name}(value, prefix)",
    ]
    if plan.minimum is not None:
        lines.append(f"    if value < {python_literal(plan.minimum)}:")
        lines.append('        raise DecoderError(f"{prefix}: value is below the minimum")')
    if plan.maximum is not None:
        lines.append(f"    if value > {python_literal(plan.maximum)}:")
        lines.append('        raise DecoderError(f"{prefix}: value is above the maximum")')
    lines.append("    return value")
    return "\n".join(lines)


def emit_enum(plan: TypePlan) -> str:
    if plan.kind == "const":
        expected = plan.enum_values[0]
        expected_repr = repr(expected)
        lines = [
            f"def {plan.decoder_name}(value: Any, prefix: str = \"const\") -> {plan.type_expression}:",
            f"    expected_repr = {expected_repr!r}",
        ]
        lines.append(f"    if value != {python_literal(expected)}:")
        lines.append(f'        raise DecoderError(f"{{prefix}}: expected {{expected_repr}}")')
        lines.append("    return value")
        return "\n".join(lines)
    values = ", ".join(python_literal(value) for value in plan.enum_values)
    values_repr = repr(list(plan.enum_values))
    lines = [
        f"def {plan.decoder_name}(value: Any, prefix: str = {plan.class_name!r}) -> {plan.class_name}:",
        f"    values_repr = {values_repr!r}",
    ]
    lines.append(f"    if value not in ({values}):")
    lines.append(f'        raise DecoderError(f"{{prefix}}: expected one of {{values_repr}}")')
    lines.append(f"    return {plan.class_name}(value)")
    return "\n".join(lines)


def emit_array(plan: TypePlan) -> str:
    item = plan.item_plan
    assert item is not None
    lines = [f"def {plan.decoder_name}(value: Any, prefix: str = \"array\") -> {plan.type_expression}:"]
    lines.append("    if not isinstance(value, list):")
    lines.append('        raise TypeDecoderError(f"{prefix}: expected array")')
    lines.append("    return [")
    lines.append(f"        {item.decoder_name}(item, f\"{{prefix}}[{{index}}]\")")
    lines.append("        for index, item in enumerate(value)")
    lines.append("    ]")
    return "\n".join(lines)


def emit_map(plan: TypePlan) -> str:
    assert plan.map_plan is not None
    value_plan = plan.map_plan
    lines = [f"def {plan.decoder_name}(value: Any, prefix: str = \"map\") -> {plan.type_expression}:"]
    lines.append("    if not isinstance(value, dict):")
    lines.append('        raise TypeDecoderError(f"{prefix}: expected map")')
    lines.append("    return {")
    lines.append("        _decode_string(key, f\"{prefix}.keys()\"):")
    lines.append(f"        {value_plan.decoder_name}(item, f\"{{prefix}}[{{key}}]\")")
    lines.append("        for key, item in value.items()")
    lines.append("    }")
    return "\n".join(lines)


def emit_tuple(plan: TypePlan) -> str:
    lines = [f"def {plan.decoder_name}(value: Any, prefix: str = \"tuple\") -> {plan.type_expression}:"]
    lines.append("    if not isinstance(value, list):")
    lines.append('        raise TypeDecoderError(f"{prefix}: expected array")')
    lines.append(f"    if len(value) != {len(plan.element_plans)}:")
    lines.append('        raise DecoderError(f"{prefix}: expected exact tuple length")')
    lines.append("    return tuple(")
    lines.append("        decoder(value[index], f\"{prefix}[{index}]\")")
    lines.append("        for index, decoder in enumerate((")
    for element in plan.element_plans:
        lines.append(f"            {element.decoder_name},")
    lines.append("        ))")
    lines.append("    )")
    return "\n".join(lines)


def emit_union(plan: TypePlan) -> str:
    if plan.union_variants:
        rendered_class = emit_union_class(plan)
        return (
            rendered_class
            + "\n\n"
            + f"def {plan.decoder_name}(value: Any, prefix: str = {plan.class_name!r}) -> {plan.type_expression}:\n"
            + f"    return {plan.class_name}.from_dict(value)"
        )
    lines = [f"def {plan.decoder_name}(value: Any, prefix: str = \"union\") -> {plan.type_expression}:"]
    lines.append("    errors = []")
    for variant in plan.union_plans:
        lines.append("    try:")
        lines.append(f"        return {variant.decoder_name}(value, prefix)")
        lines.append("    except DecoderError as error:")
        lines.append("        errors.append(str(error))")
    lines.append('    raise DecoderError(f"{prefix}: did not match any union variant: {' + "'; '.join(errors)" + '}")')
    return "\n".join(lines)


def emit_union_class(plan: TypePlan) -> str:
    class_name = plan.class_name
    assert class_name is not None
    tag = plan.tag
    assert tag is not None
    lines = [f"class {class_name}(metaclass=_TaggedUnionMeta):"]
    lines.append("    @classmethod")
    lines.append(f"    def from_dict(cls, data: Any) -> {class_name}:")
    lines.append("        if not isinstance(data, dict):")
    lines.append('            raise TypeDecoderError("expected tagged object")')
    lines.append(f"        if {tag!r} not in data:")
    lines.append(f'            raise DecoderError(f"missing discriminator {tag!r}")')
    lines.append(f"        tag_value = data[{tag!r}]")
    lines.append("        decoder = _" + snake_name(class_name) + "_decoders.get(tag_value)")
    lines.append("        if decoder is None:")
    lines.append('            raise DecoderError(f"unknown discriminator {tag_value!r}")')
    lines.append("        return decoder(data)")
    return "\n".join(lines)


def emit_dataclass(plan: TypePlan) -> str:
    assert plan.class_name is not None
    lines = [f"@dataclass(frozen=True)", f"class {plan.class_name}:"]
    if not plan.fields:
        lines.append("    pass")
        return "\n".join(lines)
    for _, field_name, field_type, _, _ in plan.fields:
        lines.append(f"    {field_name}: {field_type}")
    lines.append("")
    lines.append("    @classmethod")
    lines.append(f"    def from_dict(cls, data: Any) -> {plan.class_name}:")
    lines.append(f"        return {plan.decoder_name}(data, {plan.class_name!r})")
    return "\n".join(lines)


def emit_enum_class(plan: TypePlan) -> str:
    assert plan.class_name is not None
    enum_base = "StrEnum" if all(isinstance(value, str) for value in plan.enum_values) else "Enum"
    lines = [f"class {plan.class_name}({enum_base}):"]
    used_members: set[str] = set()
    for value in plan.enum_values:
        base = snake_name(str(value)).upper()
        if not base:
            base = "VALUE"
        if base[0].isdigit():
            base = f"VALUE_{base}"
        member = base
        suffix = 2
        while member in used_members or keyword.iskeyword(member):
            member = f"{base}_{suffix}"
            suffix += 1
        used_members.add(member)
        lines.append(f"    {member} = {python_literal(value)}")
    return "\n".join(lines)


def generate(root: Any, root_name: str) -> str:
    document = SchemaDocument(root)
    codegen = CodeGenerator(document, root_name)
    for plan in list(codegen.plans.values()):
        codegen.finish_union(plan)
    for pointer, plan in list(codegen.plans.items()):
        canonical = codegen.plans.get(plan.pointer)
        if canonical is not None:
            codegen.plans[pointer] = canonical
    codegen.root_plan = codegen.plans.get(codegen.root_plan.pointer, codegen.root_plan)
    if codegen.root_plan.kind == "union" and not codegen.root_plan.union_variants:
        raise UnsupportedSchema(
            f"{codegen.root_plan.pointer}: union variant has no serde discriminator"
        )
    class_plan_by_name = {}
    for plan in codegen.plans.values():
        if plan.class_name is not None and plan.class_name not in class_plan_by_name:
            class_plan_by_name[plan.class_name] = plan
    class_plans = list(class_plan_by_name.values())
    class_plans.sort(key=lambda plan: plan.class_name or "")
    enum_classes = [plan for plan in class_plans if plan.kind == "enum"]
    dataclasses = [plan for plan in class_plans if plan.kind == "object"]
    union_classes = [plan for plan in class_plans if plan.kind == "union"]
    function_plan_by_name = {}
    for plan in codegen.plans.values():
        needs_generated_decoder = plan.kind != "primitive" or (
            plan.minimum is not None or plan.maximum is not None
        )
        if needs_generated_decoder and plan.decoder_name not in function_plan_by_name:
            function_plan_by_name[plan.decoder_name] = plan
    functions = list(function_plan_by_name.values())
    functions.sort(key=lambda plan: plan.decoder_name)
    lines = [
        '"""Generated from a JSON Schema; do not edit."""',
        "",
        "from __future__ import annotations",
        "",
        "from dataclasses import dataclass",
        "from enum import Enum, StrEnum",
        "from typing import Any, Union",
        "",
        "",
        "class DecoderError(ValueError):",
        '    """A JSON value does not satisfy the generated schema."""',
        "",
        "",
        "class MissingKeyError(DecoderError, KeyError):",
        '    """A required JSON object key is absent."""',
        "",
        "",
        "class TypeDecoderError(DecoderError, TypeError):",
        '    """A JSON value has the wrong runtime type."""',
        "",
        "",
        "class _TaggedUnionMeta(type):",
        "    def __instancecheck__(cls, instance: Any) -> bool:",
        "        return isinstance(instance, cls._variant_types)",
        "",
        "",
        "def _decode_string(value: Any, prefix: str = \"string\") -> str:",
        "    if not isinstance(value, str):",
        '        raise TypeDecoderError(f"{prefix}: expected string")',
        "    return value",
        "",
        "",
        "def _decode_integer(value: Any, prefix: str = \"integer\") -> int:",
        "    if isinstance(value, bool) or not isinstance(value, int):",
        '        raise TypeDecoderError(f"{prefix}: expected integer")',
        "    return value",
        "",
        "",
        "def _decode_number(value: Any, prefix: str = \"number\") -> float:",
        "    if isinstance(value, bool) or not isinstance(value, (int, float)):",
        '        raise TypeDecoderError(f"{prefix}: expected number")',
        "    return value",
        "",
        "",
        "def _decode_boolean(value: Any, prefix: str = \"boolean\") -> bool:",
        "    if not isinstance(value, bool):",
        '        raise TypeDecoderError(f"{prefix}: expected boolean")',
        "    return value",
        "",
        "",
        "def _decode_null(value: Any, prefix: str = \"null\") -> None:",
        "    if value is not None:",
        '        raise TypeDecoderError(f"{prefix}: expected null")',
        "    return value",
        "",
        "",
        "def _decode_tagged_variant(decoder: Any, data: Any, tag: str, class_name: str) -> Any:",
        "    payload = {key: value for key, value in data.items() if key != tag}",
        "    return decoder(payload, class_name)",
        "",
    ]
    for plan in enum_classes:
        lines.extend(["", emit_enum_class(plan), ""])
    for plan in dataclasses:
        lines.extend(["", emit_dataclass(plan), ""])
    for plan in functions:
        emitted = emit_function(plan, codegen)
        if emitted:
            lines.extend([emitted, ""])
    lines.append("TAGGED_UNION_VARIANTS = {}")
    lines.append("")
    for plan in union_classes:
        assert plan.class_name is not None
        if not plan.union_variants:
            continue
        mapping_name = f"_{snake_name(plan.class_name)}_decoders"
        lines.append(f"{mapping_name} = {{")
        for tag_value, variant in plan.union_variants:
            lines.append(
                f"    {python_literal(tag_value)}: lambda data: _decode_tagged_variant("
                f"{variant.decoder_name}, data, {plan.tag!r}, {variant.class_name!r}),"
            )
        lines.append("}")
        variant_types = ", ".join(
            variant.class_name or "Any" for _, variant in plan.union_variants
        )
        lines.append(
            f"{plan.class_name}._variant_types = "
            + (f"({variant_types},)" if variant_types else "()")
        )
        lines.append(f"TAGGED_UNION_VARIANTS[{plan.class_name!r}] = (")
        lines.append(f"    {plan.tag!r},")
        lines.append("    {")
        for tag_value, variant in plan.union_variants:
            lines.append(f"        {tag_value!r}: {variant.class_name},")
        lines.append("    },")
        lines.append(")")
        lines.append("")
    result_item_union = next(
        (
            plan
            for plan in union_classes
            if {tag for tag, _ in plan.union_variants}
            >= {"structural_match", "configuration_fact"}
        ),
        None,
    )
    if result_item_union is not None:
        lines.append("CODE_QUERY_RESULT_ITEM_TYPES = {")
        for tag, variant in result_item_union.union_variants:
            lines.append(f"    {tag!r}: {variant.class_name},")
        lines.append("}")
        lines.append("")
    root_plan = codegen.root_plan
    if root_plan.kind == "union":
        root_union_members = [f'"{plan.type_expression}"' for plan in root_plan.union_plans]
        if root_plan.nullable:
            root_union_members.append('"None"')
        lines.append(f"Root = Union[{', '.join(root_union_members)}]")
    elif root_plan.type_expression.startswith(("dict[", "list[", "tuple[")) or " | " in root_plan.type_expression:
        lines.append(f'Root = "{root_plan.type_expression}"')
    else:
        lines.append(f"Root = {root_plan.type_expression}")
    lines.append("")
    return "\n".join(lines)


generator: CodeGenerator


def load_schema(input_path: Path | None) -> Any:
    if input_path is None:
        return json.load(sys.stdin)
    with input_path.open("r", encoding="utf-8") as source:
        return json.load(source)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, help="JSON Schema path (default: stdin)")
    parser.add_argument("--output", type=Path, required=True, help="generated Python path or - for stdout")
    parser.add_argument("--root-name", help="name of the root type (default: schema title)")
    parser.add_argument("--check", action="store_true", help="fail instead of writing stale output")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        schema = load_schema(args.input)
        root_name = args.root_name
        if root_name is None:
            title = schema.get("title") if isinstance(schema, dict) else None
            if not isinstance(title, str) or not title:
                raise UnsupportedSchema("root name required when schema has no title")
            root_name = title
        generated = generate(schema, root_name)
        if args.check:
            if args.output == Path("-"):
                raise ValueError("--check cannot compare stdout")
            if not args.output.exists() or args.output.read_text(encoding="utf-8") != generated:
                print(f"stale generated output: {args.output}", file=sys.stderr)
                return 1
        elif args.output == Path("-"):
            sys.stdout.write(generated)
        else:
            with args.output.open("w", encoding="utf-8", newline="\n") as destination:
                destination.write(generated)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
