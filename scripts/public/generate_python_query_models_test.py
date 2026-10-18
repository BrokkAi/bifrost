#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
GENERATOR = REPOSITORY_ROOT / "scripts/public/generate-python-query-models.py"

SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "QueryModels",
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "level": {"type": "integer", "default": 7},
        "note": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        "primary_mode": {"$ref": "#/$defs/SharedMode", "default": "second"},
        "secondary_mode": {"$ref": "#/$defs/SharedMode", "default": "third"},
        "required_mode": {"$ref": "#/$defs/SharedMode"},
        "definition_override_mode": {"$ref": "#/$defs/DefaultedMode", "default": "third"},
        "definition_required_mode": {"$ref": "#/$defs/DefaultedMode"},
        "definition_optional_mode": {"$ref": "#/$defs/DefaultedMode"},
        "definition_flag": {"$ref": "#/$defs/DefaultedFlag"},
        "default_note": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": None},
        "default_flag": {"$ref": "#/$defs/SharedFlag"},
        "required_flag": {"$ref": "#/$defs/SharedFlag"},
        "default_items": {"type": "array", "items": {"type": "string"}},
        "default_map": {"type": "object", "additionalProperties": {"type": "string"}},
        "entries": {"type": "array", "items": {"$ref": "#/$defs/Entry"}},
        "entries-by-name": {
            "type": "object",
            "additionalProperties": {"$ref": "#/$defs/Entry"},
        },
        "flattened": {
            "allOf": [
                {
                    "type": "object",
                    "properties": {"created": {"type": "boolean"}},
                    "required": ["created"],
                    "additionalProperties": False,
                },
                {
                    "type": "object",
                    "properties": {"timestamp": {"type": "string"}},
                    "required": ["timestamp"],
                    "additionalProperties": False,
                },
            ]
        },
    },
    "required": [
        "name", "level", "entries", "entries-by-name", "flattened", "required_mode", "default_note",
        "definition_required_mode", "required_flag",
    ],
    "additionalProperties": False,
    "$defs": {
        "SharedMode": {"type": "string", "enum": ["first", "second", "third"]},
        "DefaultedMode": {"type": "string", "enum": ["first", "second", "third"], "default": "second"},
        "DefaultedFlag": {"type": "boolean", "default": True},
        "SharedFlag": {"type": "boolean"},
        "Entry": {
            "title": "Entry",
            "oneOf": [
                {
                    "title": "Score",
                    "type": "object",
                    "properties": {
                        "kind": {"const": "score"},
                        "value": {"type": "integer"},
                        "direction": {
                            "title": "Direction",
                            "type": "string",
                            "enum": ["up", "down"],
                        },
                    },
                    "required": ["kind", "value", "direction"],
                    "additionalProperties": False,
                },
                {
                    "title": "Labels",
                    "type": "object",
                    "properties": {
                        "kind": {"const": "labels"},
                        "values": {
                            "type": "object",
                            "additionalProperties": {"type": "string"},
                        },
                    },
                    "required": ["kind", "values"],
                    "additionalProperties": False,
                },
            ],
        }
    },
}

DOCUMENT = {
    "name": "workspace",
    "required_mode": "first",
    "required_flag": True,
    "entries": [
        {"kind": "score", "value": 2, "direction": "up"},
        {"kind": "labels", "values": {"a": "b"}},
    ],
    "entries-by-name": {"main": {"kind": "score", "value": 9, "direction": "down"}},
    "flattened": {"created": True, "timestamp": "2026-09-21T00:00:00Z"},
}

ADJACENT_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Adjacent",
    "oneOf": [
        {
            "title": "Text",
            "type": "object",
            "properties": {
                "status": {"const": "text"},
                "content": {"type": "string"},
            },
            "required": ["status", "content"],
            "additionalProperties": False,
        },
        {
            "title": "Empty",
            "type": "object",
            "properties": {"status": {"const": "empty"}},
            "required": ["status"],
            "additionalProperties": False,
        },
    ],
}


def run_generator(schema: object, output: Path, check: bool = False) -> subprocess.CompletedProcess[str]:
    schema_path = output.with_suffix(".schema.json")
    schema_path.write_text(json.dumps(schema), encoding="utf-8")
    uv = shutil.which("uv")
    if uv is None:
        raise RuntimeError("uv is required to run the generator with the project's Python 3.12 floor")
    command = [
        uv,
        "run",
        "--no-project",
        "--python",
        "3.12",
        "python",
        str(GENERATOR),
        "--input",
        str(schema_path),
        "--output",
        str(output),
    ]
    if check:
        command.append("--check")
    environment = os.environ.copy()
    environment.setdefault("UV_CACHE_DIR", str(output.with_suffix(".uv-cache")))
    return subprocess.run(command, text=True, capture_output=True, check=False, env=environment)


def load_module(path: Path):
    spec = importlib.util.spec_from_file_location("generated_query_models", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class GeneratePythonQueryModelsTest(unittest.TestCase):
    def test_nullable_array_keeps_item_schema(self) -> None:
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "NullableArray",
            "type": "object",
            "properties": {
                "items": {
                    "type": ["array", "null"],
                    "items": {"type": "string"},
                }
            },
            "required": ["items"],
            "additionalProperties": False,
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "nullable_array_models.py"
            result = run_generator(schema, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            models = load_module(output)
            decoded = models.Root.from_dict({"items": ["a", "b"]})
            self.assertEqual(decoded.items, ["a", "b"])
            self.assertIsNone(models.Root.from_dict({"items": None}).items)
            with self.assertRaises(models.DecoderError):
                models.Root.from_dict({"items": [1]})

    def test_numeric_bounds_are_enforced_faithfully(self) -> None:
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "Bounds",
            "type": "object",
            "properties": {
                "formal_index": {"type": "integer", "minimum": 0},
                "ratio": {"type": "number", "minimum": 0, "maximum": 1},
            },
            "required": ["formal_index", "ratio"],
            "additionalProperties": False,
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "bounded_models.py"
            result = run_generator(schema, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            models = load_module(output)
            decoded = models.Root.from_dict({"formal_index": 0, "ratio": 1.0})
            self.assertEqual(decoded.formal_index, 0)
            self.assertEqual(decoded.ratio, 1.0)
            with self.assertRaises(models.DecoderError):
                models.Root.from_dict({"formal_index": -1, "ratio": 1.0})
            with self.assertRaises(models.DecoderError):
                models.Root.from_dict({"formal_index": 0, "ratio": -0.1})
            with self.assertRaises(models.DecoderError):
                models.Root.from_dict({"formal_index": 0, "ratio": 1.1})

    def test_nullable_integer_array_preserves_items_and_unsigned_bounds(self) -> None:
        # Hard-won #4676: Rust's nullable tuple_return_arities schema lost its
        # items contract when the generator expanded the type array.
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "TupleReturnArities",
            "type": "object",
            "properties": {
                "tuple_return_arities": {
                    "type": ["array", "null"],
                    "items": {"type": "integer", "format": "uint64", "minimum": 0},
                },
            },
            "required": ["tuple_return_arities"],
            "additionalProperties": False,
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "nullable_array_models.py"
            result = run_generator(schema, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            models = load_module(output)
            for value in (None, [], [0, 2, 3]):
                decoded = models.Root.from_dict({"tuple_return_arities": value})
                self.assertEqual(decoded.tuple_return_arities, value)
            for value in ([-1], [True], [1.5], ["2"], "2"):
                with self.subTest(value=value), self.assertRaises(models.DecoderError):
                    models.Root.from_dict({"tuple_return_arities": value})

    def test_nullable_containers_and_bounded_primitives_keep_sibling_keywords(self) -> None:
        # A `type: [X, "null"]` node carries its qualifiers (items, minimum, ...)
        # as siblings of `type`, and they apply to the concrete alternative.
        # Dropping them made a nullable array lose its element schema, so the
        # generator aborted the whole run with "arrays must declare items" and
        # the checked-in models could not be regenerated.
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "Nullable",
            "type": "object",
            "properties": {
                "comment_block_lines": {
                    "type": ["array", "null"],
                    "items": {"type": "string"},
                },
                "formal_index": {"type": ["integer", "null"], "minimum": 0},
            },
            "required": ["comment_block_lines", "formal_index"],
            "additionalProperties": False,
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "nullable_models.py"
            result = run_generator(schema, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            models = load_module(output)
            decoded = models.Root.from_dict(
                {"comment_block_lines": ["a", "b"], "formal_index": 3}
            )
            self.assertEqual(decoded.comment_block_lines, ["a", "b"])
            self.assertEqual(decoded.formal_index, 3)
            nulls = models.Root.from_dict(
                {"comment_block_lines": None, "formal_index": None}
            )
            self.assertIsNone(nulls.comment_block_lines)
            self.assertIsNone(nulls.formal_index)
            with self.assertRaises(models.DecoderError):
                models.Root.from_dict(
                    {"comment_block_lines": [1], "formal_index": 3}
                )
            with self.assertRaises(models.DecoderError):
                models.Root.from_dict(
                    {"comment_block_lines": ["a"], "formal_index": -1}
                )

    def test_generate_decode_determinism_and_check(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "generated_models.py"
            first = run_generator(SCHEMA, output)
            self.assertEqual(first.returncode, 0, first.stderr)
            generated = output.read_text(encoding="utf-8")
            second = run_generator(SCHEMA, output)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(output.read_text(encoding="utf-8"), generated)

            output.write_text(generated + "\n# stale\n", encoding="utf-8")
            stale = run_generator(SCHEMA, output, check=True)
            self.assertEqual(stale.returncode, 1)
            self.assertIn("stale generated output", stale.stderr)
            self.assertIn(f"--- {output}\n", stale.stderr)
            self.assertIn(f"+++ {output} (generated)\n", stale.stderr)
            self.assertIn("-# stale\n", stale.stderr)
            self.assertEqual(output.read_text(encoding="utf-8"), generated + "\n# stale\n")

            output.write_text(generated, encoding="utf-8")
            current = run_generator(SCHEMA, output, check=True)
            self.assertEqual(current.returncode, 0, current.stderr)

            models = load_module(output)
            decoded = models.Root.from_dict(DOCUMENT)
            self.assertEqual(decoded.name, "workspace")
            self.assertEqual(decoded.level, 7)
            # #5687: shared $ref plans lost property defaults or leaked them to required fields.
            self.assertIs(decoded.primary_mode, models.SharedMode.SECOND)
            self.assertIs(decoded.secondary_mode, models.SharedMode.THIRD)
            self.assertIs(decoded.required_mode, models.SharedMode.FIRST)
            self.assertIs(decoded.definition_required_mode, models.DefaultedMode.SECOND)
            self.assertIs(decoded.definition_optional_mode, models.DefaultedMode.SECOND)
            self.assertIs(decoded.definition_override_mode, models.DefaultedMode.THIRD)
            self.assertIs(decoded.definition_flag, True)
            self.assertIs(decoded.required_flag, True)
            self.assertIsNone(decoded.default_note)
            self.assertIs(decoded.default_flag, False)
            self.assertEqual(decoded.default_items, [])
            self.assertEqual(decoded.default_map, {})
            overridden = models.Root.from_dict(
                {**DOCUMENT, "primary_mode": "third", "secondary_mode": "second"}
            )
            self.assertIs(overridden.primary_mode, models.SharedMode.THIRD)
            self.assertIs(overridden.secondary_mode, models.SharedMode.SECOND)
            for field in ("required_mode", "required_flag"):
                missing_required = dict(DOCUMENT)
                del missing_required[field]
                with self.subTest(missing=field):
                    with self.assertRaises(models.MissingKeyError):
                        models.Root.from_dict(missing_required)
            for field in (
                "primary_mode", "secondary_mode", "required_mode", "definition_required_mode",
                "definition_optional_mode", "definition_override_mode",
            ):
                for invalid in (None, "invalid", 17):
                    with self.subTest(field=field, invalid=invalid):
                        with self.assertRaises(models.DecoderError):
                            models.Root.from_dict({**DOCUMENT, field: invalid})
            self.assertIsNone(decoded.note)
            # Hard-won: canonical Rust PythonRuleFact emitted owner_id=null,
            # which the generated nullable-string decoder rejected.
            self.assertIsNone(models.Root.from_dict({**DOCUMENT, "note": None}).note)
            self.assertEqual(models.Root.from_dict({**DOCUMENT, "note": "kept"}).note, "kept")
            with self.assertRaises(models.DecoderError):
                models.Root.from_dict({**DOCUMENT, "note": 17})
            self.assertEqual(len(decoded.entries), 2)
            self.assertIsInstance(decoded.entries[0], models.Score)
            self.assertEqual(decoded.entries[0].direction, models.Direction.UP)
            self.assertIsInstance(decoded.entries[1], models.Labels)
            self.assertEqual(decoded.entries[1].values, {"a": "b"})
            self.assertEqual(decoded.entries_by_name["main"].value, 9)
            self.assertEqual(decoded.flattened.created, True)
            self.assertEqual(decoded.flattened.timestamp, "2026-09-21T00:00:00Z")
            with self.assertRaises(Exception):
                decoded.name = "immutable"

    def test_adjacent_serde_tags_dispatch_without_exposing_tag_field(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "adjacent_models.py"
            result = run_generator(ADJACENT_SCHEMA, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            models = load_module(output)
            text = models.Adjacent.from_dict({"status": "text", "content": "body"})
            empty = models.Adjacent.from_dict({"status": "empty"})
            self.assertEqual(text.content, "body")
            self.assertEqual(empty.__class__.__name__, "Empty")
            self.assertNotIn("status", text.__dataclass_fields__)

    def test_recursive_tagged_union_uses_discriminator_at_every_depth(self) -> None:
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "RecursiveRoot",
            "type": "object",
            "properties": {"node": {"$ref": "#/$defs/Recursive"}},
            "required": ["node"],
            "additionalProperties": False,
            "$defs": {
                "Recursive": {
                    "title": "Recursive",
                    "oneOf": [
                        {
                            "title": "Leaf",
                            "type": "object",
                            "properties": {
                                "kind": {"const": "leaf"},
                                "value": {"type": "string"},
                            },
                            "required": ["kind", "value"],
                            "additionalProperties": False,
                        },
                        {
                            "title": "Branch",
                            "type": "object",
                            "properties": {
                                "kind": {"const": "branch"},
                                "child": {"$ref": "#/$defs/Recursive"},
                            },
                            "required": ["kind", "child"],
                            "additionalProperties": False,
                        },
                    ],
                }
            },
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "recursive_models.py"
            result = run_generator(schema, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            models = load_module(output)
            decoded = models.RecursiveRoot.from_dict(
                {
                    "node": {
                        "kind": "branch",
                        "child": {"kind": "leaf", "value": "done"},
                    }
                }
            )
            self.assertIsInstance(decoded.node, models.Branch)
            self.assertIsInstance(decoded.node.child, models.Leaf)
            self.assertEqual(decoded.node.child.value, "done")

    def test_reject_unsupported_schema_constructs_explicitly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "invalid_models.py"
            constrained = run_generator({"title": "Invalid", "type": "string", "pattern": "a"}, output)
            self.assertEqual(constrained.returncode, 2)
            self.assertIn("unsupported keyword(s): pattern", constrained.stderr)

            untagged = run_generator(
                {
                    "title": "Untagged",
                    "oneOf": [
                        {"type": "object", "properties": {}, "additionalProperties": False},
                        {"type": "object", "properties": {}, "additionalProperties": False},
                    ],
                },
                output,
            )
            self.assertEqual(untagged.returncode, 2)
            self.assertIn("has no serde discriminator", untagged.stderr)

            mixed_map = run_generator(
                {
                    "title": "MixedMap",
                    "type": "object",
                    "properties": {"fixed": {"type": "string"}},
                    "required": ["fixed"],
                    "additionalProperties": {"type": "integer"},
                },
                output,
            )
            self.assertEqual(mixed_map.returncode, 2)
            self.assertIn(
                "typed additionalProperties alongside declared properties is unsupported",
                mixed_map.stderr,
            )


if __name__ == "__main__":
    unittest.main()
