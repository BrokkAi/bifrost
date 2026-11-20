import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { readSupportedSemanticModelSchemaVersions } from "./semantic-model-schema-versions.mjs";

const MODEL_SOURCE = new URL(
  "../../crates/bifrost-semantic/src/analyzer/semantic_model/model.rs",
  import.meta.url,
);

test("reads a list of numeric literals", () => {
  const source = `
pub const SEMANTIC_MODEL_SUPPORTED_SCHEMA_VERSIONS: &[u32] = &[
    2, 3, 4,
];
`;
  assert.deepEqual(readSupportedSemanticModelSchemaVersions(source), [2, 3, 4]);
});

test("resolves named constants declared before and after the list", () => {
  const source = `
pub const METHOD_TYPE_PARAMETER_BOUNDS_MIN_SCHEMA_VERSION: u32 = 41;
pub const SEMANTIC_MODEL_SUPPORTED_SCHEMA_VERSIONS: &[u32] = &[
    2, // schema two
    3,
    METHOD_TYPE_PARAMETER_BOUNDS_MIN_SCHEMA_VERSION,
    CLASS_FINALITY_MIN_SCHEMA_VERSION,
];
pub const CLASS_FINALITY_MIN_SCHEMA_VERSION: u32 = 43; // schema forty-three
`;
  assert.deepEqual(readSupportedSemanticModelSchemaVersions(source), [2, 3, 41, 43]);
});

test("resolves a constant that names another constant", () => {
  const source = `
pub const BASE_SCHEMA_VERSION: u32 = 41;
pub const LATEST_SCHEMA_VERSION: u32 = BASE_SCHEMA_VERSION;
pub const SEMANTIC_MODEL_SUPPORTED_SCHEMA_VERSIONS: &[u32] = &[
    LATEST_SCHEMA_VERSION,
];
`;
  assert.deepEqual(readSupportedSemanticModelSchemaVersions(source), [41]);
});

test("an unresolved constant fails the check", () => {
  const source = `
pub const SEMANTIC_MODEL_SUPPORTED_SCHEMA_VERSIONS: &[u32] = &[
    MISSING_SCHEMA_VERSION,
];
`;
  assert.throws(
    () => readSupportedSemanticModelSchemaVersions(source),
    /cannot resolve MISSING_SCHEMA_VERSION/u,
  );
});

test("the repository declaration parses after named constants entered the list", () => {
  const versions = readSupportedSemanticModelSchemaVersions(readFileSync(MODEL_SOURCE, "utf8"));
  assert.ok(versions.length > 0);
});
