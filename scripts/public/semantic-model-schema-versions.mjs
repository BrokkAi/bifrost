#!/usr/bin/env node

// Read the semantic-model schema versions a reader accepts.
//
// The package check verifies that every supported version except schema seven
// ships a published JSON Schema resource. The source of truth is a Rust const
// list whose entries may name other u32 constants, so a version is defined
// once. Resolve those names here instead of duplicating their values in the
// check.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SUPPORTED_SCHEMA_VERSIONS_DECLARATION =
  /pub const SEMANTIC_MODEL_SUPPORTED_SCHEMA_VERSIONS: &\[u32\]\s*=\s*&\[([\s\S]*?)\];/u;
const U32_CONSTANT_DECLARATION =
  /^[ \t]*(?:pub(?:\([^)]*\))?\s+)?const\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*u32\s*=\s*([^;]+);/gmu;
const DECIMAL_LITERAL = /^\d[\d_]*$/u;
const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/u;

function parseU32(literal, description) {
  const value = Number(literal.replaceAll("_", ""));
  if (!Number.isInteger(value) || value < 0 || value > 4294967295) {
    throw new Error(`${description} is not a u32: ${literal}`);
  }
  return value;
}

function resolveEntry(entry, constants, resolving) {
  if (DECIMAL_LITERAL.test(entry)) {
    return parseU32(entry, "SEMANTIC_MODEL_SUPPORTED_SCHEMA_VERSIONS entry");
  }
  if (!IDENTIFIER.test(entry)) {
    throw new Error(`unsupported SEMANTIC_MODEL_SUPPORTED_SCHEMA_VERSIONS entry: ${entry}`);
  }
  if (resolving.includes(entry)) {
    throw new Error(`cyclic u32 constant reference: ${[...resolving, entry].join(" -> ")}`);
  }
  const expression = constants.get(entry);
  if (expression === undefined) {
    throw new Error(`cannot resolve ${entry} in SEMANTIC_MODEL_SUPPORTED_SCHEMA_VERSIONS`);
  }
  return resolveEntry(expression, constants, [...resolving, entry]);
}

export function readSupportedSemanticModelSchemaVersions(source) {
  const declaration = SUPPORTED_SCHEMA_VERSIONS_DECLARATION.exec(source);
  if (declaration === null) {
    throw new Error("cannot read SEMANTIC_MODEL_SUPPORTED_SCHEMA_VERSIONS");
  }

  const constants = new Map();
  for (const match of source.matchAll(U32_CONSTANT_DECLARATION)) {
    const [, name, expression] = match;
    if (constants.has(name)) {
      throw new Error(`duplicate u32 constant ${name} in semantic-model schema source`);
    }
    constants.set(name, expression.replace(/\/\/[^\n]*/gu, "").trim());
  }

  const versions = declaration[1]
    .replace(/\/\/[^\n]*/gu, "")
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0)
    .map((entry) => resolveEntry(entry, constants, []));
  if (versions.length === 0) {
    throw new Error("supported semantic-model schema versions must not be empty");
  }
  return versions;
}

function main(args) {
  if (args.length !== 1) {
    throw new Error(
      "Usage: node scripts/public/semantic-model-schema-versions.mjs <semantic-model model.rs>",
    );
  }
  const versions = readSupportedSemanticModelSchemaVersions(fs.readFileSync(args[0], "utf8"));
  // Schema seven has no published JSON Schema resource, so the package check
  // must not require one for it.
  console.log(versions.filter((version) => version !== 7).join(" "));
}

const thisFile = fileURLToPath(import.meta.url);
if (process.argv[1] && path.resolve(process.argv[1]) === thisFile) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
