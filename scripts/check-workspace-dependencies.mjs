#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const FACADE = "brokk-bifrost";
const CORE = "brokk-bifrost-core";
const CPP = "brokk-bifrost-cpp";
const CSHARP = "brokk-bifrost-csharp";
const GO = "brokk-bifrost-go";
const JS_TS = "brokk-bifrost-js-ts";
const JVM = "brokk-bifrost-jvm";
const PHP = "brokk-bifrost-php";
const PYTHON = "brokk-bifrost-python";
const RUBY = "brokk-bifrost-ruby";
const RUST = "brokk-bifrost-rust";
const ANALYSIS = "brokk-bifrost-analysis";
const NLP = "brokk-bifrost-nlp";
const POLICY = "brokk-bifrost-policy";
const RUNTIME = "brokk-bifrost-runtime";
const MCP = "brokk-bifrost-mcp";
const LSP = "brokk-bifrost-lsp";
const SEMANTIC_PACKS = "brokk-bifrost-semantic-packs";

const EXPECTED_MEMBERS = new Set([
  FACADE,
  CORE,
  CPP,
  CSHARP,
  GO,
  JS_TS,
  JVM,
  PHP,
  PYTHON,
  RUBY,
  RUST,
  ANALYSIS,
  NLP,
  POLICY,
  RUNTIME,
  MCP,
  LSP,
  SEMANTIC_PACKS,
]);
// Core is the bottom of the graph and depends on no workspace package; the
// analysis crate sits directly on it. The per-language crates (cpp, csharp, go,
// jvm, php, python, ruby, rust) sit between the two and depend on core alone -- that is what keeps a
// language's knowledge out of the analysis compilation unit. `jvm` is one crate
// for Java, Scala and Kotlin because the JVM source realm makes their routes
// mutually dependent and all three share one `JvmAnalyzerConfig`; `js-ts` is one
// crate for JavaScript and TypeScript for the same reason -- one module, one
// `EdgePassId`, one usage strategy and one `JsTsAnalyzerConfig`. Policy and nlp sit directly
// on analysis as siblings (#1548) so that neither can be pulled into the
// analysis compilation unit again.
const ALLOWED_WORKSPACE_DEPENDENCIES = new Map([
  [CORE, new Set()],
  [CPP, new Set([CORE])],
  [CSHARP, new Set([CORE])],
  [GO, new Set([CORE])],
  [JS_TS, new Set([CORE])],
  [JVM, new Set([CORE])],
  [PHP, new Set([CORE])],
  [PYTHON, new Set([CORE])],
  [RUBY, new Set([CORE])],
  [RUST, new Set([CORE])],
  [ANALYSIS, new Set([CORE, CPP, CSHARP, GO, JS_TS, JVM, PHP, PYTHON, RUBY, RUST])],
  [NLP, new Set([ANALYSIS])],
  [POLICY, new Set([ANALYSIS])],
  [SEMANTIC_PACKS, new Set([ANALYSIS])],
  [RUNTIME, new Set([ANALYSIS, POLICY])],
  [MCP, new Set([ANALYSIS, NLP, POLICY, RUNTIME])],
  [LSP, new Set([ANALYSIS, POLICY, RUNTIME])],
  [FACADE, new Set([ANALYSIS, NLP, POLICY, RUNTIME, MCP, LSP, SEMANTIC_PACKS])],
]);
const REQUIRED_WORKSPACE_DEPENDENCIES = new Map([
  [CORE, new Set()],
  [CPP, new Set([CORE])],
  [CSHARP, new Set([CORE])],
  [GO, new Set([CORE])],
  [JS_TS, new Set([CORE])],
  [JVM, new Set([CORE])],
  [PHP, new Set([CORE])],
  [PYTHON, new Set([CORE])],
  [RUBY, new Set([CORE])],
  [RUST, new Set([CORE])],
  [ANALYSIS, new Set([CORE, CPP, CSHARP, GO, JS_TS, JVM, PHP, PYTHON, RUBY, RUST])],
  [NLP, new Set([ANALYSIS])],
  [POLICY, new Set([ANALYSIS])],
  [SEMANTIC_PACKS, new Set([ANALYSIS])],
  [RUNTIME, new Set([ANALYSIS, POLICY])],
  [MCP, new Set([ANALYSIS, POLICY, RUNTIME])],
  [LSP, new Set([ANALYSIS, POLICY, RUNTIME])],
  [FACADE, new Set()],
]);
const FORBIDDEN_EXTERNAL_DEPENDENCIES = new Map([
  // hf-hub/tokenizers/fastrq are listed here on purpose: #1548 moved the
  // embedding stack out so that enabling semantic search stops invalidating the
  // workspace's largest compilation unit. If any of them reappears here, that
  // property is silently lost, so fail the check instead. Core inherits the
  // same ban: it is below analysis, so anything forbidden there is worse here.
  [
    CORE,
    new Set(["lsp-server", "lsp-types", "pyo3", "hf-hub", "tokenizers", "fastrq"]),
  ],
  [
    CPP,
    new Set(["lsp-server", "lsp-types", "pyo3", "hf-hub", "tokenizers", "fastrq"]),
  ],
  [
    CSHARP,
    new Set(["lsp-server", "lsp-types", "pyo3", "hf-hub", "tokenizers", "fastrq"]),
  ],
  [
    GO,
    new Set(["lsp-server", "lsp-types", "pyo3", "hf-hub", "tokenizers", "fastrq"]),
  ],
  [
    JS_TS,
    new Set(["lsp-server", "lsp-types", "pyo3", "hf-hub", "tokenizers", "fastrq"]),
  ],
  [
    JVM,
    new Set(["lsp-server", "lsp-types", "pyo3", "hf-hub", "tokenizers", "fastrq"]),
  ],
  [
    PHP,
    new Set(["lsp-server", "lsp-types", "pyo3", "hf-hub", "tokenizers", "fastrq"]),
  ],
  [
    PYTHON,
    new Set(["lsp-server", "lsp-types", "pyo3", "hf-hub", "tokenizers", "fastrq"]),
  ],
  [
    RUBY,
    new Set(["lsp-server", "lsp-types", "pyo3", "hf-hub", "tokenizers", "fastrq"]),
  ],
  [
    RUST,
    new Set(["lsp-server", "lsp-types", "pyo3", "hf-hub", "tokenizers", "fastrq"]),
  ],
  [
    ANALYSIS,
    new Set(["lsp-server", "lsp-types", "pyo3", "hf-hub", "tokenizers", "fastrq"]),
  ],
  [NLP, new Set(["lsp-server", "lsp-types", "pyo3"])],
  [POLICY, new Set(["lsp-server", "lsp-types", "pyo3"])],
  [SEMANTIC_PACKS, new Set(["lsp-server", "lsp-types", "pyo3"])],
  [RUNTIME, new Set(["lsp-server", "lsp-types", "pyo3"])],
  [MCP, new Set(["lsp-server", "lsp-types", "pyo3"])],
  [LSP, new Set(["pyo3"])],
  [FACADE, new Set()],
]);

function sorted(values) {
  return [...values].sort();
}

export function validateWorkspaceGraph(metadata) {
  const packagesById = new Map(metadata.packages.map((pkg) => [pkg.id, pkg]));
  const members = metadata.workspace_members.map((id) => packagesById.get(id)).filter(Boolean);
  const memberNames = new Set(members.map((pkg) => pkg.name));
  const errors = [];

  for (const missing of sorted([...EXPECTED_MEMBERS].filter((name) => !memberNames.has(name)))) {
    errors.push(`missing workspace package ${missing}`);
  }
  for (const unexpected of sorted([...memberNames].filter((name) => !EXPECTED_MEMBERS.has(name)))) {
    errors.push(`unexpected workspace package ${unexpected}`);
  }

  const facade = members.find((pkg) => pkg.name === FACADE);
  if (!facade) {
    return errors;
  }

  for (const pkg of members) {
    if (pkg.version !== facade.version) {
      errors.push(
        `${pkg.name} version ${pkg.version} does not match facade version ${facade.version}`,
      );
    }

    const allowed = ALLOWED_WORKSPACE_DEPENDENCIES.get(pkg.name) ?? new Set();
    const required = REQUIRED_WORKSPACE_DEPENDENCIES.get(pkg.name) ?? new Set();
    const forbiddenExternal = FORBIDDEN_EXTERNAL_DEPENDENCIES.get(pkg.name) ?? new Set();
    const workspaceDependencies = new Set(
      pkg.dependencies
        .map((dependency) => dependency.name)
        .filter((name) => EXPECTED_MEMBERS.has(name)),
    );
    const missingDependencies = [...required].filter(
      (name) => !workspaceDependencies.has(name),
    );
    for (const missing of sorted(missingDependencies)) {
      errors.push(`${pkg.name} must depend on workspace package ${missing}`);
    }
    for (const dependency of pkg.dependencies) {
      if (EXPECTED_MEMBERS.has(dependency.name) && !allowed.has(dependency.name)) {
        errors.push(`${pkg.name} must not depend on workspace package ${dependency.name}`);
      }
      if (
        EXPECTED_MEMBERS.has(dependency.name) &&
        allowed.has(dependency.name) &&
        dependency.req !== `=${facade.version}`
      ) {
        errors.push(
          `${pkg.name} dependency on ${dependency.name} must require exactly =${facade.version}`,
        );
      }
      if (forbiddenExternal.has(dependency.name)) {
        errors.push(`${pkg.name} must not depend on host-specific package ${dependency.name}`);
      }
    }
  }

  return errors;
}

function readMetadata() {
  const result = spawnSync("cargo", ["metadata", "--no-deps", "--format-version", "1"], {
    encoding: "utf8",
  });
  if (result.status !== 0) {
    process.stderr.write(result.stderr);
    throw new Error(`cargo metadata exited with status ${result.status ?? "unknown"}`);
  }
  return JSON.parse(result.stdout);
}

function main() {
  const errors = validateWorkspaceGraph(readMetadata());
  if (errors.length > 0) {
    for (const error of errors) {
      console.error(`workspace dependency error: ${error}`);
    }
    process.exitCode = 1;
    return;
  }
  console.log("workspace dependency graph is valid");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
