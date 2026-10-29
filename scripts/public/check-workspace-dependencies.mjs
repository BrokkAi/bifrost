#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { closeSync, mkdtempSync, openSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
const SEMANTIC = "brokk-bifrost-semantic";
const JVM_ANALYSIS = "brokk-bifrost-jvm-analysis";
const STORE = "brokk-bifrost-store";
const ANALYSIS = "brokk-bifrost-analysis";
const RUST_ANALYSIS = "brokk-bifrost-rust-analysis";
const GO_ANALYSIS = "brokk-bifrost-go-analysis";
const PYTHON_ANALYSIS = "brokk-bifrost-python-analysis";
const CSHARP_ANALYSIS = "brokk-bifrost-csharp-analysis";
const PHP_ANALYSIS = "brokk-bifrost-php-analysis";
const CPP_ANALYSIS = "brokk-bifrost-cpp-analysis";
const JS_TS_ANALYSIS = "brokk-bifrost-js-ts-analysis";
const RUBY_ANALYSIS = "brokk-bifrost-ruby-analysis";
const TOOLS = "brokk-bifrost-tools";
const FLOW = "brokk-bifrost-flow";
const RQL = "brokk-bifrost-rql";
const POLICY = "brokk-bifrost-policy";
const RUNTIME = "brokk-bifrost-runtime";
const MCP = "brokk-bifrost-mcp";
const SEMANTIC_PACKS = "brokk-bifrost-semantic-packs";
const TEST_MACROS = "brokk-bifrost-test-macros";
const WORKSPACE_HACK = "workspace-hack";

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
  SEMANTIC,
  STORE,
  ANALYSIS,
  JVM_ANALYSIS,
  GO_ANALYSIS,
  RUST_ANALYSIS,
  PYTHON_ANALYSIS,
  CSHARP_ANALYSIS,
  PHP_ANALYSIS,
  CPP_ANALYSIS,
  RUBY_ANALYSIS,
  JS_TS_ANALYSIS,
  TOOLS,
  FLOW,
  RQL,
  POLICY,
  RUNTIME,
  MCP,
  SEMANTIC_PACKS,
  TEST_MACROS,
  WORKSPACE_HACK,
]);
// Core is the bottom of the graph. Language knowledge crates depend on core
// alone; the shared analysis engine sits above those crates. Extracted language
// implementation crates (such as ruby-analysis) sit ABOVE the engine and depend
// on it plus their own knowledge crate. Tools assembles the implementations.
// Flow owns solvers above analysis; RQL owns query execution above flow; policy
// composes analysis, flow and RQL. JVM and JS/TS each share a knowledge crate
// because their languages share a source realm and analyzer configuration.
const ALLOWED_WORKSPACE_DEPENDENCIES = new Map([
  [JVM_ANALYSIS, new Set([CORE, SEMANTIC, ANALYSIS, JVM])],
  [STORE, new Set([
    CORE,
    SEMANTIC,
    "brokk-bifrost-cpp",
    "brokk-bifrost-csharp",
    "brokk-bifrost-go",
    "brokk-bifrost-js-ts",
    "brokk-bifrost-jvm",
    "brokk-bifrost-php",
    "brokk-bifrost-python",
    "brokk-bifrost-ruby",
    "brokk-bifrost-rust",
  ])],
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
  [SEMANTIC, new Set([CORE, CPP, CSHARP, GO, JS_TS, JVM, PHP, PYTHON, RUBY, RUST])],
  [ANALYSIS, new Set([CORE, SEMANTIC, STORE, CPP, CSHARP, GO, JS_TS, JVM, PHP, PYTHON, RUBY, RUST])],
  [GO_ANALYSIS, new Set([CORE, SEMANTIC, ANALYSIS, GO])],
  [CPP_ANALYSIS, new Set([CORE, ANALYSIS, CPP])],
  [CSHARP_ANALYSIS, new Set([CORE, ANALYSIS, CSHARP, SEMANTIC])],
  [PYTHON_ANALYSIS, new Set([CORE, SEMANTIC, ANALYSIS, PYTHON])],
  [PHP_ANALYSIS, new Set([CORE, SEMANTIC, ANALYSIS, PHP])],
  [RUBY_ANALYSIS, new Set([CORE, ANALYSIS, RUBY])],
  [JS_TS_ANALYSIS, new Set([CORE, SEMANTIC, ANALYSIS, JS_TS])],
  [TOOLS, new Set([RUST_ANALYSIS, GO_ANALYSIS, CORE, ANALYSIS, CPP_ANALYSIS, CSHARP_ANALYSIS, PHP_ANALYSIS, PYTHON_ANALYSIS, RUBY_ANALYSIS, JS_TS_ANALYSIS, CPP, GO, PHP, PYTHON, RUST, JVM_ANALYSIS])],
  [FLOW, new Set([CORE, ANALYSIS])],
  // Query execution uses the C++, Python, JVM and JS/TS crates' structured
  // grammar hooks. JS/TS property rules reuse the syntax and TypeScript object
  // helpers; these language crates remain below analysis and depend on core.
  [RQL, new Set([RUST_ANALYSIS, GO_ANALYSIS, TOOLS, CORE, ANALYSIS, CPP_ANALYSIS, CSHARP_ANALYSIS, PHP_ANALYSIS, PYTHON_ANALYSIS, RUBY_ANALYSIS, JS_TS_ANALYSIS, FLOW, CPP, PYTHON, JVM, JS_TS, JVM_ANALYSIS])],
  [POLICY, new Set([RUST_ANALYSIS, TOOLS, ANALYSIS, FLOW, RQL])],
  [SEMANTIC_PACKS, new Set([RUST_ANALYSIS, GO_ANALYSIS, ANALYSIS, CSHARP_ANALYSIS, PHP_ANALYSIS, PYTHON_ANALYSIS, RUBY_ANALYSIS, JS_TS_ANALYSIS, FLOW, JVM_ANALYSIS])],
  [RUNTIME, new Set([ANALYSIS, FLOW, POLICY, RQL])],
  [MCP, new Set([TOOLS, ANALYSIS, FLOW, POLICY, RUNTIME, RQL])],
  [FACADE, new Set([RUST_ANALYSIS, GO_ANALYSIS, TOOLS, ANALYSIS, CPP_ANALYSIS, CSHARP_ANALYSIS, PHP_ANALYSIS, PYTHON_ANALYSIS, RUBY_ANALYSIS, JS_TS_ANALYSIS, FLOW, POLICY, RUNTIME, MCP, SEMANTIC_PACKS, RQL, JVM_ANALYSIS])],
  [RUST_ANALYSIS, new Set([CORE, SEMANTIC, ANALYSIS, RUST])],
]);
// The private facade integration suites exercise parser and identity contracts
// directly. These edges are permitted only for tests, never production or builds.
const ALLOWED_DEVELOPMENT_DEPENDENCIES = new Map([
  [MCP, new Set([GO_ANALYSIS])],
  [TOOLS, new Set([CSHARP, JS_TS, SEMANTIC, RUBY, JVM_ANALYSIS, JVM])],
  [FLOW, new Set([TOOLS])],
  [RUNTIME, new Set([TOOLS])],
  [SEMANTIC_PACKS, new Set([GO_ANALYSIS, TOOLS, JS_TS_ANALYSIS, JVM_ANALYSIS])],
  [RQL, new Set([GO_ANALYSIS, RUBY_ANALYSIS, JS_TS_ANALYSIS, JVM_ANALYSIS])],
  [POLICY, new Set([CPP_ANALYSIS, PYTHON_ANALYSIS, JS_TS_ANALYSIS, JVM_ANALYSIS])],
  [FACADE, new Set([CORE, CSHARP, JS_TS, JVM, JS_TS_ANALYSIS, JVM_ANALYSIS])],
]);
// Optional production edges for feature-gated binaries. Only tools defines the
// complete language table the engine links by symbol, so the release-tooling
// `bifrost-semantic-pack` binary needs it; normal library builds must not.
// Offline catalog authoring uses the owning policy registry and RQL canonical
// encoder behind release-tooling, so generated catalogs obey the product schema.
const ALLOWED_OPTIONAL_DEPENDENCIES = new Map([
  [SEMANTIC_PACKS, new Set([TOOLS, POLICY, RQL])],
]);
const REQUIRED_WORKSPACE_DEPENDENCIES = new Map([
  [JVM_ANALYSIS, new Set([CORE, ANALYSIS, JVM])],
  [STORE, new Set()],
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
  [SEMANTIC, new Set([CORE, CPP, CSHARP, GO, JS_TS, JVM, PHP, PYTHON, RUBY, RUST])],
  [ANALYSIS, new Set([CORE, SEMANTIC, STORE, CPP, CSHARP, GO, JS_TS, JVM, PHP, PYTHON, RUBY, RUST])],
  [GO_ANALYSIS, new Set([CORE, SEMANTIC, ANALYSIS, GO])],
  [CPP_ANALYSIS, new Set([CORE, ANALYSIS, CPP])],
  [CSHARP_ANALYSIS, new Set([CORE, ANALYSIS, CSHARP])],
  [PHP_ANALYSIS, new Set([CORE, SEMANTIC, ANALYSIS, PHP])],
  [PYTHON_ANALYSIS, new Set([CORE, ANALYSIS, PYTHON])],
  [RUBY_ANALYSIS, new Set([CORE, ANALYSIS, RUBY])],
  [JS_TS_ANALYSIS, new Set([CORE, SEMANTIC, ANALYSIS, JS_TS])],
  [TOOLS, new Set([RUST_ANALYSIS, GO_ANALYSIS, ANALYSIS, CPP_ANALYSIS, CSHARP_ANALYSIS, PHP_ANALYSIS, PYTHON_ANALYSIS, RUBY_ANALYSIS, JS_TS_ANALYSIS, JVM_ANALYSIS])],
  [FLOW, new Set([CORE, ANALYSIS])],
  [RQL, new Set([RUST_ANALYSIS, GO_ANALYSIS, CORE, ANALYSIS, CPP_ANALYSIS, CSHARP_ANALYSIS, PHP_ANALYSIS, PYTHON_ANALYSIS, RUBY_ANALYSIS, JS_TS_ANALYSIS, FLOW, JVM_ANALYSIS])],
  [POLICY, new Set([RUST_ANALYSIS, ANALYSIS, FLOW, RQL])],
  [SEMANTIC_PACKS, new Set([RUST_ANALYSIS, GO_ANALYSIS, ANALYSIS, CSHARP_ANALYSIS, PHP_ANALYSIS, PYTHON_ANALYSIS, RUBY_ANALYSIS, JS_TS_ANALYSIS, FLOW, JVM_ANALYSIS])],
  [RUNTIME, new Set([ANALYSIS, FLOW, POLICY, RQL])],
  [MCP, new Set([ANALYSIS, FLOW, POLICY, RUNTIME, RQL])],
  [FACADE, new Set()],
  [RUST_ANALYSIS, new Set([CORE, SEMANTIC, ANALYSIS, RUST])],
]);
const FORBIDDEN_EXTERNAL_DEPENDENCIES = new Map([
  // Model and tokenizer dependencies remain prohibited in low-level crates.
  // Core inherits the same ban: it is below analysis, so anything forbidden
  // there is worse here.
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
    SEMANTIC,
    new Set(["lsp-server", "lsp-types", "pyo3", "hf-hub", "tokenizers", "fastrq"]),
  ],
  [
    ANALYSIS,
    new Set(["lsp-server", "lsp-types", "pyo3", "hf-hub", "tokenizers", "fastrq"]),
  ],
  [
    FLOW,
    new Set(["lsp-server", "lsp-types", "pyo3", "hf-hub", "tokenizers", "fastrq"]),
  ],
  [RQL, new Set(["lsp-server", "lsp-types", "pyo3"])],
  [POLICY, new Set(["lsp-server", "lsp-types", "pyo3"])],
  [SEMANTIC_PACKS, new Set(["lsp-server", "lsp-types", "pyo3"])],
  [RUNTIME, new Set(["lsp-server", "lsp-types", "pyo3"])],
  [MCP, new Set(["lsp-server", "lsp-types", "pyo3"])],
  [FACADE, new Set()],
]);

// Production checks seal-time store consistency on a sample of blobs; builds
// with brokk-bifrost-core/test-support check every blob. `cfg(test)` does not
// reach dependencies, so a crate whose tests can write store seals must enable
// that feature through one of its dependencies, or its tests sample silently.
const SEAL_WRITING_DEPENDENCIES = new Set([STORE, ANALYSIS, SEMANTIC]);
const CORE_TEST_SUPPORT = "test-support";

function sorted(values) {
  return [...values].sort();
}

// Follows Cargo feature entries (`feature`, `dependency/feature`,
// `dependency?/feature`; `dep:` only activates the dependency) from one
// workspace package's feature to core's test-support feature. A weak
// `dependency?/feature` entry counts only for a required dependency: deciding
// whether something else enables an optional one needs full feature resolution.
function featureReachesCoreTestSupport(membersByName, packageName, feature, visited = new Set()) {
  if (packageName === CORE) {
    return feature === CORE_TEST_SUPPORT;
  }
  const key = `${packageName}/${feature}`;
  const pkg = membersByName.get(packageName);
  if (visited.has(key) || !pkg) {
    return false;
  }
  visited.add(key);
  for (const entry of pkg.features[feature] ?? []) {
    if (entry.startsWith("dep:")) {
      continue;
    }
    const slash = entry.indexOf("/");
    if (slash < 0) {
      if (featureReachesCoreTestSupport(membersByName, packageName, entry, visited)) {
        return true;
      }
      continue;
    }
    const weak = entry[slash - 1] === "?";
    const local = entry.slice(0, weak ? slash - 1 : slash);
    const target = pkg.dependencies.find((dependency) => (dependency.rename ?? dependency.name) === local);
    if (target && !(weak && target.optional) && featureReachesCoreTestSupport(membersByName, target.name, entry.slice(slash + 1), visited)) {
      return true;
    }
  }
  return false;
}

// Cargo unifies features across normal and development edges, so any edge counts.
function enablesCoreTestSupport(membersByName, pkg) {
  return pkg.dependencies
    .some((dependency) => [
      ...dependency.features,
      ...(dependency.uses_default_features ? ["default"] : []),
    ].some((feature) => featureReachesCoreTestSupport(membersByName, dependency.name, feature)));
}

export function validateWorkspaceGraph(metadata) {
  const packagesById = new Map(metadata.packages.map((pkg) => [pkg.id, pkg]));
  const members = metadata.workspace_members.map((id) => packagesById.get(id)).filter(Boolean);
  const membersByName = new Map(members.map((pkg) => [pkg.name, pkg]));
  const memberNames = new Set(membersByName.keys());
  const errors = [];

  // Inspect resolved registry dependencies too: the retired upstream host may
  // return transitively even when it is no longer a workspace member.
  for (const pkg of metadata.packages) {
    if (pkg.name === "brokk-bifrost-lsp") {
      errors.push(`engine dependency graph contains retired upstream host ${pkg.id}`);
    }
  }

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
    if (pkg.name === WORKSPACE_HACK) {
      if (!Array.isArray(pkg.publish) || pkg.publish.length !== 0) {
        errors.push("workspace-hack must remain unpublished");
      }
      const forbidden = new Set([...FORBIDDEN_EXTERNAL_DEPENDENCIES.values()].flatMap(values => [...values]));
      for (const dependency of pkg.dependencies) {
        if (dependency.source === null || forbidden.has(dependency.name)) {
          errors.push(`workspace-hack must not depend on ${dependency.name}`);
        }
      }
      continue;
    }
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
    const sealWriting = sorted(new Set(pkg.dependencies
      .map((dependency) => dependency.name)
      .filter((name) => SEAL_WRITING_DEPENDENCIES.has(name))));
    if (sealWriting.length > 0 && !enablesCoreTestSupport(membersByName, pkg)) {
      errors.push(
        `${pkg.name} depends on ${sealWriting.join(", ")} but no dependency enables ${CORE}/${CORE_TEST_SUPPORT}; its tests would validate only sampled store seals`,
      );
    }
    for (const dependency of pkg.dependencies) {
      if (dependency.name === WORKSPACE_HACK) {
        if (dependency.kind != null || dependency.optional || dependency.source !== null || dependency.req !== "*") {
          errors.push(`${pkg.name} dependency on workspace-hack must be a required path-only normal dependency`);
        }
        continue;
      }
      if (
        dependency.name === TEST_MACROS &&
        (dependency.kind !== "dev" || dependency.req !== "*" || dependency.source !== null)
      ) {
        errors.push(
          `${pkg.name} dependency on ${TEST_MACROS} must be a path-only development dependency`,
        );
        continue;
      }
      const isAllowed = allowed.has(dependency.name) ||
        // The shared test marker is available everywhere, but never at runtime.
        (dependency.name === TEST_MACROS && dependency.kind === "dev") ||
        (dependency.kind === "dev" &&
          ALLOWED_DEVELOPMENT_DEPENDENCIES.get(pkg.name)?.has(dependency.name)) ||
        (dependency.kind == null && dependency.optional === true &&
          ALLOWED_OPTIONAL_DEPENDENCIES.get(pkg.name)?.has(dependency.name));
      if (EXPECTED_MEMBERS.has(dependency.name) && !isAllowed) {
        errors.push(`${pkg.name} must not depend on workspace package ${dependency.name}`);
      }
      if (
        EXPECTED_MEMBERS.has(dependency.name) &&
        isAllowed &&
        dependency.name !== TEST_MACROS &&
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
  // Full resolution exceeds spawnSync's default stdout buffer. Let Cargo write
  // its query result to disk, then parse it once for this validation.
  const temporary = mkdtempSync(join(tmpdir(), "bifrost-workspace-metadata-"));
  try {
    const path = join(temporary, "metadata.json");
    const output = openSync(path, "w");
    let result;
    try {
      result = spawnSync("cargo", ["metadata", "--locked", "--format-version", "1"], {
        stdio: ["ignore", output, "inherit"],
      });
    } finally {
      closeSync(output);
    }
    if (result.error) throw result.error;
    if (result.status !== 0) {
      throw new Error(`cargo metadata exited with status ${result.status ?? "unknown"}`);
    }
    return JSON.parse(readFileSync(path, "utf8"));
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
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
