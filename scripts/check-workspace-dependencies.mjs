#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const FACADE = "brokk-bifrost";
const ANALYSIS = "brokk-bifrost-analysis";
const RUNTIME = "brokk-bifrost-runtime";
const MCP = "brokk-bifrost-mcp";
const LSP = "brokk-bifrost-lsp";

const EXPECTED_MEMBERS = new Set([FACADE, ANALYSIS, RUNTIME, MCP, LSP]);
const ALLOWED_WORKSPACE_DEPENDENCIES = new Map([
  [ANALYSIS, new Set()],
  [RUNTIME, new Set([ANALYSIS])],
  [MCP, new Set([ANALYSIS, RUNTIME])],
  [LSP, new Set([ANALYSIS, RUNTIME])],
  [FACADE, new Set([ANALYSIS, RUNTIME, MCP, LSP])],
]);
const REQUIRED_WORKSPACE_DEPENDENCIES = new Map([
  [ANALYSIS, new Set()],
  [RUNTIME, new Set([ANALYSIS])],
  [MCP, new Set([ANALYSIS, RUNTIME])],
  [LSP, new Set([ANALYSIS, RUNTIME])],
  [FACADE, new Set()],
]);
const FORBIDDEN_EXTERNAL_DEPENDENCIES = new Map([
  [ANALYSIS, new Set(["lsp-server", "lsp-types", "pyo3"])],
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
