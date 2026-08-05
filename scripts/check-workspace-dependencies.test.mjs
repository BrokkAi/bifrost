import assert from "node:assert/strict";
import test from "node:test";

import { validateWorkspaceGraph } from "./check-workspace-dependencies.mjs";

const names = [
  "brokk-bifrost",
  "brokk-bifrost-core",
  "brokk-bifrost-csharp",
  "brokk-bifrost-go",
  "brokk-bifrost-php",
  "brokk-bifrost-python",
  "brokk-bifrost-rust",
  "brokk-bifrost-analysis",
  "brokk-bifrost-nlp",
  "brokk-bifrost-policy",
  "brokk-bifrost-runtime",
  "brokk-bifrost-mcp",
  "brokk-bifrost-lsp",
  "brokk-bifrost-semantic-packs",
];

function dependency(name) {
  return { name, req: "=0.8.12" };
}

function metadata(overrides = {}) {
  const dependencies = {
    "brokk-bifrost": [],
    "brokk-bifrost-core": [],
    "brokk-bifrost-csharp": [dependency("brokk-bifrost-core")],
    "brokk-bifrost-go": [dependency("brokk-bifrost-core")],
    "brokk-bifrost-php": [dependency("brokk-bifrost-core")],
    "brokk-bifrost-python": [dependency("brokk-bifrost-core")],
    "brokk-bifrost-rust": [dependency("brokk-bifrost-core")],
    "brokk-bifrost-analysis": [
      dependency("brokk-bifrost-core"),
      dependency("brokk-bifrost-csharp"),
      dependency("brokk-bifrost-go"),
      dependency("brokk-bifrost-php"),
      dependency("brokk-bifrost-python"),
      dependency("brokk-bifrost-rust"),
    ],
    "brokk-bifrost-nlp": [dependency("brokk-bifrost-analysis")],
    "brokk-bifrost-policy": [dependency("brokk-bifrost-analysis")],
    "brokk-bifrost-runtime": [
      dependency("brokk-bifrost-analysis"),
      dependency("brokk-bifrost-policy"),
    ],
    "brokk-bifrost-mcp": [
      dependency("brokk-bifrost-analysis"),
      dependency("brokk-bifrost-policy"),
      dependency("brokk-bifrost-runtime"),
    ],
    "brokk-bifrost-lsp": [
      dependency("brokk-bifrost-analysis"),
      dependency("brokk-bifrost-policy"),
      dependency("brokk-bifrost-runtime"),
    ],
    "brokk-bifrost-semantic-packs": [dependency("brokk-bifrost-analysis")],
    ...overrides.dependencies,
  };
  const versions = { ...Object.fromEntries(names.map((name) => [name, "0.8.12"])), ...overrides.versions };
  const packageNames = overrides.names ?? names;
  const packages = packageNames.map((name) => ({
    id: `path+file:///workspace/${name}#${name}@${versions[name] ?? "0.8.12"}`,
    name,
    version: versions[name] ?? "0.8.12",
    dependencies: dependencies[name] ?? [],
  }));
  return {
    packages,
    workspace_members: packages.map((pkg) => pkg.id),
  };
}

test("accepts the intended one-way workspace graph", () => {
  assert.deepEqual(validateWorkspaceGraph(metadata()), []);
});

test("rejects a runtime dependency on a protocol host", () => {
  const errors = validateWorkspaceGraph(
    metadata({
      dependencies: {
        "brokk-bifrost-runtime": [
          dependency("brokk-bifrost-analysis"),
          dependency("brokk-bifrost-policy"),
          dependency("brokk-bifrost-lsp"),
        ],
      },
    }),
  );
  assert.deepEqual(errors, [
    "brokk-bifrost-runtime must not depend on workspace package brokk-bifrost-lsp",
  ]);
});

test("rejects an analysis dependency on prebuilt semantic packs", () => {
  assert.deepEqual(
    validateWorkspaceGraph(
      metadata({
        dependencies: {
          "brokk-bifrost-analysis": [
            dependency("brokk-bifrost-core"),
            dependency("brokk-bifrost-csharp"),
            dependency("brokk-bifrost-go"),
            dependency("brokk-bifrost-php"),
            dependency("brokk-bifrost-python"),
            dependency("brokk-bifrost-rust"),
            dependency("brokk-bifrost-semantic-packs"),
          ],
        },
      }),
    ),
    [
      "brokk-bifrost-analysis must not depend on workspace package brokk-bifrost-semantic-packs",
    ],
  );
});

test("rejects a core dependency back on analysis", () => {
  assert.deepEqual(
    validateWorkspaceGraph(
      metadata({
        dependencies: {
          "brokk-bifrost-core": [dependency("brokk-bifrost-analysis")],
        },
      }),
    ),
    ["brokk-bifrost-core must not depend on workspace package brokk-bifrost-analysis"],
  );
});

test("rejects a missing required runtime dependency", () => {
  assert.deepEqual(
    validateWorkspaceGraph(
      metadata({ dependencies: { "brokk-bifrost-runtime": [] } }),
    ),
    [
      "brokk-bifrost-runtime must depend on workspace package brokk-bifrost-analysis",
      "brokk-bifrost-runtime must depend on workspace package brokk-bifrost-policy",
    ],
  );
});

test("rejects MCP dependencies on LSP transport packages", () => {
  const errors = validateWorkspaceGraph(
    metadata({
      dependencies: {
        "brokk-bifrost-mcp": [
          dependency("brokk-bifrost-analysis"),
          dependency("brokk-bifrost-policy"),
          dependency("brokk-bifrost-runtime"),
          dependency("lsp-types"),
        ],
      },
    }),
  );
  assert.deepEqual(errors, [
    "brokk-bifrost-mcp must not depend on host-specific package lsp-types",
  ]);
});

test("rejects member version drift", () => {
  assert.deepEqual(
    validateWorkspaceGraph(
      metadata({ versions: { "brokk-bifrost-runtime": "0.8.13" } }),
    ),
    ["brokk-bifrost-runtime version 0.8.13 does not match facade version 0.8.12"],
  );
});

test("rejects a non-exact implementation dependency version", () => {
  assert.deepEqual(
    validateWorkspaceGraph(
      metadata({
        dependencies: {
          "brokk-bifrost-runtime": [
            { name: "brokk-bifrost-analysis", req: "^0.8.12" },
            dependency("brokk-bifrost-policy"),
          ],
        },
      }),
    ),
    [
      "brokk-bifrost-runtime dependency on brokk-bifrost-analysis must require exactly =0.8.12",
    ],
  );
});

test("rejects unexpected workspace members", () => {
  assert.deepEqual(
    validateWorkspaceGraph(metadata({ names: [...names, "surprise-package"] })),
    ["unexpected workspace package surprise-package"],
  );
});

test("rejects a language crate reaching back up to analysis", () => {
  assert.deepEqual(
    validateWorkspaceGraph(
      metadata({
        dependencies: {
          "brokk-bifrost-rust": [
            dependency("brokk-bifrost-core"),
            dependency("brokk-bifrost-analysis"),
          ],
        },
      }),
    ),
    ["brokk-bifrost-rust must not depend on workspace package brokk-bifrost-analysis"],
  );
});

test("rejects one language crate depending on another", () => {
  assert.deepEqual(
    validateWorkspaceGraph(
      metadata({
        dependencies: {
          "brokk-bifrost-rust": [
            dependency("brokk-bifrost-core"),
            dependency("brokk-bifrost-go"),
          ],
        },
      }),
    ),
    ["brokk-bifrost-rust must not depend on workspace package brokk-bifrost-go"],
  );
});

test("rejects a php crate reaching back up to analysis", () => {
  assert.deepEqual(
    validateWorkspaceGraph(
      metadata({
        dependencies: {
          "brokk-bifrost-php": [
            dependency("brokk-bifrost-core"),
            dependency("brokk-bifrost-analysis"),
          ],
        },
      }),
    ),
    ["brokk-bifrost-php must not depend on workspace package brokk-bifrost-analysis"],
  );
});
