import assert from "node:assert/strict";
import test from "node:test";

import { validateWorkspaceGraph } from "./check-workspace-dependencies.mjs";

// Each extracted implementation adds one descriptor; its fixture package,
// required edges, consumers and layer checks follow from this entry.
const languageImplementations = [
  { name: "brokk-bifrost-rust-analysis", knowledge: "brokk-bifrost-rust", extra: ["brokk-bifrost-semantic"], consumers: ["brokk-bifrost-tools", "brokk-bifrost-rql", "brokk-bifrost-semantic-packs", "brokk-bifrost-policy"] },
  { name: "brokk-bifrost-go-analysis", knowledge: "brokk-bifrost-go", extra: ["brokk-bifrost-semantic"], consumers: ["brokk-bifrost-tools", "brokk-bifrost-rql", "brokk-bifrost-semantic-packs"] },
  { name: "brokk-bifrost-cpp-analysis", knowledge: "brokk-bifrost-cpp", consumers: ["brokk-bifrost-tools", "brokk-bifrost-rql"] },
  { name: "brokk-bifrost-js-ts-analysis", knowledge: "brokk-bifrost-js-ts", extra: ["brokk-bifrost-semantic"], consumers: ["brokk-bifrost-tools", "brokk-bifrost-rql", "brokk-bifrost-semantic-packs"] },
  {
    name: "brokk-bifrost-csharp-analysis",
    knowledge: "brokk-bifrost-csharp",
    consumers: ["brokk-bifrost-tools", "brokk-bifrost-rql", "brokk-bifrost-semantic-packs"],
  },
  {
    name: "brokk-bifrost-php-analysis",
    knowledge: "brokk-bifrost-php",
    extra: ["brokk-bifrost-semantic"],
    consumers: ["brokk-bifrost-tools", "brokk-bifrost-rql", "brokk-bifrost-semantic-packs"],
  },
  {
    name: "brokk-bifrost-python-analysis",
    knowledge: "brokk-bifrost-python",
    consumers: ["brokk-bifrost-tools", "brokk-bifrost-rql", "brokk-bifrost-semantic-packs"],
  },
  {
    name: "brokk-bifrost-ruby-analysis",
    knowledge: "brokk-bifrost-ruby",
    consumers: ["brokk-bifrost-tools", "brokk-bifrost-rql", "brokk-bifrost-semantic-packs"],
  },
];

function implementationDependencies(consumer) {
  return languageImplementations
    .filter(({ consumers }) => consumers.includes(consumer))
    .map(({ name }) => dependency(name));
}

const names = [
  "brokk-bifrost",
  "brokk-bifrost-core",
  "brokk-bifrost-cpp",
  "brokk-bifrost-csharp",
  "brokk-bifrost-go",
  "brokk-bifrost-js-ts",
  "brokk-bifrost-jvm",
  "brokk-bifrost-php",
  "brokk-bifrost-python",
  "brokk-bifrost-ruby",
  "brokk-bifrost-rust",
  "brokk-bifrost-semantic",
  "brokk-bifrost-store",
  "brokk-bifrost-analysis",
  ...languageImplementations.map(({ name }) => name),
  "brokk-bifrost-tools",
  "brokk-bifrost-flow",
  "brokk-bifrost-rql",
  "brokk-bifrost-policy",
  "brokk-bifrost-runtime",
  "brokk-bifrost-mcp",
  "brokk-bifrost-semantic-packs",
  "brokk-bifrost-test-macros",
];

function dependency(name, kind = undefined, req = "=0.8.12") {
  return { name, req, kind, source: null };
}

function metadata(overrides = {}) {
  const dependencies = {
    "brokk-bifrost": [
      dependency("brokk-bifrost-core", "dev"),
      dependency("brokk-bifrost-js-ts", "dev"),
      dependency("brokk-bifrost-jvm", "dev"),
    ],
    "brokk-bifrost-core": [],
    "brokk-bifrost-cpp": [dependency("brokk-bifrost-core")],
    "brokk-bifrost-csharp": [dependency("brokk-bifrost-core")],
    "brokk-bifrost-go": [dependency("brokk-bifrost-core")],
    "brokk-bifrost-js-ts": [dependency("brokk-bifrost-core")],
    "brokk-bifrost-jvm": [dependency("brokk-bifrost-core")],
    "brokk-bifrost-php": [dependency("brokk-bifrost-core")],
    "brokk-bifrost-python": [dependency("brokk-bifrost-core")],
    "brokk-bifrost-ruby": [dependency("brokk-bifrost-core")],
    "brokk-bifrost-rust": [dependency("brokk-bifrost-core")],
    "brokk-bifrost-semantic": [
      dependency("brokk-bifrost-core"),
      dependency("brokk-bifrost-cpp"),
      dependency("brokk-bifrost-csharp"),
      dependency("brokk-bifrost-go"),
      dependency("brokk-bifrost-js-ts"),
      dependency("brokk-bifrost-jvm"),
      dependency("brokk-bifrost-php"),
      dependency("brokk-bifrost-python"),
      dependency("brokk-bifrost-ruby"),
      dependency("brokk-bifrost-rust"),
    ],
    "brokk-bifrost-store": [],
    "brokk-bifrost-analysis": [
      dependency("brokk-bifrost-core"),
      dependency("brokk-bifrost-semantic"),
      dependency("brokk-bifrost-store"),
      dependency("brokk-bifrost-cpp"),
      dependency("brokk-bifrost-csharp"),
      dependency("brokk-bifrost-go"),
      dependency("brokk-bifrost-js-ts"),
      dependency("brokk-bifrost-jvm"),
      dependency("brokk-bifrost-php"),
      dependency("brokk-bifrost-python"),
      dependency("brokk-bifrost-ruby"),
      dependency("brokk-bifrost-rust"),
    ],
    "brokk-bifrost-tools": [dependency("brokk-bifrost-analysis")],
    "brokk-bifrost-flow": [
      dependency("brokk-bifrost-core"),
      dependency("brokk-bifrost-analysis"),
    ],
    "brokk-bifrost-rql": [
      dependency("brokk-bifrost-core"),
      dependency("brokk-bifrost-analysis"),
      dependency("brokk-bifrost-flow"),
    ],
    "brokk-bifrost-policy": [
      dependency("brokk-bifrost-cpp-analysis", "dev"),
      dependency("brokk-bifrost-analysis"),
      dependency("brokk-bifrost-flow"),
      dependency("brokk-bifrost-rql"),
    ],
    "brokk-bifrost-runtime": [
      dependency("brokk-bifrost-analysis"),
      dependency("brokk-bifrost-flow"),
      dependency("brokk-bifrost-policy"),
      dependency("brokk-bifrost-rql"),
    ],
    "brokk-bifrost-mcp": [
      dependency("brokk-bifrost-analysis"),
      dependency("brokk-bifrost-flow"),
      dependency("brokk-bifrost-policy"),
      dependency("brokk-bifrost-runtime"),
      dependency("brokk-bifrost-rql"),
    ],
    "brokk-bifrost-semantic-packs": [
      dependency("brokk-bifrost-analysis"),
      dependency("brokk-bifrost-flow"),
    ],
    ...Object.fromEntries(languageImplementations.map(({ name, knowledge, extra = [] }) => [name, [
      dependency("brokk-bifrost-core"),
      dependency("brokk-bifrost-analysis"),
      dependency(knowledge),
      ...extra.map((name) => dependency(name)),
    ]])),
  };
  for (const name of Object.keys(dependencies)) {
    dependencies[name].push(...implementationDependencies(name));
  }
  Object.assign(dependencies, overrides.dependencies);

  const versions = { ...Object.fromEntries(names.map((name) => [name, "0.8.12"])), ...overrides.versions };
  const packageNames = overrides.names ?? names;
  const packages = packageNames.map((name) => ({
    id: `path+file:///workspace/${name}#${name}@${versions[name] ?? "0.8.12"}`,
    name,
    version: versions[name] ?? "0.8.12",
    dependencies: [
      ...(dependencies[name] ?? []),
      dependency("brokk-bifrost-test-macros", "dev", "*"),
    ],
  }));
  return {
    packages,
    workspace_members: packages.map((pkg) => pkg.id),
  };
}

test("accepts the intended one-way workspace graph", () => {
  assert.deepEqual(validateWorkspaceGraph(metadata()), []);
});

test("test macros are permitted only as path-only development dependencies", () => {
  for (const invalidDependency of [
    dependency("brokk-bifrost-test-macros"),
    dependency("brokk-bifrost-test-macros", "dev", "=0.8.12"),
  ]) {
    assert.deepEqual(validateWorkspaceGraph(metadata({
      dependencies: { "brokk-bifrost": [invalidDependency] },
    })), [
      "brokk-bifrost dependency on brokk-bifrost-test-macros must be a path-only development dependency",
    ]);
  }
});

test("facade parser and identity dependencies are confined to development", () => {
  const direct = ["brokk-bifrost-core", "brokk-bifrost-js-ts", "brokk-bifrost-jvm"];
  for (const kind of ["dev", null, "build"]) {
    const errors = validateWorkspaceGraph(metadata({
      dependencies: {
        "brokk-bifrost": direct.map((name) => ({ ...dependency(name), kind })),
      },
    }));
    assert.deepEqual(errors, kind === "dev" ? [] : direct.map(
      (name) => `brokk-bifrost must not depend on workspace package ${name}`,
    ));
  }
});

test("facade development exceptions still require exact workspace versions", () => {
  assert.deepEqual(validateWorkspaceGraph(metadata({
    dependencies: {
      "brokk-bifrost": [{ name: "brokk-bifrost-core", req: "^0.8.12", kind: "dev" }],
    },
  })), ["brokk-bifrost dependency on brokk-bifrost-core must require exactly =0.8.12"]);
});

test("development edges do not bypass other workspace boundaries", () => {
  assert.deepEqual(validateWorkspaceGraph(metadata({
    dependencies: {
      "brokk-bifrost-core": [{ ...dependency("brokk-bifrost-analysis"), kind: "dev" }],
      "brokk-bifrost": [{ ...dependency("brokk-bifrost-go"), kind: "dev" }],
    },
  })), [
    "brokk-bifrost must not depend on workspace package brokk-bifrost-go",
    "brokk-bifrost-core must not depend on workspace package brokk-bifrost-analysis",
  ]);
});

test("semantic packs may reach tools only through the optional release-tooling edge", () => {
  const optional = metadata();
  optional.packages.find(({ name }) => name === "brokk-bifrost-semantic-packs")
    .dependencies.push({ ...dependency("brokk-bifrost-tools"), optional: true });
  assert.deepEqual(validateWorkspaceGraph(optional), []);
  assert.deepEqual(validateWorkspaceGraph(withExtraDependency(
    metadata(), "brokk-bifrost-semantic-packs", "brokk-bifrost-tools",
  )), ["brokk-bifrost-semantic-packs must not depend on workspace package brokk-bifrost-tools"]);
});

test("rejects a runtime dependency on a protocol host", () => {
  const errors = validateWorkspaceGraph(
    metadata({
      dependencies: {
        "brokk-bifrost-runtime": [
          dependency("brokk-bifrost-analysis"),
          dependency("brokk-bifrost-flow"),
          dependency("brokk-bifrost-policy"),
          dependency("brokk-bifrost-rql"),
          dependency("brokk-bifrost-mcp"),
        ],
      },
    }),
  );
  assert.deepEqual(errors, [
    "brokk-bifrost-runtime must not depend on workspace package brokk-bifrost-mcp",
  ]);
});

test("rejects an analysis dependency on prebuilt semantic packs", () => {
  assert.deepEqual(
    validateWorkspaceGraph(
      metadata({
        dependencies: {
          "brokk-bifrost-analysis": [
            dependency("brokk-bifrost-core"),
            dependency("brokk-bifrost-semantic"),
            dependency("brokk-bifrost-store"),
            dependency("brokk-bifrost-cpp"),
            dependency("brokk-bifrost-csharp"),
            dependency("brokk-bifrost-go"),
            dependency("brokk-bifrost-js-ts"),
            dependency("brokk-bifrost-jvm"),
            dependency("brokk-bifrost-php"),
            dependency("brokk-bifrost-python"),
            dependency("brokk-bifrost-ruby"),
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

test("rejects analysis dependencies on flow, RQL, and policy", () => {
  const analysis = metadata().packages.find(
    (pkg) => pkg.name === "brokk-bifrost-analysis",
  ).dependencies;
  const errors = validateWorkspaceGraph(
    metadata({
      dependencies: {
        "brokk-bifrost-analysis": [
          ...analysis,
          dependency("brokk-bifrost-flow"),
          dependency("brokk-bifrost-rql"),
          dependency("brokk-bifrost-policy"),
        ],
      },
    }),
  );
  assert.deepEqual(errors, [
    "brokk-bifrost-analysis must not depend on workspace package brokk-bifrost-flow",
    "brokk-bifrost-analysis must not depend on workspace package brokk-bifrost-rql",
    "brokk-bifrost-analysis must not depend on workspace package brokk-bifrost-policy",
  ]);
});

test("rejects flow dependencies on RQL and policy", () => {
  assert.deepEqual(
    validateWorkspaceGraph(
      metadata({
        dependencies: {
          "brokk-bifrost-flow": [
            dependency("brokk-bifrost-core"),
            dependency("brokk-bifrost-analysis"),
            dependency("brokk-bifrost-rql"),
            dependency("brokk-bifrost-policy"),
          ],
        },
      }),
    ),
    [
      "brokk-bifrost-flow must not depend on workspace package brokk-bifrost-rql",
      "brokk-bifrost-flow must not depend on workspace package brokk-bifrost-policy",
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

test("accepts RQL grammar hooks below analysis but rejects policy", () => {
  assert.deepEqual(
    validateWorkspaceGraph(
      metadata({
        dependencies: {
          "brokk-bifrost-rql": [
            ...implementationDependencies("brokk-bifrost-rql"),
            dependency("brokk-bifrost-core"),
            dependency("brokk-bifrost-analysis"),
            dependency("brokk-bifrost-flow"),
            dependency("brokk-bifrost-cpp"),
            dependency("brokk-bifrost-python"),
            dependency("brokk-bifrost-jvm"),
            dependency("brokk-bifrost-js-ts"),
          ],
        },
      }),
    ),
    [],
  );
  assert.deepEqual(
    validateWorkspaceGraph(
      metadata({
        dependencies: {
          "brokk-bifrost-rql": [
            ...implementationDependencies("brokk-bifrost-rql"),
            dependency("brokk-bifrost-core"),
            dependency("brokk-bifrost-analysis"),
            dependency("brokk-bifrost-flow"),
            dependency("brokk-bifrost-policy"),
          ],
        },
      }),
    ),
    ["brokk-bifrost-rql must not depend on workspace package brokk-bifrost-policy"],
  );
});

test("rejects a missing required runtime dependency", () => {
  assert.deepEqual(
    validateWorkspaceGraph(
      metadata({ dependencies: { "brokk-bifrost-runtime": [] } }),
    ),
    [
      "brokk-bifrost-runtime must depend on workspace package brokk-bifrost-analysis",
      "brokk-bifrost-runtime must depend on workspace package brokk-bifrost-flow",
      "brokk-bifrost-runtime must depend on workspace package brokk-bifrost-policy",
      "brokk-bifrost-runtime must depend on workspace package brokk-bifrost-rql",
    ],
  );
});

test("rejects MCP dependencies on LSP transport packages", () => {
  const errors = validateWorkspaceGraph(
    metadata({
      dependencies: {
        "brokk-bifrost-mcp": [
          dependency("brokk-bifrost-analysis"),
          dependency("brokk-bifrost-flow"),
          dependency("brokk-bifrost-policy"),
          dependency("brokk-bifrost-runtime"),
          dependency("brokk-bifrost-rql"),
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
            dependency("brokk-bifrost-flow"),
            dependency("brokk-bifrost-policy"),
            dependency("brokk-bifrost-rql"),
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

const knowledgeCrates = metadata().packages.find(
  (pkg) => pkg.name === "brokk-bifrost-semantic",
).dependencies.map(({ name }) => name).filter(
  (name) => name !== "brokk-bifrost-core" && name !== "brokk-bifrost-test-macros",
);

function withExtraDependency(graph, from, to) {
  graph.packages.find(({ name }) => name === from).dependencies.push(dependency(to));
  return graph;
}

test("rejects a language knowledge crate reaching back up to analysis", () => {
  for (const name of knowledgeCrates) {
    assert.deepEqual(validateWorkspaceGraph(withExtraDependency(
      metadata(), name, "brokk-bifrost-analysis",
    )), [`${name} must not depend on workspace package brokk-bifrost-analysis`]);
  }
});

test("rejects one language crate depending on another", () => {
  for (const name of knowledgeCrates) {
    for (const other of knowledgeCrates.filter((candidate) => candidate !== name)) {
      assert.deepEqual(validateWorkspaceGraph(withExtraDependency(
        metadata(), name, other,
      )), [`${name} must not depend on workspace package ${other}`]);
    }
  }
  for (const { name, knowledge } of languageImplementations) {
    const peers = [
      ...knowledgeCrates.filter((candidate) => candidate !== knowledge),
      ...languageImplementations.map((entry) => entry.name).filter((candidate) => candidate !== name),
    ];
    for (const other of peers) {
      assert.deepEqual(validateWorkspaceGraph(withExtraDependency(
        metadata(), name, other,
      )), [`${name} must not depend on workspace package ${other}`]);
    }
  }
});

test("language implementations depend on analysis while knowledge stays below it", () => {
  for (const { name, knowledge } of languageImplementations) {
    assert.deepEqual(validateWorkspaceGraph(metadata()), []);
    assert.deepEqual(validateWorkspaceGraph(withExtraDependency(
      metadata(), knowledge, name,
    )), [`${knowledge} must not depend on workspace package ${name}`]);
    assert.deepEqual(validateWorkspaceGraph(withExtraDependency(
      metadata(), "brokk-bifrost-analysis", name,
    )), [`brokk-bifrost-analysis must not depend on workspace package ${name}`]);
  }
});

test("rejects a cpp crate reaching back up to analysis", () => {
  assert.deepEqual(
    validateWorkspaceGraph(
      metadata({
        dependencies: {
          "brokk-bifrost-cpp": [
            dependency("brokk-bifrost-core"),
            dependency("brokk-bifrost-analysis"),
          ],
        },
      }),
    ),
    ["brokk-bifrost-cpp must not depend on workspace package brokk-bifrost-analysis"],
  );
});

test("rejects a jvm crate reaching back up to analysis", () => {
  assert.deepEqual(
    validateWorkspaceGraph(
      metadata({
        dependencies: {
          "brokk-bifrost-jvm": [
            dependency("brokk-bifrost-core"),
            dependency("brokk-bifrost-analysis"),
          ],
        },
      }),
    ),
    ["brokk-bifrost-jvm must not depend on workspace package brokk-bifrost-analysis"],
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

// A registry package is outside workspace_members, so checking only the
// workspace inventory cannot catch a transitive host dependency.
test("rejects the retired upstream LSP in the resolved registry closure", () => {
  const graph = metadata();
  const retired = {
    id: "registry+https://github.com/rust-lang/crates.io-index#brokk-bifrost-lsp@0.12.0",
    name: "brokk-bifrost-lsp",
    version: "0.12.0",
    dependencies: [],
  };
  graph.packages.push(retired);
  assert.deepEqual(validateWorkspaceGraph(graph), [
    `engine dependency graph contains retired upstream host ${retired.id}`,
  ]);
  graph.packages[graph.packages.length - 1] = {
    ...retired,
    id: "registry+https://github.com/rust-lang/crates.io-index#lsp-types@0.97.0",
    name: "lsp-types",
  };
  assert.deepEqual(validateWorkspaceGraph(graph), []);
});
