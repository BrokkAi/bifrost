import assert from "node:assert/strict";
import { readFile, rm } from "node:fs/promises";
import { dirname } from "node:path";
import test from "node:test";

import { DEFAULT_MAX_BYTES, DEFAULT_MAX_LINES } from "@earendil-works/pi-coding-agent";

import {
  BIFROST_CAPABILITIES,
  DEFAULT_BIFROST_CAPABILITIES,
} from "../extensions/bifrost-capabilities.ts";
import {
  assertToolsHaveUniqueNames,
  createBifrostSession,
} from "../extensions/bifrost-session.ts";

const launch = {
  command: "/tmp/bifrost",
  args: ["--root", "/workspace", "--mcp", "symbol"],
  cwd: "/workspace",
  env: {},
  source: "explicit",
};

function toolNamesFor(capabilityId) {
  const capability = BIFROST_CAPABILITIES.find((candidate) => candidate.id === capabilityId);
  return [
    ...capability.toolRequirements.map((alternatives) => alternatives[0]),
    ...("toolVariants" in capability ? capability.toolVariants[0] : []),
  ];
}

const SYMBOL_TOOL_NAMES = toolNamesFor("symbols");
const QUALITY_TOOL_NAMES = toolNamesFor("quality");
const QUERY_TOOL_NAMES = toolNamesFor("query");
const FILE_TOOL_NAMES = toolNamesFor("files");
const TEXT_TOOL_NAMES = toolNamesFor("text");
const TRANSFORMS_TOOL_NAMES = toolNamesFor("transforms");

// Keep fake MCP advertisements independent from the Pi capability declarations so
// a capability/toolset mismatch fails tests instead of teaching the fake server
// the same incorrect contract.
const SYMBOL_SERVER_TOOL_NAMES = [
  "search_symbols",
  "get_symbol_sources",
  "get_summaries",
  "scan_usages_by_location",
  "get_definitions_by_location",
  "get_type_by_location",
  "rename_symbol",
  "usage_graph",
];
const SLOPCOP_SERVER_TOOL_NAMES = [
  "compute_cyclomatic_complexity",
  "compute_cognitive_complexity",
  "report_comment_density_for_code_unit",
  "report_exception_handling_smells",
  "report_comment_density_for_files",
  "analyze_git_hotspots",
  "report_test_assertion_smells",
  "report_structural_clone_smells",
  "report_long_method_and_god_object_smells",
  "report_dead_code_and_unused_abstraction_smells",
  "report_secret_like_code",
  "analyze_commit",
];
const EXTENDED_SERVER_TOOL_NAMES = [
  "query_code",
  "get_symbol_locations",
  "get_symbol_ancestors",
  "find_filenames",
  "list_files",
  "most_relevant_files",
  "search_git_commit_messages",
  "get_git_log",
  "get_commit_diff",
  "jq",
  "xml_skim",
  "xml_select",
];
const SYMBOL_SELECTION_SERVER_TOOL_NAMES = [
  ...SYMBOL_SERVER_TOOL_NAMES,
  ...SLOPCOP_SERVER_TOOL_NAMES,
];

function piNames(toolNames) {
  return toolNames.map((name) => `bifrost_${name}`);
}

function fakePi(existingNames = [], initiallyActive = existingNames, acceptedNames) {
  const toolsByName = new Map();
  const registrationLog = [];
  let activeNames = [...initiallyActive];
  return {
    get registered() {
      return Array.from(toolsByName.values());
    },
    registrationLog,
    get activeNames() {
      return activeNames;
    },
    getAllTools() {
      return [
        ...existingNames.map((name) => ({ name })),
        ...Array.from(toolsByName.keys(), (name) => ({ name })),
      ];
    },
    getActiveTools() {
      return [...activeNames];
    },
    setActiveTools(names) {
      activeNames = acceptedNames
        ? names.filter((name) => acceptedNames.has(name))
        : [...names];
    },
    registerTool(tool) {
      toolsByName.set(tool.name, tool);
      registrationLog.push(tool.name);
    },
  };
}

function stubTool(name) {
  return { name, inputSchema: { type: "object", properties: {} } };
}

function symbolTool() {
  return {
    name: "search_symbols",
    description: "Search symbols.",
    inputSchema: {
      type: "object",
      properties: { query: { type: "string" } },
      required: ["query"],
    },
  };
}

function symbolTools({ searchSymbolsDescription } = {}) {
  return SYMBOL_SELECTION_SERVER_TOOL_NAMES.map((name) => {
    if (name !== "search_symbols") {
      return stubTool(name);
    }
    const tool = symbolTool();
    return searchSymbolsDescription ? { ...tool, description: searchSymbolsDescription } : tool;
  });
}

function queryTools() {
  return QUERY_TOOL_NAMES.map((name) => stubTool(name));
}

function transformsTools() {
  return TRANSFORMS_TOOL_NAMES.map((name) => stubTool(name));
}

function textTools({ includeAll = true } = {}) {
  const names = includeAll ? TEXT_TOOL_NAMES : TEXT_TOOL_NAMES.slice(0, 1);
  return names.map((name) => stubTool(name));
}

function defaultServerTools() {
  return [
    ...symbolTools(),
    ...EXTENDED_SERVER_TOOL_NAMES.map((name) => stubTool(name)),
  ];
}

function fakeClient(options = {}) {
  const calls = [];
  let closeCount = 0;
  let closeHandler = () => {};
  return {
    calls,
    get closeCount() {
      return closeCount;
    },
    connect: options.connect ?? (async () => {}),
    listTools: options.listTools ?? (async () => symbolTools()),
    async callTool(name, args, requestOptions) {
      calls.push({ name, args, options: requestOptions });
      if (options.callTool) {
        return await options.callTool(name, args, requestOptions);
      }
      return options.result ?? { content: [{ type: "text", text: "found" }] };
    },
    onClose(handler) {
      closeHandler = handler;
    },
    triggerUnexpectedClose() {
      closeHandler();
    },
    async close() {
      closeCount += 1;
      await options.onClose?.();
    },
  };
}

function dependencies(clients, errors = [], resolved = []) {
  let index = 0;
  return {
    async resolveLaunch(root, toolset) {
      resolved.push({ root, toolset });
      return { ...launch, cwd: root, args: ["--root", root, "--mcp", toolset] };
    },
    createClient: () => clients[index++],
    reportError: (error) => errors.push(error),
  };
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function connectedStatus(workspace, capabilities, toolCount) {
  return { state: "connected", workspace, toolCount, capabilities };
}

test("registers a namespaced tool and forwards the canonical MCP name", async () => {
  const pi = fakePi(["read"]);
  const client = fakeClient();
  const resolved = [];
  const session = createBifrostSession(pi, dependencies([client], [], resolved));
  assert.equal(await session.start("/workspace", ["symbols"]), true);

  assert.deepEqual(session.status(), connectedStatus("/workspace", ["symbols"], SYMBOL_TOOL_NAMES.length));
  assert.deepEqual(resolved, [{ root: "/workspace", toolset: "symbol|slopcop" }]);
  assert.equal(pi.registered[0].name, "bifrost_search_symbols");
  assert.equal(typeof pi.registered[0].renderCall, "function");
  assert.equal(typeof pi.registered[0].renderResult, "function");
  assert.deepEqual(new Set(pi.activeNames), new Set(["read", ...piNames(SYMBOL_TOOL_NAMES)]));

  const controller = new AbortController();
  const result = await pi.registered[0].execute("call-1", { query: "Widget" }, controller.signal);
  assert.deepEqual(result.content, [{ type: "text", text: "found" }]);
  assert.deepEqual(client.calls[0].name, "search_symbols");
  assert.deepEqual(client.calls[0].args, { query: "Widget" });
  assert.equal(client.calls[0].options.signal, controller.signal);
  assert.equal(client.calls[0].options.timeout, 300_000);

  const inactiveQualityTool = pi.registered.find(
    (tool) => tool.name === "bifrost_compute_cyclomatic_complexity",
  );
  assert.ok(inactiveQualityTool);
  await assert.rejects(
    inactiveQualityTool.execute("inactive-quality", {}),
    /capability is not active/,
  );
});

test("default capabilities match the real MCP toolset boundaries", async () => {
  const pi = fakePi(["read"]);
  const resolved = [];
  const session = createBifrostSession(
    pi,
    dependencies([fakeClient({ listTools: async () => defaultServerTools() })], [], resolved),
  );

  assert.equal(await session.start("/workspace", DEFAULT_BIFROST_CAPABILITIES), true);
  assert.deepEqual(resolved, [{ root: "/workspace", toolset: "symbol|extended|slopcop" }]);
  assert.deepEqual(
    new Set(pi.activeNames),
    new Set([
      "read",
      ...piNames(SYMBOL_TOOL_NAMES),
      ...piNames(QUERY_TOOL_NAMES),
      ...piNames(FILE_TOOL_NAMES),
    ]),
  );
  await assert.rejects(
    pi.registered.find((tool) => tool.name === "bifrost_compute_cyclomatic_complexity")
      .execute("inactive-quality", {}),
    /capability is not active/,
  );
});

test("bounds SDK call failures and preserves the complete diagnostic in an overflow file", async (t) => {
  const oversized = `${"transport failure ".repeat(6)}\n`.repeat(DEFAULT_MAX_LINES + 1000);
  const cause = new Error(oversized);
  const client = fakeClient({
    callTool: async () => {
      throw cause;
    },
  });
  const pi = fakePi();
  const session = createBifrostSession(pi, dependencies([client]));
  assert.equal(await session.start("/workspace", ["symbols"]), true);

  let error;
  try {
    await pi.registered[0].execute("failed-call", { query: "Widget" });
  } catch (caught) {
    error = caught;
  }

  assert.ok(error instanceof Error);
  assert.equal(error.cause, cause);
  assert.ok(Buffer.byteLength(error.message, "utf8") <= DEFAULT_MAX_BYTES);
  assert.ok(error.message.split("\n").length <= DEFAULT_MAX_LINES);
  const pathMatch = error.message.match(/Full output: ([^\]]+)]$/);
  assert.ok(pathMatch);
  const fullOutputPath = pathMatch[1];
  t.after(() => rm(dirname(fullOutputPath), { recursive: true }));
  assert.equal(
    await readFile(fullOutputPath, "utf8"),
    `Bifrost tool search_symbols failed: ${oversized}`,
  );
});

test("accepts reference-rendered symbol tools as alternatives to location-rendered tools", async () => {
  const referenceTools = symbolTools()
    .filter((tool) => ![
      "scan_usages_by_location",
      "get_definitions_by_location",
      "get_type_by_location",
    ].includes(tool.name));
  referenceTools.push(stubTool("scan_usages_by_reference"), stubTool("get_definitions_by_reference"));
  const pi = fakePi();
  const session = createBifrostSession(
    pi,
    dependencies([fakeClient({ listTools: async () => referenceTools })]),
  );

  assert.equal(await session.start("/workspace", ["symbols"]), true);
  assert.equal(session.status().state, "connected");
  assert.ok(pi.activeNames.includes("bifrost_scan_usages_by_reference"));
  assert.ok(pi.activeNames.includes("bifrost_get_definitions_by_reference"));
});

test("registers newly advertised unclassified tools but keeps them inactive", async () => {
  const client = fakeClient({ listTools: async () => [
    ...symbolTools(),
    { name: "future_symbol_tool", inputSchema: { type: "object" } },
  ] });
  const pi = fakePi(["read"]);
  const session = createBifrostSession(pi, dependencies([client]));

  assert.equal(await session.start("/workspace", ["symbols"]), true);
  assert.deepEqual(pi.registered.map((tool) => tool.name), [
    ...piNames(SYMBOL_SELECTION_SERVER_TOOL_NAMES),
    "bifrost_future_symbol_tool",
  ]);
  assert.deepEqual(new Set(pi.activeNames), new Set(["read", ...piNames(SYMBOL_TOOL_NAMES)]));
});

test("derives active Bifrost tools from Pi's post-filter tool set", async () => {
  const pi = fakePi(["read"], ["read"], new Set(["read"]));
  const session = createBifrostSession(pi, dependencies([fakeClient()]));

  assert.equal(await session.start("/workspace", ["symbols"]), true);

  assert.equal(session.status().state, "connected");
  assert.equal(session.status().toolCount, 0);
  assert.deepEqual(pi.activeNames, ["read"]);
  await assert.rejects(
    pi.registered[0].execute("filtered", { query: "Widget" }),
    /capability is not active/,
  );
});

test("detects duplicate and terminal-unsafe canonical names before registration", () => {
  assert.throws(
    () => assertToolsHaveUniqueNames([{ name: "same" }, { name: "same" }]),
    /duplicate tool name: same/,
  );
  assert.throws(
    () => assertToolsHaveUniqueNames([{ name: "unsafe\u001b]52;c;U0VDUkVU\u0007" }]),
    /unsafe name/,
  );
});

test("sanitizes discovered labels and descriptions before registration", async () => {
  const osc52 = "\u001b]52;c;U0VDUkVU\u0007";
  const tools = symbolTools();
  tools[0] = {
    ...tools[0],
    annotations: { title: `Symbol${osc52} Search` },
    description: `Search${osc52} symbols.`,
  };
  const pi = fakePi();
  const session = createBifrostSession(
    pi,
    dependencies([fakeClient({ listTools: async () => tools })]),
  );

  assert.equal(await session.start("/workspace", ["symbols"]), true);
  const registered = pi.registered.find((tool) => tool.name === "bifrost_search_symbols");
  assert.equal(registered.label, "Bifrost: Symbol Search");
  assert.doesNotMatch(registered.description, /\u001b\]52|U0VDUkVU|\u0007/);
});

test("changing capabilities reconnects, registers new tools, and preserves unrelated active tools", async () => {
  const pi = fakePi(["read"]);
  const first = fakeClient();
  const second = fakeClient({ listTools: async () => [...symbolTools(), ...textTools()] });
  const resolved = [];
  const session = createBifrostSession(pi, dependencies([first, second], [], resolved));

  await session.start("/workspace", ["symbols"]);
  assert.equal(await session.applySelection(["symbols", "text"]), true);

  assert.equal(first.closeCount, 1);
  assert.equal(pi.registered.length, SYMBOL_SELECTION_SERVER_TOOL_NAMES.length + TEXT_TOOL_NAMES.length);
  assert.deepEqual(
    new Set(pi.activeNames),
    new Set(["read", ...piNames(SYMBOL_TOOL_NAMES), ...piNames(TEXT_TOOL_NAMES)]),
  );
  assert.deepEqual(
    resolved.map((item) => item.toolset),
    ["symbol|slopcop", "symbol|slopcop|text"],
  );
  assert.deepEqual(
    session.status(),
    connectedStatus("/workspace", ["symbols", "text"], SYMBOL_TOOL_NAMES.length + TEXT_TOOL_NAMES.length),
  );
});

test("reconnecting re-registers tools by name so schemas and descriptions refresh", async () => {
  const pi = fakePi();
  const first = fakeClient();
  const second = fakeClient({ listTools: async () => [
    ...symbolTools({ searchSymbolsDescription: "Updated search symbols description." }),
    ...textTools(),
  ] });
  const session = createBifrostSession(pi, dependencies([first, second]));

  await session.start("/workspace", ["symbols"]);
  assert.match(pi.registered.find((tool) => tool.name === "bifrost_search_symbols").description, /Search symbols\./);

  assert.equal(await session.applySelection(["symbols", "text"]), true);

  assert.match(
    pi.registered.find((tool) => tool.name === "bifrost_search_symbols").description,
    /Updated search symbols description\./,
  );
  assert.equal(
    pi.registrationLog.filter((name) => name === "bifrost_search_symbols").length,
    2,
  );
});

test("disabling a capability without changing the server expression does not reconnect", async () => {
  const client = fakeClient({ listTools: async () => [...queryTools(), ...transformsTools()] });
  const pi = fakePi(["read"]);
  const session = createBifrostSession(pi, dependencies([client]));

  await session.start("/workspace", ["query", "transforms"]);
  await session.applySelection(["query"]);

  assert.equal(client.closeCount, 0);
  assert.deepEqual(new Set(pi.activeNames), new Set(["read", ...piNames(QUERY_TOOL_NAMES)]));
  await assert.rejects(
    pi.registered.find((tool) => tool.name === "bifrost_jq").execute("call", {}),
    /capability is not active/,
  );
});

test("enabling quality while Symbols is active does not reconnect", async () => {
  const client = fakeClient();
  const pi = fakePi(["read"]);
  const session = createBifrostSession(pi, dependencies([client]));

  await session.start("/workspace", ["symbols"]);
  assert.equal(await session.applySelection(["symbols", "quality"]), true);

  assert.equal(client.closeCount, 0);
  assert.deepEqual(
    new Set(pi.activeNames),
    new Set(["read", ...piNames(SYMBOL_TOOL_NAMES), ...piNames(QUALITY_TOOL_NAMES)]),
  );
});

test("adding a capability on the current server validates its advertised tools", async () => {
  const client = fakeClient({ listTools: async () => queryTools() });
  const pi = fakePi(["read"]);
  const session = createBifrostSession(pi, dependencies([client]));
  await session.start("/workspace", ["query"]);

  assert.equal(await session.applySelection(["query", "transforms"]), false);

  assert.deepEqual(session.status().capabilities, ["query"]);
  assert.equal(session.status().state, "connected");
  assert.match(session.status().lastOperationError.message, /jq/);
  assert.deepEqual(new Set(pi.activeNames), new Set(["read", ...piNames(QUERY_TOOL_NAMES)]));
  assert.equal(client.closeCount, 0);
});

test("disabling every capability closes the child and reports disconnected", async () => {
  const client = fakeClient();
  const pi = fakePi(["read"]);
  const session = createBifrostSession(pi, dependencies([client]));
  await session.start("/workspace", ["symbols"]);

  assert.equal(await session.applySelection([]), true);
  assert.equal(client.closeCount, 1);
  assert.deepEqual(session.status(), {
    state: "disconnected",
    workspace: "/workspace",
    toolCount: 0,
    capabilities: [],
  });
  assert.deepEqual(pi.activeNames, ["read"]);
  assert.equal(await session.applySelection([]), true);
  assert.equal(session.status().state, "disconnected");
});

test("shutdown waits for an in-flight disable cleanup and invalidates its success", async () => {
  const closing = deferred();
  const client = fakeClient({ onClose: () => closing.promise });
  const pi = fakePi();
  const session = createBifrostSession(pi, dependencies([client]));
  await session.start("/workspace", ["symbols"]);

  const disabling = session.applySelection([]);
  await new Promise((resolve) => setImmediate(resolve));
  let shutdownSettled = false;
  const shuttingDown = session.shutdown().then(() => { shutdownSettled = true; });
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(shutdownSettled, false);
  closing.resolve();
  assert.equal(await disabling, false);
  await shuttingDown;
  assert.equal(session.status().workspace, undefined);
  assert.equal(client.closeCount, 1);
});

test("failed disable cleanup cannot overwrite a newer shutdown", async () => {
  const closing = deferred();
  const client = fakeClient({ onClose: () => closing.promise });
  const pi = fakePi(["read"]);
  const session = createBifrostSession(pi, dependencies([client]));
  await session.start("/workspace", ["symbols"]);

  const disabling = session.applySelection([]);
  await new Promise((resolve) => setImmediate(resolve));
  const shuttingDown = assert.rejects(session.shutdown(), /cleanup failed/);
  closing.reject(new Error("close failed"));

  assert.equal(await disabling, false);
  await shuttingDown;
  assert.deepEqual(session.status(), {
    state: "disconnected",
    workspace: undefined,
    toolCount: 0,
    capabilities: [],
  });
  assert.deepEqual(pi.activeNames, ["read"]);
});

test("a failed capability change keeps the previous client and selection", async () => {
  const first = fakeClient();
  const incomplete = fakeClient({ listTools: async () => [...symbolTools(), ...textTools({ includeAll: false })] });
  const pi = fakePi();
  const errors = [];
  const session = createBifrostSession(pi, dependencies([first, incomplete], errors));

  await session.start("/workspace", ["symbols"]);
  assert.equal(await session.applySelection(["symbols", "text"]), false);

  assert.equal(first.closeCount, 0);
  assert.equal(incomplete.closeCount, 1);
  assert.deepEqual(session.status().capabilities, ["symbols"]);
  assert.equal(session.status().state, "connected");
  assert.equal(errors.length, 0);
  assert.match(session.status().lastOperationError.message, /Bifrost MCP configuration failed:/);
  assert.match(String(session.status().lastOperationError.cause), /search_file_contents/);
  assert.equal((await pi.registered[0].execute("still-live", { query: "x" })).content[0].text, "found");
});

test("reapplying the same selection restores active Bifrost tools without reconnecting", async () => {
  const client = fakeClient();
  const pi = fakePi(["read"]);
  const session = createBifrostSession(pi, dependencies([client]));
  await session.start("/workspace", ["symbols"]);

  pi.setActiveTools(["read"]);
  assert.equal(session.status().toolCount, 0);
  await assert.rejects(
    pi.registered[0].execute("manually-disabled", { query: "Widget" }),
    /capability is not active/,
  );
  assert.equal(await session.applySelection(["symbols"]), true);

  assert.deepEqual(new Set(pi.activeNames), new Set(["read", ...piNames(SYMBOL_TOOL_NAMES)]));
  assert.equal(client.closeCount, 0);
});

test("a successful no-op clears the previous operation failure", async () => {
  const first = fakeClient();
  const incomplete = fakeClient({
    listTools: async () => [...symbolTools(), ...textTools({ includeAll: false })],
  });
  const session = createBifrostSession(fakePi(), dependencies([first, incomplete]));
  await session.start("/workspace", ["symbols"]);
  assert.equal(await session.applySelection(["symbols", "text"]), false);
  assert.ok(session.status().lastOperationError);

  assert.equal(await session.applySelection(["symbols"]), true);

  assert.equal(session.status().lastOperationError, undefined);
  assert.equal(session.status().state, "connected");
  assert.equal(first.closeCount, 0);
});

test("a newer no-op selection cancels an older reconnect in progress", async () => {
  const replacementConnect = deferred();
  const first = fakeClient();
  const replacement = fakeClient({
    connect: () => replacementConnect.promise,
    listTools: async () => [...symbolTools(), ...textTools()],
  });
  const pi = fakePi();
  const session = createBifrostSession(pi, dependencies([first, replacement]));
  await session.start("/workspace", ["symbols"]);

  const enablingText = session.applySelection(["symbols", "text"]);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(await session.applySelection(["symbols"]), true);
  replacementConnect.resolve();

  assert.equal(await enablingText, false);
  assert.deepEqual(session.status().capabilities, ["symbols"]);
  assert.equal(session.status().state, "connected");
  assert.equal(first.closeCount, 0);
  assert.equal(replacement.closeCount, 1);
});

test("a newer selection cannot adopt a candidate owned by stale cleanup", async () => {
  const closingFirst = deferred();
  const first = fakeClient({ onClose: () => closingFirst.promise });
  const second = fakeClient({ listTools: async () => [...symbolTools(), ...textTools()] });
  const session = createBifrostSession(fakePi(), dependencies([first, second]));
  await session.start("/workspace", ["symbols"]);

  const firstChange = session.applySelection(["symbols", "text"]);
  await new Promise((resolve) => setImmediate(resolve));
  const supersedingChange = session.applySelection(["symbols", "text"]);
  await new Promise((resolve) => setImmediate(resolve));
  closingFirst.reject(new Error("old cleanup failed"));

  assert.equal(await firstChange, false);
  assert.equal(await supersedingChange, false);
  assert.equal(second.closeCount, 1);
  assert.deepEqual(session.status().capabilities, ["symbols"]);
  assert.equal(session.status().state, "error");
});

test("a failed replacement does not resurrect a previous client that closed", async () => {
  const replacementConnect = deferred();
  const first = fakeClient();
  const replacement = fakeClient({ connect: () => replacementConnect.promise });
  const pi = fakePi();
  const session = createBifrostSession(pi, dependencies([first, replacement]));
  await session.start("/workspace", ["symbols"]);

  const changing = session.applySelection(["symbols", "text"]);
  await new Promise((resolve) => setImmediate(resolve));
  first.triggerUnexpectedClose();
  replacementConnect.reject(new Error("replacement failed"));
  assert.equal(await changing, false);

  assert.equal(session.status().state, "error");
  assert.equal(session.status().toolCount, 0);
  await assert.rejects(pi.registered[0].execute("dead", {}), /capability is not active/);
});

test("shutdown while start waits for old cleanup prevents a later reconnect", async () => {
  const closing = deferred();
  const first = fakeClient({ onClose: () => closing.promise });
  const second = fakeClient();
  const pi = fakePi();
  const session = createBifrostSession(pi, dependencies([first, second]));
  await session.start("/one", ["symbols"]);

  const restarting = session.start("/two", ["symbols"]);
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(session.status(), {
    state: "connecting",
    workspace: "/two",
    toolCount: 0,
    capabilities: ["symbols"],
  });
  assert.deepEqual(pi.activeNames, []);
  await assert.rejects(
    pi.registered[0].execute("during-restart", { query: "Widget" }),
    /capability is not active/,
  );
  const shuttingDown = session.shutdown();
  closing.resolve();
  await Promise.all([restarting, shuttingDown]);

  assert.equal(second.closeCount, 0);
  assert.equal(session.status().state, "disconnected");
});

test("shutdown clears the workspace before awaiting cleanup so a pending applySelection cannot reconnect", async () => {
  const closing = deferred();
  const first = fakeClient({ onClose: () => closing.promise });
  const pi = fakePi();
  const session = createBifrostSession(pi, dependencies([first]));
  await session.start("/workspace", ["symbols"]);

  const shuttingDown = session.shutdown();
  await assert.rejects(session.applySelection(["symbols"]), /workspace/);
  assert.equal(session.status().workspace, undefined);
  closing.resolve();
  await shuttingDown;

  assert.equal(session.status().state, "disconnected");
  assert.equal(session.status().workspace, undefined);
});

test("returning true after closing the replaced client is revalidated against a concurrent shutdown", async () => {
  const closingFirst = deferred();
  const first = fakeClient({ onClose: () => closingFirst.promise });
  const second = fakeClient({ listTools: async () => [...symbolTools(), ...textTools()] });
  const pi = fakePi();
  const session = createBifrostSession(pi, dependencies([first, second]));
  await session.start("/workspace", ["symbols"]);

  const applying = session.applySelection(["symbols", "text"]);
  await new Promise((resolve) => setImmediate(resolve));
  // The candidate is live but unpublished while connectSelection awaits closeOnce(first).
  const shuttingDown = session.shutdown();
  closingFirst.resolve();
  const applied = await applying;
  await shuttingDown;

  assert.equal(applied, false);
  assert.equal(session.status().state, "disconnected");
  assert.equal(first.closeCount, 1);
  assert.equal(second.closeCount, 1);
});

test("a replacement that closes during old-client cleanup fails without a duplicate background report", async () => {
  const closingFirst = deferred();
  const first = fakeClient({ onClose: () => closingFirst.promise });
  const second = fakeClient({ listTools: async () => [...symbolTools(), ...textTools()] });
  const pi = fakePi();
  const errors = [];
  const session = createBifrostSession(pi, dependencies([first, second], errors));
  await session.start("/workspace", ["symbols"]);

  const applying = session.applySelection(["symbols", "text"]);
  await new Promise((resolve) => setImmediate(resolve));
  second.triggerUnexpectedClose();
  closingFirst.resolve();

  assert.equal(await applying, false);
  assert.equal(session.status().state, "error");
  assert.equal(session.status().toolCount, 0);
  assert.deepEqual(session.status().capabilities, ["symbols"]);
  assert.equal(errors.length, 0);
  assert.equal(first.closeCount, 1);
});

test("closed candidate cleanup cannot overwrite a newer shutdown", async () => {
  const closingFirst = deferred();
  const closingCandidate = deferred();
  const first = fakeClient({ onClose: () => closingFirst.promise });
  const second = fakeClient({
    listTools: async () => [...symbolTools(), ...textTools()],
    onClose: () => closingCandidate.promise,
  });
  const pi = fakePi(["read"]);
  const session = createBifrostSession(pi, dependencies([first, second]));
  await session.start("/workspace", ["symbols"]);

  const applying = session.applySelection(["symbols", "text"]);
  await new Promise((resolve) => setImmediate(resolve));
  second.triggerUnexpectedClose();
  closingFirst.resolve();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(second.closeCount, 1);
  const shuttingDown = session.shutdown();
  closingCandidate.resolve();

  assert.equal(await applying, false);
  await shuttingDown;
  assert.deepEqual(session.status(), {
    state: "disconnected",
    workspace: undefined,
    toolCount: 0,
    capabilities: [],
  });
  assert.deepEqual(pi.activeNames, ["read"]);
});

test("a candidate that closes before publication cannot become active", async () => {
  let candidate;
  candidate = fakeClient({
    listTools: async () => {
      candidate.triggerUnexpectedClose();
      return symbolTools();
    },
  });
  const pi = fakePi();
  const session = createBifrostSession(pi, dependencies([candidate]));

  assert.equal(await session.start("/workspace", ["symbols"]), false);

  assert.equal(session.status().state, "error");
  assert.deepEqual(session.status().capabilities, ["symbols"]);
  assert.equal(session.status().toolCount, 0);
  assert.equal(candidate.closeCount, 1);
  assert.deepEqual(pi.activeNames, []);
});

test("a stale startup client is closed and cannot replace the newer session", async () => {
  const connecting = deferred();
  const first = fakeClient({ connect: () => connecting.promise });
  const second = fakeClient();
  const pi = fakePi();
  const session = createBifrostSession(pi, dependencies([first, second]));

  const firstStart = session.start("/one", ["symbols"]);
  await new Promise((resolve) => setImmediate(resolve));
  const secondStart = session.start("/two", ["symbols"]);
  await secondStart;
  connecting.resolve();
  await firstStart;

  assert.equal(first.closeCount, 1);
  assert.equal(second.closeCount, 0);
  assert.deepEqual(session.status(), connectedStatus("/two", ["symbols"], SYMBOL_TOOL_NAMES.length));
});

test("shutdown during startup and repeated shutdown close each client only once", async () => {
  const connecting = deferred();
  const client = fakeClient({ connect: () => connecting.promise });
  const pi = fakePi(["read"]);
  const session = createBifrostSession(pi, dependencies([client]));

  const starting = session.start("/workspace", ["symbols"]);
  await new Promise((resolve) => setImmediate(resolve));
  await session.shutdown();
  await session.shutdown();
  connecting.resolve();
  await starting;

  assert.equal(client.closeCount, 1);
  assert.equal(session.status().state, "disconnected");
  assert.deepEqual(pi.activeNames, ["read"]);
});

test("reapplying a selection after unexpected close reconnects", async () => {
  const first = fakeClient();
  const second = fakeClient();
  const pi = fakePi();
  const session = createBifrostSession(pi, dependencies([first, second]));
  await session.start("/workspace", ["symbols"]);
  first.triggerUnexpectedClose();

  assert.equal(await session.applySelection(["symbols"]), true);

  assert.equal(session.status().state, "connected");
  assert.deepEqual(new Set(pi.activeNames), new Set(piNames(SYMBOL_TOOL_NAMES)));
  assert.equal(second.closeCount, 0);
});

test("unexpected connection close marks namespaced tools inactive", async () => {
  const client = fakeClient();
  const pi = fakePi(["read"]);
  const errors = [];
  const session = createBifrostSession(pi, dependencies([client], errors));
  await session.start("/workspace", ["symbols"]);

  client.triggerUnexpectedClose();

  assert.equal(session.status().state, "error");
  assert.equal(session.status().toolCount, 0);
  assert.deepEqual(pi.activeNames, ["read"]);
  assert.ok(errors[0] instanceof Error);
  assert.match(errors[0].message, /connection closed unexpectedly/);
  await assert.rejects(
    pi.registered[0].execute("after-close", { query: "Widget" }),
    /capability is not active/,
  );
});

test("replacement cleanup failure cannot report a successful selection", async () => {
  const first = fakeClient({ onClose: async () => { throw new Error("close failed"); } });
  const second = fakeClient({ listTools: async () => [...symbolTools(), ...textTools()] });
  const pi = fakePi();
  const session = createBifrostSession(pi, dependencies([first, second]));
  await session.start("/workspace", ["symbols"]);

  assert.equal(await session.applySelection(["symbols", "text"]), false);

  assert.equal(session.status().state, "error");
  assert.deepEqual(session.status().capabilities, ["symbols"]);
  assert.match(session.status().lastOperationError.message, /cleanup/);
  assert.equal(first.closeCount, 1);
  assert.equal(second.closeCount, 1);
  assert.deepEqual(pi.activeNames, []);

  await assert.rejects(session.shutdown(), /cleanup failed/);
  assert.equal(first.closeCount, 2);
});

test("shutdown retains failed cleanup ownership and retries it", async () => {
  let closeAttempts = 0;
  const client = fakeClient({
    onClose: async () => {
      closeAttempts += 1;
      if (closeAttempts === 1) {
        throw new Error("close failed");
      }
    },
  });
  const session = createBifrostSession(fakePi(), dependencies([client]));
  await session.start("/workspace", ["symbols"]);

  await assert.rejects(session.shutdown(), /cleanup failed/);
  await session.shutdown();

  assert.equal(session.status().state, "disconnected");
  assert.equal(session.status().workspace, undefined);
  assert.equal(client.closeCount, 2);
});

test("startup failure preserves a safe diagnostic and underlying cause in status", async () => {
  const cause = new Error("protocol\u001b]52;c;U0VDUkVU\u0007 handshake failed");
  const client = fakeClient({ connect: async () => { throw cause; } });
  const errors = [];
  const session = createBifrostSession(fakePi(), dependencies([client], errors));

  assert.equal(await session.start("/workspace", ["symbols"]), false);
  assert.equal(client.closeCount, 1);
  assert.equal(errors.length, 0);
  assert.deepEqual(session.status().capabilities, ["symbols"]);
  assert.equal(
    session.status().lastOperationError.message,
    "Bifrost MCP configuration failed: protocol handshake failed",
  );
  assert.equal(session.status().lastOperationError.cause, cause);
});
