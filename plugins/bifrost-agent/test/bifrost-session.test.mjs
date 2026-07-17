import assert from "node:assert/strict";
import test from "node:test";

import {
  assertNoToolCollisions,
  createBifrostSession,
} from "../extensions/bifrost-session.ts";

const launch = {
  command: "/tmp/bifrost",
  args: ["--root", "/workspace", "--mcp", "symbol"],
  cwd: "/workspace",
  env: {},
  source: "explicit",
};

function fakePi(existingNames = [], initiallyActive = existingNames) {
  const registered = [];
  let activeNames = [...initiallyActive];
  return {
    registered,
    get activeNames() {
      return activeNames;
    },
    getAllTools() {
      return [
        ...existingNames.map((name) => ({ name })),
        ...registered.map((tool) => ({ name: tool.name })),
      ];
    },
    getActiveTools() {
      return [...activeNames];
    },
    setActiveTools(names) {
      activeNames = [...names];
    },
    registerTool(tool) {
      registered.push(tool);
    },
  };
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

function qualityTool() {
  return {
    name: "compute_cyclomatic_complexity",
    description: "Compute complexity.",
    inputSchema: { type: "object", properties: {} },
  };
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
    listTools: options.listTools ?? (async () => [symbolTool()]),
    async callTool(name, args, requestOptions) {
      calls.push({ name, args, options: requestOptions });
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
    reportError: (message) => errors.push(message),
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

function connectedStatus(workspace, capabilities, toolCount = 1) {
  return { state: "connected", workspace, toolCount, capabilities };
}

test("registers a namespaced tool and forwards the canonical MCP name", async () => {
  const pi = fakePi(["read"]);
  const client = fakeClient();
  const resolved = [];
  const session = createBifrostSession(pi, dependencies([client], [], resolved));
  assert.equal(await session.start("/workspace", ["symbols"]), true);

  assert.deepEqual(session.status(), connectedStatus("/workspace", ["symbols"]));
  assert.deepEqual(resolved, [{ root: "/workspace", toolset: "symbol" }]);
  assert.equal(pi.registered[0].name, "bifrost_search_symbols");
  assert.deepEqual(new Set(pi.activeNames), new Set(["read", "bifrost_search_symbols"]));

  const controller = new AbortController();
  const result = await pi.registered[0].execute("call-1", { query: "Widget" }, controller.signal);
  assert.deepEqual(result.content, [{ type: "text", text: "found" }]);
  assert.deepEqual(client.calls[0].name, "search_symbols");
  assert.deepEqual(client.calls[0].args, { query: "Widget" });
  assert.equal(client.calls[0].options.signal, controller.signal);
  assert.equal(client.calls[0].options.timeout, 300_000);
});

test("registers newly advertised unclassified tools but keeps them inactive", async () => {
  const client = fakeClient({ listTools: async () => [
    symbolTool(),
    { name: "future_symbol_tool", inputSchema: { type: "object" } },
  ] });
  const pi = fakePi(["read"]);
  const session = createBifrostSession(pi, dependencies([client]));

  assert.equal(await session.start("/workspace", ["symbols"]), true);
  assert.deepEqual(pi.registered.map((tool) => tool.name), [
    "bifrost_search_symbols",
    "bifrost_future_symbol_tool",
  ]);
  assert.deepEqual(new Set(pi.activeNames), new Set(["read", "bifrost_search_symbols"]));
});

test("rejects namespaced collisions atomically", async () => {
  const pi = fakePi(["bifrost_search_symbols"]);
  const client = fakeClient();
  const errors = [];
  const session = createBifrostSession(pi, dependencies([client], errors));

  assert.equal(await session.start("/workspace", ["symbols"]), false);
  assert.equal(pi.registered.length, 0);
  assert.equal(client.closeCount, 1);
  assert.equal(session.status().state, "error");
  assert.match(errors[0], /tool name collision: bifrost_search_symbols/);
});

test("detects duplicate canonical names before registration", () => {
  assert.throws(
    () => assertNoToolCollisions([{ name: "same" }, { name: "same" }], []),
    /duplicate tool name: same/,
  );
});

test("changing capabilities reconnects, registers new tools, and preserves unrelated active tools", async () => {
  const pi = fakePi(["read"]);
  const first = fakeClient();
  const second = fakeClient({ listTools: async () => [symbolTool(), qualityTool()] });
  const resolved = [];
  const session = createBifrostSession(pi, dependencies([first, second], [], resolved));

  await session.start("/workspace", ["symbols"]);
  assert.equal(await session.applySelection(["symbols", "quality"]), true);

  assert.equal(first.closeCount, 1);
  assert.equal(pi.registered.length, 2);
  assert.deepEqual(
    new Set(pi.activeNames),
    new Set(["read", "bifrost_search_symbols", "bifrost_compute_cyclomatic_complexity"]),
  );
  assert.deepEqual(resolved.map((item) => item.toolset), ["symbol", "symbol|slopcop"]);
  assert.deepEqual(session.status(), connectedStatus("/workspace", ["symbols", "quality"], 2));
});

test("disabling a capability without changing the server expression does not reconnect", async () => {
  const client = fakeClient({ listTools: async () => [
    { name: "query_code", inputSchema: { type: "object" } },
    { name: "jq", inputSchema: { type: "object" } },
  ] });
  const pi = fakePi(["read"]);
  const session = createBifrostSession(pi, dependencies([client]));

  await session.start("/workspace", ["query", "transforms"]);
  await session.applySelection(["query"]);

  assert.equal(client.closeCount, 0);
  assert.deepEqual(new Set(pi.activeNames), new Set(["read", "bifrost_query_code"]));
  await assert.rejects(
    pi.registered.find((tool) => tool.name === "bifrost_jq").execute("call", {}),
    /capability is not active/,
  );
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

test("a failed capability change keeps the previous client and selection", async () => {
  const first = fakeClient();
  const unavailable = fakeClient({ listTools: async () => [symbolTool()] });
  const pi = fakePi();
  const errors = [];
  const session = createBifrostSession(pi, dependencies([first, unavailable], errors));

  await session.start("/workspace", ["symbols"]);
  assert.equal(await session.applySelection(["symbols", "semantic"]), false);

  assert.equal(first.closeCount, 0);
  assert.equal(unavailable.closeCount, 1);
  assert.deepEqual(session.status().capabilities, ["symbols"]);
  assert.equal(session.status().state, "connected");
  assert.match(errors.at(-1), /semantic/);
  assert.equal((await pi.registered[0].execute("still-live", { query: "x" })).content[0].text, "found");
});

test("reapplying the same selection restores active Bifrost tools without reconnecting", async () => {
  const client = fakeClient();
  const pi = fakePi(["read"]);
  const session = createBifrostSession(pi, dependencies([client]));
  await session.start("/workspace", ["symbols"]);

  pi.setActiveTools(["read"]);
  assert.equal(await session.applySelection(["symbols"]), true);

  assert.deepEqual(new Set(pi.activeNames), new Set(["read", "bifrost_search_symbols"]));
  assert.equal(client.closeCount, 0);
});

test("a failed replacement does not resurrect a previous client that closed", async () => {
  const replacementConnect = deferred();
  const first = fakeClient();
  const replacement = fakeClient({ connect: () => replacementConnect.promise });
  const pi = fakePi();
  const session = createBifrostSession(pi, dependencies([first, replacement]));
  await session.start("/workspace", ["symbols"]);

  const changing = session.applySelection(["symbols", "quality"]);
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
  const shuttingDown = session.shutdown();
  closing.resolve();
  await Promise.all([restarting, shuttingDown]);

  assert.equal(second.closeCount, 0);
  assert.equal(session.status().state, "disconnected");
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
  assert.deepEqual(session.status(), connectedStatus("/two", ["symbols"]));
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
  assert.deepEqual(pi.activeNames, ["bifrost_search_symbols"]);
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
  assert.match(errors[0], /connection closed unexpectedly/);
  await assert.rejects(
    pi.registered[0].execute("after-close", { query: "Widget" }),
    /capability is not active/,
  );
});

test("startup failure reports a concise diagnostic", async () => {
  const client = fakeClient({ connect: async () => { throw new Error("protocol handshake failed"); } });
  const errors = [];
  const session = createBifrostSession(fakePi(), dependencies([client], errors));

  assert.equal(await session.start("/workspace", ["symbols"]), false);
  assert.equal(client.closeCount, 1);
  assert.match(errors[0], /^Bifrost MCP configuration failed: protocol handshake failed$/);
});
