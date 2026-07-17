import assert from "node:assert/strict";
import test from "node:test";

import {
  assertNoToolCollisions,
  createBifrostSession,
} from "../extensions/bifrost-session.ts";

const launch = {
  command: "/tmp/bifrost",
  args: ["--root", "/workspace", "--mcp", "symbol|extended"],
  cwd: "/workspace",
  env: {},
  source: "explicit",
};

function fakePi(existingNames = []) {
  const registered = [];
  return {
    registered,
    getAllTools() {
      return [
        ...existingNames.map((name) => ({ name })),
        ...registered.map((tool) => ({ name: tool.name })),
      ];
    },
    registerTool(tool) {
      registered.push(tool);
    },
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
    listTools: options.listTools ?? (async () => [{
      name: "search_symbols",
      description: "Search symbols.",
      inputSchema: {
        type: "object",
        properties: { query: { type: "string" } },
        required: ["query"],
      },
    }]),
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

function dependencies(clients, errors = []) {
  let index = 0;
  return {
    resolveLaunch: async () => launch,
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

test("registers discovered tools and forwards arguments, cancellation, and five-minute timeout", async () => {
  const pi = fakePi(["read"]);
  const client = fakeClient();
  const session = createBifrostSession(pi, dependencies([client]));
  await session.start("/workspace");

  assert.deepEqual(session.status(), { state: "connected", workspace: "/workspace", toolCount: 1 });
  assert.equal(pi.registered.length, 1);
  assert.equal(pi.registered[0].name, "search_symbols");
  assert.equal(pi.registered[0].parameters.required[0], "query");

  const controller = new AbortController();
  const result = await pi.registered[0].execute("call-1", { query: "Widget" }, controller.signal);

  assert.deepEqual(result.content, [{ type: "text", text: "found" }]);
  assert.deepEqual(client.calls[0].name, "search_symbols");
  assert.deepEqual(client.calls[0].args, { query: "Widget" });
  assert.equal(client.calls[0].options.signal, controller.signal);
  assert.equal(client.calls[0].options.timeout, 300_000);
});

test("rejects collisions atomically and closes the startup client", async () => {
  const pi = fakePi(["search_symbols"]);
  const client = fakeClient();
  const errors = [];
  const session = createBifrostSession(pi, dependencies([client], errors));

  await session.start("/workspace");

  assert.equal(pi.registered.length, 0);
  assert.equal(client.closeCount, 1);
  assert.equal(session.status().state, "error");
  assert.match(errors[0], /tool name collision: search_symbols/);
});

test("detects duplicate names before registration", () => {
  assert.throws(
    () => assertNoToolCollisions([{ name: "same" }, { name: "same" }], []),
    /duplicate tool name: same/,
  );
});

test("restart closes the old client and existing definitions use the new session", async () => {
  const pi = fakePi();
  const first = fakeClient({ result: { content: [{ type: "text", text: "first" }] } });
  const second = fakeClient({ result: { content: [{ type: "text", text: "second" }] } });
  const session = createBifrostSession(pi, dependencies([first, second]));

  await session.start("/one");
  const registeredTool = pi.registered[0];
  assert.equal((await registeredTool.execute("one", { query: "x" })).content[0].text, "first");

  await session.start("/two");
  assert.equal(first.closeCount, 1);
  assert.equal(pi.registered.length, 1);
  assert.equal((await registeredTool.execute("two", { query: "x" })).content[0].text, "second");
  assert.deepEqual(session.status(), { state: "connected", workspace: "/two", toolCount: 1 });
});

test("a stale startup client is closed and cannot replace the newer session", async () => {
  const connecting = deferred();
  const first = fakeClient({ connect: () => connecting.promise });
  const second = fakeClient();
  const pi = fakePi();
  const session = createBifrostSession(pi, dependencies([first, second]));

  const firstStart = session.start("/one");
  await new Promise((resolve) => setImmediate(resolve));
  const secondStart = session.start("/two");
  await secondStart;
  connecting.resolve();
  await firstStart;

  assert.equal(first.closeCount, 1);
  assert.equal(second.closeCount, 0);
  assert.deepEqual(session.status(), { state: "connected", workspace: "/two", toolCount: 1 });
});

test("shutdown during startup and repeated shutdown close each client only once", async () => {
  const connecting = deferred();
  const client = fakeClient({ connect: () => connecting.promise });
  const session = createBifrostSession(fakePi(), dependencies([client]));

  const starting = session.start("/workspace");
  await new Promise((resolve) => setImmediate(resolve));
  await session.shutdown();
  await session.shutdown();
  connecting.resolve();
  await starting;

  assert.equal(client.closeCount, 1);
  assert.equal(session.status().state, "disconnected");
});

test("unexpected connection close marks registered tools unavailable", async () => {
  const client = fakeClient();
  const pi = fakePi();
  const errors = [];
  const session = createBifrostSession(pi, dependencies([client], errors));
  await session.start("/workspace");

  client.triggerUnexpectedClose();

  assert.deepEqual(session.status(), { state: "error", workspace: "/workspace", toolCount: 0 });
  assert.match(errors[0], /connection closed unexpectedly/);
  await assert.rejects(
    pi.registered[0].execute("after-close", { query: "Widget" }),
    /MCP session is not connected/,
  );
});

test("a failed tool registration can be retried on session restart", async () => {
  const pi = fakePi();
  const originalRegister = pi.registerTool;
  let failRegistration = true;
  pi.registerTool = (tool) => {
    if (failRegistration) {
      failRegistration = false;
      throw new Error("registration failed");
    }
    originalRegister.call(pi, tool);
  };
  const first = fakeClient();
  const second = fakeClient();
  const errors = [];
  const session = createBifrostSession(pi, dependencies([first, second], errors));

  await session.start("/workspace");
  assert.equal(session.status().state, "error");
  assert.equal(pi.registered.length, 0);

  await session.start("/workspace");
  assert.equal(session.status().state, "connected");
  assert.equal(pi.registered.length, 1);
});

test("startup failure reports a concise diagnostic and leaves tools unavailable", async () => {
  const client = fakeClient({ connect: async () => { throw new Error("protocol handshake failed"); } });
  const pi = fakePi();
  const errors = [];
  const session = createBifrostSession(pi, dependencies([client], errors));

  await session.start("/workspace");

  assert.equal(client.closeCount, 1);
  assert.equal(pi.registered.length, 0);
  assert.match(errors[0], /^Bifrost MCP startup failed: protocol handshake failed$/);
});
