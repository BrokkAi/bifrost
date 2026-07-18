import assert from "node:assert/strict";
import test from "node:test";

import { initTheme } from "@earendil-works/pi-coding-agent";

import {
  BIFROST_PROMPT_NOTE,
  configureBifrostExtension,
} from "../extensions/bifrost.ts";

function fakePi() {
  const handlers = new Map();
  const commands = new Map();
  return {
    handlers,
    commands,
    on(name, handler) {
      handlers.set(name, handler);
    },
    registerCommand(name, command) {
      commands.set(name, command);
    },
  };
}

function fakeSession(overrides = {}) {
  const starts = [];
  const applied = [];
  let status = {
    state: "connected",
    workspace: "/workspace",
    toolCount: 3,
    capabilities: ["symbols", "query", "files"],
  };
  let errorHandler = () => {};
  return {
    starts,
    applied,
    async start(workspace, capabilities) {
      starts.push({ workspace, capabilities: [...capabilities] });
      status = {
        ...status,
        state: capabilities.length > 0 ? "connected" : "disconnected",
        workspace,
        toolCount: capabilities.length > 0 ? status.toolCount : 0,
        capabilities: [...capabilities],
      };
      return true;
    },
    async applySelection(capabilities) {
      applied.push([...capabilities]);
      status = {
        ...status,
        state: capabilities.length > 0 ? "connected" : "disconnected",
        toolCount: capabilities.length > 0 ? status.toolCount : 0,
        capabilities: [...capabilities],
      };
      return true;
    },
    async shutdown() {},
    status: () => status,
    setErrorHandler(handler) {
      errorHandler = handler;
    },
    reportError(message) {
      errorHandler(message);
    },
    setStatus(next) {
      status = next;
    },
    ...overrides,
  };
}

function dependencies(session, saved, saves = []) {
  return {
    createSession: () => session,
    settingsStore: {
      async load() {
        return saved;
      },
      async save(workspace, capabilities) {
        saves.push({ workspace, capabilities: [...capabilities] });
      },
    },
  };
}

const theme = {
  fg: (_color, text) => text,
  bold: (text) => text,
};

test("restores workspace settings and injects only the short Pi namespace note", async () => {
  const pi = fakePi();
  const session = fakeSession();
  configureBifrostExtension(pi, dependencies(session, ["symbols", "quality"]));

  await pi.handlers.get("session_start")({}, {
    cwd: "/workspace",
    hasUI: false,
    ui: { notify() {} },
  });
  assert.deepEqual(session.starts, [{ workspace: "/workspace", capabilities: ["symbols", "quality"] }]);

  const result = await pi.handlers.get("before_agent_start")({ systemPrompt: "base" });
  assert.equal(result.systemPrompt, `base\n\n${BIFROST_PROMPT_NOTE}`);

  session.setStatus({ state: "disconnected", workspace: "/workspace", toolCount: 0, capabilities: [] });
  assert.equal(await pi.handlers.get("before_agent_start")({ systemPrompt: "base" }), undefined);
  session.setStatus({ state: "connected", workspace: "/workspace", toolCount: 0, capabilities: ["symbols"] });
  assert.equal(await pi.handlers.get("before_agent_start")({ systemPrompt: "base" }), undefined);
});

test("malformed settings fail closed with a TUI diagnostic", async () => {
  const pi = fakePi();
  const session = fakeSession();
  const settingsError = new Error("settings JSON is malformed");
  configureBifrostExtension(pi, {
    createSession: () => session,
    settingsStore: {
      async load() { throw settingsError; },
      async save() {},
    },
  });
  const notifications = [];

  await pi.handlers.get("session_start")({}, {
    cwd: "/workspace",
    hasUI: true,
    ui: { notify: (...args) => notifications.push(args) },
  });

  assert.deepEqual(session.starts, [{ workspace: "/workspace", capabilities: [] }]);
  assert.equal(session.status().state, "disconnected");
  assert.equal(
    await pi.handlers.get("before_agent_start")({ systemPrompt: "base" }),
    undefined,
  );
  assert.deepEqual(notifications, [[
    "Could not load Bifrost settings. Bifrost tools are disabled until the settings are updated.",
    "error",
  ]]);
});

test("malformed settings throw before Bifrost starts in headless mode", async () => {
  const pi = fakePi();
  const session = fakeSession();
  const settingsError = new Error("settings JSON is malformed");
  configureBifrostExtension(pi, {
    createSession: () => session,
    settingsStore: {
      async load() { throw settingsError; },
      async save() {},
    },
  });

  await assert.rejects(
    pi.handlers.get("session_start")({}, {
      cwd: "/workspace",
      hasUI: false,
      ui: { notify() {} },
    }),
    (error) => error.message === "Could not load Bifrost settings. Bifrost tools are disabled until the settings are updated."
      && error.cause === settingsError,
  );
  assert.deepEqual(session.starts, []);
});

test("routes background session failures through Pi UI notifications", async () => {
  const pi = fakePi();
  const session = fakeSession();
  configureBifrostExtension(pi, dependencies(session));
  const notifications = [];
  await pi.handlers.get("session_start")({}, {
    cwd: "/workspace",
    hasUI: true,
    ui: { notify: (...args) => notifications.push(args) },
  });

  session.reportError(new Error("Bifrost connection failed."));

  assert.deepEqual(notifications, [["Bifrost connection failed.", "error"]]);
});

test("session_shutdown reports cleanup failure through Pi UI when interactive", async () => {
  const pi = fakePi();
  const cleanupError = new Error("Bifrost MCP cleanup failed.", { cause: new Error("close failed") });
  const session = fakeSession({
    async shutdown() { throw cleanupError; },
  });
  configureBifrostExtension(pi, dependencies(session));
  const notifications = [];
  await pi.handlers.get("session_start")({}, {
    cwd: "/workspace",
    hasUI: true,
    ui: { notify: (...args) => notifications.push(args) },
  });

  await pi.handlers.get("session_shutdown")();

  assert.deepEqual(notifications, [["Bifrost MCP cleanup failed.", "error"]]);
});

test("session_shutdown throws cleanup failure in noninteractive mode", async () => {
  const pi = fakePi();
  const cleanupError = new Error("Bifrost MCP cleanup failed.", { cause: new Error("close failed") });
  const session = fakeSession({
    async shutdown() { throw cleanupError; },
  });
  configureBifrostExtension(pi, dependencies(session));
  await pi.handlers.get("session_start")({}, {
    cwd: "/workspace",
    hasUI: false,
    ui: { notify() {} },
  });

  await assert.rejects(pi.handlers.get("session_shutdown")(), (error) => error === cleanupError);
});

test("session_start reports a startup failure through Pi UI when interactive", async () => {
  const pi = fakePi();
  const startupError = new Error("Bifrost MCP configuration failed.", { cause: new Error("handshake failed") });
  const session = fakeSession({
    async start() {
      session.setStatus({
        state: "error",
        workspace: "/workspace",
        toolCount: 0,
        capabilities: [],
        lastOperationError: startupError,
      });
      return false;
    },
  });
  configureBifrostExtension(pi, dependencies(session));
  const notifications = [];

  await pi.handlers.get("session_start")({}, {
    cwd: "/workspace",
    hasUI: true,
    ui: { notify: (...args) => notifications.push(args) },
  });

  assert.deepEqual(notifications, [["Bifrost MCP configuration failed.", "error"]]);
  assert.equal(session.status().state, "error");
});

test("session_start throws the structured startup error in noninteractive mode", async () => {
  const pi = fakePi();
  const startupError = new Error("Bifrost MCP configuration failed.", { cause: new Error("handshake failed") });
  const session = fakeSession({
    async start() {
      session.setStatus({
        state: "error",
        workspace: "/workspace",
        toolCount: 0,
        capabilities: [],
        lastOperationError: startupError,
      });
      return false;
    },
  });
  configureBifrostExtension(pi, dependencies(session));

  await assert.rejects(
    pi.handlers.get("session_start")({}, {
      cwd: "/workspace",
      hasUI: false,
      ui: { notify() {} },
    }),
    (error) => error === startupError,
  );
});

test("/bifrost requires TUI mode", async () => {
  const pi = fakePi();
  const session = fakeSession();
  configureBifrostExtension(pi, dependencies(session));
  const notifications = [];

  await pi.commands.get("bifrost").handler("", {
    mode: "print",
    ui: { notify: (...args) => notifications.push(args) },
  });

  assert.deepEqual(notifications, [["/bifrost requires TUI mode.", "error"]]);
});

test("/bifrost applies and persists a TUI toggle", async () => {
  initTheme("dark", false);
  const pi = fakePi();
  const session = fakeSession();
  const saves = [];
  configureBifrostExtension(pi, dependencies(session, undefined, saves));

  await pi.commands.get("bifrost").handler("", {
    mode: "tui",
    ui: {
      notify() {},
      async custom(factory) {
        let closed = false;
        const component = factory(
          { requestRender() {} },
          theme,
          {},
          () => { closed = true; },
        );
        const rendered = component.render(100).join("\n");
        assert.match(rendered, /Bifrost Toolsets/);
        assert.match(rendered, /connected · \/workspace/);
        assert.match(rendered, /Symbols/);
        assert.match(rendered, /enabled/);
        component.handleInput(" ");
        assert.equal(closed, false);
      },
    },
  });

  assert.deepEqual(session.applied, [["query", "files"]]);
  assert.deepEqual(saves, [{ workspace: "/workspace", capabilities: ["query", "files"] }]);
});

test("/bifrost builds a retry from desired capabilities retained after startup failure", async () => {
  initTheme("dark", false);
  const pi = fakePi();
  const session = fakeSession();
  session.setStatus({
    state: "error",
    workspace: "/workspace",
    toolCount: 0,
    capabilities: ["symbols", "query", "files"],
    lastOperationError: new Error("startup failed"),
  });
  const saves = [];
  configureBifrostExtension(pi, dependencies(session, undefined, saves));

  await pi.commands.get("bifrost").handler("", {
    mode: "tui",
    ui: {
      notify() {},
      async custom(factory) {
        const component = factory(
          { requestRender() {} },
          theme,
          {},
          () => {},
        );
        component.handleInput(" ");
      },
    },
  });

  assert.deepEqual(session.applied, [["query", "files"]]);
  assert.deepEqual(saves, [{ workspace: "/workspace", capabilities: ["query", "files"] }]);
});

test("/bifrost refreshes its header after disconnect and recovery", async () => {
  initTheme("dark", false);
  const pi = fakePi();
  const session = fakeSession();
  session.setStatus({
    state: "connected",
    workspace: "/workspace",
    toolCount: 1,
    capabilities: ["symbols"],
  });
  configureBifrostExtension(pi, dependencies(session));
  let lastRender = "";

  const invoke = async () => {
    await pi.commands.get("bifrost").handler("", {
      mode: "tui",
      ui: {
        notify() {},
        async custom(factory) {
          let component;
          const tui = {
            requestRender() {
              if (component) {
                lastRender = component.render(100).join("\n");
              }
            },
          };
          component = factory(tui, theme, {}, () => {});
          component.handleInput(" ");
        },
      },
    });
  };

  await invoke();
  assert.match(lastRender, /disconnected · \/workspace/);

  session.setStatus({
    state: "error",
    workspace: "/workspace",
    toolCount: 0,
    capabilities: [],
    lastOperationError: new Error("connection failed"),
  });
  await invoke();
  assert.match(lastRender, /connected · \/workspace/);
});

test("/bifrost reads live session status on every render", async () => {
  initTheme("dark", false);
  const pi = fakePi();
  const session = fakeSession();
  configureBifrostExtension(pi, dependencies(session));
  let rerendered = "";

  await pi.commands.get("bifrost").handler("", {
    mode: "tui",
    ui: {
      notify() {},
      async custom(factory) {
        const component = factory({ requestRender() {} }, theme, {}, () => {});
        assert.match(component.render(100).join("\n"), /connected · \/workspace/);
        session.setStatus({
          state: "error",
          workspace: "/workspace",
          toolCount: 0,
          capabilities: ["symbols", "query", "files"],
          lastOperationError: new Error("connection closed"),
        });
        rerendered = component.render(100).join("\n");
      },
    },
  });

  assert.match(rerendered, /error · \/workspace/);
});

test("/bifrost refreshes its header after a failed apply", async () => {
  initTheme("dark", false);
  const pi = fakePi();
  const session = fakeSession();
  session.setStatus({
    state: "connecting",
    workspace: "/workspace",
    toolCount: 0,
    capabilities: ["symbols"],
  });
  session.applySelection = async () => {
    session.setStatus({
      state: "error",
      workspace: "/workspace",
      toolCount: 0,
      capabilities: ["symbols"],
      lastOperationError: new Error("apply failed"),
    });
    return false;
  };
  configureBifrostExtension(pi, dependencies(session));
  let lastRender = "";

  await pi.commands.get("bifrost").handler("", {
    mode: "tui",
    ui: {
      notify() {},
      async custom(factory) {
        let component;
        const tui = {
          requestRender() {
            if (component) {
              lastRender = component.render(100).join("\n");
            }
          },
        };
        component = factory(tui, theme, {}, () => {});
        component.handleInput(" ");
      },
    },
  });

  assert.match(lastRender, /error · \/workspace/);
});

test("/bifrost refreshes its header after persistence rollback", async () => {
  initTheme("dark", false);
  const pi = fakePi();
  const session = fakeSession();
  session.setStatus({
    state: "error",
    workspace: "/workspace",
    toolCount: 0,
    capabilities: [],
    lastOperationError: new Error("startup failed"),
  });
  configureBifrostExtension(pi, {
    createSession: () => session,
    settingsStore: {
      async load() { return undefined; },
      async save() { throw new Error("disk is read-only"); },
    },
  });
  let lastRender = "";

  await pi.commands.get("bifrost").handler("", {
    mode: "tui",
    ui: {
      notify() {},
      async custom(factory) {
        let component;
        const tui = {
          requestRender() {
            if (component) {
              lastRender = component.render(100).join("\n");
            }
          },
        };
        component = factory(tui, theme, {}, () => {});
        component.handleInput(" ");
      },
    },
  });

  assert.deepEqual(session.applied, [["symbols"], []]);
  assert.match(lastRender, /disconnected · \/workspace/);
});

test("/bifrost applies queued toggles from committed state after an earlier failure", async () => {
  initTheme("dark", false);
  const pi = fakePi();
  const session = fakeSession();
  const originalApply = session.applySelection.bind(session);
  let attempts = 0;
  session.applySelection = async (capabilities) => {
    if (attempts++ === 0) {
      session.applied.push([...capabilities]);
      return false;
    }
    return await originalApply(capabilities);
  };
  const saves = [];
  configureBifrostExtension(pi, dependencies(session, undefined, saves));

  await pi.commands.get("bifrost").handler("", {
    mode: "tui",
    ui: {
      notify() {},
      async custom(factory) {
        const component = factory(
          { requestRender() {} },
          theme,
          {},
          () => {},
        );
        component.handleInput(" ");
        component.handleInput(" ");
      },
    },
  });

  assert.deepEqual(session.applied, [
    ["query", "files"],
    ["symbols", "query", "files"],
  ]);
  assert.deepEqual(saves, [{
    workspace: "/workspace",
    capabilities: ["symbols", "query", "files"],
  }]);
});

test("/bifrost rolls back the runtime selection when persistence fails", async () => {
  initTheme("dark", false);
  const pi = fakePi();
  const session = fakeSession();
  const notifications = [];
  configureBifrostExtension(pi, {
    createSession: () => session,
    settingsStore: {
      async load() { return undefined; },
      async save() { throw new Error("disk is read-only"); },
    },
  });

  await pi.commands.get("bifrost").handler("", {
    mode: "tui",
    ui: {
      notify: (...args) => notifications.push(args),
      async custom(factory) {
        const component = factory(
          { requestRender() {} },
          theme,
          {},
          () => {},
        );
        component.handleInput(" ");
      },
    },
  });

  assert.deepEqual(session.applied, [
    ["query", "files"],
    ["symbols", "query", "files"],
  ]);
  assert.equal(
    notifications[0][0],
    "Could not save Bifrost settings. The previous runtime selection was restored. Check the settings directory and try again.",
  );
});
