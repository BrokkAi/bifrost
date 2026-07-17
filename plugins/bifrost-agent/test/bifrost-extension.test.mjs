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
      return true;
    },
    async applySelection(capabilities) {
      applied.push([...capabilities]);
      status = { ...status, capabilities: [...capabilities] };
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

  session.reportError("Bifrost connection failed.");

  assert.deepEqual(notifications, [["Bifrost connection failed.", "error"]]);
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
  assert.match(notifications[0][0], /disk is read-only/);
});
