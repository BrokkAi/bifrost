import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, realpath, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  createBifrostSettingsStore,
  parseSettingsDocument,
} from "../extensions/bifrost-settings.ts";

async function workspaceSettingsPath(directory, workspace) {
  const canonical = await realpath(workspace);
  return path.join(directory, `${createHash("sha256").update(canonical).digest("hex")}.json`);
}

test("persists concurrent selections in independent canonical-workspace files", async () => {
  const temp = await mkdtemp(path.join(os.tmpdir(), "bifrost-settings-test-"));
  const firstWorkspace = await mkdtemp(path.join(temp, "first-"));
  const secondWorkspace = await mkdtemp(path.join(temp, "second-"));
  const settingsDirectory = path.join(temp, "agent", "bifrost", "workspaces");
  const store = createBifrostSettingsStore(settingsDirectory);

  assert.equal(await store.load(firstWorkspace), undefined);
  await Promise.all([
    store.save(firstWorkspace, ["quality", "symbols"]),
    store.save(secondWorkspace, ["query", "files"]),
  ]);

  assert.deepEqual(await store.load(firstWorkspace), ["symbols", "quality"]);
  assert.deepEqual(await store.load(secondWorkspace), ["query", "files"]);
});

test("a valid save repairs malformed workspace settings", async () => {
  const temp = await mkdtemp(path.join(os.tmpdir(), "bifrost-settings-test-"));
  const workspace = await mkdtemp(path.join(temp, "workspace-"));
  const settingsDirectory = path.join(temp, "settings");
  const settingsPath = await workspaceSettingsPath(settingsDirectory, workspace);
  const store = createBifrostSettingsStore(settingsDirectory);

  await mkdir(settingsDirectory, { recursive: true });
  await writeFile(settingsPath, "{");
  await assert.rejects(store.load(workspace), /not valid JSON/);

  await store.save(workspace, ["symbols", "quality"]);
  assert.deepEqual(await store.load(workspace), ["symbols", "quality"]);
});

test("rejects malformed, mismatched, and unknown persisted settings", () => {
  assert.throws(() => parseSettingsDocument("{"), /not valid JSON/);
  assert.throws(
    () => parseSettingsDocument('{"version":1,"workspace":"/repo","capabilities":["future"]}'),
    /unknown capabilities: future/,
  );
  assert.throws(
    () => parseSettingsDocument(
      '{"version":1,"workspace":"/other","capabilities":["symbols"]}',
      "/repo",
    ),
    /do not match/,
  );
  assert.throws(
    () => parseSettingsDocument('{"version":2,"workspace":"/repo","capabilities":[]}'),
    /version 1/,
  );
});

test("rejects a top-level array through the schema boundary", () => {
  assert.throws(
    () => parseSettingsDocument('["symbols"]'),
    /version 1/,
  );
});

test("rejects a top-level null through the schema boundary", () => {
  assert.throws(
    () => parseSettingsDocument("null"),
    /version 1/,
  );
});

test("rejects extra fields not defined by the settings schema", () => {
  assert.throws(
    () => parseSettingsDocument(
      '{"version":1,"workspace":"/repo","capabilities":[],"extra":true}',
    ),
    /version 1/,
  );
});
