import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const action = fs.readFileSync(new URL("../../.github/actions/policy-scan/action.yml", import.meta.url), "utf8");

test("policy action resolves acquisition identity with the installed bifrost binary", () => {
  const install = action.indexOf("    - name: Install bifrost");
  const identity = action.indexOf("    - name: Resolve pack acquisition identity");
  const restore = action.indexOf("    - name: Restore pinned content cache");
  const acquire = action.indexOf("    - name: Acquire and reverify selected external content");
  assert.ok(install >= 0 && install < identity && identity < acquire);
  const identityStep = action.slice(identity, restore);
  assert.match(identityStep, /prepare-open-packs --cache-dir .*--identity-only/u);
  assert.match(identityStep, /\.identity \| select\(test\("\^\[0-9a-f\]\{64\}\$"\)\)/u);
  assert.doesNotMatch(identityStep, /PACK_TOKEN/u);
  assert.match(action, /path: \$\{\{ steps\.pack-identity\.outputs\.cache-path \}\}/u);
});

test("private credentials reach only the binary acquisition process and never the cache", () => {
  const acquire = action.indexOf("    - name: Acquire and reverify selected external content");
  const save = action.indexOf("    - name: Save verified selected content cache");
  const acquireStep = action.slice(acquire, save);
  assert.match(acquireStep, /PACK_TOKEN: \$\{\{ inputs\.packs-token \}\}/u);
  assert.match(acquireStep, /prepare-open-packs --cache-dir .*--receipt-path .*--env-path/u);
  assert.match(acquireStep, /GITHUB_EVENT_NAME.*push.*workflow_dispatch/u);
  const restore = action.indexOf("    - name: Restore pinned content cache");
  const restoreStep = action.slice(restore, acquire);
  assert.doesNotMatch(restoreStep, /PACK_TOKEN:/u);
  assert.match(restoreStep, /inputs\.packs-token == ''/u);
  assert.match(action.slice(save, action.indexOf("    - name: Resolve analyzer cache identity")), /inputs\.packs-token == ''/u);
  const run = action.indexOf("    - name: Run policies");
  const runEnd = action.indexOf("\n    - name:", run + 1);
  assert.doesNotMatch(action.slice(run, runEnd), /PACK_TOKEN:/u);
});

test("source and cache identities are selected by the Rust binary contract", () => {
  assert.match(action, /packs-source:/u);
  assert.match(action, /packs-token:/u);
  assert.match(action, /Invalid explicit selections never fall back/u);
  assert.match(action, /actions\/cache\/restore/u);
  assert.match(action, /actions\/cache\/save/u);
  assert.match(action, /selection-id=/u);
  assert.match(action, /cache-reused=/u);
});
