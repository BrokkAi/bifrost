import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { execFileSync, spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";

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

test("#4523: native explicit selection preserves full inventory and rejects lost Rust models", {
  skip: !process.env.BIFROST_BIN,
}, () => {
  const binary = path.resolve(process.env.BIFROST_BIN);
  const tool = path.join(path.dirname(binary), process.platform === "win32" ? "bifrost-semantic-pack.exe" : "bifrost-semantic-pack");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-4523-native-"));
  try {
    const selection = path.join(root, "selection");
    execFileSync(tool, ["export-embedded-registry", selection]);
    const inventory = JSON.parse(fs.readFileSync(path.join(selection, "embedded-registry.json"), "utf8"));
    const manifests = inventory.sources.map((_, i) => JSON.parse(fs.readFileSync(path.join(selection, String(i), "manifest.json"), "utf8")));
    assert.ok(manifests.some((pack) => pack.language === "rust"));
    assert.ok(manifests.some((pack) => pack.language === "python"));
    assert.ok(manifests.some((pack) => pack.language === "java"));
    const workspace = path.join(root, "workspace");
    fs.mkdirSync(workspace);
    execFileSync("git", ["init", "-q", workspace]);
    fs.writeFileSync(path.join(workspace, "main.rs"), "fn danger() {}\nfn main() { danger(); }\n");
    fs.writeFileSync(path.join(workspace, "host.rqlp"), `(policy
      :schema-version 1 :id "host.selection" :name "Explicit semantic selection"
      :message "Review danger" :severity warning
      :analysis (analysis :type match :selector
        (rql :schema-version 1 (language rust (call :callee (name "danger"))))))\n`);
    const env = { ...process.env, BIFROST_OPEN_SEMANTIC_PACK_BUNDLE: selection,
      // The same retained, public-classified engine fixture catalog that
      // master supplies. A configured root must contain real packs even when
      // this witness selects only its tiny host-authored policy file.
      BIFROST_OPEN_POLICY_PACK_ROOT: path.resolve("crates/bifrost-policy/policy-packs"),
      BIFROST_SEMANTIC_PACK_CACHE_ROOT: path.join(root, "semantic-cache"),
      BIFROST_PARALLELISM: "1", RAYON_NUM_THREADS: "1", JAVA_HOME: "" };
    const args = ["--root", workspace, "--policy-file", "host.rqlp", "--no-builtin-policies", "--format", "sarif", "--fail-on", "never"];
    const valid = spawnSync(binary, args, { env, encoding: "utf8", timeout: 120_000 });
    assert.equal(valid.status, 0, valid.stdout + valid.stderr);
    const sarif = JSON.parse(valid.stdout);
    assert.ok(sarif.runs.some((run) => run.results.some((result) => result.ruleId === "host.selection")), valid.stdout);
    // Losing an unrelated Rust model must invalidate the selected full set,
    // even though the policy itself only asks about one workspace-local call.
    const rustPosition = manifests.findIndex((pack) => pack.language === "rust");
    fs.rmSync(path.join(selection, String(rustPosition), "manifest.json"));
    const invalid = spawnSync(binary, args, { env, encoding: "utf8", timeout: 120_000 });
    assert.notEqual(invalid.status, 0, "missing selected content must not fall back to the binary");
    assert.match(invalid.stdout + invalid.stderr, /configured semantic selection/u);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
