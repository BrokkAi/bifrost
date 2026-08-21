// Tests for the alias-repository release step.
//
// v0.10.5 could not be listed on the Marketplace partly because the alias
// repository held tags and no releases at all, and Marketplace publishes an
// Action from a release. This step creates it; these tests pin what it creates
// and, more importantly, what it refuses to claim.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const SCRIPT = fileURLToPath(new URL("create-policy-scan-release.sh", import.meta.url));
const FIXTURE_BIN = fileURLToPath(new URL("../fixtures/workflow-shell/", import.meta.url));

function withTempDir(body) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-policy-scan-release."));
  try {
    return body(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// The `gh` double in scripts/fixtures/workflow-shell only answers `gh api`. The
// release step uses `gh release`, so this stands in a small double of its own
// that records its argv and can be told whether the release already exists.
function fakeGh(dir, { releaseExists }) {
  const bin = path.join(dir, "bin");
  fs.mkdirSync(bin, { recursive: true });
  const log = path.join(dir, "gh-calls.log");
  fs.writeFileSync(log, "");
  fs.writeFileSync(
    path.join(bin, "gh"),
    `#!/usr/bin/env bash
printf '%s\\0' "$@" >> ${JSON.stringify(log)}
printf '\\n' >> ${JSON.stringify(log)}
if [ "$1" = release ] && [ "$2" = view ]; then
  exit ${releaseExists ? 0 : 1}
fi
if [ "$1" = release ] && [ "$2" = create ]; then
  exit 0
fi
echo "fake gh does not implement: $*" >&2
exit 1
`,
    { mode: 0o755 },
  );
  return {
    env: { PATH: `${bin}${path.delimiter}${process.env.PATH}` },
    calls: () =>
      fs
        .readFileSync(log, "utf8")
        .split("\n")
        .filter(Boolean)
        .map((line) => line.split("\0").filter(Boolean)),
  };
}

function run(dir, { tag = "v0.11.0", isNewest = "1", releaseExists = false } = {}) {
  const gh = fakeGh(dir, { releaseExists });
  let status = 0;
  let stdout = "";
  let stderr = "";
  try {
    stdout = execFileSync("bash", [SCRIPT], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        ...gh.env,
        RELEASE_TAG: tag,
        IS_NEWEST: isNewest,
        POLICY_SCAN_SYNC_TOKEN: "token",
        POLICY_SCAN_ALIAS_REPO: "BrokkAi/bifrost-policy-scan",
      },
    });
  } catch (error) {
    status = error.status ?? 1;
    stdout = error.stdout ?? "";
    stderr = error.stderr ?? "";
  }
  return { status, stdout, stderr, calls: gh.calls() };
}

function createCall(calls) {
  return calls.find((call) => call[0] === "release" && call[1] === "create");
}

test("the newest release is created and claims latest", () => {
  withTempDir((dir) => {
    const result = run(dir);
    assert.equal(result.status, 0, result.stderr);
    const create = createCall(result.calls);
    assert.ok(create, "no release was created");
    assert.ok(create.includes("v0.11.0"));
    assert.ok(create.includes("--latest"), "the newest release must claim latest");
    // --verify-tag keeps this from inventing a tag the sync never pushed.
    assert.ok(create.includes("--verify-tag"));
  });
});

test("an out-of-order older release does not claim latest", () => {
  withTempDir((dir) => {
    // Same reasoning as the floating major tag: a recovery dispatch publishing
    // an older version must not present itself as the current release.
    const result = run(dir, { tag: "v0.10.9", isNewest: "0" });
    assert.equal(result.status, 0, result.stderr);
    const create = createCall(result.calls);
    assert.ok(create.includes("--latest=false"));
    assert.equal(create.includes("--latest"), false);
  });
});

test("an existing release is left alone rather than duplicated", () => {
  withTempDir((dir) => {
    const result = run(dir, { releaseExists: true });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(createCall(result.calls), undefined, "a recovery re-run recreated the release");
    assert.match(result.stdout, /already exists/u);
  });
});

test("a malformed tag or reuse flag is refused before anything is created", () => {
  for (const overrides of [
    { tag: "latest" },
    { tag: "v0.11" },
    { tag: "0.11.0" },
    { isNewest: "yes" },
    { isNewest: "" },
  ]) {
    withTempDir((dir) => {
      const result = run(dir, overrides);
      assert.notEqual(result.status, 0, `${JSON.stringify(overrides)} was accepted`);
      assert.equal(createCall(result.calls), undefined);
    });
  }
});
