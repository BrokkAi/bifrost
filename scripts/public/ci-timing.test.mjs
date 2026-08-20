import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const script = new URL("./ci-timing.mjs", import.meta.url);

test("records successful command timing in the GitHub Step Summary format", () => {
  const summary = join(mkdtempSync(join(tmpdir(), "bifrost-ci-timing-")), "summary.md");
  const result = spawnSync(process.execPath, [script.pathname, "--label", "unit command", "--", process.execPath, "-e", ""], {
    encoding: "utf8",
    env: { ...process.env, GITHUB_STEP_SUMMARY: summary },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /ci_timing_ms label=unit command elapsed_ms=\d+ status=success/u);
  assert.match(readFileSync(summary, "utf8"), /\| unit command \| success \| \d+ \|/u);
});

test("propagates failures after recording their timing", () => {
  const result = spawnSync(process.execPath, [script.pathname, "--label", "failing command", "--", process.execPath, "-e", "process.exit(7)"], {
    encoding: "utf8",
  });
  assert.equal(result.status, 7);
  assert.match(result.stdout, /status=failed \(7\)/u);
});
