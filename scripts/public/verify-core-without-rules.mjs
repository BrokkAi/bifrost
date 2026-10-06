#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";

const execute = promisify(execFile);

export async function verifyCoreWithoutRules(binary, expectedIdentity, { exec = execute } = {}) {
  assert.match(expectedIdentity, /^[a-f0-9]{40}$/u);
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "bifrost-core-without-rules-"));
  const env = { ...process.env };
  delete env.BIFROST_OPEN_POLICY_PACK_ROOT;
  try {
    const options = { env, cwd: root, encoding: "utf8", timeout: 60_000, maxBuffer: 4 * 1024 * 1024 };
    const identity = (await exec(binary, ["--build-identity"], options)).stdout.trim();
    assert.equal(identity, expectedIdentity, "staged binary build identity differs");
    const catalog = JSON.parse((await exec(binary, ["scan", "--list-builtin-policies"], options)).stdout);
    assert.equal(catalog.schema_version, 2);
    assert.deepEqual(catalog.packs, [], "core engine still delivers product rules");
    const scan = await exec(binary, ["scan", root, "--format", "json", "--fail-on", "never"], options);
    const report = JSON.parse(scan.stdout);
    assert.match(scan.stderr, /no rules were evaluated/u);
    assert.equal(report.schema_version, 1);
    assert.equal(report.status, "not-evaluated", "core scan claimed an evaluated policy result");
    assert.equal(report.reason, "no-active-rule-packs");
    assert.deepEqual(report.findings, [], "core scan unexpectedly evaluated rules");
    let rejected = false;
    try {
      await exec(binary, ["--root", root, "--policy", "--policy-id", "bifrost.correctness.dynamic-evaluation"], options);
    } catch (error) {
      assert.ok(error.code !== "ENOENT" && !error.killed, "selection check failed to execute");
      assert.match(String(error.stderr), /unknown|not found|no.*polic/iu);
      rejected = true;
    }
    assert.ok(rejected, "core engine silently restored an absent product rule");
    return {
      schema_version: 1,
      core: { status: "verified", build_identity: identity, rules: "host-supplied", active_rule_packs: 0 },
      external_content: { status: "not-qualified", reason: "Separate host acquisition and runtime acceptance is required." },
    };
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const [binary, identity, output] = process.argv.slice(2);
  assert.ok(binary && identity && output && process.argv.length === 5,
    "Usage: verify-core-without-rules.mjs BINARY BUILD_IDENTITY OUTPUT.json");
  const result = await verifyCoreWithoutRules(path.resolve(binary), identity);
  result.core.binary_sha256 = createHash("sha256").update(await fs.readFile(binary)).digest("hex");
  await fs.mkdir(path.dirname(path.resolve(output)), { recursive: true });
  await fs.writeFile(output, `${JSON.stringify(result, null, 2)}\n`, { flag: "wx" });
  console.log(JSON.stringify(result));
}
