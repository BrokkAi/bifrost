import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { validatePreflight } from "./release-preflight.mjs";

const SCRIPT = fileURLToPath(new URL("./release-preflight.mjs", import.meta.url));
const PUBLIC_COMMIT = "a".repeat(40);
const PUBLIC_HEAD = "b".repeat(40);
const ACTION_SHA = "0123456789abcdef0123456789abcdef01234567";

function validInput() {
  const publisher = {
    package: "@brokkai/bifrost",
    registry: "npm",
    repository: "BrokkAi/bifrost",
    workflow: ".github/workflows/publish-npm.yml",
    environment: "npm-publish",
  };
  return {
    publicCommit: PUBLIC_COMMIT,
    expectedPublicHead: PUBLIC_HEAD,
    observedPublicHead: PUBLIC_HEAD,
    tag: "v0.10.3",
    version: "0.10.3",
    refs: ["refs/heads/master"],
    versionCheck: {
      command: ["node", "scripts/public/release-version.mjs", "check", "--tag", "v0.10.3"],
      exitCode: 0,
      version: "0.10.3",
      tag: "v0.10.3",
    },
    workflows: [
      {
        path: ".github/workflows/release-readiness.yml",
        contents: [
          `      - uses: actions/checkout@${ACTION_SHA} # v5.1.0`,
          `      - uses: github/codeql-action/upload-sarif@${ACTION_SHA} # v3.28.10`,
          "      - uses: ./.github/actions/local-check",
          "",
        ].join("\n"),
      },
    ],
    actionRevisions: [
      { repository: "actions/checkout", revision: ACTION_SHA, status: 200 },
      { repository: "github/codeql-action", revision: ACTION_SHA, status: 200 },
    ],
    releaseInventory: [publisher],
    trustedPublishers: [{ ...publisher }],
  };
}

function runCli(input) {
  const directory = mkdtempSync(join(process.cwd(), ".release-preflight-test-"));
  const inputPath = join(directory, "input.json");
  writeFileSync(inputPath, `${JSON.stringify(input)}\n`);
  const result = spawnSync(process.execPath, [SCRIPT, "--input", inputPath], { encoding: "utf8" });
  rmSync(directory, { recursive: true, force: true });
  return result;
}

test("accepts the canonical fixture-backed preflight and CLI", () => {
  assert.deepEqual(validatePreflight(validInput()), []);
  const result = runCli(validInput());
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Release preflight passed/u);
});

test("rejects an invalid public commit identity", () => {
  const input = validInput();
  input.publicCommit = PUBLIC_COMMIT.toUpperCase();

  const failures = validatePreflight(input).join("\n");
  assert.match(failures, /Invalid public commit: expected exactly 40 lowercase hexadecimal characters/u);
  const result = runCli(input);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Invalid public commit/u);
});

test("rejects a release tag present in full refs evidence", () => {
  const input = validInput();
  input.refs.push("refs/tags/v0.10.3");

  const failures = validatePreflight(input).join("\n");
  assert.match(failures, /Release tag v0\.10\.3 is already present/u);
  const result = runCli(input);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /already present in supplied git refs evidence/u);
});

test("rejects a changed observed public head", () => {
  const input = validInput();
  input.observedPublicHead = "c".repeat(40);

  const failures = validatePreflight(input).join("\n");
  assert.match(failures, /Public head changed: expected independently supplied head/u);
  const result = runCli(input);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Public head changed/u);
});

test("rejects a tag and version mismatch", () => {
  const input = validInput();
  input.tag = "v0.10.4";

  const failures = validatePreflight(input).join("\n");
  assert.match(failures, /Release version mismatch/u);
  const result = runCli(input);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Release version mismatch/u);
});

test("requires the exact successful version check command and evidence", () => {
  const input = validInput();
  input.versionCheck.command = ["node", "scripts/public/release-version.mjs", "sync"];
  input.versionCheck.exitCode = 1;
  input.versionCheck.version = "0.10.2";

  const failures = validatePreflight(input).join("\n");
  assert.match(failures, /Version check command did not succeed/u);
  assert.match(failures, /Version check command must exactly/u);
  assert.match(failures, /reports 0\.10\.2, expected 0\.10\.3/u);
});

test("accepts external action subpaths while requiring full pinned revisions", () => {
  const input = validInput();
  assert.deepEqual(validatePreflight(input), []);
});

test("rejects an unpinned external workflow action", () => {
  const input = validInput();
  input.workflows[0].contents = "      - uses: actions/checkout@v5\n";

  const failures = validatePreflight(input).join("\n");
  assert.match(failures, /external workflow action actions\/checkout must use a full lowercase 40-hex revision/u);
  const result = runCli(input);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /full lowercase 40-hex revision/u);
});

test("rejects missing action revision evidence", () => {
  const input = validInput();
  delete input.actionRevisions;

  const failures = validatePreflight(input).join("\n");
  assert.match(failures, /Action revision evidence must be an array/u);
  const result = runCli(input);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Action revision evidence must be an array/u);
});

test("rejects unreachable action revision evidence", () => {
  const input = validInput();
  input.actionRevisions[1].status = 404;

  const failures = validatePreflight(input).join("\n");
  assert.match(failures, /github\/codeql-action@/u);
  assert.match(failures, /unreachable.*expected 200/u);
  const result = runCli(input);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /unreachable.*expected 200/u);
});

test("requires trusted-publisher evidence for every inventory entry", () => {
  const input = validInput();
  delete input.trustedPublishers;

  const failures = validatePreflight(input).join("\n");
  assert.match(failures, /Trusted-publisher evidence must be an array/u);
  const result = runCli(input);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Trusted-publisher evidence must be an array/u);
});

test("rejects a trusted-publisher repository, workflow, or environment mismatch", () => {
  const input = validInput();
  input.trustedPublishers[0].repository = "BrokkAi/other-repository";
  input.trustedPublishers[0].workflow = ".github/workflows/other.yml";
  input.trustedPublishers[0].environment = "other-environment";

  const failures = validatePreflight(input).join("\n");
  assert.match(failures, /does not exactly match/u);
  const result = runCli(input);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /does not exactly match/u);
});

test("rejects unexpected keys at every canonical evidence boundary", () => {
  const input = validInput();
  input.unexpected = true;
  input.versionCheck.extra = true;
  input.workflows[0].name = "typo";
  input.actionRevisions[0].sha = ACTION_SHA;
  input.releaseInventory[0].scope = "release";
  input.trustedPublishers[0].scope = "release";

  const failures = validatePreflight(input).join("\n");
  for (const key of ["unexpected", "extra", "name", "sha", "scope"]) {
    assert.ok(failures.includes(`unexpected key '${key}'`), `missing unexpected-key diagnostic for ${key}`);
  }
  const result = runCli(input);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /unexpected key 'unexpected'/u);
});

test("rejects duplicate action and publisher record identities", () => {
  const input = validInput();
  input.actionRevisions.push({ ...input.actionRevisions[0] });
  input.releaseInventory.push({ ...input.releaseInventory[0] });
  input.trustedPublishers.push({ ...input.trustedPublishers[0] });

  const failures = validatePreflight(input).join("\n");
  assert.match(failures, /Duplicate action revision identity actions\/checkout@/u);
  assert.match(failures, /Release inventory contains duplicate publisher record keys/u);
  assert.match(failures, /Trusted-publisher evidence contains duplicate publisher record keys/u);
  const result = runCli(input);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /duplicate publisher record keys/u);
});

test("accepts only the input-file CLI shape", () => {
  const result = spawnSync(process.execPath, [SCRIPT, "--help"], { encoding: "utf8" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Usage: node scripts\/public\/release-preflight\.mjs --input FILE/u);
});
