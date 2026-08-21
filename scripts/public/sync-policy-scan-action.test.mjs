// Tests for the policy-scan alias sync.
//
// This script had no tests, and shipped v0.10.5 with a README telling readers
// to pin @v0.10.4 -- the front page of the Marketplace listing. It already
// carried a POLICY_SCAN_ALIAS_URL hook documented as the thing local tests
// would point at a file:// bare repository; nothing ever did.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const SCRIPT = fileURLToPath(new URL("sync-policy-scan-action.sh", import.meta.url));

const ACTION = `name: Bifrost Policy Scan
description: Run Bifrost static-analysis policies.

branding:
  icon: shield
  color: purple

inputs:
  version:
    description: Bifrost release tag to install.
    required: false
    default: v0.10.4

runs:
  using: composite
  steps: []
`;

const README = `# Bifrost Policy Scan

## Quick start

\`\`\`yaml
      - uses: BrokkAi/bifrost-policy-scan@v0
\`\`\`

## Versioning

Pin an exact tag when a gate has to stay reproducible:

\`\`\`yaml
      - uses: BrokkAi/bifrost-policy-scan@v0.10.4
\`\`\`
`;

function git(args, cwd) {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: "Test",
      GIT_AUTHOR_EMAIL: "test@example.com",
      GIT_COMMITTER_NAME: "Test",
      GIT_COMMITTER_EMAIL: "test@example.com",
    },
  });
}

function withFixture(body, { action = ACTION, readme = README } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-policy-scan-sync."));
  try {
    // A release checkout: only the three files the script reads.
    const checkout = path.join(dir, "checkout");
    fs.mkdirSync(path.join(checkout, ".github/actions/policy-scan"), { recursive: true });
    fs.mkdirSync(path.join(checkout, "packaging/policy-scan-action"), { recursive: true });
    fs.writeFileSync(path.join(checkout, ".github/actions/policy-scan/action.yml"), action);
    fs.writeFileSync(path.join(checkout, "packaging/policy-scan-action/README.md"), readme);
    fs.writeFileSync(path.join(checkout, "LICENSE.md"), "Apache 2.0\n");

    // The alias repository, as a bare repo the script can clone and push to.
    const bare = path.join(dir, "alias.git");
    git(["init", "-q", "--bare", "-b", "main", bare]);
    const seed = path.join(dir, "seed");
    git(["init", "-q", "-b", "main", seed]);
    fs.writeFileSync(path.join(seed, "README.md"), "seed\n");
    git(["add", "-A"], seed);
    git(["commit", "-q", "-m", "seed"], seed);
    git(["remote", "add", "origin", bare], seed);
    git(["push", "-q", "origin", "main"], seed);

    return body({ dir, checkout, bare });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function sync(checkout, bare, tag, { githubOutput } = {}) {
  const env = { ...process.env, RELEASE_TAG: tag, POLICY_SCAN_ALIAS_URL: bare };
  if (githubOutput) {
    fs.writeFileSync(githubOutput, "");
    env.GITHUB_OUTPUT = githubOutput;
  }
  const read = () =>
    githubOutput
      ? Object.fromEntries(
        fs.readFileSync(githubOutput, "utf8").split("\n").filter(Boolean)
          .map((line) => {
            const index = line.indexOf("=");
            return [line.slice(0, index), line.slice(index + 1)];
          }),
      )
      : {};
  try {
    const stdout = execFileSync("bash", [SCRIPT], {
      cwd: checkout,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      env,
    });
    return { status: 0, stdout, stderr: "", outputs: read() };
  } catch (error) {
    return {
      status: error.status ?? 1,
      stdout: error.stdout ?? "",
      stderr: error.stderr ?? "",
      outputs: read(),
    };
  }
}

function fileAtTag(bare, tag, file) {
  return execFileSync("git", ["show", `${tag}:${file}`], { cwd: bare, encoding: "utf8" });
}

test("both version literals are rewritten to the release being published", () => {
  withFixture(({ checkout, bare }) => {
    const result = sync(checkout, bare, "v0.11.0");
    assert.equal(result.status, 0, result.stderr);

    const action = fileAtTag(bare, "v0.11.0", "action.yml");
    assert.match(action, /^ {4}default: v0\.11\.0$/mu);
    assert.equal((action.match(/v0\.10\.4/gu) ?? []).length, 0, "stale action default survived");

    const readme = fileAtTag(bare, "v0.11.0", "README.md");
    assert.match(readme, /uses: BrokkAi\/bifrost-policy-scan@v0\.11\.0/u);
    assert.equal(
      (readme.match(/v0\.10\.4/gu) ?? []).length,
      0,
      "the README still tells readers to pin the previous release",
    );
  });
});

test("the quick start keeps the floating major tag", () => {
  withFixture(({ checkout, bare }) => {
    assert.equal(sync(checkout, bare, "v0.11.0").status, 0);
    const readme = fileAtTag(bare, "v0.11.0", "README.md");
    // The rewrite must not touch @v0: the quick start deliberately follows the
    // newest release, and pinning it to an exact tag would freeze every reader
    // who copies it.
    assert.match(readme, /uses: BrokkAi\/bifrost-policy-scan@v0$/mu);
  });
});

test("a canonical file that lost or gained its version literal fails the release", () => {
  const cases = [
    ["action.yml with no version default", { action: ACTION.replace("    default: v0.10.4\n", "") }],
    ["action.yml with two version defaults", { action: `${ACTION}    default: v0.9.0\n` }],
    ["README with no pinned example", { readme: README.replace(/^ {6}- uses: .*@v0\.10\.4$/mu, "") }],
  ];
  for (const [label, overrides] of cases) {
    withFixture(({ checkout, bare }) => {
      const result = sync(checkout, bare, "v0.11.0");
      assert.notEqual(result.status, 0, `${label} was accepted`);
      assert.match(result.stderr, /expected exactly one/u);
    }, overrides);
  }
});

test("the exact release tag and the floating major tag both land", () => {
  withFixture(({ checkout, bare }) => {
    assert.equal(sync(checkout, bare, "v0.11.0").status, 0);
    const exact = execFileSync("git", ["rev-parse", "v0.11.0"], { cwd: bare, encoding: "utf8" }).trim();
    const major = execFileSync("git", ["rev-parse", "v0"], { cwd: bare, encoding: "utf8" }).trim();
    const branch = execFileSync("git", ["rev-parse", "main"], { cwd: bare, encoding: "utf8" }).trim();
    assert.equal(major, exact);
    assert.equal(branch, exact);
  });
});

test("an out-of-order older release publishes its tag without moving v0", () => {
  withFixture(({ checkout, bare }) => {
    assert.equal(sync(checkout, bare, "v0.11.0").status, 0);
    const newest = execFileSync("git", ["rev-parse", "v0"], { cwd: bare, encoding: "utf8" }).trim();

    const older = sync(checkout, bare, "v0.10.9");
    assert.equal(older.status, 0, older.stderr);
    assert.match(older.stdout, /exact tag only/u);
    assert.equal(
      execFileSync("git", ["rev-parse", "v0"], { cwd: bare, encoding: "utf8" }).trim(),
      newest,
      "a recovery re-run of an older release downgraded consumers following v0",
    );
    // The older tag still carries its own release's literals.
    assert.match(fileAtTag(bare, "v0.10.9", "action.yml"), /^ {4}default: v0\.10\.9$/mu);
  });
});

// The release step reuses this decision rather than deriving "which release do
// consumers follow" a second time, so the two cannot disagree about whether a
// given sync is the newest.
test("the newest decision is published for the release step to reuse", () => {
  withFixture(({ dir, checkout, bare }) => {
    const githubOutput = path.join(dir, "github-output");

    const newest = sync(checkout, bare, "v0.11.0", { githubOutput });
    assert.equal(newest.status, 0, newest.stderr);
    assert.equal(newest.outputs.is_newest, "1");
    assert.equal(
      newest.outputs.target_commit,
      execFileSync("git", ["rev-parse", "v0.11.0"], { cwd: bare, encoding: "utf8" }).trim(),
    );

    const older = sync(checkout, bare, "v0.10.9", { githubOutput });
    assert.equal(older.status, 0, older.stderr);
    assert.equal(older.outputs.is_newest, "0");
    assert.equal(
      older.outputs.target_commit,
      execFileSync("git", ["rev-parse", "v0.10.9"], { cwd: bare, encoding: "utf8" }).trim(),
    );
  });
});

// GitHub Marketplace refuses to publish a listing whose action description is
// 125 characters or more, and it says so at the publish form -- after the
// release tag is cut, which the sync then refuses to move. v0.10.5 was tagged
// with a 281-character description and could not be listed. Fail here instead.
test("the canonical action description fits the Marketplace limit", () => {
  const action = fs.readFileSync(".github/actions/policy-scan/action.yml", "utf8");
  const folded = action.match(/^description: >-\n((?: {2}.*\n)+)/mu);
  assert.ok(folded, "expected a folded description block in the policy-scan action");
  const description = folded[1]
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .join(" ");
  assert.ok(
    description.length < 125,
    `Marketplace requires under 125 characters; this is ${description.length}: ${description}`,
  );
});
