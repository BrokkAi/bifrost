// Tests for the shell entry points release-readiness.yml invokes.
//
// These used to be `run: |` blocks, which execute only inside a workflow run:
// the only way to exercise release logic was to perform a release, and several
// defects were duly found by a release failing rather than by a test. Each case
// below is decidable without a workflow run.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { fakeGhEnv } from "../fixtures/workflow-shell/fake-gh.mjs";

const scriptsDir = fileURLToPath(new URL(".", import.meta.url));
const repoRoot = path.resolve(scriptsDir, "..", "..");

function script(name) {
  return path.join(scriptsDir, name);
}

// The workflows run these scripts under whatever bash the runner ships, which is
// bash 5. macOS ships bash 3.2, whose `set -e` is more forgiving -- it does not
// abort on a failed `[[ ... ]]` or a false `(( ... ))`. A script that only ever
// runs under 3.2 locally can therefore pass here and die silently in CI, which
// is exactly what happened once. Prefer the newest bash on the machine so a
// local run means the same thing as the gated one.
const BASH = (() => {
  const candidates = ["/opt/homebrew/bin/bash", "/usr/local/bin/bash", "bash"];
  for (const candidate of candidates) {
    try {
      const version = execFileSync(candidate, ["-c", "echo $BASH_VERSINFO"], { encoding: "utf8" });
      if (Number(version.trim()) >= 4) {
        return candidate;
      }
    } catch {
      // Not present; try the next one.
    }
  }
  return "bash";
})();

function withTempDir(body) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-readiness-scripts."));
  try {
    return body(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function run(command, args, options = {}) {
  try {
    const stdout = execFileSync(command, args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      ...options,
      env: { ...process.env, ...(options.env ?? {}) },
    });
    return { status: 0, stdout, stderr: "" };
  } catch (error) {
    return {
      status: error.status ?? 1,
      stdout: error.stdout ?? "",
      stderr: error.stderr ?? "",
    };
  }
}

function git(cwd, ...args) {
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
  }).trim();
}

function writeFile(root, relativePath, contents) {
  const target = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, contents, "utf8");
}

function commit(root, message, files) {
  for (const [relativePath, contents] of Object.entries(files)) {
    writeFile(root, relativePath, contents);
  }
  git(root, "add", "-A");
  git(root, "commit", "-q", "-m", message);
  return git(root, "rev-parse", "HEAD");
}

// The allowlisted files are pretty-printed JSON, and the version gate reads
// whole diff lines, so the fixtures have to be shaped the same way.
function releaseMetadata(version, digest) {
  return `${JSON.stringify({ binaryVersion: version, minimumBinaryVersion: version, archiveSha256: { "universal-apple-darwin": digest } }, null, 2)}\n`;
}

function vscodeManifest(version) {
  return `${JSON.stringify({ name: "bifrost-vscode", version, bifrost: { binaryVersion: version } }, null, 2)}\n`;
}

// A repository shaped like the public one: a compiled-input commit, then a
// checksum-only correction on top of it.
function releaseLikeRepository(dir) {
  const origin = path.join(dir, "origin.git");
  const work = path.join(dir, "work");
  execFileSync("git", ["init", "-q", "--bare", "-b", "master", origin]);
  execFileSync("git", ["init", "-q", "-b", "master", work]);
  git(work, "remote", "add", "origin", origin);

  const base = commit(work, "compiled input", {
    "src/main.rs": "fn main() {}\n",
    "plugins/bifrost-agent/bifrost-release.json": releaseMetadata("0.10.5", "old"),
    "editors/vscode/package.json": vscodeManifest("0.10.5"),
  });
  const corrected = commit(work, "sync tracked launcher checksums", {
    "plugins/bifrost-agent/bifrost-release.json": releaseMetadata("0.10.5", "new"),
  });
  git(work, "push", "-q", "origin", "master");
  return { origin, work, base, corrected };
}

test("the release crate inventory matches the workspace members plus the facade", () => {
  const listed = run(BASH, [
    "-c",
    'source "$1"; printf "%s\\n" "${RELEASE_CRATES[@]}"',
    "bash",
    path.join(repoRoot, "scripts", "lib", "release-crates.sh"),
  ]);
  assert.equal(listed.status, 0, listed.stderr);
  const crates = listed.stdout.trim().split("\n");

  const manifest = fs.readFileSync(path.join(repoRoot, "Cargo.toml"), "utf8");
  const members = [...manifest.matchAll(/^\s*"crates\/([\w-]+)",\s*$/gmu)].map((match) => match[1]);
  assert.ok(members.length > 0, "expected workspace members");

  const expected = [...members.map((member) => `brokk-${member}`), "brokk-bifrost"];
  assert.deepEqual([...crates].sort(), expected.sort());
  assert.equal(crates.at(-1), "brokk-bifrost", "the facade must be packaged last");
});

test("every non-facade release crate gets a patch pointing at a real directory", () => {
  const listed = run(BASH, [
    "-c",
    'source "$1"; printf "%s\\n" "${RELEASE_CRATE_PATCH_ARGS[@]}"',
    "bash",
    path.join(repoRoot, "scripts", "lib", "release-crates.sh"),
  ]);
  assert.equal(listed.status, 0, listed.stderr);
  const patches = listed.stdout
    .trim()
    .split("\n")
    .filter((line) => line !== "--config");

  const crateCount = run(BASH, [
    "-c",
    'source "$1"; echo "${#RELEASE_CRATES[@]}"',
    "bash",
    path.join(repoRoot, "scripts", "lib", "release-crates.sh"),
  ]);
  assert.equal(patches.length, Number(crateCount.stdout.trim()) - 1);

  for (const patch of patches) {
    const parsed = patch.match(/^patch\.crates-io\.(?<crate>[\w-]+)\.path="(?<dir>[\w/-]+)"$/u);
    assert.ok(parsed, `unparseable patch argument: ${patch}`);
    assert.ok(
      fs.existsSync(path.join(repoRoot, parsed.groups.dir, "Cargo.toml")),
      `${parsed.groups.crate} is patched to ${parsed.groups.dir}, which has no manifest`,
    );
  }
});

function identityRun(work, overrides = {}) {
  const outputFile = path.join(work, "github-output");
  fs.writeFileSync(outputFile, "");
  const result = run(BASH, [script("release-readiness-identity.sh")], {
    cwd: work,
    env: {
      GITHUB_OUTPUT: outputFile,
      PRIVATE_COMMIT: "",
      ...overrides,
    },
  });
  const outputs = Object.fromEntries(
    fs
      .readFileSync(outputFile, "utf8")
      .split("\n")
      .filter(Boolean)
      .map((line) => line.split("=")),
  );
  return { ...result, outputs };
}

test("preflight identity accepts the exact commit and names the compiled-input build identity", () => {
  withTempDir((dir) => {
    const { work, base, corrected } = releaseLikeRepository(dir);
    const result = identityRun(work, {
      PUBLIC_COMMIT: corrected,
      EXPECTED_PUBLIC_HEAD: corrected,
      RELEASE_VERSION: "0.10.5",
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.outputs.commit, corrected);
    // The whole point of #2459: a checksum-only commit must not move the
    // identity the binary compiles in.
    assert.equal(result.outputs.build_identity, base);
  });
});

test("preflight identity refuses a checkout that is not the requested commit", () => {
  withTempDir((dir) => {
    const { work, base, corrected } = releaseLikeRepository(dir);
    const result = identityRun(work, {
      PUBLIC_COMMIT: base,
      EXPECTED_PUBLIC_HEAD: corrected,
      RELEASE_VERSION: "0.10.5",
    });
    assert.notEqual(result.status, 0);
  });
});

test("preflight identity refuses a public head the caller did not observe", () => {
  withTempDir((dir) => {
    const { work, base, corrected } = releaseLikeRepository(dir);
    const result = identityRun(work, {
      PUBLIC_COMMIT: corrected,
      EXPECTED_PUBLIC_HEAD: base,
      RELEASE_VERSION: "0.10.5",
    });
    assert.notEqual(result.status, 0);
  });
});

test("preflight identity refuses a malformed commit or private commit", () => {
  withTempDir((dir) => {
    const { work, corrected } = releaseLikeRepository(dir);
    assert.notEqual(
      identityRun(work, {
        PUBLIC_COMMIT: "not-a-sha",
        EXPECTED_PUBLIC_HEAD: corrected,
        RELEASE_VERSION: "0.10.5",
      }).status,
      0,
    );
    assert.notEqual(
      identityRun(work, {
        PUBLIC_COMMIT: corrected,
        EXPECTED_PUBLIC_HEAD: corrected,
        PRIVATE_COMMIT: "abc",
        RELEASE_VERSION: "0.10.5",
      }).status,
      0,
    );
  });
});

test("preflight identity refuses to qualify a version whose tag already exists", () => {
  withTempDir((dir) => {
    const { work, corrected } = releaseLikeRepository(dir);
    git(work, "tag", "-a", "v0.10.5", "-m", "release");
    git(work, "push", "-q", "origin", "v0.10.5");
    const result = identityRun(work, {
      PUBLIC_COMMIT: corrected,
      EXPECTED_PUBLIC_HEAD: corrected,
      RELEASE_VERSION: "0.10.5",
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /already exists/u);
  });
});

function checksumDiffRun(work, args = []) {
  return run(BASH, [script("check-checksum-only-diff.sh"), ...args], { cwd: work });
}

test("the checksum-only gate accepts a correction confined to the projection set", () => {
  withTempDir((dir) => {
    const { work, base, corrected } = releaseLikeRepository(dir);
    const result = checksumDiffRun(work, [base, corrected]);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /plugins\/bifrost-agent\/bifrost-release\.json/u);
  });
});

test("the checksum-only gate refuses a source file smuggled alongside the metadata", () => {
  withTempDir((dir) => {
    const { work, base } = releaseLikeRepository(dir);
    const smuggled = commit(work, "and one more thing", {
      "src/main.rs": "fn main() { println!(\"backdoor\"); }\n",
    });
    const result = checksumDiffRun(work, [base, smuggled]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /src\/main\.rs/u);
  });
});

test("the checksum-only gate refuses a lone unrelated file", () => {
  withTempDir((dir) => {
    const { work, corrected } = releaseLikeRepository(dir);
    const unrelated = commit(work, "docs", { "README.md": "hello\n" });
    const result = checksumDiffRun(work, [corrected, unrelated]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /README\.md/u);
  });
});

test("the checksum-only gate refuses Cargo.lock", () => {
  withTempDir((dir) => {
    const { work, corrected } = releaseLikeRepository(dir);
    const locked = commit(work, "bump a dependency", { "Cargo.lock": "version = 4\n" });
    const result = checksumDiffRun(work, [corrected, locked]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Cargo\.lock/u);
  });
});

test("the checksum-only gate refuses a version bump hiding inside an allowlisted file", () => {
  withTempDir((dir) => {
    const { work, corrected } = releaseLikeRepository(dir);
    const bumped = commit(work, "checksums, and a version", {
      "editors/vscode/package.json": vscodeManifest("0.10.6"),
    });
    const result = checksumDiffRun(work, [corrected, bumped]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /version string changed/u);
  });
});

test("the checksum-only gate refuses an empty diff", () => {
  withTempDir((dir) => {
    const { work, corrected } = releaseLikeRepository(dir);
    const result = checksumDiffRun(work, [corrected, corrected]);
    assert.notEqual(result.status, 0);
  });
});

test("the checksum-only gate reads the working tree when given no revisions", () => {
  withTempDir((dir) => {
    const { work } = releaseLikeRepository(dir);
    writeFile(work, "plugins/bifrost-agent/bifrost-release.json", releaseMetadata("0.10.5", "newer"));
    assert.equal(checksumDiffRun(work).status, 0);
    writeFile(work, "src/main.rs", "fn main() { /* nope */ }\n");
    assert.notEqual(checksumDiffRun(work).status, 0);
  });
});

function requalificationRun(work, sourceCommit, publicCommit) {
  return run(BASH, [script("check-requalification-correction.sh")], {
    cwd: work,
    env: { SOURCE_COMMIT: sourceCommit, PUBLIC_COMMIT: publicCommit },
  });
}

test("re-qualification accepts a metadata-only correction on the same release line", () => {
  withTempDir((dir) => {
    const { work, base, corrected } = releaseLikeRepository(dir);
    const result = requalificationRun(work, base, corrected);
    assert.equal(result.status, 0, result.stderr);
  });
});

test("re-qualification refuses to reuse artifacts already qualified for this commit", () => {
  withTempDir((dir) => {
    const { work, corrected } = releaseLikeRepository(dir);
    const result = requalificationRun(work, corrected, corrected);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /already qualified/u);
  });
});

test("re-qualification refuses a source commit off the release line", () => {
  withTempDir((dir) => {
    const { work, base, corrected } = releaseLikeRepository(dir);
    git(work, "checkout", "-q", base);
    const sibling = commit(work, "a different line", {
      "plugins/bifrost-agent/bifrost-release.json": releaseMetadata("0.10.5", "sibling"),
    });
    const result = requalificationRun(work, sibling, corrected);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /not an ancestor/u);
  });
});

const QUALIFIED_COMMIT = "a".repeat(40);

function sourceQualificationRun(dir, routes, overrides = {}) {
  const outputFile = path.join(dir, "github-output");
  fs.writeFileSync(outputFile, "");
  const result = run(BASH, [script("read-source-qualification.sh")], {
    env: {
      ...fakeGhEnv(dir, { routes }).env,
      PUBLIC_REPOSITORY: "BrokkAi/bifrost",
      SOURCE_RUN_ID: "123",
      RELEASE_VERSION: "0.10.5",
      GITHUB_OUTPUT: outputFile,
      ...overrides,
    },
  });
  const outputs = Object.fromEntries(
    fs
      .readFileSync(outputFile, "utf8")
      .split("\n")
      .filter(Boolean)
      .map((line) => line.split("=")),
  );
  return { ...result, outputs };
}

function qualificationRoutes({ conclusion = "success", workflowPath = ".github/workflows/release-readiness.yml", artifacts } = {}) {
  return {
    "repos/BrokkAi/bifrost/actions/runs/123": { conclusion, path: workflowPath },
    "repos/BrokkAi/bifrost/actions/runs/123/artifacts": {
      artifacts: artifacts ?? [
        { name: `release-qualification-${QUALIFIED_COMMIT}-v0.10.5`, expired: false },
      ],
    },
  };
}

test("the source qualification is taken from the artifact name, not the run head", () => {
  withTempDir((dir) => {
    const result = sourceQualificationRun(dir, qualificationRoutes());
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.outputs.source_commit, QUALIFIED_COMMIT);
    assert.equal(result.outputs.artifact_name, `release-qualification-${QUALIFIED_COMMIT}-v0.10.5`);
  });
});

test("a qualification run that did not succeed cannot authorize reuse", () => {
  withTempDir((dir) => {
    const result = sourceQualificationRun(dir, qualificationRoutes({ conclusion: "failure" }));
    assert.notEqual(result.status, 0);
  });
});

test("a run from another workflow cannot authorize reuse", () => {
  withTempDir((dir) => {
    const result = sourceQualificationRun(
      dir,
      qualificationRoutes({ workflowPath: ".github/workflows/nightly.yml" }),
    );
    assert.notEqual(result.status, 0);
  });
});

test("an expired bundle is not reusable", () => {
  withTempDir((dir) => {
    const result = sourceQualificationRun(
      dir,
      qualificationRoutes({
        artifacts: [{ name: `release-qualification-${QUALIFIED_COMMIT}-v0.10.5`, expired: true }],
      }),
    );
    assert.notEqual(result.status, 0);
  });
});

test("a bundle qualified for a different version is not reusable", () => {
  withTempDir((dir) => {
    const result = sourceQualificationRun(
      dir,
      qualificationRoutes({
        artifacts: [{ name: `release-qualification-${QUALIFIED_COMMIT}-v0.10.4`, expired: false }],
      }),
    );
    assert.notEqual(result.status, 0);
  });
});

test("an artifact whose name carries no commit is not reusable", () => {
  withTempDir((dir) => {
    const result = sourceQualificationRun(
      dir,
      qualificationRoutes({
        artifacts: [{ name: "release-qualification-latest-v0.10.5", expired: false }],
      }),
    );
    assert.notEqual(result.status, 0);
  });
});

function completeBundle(dir, { crates = 20, wheels = 10, vsix = 1, tgz = 1, sidecars = 8, notices = true } = {}) {
  const bundle = path.join(dir, "qualification-bundle");
  fs.mkdirSync(bundle, { recursive: true });
  for (let index = 0; index < crates; index += 1) {
    fs.writeFileSync(path.join(bundle, `crate-${index}.crate`), "");
    fs.writeFileSync(path.join(bundle, `crate-${index}.crate.metadata.json`), "{}");
  }
  for (let index = 0; index < wheels; index += 1) {
    fs.writeFileSync(path.join(bundle, `wheel-${index}.whl`), "");
  }
  for (let index = 0; index < vsix; index += 1) {
    fs.writeFileSync(path.join(bundle, `extension-${index}.vsix`), "");
  }
  for (let index = 0; index < tgz; index += 1) {
    fs.writeFileSync(path.join(bundle, `package-${index}.tgz`), "");
  }
  for (let index = 0; index < sidecars; index += 1) {
    fs.writeFileSync(path.join(bundle, `archive-${index}.sha256`), "");
  }
  if (notices) {
    fs.writeFileSync(path.join(bundle, "THIRD_PARTY_LICENSES.html"), "");
  }
  return bundle;
}

function inventoryRun(bundle) {
  return run(BASH, [script("check-qualification-inventory.sh"), bundle]);
}

test("a complete qualification bundle passes the inventory check", () => {
  withTempDir((dir) => {
    const result = inventoryRun(completeBundle(dir));
    assert.equal(result.status, 0, result.stderr);
  });
});

test("the inventory check counts crates against the release crate inventory", () => {
  withTempDir((dir) => {
    const result = inventoryRun(completeBundle(dir, { crates: 18 }));
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /\*\.crate,/u);
  });
});

test("a bundle missing every wheel is refused", () => {
  withTempDir((dir) => {
    const result = inventoryRun(completeBundle(dir, { wheels: 0 }));
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /whl/u);
  });
});

test("a bundle of sidecars alone is refused", () => {
  // The re-qualification path used to assert only that eight sidecars were
  // present, which this bundle satisfies.
  withTempDir((dir) => {
    const bundle = path.join(dir, "qualification-bundle");
    fs.mkdirSync(bundle, { recursive: true });
    for (let index = 0; index < 8; index += 1) {
      fs.writeFileSync(path.join(bundle, `archive-${index}.sha256`), "");
    }
    assert.notEqual(inventoryRun(bundle).status, 0);
  });
});

test("a bundle without third-party notices is refused", () => {
  withTempDir((dir) => {
    assert.notEqual(inventoryRun(completeBundle(dir, { notices: false })).status, 0);
  });
});

const identityEnv = {
  RELEASE_VERSION: "0.10.5",
  RELEASE_TAG: "v0.10.5",
  PUBLIC_REPOSITORY: "BrokkAi/bifrost",
  PUBLIC_COMMIT: QUALIFIED_COMMIT,
  RUN_ID: "999",
  RUN_ATTEMPT: "1",
};

function writeIdentity(dir, env) {
  const output = path.join(dir, "qualification-identity.json");
  const result = run("node", [script("write-qualification-identity.mjs"), "--output", output], {
    env: { ...identityEnv, PRIVATE_COMMIT: "", SOURCE_RUN_ID: "", SOURCE_COMMIT: "", ...env },
  });
  return {
    ...result,
    identity: fs.existsSync(output) ? JSON.parse(fs.readFileSync(output, "utf8")) : null,
  };
}

test("a freshly built bundle records no reuse provenance", () => {
  withTempDir((dir) => {
    const { status, identity } = writeIdentity(dir, {});
    assert.equal(status, 0);
    assert.deepEqual(identity, {
      release: { version: "0.10.5", tag: "v0.10.5" },
      source: { repository: "BrokkAi/bifrost", publicCommit: QUALIFIED_COMMIT },
      qualification: { workflow: "release-readiness.yml", runId: 999, runAttempt: 1 },
    });
  });
});

test("a re-qualified bundle records where its artifacts were built", () => {
  withTempDir((dir) => {
    const sourceCommit = "b".repeat(40);
    const { status, identity } = writeIdentity(dir, {
      SOURCE_RUN_ID: "123",
      SOURCE_COMMIT: sourceCommit,
      PRIVATE_COMMIT: "c".repeat(40),
    });
    assert.equal(status, 0);
    assert.equal(identity.source.privateCommit, "c".repeat(40));
    assert.equal(identity.qualification.builtByRunId, 123);
    assert.equal(identity.qualification.builtFromCommit, sourceCommit);
  });
});

test("half a reuse record is refused rather than written", () => {
  withTempDir((dir) => {
    const { status, identity } = writeIdentity(dir, { SOURCE_RUN_ID: "123" });
    assert.notEqual(status, 0);
    assert.equal(identity, null);
  });
});

test("an identity missing a required field is refused", () => {
  withTempDir((dir) => {
    const { status, identity } = writeIdentity(dir, { RELEASE_TAG: "" });
    assert.notEqual(status, 0);
    assert.equal(identity, null);
  });
});
