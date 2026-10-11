// Tests for the shell entry points release-readiness.yml invokes.
//
// These used to be `run: |` blocks, which execute only inside a workflow run:
// the only way to exercise release logic was to perform a release, and several
// defects were duly found by a release failing rather than by a test. Each case
// below is decidable without a workflow run.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { fakeGhEnv } from "../fixtures/workflow-shell/fake-gh.mjs";
import { run, scriptForDirectory } from "./release-script-test-helpers.mjs";
import {
  createBareGitPair,
  gitWithTestIdentity,
  withTempDir as withSharedTempDir,
  writeExecutable,
} from "./test-fixtures.mjs";
import { writeFixtureFile as writeFile } from "../test-support/write-file.mjs";

const scriptsDir = fileURLToPath(new URL(".", import.meta.url));
const repoRoot = path.resolve(scriptsDir, "..", "..");
const script = scriptForDirectory(scriptsDir);

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

const offlineAcceptance = script("accept-offline-semantic-pack-install.sh");
const OFFLINE_PROFILE = {
  build_identity: "a".repeat(40),
  capabilities: ["taint"],
  capability_contract_version: 1,
  engine_version: "0.13.0",
  model_set_sha256: "b".repeat(64),
  schemas: {
    policy_document: [1],
    rql: [1],
    builtin_catalog: [2],
    policy_bundle: [1],
    semantic_model_read: [2],
    semantic_model_write: [8],
    semantic_spec: [1],
    release_index: [3],
    runtime: [1],
  },
};
const OFFLINE_POLICY_ID = "bifrost.security.java.system-getenv-to-runtime-exec";
const OFFLINE_PACK_IDS = [
  "bifrost.jdk",
  "bifrost.kotlin-stdlib",
  "bifrost.python-stdlib",
  "bifrost.python-stdlib-assertions",
  "bifrost.rust-stdlib",
  "bifrost.scala-library",
  "bifrost.typescript-stdlib",
];

function digestBytes(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function offlineAcceptanceFixture(dir) {
  const fakeBin = path.join(dir, "fake-bin");
  const openPackRoot = path.join(dir, "open-pack-releases");
  const cacheRoot = path.join(openPackRoot, "semantic-pack-catalog-v1");
  const selectionId = "c".repeat(64);
  const selectionRoot = path.join(openPackRoot, "selections", selectionId);
  const policyRoot = path.join(selectionRoot, "root", "rules");
  const bundleRoot = path.join(
    selectionRoot,
    "dependency-bifrost.public.packs",
    "bifrost-semantic-packs",
  );
  const receiptPath = path.join(selectionRoot, "receipt.json");
  const outcomePath = path.join(dir, "open-packs-outcome.json");
  const scratchRoot = path.join(dir, "scratch");
  const javaHome = path.join(dir, "jdk");
  const dockerLog = path.join(dir, "docker.log");
  const installerLog = path.join(dir, "installer.log");
  const bifrost = path.join(fakeBin, "bifrost");
  const installer = path.join(fakeBin, "bifrost-semantic-pack");
  const docker = path.join(fakeBin, "docker");

  fs.mkdirSync(path.join(policyRoot, "bifrost.security"), { recursive: true });
  fs.mkdirSync(path.join(bundleRoot), { recursive: true });
  fs.mkdirSync(cacheRoot, { recursive: true });
  writeExecutable(path.join(javaHome, "bin", "java"), "#!/usr/bin/env bash\nexit 0\n");
  fs.mkdirSync(path.join(javaHome, "jmods"), { recursive: true });

  const policyManifest = `${JSON.stringify({
    schema_version: 2,
    id: "bifrost.security",
    version: "1.3.0",
    policies: [{
      path: "policies/jvm/system-getenv-to-runtime-exec.rqlp",
      id: OFFLINE_POLICY_ID,
      resolved_semantic_hash: "d".repeat(64),
    }],
  }, null, 2)}\n`;
  const policyManifestBytes = Buffer.from(policyManifest);
  fs.writeFileSync(path.join(policyRoot, "bifrost.security", "manifest.json"), policyManifestBytes);
  fs.writeFileSync(
    path.join(bundleRoot, "index.json"),
    JSON.stringify({ packs: OFFLINE_PACK_IDS.map((pack_id) => ({ pack_id })) }),
  );
  const manifestDigest = digestBytes(policyManifestBytes);
  const manifestRelativePath = "rules/bifrost.security/manifest.json";
  const request = {
    request_schema_version: 1,
    pack_id: "bifrost.public.rules",
    repository: "https://github.com/BrokkAi/bifrost-packs",
    selection: { mode: "preferred", allowed_versions: "*", channel: "stable" },
    dependencies: [{
      pack_id: "bifrost.public.packs",
      repository: "https://github.com/BrokkAi/bifrost-packs",
      manifest_sha256: "e".repeat(64),
    }],
  };
  const createdAt = "2026-10-09T00:00:00.000Z";
  const receipt = {
    receipt_schema_version: 3,
    status: "qualified",
    selection_id: selectionId,
    selection_reason: "highest-eligible",
    request,
    engine: {
      version: OFFLINE_PROFILE.engine_version,
      build_identity: OFFLINE_PROFILE.build_identity,
      profile: OFFLINE_PROFILE,
    },
    source: {
      repository: request.repository,
      inventory_url: null,
      inventory_sha256_pin: null,
      index_sha256: "f".repeat(64),
      fetched_at: createdAt,
      fetched_online: false,
    },
    releases: [
      {
        role: "root",
        pack_id: "bifrost.public.rules",
        release_version: "1.3.0",
        visibility: "public",
        tag: "rules/v1.3.0",
        tag_commit: "1".repeat(40),
        source_commit: "1".repeat(40),
        manifest_schema_version: 2,
        manifest_sha256: "2".repeat(64),
        qualification: {
          integrity: { status: "verified", evidence: [] },
          behavior: { status: "qualified", evidence: [] },
        },
        provenance: null,
        artifacts: [{
          name: "rules.tar.gz",
          role: "policy",
          size_bytes: 1,
          sha256: "3".repeat(64),
        }],
        contents: [{ path: manifestRelativePath, sha256: manifestDigest }],
      },
      {
        role: "dependency",
        pack_id: "bifrost.public.packs",
        release_version: "1.3.0",
        visibility: "public",
        tag: "packs/v1.3.0",
        tag_commit: "4".repeat(40),
        source_commit: "4".repeat(40),
        manifest_schema_version: 2,
        manifest_sha256: "5".repeat(64),
        qualification: {
          integrity: { status: "verified", evidence: [] },
          behavior: { status: "qualified", evidence: [] },
        },
        provenance: null,
        artifacts: [{
          name: "packs.tar.gz",
          role: "native",
          size_bytes: 1,
          sha256: "6".repeat(64),
        }],
        contents: [],
      },
    ],
    rejections: [],
    extracted_files: {
      root: [{ path: manifestRelativePath, size_bytes: policyManifestBytes.length, sha256: manifestDigest }],
      "dependency-bifrost.public.packs": [],
    },
    artifacts: [],
    replay: request,
    created_at: createdAt,
  };
  fs.mkdirSync(selectionRoot, { recursive: true });
  fs.writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`);
  const outcome = {
    outcome_schema_version: 1,
    status: "selected",
    engine: {
      version: OFFLINE_PROFILE.engine_version,
      build_identity: OFFLINE_PROFILE.build_identity,
      executable_sha256: "",
    },
    request,
    failure: null,
    rejections: [],
    inventory: {
      index_sha256: "f".repeat(64),
      fetched_at: createdAt,
      fetched_online: false,
    },
    selection: {
      selection_id: selectionId,
      selection_reason: "highest-eligible",
      cache_reused: true,
      receipt_path: receiptPath,
      policy_pack_root: policyRoot,
      semantic_bundle_root: bundleRoot,
      receipt,
    },
    created_at: createdAt,
  };

  writeExecutable(
    bifrost,
    `#!/usr/bin/env bash
set -euo pipefail
if [[ "\${1:-}" == pack-engine-profile ]]; then
  printf '%s\\n' "$FAKE_PROFILE"
else
  exit 91
fi
`,
  );
  outcome.engine.executable_sha256 = digestBytes(fs.readFileSync(bifrost));
  fs.writeFileSync(outcomePath, `${JSON.stringify(outcome, null, 2)}\n`);

  writeExecutable(
    installer,
    `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$FAKE_INSTALLER_LOG"
case "\${1:-}" in
  verify) printf 'verified\\n' ;;
  install)
    mkdir -p "$3"
    python3 - "$3/catalog.db" <<'PY'
import sqlite3
import sys
connection = sqlite3.connect(sys.argv[1])
connection.execute("create table if not exists marker (value text)")
connection.commit()
connection.close()
PY
    ;;
  list)
    printf '%s\\n' '${JSON.stringify({ installed: OFFLINE_PACK_IDS.map((pack_id) => ({ pack_id })) })}'
    ;;
  *) exit 92 ;;
esac
`,
  );
  const missingReport = {
    runs: [{
      policy_id: OFFLINE_POLICY_ID,
      findings: [],
      completion: { type: "inconclusive", reasons: ["partial_discovery"] },
      diagnostics: [{
        code: { type: "evaluation_failure" },
        severity: "warning",
        impact: "run_incomplete",
        family: "evaluation_failure",
        message: "/analysis/sinks/entries/runtime-exec-command/selector call_binding_dispatch_partial UnsupportedExpression",
      }],
    }],
    packs: { decisions: [] },
  };
  const positiveReport = {
    runs: [{
      policy_id: OFFLINE_POLICY_ID,
      policy_hash: "d".repeat(64),
      findings: [{ evidence: { evidence: {
        source_endpoint: { entry_id: "environment-variable" },
        sink_endpoint: { entry_id: "runtime-exec-command" },
      } } }],
      completion: { type: "complete" },
      diagnostics: [],
    }],
    packs: { decisions: [{ pack: "bifrost.jdk@21.0.8", status: "selected" }] },
  };
  const negativeReport = {
    runs: [{ policy_id: OFFLINE_POLICY_ID, findings: [], completion: { type: "inconclusive" } }],
    packs: { decisions: [] },
  };
  const cleanReport = {
    runs: [{ policy_id: OFFLINE_POLICY_ID, findings: [], completion: { type: "complete" }, diagnostics: [] }],
    packs: { decisions: [] },
  };
  writeExecutable(
    docker,
    `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$FAKE_DOCKER_LOG"
case "$(wc -l < "$FAKE_DOCKER_LOG" | tr -d ' ')" in
  1) printf '%s\\n' "$FAKE_MISSING_REPORT"; exit 2 ;;
  2) printf '%s\\n' "$FAKE_POSITIVE_REPORT"; exit 0 ;;
  *) printf '%s\\n' "$FAKE_NEGATIVE_REPORT"; exit 1 ;;
esac
`,
  );

  return {
    bifrost,
    installer,
    bundleRoot,
    policyRoot,
    cacheRoot,
    outcomePath,
    javaHome,
    scratchRoot,
    dockerLog,
    installerLog,
    receipt,
    outcome,
    fakeBin,
    profile: JSON.stringify(OFFLINE_PROFILE),
    reports: {
      missing: JSON.stringify(missingReport),
      positive: JSON.stringify(positiveReport),
      negative: JSON.stringify(negativeReport),
      clean: JSON.stringify(cleanReport),
    },
  };
}

function runOfflineAcceptance(dir, mutate = () => {}) {
  const fixture = offlineAcceptanceFixture(dir);
  mutate(fixture);
  fs.writeFileSync(fixture.outcomePath, `${JSON.stringify(fixture.outcome, null, 2)}\n`);
  const result = run(BASH, [
    offlineAcceptance,
    fixture.bifrost,
    fixture.installer,
    fixture.bundleRoot,
    fixture.policyRoot,
    fixture.cacheRoot,
    fixture.outcomePath,
    fixture.javaHome,
    fixture.scratchRoot,
  ], {
    env: {
      PATH: `${fixture.fakeBin}:${process.env.PATH}`,
      FAKE_PROFILE: fixture.profile,
      FAKE_INSTALLER_LOG: fixture.installerLog,
      FAKE_DOCKER_LOG: fixture.dockerLog,
      FAKE_MISSING_REPORT: fixture.reports.missing,
      FAKE_POSITIVE_REPORT: fixture.reports.positive,
      FAKE_NEGATIVE_REPORT: fixture.reports.negative,
    },
  });
  return { ...fixture, result };
}

test("offline semantic-pack acceptance requires the producer's eight exact inputs", () => {
  withTempDir((dir) => {
    const result = run(BASH, [offlineAcceptance, ...Array.from({ length: 7 }, () => dir)]);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /usage: .*BUNDLE POLICY_ROOT CACHE OUTCOME_RECEIPT JAVA_HOME SCRATCH_ROOT/u);
  });
});

test("offline semantic-pack acceptance passes provenance validation before its four scans", () => {
  withTempDir((dir) => {
    const fixture = runOfflineAcceptance(dir);
    assert.equal(fixture.result.status, 0, fixture.result.stderr);
    assert.equal(fs.readFileSync(fixture.dockerLog, "utf8").trim().split("\n").length, 4);
    assert.match(fs.readFileSync(fixture.installerLog, "utf8"), /^verify /mu);
    assert.match(fs.readFileSync(fixture.installerLog, "utf8"), /^install /mu);
    const retained = JSON.parse(fs.readFileSync(path.join(fixture.scratchRoot, "open-packs-receipt.json"), "utf8"));
    assert.equal(retained.receipt_schema_version, 3);
    assert.equal(retained.selection_id, fixture.receipt.selection_id);
    assert.equal(retained.outcome_schema_version, undefined);
  });
});

for (const [label, mutate] of [
  ["wrong executable digest", (fixture) => {
    fixture.outcome.engine.executable_sha256 = "b".repeat(64);
  }],
  ["wrong selected profile", (fixture) => {
    fixture.receipt.engine.profile = { ...fixture.receipt.engine.profile, build_identity: "b".repeat(40) };
    fixture.outcome.selection.receipt = fixture.receipt;
    fs.writeFileSync(
      path.join(path.dirname(fixture.outcome.selection.receipt_path), "receipt.json"),
      `${JSON.stringify(fixture.receipt, null, 2)}\n`,
    );
  }],
  ["wrong selected roots", (fixture) => {
    const wrongRoot = path.join(path.dirname(fixture.policyRoot), "wrong-rules");
    fs.mkdirSync(wrongRoot, { recursive: true });
    fixture.outcome.selection.policy_pack_root = wrongRoot;
  }],
]) {
  test(`offline semantic-pack acceptance rejects ${label} before Docker or install`, () => {
    withTempDir((dir) => {
      const fixture = runOfflineAcceptance(dir, mutate);
      assert.notEqual(fixture.result.status, 0);
      assert.equal(fs.existsSync(fixture.dockerLog), false);
      assert.equal(fs.existsSync(fixture.installerLog), false);
    });
  });
}

test("offline semantic-pack acceptance rejects a tampered selected manifest before Docker or install", () => {
  withTempDir((dir) => {
    const fixture = runOfflineAcceptance(dir, (value) => {
      fs.writeFileSync(path.join(value.policyRoot, "bifrost.security", "manifest.json"), "tampered\n");
    });
    assert.notEqual(fixture.result.status, 0);
    assert.match(fixture.result.stderr, /selected policy manifest digest disagrees/u);
    assert.equal(fs.existsSync(fixture.dockerLog), false);
    assert.equal(fs.existsSync(fixture.installerLog), false);
  });
});

test("offline semantic-pack acceptance rejects an embedded receipt that disagrees with disk before Docker or install", () => {
  withTempDir((dir) => {
    const fixture = runOfflineAcceptance(dir, (value) => {
      const onDiskReceipt = {
        ...value.receipt,
        source: { ...value.receipt.source, index_sha256: "e".repeat(64) },
      };
      fs.writeFileSync(
        value.outcome.selection.receipt_path,
        `${JSON.stringify(onDiskReceipt, null, 2)}\n`,
      );
    });
    assert.notEqual(fixture.result.status, 0);
    assert.match(fixture.result.stderr, /embedded receipt differs/u);
    assert.equal(fs.existsSync(fixture.dockerLog), false);
    assert.equal(fs.existsSync(fixture.installerLog), false);
  });
});

test("offline semantic-pack acceptance rejects a complete clean missing-JAVA_HOME report", () => {
  withTempDir((dir) => {
    const fixture = runOfflineAcceptance(dir, (value) => {
      value.reports.missing = value.reports.clean;
    });
    assert.notEqual(fixture.result.status, 0);
    assert.match(fixture.result.stderr, /missing catalog produced a complete clean policy run/u);
  });
});

test("offline semantic-pack acceptance rejects a complete clean corrupt-catalog report", () => {
  withTempDir((dir) => {
    const fixture = runOfflineAcceptance(dir, (value) => {
      value.reports.negative = value.reports.clean;
    });
    assert.notEqual(fixture.result.status, 0);
    assert.match(fixture.result.stderr, /corrupt catalog produced a complete clean policy run/u);
  });
});

function withTempDir(body) {
  return withSharedTempDir(body, "bifrost-readiness-scripts.");
}

function git(cwd, ...args) {
  return gitWithTestIdentity(cwd, args).trim();
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

// A repository shaped like the public one: a compiled-input commit, then a
// checksum-only correction on top of it.
function releaseLikeRepository(dir) {
  const { origin, work } = createBareGitPair(dir);
  git(work, "config", "commit.gpgsign", "false");
  git(work, "remote", "add", "origin", origin);

  const base = commit(work, "compiled input", {
    "src/main.rs": "fn main() {}\n",
    "plugins/bifrost-agent/bifrost-release.json": releaseMetadata("0.10.5", "old"),
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
  // A member that opts out of publication (such as a test-only proc-macro
  // crate) is not part of the release.
  const published = members.filter(
    (member) =>
      !/^publish\s*=\s*false\s*$/mu.test(
        fs.readFileSync(path.join(repoRoot, "crates", member, "Cargo.toml"), "utf8"),
      ),
  );

  const expected = [...published.map((member) => `brokk-${member}`), "brokk-bifrost"];
  assert.deepEqual([...crates].sort(), expected.sort());
  assert.equal(crates.at(-1), "brokk-bifrost", "the facade must be packaged last");
});

test("the facade excludes readiness artifacts and the packager enforces crates.io's size cap", () => {
  const manifest = fs.readFileSync(path.join(repoRoot, "Cargo.toml"), "utf8");
  const packager = fs.readFileSync(script("package-release-crates.sh"), "utf8");

  assert.match(manifest, /^\s*"dist\/\*\*",$/mu);
  assert.match(packager, /max_crates_io_upload_bytes=10485760/u);
  assert.match(packager, /archive_bytes <= max_crates_io_upload_bytes/u);
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
      "plugins/bifrost-agent/bifrost-release.json": releaseMetadata("0.10.6", "new"),
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

// The inventory check counts *.crate archives against RELEASE_CRATES, so a
// complete bundle must hold exactly that many. Reading the count from the
// shared inventory keeps this fixture from drifting when a crate is added or
// removed, which is how a fixed 20 outlived the NLP crate's removal.
const releaseCrateCount = Number(
  execFileSync(
    BASH,
    ["-c", 'source "$1"; echo "${#RELEASE_CRATES[@]}"', "bash", path.join(repoRoot, "scripts", "lib", "release-crates.sh")],
    { encoding: "utf8" },
  ).trim(),
);

function completeBundle(dir, { crates = releaseCrateCount, wheels = 10, tgz = 2, sidecars = 7, notices = true } = {}) {
  const bundle = path.join(dir, "qualification-bundle");
  fs.mkdirSync(bundle, { recursive: true });
  for (let index = 0; index < crates; index += 1) {
    fs.writeFileSync(path.join(bundle, `crate-${index}.crate`), "");
    fs.writeFileSync(path.join(bundle, `crate-${index}.crate.metadata.json`), "{}");
  }
  for (let index = 0; index < wheels; index += 1) {
    fs.writeFileSync(path.join(bundle, `wheel-${index}.whl`), "");
  }
  for (let index = 0; index < tgz; index += 1) {
    fs.writeFileSync(path.join(bundle, `package-${index}.tgz`), "");
  }
  for (let index = 0; index < sidecars; index += 1) {
    fs.writeFileSync(path.join(bundle, `archive-${index}.sha256`), "");
  }
  const installer = "bifrost-semantic-pack-v0.11.5-x86_64-unknown-linux-gnu.tar.gz";
  fs.writeFileSync(path.join(bundle, installer), "installer fixture");
  const installerDigest = createHash("sha256").update("installer fixture").digest("hex");
  fs.writeFileSync(path.join(bundle, `${installer}.sha256`), `${installerDigest}  ${installer}\n`);
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

function v013Bundle(dir, status) {
  const bundle = completeBundle(dir);
  const before = "bifrost-semantic-pack-v0.11.5-x86_64-unknown-linux-gnu.tar.gz";
  const after = before.replace("v0.11.5", "v0.13.0");
  fs.renameSync(path.join(bundle, before), path.join(bundle, after));
  const digest = createHash("sha256").update("installer fixture").digest("hex");
  fs.unlinkSync(path.join(bundle, `${before}.sha256`));
  fs.writeFileSync(path.join(bundle, `${after}.sha256`), `${digest}  ${after}\n`);
  if (status) fs.writeFileSync(path.join(bundle, "core-policy-status.json"), JSON.stringify(status));
  return bundle;
}

const emptyCoreStatus = {
  schema_version: 1,
  core: { status: "verified", rules: "host-supplied", active_rule_packs: 0,
    build_identity: "a".repeat(40), binary_sha256: "b".repeat(64) },
  external_content: { status: "not-qualified" },
};

test("v0.13 requires verified core-without-rules evidence in the release bundle", () => {
  withTempDir((dir) => {
    const result = inventoryRun(v013Bundle(dir, emptyCoreStatus));
    assert.equal(result.status, 0, result.stderr);
  });
});
test("v0.13 cannot reuse a bundle missing core-without-rules evidence", () => {
  withTempDir((dir) => {
    const result = inventoryRun(v013Bundle(dir));
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /core-policy-status/u);
  });
});
test("v0.13 refuses a bundle that labels embedded rules as core qualification", () => {
  withTempDir((dir) => {
    const status = structuredClone(emptyCoreStatus);
    status.core.active_rule_packs = 1;
    assert.notEqual(inventoryRun(v013Bundle(dir, status)).status, 0);
  });
});

test("a qualification bundle containing retired semantic-pack content is refused", () => {
  withTempDir((dir) => {
    const bundle = completeBundle(dir);
    fs.writeFileSync(path.join(bundle, "bifrost-semantic-packs-v0.13.0.tar.gz"), "retired content");
    const result = inventoryRun(bundle);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /holds 1 bifrost-semantic-packs-\*/u);
  });
});

test("a qualification bundle missing the DSH npm archive is refused", () => {
  withTempDir((dir) => {
    const result = inventoryRun(completeBundle(dir, { tgz: 1 }));
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /holds 1 \*\.tgz, expected at-least 2/u);
  });
});

test("the inventory check counts crates against the release crate inventory", () => {
  withTempDir((dir) => {
    const result = inventoryRun(completeBundle(dir, { crates: releaseCrateCount - 1 }));
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
  // The re-qualification path used to assert only that seven sidecars were
  // present, which this bundle satisfies.
  withTempDir((dir) => {
    const bundle = path.join(dir, "qualification-bundle");
    fs.mkdirSync(bundle, { recursive: true });
    for (let index = 0; index < 7; index += 1) {
      fs.writeFileSync(path.join(bundle, `archive-${index}.sha256`), "");
    }
    assert.notEqual(inventoryRun(bundle).status, 0);
  });
});

function elfVerifierRun(dir, target, overrides = {}) {
  const fakeBin = path.join(dir, "bin");
  fs.mkdirSync(fakeBin, { recursive: true });
  const fakeReadelf = path.join(fakeBin, "readelf");
  fs.writeFileSync(
    fakeReadelf,
    `#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  -hW)
    printf '  Machine:                           %s\\n' "$FAKE_MACHINE"
    ;;
  -lW)
    printf '      [Requesting program interpreter: %s]\\n' "$FAKE_INTERPRETER"
    ;;
  --version-info)
    for version in $FAKE_GLIBC_VERSIONS; do
      printf '  Name: GLIBC_%s  Flags: none  Version: 1\\n' "$version"
    done
    ;;
  -dW)
    for library in $FAKE_NEEDED; do
      printf ' 0x0000000000000001 (NEEDED) Shared library: [%s]\\n' "$library"
    done
    ;;
  *)
    exit 2
    ;;
esac
`,
  );
  fs.chmodSync(fakeReadelf, 0o755);
  const binary = path.join(dir, "bifrost");
  fs.writeFileSync(binary, "fake ELF");
  return run(BASH, [script("verify-linux-release-elf.sh"), binary, target], {
    env: {
      PATH: `${fakeBin}:${process.env.PATH}`,
      FAKE_MACHINE: "Advanced Micro Devices X86-64",
      FAKE_INTERPRETER: "/lib64/ld-linux-x86-64.so.2",
      FAKE_GLIBC_VERSIONS: "2.2.5 2.17 2.28",
      FAKE_NEEDED: "libm.so.6 libpthread.so.0 libc.so.6 libdl.so.2 ld-linux-x86-64.so.2",
      ...overrides,
    },
  });
}

test("the ELF verifier accepts the approved GNU runtime contract for both architectures", () => {
  withTempDir((dir) => {
    const x86 = elfVerifierRun(dir, "x86_64-unknown-linux-gnu");
    assert.equal(x86.status, 0, x86.stderr);
    assert.match(x86.stdout, /maximum GLIBC version: 2\.28/u);
  });
  withTempDir((dir) => {
    const arm = elfVerifierRun(dir, "aarch64-unknown-linux-gnu", {
      FAKE_MACHINE: "AArch64",
      FAKE_INTERPRETER: "/lib/ld-linux-aarch64.so.1",
      FAKE_NEEDED: "libgcc_s.so.1 libm.so.6 libc.so.6 ld-linux-aarch64.so.1",
    });
    assert.equal(arm.status, 0, arm.stderr);
    assert.match(arm.stdout, /aarch64-unknown-linux-gnu/u);
  });
});

test("the ELF verifier rejects a glibc requirement above the release floor", () => {
  withTempDir((dir) => {
    const result = elfVerifierRun(dir, "x86_64-unknown-linux-gnu", {
      FAKE_GLIBC_VERSIONS: "2.2.5 2.28 2.29",
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /maximum GLIBC version is 2\.29/u);
  });
});

test("the ELF verifier rejects unexpected shared libraries with the complete dependency set", () => {
  withTempDir((dir) => {
    const result = elfVerifierRun(dir, "x86_64-unknown-linux-gnu", {
      FAKE_NEEDED: "libc.so.6 libz.so.1 ld-linux-x86-64.so.2",
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /unexpected dynamic dependency libz\.so\.1/u);
    assert.match(result.stderr, /libc\.so\.6 libz\.so\.1 ld-linux-x86-64\.so\.2/u);
  });
});

test("the ELF verifier rejects the wrong architecture or dynamic loader", () => {
  withTempDir((dir) => {
    const wrongMachine = elfVerifierRun(dir, "x86_64-unknown-linux-gnu", {
      FAKE_MACHINE: "AArch64",
    });
    assert.notEqual(wrongMachine.status, 0);
    assert.match(wrongMachine.stderr, /requires machine/u);
  });
  withTempDir((dir) => {
    const wrongLoader = elfVerifierRun(dir, "x86_64-unknown-linux-gnu", {
      FAKE_INTERPRETER: "/lib/ld-linux-aarch64.so.1",
    });
    assert.notEqual(wrongLoader.status, 0);
    assert.match(wrongLoader.stderr, /requires interpreter/u);
  });
});

test("the ELF verifier rejects binaries without glibc symbol versions", () => {
  withTempDir((dir) => {
    const result = elfVerifierRun(dir, "x86_64-unknown-linux-gnu", {
      FAKE_GLIBC_VERSIONS: "",
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /no GLIBC symbol versions found/u);
  });
});

function linuxInstallerRun(dir, architecture, overrides = {}) {
  const fakeBin = path.join(dir, "bin");
  fs.mkdirSync(fakeBin, { recursive: true });
  writeFile(
    fakeBin,
    "uname",
    `#!/usr/bin/env bash
case "\${1:-}" in
  -s) printf 'Linux\\n' ;;
  -m) printf '%s\\n' "$FAKE_ARCH" ;;
  -o) printf 'GNU/Linux\\n' ;;
esac
`,
  );
  writeFile(fakeBin, "getconf", `#!/usr/bin/env bash
printf '%s\\n' "$FAKE_GETCONF"
exit "$FAKE_GETCONF_STATUS"
`);
  writeFile(fakeBin, "ldd", `#!/usr/bin/env bash
printf '%s\\n' "$FAKE_LDD" >&2
exit "$FAKE_LDD_STATUS"
`);
  writeFile(fakeBin, "curl", `#!/usr/bin/env bash
touch "$CURL_MARKER"
while [[ "$1" != -o ]]; do shift; done
if [[ "$3" == *api.github.com* ]]; then
  printf '{"tag_name":"v0.11.0","assets":[{"browser_download_url":"https://example.test/bifrost-v0.11.0-%s-unknown-linux-gnu.tar.gz"}]}' "$FAKE_ARCH" > "$2"
else
  exit 99
fi
`);
  // Override only the loader glob, without relying on or modifying host /lib.
  const bashEnv = path.join(dir, "bash-env");
  fs.writeFileSync(bashEnv, `compgen() {
  if [[ "$1" == -G && "$2" == '/lib/ld-musl-*' ]]; then
    [[ "$FAKE_MUSL_LOADER" == 1 ]]
  else
    builtin compgen "$@"
  fi
}
`);
  for (const command of ["uname", "getconf", "ldd", "curl"]) {
    fs.chmodSync(path.join(fakeBin, command), 0o755);
  }
  const curlMarker = path.join(dir, "curl-called");
  const result = run(BASH, [path.join(repoRoot, "install.sh")], {
    env: {
      PATH: `${fakeBin}:${process.env.PATH}`,
      HOME: dir,
      FAKE_ARCH: architecture,
      FAKE_GETCONF: "",
      FAKE_GETCONF_STATUS: "1",
      FAKE_LDD: "musl libc (test)",
      FAKE_LDD_STATUS: "1",
      FAKE_MUSL_LOADER: "0",
      BASH_ENV: bashEnv,
      BIFROST_INSTALL_DIR: path.join(dir, "install"),
      BIFROST_VERSION: "v0.11.0",
      CURL_MARKER: curlMarker,
      ...overrides,
    },
  });
  return { ...result, curlCalled: fs.existsSync(curlMarker) };
}

test("the installer rejects x86-64 and ARM64 musl before consulting a release", () => {
  for (const architecture of ["x86_64", "aarch64"]) {
    withTempDir((dir) => {
      const result = linuxInstallerRun(dir, architecture);
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /no prebuilt musl release is published/u);
      assert.match(result.stderr, /Musl is unsupported/u);
      assert.equal(result.curlCalled, false, "musl rejection must happen before release download");
    });
  }
});

test("the installer selects GNU assets on glibc hosts with musl also installed", () => {
  for (const architecture of ["x86_64", "aarch64"]) {
    for (const probes of [
      { FAKE_GETCONF: "glibc 2.36", FAKE_GETCONF_STATUS: "0" },
      { FAKE_LDD: "ldd (Debian GLIBC 2.36-9) 2.36", FAKE_LDD_STATUS: "0" },
      { FAKE_LDD: "ldd (GNU libc) 2.28", FAKE_LDD_STATUS: "0", FAKE_GETCONF_STATUS: "127" },
    ]) {
      withTempDir((dir) => {
        const result = linuxInstallerRun(dir, architecture, { FAKE_MUSL_LOADER: "1", ...probes });
        assert.equal(result.status, 99, "fixture stops at the selected archive download");
        assert.equal(result.curlCalled, true);
        assert.match(result.stdout, new RegExp(`downloading v0\\.11\\.0 \\(bifrost-v0\\.11\\.0-${architecture}-unknown-linux-gnu\\.tar\\.gz\\)`));
        assert.doesNotMatch(result.stderr, /Musl is unsupported/u);
      });
    }
  }
});

test("the installer rejects loader-only musl evidence when libc probes are unavailable", () => {
  withTempDir((dir) => {
    const result = linuxInstallerRun(dir, "x86_64", {
      FAKE_GETCONF_STATUS: "127",
      FAKE_LDD: "ldd: not found",
      FAKE_LDD_STATUS: "127",
      FAKE_MUSL_LOADER: "1",
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Musl is unsupported/u);
    assert.equal(result.curlCalled, false);
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

test("pinned cargo-about reuses only an exact cache and repairs a version mismatch", () => {
  withTempDir((dir) => {
    const installer = script("install-pinned-release-tool.sh");
    const fakeBin = path.join(dir, "fake-bin");
    const cargoLog = path.join(dir, "cargo.log");
    const toolRoot = path.join(dir, "cargo-about");
    writeExecutable(
      path.join(fakeBin, "cargo"),
      `#!/usr/bin/env bash
printf '%s\\n' "$*" >> '${cargoLog}'
tool="\${@: -1}"
mkdir -p '${toolRoot}/bin'
rm -f '${toolRoot}.mismatch'
binary='${toolRoot}/bin/'"$tool"
cat > "$binary" <<'FAKE'
#!/usr/bin/env bash
if [[ -f '${toolRoot}.mismatch' ]]; then
  echo cargo-about 0.0.0
else
  echo cargo-about 0.9.1
fi
FAKE
chmod +x "$binary"
`,
    );
    const environment = { PATH: `${fakeBin}:${process.env.PATH}` };
    const install = () =>
      run(BASH, [installer, "cargo-about", toolRoot, "0.9.1"], { env: environment });

    assert.equal(install().status, 0, install().stderr);
    assert.equal(install().status, 0, install().stderr);
    assert.equal(fs.readFileSync(cargoLog, "utf8").split("\n").filter(Boolean).length, 1);
    assert.match(fs.readFileSync(cargoLog, "utf8"), /--locked --version 0\.9\.1 --root .* --features cli cargo-about$/mu);

    fs.writeFileSync(`${toolRoot}.mismatch`, "yes");
    assert.equal(install().status, 0, install().stderr);
    assert.equal(fs.readFileSync(cargoLog, "utf8").split("\n").filter(Boolean).length, 2);
  });
});

test("pinned Zig reuses its venv only when python-zig reports the exact version", () => {
  withTempDir((dir) => {
    const installer = script("install-pinned-release-tool.sh");
    const fakeBin = path.join(dir, "fake-bin");
    const pythonLog = path.join(dir, "python.log");
    const zigRoot = path.join(dir, "ziglang");
    writeExecutable(
      path.join(fakeBin, "python3"),
      `#!/usr/bin/env bash
printf '%s\\n' "$*" >> '${pythonLog}'
[[ "$1" == -m && "$2" == venv ]] || exit 64
mkdir -p "$3/bin"
cat > "$3/bin/pip" <<'FAKE'
#!/usr/bin/env bash
rm -f '${zigRoot}.mismatch'
cat > '${zigRoot}/bin/python-zig' <<'ZIG'
#!/usr/bin/env bash
if [[ -f '${zigRoot}.mismatch' ]]; then
  echo 0.0.0
else
  echo 0.15.2
fi
ZIG
chmod +x '${zigRoot}/bin/python-zig'
FAKE
chmod +x "$3/bin/pip"
`,
    );
    const environment = { PATH: `${fakeBin}:${process.env.PATH}` };
    const install = () =>
      run(BASH, [installer, "ziglang", zigRoot, "0.15.2"], { env: environment });

    assert.equal(install().status, 0, install().stderr);
    assert.equal(install().status, 0, install().stderr);
    assert.equal(fs.readFileSync(pythonLog, "utf8").split("\n").filter(Boolean).length, 1);

    fs.writeFileSync(`${zigRoot}.mismatch`, "yes");
    assert.equal(install().status, 0, install().stderr);
    assert.equal(fs.readFileSync(pythonLog, "utf8").split("\n").filter(Boolean).length, 2);
  });
});

test("pinned Zig repairs a cached venv whose entry point cannot execute", () => {
  withTempDir((dir) => {
    const installer = script("install-pinned-release-tool.sh");
    const fakeBin = path.join(dir, "fake-bin");
    const pythonLog = path.join(dir, "python.log");
    const zigRoot = path.join(dir, "ziglang");
    writeExecutable(
      path.join(fakeBin, "python3"),
      `#!/usr/bin/env bash
printf '%s\\n' "$*" >> '${pythonLog}'
[[ "$1" == -m && "$2" == venv ]] || exit 64
mkdir -p "$3/bin"
cat > "$3/bin/pip" <<'FAKE'
#!/usr/bin/env bash
cat > '${zigRoot}/bin/python-zig' <<'ZIG'
#!/usr/bin/env bash
echo 0.15.2
ZIG
chmod +x '${zigRoot}/bin/python-zig'
FAKE
chmod +x "$3/bin/pip"
`,
    );
    writeExecutable(path.join(zigRoot, "bin", "python-zig"), "#!/usr/bin/env bash\nexit 126\n");

    const result = run(BASH, [installer, "ziglang", zigRoot, "0.15.2"], {
      env: { PATH: `${fakeBin}:${process.env.PATH}` },
    });

    assert.equal(result.status, 0, result.stderr);
    assert.equal(fs.readFileSync(pythonLog, "utf8").split("\n").filter(Boolean).length, 1);
  });
});
