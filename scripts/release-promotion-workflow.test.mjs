import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const release = readFileSync(
  new URL("../.github/workflows/release.yml", import.meta.url),
  "utf8",
);
const releaseContext = readFileSync(
  new URL("../.github/workflows/release-context.yml", import.meta.url),
  "utf8",
);
const cratePublisher = readFileSync(
  new URL("../.github/workflows/publish-crate.yml", import.meta.url),
  "utf8",
);
const wheelBuilder = readFileSync(
  new URL("../.github/workflows/build-wheels.yml", import.meta.url),
  "utf8",
);
const tagVerifier = readFileSync(
  new URL("./verify-release-tag-commit.sh", import.meta.url),
  "utf8",
);
const agentPluginSmoke = readFileSync(
  new URL("./smoke-agent-plugin-release.mjs", import.meta.url),
  "utf8",
);
const semanticPacksManifest = readFileSync(
  new URL("../crates/bifrost-semantic-packs/Cargo.toml", import.meta.url),
  "utf8",
);
const semanticPackBuilder = readFileSync(
  new URL("./build-pinned-jvm-semantic-packs.sh", import.meta.url),
  "utf8",
);
const uvCliManifest = readFileSync(
  new URL("../packaging/bifrost-cli/pyproject.toml", import.meta.url),
  "utf8",
);
const uvCliPreparer = readFileSync(
  new URL("./prepare-uv-cli-package.mjs", import.meta.url),
  "utf8",
);

function jobBlock(workflow, job) {
  const jobStart = new RegExp(`^  ${job}:\\n`, "mu");
  const start = workflow.search(jobStart);
  assert.notEqual(start, -1, `expected ${job} job`);
  const afterStart = workflow.slice(start + workflow.slice(start).indexOf("\n") + 1);
  const nextJob = afterStart.search(/^  [a-z][a-z0-9-]*:\n/mu);
  return nextJob === -1 ? afterStart : afterStart.slice(0, nextJob);
}

function jobNeedsPromotionEvidence(job) {
  assert.match(
    jobBlock(release, job),
    /^    needs: \[[^\]]*promotion-evidence[^\]]*\]$/mu,
  );
}

test("release is the only tag and manual-dispatch entrypoint for package publication", () => {
  assert.match(release, /^  push:\n    tags:/mu);
  assert.match(release, /^  workflow_dispatch:/mu);
  for (const publisher of [cratePublisher, wheelBuilder]) {
    assert.match(publisher, /^  workflow_call:/mu);
    assert.doesNotMatch(publisher, /^  push:/mu);
    assert.doesNotMatch(publisher, /^  workflow_dispatch:/mu);
  }
});

test("uv CLI package exposes bifrost through its package name", () => {
  assert.match(uvCliManifest, /^name = "brokk-bifrost"$/mu);
  assert.match(uvCliManifest, /^dynamic = \["version"\]$/mu);
  assert.match(uvCliManifest, /^bindings = "bin"$/mu);
  assert.match(uvCliManifest, /^manifest-path = "\.\.\/\.\.\/Cargo\.toml"$/mu);
  assert.match(
    uvCliManifest,
    /^targets = \[\{ name = "bifrost", kind = "bin" \}\]$/mu,
  );
  assert.match(uvCliManifest, /^data = "wheel-data"$/mu);
  assert.match(uvCliManifest, /^license-files = \["\.generated-licenses\/\*"\]$/mu);
  for (const license of [
    "LICENSE.md",
    "GPL-3.0.md",
    "SOURCE.md",
    "SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt",
    "THIRD_PARTY_LICENSES.html",
  ]) {
    assert.ok(uvCliPreparer.includes(license));
  }
  assert.match(wheelBuilder, /node scripts\/prepare-uv-cli-package\.mjs/u);
});

test("release context captures a commit and every called workflow receives it", () => {
  assert.match(releaseContext, /^      commit:/mu);
  assert.match(releaseContext, /git rev-parse HEAD/u);
  assert.match(releaseContext, /ref: refs\/tags\/\$\{\{ inputs\.tag \}\}/u);
  assert.match(releaseContext, /refs\/tags\/\$\{RELEASE_TAG\}\^\{commit\}/u);
  assert.doesNotMatch(release, /validation_ref/u);
  assert.doesNotMatch(
    release,
    /ref: \$\{\{ needs\.release-context\.outputs\.tag \}\}/u,
  );
  for (const workflow of [cratePublisher, wheelBuilder]) {
    assert.match(workflow, /^      commit:/mu);
  }
  assert.match(release, /commit: \$\{\{ needs\.release-context\.outputs\.commit \}\}/u);
  assert.match(
    jobBlock(release, "publish-wheels"),
    /RELEASE_COMMIT: \$\{\{ needs\.release-context\.outputs\.commit \}\}/u,
  );
});

test("publish actions fail closed if the remote tag no longer selects the validated commit", () => {
  assert.match(tagVerifier, /git ls-remote --tags origin/u);
  assert.match(tagVerifier, /"\$\{tag_ref\}\*"/u);
  assert.match(tagVerifier, /refs\/tags\/\$\{release_tag\}/u);
  assert.match(tagVerifier, /test "\$actual_commit" = "\$expected_commit"/u);
  for (const workflow of [release, cratePublisher]) {
    assert.match(workflow, /git ls-remote --tags origin/u);
    assert.match(workflow, /test "\$actual_commit" = "\$RELEASE_COMMIT"/u);
  }
});

test("reusable crate publisher inputs are environment-bound before shell execution", () => {
  assert.match(cratePublisher, /RELEASE_TAG: \$\{\{ inputs\.tag \}\}/u);
  assert.match(cratePublisher, /RELEASE_VERSION: \$\{\{ inputs\.version \}\}/u);
  assert.match(cratePublisher, /RELEASE_COMMIT: \$\{\{ inputs\.commit \}\}/u);
  assert.doesNotMatch(cratePublisher, /(?:bash|echo).*\$\{\{ inputs\./u);
});

test("crate publisher verifies registry visibility with bounded inline recovery", () => {
  assert.match(
    cratePublisher,
    /EXPECTED_CHECKSUM: \$\{\{ steps\.package\.outputs\.checksum \}\}/u,
  );
  assert.match(
    cratePublisher,
    /endpoint="https:\/\/crates\.io\/api\/v1\/crates\/\$\{CRATE_PACKAGE\}\/\$\{RELEASE_VERSION\}"/u,
  );
  assert.match(cratePublisher, /max_attempts=30/u);
  assert.match(
    cratePublisher,
    /for \(\(attempt = 1; attempt <= max_attempts; attempt\+\+\)\); do/u,
  );
  assert.match(cratePublisher, /actual_checksum.*EXPECTED_CHECKSUM/su);
});

test("promotion evidence covers validation before every external publisher", () => {
  const evidence = jobBlock(release, "promotion-evidence");
  for (const prerequisite of [
    "crate-package",
    "semantic-pack-bundle",
    "build-wheels",
    "build",
    "agent-plugin-package",
    "agent-plugin-prepublish-smoke",
    "pi-package",
    "vscode-package",
  ]) {
    assert.ok(evidence.includes(`      - ${prerequisite}\n`));
  }
  for (const job of [
    "release",
    "publish-crate-core",
    "publish-crate-csharp",
    "publish-crate-go",
    "publish-crate-php",
    "publish-crate-python",
    "publish-crate-rust",
    "publish-crate-analysis",
    "publish-wheels",
    "publish-agent-plugin",
    "publish-pi-package",
    "attach-vscode",
    "publish-vscode",
    "publish-open-vsx",
  ]) {
    jobNeedsPromotionEvidence(job);
  }
  assert.match(
    jobBlock(release, "agent-plugin-release-smoke"),
    /^    needs: \[release-context, agent-plugin-package, release\]$/mu,
  );
  const semanticPacks = jobBlock(release, "semantic-pack-bundle");
  assert.match(semanticPacks, /scripts\/build-pinned-jvm-semantic-packs\.sh/u);
  assert.match(semanticPackBuilder, /scala-library-2\.13\.16-sources\.jar/u);
  assert.match(semanticPackBuilder, /OpenJDK21U-jdk_aarch64_mac_hotspot_21\.0\.8_9\.tar\.gz/u);
  assert.match(semanticPackBuilder, /bifrost-semantic-pack -- generate/u);
  assert.match(semanticPackBuilder, /bifrost-semantic-pack -- verify/u);
  assert.match(semanticPacksManifest, /^release-tooling = \[/mu);
  assert.match(semanticPacksManifest, /^name = "bifrost-semantic-pack"$/mu);
  assert.match(
    semanticPacksManifest,
    /^required-features = \["release-tooling"\]$/mu,
  );
  assert.match(semanticPackBuilder, /--retry 5 --retry-all-errors/u);
  assert.match(
    semanticPacks,
    /mv .*measurements\.json.*-measurements\.json/su,
  );
  assert.match(
    jobBlock(release, "release"),
    /dist\/bifrost-semantic-packs-\$\{\{ needs\.release-context\.outputs\.tag \}\}\.tar\.gz/u,
  );

  // Each language crate publishes straight after core; analysis waits for all
  // of them, because it names every one with an exact `=` requirement.
  for (const language of ["csharp", "go", "php", "python", "rust"]) {
    assert.match(
      jobBlock(release, `publish-crate-${language}`),
      /^    needs: \[release-context, promotion-evidence, publish-crate-core\]$/mu,
    );
  }
  assert.match(
    jobBlock(release, "publish-crate-analysis"),
    /^    needs: \[release-context, promotion-evidence, publish-crate-core, publish-crate-csharp, publish-crate-go, publish-crate-php, publish-crate-python, publish-crate-rust\]$/mu,
  );
  // Publish order mirrors the workspace dependency DAG (#1548): analysis, then
  // its direct dependents policy/nlp/semantic-packs, then runtime (which needs
  // policy), then the hosts, then the facade.
  for (const sibling of ["policy", "nlp", "semantic-packs"]) {
    assert.match(
      jobBlock(release, `publish-crate-${sibling}`),
      /^    needs: \[release-context, publish-crate-analysis\]$/mu,
    );
  }
  assert.match(
    jobBlock(release, "publish-crate-runtime"),
    /^    needs: \[release-context, publish-crate-policy\]$/mu,
  );
  assert.match(
    jobBlock(release, "publish-crate-mcp"),
    /^    needs: \[release-context, publish-crate-runtime, publish-crate-nlp\]$/mu,
  );
  assert.match(
    jobBlock(release, "publish-crate-lsp"),
    /^    needs: \[release-context, publish-crate-runtime\]$/mu,
  );
  assert.match(
    jobBlock(release, "publish-crate-facade"),
    /^    needs: \[release-context, publish-crate-mcp, publish-crate-lsp, publish-crate-semantic-packs, publish-crate-nlp\]$/mu,
  );
  assert.match(cratePublisher, /^      package:/mu);
});

test("Open VSX publisher reuses the validated VSIX and verifies exact-version reruns", () => {
  const publisher = jobBlock(release, "publish-open-vsx");
  assert.match(publisher, /^    environment: release$/mu);
  assert.match(publisher, /name: vscode-package/u);
  assert.match(
    publisher,
    /ref: \$\{\{ needs\.release-context\.outputs\.commit \}\}/u,
  );
  assert.match(publisher, /git ls-remote --tags origin/u);
  assert.match(publisher, /test "\$actual_commit" = "\$RELEASE_COMMIT"/u);
  assert.match(
    publisher,
    /metadata_url="https:\/\/open-vsx\.org\/api\/brokk\/bifrost-vscode\/\$RELEASE_VERSION"/u,
  );
  assert.match(publisher, /registry_status.*404/su);
  assert.match(
    publisher,
    /checksum_url="\$metadata_url\/file\/brokk\.bifrost-vscode-\$RELEASE_VERSION\.sha256"/u,
  );
  assert.match(publisher, /--proto '=https' --proto-redir '=https'/u);
  assert.match(publisher, /\^\[0-9a-f\]\{64\}\$/u);
  assert.match(publisher, /registry_checksum.*local_checksum/su);
  assert.match(publisher, /OVSX_PAT is not configured/u);
  assert.match(publisher, /ovsx publish "\$VSIX_PATH" --skip-duplicate/u);
  assert.match(publisher, /max_attempts=30/u);
  assert.match(
    publisher,
    /for \(\(attempt = 1; attempt <= max_attempts; attempt\+\+\)\); do/u,
  );
});

test("agent plugin release smoke follows the packaged Codex manifest and release assets stay immutable", () => {
  const releaseJob = jobBlock(release, "release");
  assert.match(releaseJob, /overwrite_files: false/u);

  assert.match(agentPluginSmoke, /\.codex-plugin", "plugin\.json"/u);
  assert.match(agentPluginSmoke, /const mcpConfigPath = path\.resolve\(pluginRoot, manifest\.mcpServers\)/u);
  assert.match(agentPluginSmoke, /const command = path\.resolve\(mcpConfigDir, server\.command\)/u);
  assert.match(agentPluginSmoke, /const cwd = path\.resolve\(mcpConfigDir, server\.cwd\)/u);
  assert.match(agentPluginSmoke, /server\.args, \["--mcp", "symbol\|extended"\]/u);
  for (const tool of ["search_symbols", "list_policies", "run_policy"]) {
    assert.ok(agentPluginSmoke.includes(`tool.name === "${tool}"`));
  }
  for (const jobName of ["agent-plugin-prepublish-smoke", "agent-plugin-release-smoke"]) {
    const smoke = jobBlock(release, jobName);
    assert.match(smoke, /BIFROST_MCP_RMCP: 'on'/u);
    assert.match(smoke, /scripts\/smoke-agent-plugin-release\.mjs/u);
  }
});

test("publishers preserve their platform, environment, and OIDC protections", () => {
  for (const target of [
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-gnu",
    "aarch64-linux-android",
    "universal-apple-darwin",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
  ]) {
    assert.ok(release.includes(`target: ${target}`));
  }
  for (const target of [
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
  ]) {
    assert.ok(wheelBuilder.includes(`target: ${target}`));
  }
  assert.match(wheelBuilder, /^  build-cli:$/mu);
  assert.match(wheelBuilder, /working-directory: packaging\/bifrost-cli/u);
  assert.match(wheelBuilder, /name: cli-wheels-\$\{\{ matrix\.target \}\}/u);
  assert.match(wheelBuilder, /pattern: cli-wheels-\*/u);
  assert.match(wheelBuilder, /cli_wheels=\(dist\/brokk_bifrost-\*\.whl\)/u);
  assert.match(jobBlock(release, "publish-wheels"), /pattern: cli-wheels-\*/u);
  assert.match(cratePublisher, /^    environment: release$/mu);
  assert.match(cratePublisher, /^      id-token: write$/mu);
  const wheelPublisher = jobBlock(release, "publish-wheels");
  assert.match(wheelPublisher, /^    environment: release$/mu);
  assert.match(wheelPublisher, /^      id-token: write$/mu);
  const vscodePublisher = jobBlock(release, "publish-vscode");
  const openVsxPublisher = jobBlock(release, "publish-open-vsx");
  assert.match(vscodePublisher, /^    environment: release$/mu);
  assert.match(openVsxPublisher, /^    environment: release$/mu);
  assert.match(cratePublisher, /crates-io-auth-action/u);
  assert.match(wheelPublisher, /gh-action-pypi-publish/u);
  assert.doesNotMatch(release, /uses: \.\/\.github\/workflows\/publish-wheels\.yml/u);
});

test("an always-run summary names targets and safe retry guidance", () => {
  const summary = jobBlock(release, "release-summary");
  assert.match(release, /^  release-summary:/mu);
  assert.match(summary, /^    if: \$\{\{ always\(\) \}\}$/mu);
  assert.match(summary, /^      - publish-open-vsx$/mu);
  assert.match(release, /Safe recovery/u);
  assert.match(release, /Re-run failed jobs/u);
  assert.match(release, /different tag, branch, or commit/u);
  for (const target of [
    "CLI archives and checksums built",
    "Crate package contents verified",
    "Pinned JVM semantic packs generated and verified",
    "Python client and uv CLI wheels built and version-verified",
    "Agent plugin prepublication smoke",
    "VS Code extension built and tested",
    "crates.io",
    "PyPI",
    "VS Code release asset attachment",
    "VS Code Marketplace",
    "Open VSX",
  ]) {
    assert.ok(release.includes(target));
  }
});
