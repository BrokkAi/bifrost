import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
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
const qualifiedCratePublisher = readFileSync(
  new URL("./publish-qualified-crate.mjs", import.meta.url),
  "utf8",
);
const publishNpm = readFileSync(
  new URL("../.github/workflows/publish-npm.yml", import.meta.url),
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
const contributing = readFileSync(
  new URL("../CONTRIBUTING.md", import.meta.url),
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
const readinessPath = fileURLToPath(new URL("../.github/workflows/release-readiness.yml", import.meta.url));
const readiness = existsSync(readinessPath) ? readFileSync(readinessPath, "utf8") : null;
const postReleaseSmoke = readFileSync(
  new URL("../.github/workflows/post-release-smoke.yml", import.meta.url),
  "utf8",
);

function readinessTest(name, body) {
  test(name, { skip: readiness === null ? "release-readiness.yml is not present yet" : false }, body);
}

function jobBlock(workflow, job) {
  const jobStart = new RegExp(`^  ${job}:\\n`, "mu");
  const start = workflow.search(jobStart);
  assert.notEqual(start, -1, `expected ${job} job`);
  const afterStart = workflow.slice(start + workflow.slice(start).indexOf("\n") + 1);
  const nextJob = afterStart.search(/^  [a-z][a-z0-9-]*:\n/mu);
  return nextJob === -1 ? afterStart : afterStart.slice(0, nextJob);
}

test("release triggers stay independent from source projection", () => {
  assert.match(release, /^  push:\n    tags:/mu);
  assert.match(release, /^  workflow_dispatch:/mu);
  assert.doesNotMatch(release, /^  workflow_run:/mu);
  assert.doesNotMatch(release, /^  repository_dispatch:/mu);
  assert.doesNotMatch(release, /^    branches:/mu);
  assert.match(
    jobBlock(release, "release-context"),
    /^    if: \$\{\{ github\.repository == 'BrokkAi\/bifrost' && github\.event\.repository\.private == false \}\}$/mu,
  );
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
    "LGPL-3.0.md",
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
  for (const workflow of [cratePublisher]) {
    assert.match(workflow, /^      commit:/mu);
  }
  assert.match(release, /commit: \$\{\{ needs\.release-context\.outputs\.commit \}\}/u);
});

test("publish actions fail closed if the remote tag no longer selects the validated commit", () => {
  assert.match(tagVerifier, /git ls-remote --tags origin/u);
  assert.match(tagVerifier, /"\$\{tag_ref\}\*"/u);
  assert.match(tagVerifier, /refs\/tags\/\$\{release_tag\}/u);
  assert.match(tagVerifier, /test "\$actual_commit" = "\$expected_commit"/u);
  for (const workflow of [release]) {
    assert.match(workflow, /git ls-remote --tags origin/u);
    assert.match(workflow, /test "\$actual_commit" = "\$RELEASE_COMMIT"/u);
  }
  assert.match(release, /needs\.release-context\.outputs\.commit/u);
});

test("release selects exactly one qualified run for the tag commit and version", () => {
  assert.match(release, /^  push:\n    tags:/mu);
  assert.match(release, /^  workflow_dispatch:/mu);
  assert.match(release, /qualification_run_id/iu);
  assert.match(
    release,
    /qualification_run_id:[\s\S]{0,300}?type:\s*string/iu,
  );
  assert.match(release, /release-qualification\.mjs/iu);
  assert.match(release, /select-run/iu);
  assert.match(release, /workflow_runs/iu);
  assert.match(release, /artifacts/iu);
  assert.match(release, /head_sha/iu);
  assert.match(release, /run_attempt/iu);
  assert.match(release, /needs\.release-context\.outputs\.commit/u);
  assert.match(release, /needs\.release-context\.outputs\.version/u);

  const releaseJobNames = new Set(
    [...release.matchAll(/^  ([a-z][a-z0-9-]*):$/gmu)].map((match) => match[1]),
  );
  for (const obsoleteJob of [
    "crate-package",
    "semantic-pack-bundle",
    "build-wheels",
    "build",
    "agent-plugin-package",
    "agent-plugin-prepublish-smoke",
    "pi-package",
    "vscode-package",
    "promotion-evidence",
  ]) {
    assert.equal(releaseJobNames.has(obsoleteJob), false, `obsolete job remains: ${obsoleteJob}`);
  }
});

test("promotion downloads and verifies one immutable qualification bundle", () => {
  assert.match(release, /actions\/download-artifact@[0-9a-f]{40}/u);
  assert.match(release, /(?:run-id|run_id):\s*\$\{\{[^\n]*(?:qualification|run)/iu);
  assert.match(release, /(?:artifact-id|artifact_id)/iu);
  assert.match(release, /(?:artifact-digest|artifact_digest)/iu);
  assert.match(release, /release-qualification\.json/u);
  assert.match(release, /(?:release-qualification|verify-qualified-release)\.mjs\s+verify/iu);
  assert.match(release, /sha256sum|sha256/iu);
  assert.match(release, /manifest.*(?:digest|sha256)|(?:digest|sha256).*manifest/isu);
  assert.doesNotMatch(release, /actions\/upload-artifact@/u);
});

test("GitHub release recovery uses fail-closed curl status handling", () => {
  assert.doesNotMatch(release, /gh api[^\n]*--output/iu);
  assert.match(release, /curl[\s\S]{0,500}--write-out '%\{http_code\}'/u);
  assert.match(release, /Authorization: Bearer \$\{GH_TOKEN\}/u);
  assert.match(release, /Unexpected GitHub release lookup status/u);
});

test("promotion is byte-only and does not rebuild, package, or repack", () => {
  for (const workflow of [release, cratePublisher]) {
    for (const forbidden of [
      /^\s*(?:cargo\s+(?:build|package|publish|install)|maturin\s+(?:build|publish)|npm\s+pack|(?:npx\s+)?(?:vsce|ovsx)\s+package)\b/mu,
      /build-pinned-jvm-semantic-packs\.sh/u,
      /prepare-uv-cli-package\.mjs/u,
      /cargo package/u,
    ]) {
      assert.doesNotMatch(workflow, forbidden);
    }
  }
  assert.match(release, /(?:qualified|qualification|bundle)/iu);
  assert.match(release, /(?:sha256sum|sha256)/iu);
});

test("qualified crates use the exact crates.io archive publisher", () => {
  const combined = `${release}\n${cratePublisher}\n${qualifiedCratePublisher}`;
  assert.match(combined, /scripts\/publish-qualified-crate\.mjs/u);
  assert.match(combined, /metadata_path/u);
  assert.match(combined, /\.metadata\.json/u);
  assert.match(combined, /--expected-sha256/u);
  assert.match(combined, /\/api\/v1\/crates\/new/u);
  assert.match(combined, /Authorization|TOKEN/u);
  assert.doesNotMatch(cratePublisher, /^\s*cargo\s+(?:package|publish)\b/mu);
  assert.doesNotMatch(release, /^\s*cargo\s+(?:package|publish)\b/mu);
});

test("publisher dependency order and protected identities remain explicit", () => {
  const publisherNames = [
    ...release.matchAll(/^  ((?:publish|attach|release)(?:-[a-z0-9-]+)?):\n/gmu),
  ].map((match) => match[1]).filter((name) => !["release-context", "release-summary"].includes(name));
  assert.ok(publisherNames.length >= 3, "expected multiple promotion publishers");
  for (const name of publisherNames) {
    const publisher = jobBlock(release, name);
    assert.match(publisher, /needs:[\s\S]{0,300}(?:qualification|verify)/iu, `${name} must wait for qualification verification`);
  }
  for (const name of ["publish-wheels", "publish-vscode", "publish-open-vsx"]) {
    assert.match(jobBlock(release, name), /environment:\s*(?:release|npm-publish)/u, `${name} must retain a protected environment`);
  }
  const languageCrates = ["cpp", "csharp", "go", "js-ts", "jvm", "php", "python", "ruby", "rust"];
  for (const language of languageCrates) {
    assert.match(
      jobBlock(release, `publish-crate-${language}`),
      /^    needs: \[release-context, promote-qualification, publish-crate-core\]$/mu,
    );
  }
  assert.match(
    jobBlock(release, "publish-crate-rql"),
    /^    needs: \[release-context, promote-qualification, publish-crate-core\]$/mu,
  );
  const analysisBlock = jobBlock(release, "publish-crate-analysis");
  const analysisNeeds = analysisBlock.match(/^    needs: \[([^\]]*)\]$/mu);
  assert.ok(analysisNeeds, "analysis crate must declare a dependency list");
  const analysisDependencies = new Set(analysisNeeds[1].split(",").map((dependency) => dependency.trim()));
  for (const dependency of [
    "release-context",
    "promote-qualification",
    "publish-crate-core",
    ...languageCrates.map((language) => `publish-crate-${language}`),
    "publish-crate-rql",
  ]) {
    assert.equal(analysisDependencies.has(dependency), true, `analysis crate must wait for ${dependency}`);
  }
  for (const sibling of ["policy", "nlp", "semantic-packs"]) {
    assert.match(
      jobBlock(release, `publish-crate-${sibling}`),
      /^    needs: \[release-context, promote-qualification, publish-crate-analysis\]$/mu,
    );
  }
  assert.match(
    jobBlock(release, "publish-crate-runtime"),
    /^    needs: \[release-context, promote-qualification, publish-crate-policy\]$/mu,
  );
  assert.match(
    jobBlock(release, "publish-crate-mcp"),
    /^    needs: \[release-context, promote-qualification, publish-crate-runtime, publish-crate-nlp\]$/mu,
  );
  assert.match(
    jobBlock(release, "publish-crate-lsp"),
    /^    needs: \[release-context, promote-qualification, publish-crate-runtime\]$/mu,
  );
  assert.match(
    jobBlock(release, "publish-crate-facade"),
    /^    needs: \[release-context, promote-qualification, publish-crate-mcp, publish-crate-lsp, publish-crate-semantic-packs, publish-crate-nlp\]$/mu,
  );
  assert.match(cratePublisher, /^      id-token:\s*write$/mu);
  assert.match(cratePublisher, /crates-io-auth-action/u);
  assert.match(release, /id-token:\s*write/u);
  assert.match(release, /publish-crate-(?:analysis|runtime|facade)/u);
});

test("qualified bytes publish directly to PyPI, npm, marketplaces, and GitHub", () => {
  assert.match(release, /gh-action-pypi-publish/u);
  assert.match(release, /gh\s+workflow\s+run\s+publish-npm\.yml/u);
  assert.match(publishNpm, /npm\s+run\s+publish-release/u);
  assert.match(release, /(?:vsce|ovsx)\s+publish/u);
  assert.match(release, /(?:gh\s+release\s+upload|action-gh-release|upload-release-asset)/u);
  assert.match(release, /(?:qualified|qualification|bundle)/iu);
  for (const forbidden of [/--clobber/u, /--overwrite/u, /overwrite_files:\s*true/u]) {
    assert.doesNotMatch(release, forbidden);
  }
});

test("post-release smoke is invoked separately with the exact release tag", () => {
  assert.match(release, /post-release-smoke\.yml/u);
  assert.match(release, /(?:workflow_call|workflow_dispatch|gh\s+workflow\s+run)/u);
  assert.match(release, /post-release-smoke\.yml[\s\S]{0,300}needs\.release-context\.outputs\.tag/isu);
  assert.match(jobBlock(release, "post-release-smoke"), /^    needs: \[[^\]]*release-context/mu);
  assert.match(postReleaseSmoke, /^  workflow_dispatch:/mu);
  assert.match(postReleaseSmoke, /^  workflow_call:/mu);
  assert.match(postReleaseSmoke, /tools\/list/u);
  assert.match(postReleaseSmoke, /tools\/call/u);
});

test("agent plugin validation remains in post-release smoke and release assets are immutable", () => {
  assert.match(postReleaseSmoke, /scripts\/smoke-agent-plugin-release\.mjs/u);
  assert.match(postReleaseSmoke, /list_policies/u);
  assert.match(release, /(?:overwrite_files:\s*false|--clobber is not|refuse.*overwrite)/isu);
  assert.match(agentPluginSmoke, /path\.join\(pluginRoot, "plugin\.json"\)/u);
  assert.match(agentPluginSmoke, /path\.join\(pluginRoot, "mcp\.json"\)/u);
  assert.match(agentPluginSmoke, /const command = path\.resolve\(pluginRoot, server\.command\)/u);
  assert.match(agentPluginSmoke, /server\.args, \["--mcp", "symbol\|extended"\]/u);
  for (const tool of ["search_symbols", "list_policies", "run_policy"]) {
    assert.ok(agentPluginSmoke.includes(`tool.name === "${tool}"`));
  }
  assert.doesNotMatch(agentPluginSmoke, /policies\?\.length,\s*\d+/u);
  assert.match(agentPluginSmoke, /new Set\(policyIds\)\.size/u);
  assert.match(agentPluginSmoke, /bifrost\.correctness\.dynamic-evaluation/u);
  assert.match(contributing, /scripts\/smoke-agent-plugin-release\.mjs/u);
});

test("promotion and recovery are immutable and never write source", () => {
  assert.match(release, /^concurrency:[\s\S]{0,160}?cancel-in-progress:\s*false/mu);
  assert.match(release, /retry.*same|different checksum|never overwritten/isu);
  assert.match(release, /qualification_run_id/iu);
  for (const forbidden of [
    /^\s*git\s+(?:add|commit|push|tag)\b/mu,
    /contents:\s*write[\s\S]{0,500}?git\s+(?:add|commit|push|tag)\b/iu,
    /overwrite_files:\s*true/iu,
    /\b--(?:clobber|overwrite)\b/iu,
  ]) {
    assert.doesNotMatch(release, forbidden);
  }
});

test("publishers preserve their platform, environment, and OIDC protections", () => {
  assert.match(cratePublisher, /^    environment: release$/mu);
  assert.match(cratePublisher, /^      id-token: write$/mu);
  assert.match(cratePublisher, /crates-io-auth-action/u);
  assert.match(release, /gh-action-pypi-publish/u);
  assert.match(release, /id-token:\s*write/u);
  assert.match(release, /environment:\s*release/u);

  const npmDispatch = jobBlock(release, "publish-npm");
  assert.match(npmDispatch, /^      actions:\s*write$/mu);
  assert.doesNotMatch(npmDispatch, /^    environment:/mu);
  assert.doesNotMatch(npmDispatch, /^      id-token:\s*write$/mu);
  assert.match(publishNpm, /^    environment:\s*npm-publish$/mu);
  assert.match(publishNpm, /^      id-token:\s*write$/mu);
  assert.match(publishNpm, /^          node-version:\s*24$/mu);
  assert.doesNotMatch(
    publishNpm,
    /^          registry-url:/mu,
    "trusted npm publishing must not create a classic token entry in .npmrc",
  );
  assert.match(publishNpm, /npm install --global npm@11\.19\.0/u);
  assert.match(publishNpm, /NODE_AUTH_TOKEN:\s*""/u);
  assert.match(publishNpm, /NPM_CONFIG_PROVENANCE:\s*"true"/u);
  assert.match(publishNpm, /verify-qualified-release\.mjs\s+verify/u);
  assert.match(publishNpm, /--manifest-sha256/u);
  assert.match(publishNpm, /actions\/download-artifact@[0-9a-f]{40}/u);
  assert.match(publishNpm, /--dist "\$RUNNER_TEMP\/npm-qualified"/u);
  assert.doesNotMatch(publishNpm, /^\s*npm\s+pack\b/mu);
});

test("npm dispatch is deterministically correlated with its child run", () => {
  const npmDispatch = jobBlock(release, "publish-npm");
  assert.match(
    npmDispatch,
    /^      DISPATCH_NONCE: \$\{\{ github\.run_id \}\}-\$\{\{ github\.run_attempt \}\}$/mu,
  );
  assert.match(
    npmDispatch,
    /gh workflow run publish-npm\.yml[\s\\]+--repo "\$GITHUB_REPOSITORY"/u,
    "the dispatch job has no checkout, so gh must target the release repository explicitly",
  );
  assert.doesNotMatch(npmDispatch, /actions\/checkout/u);
  assert.match(npmDispatch, /--field dispatch_nonce="\$DISPATCH_NONCE"/u);
  assert.match(npmDispatch, /expected_title="Publish npm \$\{RELEASE_TAG\} \[\$\{DISPATCH_NONCE\}\]"/u);
  assert.match(npmDispatch, /gh run list[\s\S]{0,300}--workflow publish-npm\.yml/isu);
  assert.match(npmDispatch, /\.displayTitle == \$title/u);
  assert.match(
    publishNpm,
    /^run-name: Publish npm \$\{\{ inputs\.release_tag \}\} \[\$\{\{ inputs\.dispatch_nonce \}\}\]$/mu,
  );
  assert.match(publishNpm, /dispatch_nonce:/u);
});

test("an always-run summary names targets and safe retry guidance", () => {
  const summary = jobBlock(release, "release-summary");
  assert.match(release, /^  release-summary:/mu);
  assert.match(summary, /^    if: \$\{\{ always\(\) \}\}$/mu);
  assert.match(summary, /qualification/iu);
  assert.match(summary, /crates\.io|PyPI|npm|Marketplace|Open VSX/iu);
  assert.match(summary, /retry.*same|different checksum|qualification/isu);
  for (const target of [
    "crates.io",
    "PyPI",
    "GitHub",
    "Visual Studio Marketplace",
    "Open VSX",
  ]) {
    assert.ok(release.includes(target));
  }
});

readinessTest("release readiness is manually dispatched for an exact public commit", () => {
  assert.match(readiness, /^  workflow_dispatch:\n/mu);
  assert.match(readiness, /public[_-]commit:/iu);
  assert.match(readiness, /public[_-]commit:[\s\S]{0,500}?required:\s*true[\s\S]{0,500}?type:\s*string/iu);
  assert.match(
    readiness,
    /if:\s*\$\{\{[^\n]*github\.repository\s*==\s*['"]BrokkAi\/bifrost['"][^\n]*github\.event\.repository\.private\s*==\s*false/iu,
  );
});

readinessTest("release readiness is read-only and contains no publishing boundary", () => {
  assert.match(readiness, /^\s+contents:\s*read\s*$/mu);
  assert.match(readiness, /^\s+actions:\s*read\s*$/mu);
  for (const forbidden of [
    /^\s+(?:contents|packages):\s*write\s*$/mu,
    /\bsecrets\./iu,
    /^\s*environment:\s*(?:release|npm-publish)\s*$/mu,
    /\bgit\s+tag\b/iu,
    /\bgh\s+release\b/iu,
    /\bgit\s+push\b/iu,
    /\bnpm\s+publish\b/iu,
    /\bcargo\s+publish\b/iu,
    /\bmaturin\s+publish\b/iu,
    /\btwine\s+upload\b/iu,
    /\b(?:vsce|ovsx)\s+publish\b/iu,
    /pypa\/gh-action-pypi-publish/iu,
  ]) {
    assert.doesNotMatch(readiness, forbidden);
  }
});

readinessTest("release readiness caps matrix concurrency", () => {
  const caps = [...readiness.matchAll(/^\s+max-parallel:\s*(\d+)\s*$/gmu)].map((match) => Number(match[1]));
  assert.ok(caps.length > 0, "expected at least one bounded matrix");
  assert.ok(caps.every((cap) => cap >= 1 && cap <= 4), `unexpected max-parallel caps: ${caps.join(", ")}`);
});

readinessTest("release readiness uses bash for the portable binary build", () => {
  const build = jobBlock(readiness, "build");
  const binaryBuild = build.match(
    /^      - name: Build binary\n[\s\S]*?(?=^      - name: Build macOS universal binary)/mu,
  )?.[0];
  assert.ok(binaryBuild, "expected the cross-platform binary build step");
  assert.match(binaryBuild, /^        shell: bash$/mu);
  assert.match(binaryBuild, /run: cargo build --release --locked --bin "\$BIN_NAME"/u);
});

readinessTest("npm release packaging resolves assets from the workspace root", () => {
  const npmPackage = jobBlock(readiness, "npm-package");
  assert.match(npmPackage, /--assets "\$\{\{ github\.workspace \}\}\/release-assets"/u);
});

readinessTest("release readiness creates and verifies a retained commit/version qualification bundle", () => {
  assert.match(readiness, /upload-artifact@/u);
  assert.match(readiness, /release-qualification/iu);
  assert.match(readiness, /release-qualification\.json/u);
  assert.match(readiness, /node\s+scripts\/release-qualification\.mjs\s+manifest/iu);
  assert.match(readiness, /node\s+scripts\/release-qualification\.mjs\s+verify/iu);

  const retentionDays = [...readiness.matchAll(/retention-days:\s*(\d+)/gmu)].map((match) => Number(match[1]));
  assert.ok(retentionDays.length > 0, "expected qualification artifact retention");
  assert.ok(retentionDays.every((days) => days >= 14), `retention must be at least 14 days: ${retentionDays}`);

  const qualificationName = readiness.match(/^\s*name:\s*[^\n]*qualification[^\n]*$/imu)?.[0] ?? "";
  assert.match(qualificationName, /(?:commit|sha)/iu);
  assert.match(qualificationName, /version/iu);
});

readinessTest("release readiness records Codex and Claude list_policies prepublish smoke evidence", () => {
  const lines = readiness.toLowerCase().split(/\r?\n/u);
  assert.ok(lines.some((line) => line.includes("prepublish")), "expected prepublish smoke job");
  assert.ok(lines.some((line) => line.includes("smoke")), "expected smoke evidence");
  for (const adapter of ["codex", "claude"]) {
    const nearby = lines.some((line, index) => {
      if (!line.includes(adapter)) {
        return false;
      }
      return lines.slice(Math.max(0, index - 40), index + 41).some((candidate) => candidate.includes("list_policies"));
    });
    assert.ok(nearby, `expected ${adapter} MCP list_policies smoke evidence`);
  }
});
