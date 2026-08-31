import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const workflow = readFileSync(
  new URL("../../.github/workflows/post-release-smoke.yml", import.meta.url),
  "utf8",
);

const CRATE_PACKAGES = [
  "brokk-bifrost-core",
  "brokk-bifrost-go",
  "brokk-bifrost-cpp",
  "brokk-bifrost-js-ts",
  "brokk-bifrost-jvm",
  "brokk-bifrost-csharp",
  "brokk-bifrost-php",
  "brokk-bifrost-python",
  "brokk-bifrost-ruby",
  "brokk-bifrost-rust",
  "brokk-bifrost-analysis",
  "brokk-bifrost-flow",
  "brokk-bifrost-rql",
  "brokk-bifrost-policy",
  "brokk-bifrost-runtime",
  "brokk-bifrost-semantic-packs",
  "brokk-bifrost-mcp",
  "brokk-bifrost-lsp",
  "brokk-bifrost",
];

const NPM_PACKAGES = [
  "@brokkai/bifrost",
  "@brokkai/bifrost-darwin-universal",
  "@brokkai/bifrost-linux-x64-gnu",
  "@brokkai/bifrost-linux-arm64-gnu",
  "@brokkai/bifrost-android-arm64",
  "@brokkai/bifrost-win32-x64",
  "@brokkai/bifrost-win32-arm64",
];

test("is manually resumable and reusable after promotion with an exact tag", () => {
  assert.match(
    workflow,
    /^  workflow_dispatch:\n    inputs:\n      tag:\n        description:.*\n        required: true\n        type: string$/mu,
  );
  assert.match(
    workflow,
    /^  workflow_call:\n    inputs:\n      tag:\n        description:.*\n        required: true\n        type: string$/mu,
  );
  assert.doesNotMatch(workflow, /^  workflow_run:/mu);
  assert.ok(workflow.includes("RELEASE_TAG: ${{ inputs.tag }}"));
  assert.ok(workflow.includes("ref: ${{ inputs.tag }}"));
  assert.ok(
    workflow.includes(
      'node scripts/public/release-version.mjs check --tag "$RELEASE_TAG" --github-output "$GITHUB_OUTPUT"',
    ),
  );
  assert.doesNotMatch(workflow, /RELEASE_TAG.*=~/u);
  const checkout = workflow.indexOf("uses: actions/checkout@");
  const validator = workflow.indexOf("node scripts/public/release-version.mjs check");
  assert.ok(checkout >= 0 && checkout < validator, "validator must run after exact-tag checkout");
});

test("guards public read-only execution and contains no publication boundary", () => {
  assert.match(
    workflow,
    /github\.repository == 'BrokkAi\/bifrost' && github\.event\.repository\.private == false/u,
  );
  assert.match(workflow, /^permissions:\n  contents: read$/mu);
  for (const forbidden of [
    "contents: write",
    "packages: write",
    "id-token:",
    "secrets.",
    "environment: release",
    "actions/upload-artifact@",
    "actions/upload-release-asset@",
    "softprops/action-gh-release@",
    "gh release upload",
    "overwrite_files",
    "--overwrite",
    "npm publish",
    "cargo publish",
    "pypa/gh-action-pypi-publish",
    "vsce publish",
    "ovsx publish",
    "git push",
  ]) {
    assert.equal(workflow.includes(forbidden), false, `unexpected mutation: ${forbidden}`);
  }
});

test("pins every external action to one full lowercase commit", () => {
  const actionLines = workflow
    .split(/\r?\n/u)
    .filter((line) => /\buses:\s*/u.test(line));
  assert.ok(actionLines.length > 0);
  for (const line of actionLines) {
    assert.match(
      line,
      /\buses:\s*(?!\.\/)[^\s@]+@[0-9a-f]{40}\s+#\s*\S+$/u,
      `unpinned action: ${line}`,
    );
  }
});

test("checks every GitHub asset and published SHA-256 sidecar", () => {
  assert.match(
    workflow,
    /api\.github\.com\/repos\/BrokkAi\/bifrost\/releases\/tags\/\$\{RELEASE_TAG\}/u,
  );
  assert.match(workflow, /\.tag_name == \$tag and \.draft == false/u);
  assert.match(workflow, /bifrost-agent-\$\{RELEASE_TAG\}\.tar\.gz/u);
  assert.match(workflow, /brokk-bifrost-agent-\$\{RELEASE_VERSION\}\.tgz/u);
  assert.match(workflow, /bifrost-vscode-\$\{RELEASE_TAG\}\.vsix/u);
  const requiredStart = workflow.indexOf("          for required in");
  const requiredEnd = workflow.indexOf("\n          done", requiredStart);
  assert.ok(requiredStart >= 0 && requiredEnd > requiredStart, "required asset loop must be present");
  const requiredAssets = workflow.slice(requiredStart, requiredEnd);
  for (const asset of [
    "bifrost-semantic-packs-${RELEASE_TAG}.tar.gz",
    "bifrost-semantic-packs-${RELEASE_TAG}.tar.gz.sha256",
  ]) {
    assert.ok(requiredAssets.includes(asset), `missing required semantic-pack asset ${asset}`);
  }
  assert.ok(workflow.includes('.digest // ""'));
  assert.match(workflow, /\^sha256:\[0-9a-f\]\{64\}\$/u);
  assert.ok(workflow.includes('expected="${digest#sha256:}"'));
  assert.match(workflow, /has no public SHA-256 digest/u);
  assert.match(workflow, /has SHA-256 \$actual, expected \$expected/u);
  assert.match(workflow, /tar -xOf .*bifrost-agent-\$\{RELEASE_TAG\}\.tar\.gz/u);
  assert.ok(workflow.includes('.name == "@brokk/bifrost-agent" and .version == $version'));
  assert.ok(
    workflow.includes(
      'tar -xOf "$asset_dir/brokk-bifrost-agent-${RELEASE_VERSION}.tgz" package/package.json |\n' +
        '            jq -e --arg version "$RELEASE_VERSION" \'.name == "@brokk/bifrost-agent" and .version == $version\' >/dev/null',
    ),
  );
  assert.match(workflow, /unzip -p .*bifrost-vscode-\$\{RELEASE_TAG\}\.vsix/u);
  assert.match(workflow, /sha256sum -c/u);
  assert.match(workflow, /checksums=\("\$asset_dir"\/\*\.sha256\)/u);
  const checksumStart = workflow.indexOf('checksums=("$asset_dir"/*.sha256)');
  assert.match(workflow.slice(checksumStart), /sha256sum -c/u, "downloaded checksum sidecars must be checked");
  assert.match(
    workflow,
    /raw\.githubusercontent\.com\/BrokkAi\/bifrost\/master\/plugins\/bifrost-agent\/bifrost-release\.json/u,
  );
  assert.match(workflow, /Public master plugin metadata matches/u);
  assert.match(workflow, /\.archiveSha256\[\$target\]/u);
  assert.match(workflow, /source_metadata.*binaryVersion.*minimumBinaryVersion/su);
});

test("source metadata check rebinds the downloaded asset directory in its own step", () => {
  const start = workflow.indexOf("      - name: Check public marketplace source metadata against release sidecars");
  const end = workflow.indexOf("\n\n  crates-io:", start);
  assert.ok(start >= 0 && end > start, "source metadata check step must be present");
  const step = workflow.slice(start, end);
  assert.match(step, /^          asset_dir="\$RUNNER_TEMP\/release-assets"$/mu);
});

test("checks all crates.io packages with bounded propagation retries", () => {
  for (const packageName of CRATE_PACKAGES) {
    assert.ok(
      workflow.includes(`        ${packageName}\n`),
      `missing crate package ${packageName}`,
    );
  }
  assert.match(
    workflow,
    /crates\.io\/api\/v1\/crates\/\$\{crate\}\/\$\{RELEASE_VERSION\}/u,
  );
  assert.match(workflow, /for attempt in \$\(seq 1 30\)/u);
  assert.match(workflow, /\.version\.num == \$version/u);
  assert.match(workflow, /\.version\.checksum.*\^\[0-9a-f\]\{64\}\$/su);
});

test("checks PyPI and npm versions, archives, and integrity evidence", () => {
  assert.match(
    workflow,
    /pypi\.org\/pypi\/brokk-bifrost\/\$\{RELEASE_VERSION\}\/json/u,
  );
  assert.match(workflow, /\.info\.version == \$version/u);
  assert.match(workflow, /all\(\.urls\[\];.*\.digests\.sha256.*\^\[0-9a-f\]\{64\}\$/su);
  assert.doesNotMatch(workflow, /all\(\.\[\];.*\.digests\.sha256/u);
  assert.match(workflow, /registry\.npmjs\.org\/\$\{encoded\}/u);
  assert.match(workflow, /\.versions\[\$version\]\.version == \$version/u);
  assert.match(workflow, /\.dist\.tarball.*startswith\("https:\/\/"\)/su);
  assert.match(workflow, /\.dist\.integrity.*startswith\("sha512-"\)/su);
  assert.match(workflow, /Waiting for npm visibility/u);
  for (const packageName of NPM_PACKAGES) {
    assert.ok(workflow.includes(`        ${packageName}\n`), `missing npm package ${packageName}`);
  }
  assert.equal(workflow.includes("        @brokk/bifrost-agent\n"), false);
});

test("selects and checks the published root binary on supported runner platforms", () => {
  const installStart = workflow.indexOf("\n  install-smoke:\n");
  const extensionStart = workflow.indexOf("\n  extensions:\n", installStart);
  const installJob = workflow.slice(installStart, extensionStart);
  assert.equal((installJob.match(/^    needs: resolve$/gmu) ?? []).length, 1);
  assert.match(
    workflow,
    /matrix:\n        os: \[ubuntu-latest, macos-latest, windows-latest\]/u,
  );
  assert.match(workflow, /max-parallel: 2/u);
  assert.ok(
    workflow.includes('--registry https://registry.npmjs.org "@brokkai/bifrost@${RELEASE_VERSION}"'),
  );
  assert.match(workflow, /npm exec --prefix .* bifrost --version/u);
  assert.ok(workflow.includes('grep -F "$RELEASE_VERSION"'));
});

test("checks both extension marketplaces and states the Marketplace checksum boundary", () => {
  assert.match(workflow, /marketplace\.visualstudio\.com\/_apis\/public\/gallery\/extensionquery/u);
  assert.match(workflow, /brokk\/vsextensions\/bifrost-vscode\/\$\{RELEASE_VERSION\}\/vspackage/u);
  assert.match(workflow, /Marketplace public API exposes no checksum endpoint/u);
  assert.match(workflow, /open-vsx\.org\/api\/brokk\/bifrost-vscode\/\$\{RELEASE_VERSION\}/u);
  assert.match(workflow, /checksum_url=.*\.sha256/u);
  assert.ok(workflow.includes('test "$expected" = "$actual"'));
  assert.match(workflow, /unzip -tq/u);
  assert.match(workflow, /archive_found=0/u);
  assert.match(workflow, /Waiting for a valid Visual Studio Marketplace archive \(\$attempt\/30\)/u);
  assert.match(workflow, /Accept: application\/octet-stream/u);
  assert.match(workflow, /--compressed/u);
});

test("invokes published Codex and Claude MCP list_policies smoke checks", () => {
  assert.match(workflow, /scripts\/public\/smoke-agent-plugin-release\.mjs/u);
  assert.match(workflow, /mcp\.json/u);
  assert.match(workflow, /claude-mcp\.json/u);
  assert.match(workflow, /tools\/list/u);
  assert.match(workflow, /tools\/call/u);
  assert.ok(workflow.includes('name: "list_policies"'));
  assert.match(workflow, /Claude MCP list_policies passed/u);
});
