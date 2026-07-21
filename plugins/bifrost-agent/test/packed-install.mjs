import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const npmExecPath = process.env.npm_execpath;
assert.ok(npmExecPath, "npm_execpath is required to run npm portably");
const packageDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = path.resolve(packageDir, "..", "..");

const canonicalSkillNames = ["bifrost-code-navigation", "bifrost-code-reading", "bifrost-codebase-search"];
const sourceManifest = JSON.parse(await fsp.readFile(path.join(packageDir, "package.json"), "utf8"));
const piPeerPackages = [
  "@earendil-works/pi-coding-agent",
  "@earendil-works/pi-tui",
  "typebox",
].map((name) => `${name}@${sourceManifest.devDependencies[name]}`);

const tmpRoot = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-agent-packed-install-"));
let cleanedUp = false;
async function cleanup() {
  if (cleanedUp) {
    return;
  }
  cleanedUp = true;
  await fsp.rm(tmpRoot, { recursive: true, force: true });
}
const cleanupOnSignal = (signal) => {
  cleanup().finally(() => process.exit(128 + signal));
};
process.once("SIGINT", () => cleanupOnSignal(2));
process.once("SIGTERM", () => cleanupOnSignal(15));

try {
  const packDir = path.join(tmpRoot, "pack");
  await fsp.mkdir(packDir);
  const { stdout: packStdout } = await execFileAsync(
    process.execPath,
    [npmExecPath, "pack", "--json", "--pack-destination", packDir],
    { cwd: packageDir, maxBuffer: 10 * 1024 * 1024 },
  );
  const [{ filename: tarballName }] = JSON.parse(packStdout);
  const tarballPath = path.join(packDir, tarballName);
  assert.ok(fs.existsSync(tarballPath), `npm pack did not produce ${tarballName}`);

  const consumerDir = path.join(tmpRoot, "consumer");
  await fsp.mkdir(consumerDir);
  await fsp.writeFile(
    path.join(consumerDir, "package.json"),
    `${JSON.stringify({ name: "bifrost-agent-packed-install-smoke", version: "0.0.0", private: true }, null, 2)}\n`,
  );

  await execFileAsync(
    process.execPath,
    [
      npmExecPath,
      "install",
      "--no-save",
      "--no-audit",
      "--no-fund",
      "--ignore-scripts",
      "--prefer-offline",
      tarballPath,
      ...piPeerPackages,
    ],
    { cwd: consumerDir, maxBuffer: 10 * 1024 * 1024 },
  );

  const installedPackageDir = path.join(consumerDir, "node_modules", "@brokk", "bifrost-agent");
  assert.ok(fs.existsSync(installedPackageDir), "installed tarball is missing @brokk/bifrost-agent in node_modules");

  const installedManifest = JSON.parse(
    await fsp.readFile(path.join(installedPackageDir, "package.json"), "utf8"),
  );

  const installedLicenseNotices = [
    { packaged: "LICENSE.md", source: "LICENSE.md" },
    { packaged: "GPL-3.0.md", source: "licenses/GPL-3.0.md" },
    { packaged: "SOURCE.md", source: "licenses/SOURCE.md" },
  ];
  for (const notice of installedLicenseNotices) {
    const installedText = await fsp.readFile(path.join(installedPackageDir, notice.packaged), "utf8");
    const sourceText = await fsp.readFile(path.join(repoRoot, notice.source), "utf8");
    assert.equal(
      installedText,
      sourceText,
      `installed ${notice.packaged} must be an exact copy of ${notice.source}`,
    );
  }

  const probePath = path.join(consumerDir, "pi-discovery-probe.mjs");
  await fsp.writeFile(probePath, probeScript());

  const { stdout: probeStdout } = await execFileAsync(process.execPath, [probePath], {
    cwd: consumerDir,
    maxBuffer: 10 * 1024 * 1024,
  });
  const probeResult = JSON.parse(probeStdout);

  assert.deepEqual(
    probeResult.extensionErrors,
    [],
    `Pi's extension loader reported errors loading the installed package: ${JSON.stringify(probeResult.extensionErrors)}`,
  );
  assert.equal(
    probeResult.extensionCount,
    1,
    `expected the installed tarball to load exactly one extension, got ${probeResult.extensionCount}`,
  );
  assert.deepEqual(
    probeResult.skillDiagnostics,
    [],
    `Pi's skill loader reported diagnostics for the installed package: ${JSON.stringify(probeResult.skillDiagnostics)}`,
  );
  assert.deepEqual(
    probeResult.skillNames,
    canonicalSkillNames,
    "installed tarball must load exactly the three canonical Bifrost skills",
  );
  assert.equal(installedManifest.pi.skills.length, canonicalSkillNames.length);

  console.log(
    `Installed ${tarballName} into a clean package and verified Pi's extension and skill loaders discover 1 extension and ${canonicalSkillNames.length} skills without starting Bifrost.`,
  );
} finally {
  await cleanup();
}

function probeScript() {
  return `import { discoverAndLoadExtensions, loadSkills } from "@earendil-works/pi-coding-agent";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const consumerDir = path.dirname(fileURLToPath(import.meta.url));
const pkgDir = path.join(consumerDir, "node_modules", "@brokk", "bifrost-agent");
const manifest = JSON.parse(fs.readFileSync(path.join(pkgDir, "package.json"), "utf8"));

const tmpCwd = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-agent-probe-cwd-"));
const tmpAgentDir = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-agent-probe-agent-"));

try {
  const extensionsResult = await discoverAndLoadExtensions([pkgDir], tmpCwd, tmpAgentDir);
  const skillPaths = manifest.pi.skills.map((relativePath) => path.resolve(pkgDir, relativePath));
  const skillsResult = loadSkills({ cwd: tmpCwd, agentDir: tmpAgentDir, skillPaths, includeDefaults: false });

  process.stdout.write(JSON.stringify({
    extensionErrors: extensionsResult.errors.map((entry) => ({
      path: entry.path,
      message: String(entry.error?.message ?? entry.error),
    })),
    extensionCount: extensionsResult.extensions.length,
    skillDiagnostics: skillsResult.diagnostics,
    skillNames: skillsResult.skills.map((skill) => skill.name).sort(),
  }));
} finally {
  fs.rmSync(tmpCwd, { recursive: true, force: true });
  fs.rmSync(tmpAgentDir, { recursive: true, force: true });
}
`;
}
