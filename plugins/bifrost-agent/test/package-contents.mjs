import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fsp from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const npmExecPath = process.env.npm_execpath;
assert.ok(npmExecPath, "npm_execpath is required to run npm portably");
const packageDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(await fsp.readFile(path.join(packageDir, "package.json"), "utf8"));
const release = JSON.parse(await fsp.readFile(path.join(packageDir, "bifrost-release.json"), "utf8"));
const readme = await fsp.readFile(path.join(packageDir, "README.md"), "utf8");

const canonicalSkills = [
  "./skills/bifrost-code-navigation",
  "./skills/bifrost-code-reading",
  "./skills/bifrost-codebase-search",
];

const repoRoot = path.resolve(packageDir, "..", "..");
const licenseNotices = [
  { packaged: "LICENSE.md", source: "LICENSE.md" },
  { packaged: "GPL-3.0.md", source: "licenses/GPL-3.0.md" },
  { packaged: "SOURCE.md", source: "licenses/SOURCE.md" },
];
for (const notice of licenseNotices) {
  const packagedText = await fsp.readFile(path.join(packageDir, notice.packaged), "utf8");
  const sourceText = await fsp.readFile(path.join(repoRoot, notice.source), "utf8");
  assert.equal(
    packagedText,
    sourceText,
    `plugins/bifrost-agent/${notice.packaged} must be an exact copy of ${notice.source}`,
  );
}
assert.deepEqual(manifest.pi.extensions, ["./extensions/bifrost.ts"]);
assert.deepEqual(manifest.pi.skills, canonicalSkills);
assert.equal(manifest.dependencies["@modelcontextprotocol/sdk"], "1.29.0");
assert.equal(manifest.peerDependencies["@earendil-works/pi-coding-agent"], "*");
assert.equal(manifest.peerDependencies["@earendil-works/pi-tui"], "*");
assert.equal(manifest.peerDependencies.typebox, "*");
assert.equal(manifest.version, release.binaryVersion);
assert.ok(
  readme.includes(`pi install npm:@brokk/bifrost-agent@${manifest.version}`),
  "README npm install command must match the package version",
);

const { stdout } = await execFileAsync(
  process.execPath,
  [npmExecPath, "pack", "--dry-run", "--json"],
  { cwd: packageDir, maxBuffer: 10 * 1024 * 1024 },
);
const [{ files }] = JSON.parse(stdout);
const packed = new Set(files.map((file) => file.path));
const requiredFiles = [
  "bin/bifrost-launcher.mjs",
  "bin/bifrost-launcher.d.mts",
  "bifrost-release.json",
  "extensions/bifrost.ts",
  "extensions/bifrost-capabilities.ts",
  "extensions/bifrost-session.ts",
  "extensions/bifrost-settings-component.ts",
  "extensions/bifrost-settings.ts",
  "extensions/mcp-adapter.ts",
  "skills/bifrost-code-navigation/SKILL.md",
  "skills/bifrost-code-reading/SKILL.md",
  "skills/bifrost-codebase-search/SKILL.md",
  "LICENSE.md",
  "GPL-3.0.md",
  "SOURCE.md",
];
for (const file of requiredFiles) {
  assert.ok(packed.has(file), `npm package is missing ${file}`);
}

const exposedSkillFiles = files
  .map((file) => file.path)
  .filter((file) => file.startsWith("skills/") && file.endsWith("/SKILL.md"))
  .sort();
assert.deepEqual(exposedSkillFiles, requiredFiles.filter((file) => file.startsWith("skills/")).sort());
assert.equal(files.some((file) => file.path.startsWith("test/")), false);
assert.equal(files.some((file) => file.path.startsWith("codex-skills/")), false);

console.log(`Validated Pi manifest and ${files.length} packed files.`);
