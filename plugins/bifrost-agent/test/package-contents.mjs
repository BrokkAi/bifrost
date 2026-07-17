import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fsp from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const packageDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(await fsp.readFile(path.join(packageDir, "package.json"), "utf8"));
const release = JSON.parse(await fsp.readFile(path.join(packageDir, "bifrost-release.json"), "utf8"));

const canonicalSkills = [
  "./skills/bifrost-code-navigation",
  "./skills/bifrost-code-reading",
  "./skills/bifrost-codebase-search",
];
assert.deepEqual(manifest.pi.extensions, ["./extensions/bifrost.ts"]);
assert.deepEqual(manifest.pi.skills, canonicalSkills);
assert.equal(manifest.dependencies["@modelcontextprotocol/sdk"], "1.29.0");
assert.equal(manifest.peerDependencies["@earendil-works/pi-coding-agent"], "*");
assert.equal(manifest.peerDependencies["@earendil-works/pi-tui"], "*");
assert.equal(manifest.peerDependencies.typebox, "*");
assert.equal(manifest.version, release.binaryVersion);

const { stdout } = await execFileAsync("npm", ["pack", "--dry-run", "--json"], {
  cwd: packageDir,
  maxBuffer: 10 * 1024 * 1024,
});
const [{ files }] = JSON.parse(stdout);
const packed = new Set(files.map((file) => file.path));
const requiredFiles = [
  "bin/bifrost-launcher.mjs",
  "bin/bifrost-launcher.d.mts",
  "bifrost-release.json",
  "extensions/bifrost.ts",
  "extensions/bifrost-capabilities.ts",
  "extensions/bifrost-session.ts",
  "extensions/bifrost-settings.ts",
  "extensions/mcp-adapter.ts",
  "skills/bifrost-code-navigation/SKILL.md",
  "skills/bifrost-code-reading/SKILL.md",
  "skills/bifrost-codebase-search/SKILL.md",
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
