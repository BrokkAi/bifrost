import assert from "node:assert/strict";
import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const checker = path.join(repositoryRoot, "scripts/public/check-codex-plugin-manifest.mjs");

test("accepts a public projection without the private marketplace", async () => {
  await withRepositoryFixture(async (fixtureRoot) => {
    const result = runChecker(fixtureRoot);
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  });
});

test("still validates the private marketplace when present", async () => {
  await withRepositoryFixture(async (fixtureRoot) => {
    const marketplacePath = path.join(fixtureRoot, ".agents/plugins/marketplace.json");
    await mkdir(path.dirname(marketplacePath), { recursive: true });
    await writeFile(marketplacePath, "not json\n");
    const result = runChecker(fixtureRoot);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /SyntaxError|Unexpected token/u);
  });
});

async function withRepositoryFixture(run) {
  const fixtureRoot = await mkdtemp(path.join(os.tmpdir(), "bifrost-plugin-manifest-test-"));
  try {
    for (const relativePath of [
      "Cargo.toml",
      ".claude-plugin/marketplace.json",
      ".cursor-plugin/marketplace.json",
      "editors/vscode/package.json",
      "plugins/bifrost-agent",
      "plugins/bifrost-dsh",
    ]) {
      const source = path.join(repositoryRoot, relativePath);
      const destination = path.join(fixtureRoot, relativePath);
      await mkdir(path.dirname(destination), { recursive: true });
      await cp(source, destination, { recursive: true });
    }
    await run(fixtureRoot);
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
}

function runChecker(cwd) {
  return spawnSync(process.execPath, [checker], { cwd, encoding: "utf8" });
}
