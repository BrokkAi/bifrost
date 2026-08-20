#!/usr/bin/env node

// Vendors the shared launcher into this package so the published bundle is
// self-contained. Source of truth stays in plugins/bifrost-agent; the copies
// here must remain byte-identical (enforced by test/plugin.test.mjs and
// scripts/public/check-codex-plugin-manifest.mjs). `--check` verifies without
// writing, for prepack and CI.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const packageDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const agentPackageDir = path.resolve(packageDir, "..", "bifrost-agent");

export const SYNCED_FILES = [
  {
    source: path.join(agentPackageDir, "bin", "bifrost-launcher.mjs"),
    target: path.join(packageDir, "bin", "bifrost-launcher.mjs"),
    mode: 0o755,
  },
  {
    source: path.join(agentPackageDir, "bifrost-release.json"),
    target: path.join(packageDir, "bifrost-release.json"),
    mode: 0o644,
  },
];

const checkOnly = process.argv.includes("--check");
for (const { source, target, mode } of SYNCED_FILES) {
  const sourceBytes = fs.readFileSync(source);
  if (checkOnly) {
    const targetBytes = fs.readFileSync(target);
    if (!sourceBytes.equals(targetBytes)) {
      console.error(`${target} is out of sync with ${source}; run npm run sync-launcher`);
      process.exit(1);
    }
    continue;
  }
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, sourceBytes, { mode });
  fs.chmodSync(target, mode);
}
console.log(checkOnly ? "Launcher copies are in sync." : "Launcher copies synced.");
