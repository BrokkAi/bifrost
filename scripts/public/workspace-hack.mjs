#!/usr/bin/env node

// Keep hakari's generated features and cargo-machete's exemptions together.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const check = process.argv.includes("--check");
assert.ok(process.argv.slice(2).every(arg => arg === "--check"), "usage: workspace-hack.mjs [--check]");
const cargo = args => execFileSync("cargo", args, { cwd: root, stdio: "inherit" });
cargo(["hakari", "generate", ...(check ? ["--diff"] : [])]);
cargo(["hakari", "manage-deps", check ? "--dry-run" : "--yes"]);
const metadata = JSON.parse(execFileSync("cargo", ["metadata", "--no-deps", "--format-version", "1"], {
  cwd: root, encoding: "utf8", maxBuffer: 8 * 1024 * 1024,
}));
const hack = metadata.packages.find(pkg => pkg.name === "workspace-hack");
assert.ok(hack, "workspace-hack must be a workspace member");
const ignored = [...new Set(hack.dependencies.map(dep => dep.rename ?? dep.name))].sort();
const manifest = path.join(root, "crates", "workspace-hack", "Cargo.toml");
const text = fs.readFileSync(manifest, "utf8");
const marker = "# Generated cargo-machete exemptions; run node scripts/public/workspace-hack.mjs.\n";
const original = text.split(marker)[0].trimEnd();
const updated = `${original}\n\n${marker}[package.metadata.cargo-machete]\nignored = ${JSON.stringify(ignored)}\n`;
if (check) {
  assert.equal(text, updated, "workspace-hack cargo-machete metadata is stale; run node scripts/public/workspace-hack.mjs");
} else {
  fs.writeFileSync(manifest, updated);
}
