#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const MIGRATIONS_DIRECTORY = "crates/bifrost-core/migrations/cache/";
const MIGRATION_FILE = /^(\d+)-.+\.sql$/;
const ZERO_SHA = /^0+$/;

function git(cwd, args) {
  const result = spawnSync("git", args, { cwd, encoding: "utf8" });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || `git ${args.join(" ")} failed`);
  }
  return result.stdout;
}

function migrationVersion(path) {
  const filename = path.slice(path.lastIndexOf("/") + 1);
  const match = MIGRATION_FILE.exec(filename);
  return match ? Number(match[1]) : null;
}

export function checkMigrationLandingOrder({ base, head, cwd = process.cwd() }) {
  if (ZERO_SHA.test(base)) {
    return { skipped: true, baseHighest: null, added: [], problems: [] };
  }

  const baseFiles = git(cwd, ["ls-tree", "-r", "--name-only", base, "--", MIGRATIONS_DIRECTORY])
    .trimEnd()
    .split("\n")
    .filter(Boolean);
  const baseVersions = baseFiles.map(migrationVersion).filter((version) => version !== null);
  const baseHighest = baseVersions.length > 0 ? Math.max(...baseVersions) : null;

  const added = git(cwd, [
    "diff",
    "--no-renames",
    "--name-only",
    "--diff-filter=A",
    base,
    head,
    "--",
    MIGRATIONS_DIRECTORY,
  ])
    .trimEnd()
    .split("\n")
    .filter(Boolean)
    .map((file) => ({ file, version: migrationVersion(file) }))
    .filter(({ version }) => version !== null);

  const problems = [];
  for (const migration of added) {
    if (baseHighest !== null && migration.version <= baseHighest) {
      problems.push({
        kind: "below-base",
        ...migration,
        baseHighest,
      });
    }
  }

  const byVersion = new Map();
  for (const migration of added) {
    const files = byVersion.get(migration.version) ?? [];
    files.push(migration.file);
    byVersion.set(migration.version, files);
  }
  for (const [version, files] of byVersion) {
    if (files.length > 1) problems.push({ kind: "duplicate", version, files, baseHighest });
  }

  return { skipped: false, baseHighest, added, problems };
}

function usage() {
  return "Usage: check-migration-landing-order.mjs --base <rev> --head <rev>";
}

function argumentsFrom(argv) {
  const parsed = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if ((key !== "--base" && key !== "--head") || !value || parsed[key]) {
      throw new Error(usage());
    }
    parsed[key] = value;
  }
  if (!parsed["--base"] || !parsed["--head"]) throw new Error(usage());
  return { base: parsed["--base"], head: parsed["--head"] };
}

function main() {
  let args;
  try {
    args = argumentsFrom(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 2;
    return;
  }

  let result;
  try {
    result = checkMigrationLandingOrder(args);
  } catch (error) {
    process.stderr.write(`Migration landing-order check failed: ${error.message}\n`);
    process.exitCode = 2;
    return;
  }

  if (result.skipped) {
    process.stdout.write("Skipping migration landing-order check for the first push (no base commit).\n");
    return;
  }
  if (result.problems.length === 0) {
    process.stdout.write(
      `Migration landing-order check passed: ${result.added.length} added migration(s); base highest is ${result.baseHighest ?? "none"}.\n`,
    );
    return;
  }

  for (const problem of result.problems) {
    if (problem.kind === "below-base") {
      process.stderr.write(
        `${problem.file}: version ${problem.version} is not above base highest ${problem.baseHighest}.\n`,
      );
    } else {
      process.stderr.write(
        `Added migrations ${problem.files.join(", ")} share version ${problem.version} (base highest ${problem.baseHighest ?? "none"}).\n`,
      );
    }
  }
  process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
