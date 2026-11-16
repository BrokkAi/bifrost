import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { checkMigrationLandingOrder } from "./check-migration-landing-order.mjs";

const MIGRATIONS = "crates/bifrost-core/migrations/cache";

function git(directory, ...args) {
  const result = spawnSync("git", args, { cwd: directory, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function repository(t) {
  const directory = mkdtempSync(join(tmpdir(), "migration-landing-order-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  git(directory, "init", "-q");
  git(directory, "config", "user.name", "Migration test");
  git(directory, "config", "user.email", "migration-test@example.invalid");
  mkdirSync(join(directory, MIGRATIONS), { recursive: true });
  writeFileSync(join(directory, MIGRATIONS, "0361-base.sql"), "SELECT 1;\n");
  git(directory, "add", ".");
  git(directory, "commit", "-qm", "base");
  const base = git(directory, "rev-parse", "HEAD");
  return {
    directory,
    base,
    add(files) {
      for (const [name, content] of Object.entries(files)) {
        writeFileSync(join(directory, MIGRATIONS, name), content);
      }
      git(directory, "add", "-A");
      git(directory, "commit", "-qm", "change");
      return git(directory, "rev-parse", "HEAD");
    },
  };
}

test("rejects an added migration below the base highest and reports both versions", (t) => {
  const repo = repository(t);
  const head = repo.add({ "0360-too-low.sql": "SELECT 2;\n" });
  const result = checkMigrationLandingOrder({ base: repo.base, head, cwd: repo.directory });
  assert.deepEqual(result.problems, [
    {
      kind: "below-base",
      file: `${MIGRATIONS}/0360-too-low.sql`,
      version: 360,
      baseHighest: 361,
    },
  ]);
});

test("accepts an added migration above the base highest", (t) => {
  const repo = repository(t);
  const head = repo.add({ "0362-next.sql": "SELECT 2;\n" });
  const result = checkMigrationLandingOrder({ base: repo.base, head, cwd: repo.directory });
  assert.deepEqual(result.problems, []);
  assert.equal(result.added[0].version, 362);
});

test("rejects two added migrations that share a version", (t) => {
  const repo = repository(t);
  const head = repo.add({
    "0362-one.sql": "SELECT 2;\n",
    "0362-two.sql": "SELECT 3;\n",
  });
  const result = checkMigrationLandingOrder({ base: repo.base, head, cwd: repo.directory });
  assert.deepEqual(result.problems, [
    {
      kind: "duplicate",
      version: 362,
      files: [`${MIGRATIONS}/0362-one.sql`, `${MIGRATIONS}/0362-two.sql`],
      baseHighest: 361,
    },
  ]);
});

test("treats a renumbered migration as an addition", (t) => {
  const repo = repository(t);
  git(repo.directory, "mv", `${MIGRATIONS}/0361-base.sql`, `${MIGRATIONS}/0360-renumbered.sql`);
  git(repo.directory, "commit", "-qm", "renumber migration");
  const head = git(repo.directory, "rev-parse", "HEAD");
  const result = checkMigrationLandingOrder({ base: repo.base, head, cwd: repo.directory });
  assert.equal(result.added.length, 1);
  assert.equal(result.problems[0].file, `${MIGRATIONS}/0360-renumbered.sql`);
  assert.equal(result.problems[0].version, 360);
});

test("ignores non-migration files in the migrations directory", (t) => {
  const repo = repository(t);
  const head = repo.add({
    "README.md": "notes\n",
    "current-schema.sql": "SELECT 2;\n",
    "not-a-migration.sql": "SELECT 3;\n",
  });
  const result = checkMigrationLandingOrder({ base: repo.base, head, cwd: repo.directory });
  assert.equal(result.added.length, 0);
  assert.deepEqual(result.problems, []);
});
