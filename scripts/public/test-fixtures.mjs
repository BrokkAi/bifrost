import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

export function writeExecutable(filePath, contents) {
  mkdirSync(path.dirname(filePath), { recursive: true });
  writeFileSync(filePath, contents);
  chmodSync(filePath, 0o755);
}

export function withTempDir(body, prefix) {
  const directory = mkdtempSync(path.join(os.tmpdir(), prefix));
  try {
    return body(directory);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

export function gitTestEnvironment(overrides = {}) {
  return {
    ...process.env,
    GIT_AUTHOR_NAME: "Test",
    GIT_AUTHOR_EMAIL: "test@example.com",
    GIT_COMMITTER_NAME: "Test",
    GIT_COMMITTER_EMAIL: "test@example.com",
    ...overrides,
  };
}

export function gitWithTestIdentity(cwd, args, envOverrides = {}) {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    env: gitTestEnvironment(envOverrides),
  });
}

export function createBareGitPair(directory) {
  const origin = path.join(directory, "origin.git");
  const work = path.join(directory, "work");
  execFileSync("git", ["init", "-q", "--bare", origin]);
  execFileSync("git", ["--git-dir", origin, "symbolic-ref", "HEAD", "refs/heads/master"]);
  execFileSync("git", ["init", "-q", work]);
  execFileSync("git", ["-C", work, "symbolic-ref", "HEAD", "refs/heads/master"]);
  return { origin, work };
}
