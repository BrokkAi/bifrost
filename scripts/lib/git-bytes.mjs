import { execFileSync } from "node:child_process";

export function readGitBlob(source, repositoryPath, maxBuffer) {
  return execFileSync("git", ["show", `${source}:${repositoryPath}`], {
    encoding: null,
    maxBuffer,
    stdio: ["ignore", "pipe", "pipe"],
  });
}
