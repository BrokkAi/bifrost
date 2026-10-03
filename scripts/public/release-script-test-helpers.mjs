import { execFileSync } from "node:child_process";
import path from "node:path";

export function scriptForDirectory(scriptsDir) {
  return (name) => path.join(scriptsDir, name);
}

export function run(command, args, options = {}) {
  try {
    const stdout = execFileSync(command, args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      ...options,
      env: { ...process.env, ...(options.env ?? {}) },
    });
    return { status: 0, stdout, stderr: "" };
  } catch (error) {
    return {
      status: error.status ?? 1,
      stdout: error.stdout ?? "",
      stderr: error.stderr ?? "",
    };
  }
}
