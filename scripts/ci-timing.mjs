import { appendFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

function parseArgs(argv) {
  const separator = argv.indexOf("--");
  if (separator === -1 || separator === argv.length - 1 || argv[0] !== "--label" || !argv[1]) {
    throw new Error("Usage: ci-timing.mjs --label LABEL -- command [args...]");
  }
  return { label: argv[1], command: argv.slice(separator + 1) };
}

function appendSummary(label, elapsedMilliseconds, status) {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryPath) {
    return;
  }
  appendFileSync(
    summaryPath,
    `| ${label.replaceAll("|", "\\|")} | ${status} | ${elapsedMilliseconds} |\n`,
  );
}

function main() {
  const { label, command } = parseArgs(process.argv.slice(2));
  const startedAt = process.hrtime.bigint();
  const result = spawnSync(command[0], command.slice(1), {
    shell: process.platform === "win32",
    stdio: "inherit",
  });
  const elapsedMilliseconds = Number((process.hrtime.bigint() - startedAt) / 1_000_000n);
  const exitCode = result.status ?? 1;
  const status = exitCode === 0 ? "success" : `failed (${exitCode})`;
  process.stdout.write(`ci_timing_ms label=${label} elapsed_ms=${elapsedMilliseconds} status=${status}\n`);
  appendSummary(label, elapsedMilliseconds, status);
  process.exitCode = exitCode;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main();
}
