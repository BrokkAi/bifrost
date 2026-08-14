#!/usr/bin/env node

import { spawn } from "node:child_process";
import { realpathSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);

export function linuxLibc(report = process.report?.getReport?.()) {
  return report?.header?.glibcVersionRuntime ? "gnu" : "musl";
}

export function platformPackageName(
  platform = process.platform,
  arch = process.arch,
  libc = platform === "linux" ? linuxLibc() : undefined,
) {
  const packages = {
    "darwin-arm64": "@brokkai/bifrost-darwin-universal",
    "darwin-x64": "@brokkai/bifrost-darwin-universal",
    "linux-arm64-gnu": "@brokkai/bifrost-linux-arm64-gnu",
    "linux-x64-gnu": "@brokkai/bifrost-linux-x64-gnu",
    "linux-x64-musl": "@brokkai/bifrost-linux-x64-musl",
    "android-arm64": "@brokkai/bifrost-android-arm64",
    "win32-arm64": "@brokkai/bifrost-win32-arm64",
    "win32-x64": "@brokkai/bifrost-win32-x64",
  };
  const key = platform === "linux" ? `${platform}-${arch}-${libc}` : `${platform}-${arch}`;
  const packageName = packages[key];
  if (!packageName) {
    throw new Error(`Bifrost does not publish an npm package for ${key}.`);
  }
  return packageName;
}

export function resolveBundle(
  resolve = require.resolve,
  platform = process.platform,
  arch = process.arch,
  libc = platform === "linux" ? linuxLibc() : undefined,
) {
  const packageName = platformPackageName(platform, arch, libc);
  try {
    return path.dirname(resolve(`${packageName}/package.json`));
  } catch (error) {
    throw new Error(
      `The ${packageName} native package is not installed. Reinstall @brokkai/bifrost with optional dependencies enabled.`,
      { cause: error },
    );
  }
}

export function nativeBinaryPath(bundleRoot, platform = process.platform) {
  return path.join(bundleRoot, "bin", platform === "win32" ? "bifrost.exe" : "bifrost");
}

const SIGNAL_EXIT_CODES = {
  SIGHUP: 129,
  SIGINT: 130,
  SIGTERM: 143,
};

export function launch(
  bundleRoot,
  args,
  platform = process.platform,
  spawnProcess = spawn,
  exitProcess = process.exit,
) {
  const child = spawnProcess(nativeBinaryPath(bundleRoot, platform), args, { stdio: "inherit" });
  const signalHandlers = new Map();
  for (const signal of Object.keys(SIGNAL_EXIT_CODES)) {
    const handler = () => child.kill(signal);
    signalHandlers.set(signal, handler);
    process.on(signal, handler);
  }
  const removeSignalHandlers = () => {
    for (const [signal, handler] of signalHandlers) process.off(signal, handler);
  };
  child.on("error", (error) => {
    removeSignalHandlers();
    console.error(`bifrost: could not start the native package: ${error.message}`);
    exitProcess(1);
  });
  child.on("exit", (code, signal) => {
    removeSignalHandlers();
    if (signal) {
      exitProcess(SIGNAL_EXIT_CODES[signal] ?? 1);
      return;
    }
    exitProcess(code ?? 1);
  });
}

export function isMainModule(argvPath = process.argv[1], resolveRealPath = realpathSync) {
  return Boolean(argvPath && resolveRealPath(path.resolve(argvPath)) === fileURLToPath(import.meta.url));
}

if (isMainModule()) {
  launch(resolveBundle(), process.argv.slice(2));
}
