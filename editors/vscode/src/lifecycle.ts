import { ChildProcess, spawn } from "child_process";
import { existsSync, statSync } from "fs";
import path from "path";
import * as vscode from "vscode";

export type LaunchMode = "auto" | "bundled" | "path";

export interface BifrostLaunchConfig {
  command: string;
  args: string[];
  cwd: string;
  env: NodeJS.ProcessEnv;
  label: string;
}

export interface BifrostServerHandle {
  process: ChildProcess;
  commandLine: string;
}

export function resolveLaunchMode(
  mode: LaunchMode,
  extensionDir: string,
  configuredPath: string
): LaunchMode {
  if (mode !== "auto") {
    return mode;
  }
  if (configuredPath.trim() && configuredPath.trim() !== "bifrost") {
    return "path";
  }
  if (findBundledBinary(extensionDir)) {
    return "bundled";
  }
  return "path";
}

export function buildLaunchConfig(
  workspaceRoot: string,
  extensionDir: string,
  mode: LaunchMode,
  configuredPath: string,
  extraArgs: string[],
  debug: boolean,
  slowRequestMs: number
): BifrostLaunchConfig {
  const resolvedMode = resolveLaunchMode(mode, extensionDir, configuredPath);
  const command = commandForMode(resolvedMode, extensionDir, configuredPath);
  const args = ["--root", workspaceRoot, "--server", "lsp", ...extraArgs];
  return {
    command,
    args,
    cwd: workspaceRoot,
    env: {
      ...process.env,
      BIFROST_LSP_DEBUG: debug ? "1" : (process.env.BIFROST_LSP_DEBUG ?? "0"),
      BIFROST_LSP_SLOW_MS: String(slowRequestMs),
      RUST_BACKTRACE: process.env.RUST_BACKTRACE ?? "1"
    },
    label: resolvedMode
  };
}

export function spawnBifrostServer(
  config: BifrostLaunchConfig,
  log: (message: string) => void
): BifrostServerHandle {
  const child = spawnCommand(config.command, config.args, config.cwd, config.env);
  const commandLine = formatCommandLine(config.command, config.args);

  child.stderr?.on("data", (chunk: Buffer) => {
    const message = chunk.toString().trimEnd();
    if (message) {
      log(`[server] ${message}`);
    }
  });

  child.on("error", (error) => {
    log(`Bifrost language server process error: ${formatSpawnError(error)}`);
  });

  child.on("exit", (code, signal) => {
    log(
      `Bifrost language server exited with code ${code ?? "null"}${
        signal ? ` and signal ${signal}` : ""
      }.`
    );
  });

  return { process: child, commandLine };
}

export function findBundledBinary(extensionDir: string): string | null {
  const executable = process.platform === "win32" ? "bifrost.exe" : "bifrost";
  const platformArch = `${process.platform}-${process.arch}`;
  const candidates = [
    path.join(extensionDir, "bin", platformArch, executable),
    path.join(extensionDir, "bin", executable)
  ];
  return candidates.find((candidate) => existsSync(candidate)) ?? null;
}

export function findLocalDevBinary(extensionDir: string): string | null {
  const executable = process.platform === "win32" ? "bifrost.exe" : "bifrost";
  const candidates = [
    path.resolve(extensionDir, "..", "..", "target", "debug", executable),
    path.resolve(extensionDir, "..", "..", "target", "release", executable)
  ];
  const matches = candidates
    .filter((candidate) => existsSync(candidate))
    .map((candidate) => ({
      path: candidate,
      mtime: statSync(candidate).mtimeMs
    }))
    .sort((left, right) => right.mtime - left.mtime);
  return matches[0]?.path ?? null;
}

export function supportedWorkspaceRoot(): string | null {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    return null;
  }
  return folders[0].uri.fsPath;
}

export function sourceFileWatchers(): vscode.FileSystemWatcher[] {
  return [
    "**/*.{java,go,c,cc,cpp,cxx,h,hpp,hh,hxx,js,mjs,cjs,jsx,ts,tsx,py,rs,php,scala,cs,rb}",
    "**/{pom.xml,build.gradle,build.gradle.kts,settings.gradle,settings.gradle.kts,tsconfig.json,jsconfig.json,package.json,Cargo.toml,go.mod,composer.json}"
  ].map((pattern) => vscode.workspace.createFileSystemWatcher(pattern));
}

export function parseExtraArgs(raw: string[]): string[] {
  return raw.map((arg) => arg.trim()).filter(Boolean);
}

export function formatError(error: unknown): string {
  if (error instanceof Error) {
    return error.stack ?? error.message;
  }
  return String(error);
}

function commandForMode(
  mode: LaunchMode,
  extensionDir: string,
  configuredPath: string
): string {
  if (mode === "bundled") {
    const bundled = findBundledBinary(extensionDir);
    if (!bundled) {
      throw new Error(
        `No bundled Bifrost binary found for ${process.platform}-${process.arch}. Configure bifrost.serverPath or choose launch mode "path".`
      );
    }
    return bundled;
  }

  const configured = configuredPath.trim();
  if (configured && configured !== "bifrost") {
    return configured;
  }

  return findLocalDevBinary(extensionDir) ?? "bifrost";
}

function spawnCommand(
  command: string,
  args: string[],
  cwd: string,
  env: NodeJS.ProcessEnv
): ChildProcess {
  if (process.platform !== "win32") {
    return spawn(command, args, { cwd, env, stdio: ["pipe", "pipe", "pipe"] });
  }

  const lower = command.toLowerCase();
  if (lower.endsWith(".ps1")) {
    return spawn(
      "powershell.exe",
      ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", command, ...args],
      { cwd, env, stdio: ["pipe", "pipe", "pipe"] }
    );
  }

  if (lower.endsWith(".cmd") || lower.endsWith(".bat")) {
    return spawn(command, args, {
      cwd,
      env,
      shell: true,
      stdio: ["pipe", "pipe", "pipe"]
    });
  }

  return spawn(command, args, { cwd, env, stdio: ["pipe", "pipe", "pipe"] });
}

function formatSpawnError(error: Error): string {
  const spawnError = error as NodeJS.ErrnoException & { spawnargs?: string[] };
  return [
    `message=${spawnError.message}`,
    spawnError.code ? `code=${spawnError.code}` : "",
    spawnError.errno ? `errno=${String(spawnError.errno)}` : "",
    spawnError.syscall ? `syscall=${spawnError.syscall}` : "",
    spawnError.path ? `path=${spawnError.path}` : "",
    Array.isArray(spawnError.spawnargs)
      ? `spawnargs=${JSON.stringify(spawnError.spawnargs)}`
      : ""
  ]
    .filter(Boolean)
    .join(", ");
}

function formatCommandLine(command: string, args: string[]): string {
  return [command, ...args].map(shellQuote).join(" ");
}

function shellQuote(value: string): string {
  if (/^[A-Za-z0-9_./:=+-]+$/.test(value)) {
    return value;
  }
  return `"${value.replace(/(["\\$`])/g, "\\$1")}"`;
}
