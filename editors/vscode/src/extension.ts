import { spawn } from "child_process";
import * as vscode from "vscode";
import {
  CloseAction,
  ErrorAction,
  LanguageClient,
  LanguageClientOptions,
  RevealOutputChannelOn,
  ServerOptions,
  State
} from "vscode-languageclient/node";

let client: LanguageClient | undefined;

export function activate(context: vscode.ExtensionContext): void {
  const config = vscode.workspace.getConfiguration("bifrost");
  const command = config.get<string>("serverPath") || "bifrost";
  const debug = config.get<boolean>("debug") ?? false;
  const slowRequestMs = config.get<number>("slowRequestMs") ?? 2000;
  const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? process.cwd();
  const outputChannel = vscode.window.createOutputChannel("Bifrost");
  context.subscriptions.push(outputChannel);

  const serverArgs = ["--root", root, "--server", "lsp"];
  const serverOptions: ServerOptions = async () => {
    outputChannel.appendLine(`Starting Bifrost language server: ${command} ${serverArgs.join(" ")}`);
    const server = spawn(command, serverArgs, {
      cwd: root,
      env: {
        ...process.env,
        BIFROST_LSP_DEBUG: debug ? "1" : (process.env.BIFROST_LSP_DEBUG ?? "0"),
        BIFROST_LSP_SLOW_MS: String(slowRequestMs),
        RUST_BACKTRACE: process.env.RUST_BACKTRACE ?? "1"
      },
      stdio: ["pipe", "pipe", "pipe"]
    });
    server.stderr?.on("data", (chunk: Buffer) => {
      outputChannel.append(chunk.toString());
    });
    server.on("error", (error) => {
      outputChannel.appendLine(`Bifrost language server process error: ${formatError(error)}`);
    });
    server.on("exit", (code, signal) => {
      outputChannel.appendLine(`Bifrost language server exited with code ${code ?? "null"}${signal ? ` and signal ${signal}` : ""}.`);
    });
    return server;
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [
      { scheme: "file", language: "java" },
      { scheme: "file", language: "javascript" },
      { scheme: "file", language: "javascriptreact" },
      { scheme: "file", language: "typescript" },
      { scheme: "file", language: "typescriptreact" },
      { scheme: "file", language: "rust" },
      { scheme: "file", language: "go" },
      { scheme: "file", language: "python" },
      { scheme: "file", language: "c" },
      { scheme: "file", language: "cpp" },
      { scheme: "file", language: "csharp" },
      { scheme: "file", language: "php" },
      { scheme: "file", language: "scala" }
    ],
    outputChannel,
    revealOutputChannelOn: RevealOutputChannelOn.Error,
    initializationFailedHandler: (error) => {
      outputChannel.appendLine(`Bifrost language server failed to initialize: ${formatError(error)}`);
      return false;
    },
    errorHandler: {
      error: (error) => {
        outputChannel.appendLine(`Bifrost language server connection error: ${formatError(error)}`);
        return { action: ErrorAction.Shutdown, handled: true };
      },
      closed: () => {
        outputChannel.appendLine("Bifrost language server connection closed.");
        return { action: CloseAction.DoNotRestart, handled: true };
      }
    },
    synchronize: {
      fileEvents: sourceFileWatchers()
    }
  };

  client = new LanguageClient("bifrost", "Bifrost", serverOptions, clientOptions);
  context.subscriptions.push({
    dispose: () => {
      void stopClient(outputChannel);
    }
  });
  void client.start().catch((error: unknown) => {
    outputChannel.appendLine(`Bifrost language client failed to start: ${formatError(error)}`);
  });
}

export function deactivate(): Thenable<void> | undefined {
  const current = client;
  if (!current || current.state !== State.Running) {
    return undefined;
  }
  return current.stop();
}

async function stopClient(outputChannel: vscode.OutputChannel): Promise<void> {
  const current = client;
  if (!current || current.state !== State.Running) {
    return;
  }
  try {
    await current.stop();
  } catch (error) {
    outputChannel.appendLine(`Bifrost language client failed to stop: ${formatError(error)}`);
  }
}

function formatError(error: unknown): string {
  if (error instanceof Error) {
    return error.stack ?? error.message;
  }
  return String(error);
}

function sourceFileWatchers(): vscode.FileSystemWatcher[] {
  return [
    "**/*.{java,go,c,cc,cpp,cxx,h,hpp,hh,hxx,js,mjs,cjs,jsx,ts,tsx,py,rs,php,scala,cs,rb}",
    "**/{pom.xml,build.gradle,build.gradle.kts,settings.gradle,settings.gradle.kts,tsconfig.json,jsconfig.json,package.json,Cargo.toml,go.mod,composer.json}"
  ].map((pattern) => vscode.workspace.createFileSystemWatcher(pattern));
}
