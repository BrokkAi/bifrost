export const RUNE_IR_METHOD = "bifrost/runeIr";

export interface RuneIrPosition {
  line: number;
  character: number;
}

export interface RuneIrRange {
  start: RuneIrPosition;
  end: RuneIrPosition;
}

export interface RuneIrDocument {
  uri: string;
  languageId: string;
}

export interface RuneIrResponse {
  codeUnit: string;
  sourceRange: RuneIrRange;
  runeIr: string;
  starterRql: string;
  truncated: boolean;
  displayText: string;
}

export interface RuneIrRunner {
  isReady(): boolean;
  sendRequest(
    method: string,
    params: {
      textDocument: { uri: string };
      position?: RuneIrPosition;
      range?: RuneIrRange;
    }
  ): Promise<RuneIrResponse>;
  showError(message: string): void;
  showWarning(message: string): void;
  showDocument(text: string): Promise<void>;
}

export const RUNE_IR_SOURCE_LANGUAGE_IDS = [
  "java",
  "javascript",
  "javascriptreact",
  "typescript",
  "typescriptreact",
  "rust",
  "go",
  "python",
  "c",
  "cpp",
  "csharp",
  "php",
  "scala",
  "ruby"
] as const;

const SUPPORTED_SOURCE_LANGUAGES = new Set<string>(RUNE_IR_SOURCE_LANGUAGE_IDS);

export function isRuneIrSourceLanguage(languageId: string): boolean {
  return SUPPORTED_SOURCE_LANGUAGES.has(languageId);
}

export async function showRuneIr(
  document: RuneIrDocument | undefined,
  selection: RuneIrRange | undefined,
  position: RuneIrPosition | undefined,
  runner: RuneIrRunner
): Promise<RuneIrResponse | undefined> {
  if (!document || !isRuneIrSourceLanguage(document.languageId)) {
    runner.showWarning("Open a supported source file to show Rune IR.");
    return undefined;
  }
  if (!runner.isReady()) {
    runner.showWarning("Bifrost is not ready. Start the language server and wait for indexing to finish.");
    return undefined;
  }
  if (!selection && !position) {
    runner.showWarning("Place the cursor or a selection inside an indexed declaration.");
    return undefined;
  }

  const params = selection
    ? { textDocument: { uri: document.uri }, range: selection }
    : { textDocument: { uri: document.uri }, position: position! };
  try {
    const response = await runner.sendRequest(RUNE_IR_METHOD, params);
    if (!response || typeof response.displayText !== "string") {
      runner.showError(
        "Rune IR requires an updated Bifrost language server. Rebuild and restart Bifrost, then try again."
      );
      return undefined;
    }
    await runner.showDocument(response.displayText);
    return response;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    runner.showError(`Bifrost Rune IR failed: ${message}`);
    return undefined;
  }
}
