import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import {
  RUNE_IR_LANGUAGE_ID,
  RUNE_IR_METHOD,
  RUNE_IR_SOURCE_LANGUAGE_IDS,
  isRuneIrSourceLanguage,
  showRuneIr,
  type RuneIrRunner
} from "../src/rune_ir";

interface ExtensionManifest {
  contributes: {
    menus: {
      commandPalette: Array<{ command: string; when: string }>;
      "editor/context": Array<{ command: string; when: string }>;
    };
  };
}

interface RunnerMessages {
  errors: string[];
  warnings: string[];
  documents: Array<{ text: string; languageId: string }>;
}

const extensionRoot = path.resolve(__dirname, "../..");

function languagesFromWhenClause(value: string): string[] {
  return [...value.matchAll(/resourceLangId == ([a-z]+)/g)].map((match) => match[1]);
}

function runner(overrides: Partial<RuneIrRunner> = {}): {
  messages: RunnerMessages;
  value: RuneIrRunner;
} {
  const messages: RunnerMessages = { errors: [], warnings: [], documents: [] };
  return {
    messages,
    value: {
      isReady: () => true,
      sendRequest: () =>
        Promise.resolve({
          codeUnit: "demo",
          sourceRange: {
            start: { line: 0, character: 0 },
            end: { line: 0, character: 12 }
          },
          runeIr: '(function :name "demo")\n',
          starterRql: '(function :name "demo")',
          truncated: false,
          displayText: "opaque server text\n"
        }),
      showError: (message) => messages.errors.push(message),
      showWarning: (message) => messages.warnings.push(message),
      showDocument: (text, languageId) => {
        messages.documents.push({ text, languageId });
        return Promise.resolve();
      },
      ...overrides
    }
  };
}

void test("showRuneIr sends a cursor request and displays server text verbatim", async () => {
  let observed: { method: string; params: Parameters<RuneIrRunner["sendRequest"]>[1] } | undefined;
  const state = runner({
    sendRequest: (method, params) => {
      observed = { method, params };
      return Promise.resolve({
        codeUnit: "demo",
        sourceRange: {
          start: { line: 0, character: 0 },
          end: { line: 2, character: 1 }
        },
        runeIr: "client must not parse this",
        starterRql: '(function :name "demo")',
        truncated: false,
        displayText: "exact server-rendered document\n"
      });
    }
  });
  const result = await showRuneIr(
    { uri: "file:///workspace/demo.rs", languageId: "rust" },
    undefined,
    { line: 1, character: 4 },
    state.value
  );

  assert.ok(observed);
  assert.equal(observed.method, RUNE_IR_METHOD);
  assert.deepEqual(observed.params, {
    textDocument: { uri: "file:///workspace/demo.rs" },
    position: { line: 1, character: 4 }
  });
  assert.ok(result);
  assert.equal(result.codeUnit, "demo");
  assert.deepEqual(state.messages.documents, [
    {
      text: "exact server-rendered document\n",
      languageId: RUNE_IR_LANGUAGE_ID
    }
  ]);
});

void test("showRuneIr sends a non-empty selection instead of a cursor", async () => {
  let observed: Parameters<RuneIrRunner["sendRequest"]>[1] | undefined;
  const state = runner({
    sendRequest: async (method, params) => {
      observed = params;
      return runner().value.sendRequest(method, params);
    }
  });
  const range = {
    start: { line: 1, character: 2 },
    end: { line: 3, character: 4 }
  };
  await showRuneIr(
    { uri: "file:///workspace/demo.py", languageId: "python" },
    range,
    { line: 1, character: 2 },
    state.value
  );
  assert.deepEqual(observed, {
    textDocument: { uri: "file:///workspace/demo.py" },
    range
  });
});

void test("showRuneIr reports unsupported, not-ready, and request failures", async () => {
  const unsupported = runner();
  assert.equal(isRuneIrSourceLanguage("plaintext"), false);
  assert.equal(isRuneIrSourceLanguage("typescriptreact"), true);
  await showRuneIr(
    { uri: "file:///notes.txt", languageId: "plaintext" },
    undefined,
    { line: 0, character: 0 },
    unsupported.value
  );
  assert.match(unsupported.messages.warnings[0], /supported source file/);

  const notReady = runner({ isReady: () => false });
  await showRuneIr(
    { uri: "file:///demo.go", languageId: "go" },
    undefined,
    { line: 0, character: 0 },
    notReady.value
  );
  assert.match(notReady.messages.warnings[0], /not ready/);

  const failed = runner({
    sendRequest: () => Promise.reject(new Error("no declaration here"))
  });
  await showRuneIr(
    { uri: "file:///demo.java", languageId: "java" },
    undefined,
    { line: 0, character: 0 },
    failed.value
  );
  assert.match(failed.messages.errors[0], /no declaration here/);
  assert.deepEqual(failed.messages.documents, []);
});

void test("Rune IR manifest contexts match the runtime source-language registry", () => {
  const manifest = JSON.parse(
    fs.readFileSync(path.join(extensionRoot, "package.json"), "utf8")
  ) as ExtensionManifest;
  const palette = manifest.contributes.menus.commandPalette.find(
    (entry) => entry.command === "bifrost.showRuneIr"
  );
  const editorContext = manifest.contributes.menus["editor/context"].find(
    (entry) => entry.command === "bifrost.showRuneIr"
  );

  assert.ok(palette);
  assert.ok(editorContext);
  assert.deepEqual(languagesFromWhenClause(palette.when), [...RUNE_IR_SOURCE_LANGUAGE_IDS]);
  assert.deepEqual(languagesFromWhenClause(editorContext.when), [...RUNE_IR_SOURCE_LANGUAGE_IDS]);
});
