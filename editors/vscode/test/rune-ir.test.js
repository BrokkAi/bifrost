const assert = require("node:assert/strict");
const test = require("node:test");

const {
  RUNE_IR_METHOD,
  isRuneIrSourceLanguage,
  showRuneIr
} = require("../out-test/rune_ir.js");

function runner(overrides = {}) {
  const messages = { errors: [], warnings: [], documents: [] };
  return {
    messages,
    value: {
      isReady: () => true,
      sendRequest: async () => ({
        codeUnit: "demo",
        sourceRange: {
          start: { line: 0, character: 0 },
          end: { line: 0, character: 12 }
        },
        runeIr: "(function :name \"demo\")\n",
        starterRql: "(function :name \"demo\")",
        truncated: false,
        displayText: "opaque server text\n"
      }),
      showError: (message) => messages.errors.push(message),
      showWarning: (message) => messages.warnings.push(message),
      showDocument: async (text) => messages.documents.push(text),
      ...overrides
    }
  };
}

test("showRuneIr sends a cursor request and displays server text verbatim", async () => {
  let observed;
  const state = runner({
    sendRequest: async (method, params) => {
      observed = { method, params };
      return {
        codeUnit: "demo",
        sourceRange: {
          start: { line: 0, character: 0 },
          end: { line: 2, character: 1 }
        },
        runeIr: "client must not parse this",
        starterRql: "(function :name \"demo\")",
        truncated: false,
        displayText: "exact server-rendered document\n"
      };
    }
  });
  const result = await showRuneIr(
    { uri: "file:///workspace/demo.rs", languageId: "rust" },
    undefined,
    { line: 1, character: 4 },
    state.value
  );

  assert.equal(observed.method, RUNE_IR_METHOD);
  assert.deepEqual(observed.params, {
    textDocument: { uri: "file:///workspace/demo.rs" },
    position: { line: 1, character: 4 }
  });
  assert.equal(result.codeUnit, "demo");
  assert.deepEqual(state.messages.documents, ["exact server-rendered document\n"]);
});

test("showRuneIr sends a non-empty selection instead of a cursor", async () => {
  let observed;
  const state = runner({
    sendRequest: async (_method, params) => {
      observed = params;
      return runner().value.sendRequest();
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

test("showRuneIr reports unsupported, not-ready, and request failures", async () => {
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
    sendRequest: async () => {
      throw new Error("no declaration here");
    }
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
