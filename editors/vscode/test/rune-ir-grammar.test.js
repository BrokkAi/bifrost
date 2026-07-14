const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { loadWASM, OnigScanner, OnigString } = require("vscode-oniguruma");
const { Registry, parseRawGrammar } = require("vscode-textmate");

const extensionRoot = path.resolve(__dirname, "..");
const grammarPath = path.join(extensionRoot, "syntaxes", "bifrost-rune-ir.tmLanguage.json");
const scopeName = "source.bifrost-rune-ir";

async function grammar() {
  const wasm = fs.readFileSync(require.resolve("vscode-oniguruma/release/onig.wasm"));
  await loadWASM(wasm.buffer.slice(wasm.byteOffset, wasm.byteOffset + wasm.byteLength));
  const onigLib = Promise.resolve({
    createOnigScanner: (patterns) => new OnigScanner(patterns),
    createOnigString: (value) => new OnigString(value)
  });
  const registry = new Registry({
    onigLib,
    loadGrammar: (requestedScope) => requestedScope === scopeName
      ? parseRawGrammar(fs.readFileSync(grammarPath, "utf8"), grammarPath)
      : null
  });
  return registry.loadGrammar(scopeName);
}

function tokenWithScope(tokens, text, scope) {
  return tokens.find((token) => token.text === text && token.scopes.includes(scope));
}

test("tokenizes Rune IR comments, vocabulary, metadata, strings, and spans", async () => {
  const source = [
    "; Rune IR for greet (rust)",
    "(function :range (0 42) :name \"greet\"",
    "  (callee :span (20 27) :text \"println\")",
    "  (args :span (28 34) :text \"name\"))",
    "; Starter RQL",
    "(function :name \"greet\")",
    "(truncated \"node limit reached\")"
  ];
  const loaded = await grammar();
  const tokens = source.flatMap((line) => loaded.tokenizeLine(line).tokens.map((token) => ({
    text: line.slice(token.startIndex, token.endIndex),
    scopes: token.scopes
  })));

  assert.ok(tokenWithScope(tokens, "; Rune IR for greet (rust)", "comment.line.semicolon.bifrost-rune-ir"));
  assert.ok(tokenWithScope(tokens, "function", "entity.name.type.kind.bifrost-rune-ir"));
  assert.ok(tokenWithScope(tokens, "callee", "variable.parameter.role.bifrost-rune-ir"));
  assert.ok(tokenWithScope(tokens, "args", "variable.parameter.role.bifrost-rune-ir"));
  assert.ok(tokenWithScope(tokens, ":range", "variable.other.property.bifrost-rune-ir"));
  assert.ok(tokenWithScope(tokens, "\"greet\"", "string.quoted.double.bifrost-rune-ir"));
  assert.ok(tokenWithScope(tokens, "42", "constant.numeric.integer.decimal.bifrost-rune-ir"));
  assert.ok(tokenWithScope(tokens, "truncated", "invalid.deprecated.truncated.bifrost-rune-ir"));
});
