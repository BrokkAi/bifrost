const assert = require("node:assert/strict");
const fs = require("node:fs");
const { loadWASM, OnigScanner, OnigString } = require("vscode-oniguruma");
const { INITIAL, Registry, parseRawGrammar } = require("vscode-textmate");

let onigLib;

async function loadTextMateGrammar(grammarPath, scopeName) {
  if (!onigLib) {
    const wasm = fs.readFileSync(require.resolve("vscode-oniguruma/release/onig.wasm"));
    await loadWASM(wasm.buffer.slice(wasm.byteOffset, wasm.byteOffset + wasm.byteLength));
    onigLib = Promise.resolve({
      createOnigScanner: (patterns) => new OnigScanner(patterns),
      createOnigString: (value) => new OnigString(value)
    });
  }

  const registry = new Registry({
    onigLib,
    loadGrammar: (requestedScope) => requestedScope === scopeName
      ? parseRawGrammar(fs.readFileSync(grammarPath, "utf8"), grammarPath)
      : null
  });
  return registry.loadGrammar(scopeName);
}

function tokenizeGrammar(grammar, source) {
  let ruleStack = INITIAL;
  return source.split(/\r?\n/).flatMap((line) => {
    const result = grammar.tokenizeLine(line, ruleStack);
    ruleStack = result.ruleStack;
    return result.tokens.map((token) => ({
      text: line.slice(token.startIndex, token.endIndex),
      scopes: token.scopes
    }));
  });
}

function assertScoped(tokens, text, scope) {
  const token = tokens.find((candidate) => candidate.text === text && candidate.scopes.includes(scope));
  assert.ok(token, `expected ${JSON.stringify(text)} to have ${scope}`);
}

module.exports = { assertScoped, loadTextMateGrammar, tokenizeGrammar };
