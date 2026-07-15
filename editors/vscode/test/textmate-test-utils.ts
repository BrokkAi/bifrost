import assert from "node:assert/strict";
import fs from "node:fs";
import { loadWASM, OnigScanner, OnigString } from "vscode-oniguruma";
import { INITIAL, Registry, parseRawGrammar, type IGrammar, type IOnigLib } from "vscode-textmate";

export interface GrammarToken {
  text: string;
  scopes: string[];
}

let onigLib: Promise<IOnigLib> | undefined;

export async function loadTextMateGrammar(
  grammarPath: string,
  scopeName: string
): Promise<IGrammar> {
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
    loadGrammar: (requestedScope) =>
      Promise.resolve(
        requestedScope === scopeName
          ? parseRawGrammar(fs.readFileSync(grammarPath, "utf8"), grammarPath)
          : null
      )
  });
  const grammar = await registry.loadGrammar(scopeName);
  assert.ok(grammar, `failed to load TextMate grammar ${scopeName}`);
  return grammar;
}

export function tokenizeGrammar(grammar: IGrammar, source: string): GrammarToken[] {
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

export function assertScoped(tokens: readonly GrammarToken[], text: string, scope: string): void {
  const token = tokens.find(
    (candidate) => candidate.text === text && candidate.scopes.includes(scope)
  );
  assert.ok(token, `expected ${JSON.stringify(text)} to have ${scope}`);
}
