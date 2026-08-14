import assert from "node:assert/strict";
import fs from "node:fs";
import { loadWASM, OnigScanner, OnigString } from "vscode-oniguruma";
import { INITIAL, Registry, parseRawGrammar, type IGrammar, type IOnigLib } from "vscode-textmate";

export interface GrammarToken {
  text: string;
  scopes: string[];
}

let onigLib: Promise<IOnigLib> | undefined;

export interface TextMateGrammarDependency {
  scopeName: string;
  grammarPath: string;
}

export async function loadTextMateGrammar(
  grammarPath: string,
  scopeName: string,
  dependencies: readonly TextMateGrammarDependency[] = []
): Promise<IGrammar> {
  if (!onigLib) {
    const wasm = fs.readFileSync(require.resolve("vscode-oniguruma/release/onig.wasm"));
    await loadWASM(wasm.buffer.slice(wasm.byteOffset, wasm.byteOffset + wasm.byteLength));
    onigLib = Promise.resolve({
      createOnigScanner: (patterns) => new OnigScanner(patterns),
      createOnigString: (value) => new OnigString(value)
    });
  }

  const grammarPaths = new Map<string, string>([
    [scopeName, grammarPath],
    ...dependencies.map((dependency) => [dependency.scopeName, dependency.grammarPath] as const)
  ]);
  const registry = new Registry({
    onigLib,
    loadGrammar: (requestedScope) => {
      const requestedPath = grammarPaths.get(requestedScope);
      return Promise.resolve(
        requestedPath
          ? parseRawGrammar(fs.readFileSync(requestedPath, "utf8"), requestedPath)
          : null
      );
    }
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

export function assertNotScoped(
  tokens: readonly GrammarToken[],
  text: string,
  scope: string
): void {
  const matching = tokens.filter((candidate) => candidate.text === text);
  assert.ok(matching.length > 0, `expected to find ${JSON.stringify(text)}`);
  assert.ok(
    matching.every((candidate) => !candidate.scopes.includes(scope)),
    `expected ${JSON.stringify(text)} not to have ${scope}`
  );
}
