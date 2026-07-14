const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { loadWASM, OnigScanner, OnigString } = require("vscode-oniguruma");
const { INITIAL, Registry, parseRawGrammar } = require("vscode-textmate");

const extensionRoot = path.resolve(__dirname, "..");
const grammarPath = path.join(extensionRoot, "syntaxes", "bifrost-rql.tmLanguage.json");
const fixturePath = path.join(__dirname, "fixtures", "rql", "highlighting.rql");
const scopeName = "source.bifrost-rql";

let onigLib;

async function grammar() {
  if (!onigLib) {
    const wasm = fs.readFileSync(require.resolve("vscode-oniguruma/release/onig.wasm"));
    await loadWASM(wasm.buffer.slice(wasm.byteOffset, wasm.byteOffset + wasm.byteLength));
    onigLib = Promise.resolve({
      createOnigScanner(patterns) {
        return new OnigScanner(patterns);
      },
      createOnigString(value) {
        return new OnigString(value);
      }
    });
  }

  const registry = new Registry({
    onigLib,
    loadGrammar(requestedScope) {
      if (requestedScope !== scopeName) {
        return null;
      }
      return parseRawGrammar(fs.readFileSync(grammarPath, "utf8"), grammarPath);
    }
  });
  return registry.loadGrammar(scopeName);
}

function tokenize(grammar, source) {
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

test("registers Bifrost RQL as a distinct .rql language", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(extensionRoot, "package.json"), "utf8"));
  const runeIrSourceContext = "resourceLangId == java || resourceLangId == javascript || resourceLangId == javascriptreact || resourceLangId == typescript || resourceLangId == typescriptreact || resourceLangId == rust || resourceLangId == go || resourceLangId == python || resourceLangId == c || resourceLangId == cpp || resourceLangId == csharp || resourceLangId == php || resourceLangId == scala || resourceLangId == ruby";
  assert.ok(manifest.activationEvents.includes("onLanguage:bifrost-rql"));
  assert.deepEqual(manifest.contributes.languages, [
    {
      id: "bifrost-rql",
      aliases: ["Bifrost RQL", "bifrost-rql"],
      extensions: [".rql"],
      configuration: "./language-configuration.json",
      icon: {
        light: "./icons/bifrost-rql.png",
        dark: "./icons/bifrost-rql.png"
      }
    }
  ]);
  assert.deepEqual(manifest.contributes.grammars, [
    {
      language: "bifrost-rql",
      scopeName,
      path: "./syntaxes/bifrost-rql.tmLanguage.json"
    }
  ]);
  assert.deepEqual(
    manifest.contributes.commands.find((command) => command.command === "bifrost.runRqlQuery"),
    {
      command: "bifrost.runRqlQuery",
      title: "Bifrost: Run RQL Query",
      icon: "$(play)"
    }
  );
  assert.deepEqual(
    manifest.contributes.commands.find((command) => command.command === "bifrost.showRuneIr"),
    {
      command: "bifrost.showRuneIr",
      title: "Bifrost: Show Rune IR"
    }
  );
  assert.deepEqual(manifest.contributes.menus["editor/title"], [
    {
      command: "bifrost.runRqlQuery",
      when: "resourceLangId == bifrost-rql",
      group: "navigation@1"
    }
  ]);
  assert.deepEqual(manifest.contributes.menus.commandPalette, [
    { command: "bifrost.runRqlQuery", when: "false" },
    { command: "bifrost.openRqlQueryResult", when: "false" },
    { command: "bifrost.showRuneIr", when: runeIrSourceContext }
  ]);
  assert.deepEqual(manifest.contributes.menus["editor/context"], [
    {
      command: "bifrost.showRuneIr",
      when: runeIrSourceContext,
      group: "navigation@10"
    }
  ]);
  assert.deepEqual(manifest.contributes.views.explorer, [
    { id: "bifrost.queryResults", name: "Bifrost Query Results" }
  ]);
});

test("tokenizes nested RQL structure, literals, and incomplete input", async () => {
  const tokens = tokenize(await grammar(), fs.readFileSync(fixturePath, "utf8"));

  assertScoped(tokens, "; A complete nested query and deliberately incomplete trailing input.", "comment.line.semicolon.bifrost-rql");
  assertScoped(tokens, "(", "punctuation.section.brackets.bifrost-rql");
  assertScoped(tokens, "where", "support.function.wrapper.bifrost-rql");
  assertScoped(tokens, "call", "entity.name.type.kind.bifrost-rql");
  assertScoped(tokens, ":callee", "variable.parameter.role.bifrost-rql");
  assertScoped(tokens, "name/regex", "support.function.predicate.bifrost-rql");
  assertScoped(tokens, "eval\\\\(", "string.regexp.bifrost-rql");
  assertScoped(tokens, "\"src/**/*.py\"", "string.quoted.double.bifrost-rql");
  assertScoped(tokens, "25", "constant.numeric.integer.decimal.bifrost-rql");
  assertScoped(tokens, "full", "constant.language.result-detail.bifrost-rql");
  assertScoped(tokens, "; trailing comment", "comment.line.semicolon.bifrost-rql");
  assertScoped(tokens, "\"semi;colon\"", "string.quoted.double.bifrost-rql");
  const unknown = tokens.find((candidate) => candidate.text.includes("custom_identifier :unexpected true false null 7"));
  assert.deepEqual(unknown?.scopes, [scopeName]);
});

test("highlights registered underscore predicate aliases", async () => {
  const tokens = tokenize(await grammar(), "(not_has (call)) (not_kind class)");
  assertScoped(tokens, "not_has", "support.function.predicate.bifrost-rql");
  assertScoped(tokens, "not_kind", "support.function.predicate.bifrost-rql");
});
