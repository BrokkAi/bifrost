const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const {
  assertScoped,
  loadTextMateGrammar,
  tokenizeGrammar
} = require("./textmate-test-utils");

const extensionRoot = path.resolve(__dirname, "..");
const grammarPath = path.join(extensionRoot, "syntaxes", "bifrost-rql.tmLanguage.json");
const fixturePath = path.join(__dirname, "fixtures", "rql", "highlighting.rql");
const scopeName = "source.bifrost-rql";

async function grammar() {
  return loadTextMateGrammar(grammarPath, scopeName);
}

test("registers Bifrost RQL as a distinct .rql language", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(extensionRoot, "package.json"), "utf8"));
  const runeIrSourceContext = "resourceLangId == java || resourceLangId == javascript || resourceLangId == javascriptreact || resourceLangId == typescript || resourceLangId == typescriptreact || resourceLangId == rust || resourceLangId == go || resourceLangId == python || resourceLangId == c || resourceLangId == cpp || resourceLangId == csharp || resourceLangId == php || resourceLangId == scala || resourceLangId == ruby";
  assert.ok(manifest.activationEvents.includes("onLanguage:bifrost-rql"));
  assert.ok(!manifest.activationEvents.includes("onLanguage:bifrost-rune-ir"));
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
    },
    {
      id: "bifrost-rune-ir",
      aliases: ["Bifrost Rune IR", "bifrost-rune-ir"],
      extensions: [".rune"],
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
    },
    {
      language: "bifrost-rune-ir",
      scopeName: "source.bifrost-rune-ir",
      path: "./syntaxes/bifrost-rune-ir.tmLanguage.json"
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
  const tokens = tokenizeGrammar(await grammar(), fs.readFileSync(fixturePath, "utf8"));

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
  const tokens = tokenizeGrammar(await grammar(), "(not_has (call)) (not_kind class)");
  assertScoped(tokens, "not_has", "support.function.predicate.bifrost-rql");
  assertScoped(tokens, "not_kind", "support.function.predicate.bifrost-rql");
});
