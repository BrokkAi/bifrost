import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { assertScoped, loadTextMateGrammar, tokenizeGrammar } from "./textmate-test-utils";

interface ExtensionManifest {
  activationEvents: string[];
  contributes: {
    languages: unknown[];
    grammars: unknown[];
    commands: Array<{ command: string; [key: string]: unknown }>;
    menus: Record<string, Array<Record<string, string>>>;
    views: { explorer: unknown[] };
  };
}

const extensionRoot = path.resolve(__dirname, "../..");
const grammarPath = path.join(extensionRoot, "syntaxes", "bifrost-rql.tmLanguage.json");
const fixturePath = path.join(extensionRoot, "test", "fixtures", "rql", "highlighting.rql");
const scopeName = "source.bifrost-rql";

async function grammar() {
  return loadTextMateGrammar(grammarPath, scopeName);
}

void test("registers distinct RQL, policy, and Rune IR languages", () => {
  const manifest = JSON.parse(
    fs.readFileSync(path.join(extensionRoot, "package.json"), "utf8")
  ) as ExtensionManifest;
  const runeIrSourceContext =
    "resourceLangId == java || resourceLangId == javascript || resourceLangId == javascriptreact || resourceLangId == typescript || resourceLangId == typescriptreact || resourceLangId == rust || resourceLangId == go || resourceLangId == python || resourceLangId == c || resourceLangId == cpp || resourceLangId == csharp || resourceLangId == php || resourceLangId == scala || resourceLangId == ruby";
  assert.ok(manifest.activationEvents.includes("onLanguage:bifrost-rql"));
  assert.ok(manifest.activationEvents.includes("onLanguage:bifrost-rql-policy"));
  assert.ok(manifest.activationEvents.includes("onLanguage:bifrost-rune-ir"));
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
      id: "bifrost-rql-policy",
      aliases: ["Bifrost RQL Policy", "bifrost-rql-policy"],
      extensions: [".rqlp"],
      configuration: "./language-configuration.json",
      icon: {
        light: "./icons/bifrost-rql-policy.svg",
        dark: "./icons/bifrost-rql-policy.svg"
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
      language: "bifrost-rql-policy",
      scopeName: "source.bifrost-rql-policy",
      path: "./syntaxes/bifrost-rql-policy.tmLanguage.json"
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

void test("tokenizes nested RQL structure, literals, and incomplete input", async () => {
  const tokens = tokenizeGrammar(await grammar(), fs.readFileSync(fixturePath, "utf8"));

  assertScoped(
    tokens,
    "; A complete nested query and deliberately incomplete trailing input.",
    "comment.line.semicolon.bifrost-rql"
  );
  assertScoped(tokens, "(", "punctuation.section.brackets.bifrost-rql");
  assertScoped(tokens, "where", "support.function.wrapper.bifrost-rql");
  assertScoped(tokens, "call", "entity.name.type.kind.bifrost-rql");
  assertScoped(tokens, ":callee", "variable.parameter.role.bifrost-rql");
  assertScoped(tokens, "name/regex", "support.function.predicate.bifrost-rql");
  assertScoped(tokens, "eval\\\\(", "string.regexp.bifrost-rql");
  assertScoped(tokens, '"src/**/*.py"', "string.quoted.double.bifrost-rql");
  assertScoped(tokens, "25", "constant.numeric.integer.decimal.bifrost-rql");
  assertScoped(tokens, "full", "constant.language.result-detail.bifrost-rql");
  assertScoped(tokens, "; trailing comment", "comment.line.semicolon.bifrost-rql");
  assertScoped(tokens, '"semi;colon"', "string.quoted.double.bifrost-rql");
  const unknown = tokens.find((candidate) =>
    candidate.text.includes("custom_identifier :unexpected true false null 7")
  );
  assert.deepEqual(unknown?.scopes, [scopeName]);
});

void test("highlights registered underscore predicate aliases", async () => {
  const tokens = tokenizeGrammar(await grammar(), "(not_has (call)) (not_kind class)");
  assertScoped(tokens, "not_has", "support.function.predicate.bifrost-rql");
  assertScoped(tokens, "not_kind", "support.function.predicate.bifrost-rql");
});

void test("highlights explain and profile execution controls", async () => {
  const tokens = tokenizeGrammar(await grammar(), "(explain (class)) (profile (call))");
  assertScoped(tokens, "explain", "support.function.wrapper.bifrost-rql");
  assertScoped(tokens, "profile", "support.function.wrapper.bifrost-rql");
});

void test("highlights semantic traversal forms and options", async () => {
  const tokens = tokenizeGrammar(
    await grammar(),
    '(references-of :reference-kinds [field-write] :proof proven :surface external-usages (class :name "Target")) (used-by (class)) (uses (method)) (call-input :parameter-name "payload" (call-sites-to (method))) (callers :depth 2 (method))'
  );
  assertScoped(tokens, "references-of", "support.function.wrapper.bifrost-rql");
  assertScoped(tokens, ":reference-kinds", "variable.parameter.role.bifrost-rql");
  assertScoped(tokens, ":proof", "variable.parameter.role.bifrost-rql");
  assertScoped(tokens, ":surface", "variable.parameter.role.bifrost-rql");
  assertScoped(tokens, "used-by", "support.function.wrapper.bifrost-rql");
  assertScoped(tokens, "uses", "support.function.wrapper.bifrost-rql");
  assertScoped(tokens, "call-input", "support.function.wrapper.bifrost-rql");
  assertScoped(tokens, ":parameter-name", "variable.parameter.role.bifrost-rql");
  assertScoped(tokens, "call-sites-to", "support.function.wrapper.bifrost-rql");
  assertScoped(tokens, "callers", "support.function.wrapper.bifrost-rql");
});

void test("highlights receiver traversal forms and capture options", async () => {
  const tokens = tokenizeGrammar(
    await grammar(),
    "(receiver-targets (call)) (points-to :capture service (call :receiver (capture service))) (member-targets (field-access))"
  );
  assertScoped(tokens, "receiver-targets", "support.function.wrapper.bifrost-rql");
  assertScoped(tokens, "points-to", "support.function.wrapper.bifrost-rql");
  assertScoped(tokens, ":capture", "variable.parameter.role.bifrost-rql");
  assertScoped(tokens, "member-targets", "support.function.wrapper.bifrost-rql");
});
