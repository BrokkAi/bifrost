const path = require("node:path");
const test = require("node:test");
const {
  assertScoped,
  loadTextMateGrammar,
  tokenizeGrammar
} = require("./textmate-test-utils");

const extensionRoot = path.resolve(__dirname, "..");
const grammarPath = path.join(extensionRoot, "syntaxes", "bifrost-rune-ir.tmLanguage.json");
const scopeName = "source.bifrost-rune-ir";

async function grammar() {
  return loadTextMateGrammar(grammarPath, scopeName);
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
  const tokens = tokenizeGrammar(loaded, source.join("\n"));

  assertScoped(tokens, "; Rune IR for greet (rust)", "comment.line.semicolon.bifrost-rune-ir");
  assertScoped(tokens, "function", "entity.name.type.kind.bifrost-rune-ir");
  assertScoped(tokens, "callee", "variable.parameter.role.bifrost-rune-ir");
  assertScoped(tokens, "args", "variable.parameter.role.bifrost-rune-ir");
  assertScoped(tokens, ":range", "variable.other.property.bifrost-rune-ir");
  assertScoped(tokens, "\"greet\"", "string.quoted.double.bifrost-rune-ir");
  assertScoped(tokens, "42", "constant.numeric.integer.decimal.bifrost-rune-ir");
  assertScoped(tokens, "truncated", "invalid.deprecated.truncated.bifrost-rune-ir");
});
