import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import {
  assertNotScoped,
  assertScoped,
  loadTextMateGrammar,
  tokenizeGrammar
} from "./textmate-test-utils";

const extensionRoot = path.resolve(__dirname, "../..");
const policyGrammarPath = path.join(
  extensionRoot,
  "syntaxes",
  "bifrost-rql-policy.tmLanguage.json"
);
const rqlGrammarPath = path.join(extensionRoot, "syntaxes", "bifrost-rql.tmLanguage.json");
const fixturePath = path.join(extensionRoot, "test", "fixtures", "rql-policy", "highlighting.rqlp");
const policyScope = "source.bifrost-rql-policy";
const rqlScope = "source.bifrost-rql";

async function grammar() {
  return loadTextMateGrammar(policyGrammarPath, policyScope, [
    { scopeName: rqlScope, grammarPath: rqlGrammarPath }
  ]);
}

void test("tokenizes policy structure with conservative syntactic scopes", async () => {
  const tokens = tokenizeGrammar(await grammar(), fs.readFileSync(fixturePath, "utf8"));

  assertScoped(
    tokens,
    "; Policy forms use their own grammar while inline selectors embed native RQL.",
    "comment.line.semicolon.bifrost-rql-policy"
  );
  assertScoped(tokens, "policy", "entity.name.function.record.bifrost-rql-policy");
  assertScoped(tokens, ":schema-version", "variable.parameter.keyword.bifrost-rql-policy");
  assertScoped(tokens, "1", "constant.numeric.integer.decimal.bifrost-rql-policy");
  assertScoped(tokens, "No dynamic evaluation", "string.quoted.double.bifrost-rql-policy");
  assertScoped(tokens, "rql", "support.function.embedded.rql.bifrost-rql-policy");
});

void test("includes native RQL scopes only inside inline rql bodies", async () => {
  const tokens = tokenizeGrammar(await grammar(), fs.readFileSync(fixturePath, "utf8"));

  assertScoped(tokens, "language", rqlScope);
  assertScoped(tokens, "language", "support.function.wrapper.bifrost-rql");
  assertScoped(tokens, "call", rqlScope);
  assertScoped(tokens, "call", "entity.name.type.kind.bifrost-rql");
  assertScoped(tokens, ":callee", rqlScope);
  assertNotScoped(tokens, "policy", rqlScope);
  assertNotScoped(tokens, "endpoint", rqlScope);
  assertNotScoped(tokens, "rql-file", rqlScope);
  assertScoped(tokens, "rql-file", "entity.name.function.record.bifrost-rql-policy");
});
