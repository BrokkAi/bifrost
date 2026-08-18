import assert from "node:assert/strict";
import test from "node:test";

import { toolInventoryFromMarkdown, unavailableSkillTools } from "./skill-tool-contract.mjs";

test("extracts only Bifrost tools from portable skill tool tables", () => {
  const skill = `
## Tools

| Goal | Tool |
|---|---|
| Find symbols | \`search_symbols\` |
| Find related files | \`most_relevant_files\` |
| Find paths | Host file search such as \`rg --files\` |
`;

  assert.deepEqual(toolInventoryFromMarkdown(skill), ["most_relevant_files", "search_symbols"]);
});

test("reports a portable skill tool absent from the server tools/list result", () => {
  const skill = `
## Tools

| Tool | Purpose |
|---|---|
| \`search_symbols\` | Find symbols |
| \`removed_lookup\` | Stale skill expectation |
`;
  const serverToolNames = new Set(["search_symbols", "get_symbol_sources"]);
  const skillToolNames = toolInventoryFromMarkdown(skill);

  assert.deepEqual(unavailableSkillTools(skillToolNames, serverToolNames), ["removed_lookup"]);
});
