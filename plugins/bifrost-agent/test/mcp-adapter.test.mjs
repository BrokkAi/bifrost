import assert from "node:assert/strict";
import test from "node:test";

import { DEFAULT_MAX_BYTES, DEFAULT_MAX_LINES } from "@earendil-works/pi-coding-agent";

import {
  mapToolResult,
  toolLabel,
  toolParameters,
} from "../extensions/mcp-adapter.ts";

test("preserves discovered JSON Schema without rebuilding it", () => {
  const inputSchema = {
    type: "object",
    properties: {
      request: { $ref: "#/$defs/request" },
    },
    required: ["request"],
    additionalProperties: false,
    $defs: {
      request: {
        oneOf: [
          { type: "object", properties: { kind: { const: "symbol" } } },
          { type: "object", properties: { kind: { const: "file" } } },
        ],
      },
    },
  };

  const parameters = toolParameters({ name: "query_code", inputSchema });

  for (const [key, value] of Object.entries(inputSchema)) {
    assert.deepEqual(parameters[key], value);
  }
});

test("uses an advertised title or a readable tool name as the label", () => {
  assert.equal(toolLabel({ name: "search_symbols", annotations: { title: "Symbol Search" } }), "Symbol Search");
  assert.equal(toolLabel({ name: "search_symbols" }), "Search Symbols");
});

test("maps MCP text, images, and structured content into model-visible content", () => {
  const mcpResult = {
    content: [
      { type: "text", text: "rendered summary" },
      { type: "image", data: "aGVsbG8=", mimeType: "image/png" },
      { type: "resource", resource: { uri: "file:///ignored" } },
    ],
    structuredContent: { matches: [{ file: "src/lib.rs", line: 12 }] },
  };

  const result = mapToolResult("search_symbols", mcpResult);

  assert.match(result.content[0].text, /^rendered summary/);
  assert.match(result.content[0].text, /"file": "src\/lib.rs"/);
  assert.deepEqual(result.content[1], { type: "image", data: "aGVsbG8=", mimeType: "image/png" });
  assert.equal(result.details.mcpResult, mcpResult);
  assert.equal(result.details.truncated, false);
});

test("keeps a text-only success unchanged", () => {
  const result = mapToolResult("get_summaries", {
    content: [{ type: "text", text: "summary" }],
  });
  assert.deepEqual(result.content, [{ type: "text", text: "summary" }]);
});

test("turns MCP error results into failed Pi tool executions", () => {
  assert.throws(
    () => mapToolResult("query_code", {
      isError: true,
      content: [{ type: "text", text: "invalid query at line 2" }],
    }),
    /Bifrost tool query_code failed: invalid query at line 2/,
  );
});

test("truncates combined model-visible output within Pi line and byte limits", () => {
  const oversized = `${"x".repeat(80)}\n`.repeat(DEFAULT_MAX_LINES + 1000);
  const result = mapToolResult("query_code", {
    content: [{ type: "text", text: oversized }, { type: "text", text: oversized }],
  });
  const text = result.content[0].text;

  assert.equal(result.details.truncated, true);
  assert.match(text, /Output truncated: showing/);
  assert.doesNotMatch(text, /tool details/);
  assert.ok(Buffer.byteLength(text, "utf8") <= DEFAULT_MAX_BYTES);
  assert.ok(text.split("\n").length <= DEFAULT_MAX_LINES);
  assert.equal(result.details.mcpResult.content[0].text, oversized);
});
