import assert from "node:assert/strict";
import { readFile, rm } from "node:fs/promises";
import { dirname } from "node:path";
import test from "node:test";

import { DEFAULT_MAX_BYTES, DEFAULT_MAX_LINES, initTheme } from "@earendil-works/pi-coding-agent";

import {
  mapToolResult,
  renderToolResult,
  toolLabel,
  toolParameters,
} from "../extensions/mcp-adapter.ts";

initTheme("dark", false);

const plainTheme = {
  fg: (_color, text) => text,
};

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

test("maps MCP text, images, and structured content into model-visible content", async () => {
  const mcpResult = {
    content: [
      { type: "text", text: "rendered summary" },
      { type: "image", data: "aGVsbG8=", mimeType: "image/png" },
      { type: "resource", resource: { uri: "file:///ignored" } },
    ],
    structuredContent: { matches: [{ file: "src/lib.rs", line: 12 }] },
  };

  const result = await mapToolResult("search_symbols", mcpResult);

  assert.match(result.content[0].text, /^rendered summary/);
  assert.match(result.content[0].text, /"file": "src\/lib.rs"/);
  assert.deepEqual(result.content[1], { type: "image", data: "aGVsbG8=", mimeType: "image/png" });
  assert.deepEqual(result.details, {});
});

test("keeps a text-only success unchanged", async () => {
  const result = await mapToolResult("get_summaries", {
    content: [{ type: "text", text: "summary" }],
  });
  assert.deepEqual(result.content, [{ type: "text", text: "summary" }]);
});

test("turns MCP error results into failed Pi tool executions", async () => {
  await assert.rejects(
    mapToolResult("query_code", {
      isError: true,
      content: [{ type: "text", text: "invalid query at line 2" }],
    }),
    /Bifrost tool query_code failed: invalid query at line 2/,
  );
});

test("caps oversized MCP errors after their full tool prefix and saves complete diagnostics", async (t) => {
  const oversized = `${"failure".repeat(12)}\n`.repeat(DEFAULT_MAX_LINES + 1000);
  const fullError = `Bifrost tool query_code failed: ${oversized.trim()}`;
  let error;
  try {
    await mapToolResult("query_code", {
      isError: true,
      content: [{ type: "text", text: oversized }],
    });
  } catch (cause) {
    error = cause;
  }

  assert.ok(error instanceof Error);
  assert.ok(Buffer.byteLength(error.message, "utf8") <= DEFAULT_MAX_BYTES);
  assert.ok(error.message.split("\n").length <= DEFAULT_MAX_LINES);
  const pathMatch = error.message.match(/Full output: ([^\]]+)]$/);
  assert.ok(pathMatch);
  const fullOutputPath = pathMatch[1];
  t.after(() => rm(dirname(fullOutputPath), { recursive: true }));
  assert.equal(await readFile(fullOutputPath, "utf8"), fullError);
});

test("caps the model result and saves complete output in a dedicated overflow file", async (t) => {
  const oversized = `${"x".repeat(80)}\n`.repeat(DEFAULT_MAX_LINES + 1000);
  const overflowOnly = `${oversized}OVERFLOW_ONLY`;
  const fullText = `${oversized}\n\n${overflowOnly}`;
  const result = await mapToolResult("query_code", {
    content: [{ type: "text", text: oversized }, { type: "text", text: overflowOnly }],
  });
  const text = result.content[0].text;
  const fullOutputPath = result.details.fullOutputPath;
  t.after(() => rm(dirname(fullOutputPath), { recursive: true }));

  assert.equal(result.details.truncation.truncated, true);
  assert.match(text, /Output truncated at Pi's 2,000-line\/50KB model limit/);
  assert.match(text, new RegExp(fullOutputPath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.ok(Buffer.byteLength(text, "utf8") <= DEFAULT_MAX_BYTES);
  assert.ok(text.split("\n").length <= DEFAULT_MAX_LINES);
  assert.equal(await readFile(fullOutputPath, "utf8"), fullText);

  const tuiOutput = renderToolResult(
    result,
    { expanded: false, isPartial: false },
    plainTheme,
  ).render(80).join("\n");
  assert.match(tuiOutput, new RegExp(fullOutputPath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.match(tuiOutput, /to expand/);
  assert.doesNotMatch(tuiOutput, /Output truncated at Pi's/);

  const expandedTuiOutput = renderToolResult(
    result,
    { expanded: true, isPartial: false },
    plainTheme,
  ).render(80).join("\n");
  assert.doesNotMatch(expandedTuiOutput, /OVERFLOW_ONLY/);
  assert.match(await readFile(fullOutputPath, "utf8"), /OVERFLOW_ONLY$/);
});

test("keeps the TUI compact until the user expands tool output", () => {
  const text = Array.from({ length: 12 }, (_, index) => `result ${index + 1}`).join("\n");
  const result = { content: [{ type: "text", text }], details: {} };

  const collapsed = renderToolResult(
    result,
    { expanded: false, isPartial: false },
    plainTheme,
  ).render(80);
  const expanded = renderToolResult(
    result,
    { expanded: true, isPartial: false },
    plainTheme,
  ).render(80);

  assert.equal(collapsed.length, 6);
  assert.match(collapsed.join("\n"), /to expand/);
  assert.doesNotMatch(collapsed.join("\n"), /result 1(?:\n|$)/);
  assert.match(collapsed.join("\n"), /result 12/);
  assert.match(expanded.join("\n"), /result 1/);
  assert.match(expanded.join("\n"), /result 12/);

  const wrappedCollapsed = renderToolResult(
    result,
    { expanded: false, isPartial: false },
    plainTheme,
  ).render(8);
  assert.equal(wrappedCollapsed.length, 6);
});
