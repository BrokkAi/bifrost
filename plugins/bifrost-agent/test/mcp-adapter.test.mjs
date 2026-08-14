import assert from "node:assert/strict";
import { readFile, rm } from "node:fs/promises";
import { dirname } from "node:path";
import test from "node:test";

import { DEFAULT_MAX_BYTES, DEFAULT_MAX_LINES, initTheme } from "@earendil-works/pi-coding-agent";

import {
  createBoundedToolError,
  mapToolResult,
  renderToolCall,
  renderToolResult,
  sanitizeTerminalLine,
  sanitizeTerminalText,
  toolLabel,
  toolParameters,
} from "../extensions/mcp-adapter.ts";

initTheme("dark", false);

const plainTheme = {
  bold: (text) => text,
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

test("renders concise tool arguments and expands their complete JSON", () => {
  const args = {
    patterns: ["Widget", "Widget\nFactory"],
    include_tests: true,
    note: "first line\nsecond line",
  };
  const collapsed = renderToolCall("bifrost_search_symbols", args, false, plainTheme).render(140);
  const expanded = renderToolCall("bifrost_search_symbols", args, true, plainTheme).render(140);

  assert.deepEqual(collapsed, [
    "bifrost_search_symbols patterns: Widget, Widget Factory  include_tests: true  note: first line second line",
  ]);
  const expandedText = expanded.map((line) => line.trimEnd()).join("\n");
  assert.match(expandedText, /^bifrost_search_symbols\n\{/);
  assert.match(expandedText, /"patterns": \[/);
});

test("sanitizes terminal controls before applying trusted TUI styling", () => {
  const osc52 = "\u001b]52;c;U0VDUkVU\u0007";
  const unsafeText = `before${osc52}after\u0001`;
  const styledTheme = {
    bold: (text) => text,
    fg: (_color, text) => `\u001b[32m${text}\u001b[0m`,
  };

  assert.equal(sanitizeTerminalText(unsafeText), "beforeafter\\u0001");
  assert.equal(sanitizeTerminalText("\u001b[31mred\u001b[0m\u007f"), "red\\u007f");
  assert.equal(sanitizeTerminalText("\u009b31mred\u009b0m"), "red");
  assert.equal(sanitizeTerminalText("\u009d52;c;data\u009c"), "\\u009d52;c;data\\u009c");
  assert.equal(sanitizeTerminalText("lone\u001b"), "lone\\u001b");
  assert.equal(sanitizeTerminalLine("first\nsecond"), "first\\nsecond");
  assert.equal(toolLabel({ name: "unsafe", annotations: { title: unsafeText } }), "beforeafter\\u0001");
  assert.equal(toolLabel({ name: "safe_fallback", annotations: { title: osc52 } }), "Safe Fallback");

  const collapsedCall = renderToolCall(
    "bifrost_search_symbols",
    { [`unsafe\nname`]: unsafeText },
    false,
    styledTheme,
  ).render(160).join("\n");
  const expandedCall = renderToolCall(
    "bifrost_search_symbols",
    { note: unsafeText },
    true,
    styledTheme,
  ).render(160).join("\n");
  const renderedResult = renderToolResult(
    { content: [{ type: "text", text: unsafeText }], details: {} },
    { expanded: false, isPartial: false },
    styledTheme,
  ).render(160).join("\n");

  for (const rendered of [collapsedCall, expandedCall, renderedResult]) {
    assert.doesNotMatch(rendered, /\u001b\]52/);
    assert.doesNotMatch(rendered, /\u0007|\u0001/);
    assert.match(rendered, /\u001b\[32m/);
  }
  assert.match(collapsedCall, /unsafe\\nname: beforeafter\\u0001/);
  assert.match(renderedResult, /beforeafter\\u0001/);
});

test("bounds sanitized errors while preserving raw diagnostics", async (t) => {
  const rawError = `Bifrost failed: ${"\u0001".repeat(10_000)}`;
  const error = await createBoundedToolError(rawError);
  const pathMatch = error.message.match(/Full output: ([^\]]+)]$/);

  assert.ok(pathMatch);
  assert.doesNotMatch(error.message, /\u0001/);
  assert.ok(Buffer.byteLength(error.message, "utf8") <= DEFAULT_MAX_BYTES);
  assert.ok(error.message.split("\n").length <= DEFAULT_MAX_LINES);
  t.after(() => rm(dirname(pathMatch[1]), { recursive: true }));
  assert.equal(await readFile(pathMatch[1], "utf8"), rawError);
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
  assert.match(tuiOutput, /more visual lines/);
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

  assert.equal(collapsed.length, 7);
  assert.equal(collapsed[0], "");
  assert.equal(collapsed[1].trimEnd(), "result 1");
  assert.doesNotMatch(collapsed.join("\n"), /result 12/);
  assert.match(collapsed.at(-1), /7 more visual lines/);
  assert.match(collapsed.at(-1), /to expand/);
  assert.equal(expanded[0].trim(), "");
  assert.match(expanded.join("\n"), /result 1/);
  assert.match(expanded.join("\n"), /result 12/);

  const wrappedCollapsed = renderToolResult(
    result,
    { expanded: false, isPartial: false },
    plainTheme,
  ).render(8);
  assert.equal(wrappedCollapsed.length, 7);
  assert.equal(wrappedCollapsed[0], "");
  assert.match(wrappedCollapsed.at(-1), /^\.\.\. \(/);
});
