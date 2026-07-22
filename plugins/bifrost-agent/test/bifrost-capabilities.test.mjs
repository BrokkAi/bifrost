import assert from "node:assert/strict";
import test from "node:test";

import {
  BIFROST_CAPABILITY_IDS,
  DEFAULT_BIFROST_CAPABILITIES,
  capabilityForTool,
  normalizeCapabilities,
  piToolName,
  serverToolsetExpression,
  toolBelongsToSelection,
} from "../extensions/bifrost-capabilities.ts";

test("normalizes capability order and builds existing Bifrost toolsets", () => {
  assert.deepEqual(
    normalizeCapabilities(["text", "symbols", "quality", "symbols", "unknown"]),
    ["symbols", "quality", "text"],
  );
  assert.equal(serverToolsetExpression(["symbols"]), "symbol|slopcop");
  assert.equal(
    serverToolsetExpression(DEFAULT_BIFROST_CAPABILITIES),
    "symbol|extended|slopcop",
  );
  assert.equal(
    serverToolsetExpression(["symbols", "query", "files", "quality", "git", "transforms"]),
    "symbol|extended|slopcop",
  );
  assert.equal(serverToolsetExpression([]), "");
});

test("classifies broad extended tools into Pi capabilities", () => {
  assert.equal(capabilityForTool("analyze_commit"), "symbols");
  assert.equal(toolBelongsToSelection("analyze_commit", ["symbols"]), true);
  assert.equal(toolBelongsToSelection("compute_cyclomatic_complexity", ["symbols"]), false);
  assert.equal(capabilityForTool("query_code"), "query");
  assert.equal(capabilityForTool("list_files"), "files");
  assert.equal(capabilityForTool("get_git_log"), "git");
  assert.equal(capabilityForTool("jq"), "transforms");
  assert.equal(toolBelongsToSelection("jq", ["query"]), false);
  assert.equal(toolBelongsToSelection("query_code", ["query"]), true);
});

test("uses one stable namespace for every Pi-visible tool", () => {
  assert.equal(piToolName("query_code"), "bifrost_query_code");
  assert.equal(piToolName("jq"), "bifrost_jq");
});

test("does not advertise Semantic Search as a Pi capability", () => {
  assert.equal(BIFROST_CAPABILITY_IDS.includes("semantic"), false);
  assert.equal(capabilityForTool("semantic_search"), undefined);
  assert.equal(toolBelongsToSelection("semantic_search", BIFROST_CAPABILITY_IDS), false);
});
