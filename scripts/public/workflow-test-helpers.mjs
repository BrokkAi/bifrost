import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

export function workflowReader(importMetaUrl) {
  return (relativePath) => readFileSync(new URL(`../${relativePath}`, importMetaUrl), "utf8");
}

export function section(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  assert.notEqual(start, -1, `missing ${startMarker}`);
  const end = endMarker === undefined ? source.length : source.indexOf(endMarker, start);
  assert.notEqual(end, -1, `missing end before ${endMarker}`);
  return source.slice(start, end);
}
