---
title: JSON AstQuery
description: Use the canonical JSON representation for Bifrost's search_ast structural query engine.
---

JSON `AstQuery` is the canonical representation accepted by Bifrost's `search_ast` structural query engine. It is the stable tool-facing shape used over MCP and the form printed by `:json` inside the REPL.

JSON itself is not a Bifrost query language. It is the serialization format for the `AstQuery` model that every query frontend must produce before execution.

## Minimal Query

```json
{
  "schema_version": 1,
  "match": {
    "kind": "call",
    "callee": {
      "name": "eval"
    }
  }
}
```

The `match` object is the root pattern. It must constrain at least one of `kind`, `name`, or `text` so the engine does not run a wildcard query over every normalized fact in the workspace.

## Query Fields

Top-level fields control workspace scope and result shape:

| Field | Purpose |
| --- | --- |
| `schema_version` | Schema version. Version `1` is current. |
| `match` | Root pattern to search for. |
| `where` | Optional workspace-relative glob list. Empty means every file with a structural adapter. |
| `languages` | Optional language filter. Empty means every supported structural adapter. |
| `inside` | Optional container pattern the root match must be lexically inside. |
| `not_inside` | Optional container pattern the root match must not be inside. |
| `limit` | Maximum result count. Defaults to `100`; maximum is `1000`. |
| `result_detail` | `compact` or `full`. Defaults to `compact`. |

## Pattern Fields

Patterns match normalized facts and their role edges:

| Field | Purpose |
| --- | --- |
| `kind` | A normalized kind or list of kinds. Kind matching is subtype-aware. |
| `not_kind` | A normalized kind or list of kinds to exclude. |
| `name` | Exact name predicate. |
| `name_regex` | Regular expression over the normalized name. |
| `text` | Exact source-text predicate. |
| `text_regex` | Regular expression over the source text. |
| `capture` | Capture the matched node under a name. |
| `has` | Require a descendant matching another pattern. |
| `not_has` | Reject matches with a descendant matching another pattern. |

Role fields constrain language-neutral child relationships:

| Role | Typical use |
| --- | --- |
| `callee` | Callee of a call. |
| `receiver` | Receiver of a method call or member access. |
| `args` | Ordered positional argument patterns. |
| `kwargs` | Named argument patterns keyed by argument name. |
| `left`, `right` | Assignment or binary-like sides. |
| `module` | Imported module target. |
| `decorators` | Decorator or annotation patterns. |
| `object`, `field` | Object and field sides of field access. |

## Example

```json
{
  "schema_version": 1,
  "where": ["src/**/*.py"],
  "languages": ["python"],
  "match": {
    "kind": "call",
    "callee": {
      "name_regex": "eval|exec"
    },
    "args": [
      {
        "capture": "argument"
      }
    ]
  },
  "inside": {
    "kind": "function",
    "name": "handler"
  },
  "limit": 25,
  "result_detail": "full"
}
```

The same query can be written in [RQL](/search-ast-repl/) while exploring interactively, then inspected with `:json` before moving it into an MCP client or script.
