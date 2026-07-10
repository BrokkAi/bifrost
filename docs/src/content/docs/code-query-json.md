---
title: JSON CodeQuery
description: Use the canonical JSON representation for Bifrost's query_code engine.
---

JSON `CodeQuery` is the canonical machine-facing representation accepted by Bifrost's `query_code` tool. MCP hosts and the Python client send this shape directly. The RQL REPL prints the same representation with `:json`.

Version 1 queries normalized syntactic structure. It does not traverse the call graph, resolve types or aliases, or perform control-flow or data-flow analysis. Those are possible future query facets, not fields accepted by the current schema.

## Minimal Query

<!-- code-query-test:json:minimal-call -->
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

The `match` object is the root pattern. It must constrain at least one of `kind`, `name`, or `text`; a capture-only or wildcard root would match nearly every normalized fact in the workspace and is rejected.

## Top-Level Fields

| Field | Shape | Meaning |
| --- | --- | --- |
| `schema_version` | integer | Optional. Omit it for version 1 or pass `1` explicitly. Other versions are rejected. |
| `match` | pattern | Required root pattern. |
| `where` | string array | Optional project-relative globs. Absolute paths or globs inside the active workspace are normalized by MCP and CLI entrypoints. |
| `languages` | string array | Optional language labels such as `python`, `typescript`, `cpp`, or `csharp`. Empty means every structural adapter. |
| `inside` | pattern | Require the root match to be lexically inside a matching ancestor. |
| `not_inside` | pattern | Reject the root match when a matching ancestor exists. |
| `limit` | integer | Maximum returned matches. Defaults to `100`; valid range is `1` through `1000`. |
| `result_detail` | string | `compact` by default or `full` for stable IDs and precise ranges. |

Unknown fields are rejected rather than ignored.

## Pattern Fields

A pattern combines all supplied constraints with logical AND.

| Field | Shape | Meaning |
| --- | --- | --- |
| `kind` | string or string array | Match one normalized kind or a union. Every entry is subtype-aware. |
| `not_kind` | string or string array | Exclude matching kinds and their subtypes. It never helps candidate pruning. |
| `name` | string or `{ "regex": string }` | Match a normalized name exactly or by Rust regular expression. |
| `text` | `{ "regex": string }` | Match parser-backed source text by Rust regular expression. There is no exact string shorthand. |
| `capture` | string | Return this node or role target under the supplied capture label. |
| `has` | pattern | Require some structural descendant to match. |
| `not_has` | pattern | Reject the node if any structural descendant matches. It never helps candidate pruning. |

Nested role targets may be capture-only or otherwise unconstrained. The root `match` may not.

### Exact And Regex Predicates

An exact name uses string shorthand:

```json
{ "name": "handler" }
```

A name regex nests the `regex` key under `name`:

```json
{ "name": { "regex": "^(eval|exec)$" } }
```

Source text always uses the regex object:

```json
{ "text": { "regex": "^safe_eval\\(" } }
```

Fields such as `name_regex` and `text_regex` do not exist. To express exact source text, use an anchored, escaped regular expression.

## Normalized Kind Hierarchy

Kinds are language-neutral. Adapters map grammar-specific nodes such as Java `method_invocation`, Python `call`, and TypeScript `call_expression` to the same `call` kind.

Kind matching is subtype-aware:

```text
declaration
├── callable
│   ├── function
│   ├── method
│   ├── constructor
│   └── lambda
├── class
└── import

literal
├── string_literal
├── numeric_literal
├── boolean_literal
└── null_literal
```

The remaining kinds are independent leaves: `call`, `assignment`, `field_access`, `identifier`, `return`, `throw`, `catch`, `if`, `loop`, and `decorator`.

Therefore `{"kind":"callable"}` matches functions, methods, constructors, and lambdas, and `{"kind":"literal"}` matches every normalized literal subtype. There is deliberately no exact-kind operator. Use a leaf kind or subtract unwanted subtypes with `not_kind`.

## Roles

Roles are normalized edges from one structural fact to a related node or source span. The parent pattern must declare a kind for which the role is valid.

| Role | Cardinality | Valid parent kinds | Meaning |
| --- | --- | --- | --- |
| `callee` | one | `call` | Terminal call target, such as `run` in `service.run()`. |
| `receiver` | one | `call` | Receiver or qualifying scope, such as `service`. |
| `args` | ordered list | `call` | Positional argument patterns. |
| `kwargs` | name-to-pattern map | `call` | Named or keyword argument values. |
| `left`, `right` | one each | `assignment` | Assignment target and assigned value. |
| `module` | one | `import`, `declaration` | Imported module or binding target. |
| `decorators` | list | callable or class-like declarations | Decorators, annotations, or attributes. |
| `object`, `field` | one each | `field_access` | Object and terminal field sides of member access. |

Each `args` pattern must match a distinct positional argument in source order, but the matches need not be contiguous and do not assert exact arity. For exact positions or arity, narrow the surrounding source shape in a follow-up query; version 1 has no positional-index operator.

`kwargs` support is adapter-specific. Python, PHP, Scala, C#, and Ruby expose normalized named arguments; languages without that role return a capability diagnostic.

## Captures And Results

`capture` adds a named entry to the result. Captures include their text and start line in compact mode; full mode also includes their normalized kind and byte/line/column range when available.

The same capture label may appear more than once in a query. Every occurrence must bind exactly the same source text, allowing equality constraints such as “both arguments use the same expression.”

Each result also includes the matched path, language, kind, line range, a bounded text snippet, and a best-effort `enclosing_symbol`. `enclosing_symbol` describes the root match's nearest indexed declaration; it is not another implicit capture.

With `result_detail: "full"`, results additionally include:

- a deterministic match `id`
- `node_range` byte and 1-based line/column bounds
- capture ranges and kinds
- `decorator_ranges` for matched declarations
- `decorated_range`, the union of the declaration and its decorators

## Containment And Descendants

`inside` and `not_inside` inspect lexical ancestors of the root match. `has` and `not_has` inspect descendants of the pattern on which they appear.

<!-- code-query-test:json:containment -->
```json
{
  "match": {
    "kind": "call",
    "callee": { "name": "execute" },
    "capture": "call"
  },
  "inside": {
    "kind": ["function", "method"],
    "name": { "regex": "Controller$" },
    "capture": "handler"
  },
  "not_inside": {
    "kind": "callable",
    "name": { "regex": "^(test_|mock_)" }
  }
}
```

<!-- code-query-test:json:negative-descendant -->
```json
{
  "match": {
    "kind": "function",
    "has": {
      "kind": "call",
      "callee": { "name": "open" }
    },
    "not_has": {
      "kind": "call",
      "callee": { "name": "close" }
    }
  }
}
```

## Copy-Paste Examples

### Receiver, Positional Arguments, Keyword Arguments, And Captures

<!-- code-query-test:json:receiver-args-kwargs -->
```json
{
  "languages": ["python"],
  "match": {
    "kind": "call",
    "receiver": { "name": "subprocess" },
    "callee": { "name": "run" },
    "args": [
      { "capture": "command" }
    ],
    "kwargs": {
      "shell": {
        "kind": "boolean_literal",
        "capture": "shell_value"
      }
    }
  },
  "result_detail": "full"
}
```

### Imports By Module

<!-- code-query-test:json:import -->
```json
{
  "match": {
    "kind": "import",
    "module": { "name": "pickle", "capture": "module" }
  }
}
```

Module names are normalized from syntax, not resolved through aliases or re-exports.

### Assignments To Literals

<!-- code-query-test:json:assignment -->
```json
{
  "match": {
    "kind": "assignment",
    "left": { "name": "password" },
    "right": {
      "kind": "string_literal",
      "capture": "value"
    }
  }
}
```

### Decorators And Annotations

<!-- code-query-test:json:decorator -->
```json
{
  "match": {
    "kind": "callable",
    "decorators": [
      { "name": { "regex": "^(route|GetMapping)$" }, "capture": "decorator" }
    ]
  },
  "result_detail": "full"
}
```

Adapters normalize Python decorators, Java annotations, PHP/C# attributes, and equivalent supported forms into the `decorators` role.

### Kind Unions And Exclusions

<!-- code-query-test:json:kind-union -->
```json
{
  "match": {
    "kind": "callable",
    "not_kind": ["constructor", "lambda"],
    "name": { "regex": "^(load|save)" }
  }
}
```

The subtractive form above selects named functions and methods. A direct union such as `"kind": ["function", "method"]` expresses the same kind set when no broader callable subtype is wanted.

### Path And Language Scoping

<!-- code-query-test:json:scope -->
```json
{
  "where": ["src/**/*.ts", "src/**/*.tsx"],
  "languages": ["typescript"],
  "match": {
    "kind": "call",
    "callee": { "name": { "regex": "^(eval|exec)$" } },
    "args": [
      { "capture": "argument" }
    ]
  },
  "limit": 25
}
```

## Planner And Capability Diagnostics

The planner may skip a file only when a positive literal anchor proves that the file cannot match. Exact `name` predicates and `kwargs` keys in positive `match`, `inside`, `has`, and role positions can become source anchors. Regex predicates, `not_kind`, `not_has`, and `not_inside` never prune; they are checked only by the structural verifier.

Kind-only, text-regex, and name-regex queries may scan many files because they provide no safe literal anchor. Large broad queries return guidance diagnostics suggesting `where`, `languages`, or exact names.

A query is validated against the global normalized schema first. Each language adapter then reports unsupported kinds or roles separately. A query can therefore be valid but still produce a diagnostic such as:

```text
structural adapter for javascript does not support role(s): kwargs
```

That diagnostic means the affected language was not searched for that feature; it does not silently claim that no matches exist.

## Limits And Validation Errors

Version 1 enforces these budgets:

| Budget | Maximum |
| --- | --- |
| Results | `1000` |
| `where` globs | `128` entries, `1024` bytes each |
| Language filters | `32` |
| Pattern nodes | `256` |
| Pattern nesting | `64` levels |
| Kinds in one union/exclusion | `32` |
| Entries in one role list | `64` |
| Named arguments | `64`; names at most `128` bytes |
| Name/text regex source | `4096` bytes |
| Capture label | `128` bytes |

Validation failures carry a JSON path so agents can correct the precise field. For example, this misspelling:

```json
{
  "match": {
    "kind": "call",
    "calee": { "name": "eval" }
  }
}
```

reports an error at `match.calee` and lists the accepted pattern fields. Invalid regexes report paths such as `match.callee.name.regex`; malformed kind arrays include the failing index, such as `match.kind[1]`.

## RQL Interoperability

The same semantic query can be written in [Rune Query Language](/rune-query-language/) while exploring interactively, then inspected with `:json`. JSON and RQL are peer frontends over `CodeQuery`; neither has separate matching semantics.
