---
title: JSON CodeQuery
description: Use the canonical JSON representation for Bifrost's query_code engine.
---

JSON `CodeQuery` is the canonical machine-facing representation accepted by Bifrost's `query_code` tool. MCP hosts and the Python client send this shape directly. The RQL REPL prints the same representation with `:json`.

Version 2 starts with normalized syntactic structure and can apply typed semantic steps for enclosing declarations, resolved call edges and direct call-site inputs, direct project import edges, indexed type hierarchies, declaration ownership, and bounded receiver provenance in Java, JavaScript, and TypeScript. It does not infer override families, resolve general aliases, or perform control-flow, taint, or general data-flow analysis.

## Minimal Query

<!-- code-query-test:json:minimal-call -->
```json
{
  "schema_version": 2,
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
| `schema_version` | integer | Optional. Omit it for version 2 or pass `2` explicitly. Other versions are rejected. |
| `match` | pattern | Required root pattern. |
| `where` | string array | Optional project-relative globs. Absolute paths or globs inside the active workspace are normalized by MCP and CLI entrypoints. |
| `languages` | string array | Optional language labels such as `python`, `typescript`, `cpp`, or `csharp`. Empty means every structural adapter. |
| `inside` | pattern | Require the root match to be lexically inside a matching ancestor. |
| `not_inside` | pattern | Reject the root match when a matching ancestor exists. |
| `steps` | step array | Ordered typed transformations applied after structural matching. At most `16`. |
| `limit` | integer | Maximum terminal results after pipeline deduplication. Defaults to `100`; valid range is `1` through `1000`. |
| `result_detail` | string | `compact` by default or `full` for stable IDs and precise ranges. |
| `execution_mode` | string | `results` by default, `explain` for planning without execution, or `profile` for results plus opt-in measurements. |

Unknown fields are rejected rather than ignored.

`execution_mode` is a root-only output control, like `limit` and `result_detail`. It cannot appear inside a `union`, `intersect`, or `except` operand. Ordinary `results` mode preserves the established result shape; the other modes return versioned report objects described in [Explain and Profile CodeQuery](/code-query-explain-profile/).

When calling `query_code`, MCP clients may instead send a tool-call envelope such as `{ "query_file": "queries/audit.json" }`. That selector is not a `CodeQuery` field and must not be written inside the JSON file itself: the file contains the complete canonical query shown in this reference. The same tool-call input accepts `.rql` files, which lower through RQL before validation.

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

Each `args` pattern must match a distinct positional argument in source order, but the matches need not be contiguous and do not assert exact arity. For exact positions or arity, narrow the surrounding source shape in a follow-up query; version 2 has no positional-index operator.

`kwargs` support is adapter-specific. Python, PHP, Scala, C#, and Ruby expose normalized named arguments; languages without that role return a capability diagnostic.

## Captures And Results

`capture` adds a named entry to the result. Captures include their text and start line in compact mode; full mode also includes their normalized kind and byte/line/column range when available.

The same capture label may appear more than once in a query. Every occurrence must bind exactly the same source text, allowing equality constraints such as “both arguments use the same expression.”

The response contains a `results` array. Every item has a `result_type`: `structural_match`, `declaration`, `reference_site`, `call_site`, `expression_site`, `receiver_analysis`, or `file`. A query without steps returns structural matches with path, language, kind, line range, a bounded text snippet, captures, and a best-effort `enclosing_symbol`.

With `result_detail: "full"`, results additionally include:

- a deterministic match `id`
- `node_range` byte and 1-based line/column bounds
- capture ranges and kinds
- `decorator_ranges` for matched declarations
- `decorated_range`, the union of the declaration and its decorators

Every derived result includes `provenance`. Each provenance path records the original structural seed and every ordered step result. Declaration-returning reference steps additionally record the exact proving reference site under `via`. Compact mode keeps minimal identities; full mode adds stable IDs and precise ranges. At most sixteen paths are retained per terminal result, with `provenance_truncated: true` when more paths converge.

For completeness claims, result metadata is mandatory: inspect diagnostics, require `truncated: false`, distinguish `proven` from `unproven` graph edges, and check every derived result's `provenance_truncated` field. [Agent Result Safety](/agent-result-safety/) turns those fields into an explicit decision rule.

## Typed Set Composition

At every query-plan node, use exactly one source field: `match`, `union`, `intersect`, or `except`. Set fields contain between two and sixteen complete child plans. Every child must end in exactly the same typed domain; Bifrost rejects incompatible branches before workspace execution with a path such as `union[1].steps[0]`.

```json
{
  "union": [
    {"match":{"kind":"class","name":"Legacy"},"steps":[{"op":"enclosing_decl"}]},
    {"match":{"kind":"class","name":"Replacement"},"steps":[{"op":"enclosing_decl"}]}
  ],
  "steps": [{"op":"file_of"}]
}
```

`union` retains the first appearance of each exact typed endpoint in branch order. `intersect` retains endpoints present in every branch, in the first branch's order. `except` retains first-branch endpoints absent from every later branch. Endpoint identity comes from structured ranges and declaration/site identities, never rendered text.

Union and intersection merge at most sixteen provenance traces in branch order. A trace or diagnostic inside composition includes a zero-based `branch` path; plain leaf queries omit it. Except retains provenance only from its positive first branch. Root-only `limit`, `result_detail`, `execution_mode`, and `schema_version` fields cannot appear inside operands, while structural `where`, `languages`, `inside`, and `not_inside` belong inside the branch containing `match`.

The public `limit` applies after the complete root set and common suffix. Execution budgets are shared across the request and fairly reserve work for later immediate operands. An incomplete operand sets `truncated: true` and produces a branch-labeled diagnostic rather than claiming a complete set. See the executable [Typed Set Composition](/code-query-tutorials/set-composition/) cookbook.

## Typed Pipeline Steps

Steps execute in array order and are validated before the workspace is searched:

| Operation | Input | Output | Meaning |
| --- | --- | --- | --- |
| `enclosing_decl` | structural match | declaration | Smallest non-synthetic indexed declaration containing the exact match range, inclusive of a matched declaration itself. |
| `references_of` | declaration | reference site | Exact structured source sites targeting the declaration. |
| `used_by` | declaration | declaration | Smallest exact declaration enclosing each matching site. |
| `uses` | declaration | declaration | Exact indexed declarations referenced by this semantic owner. |
| `callers` | declaration | declaration | Resolved incoming call edges; accepts positive `depth` and optional `proof`. |
| `callees` | declaration | declaration | Resolved outgoing call edges; accepts positive `depth` and optional `proof`. |
| `call_sites_to` | declaration | call site | Structured incoming sites; accepts optional `proof`. |
| `call_sites_from` | declaration | call site | Structured outgoing sites; accepts optional `proof`. |
| `call_input` | call site | expression site | Direct receiver or formal-parameter input selected by exactly one selector. |
| `receiver_targets` | structural match, reference site, call site, or expression site | receiver analysis | Receiver values extracted from a call/member site or supplied as an exact expression. |
| `points_to` | structural match, reference site, or expression site | receiver analysis | Bounded value, allocation, type, module, current-receiver, and factory provenance. |
| `member_targets` | structural match or reference site | receiver analysis | Exact indexed declarations selected by a receiver-qualified member access. |
| `file_of` | structural match, declaration, reference site, call site, expression site, or receiver analysis | file | Exact project file containing the analyzed input value. |
| `imports_of` | file | file | Direct project-local files imported by the input file. |
| `importers_of` | file | file | Direct project-local files importing the input file. |
| `supertypes` | declaration | declaration | Direct ancestors by default, or a bounded/full indexed ancestor closure. |
| `subtypes` | declaration | declaration | Direct descendants by default, or a bounded/full indexed descendant closure. |
| `members` | declaration | declaration | Real direct declaration children of a type. |
| `owner` | declaration | declaration | Exact declaring type of a direct member. |

Repeat an import step for multiple hops. Traversal is cycle-safe and deterministic; it does not silently compute a transitive closure.

```json
{
  "match": {"kind": "function", "name": "handle"},
  "steps": [
    {"op": "file_of"},
    {"op": "imports_of"}
  ]
}
```

Hierarchy steps are direct by default. A positive `depth` returns declarations reachable in one through that many edges; `transitive: true` returns the full reachable closure under the global execution budget:

```json
{"op":"supertypes"}
{"op":"supertypes","depth":2}
{"op":"subtypes","transitive":true}
```

Zero depth, `transitive: false`, unknown fields, `depth` together with `transitive`, and traversal options on `members` or `owner` are rejected. Invalid input declarations are omitted with aggregated per-language diagnostics, while supported hierarchy leaves simply return no rows. `owner` after `members` round-trips each returned member to its exact type.

Hierarchy and ownership results are restricted to declarations returned by the active analyzer's index and having renderable ranges. Bifrost may observe usages that refer to library code without having indexed that library's declaration; such a declaration is intentionally absent from these results. This is the current precision boundary until library code can be targeted and indexed explicitly.

Reference steps accept optional `reference_kinds`, `proof`, and `surface` fields. `reference_kinds` is a non-empty array drawn from `method_call`, `constructor_call`, `field_read`, `field_write`, `type_reference`, `static_reference`, `super_call`, and `inheritance`. `proof` is `proven` or `unproven`. `surface` is `external_usages` (the default) or `lsp_references`. Omitted kind and proof fields include both tiers; a kind filter excludes unclassified structured hits. See the executable [Reference Traversal](/code-query-tutorials/reference-traversal/) recipes.

Call traversal is direct by default. `callers` and `callees` accept a positive finite `depth`; there is deliberately no unbounded `transitive` form. Traversal is iterative and cycle-safe. A real recursive or cyclic edge is returned, but Bifrost stops expanding when the next declaration is already present on that provenance path. The same declaration may still be expanded through a different path, preserving alternate provenance within the execution budget. Every declaration reached by a call step records the proving `call_site` under provenance `via`.

`call_sites_to` and `call_sites_from` expose the full call range, callee range, caller and callee declarations, call kind, proof tier, optional explicit receiver, and arguments. `call_input` requires exactly one of `{"receiver":true}`, `{"parameter_index":0}`, or `{"parameter_name":"payload"}`. Parameter indexes are zero-based formal slots and exclude receiver-bound parameters; keyword/named arguments bind by the callee's declared parameter name. A variadic slot may yield several expression rows. Spreads/splats are retained on the call-site result but are not guessed into a formal slot. An implicit receiver has no synthetic expression row.

The three receiver steps return a tagged `receiver_analysis` row for every input, including unknown and unsupported cases. Each row includes `analysis_kind`, input path/language/range/text/kind, and `outcome`. `receiver_targets` and `points_to` use recursive `values`; `member_targets` uses exact `CodeQueryDeclaration` values under `member_targets`. Allocation values include their exact type declaration and allocation site. Factory returns include the exact factory declaration plus a nested returned value. Unsupported shapes/providers add `reason`; budget exits add `limit`.

Stable outcomes are `precise`, `ambiguous`, `unknown`, `unsupported`, and `exceeded_budget`. Ordinary bounded ambiguity retains every candidate and does not set top-level `truncated`. Candidate-cap truncation and `exceeded_budget` do set `truncated` and emit an aggregated limit diagnostic. Languages other than Java, JavaScript, and TypeScript return explicit `unsupported` rows plus capability diagnostics rather than empty results. Receiver-analysis rows are terminal except for `file_of`.

An optional `capture` is valid only when the preceding domain is a structural match. It must be between 1 and 128 bytes and name a positive capture declared by the structural query; every unique bound range is analyzed. Without a capture, `points_to` analyzes the match or the normalized `right` side of assignment/binding shapes, `receiver_targets` extracts the call `receiver` or field-access `object`, and `member_targets` extracts the receiver plus terminal member. See [Receiver Traversal](/code-query-tutorials/receiver-traversal/) for exact JSON/RQL/output triples.

These steps use tree-sitter call shapes and the existing definition/usage resolvers for Java, Go, C/C++, JavaScript, TypeScript, Python, Rust, PHP, Scala, C#, and Ruby. Resolution precision still varies with each language analyzer: unresolved calls are omitted, ambiguous edges are `unproven`, and formal input projection appears only when Bifrost can pair the resolved callee with structured parameter syntax. This is direct call-site projection, not local or interprocedural data flow.

```json
{
  "match": {"kind": "callable", "name": "dangerous"},
  "steps": [
    {"op": "enclosing_decl"},
    {"op": "call_sites_to", "proof": "proven"},
    {"op": "call_input", "parameter_name": "payload"}
  ]
}
```

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

Version 2 enforces these budgets:

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
| Name predicate source (exact or regex) and text regex source | `4096` bytes |
| Capture label | `128` bytes |
| Pipeline steps | `16` |
| Set operands at one node | `16` |
| Query-plan nodes / composition depth | `64` nodes / `16` levels |
| Seed and edge rows per execution | `50000` |
| Provenance paths per terminal result | `16` |

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
