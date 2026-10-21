---
title: JSON CodeQuery
description: Use the canonical JSON representation for Bifrost's query_code engine.
---

JSON `CodeQuery` is the canonical machine-facing representation accepted by Bifrost's `query_code` tool. MCP hosts and the Python client send this shape directly. Author queries in RQL, then generate this serialization from the decoded `CodeQuery`; the RQL REPL prints it with `:json`. JSON examples on this page describe the machine wire contract, not a second authoring syntax. Generated `.json` query files remain supported; JSON text in `.rql` files or editor buffers is not supported.

The single supported schema version is `"1"`. The [CodeQuery and RQL Vocabulary Reference](/reference/code-query/) lists every field, kind, role, step, option, value label, result type, diagnostic code, and limit. This page explains the JSON shape. A taint query names only a registered immutable result; it cannot load a policy, compile selectors, run propagation, reconstruct witnesses, or perform policy classification.

## Minimal Query

<!-- code-query-test:json:minimal-call -->
```json
{
  "schema_version": "1",
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

A query object has exactly one source:

- `match`, a root pattern;
- a set operator, `union`, `intersect`, or `except`, holding 2 to 16 complete child queries; or
- one seed source: `occurrences`, `scopes`, `bindings`, `paths`, `generation_sites`, `exports`, `dependency_evidence`, or `configuration_facts`. Each seed source takes a filter object, and an empty object `{}` selects every row.

The other top-level fields scope or shape the query:

- `where` holds project-relative globs. A flat list means any glob. Nested lists mean every group, with any glob inside a group. MCP and CLI entry points normalize absolute paths and globs inside the active workspace.
- `languages` holds at most 32 language labels. The labels are `java`, `go`, `cpp`, `javascript`, `typescript`, `python`, `rust`, `php`, `scala`, `csharp`, `ruby`, and `kotlin`, plus the families `jvm` (`java`, `kotlin`, `scala`) and `js-ts` (`javascript`, `typescript`). The list also accepts `c++`, `c#`, and any file extension that Bifrost indexes, such as `py`, `kts`, `tsx`, or `h`; each one selects the language that owns it. An extension selects the whole language, so `c` and `h` select every `cpp` file. Omit `languages` to search every structural adapter. `configuration_facts` rejects it. See [the label table](/reference/code-query/#languages) and [language support](/reference/languages/).
- `inside`, `inside_decl`, and `not_inside` constrain the ancestors of a `match` root.
- `steps` is an ordered array of at most 16 typed steps.
- `limit` (1 to 1000, default 100), `result_detail` (`compact` or `full`), `execution_mode` (`results`, `explain`, or `profile`), and `schema_version` (`"1"`) control the output. The number `1` is also accepted for `schema_version` and is rewritten to `"1"`.

The [query plan field table](/reference/code-query/#query-plan-fields) gives the value shape and default of each field, and the [seed source filter table](/reference/code-query/#seed-source-filters) lists every filter axis.

Unknown fields are rejected rather than ignored.

`execution_mode` is a root-only output control, like `limit` and `result_detail`. It cannot appear inside a `union`, `intersect`, or `except` operand. Ordinary `results` mode preserves the established result shape; the other modes return versioned report objects described in [Explain and Profile CodeQuery](/code-query-explain-profile/).

When calling `query_code`, MCP clients may instead send a tool-call envelope such as `{ "query_file": "queries/audit.json" }`. That selector is not a `CodeQuery` field and must not be written inside the JSON file itself: the file contains the complete canonical query shown in this reference. The same tool-call input accepts `.rql` files, which lower through RQL before validation.

## Pattern Fields

A pattern combines all supplied constraints with logical AND. Its fields are `kind`, `not_kind`, `async`, `name`, `text`, `boolean_value`, `capture`, `arity`, `visibility`, `parameter_type`, `has`, `not_has`, and the [roles](/reference/code-query/#roles) that the pattern's kind allows. The [pattern field table](/reference/code-query/#patterns) gives each value shape and limit.

Notes on the JSON form:

- `kind` and `not_kind` take one kind or an array. Matching includes subtypes. `not_kind` and `not_has` are never used to skip files.
- `async` takes `true` or `false` and matches AST-backed callable asyncness. Valid only on callable kinds; an adapter that cannot provide the fact reports incomplete.
- `name` and `parameter_type` take an exact string or `{ "regex": "..." }`. `text` takes only `{ "regex": "..." }`; there is no exact-text form.
- `arity` takes an exact count, such as `2`, or inclusive bounds, such as `{ "min": 1 }` or `{ "min": 1, "max": 3 }`. It counts a call's positional arguments or a collection literal's elements.
- `boolean_value` takes `true` or `false` and matches a boolean literal by its value.
- `visibility` takes one label or an array: `public`, `protected`, `internal`, `package_private`, `private`, `crate_or_module`, or `unknown`. `unknown` means the adapter looked and could not classify; it is never equal to `public`. Valid only on callable kinds. An unrecorded modifier, and a recorded `unknown` against a concrete label, are incomplete, not a miss.
- `parameter_type` matches a callable that has a parameter whose recorded type spelling satisfies the predicate. The spelling is a discriminator, not a resolved type identity. Valid only on callable kinds. Unrecorded parameter types are incomplete, not a miss.
- `capture` returns this node or role target under the label.

Nested role targets may be capture-only or otherwise unconstrained. The root `match` may not.

<!-- code-query-test:json:callable-visibility -->
```json
{
  "languages": ["java"],
  "match": {
    "kind": "method",
    "visibility": "public",
    "parameter_type": { "regex": "String" }
  }
}
```

`visibility` and `parameter_type` read persisted callable signature metadata, not source text. A language that does not record modifiers or parameter types returns incomplete rather than an empty complete miss.

<!-- code-query-test:rql:callable-visibility -->
```lisp
(language java (method :visibility public :parameter-type/regex "String"))
```

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
├── import
├── parameter
└── module

literal
├── string_literal
├── numeric_literal
├── boolean_literal
├── null_literal
└── collection_literal

loop
├── for_loop
└── while_loop
```

The remaining kinds are independent leaves: `call`, `concurrent_spawn`, `resource_release`, `assignment`, `field_access`, `identifier`, `jsx_element`, `jsx_attribute`, `jsx_spread_attribute`, `object_property`, `computed_property`, `spread_element`, `return`, `throw`, `catch`, `if`, `decorator`, and `block`. The [kind table](/reference/code-query/#normalized-kinds) gives a one-line meaning for each kind. `block` matches a statement list that opens a lexical scope of its own — a method body, a bare block, a loop or conditional body, a `switch` body — and never a class or interface member list. `for_loop` covers the for-each family (iteration over a collection, iterator, or range); `while_loop` covers condition-controlled loops including do-while and until. Loop forms a language cannot refine lexically — Go's single `for` construct, C-style counting `for`, and Rust's bare `loop` — remain plain `loop`, so query `loop` when every form must match. `collection_literal` covers collection display literals — array, list, set, dictionary, and tuple literals — in the adapters that classify them (JavaScript, TypeScript, Python, Java array initializers, Rust arrays and tuples); a Rust `[value; length]` repeat array is a `collection_literal` fact with no `elements` edges because its run-time size is not its spelled element count. `module` covers a module or namespace declaration that encloses other declarations — a Rust `mod`, a C# `namespace` (block or file-scoped), a C++ or PHP `namespace`, and a Ruby `module` — and is a containment parent, so `not_inside` a `module` pattern excludes everything written inside it. Languages whose module structure is not a container declaration report a capability diagnostic instead: Python has no module declaration syntax at all, and a Java `package`, Go `package`, Kotlin or Scala `package` clause names the file's module without enclosing it.

Therefore `{"kind":"callable"}` matches functions, methods, constructors, and lambdas, and `{"kind":"literal"}` matches every normalized literal subtype. There is deliberately no exact-kind operator. Use a leaf kind or subtract unwanted subtypes with `not_kind`.

## Roles

Roles are normalized edges from one structural fact to a related node or source span. The parent pattern must declare a kind for which the role is valid. For example, `callee`, `receiver`, `args`, and `kwargs` are valid on `call` and `concurrent_spawn`; `left`, `right`, and `operator` on `assignment`; and `tag`, `attributes`, and `children` on `jsx_element`. The [role table](/reference/code-query/#roles) lists all 18 roles with their valid parent kinds.

In JSON, a single-target role takes a pattern object, a list role takes an array of patterns, and `kwargs` takes an object that maps argument names to patterns.

Every ordered-list role reads the same way: each listed pattern must match a distinct edge of that role in source order, but the matches need not be contiguous and do not assert exact arity. So `"args": [a, b]` needs two different arguments with `a` before `b`, and `"decorators": [a, a]` needs two decorators rather than one matched twice. Use the `arity` field to fix the count: an exact number, or inclusive `min` and `max` bounds. There is no positional-index operator; to pin a position, narrow the surrounding source shape in a follow-up query.

`kwargs` support is adapter-specific. Python, PHP, Scala, C#, Ruby, and Kotlin expose normalized named arguments; languages without that role return a capability diagnostic.

## Captures And Results

`capture` adds a named entry to the result. Captures include their text and start line in compact mode; full mode also includes their normalized kind and byte/line/column range when available.

The same capture label may appear more than once in a query. Every occurrence must bind exactly the same source text, allowing equality constraints such as “both arguments use the same expression.”

The response contains a `results` array. Every item has a `result_type`, which names the output domain of the last step, or the source domain when there are no steps. The reference lists [all 75 result types](/reference/code-query/#result-types). `bifrost --list-row-schemas` prints every domain's fields, scalar types, nullability, and enum labels. A query without steps returns structural matches with path, language, kind, line range, a bounded text snippet, captures, and a best-effort `enclosing_symbol`.

With `result_detail: "full"`, results additionally include:

- a deterministic match `id`
- declaration `id` values in the analyzer's `decl:v1:<hex>` format and a
  `site_id` formed from that ID plus the exact declaration byte span
- `node_range` byte and 1-based line/column bounds
- capture ranges and kinds
- `decorator_ranges` for matched declarations
- `decorated_range`, the union of the declaration and its decorators

Every derived result includes `provenance`. Each provenance path records the original structural seed and every ordered step result. Declaration-returning reference steps additionally record the exact proving reference site under `via`. Compact mode keeps minimal identities; full mode adds stable IDs and precise ranges. At most sixteen paths are retained per terminal result, with `provenance_truncated: true` when more paths converge.

Declaration identity is one cross-domain vocabulary. A declaration row's
`id` and declaration-valued aliases such as `target_id`, `caller_id`,
`callee_id`, `procedure_id`, and `declaration_id` are byte-identical when they
name the same analyzer declaration. `procedure_effect` and
`callable_signature` repeat that declaration's `site_id` because their range
is the declaration site itself. Other `site_id` fields name their own typed
domains, such as calls or AST occurrences, and are not declaration IDs.

For completeness claims, result metadata is mandatory: inspect diagnostics, require `truncated: false`, distinguish `proven` from `unproven` graph edges, and check every derived result's `provenance_truncated` field. [Agent Result Safety](/agent-result-safety/) turns those fields into an explicit decision rule.

## Typed Set Composition

At every query-plan node, use exactly one source field: `match`, a seed source, or one of `union`, `intersect`, and `except`. Set fields contain between two and sixteen complete child plans. Every child of `intersect` and `except` must end in exactly the same typed domain, and so must the children of a `union` that a typed step follows. A `union` that only `filter` and `project` steps follow may combine branches of different row kinds: each row keeps its own kind, those steps see only the fields every branch publishes under one name and type, and the query's reported kind is the first branch's. Bifrost rejects incompatible branches before workspace execution with a path such as `union[1].steps[0]`.

```json
{
  "union": [
    {"match":{"kind":"class","name":"Legacy"},"steps":[{"op":"enclosing_decl"}]},
    {"match":{"kind":"class","name":"Replacement"},"steps":[{"op":"enclosing_decl"}]}
  ],
  "steps": [{"op":"file_of"}]
}
```

`union` retains the first appearance of each exact typed endpoint in branch order; endpoints of different row kinds never coincide, so a union of different row kinds keeps every branch's rows. `intersect` retains endpoints present in every branch, in the first branch's order. `except` retains first-branch endpoints absent from every later branch. Endpoint identity comes from structured ranges and declaration/site identities, never rendered text.

Union and intersection merge at most sixteen provenance traces in branch order. A trace or diagnostic inside composition includes a zero-based `branch` path; plain leaf queries omit it. Except retains provenance only from its positive first branch. Root-only `limit`, `result_detail`, `execution_mode`, and `schema_version` fields cannot appear inside operands, while `inside`, `inside_decl`, and `not_inside` belong inside the branch containing `match`. Outer `where` and `languages` constraints conjoin with every branch's source scope before its pipeline steps; disjoint explicit language scopes are rejected.

The public `limit` applies after the complete root set and common suffix. Execution budgets are shared across the request and fairly reserve work for later immediate operands. An incomplete operand sets `truncated: true` and produces a branch-labeled diagnostic rather than claiming a complete set. See the executable [Typed Set Composition](/code-query-tutorials/set-composition/) cookbook.

Set composition stays inside one input domain. A code branch beside a `configuration_facts` branch is rejected before execution: configuration formats are not languages, and two rows that merely co-occur in one repository are not related.

## Code And Configuration Correlation

Two registered cross-domain sources combine a programming-code query with a configuration-fact query. Both take a `code` query and a `configuration` query, run them independently, and return `cross_domain` rows.

`correlate` pairs a code row with a configuration fact only where its typed `relation` holds. The `configuration_key` relation pairs a Java argument with a `.properties` member. The argument must be bound by a resolver-proven call to a formal parameter of the accessor the code query selects, and it must be a plain string literal. The member's route must be exactly one key segment equal to that literal, inside one of the declared `documents`:

<!-- code-query-test:json:correlate -->
```json
{
  "correlate": {
    "relation": {
      "configuration_key": {"documents": ["src/main/resources/app.properties"]}
    },
    "code": {
      "match": {"kind": "method", "name": "get"},
      "inside": {"kind": "class", "name": "AppConfig"},
      "steps": [
        {"op": "enclosing_decl"},
        {"op": "call_sites_to", "proof": "proven"},
        {"op": "call_input", "parameter_index": 0}
      ]
    },
    "configuration": {
      "configuration_facts": {"formats": ["properties"], "node_kinds": ["member"]}
    }
  }
}
```

The same query in RQL:

<!-- code-query-test:rql:correlate -->
```lisp
(correlate
  :relation (configuration-key :documents ["src/main/resources/app.properties"])
  :code (call-input :parameter-index 0
          (call-sites-to :proof proven
            (enclosing-decl (inside (class (name "AppConfig")) (method (name "get"))))))
  :configuration (configuration-facts :format properties :node-kind member))
```

The correlation key is structural, never a spelling match. `audit.get("db.url")` on an unrelated `Audit` class is not a call of `AppConfig.get`, so the code query never returns it. `log("db.url")` is not a bound argument at all. `db.url` in an undeclared `config/other.properties` never pairs, and an unrelated `db.user` row in the declared document pairs with nothing. Documents are exact workspace-relative `.properties` paths, never globs, because a glob would correlate every document in the repository.

Each correlated row has `operator: "correlate"`, `domain: "correlated"`, `relation`, the `key`, and a `binding` of `unique` or `ambiguous`. It carries a reference to the code row in `code` (its own `result_type`, exact location, and identity fields) and the whole configuration fact in `configuration`, with `code_id`, `code_path`, `configuration_id`, and `configuration_path`. `configuration_id` equals the configuration fact row's `id`. `path` and `range` anchor the row at the code row. A key that names more than one authored fact, such as a duplicate key or the same key in two declared documents, pairs with every candidate, marks each row `ambiguous`, and adds an advisory `cross_domain_correlation_ambiguous` diagnostic. Which value wins is an effective-configuration question this operator does not answer.

`require_both` checks boolean satisfaction:

<!-- code-query-test:rql:require-both -->
```lisp
(require-both
  :code (call-sites-to :proof proven
          (enclosing-decl (inside (class (name "AppConfig")) (method (name "get")))))
  :configuration (configuration-facts :format properties :key "db.url"))
```

When both queries return rows, it returns each of them as a `cross_domain` row with `operator: "require_both"` and `domain` set to `code` or `configuration`; each carries one input row (a code reference or a whole configuration fact) and no `relation` or `key`. When either query returns nothing, the answer is empty. It never pairs rows, so satisfying both predicates does not claim that any code row and configuration row are related.

Neither operator turns a gap into a clean answer. These diagnostics have `incomplete` impact:

- `cross_domain_binding_unproven`: a bound call did not resolve to its callee with proof.
- `cross_domain_key_unsupported`: a bound argument is not a plain string literal (an escape, a text block, a concatenation, or a constant), its source could not be read, or it is in a language other than Java.
- `cross_domain_document_incomplete`: a declared document is missing from the workspace, outside the configuration query's `where` or format scope, produced no facts, or was only partly recovered.

Either operator's inputs report their own diagnostics under branch `0` (code) and branch `1` (configuration). The operators are whole-workspace sources: they cannot sit inside `union`, `intersect`, or `except`, and a policy runs them once rather than per seed file. Only `filter` and `project` may follow them.

## Typed Pipeline Steps

Steps execute in array order and are validated before the workspace is searched. Each step is an object whose `op` names the step; its options are sibling fields:

```json
{"op": "callers", "depth": 2, "proof": "proven"}
```

Each step consumes one row domain and produces another, so a pipeline is valid only when every step accepts the domain the previous step produced. Bifrost groups query steps into row operations, declarations and imports, type hierarchy, references and calls, reference edges, occurrences and resolution, qualified paths, receivers and dispatch, call shape and bindings, effects and result contracts, control flow, flow and typestate, values, build topology, materialization, and rewrite paths. The [step tables](/reference/code-query/#steps) give every step's input and output domains, options, and meaning, and the [step option table](/reference/code-query/#step-options) gives each option's values and default. `bifrost --help query_code` prints the step list for the running build.

The sections below explain the steps whose rows need more than one sentence.

Repeat an import step for multiple hops. Traversal is cycle-safe and deterministic; it does not silently compute a transitive closure.

### Typed row predicates and columns

The `filter` and `project` steps read the same public row-schema tables used by
relational policies. Those tables define each field's stable name, scalar type,
nullability, and constrained enum labels. Canonical JSON tags literal types
explicitly, so an enum label is never an internal Rust enum name and can never
be confused with an arbitrary string:

```json
{
  "schema_version": "1",
  "occurrences": { "class": "reference" },
  "steps": [
    {
      "op": "filter",
      "where": [
        { "field": "class", "op": "in", "values": [
          { "enum": "reference" }, { "enum": "declaration" }
        ] },
        { "field": "target_count", "op": "ge", "value": { "integer": 1 } },
        { "field": "target_count", "op": "le", "value": { "field": "target_count" } },
        { "field": "target_id", "op": "is_not_null" }
      ]
    },
    {
      "op": "project",
      "columns": [
        { "source": "ast_id", "name": "site" },
        { "source": "target_count", "name": "candidates" }
      ]
    }
  ]
}
```

Comparison `value` accepts exactly one of `string`, `integer`, `boolean`, or
`enum`, or the object `{ "field": "OTHER_FIELD" }`. The public operators are
`eq`, `ne`, `lt`, `le`, `gt`, `ge`, `is_null`, `is_not_null`, and `in`.
`is_null` and `is_not_null` have no operand; `in` uses `values`, a non-empty
array of at most 64 typed literals. A filter carries 1 through 16 predicates.
A projection carries 1 through 32 `{ "source", "name" }` entries with unique
output names. Its output schema contains exactly those names in that order,
with the source fields' public types, nullability, and enum domains. After a
`project` step, only `filter` and `project` steps may follow, and they see only
the projected names. The projected schema is what a later filter and a relational
policy binding read; the `query_code` result still renders each row as its source
row.

### Procedure-local CFG inspection

This query starts from a structural function match, resolves its executable procedure, enters its CFG, follows one outgoing edge, and projects the target point:

<!-- code-query-test:json:cfg-entry-successor -->
```json
{
  "schema_version": "1",
  "languages": ["typescript"],
  "match": {"kind": "function", "name": "run"},
  "steps": [
    {"op": "procedure_of"},
    {"op": "cfg_entry"},
    {"op": "cfg_successor_edges"},
    {"op": "cfg_edge_target"}
  ]
}
```

`procedure` rows include stable content-scoped `id` and `artifact_id`, workspace-relative `path`, `procedure_kind`, exact `range`, and semantic `evidence`. `program_point` rows add `procedure_id`, optional `boundary` (`entry`, `normal_exit`, or `exceptional_exit`), and `event_count`. `control_edge` rows add `edge_kind` plus complete source and target point references.

Every semantic row carries one `evidence` object: `proof` is `proven` or `unproven`, `completeness` is `complete` or `partial`, and optional `reason` preserves the typed failure or limit when either axis is degraded. There is no composite quality label and no separate per-axis reason field. Public IDs never expose dense semantic arena IDs and remain stable for identical indexed content mounted at different absolute checkout paths. Diagnostics distinguish unsupported/partial capability, provider failure, missing workspace services, no enclosing procedure, cancellation, and budget exhaustion. An incomplete diagnostic prevents a complete-negative conclusion even when the result array is empty.

Each edge operation is exactly one hop. Compose more steps for a finite traversal; the CFG surface does not provide an unbounded closure, ICFG, data-flow, taint, typestate, finding, or witness endpoint. The registered typestate adapter described next is the only typestate entry point.

`program_point_of` projects a structural match to its unique source-mapped CFG point. An `await` match selects the point carrying `AsyncSuspend`; missing or ambiguous mappings produce an incomplete diagnostic.
The point row's `id` joins to `program_point_id` on state-event rows from `state_events_of`, so a consumer can correlate an await with binding reads at that suspension.

<!-- code-query-test:json:program-point-of-await -->
```json
{
  "schema_version": "1",
  "languages": ["rust"],
  "match": { "kind": "await" },
  "steps": [{ "op": "program_point_of" }]
}
```

### Registered typestate findings and witnesses

An embedding first registers an in-memory compiled protocol and its pre-resolved binding plan under a namespaced reference. The JSON request supplies only that reference; it never supplies a protocol path, binding JSON, policy severity, or query-time mode override.

<!-- code-query-test:json:typestate-witness -->
```json
{
  "schema_version": "1",
  "match": {"kind": "function", "name": "lifecycle"},
  "steps": [
    {"op": "procedure_of"},
    {"op": "typestate", "protocol_ref": "embedding:resource-lifecycle"},
    {"op": "witness", "max_steps": 32, "max_bytes": 16384}
  ]
}
```

`typestate_finding` rows carry stable protocol and binding-plan hashes, canonical subject identity, finding kind, certainty (`may`, `must`, or `inconclusive`), exact primary range, proof/completeness flags, uncertainty causes, abstention, and retained/omitted witness counts. They deliberately have no policy ID, severity, message, CWE, CVSS, or SARIF fields. `typestate_witness` rows retain the same identity plus ordered source-backed steps, semantic evidence, truncation flags, and omission lower bounds.

One request solves each exact procedure/protocol/binding tuple at most once. `witness` only trims retained evidence and never reruns the solver. Solver, finding, witness, semantic, and ordinary pipeline work all remain finitely bounded; profile mode reports typestate solves, request-cache hits, reached rows, findings, witnesses, steps, bytes, termination, and exhaustion. Missing references, stale workspace generations or artifacts, wrong roots, cancellation, provider failure, and exhausted budgets are explicit incomplete diagnostics, never clean empty negatives.

### Registered value-flow endpoints and witnesses

The host registers an already-built `ValueFlowPlan` under a namespaced reference. A query sends only that reference:

<!-- code-query-test:json:value-flow-witness -->
```json
{
  "schema_version": "1",
  "match": {"kind": "method", "name": "run"},
  "steps": [
    {"op": "procedure_of"},
    {"op": "value_flow", "plan_ref": "embedding:request-to-sink"},
    {"op": "witness", "max_steps": 32, "max_bytes": 16384}
  ]
}
```

`flow_endpoint` rows keep reachability (`reached`, `not_reached`, or `inconclusive`), exact/may certainty, and ambiguity. One `status` describes how the flow analysis ended, while optional `reason` carries the exact capability, budget, cancellation, or retained-evidence detail. There is no `must` field until must analysis exists. `flow_witness` rows contain bounded ordered source-backed steps, one `evidence` object, and truncation metadata. The adapter consumes the existing plan and solver, caches one solve per procedure/plan tuple within the request, and never performs policy classification.

| Flow `status` | Meaning |
| --- | --- |
| `complete` | Semantic input was complete and the solver reached a fixed point with complete coverage. |
| `partial` | The solver reached a fixed point, but retained semantic evidence or coverage was incomplete. |
| `ambiguous` | Structured semantic alternatives remain. |
| `unknown` | The semantic provider could not establish the requested relation. |
| `unproven` | A structured relation was retained without sufficient proof. |
| `unsupported` | A required semantic capability is unavailable; `reason` names it. |
| `semantic_budget_exhausted` | Semantic input construction hit a public semantic budget lane. |
| `solver_budget_exhausted` | Flow propagation hit a solver work limit. |
| `semantic_cancelled` | Cancellation stopped semantic input construction. |
| `solver_cancelled` | Cancellation stopped the flow solver. |
| `query_cancelled` | The enclosing query stopped after the solve and capped an otherwise complete row. |

When solver termination and semantic input are both limited, `status` names the solver outcome and `reason` also retains the semantic outcome. Thus every formerly observable `semantic_status`/`completion`/`solver_termination` combination remains distinguishable without exposing those internal enums as separate public columns. `path_qualities` remains a collection of evidence objects because it is the frontier of incomparable concrete paths, not a second endpoint status.

### Caller-driven absent-member witnesses

`class_set` follows caller values to receiver accesses. By default,
`absent_member` emits only proven class/member absences; set `finding_proof`
to `conditional` or `any` to also select conditional findings. Both steps run only for `python`,
`javascript`, `typescript`, `php`, and `ruby`. For other languages they return
no rows and a `semantic_capability_unsupported` diagnostic with the message
`class-set propagation is unsupported for <label>`. Python absence queries
require an active Python declaration-model surface. Unknown receivers and incomplete member
models suppress Proven findings; a complete empty result does not mean every
runtime receiver was classified. The explicitly limited Conditional cases
below can retain their stated remainder.

Conditional findings may retain other unclassified receiver values, or a
possible member installation by a listed global dynamic write only when every
matching write has no receiver bound and an Any member-name set; the condition
names those write sites. A `DeclaredParameter` origin is admitted only when its
annotation resolves to one workspace class with no workspace subclasses,
unresolved or unmodeled external bases, or attribute hooks such as
`__getattr__`, `__getattribute__`, or `__setattr__`. Its condition states the
annotated type and that no workspace subclass exists.

<!-- code-query-test:json:absent-member-witness -->
```json
{
  "schema_version": "1",
  "languages": ["python"],
  "match": {"kind": "function", "name": "read_config"},
  "steps": [
    {"op": "procedure_of"},
    {"op": "absent_member"},
    {"op": "witness", "max_steps": 32, "max_bytes": 16384}
  ]
}
```

`absent_member_witness` rows link to a site-keyed `finding_id` and retain ordered
source-backed `steps`, `evidence`, byte counts, and omission/truncation metadata.
Witness IDs additionally distinguish caller contexts. `witness_status` is
`available`, `truncated`, or `unavailable`; unavailable rows have no steps and
include `unavailable_reason`. Retention exhaustion is a truncated marker, not an
unavailable error or a complete empty path. Missing or truncated witness evidence
does not revoke the independently Proven finding.

Setting `max_steps` to 1 retains at most one step and labels a longer path as
truncated. Query limits only reduce host per-witness and aggregate limits;
projection never runs the solver again. Named `type_flow_witness_truncated` and
`type_flow_witness_unavailable` diagnostics distinguish the two evidence limits.

### Retained production taint findings

The host registers immutable results produced by the production taint policy compiler, batch planner, solver, collector, and public projector. A query selects the exact procedure root and projects only retained evidence:

```json
{
  "schema_version": "1",
  "match": {"kind": "method", "name": "run"},
  "steps": [
    {"op": "procedure_of"},
    {"op": "taint", "taint_ref": "request:http-to-database"}
  ]
}
```

`taint_finding` rows preserve stable IDs, reached labels, origins, witnesses, one semantic `evidence` object, ambiguity, and truncation metadata. Registration aliases never enter those IDs. Matching projection limits produce rows field-for-field equal to the production policy outcome's public taint findings.

### Typed occurrences

An occurrence is what the parser says one identifier token *is* at one exact position: a declaration name, a binder, a type operand, a map key, a path segment, a plain read. `occurrences` is a query source of its own, scoped by the usual `where` and `languages`:

<!-- code-query-test:json:occurrence-seed -->
```json
{
  "languages": ["rust"],
  "occurrences": {"role": ["binder"], "namespace": ["value"]}
}
```

Each row carries `id`, `ast_id`, `path`, `language`, `class`, `role`, `namespace`, `range`, `start_byte`, `end_byte`, `enclosing_symbol`, `raw_spelling`, an optional `decoded_spelling` (present only where decoding changes the spelling, such as a Rust `r#type`), and a `target` object whose `target_kind` is `none`, `resolved`, `lexical`, or `unresolved`. A non-reference row is always `none` and a reference row never is, so an empty target never means "resolution was skipped".

The three filter axes are conjunctive with one another and disjunctive within one axis. `class` is derived from `role` (`declaration`, `reference`, `binding`, `non_reference`), so filtering on both narrows to their intersection.

Containment is expressed by `occurrences_in` over a structural query rather than by `inside` on the source, so lexical containment is verified in exactly one place:

<!-- code-query-test:json:occurrences-in -->
```json
{
  "match": {"kind": "function", "name": "handle"},
  "steps": [{"op": "occurrences_in", "class": ["binding"]}]
}
```

`occurrences_of` answers "every occurrence of this declaration" and `occurrence_target` walks back from a reference-class row to what it resolved to:

<!-- code-query-test:json:occurrences-of -->
```json
{
  "match": {"kind": "function", "name": "handle"},
  "steps": [
    {"op": "enclosing_decl"},
    {"op": "occurrences_of", "class": ["reference"]},
    {"op": "occurrence_target"}
  ]
}
```

`ast_id` is the content-scoped identity of the underlying AST node. In `result_detail: "full"`, a `structural_match` and each of its `captures` carry the same field, so a captured node and the occurrence at that node are joined by string equality of `ast_id` -- never by comparing ranges, paths, or spellings.

Occurrence support is declared per language and per role. Where a language's adapter does not classify a role a query names, or cannot place it in a namespace, the run reports `occurrence_role_unsupported` with `incomplete` impact instead of returning a clean empty answer. Java and Rust path qualifiers use `path_prefix`: the qualifier can name a module or a type, with resolution determining which. A role the adapter *does* support is not degraded by an unsupported sibling role.

### The lexical environment and resolution candidates

An occurrence says *what* an identifier resolved to. Scope, binding, and candidate rows say *why*, and why not.

A **lexical scope** is a region a file is made of. Every file contributes a synthesized whole-file scope at index 0 plus one row per scope-forming node, parent-linked by index so ancestry is a chain walk. `scopes` is a source of its own:

<!-- code-query-test:json:scope-seed -->
```json
{
  "languages": ["java"],
  "scopes": {"kind": ["block"]}
}
```

Each scope row carries `id`, an optional `ast_id`, `path`, `language`, `index`, an optional `kind`, `range`, `start_byte`, `end_byte`, and an optional `parent_index`. Exactly one scope per file has no `ast_id` and no `kind`: the synthesized whole-file scope, which no grammar gives an AST node. A non-empty `kind` filter therefore never selects it, which is the honest reading of "give me the block scopes".

A **binding** is one name a scope introduces, with the byte interval over which it is in effect:

<!-- code-query-test:json:binding-seed -->
```json
{
  "languages": ["java"],
  "bindings": {"kind": ["local"], "hoisting": ["source_order"]}
}
```

Each binding row carries `name`, `kind` (`local`, `parameter`, `pattern_binder`, `loop_variable`, `catch_or_resource`, `import_binder`, `type_parameter`), `hoisting` (`source_order`, `scope_wide`, `declared_head`), `namespace`, its `range`, its `activation_start_byte`/`activation_end_byte`, its `declaring_scope_index`, its `source_order` within that scope, its `visibility`, and an `import` object for import binders. `ast_id` is absent when the binder's local name is not spelled by a classified token -- a wildcard import binds no identifier, and an adapter that records no structured import path cannot locate the declaration.

The `import` object carries `local_name`, an optional `alias`, `target_segments`, `wildcard`, an optional `wildcard_ambiguous`, and a `boundary`. `target_segments` is empty where the adapter records no parser-derived import path, which is a stated gap rather than a claim that the import has no target. `wildcard_ambiguous` is absent where the language does not compute it at all; `true` means more than one on-demand import in this file could supply a simple name, so a selection through the wildcard tier is not provably unique here.

`scope-of` maps a binding, an occurrence or a structural match to its innermost owning scope; `scope-ancestors` walks outward from a scope, excluding the scope itself; `bindings-in` returns the bindings a scope declares. Together they answer the loop-invariance question -- is the value operated on inside this loop declared inside or outside the loop body? -- as a structural query:

<!-- code-query-test:json:binding-of -->
```json
{
  "languages": ["java"],
  "occurrences": {"role": ["receiver_position"]},
  "steps": [
    {"op": "binding_of"},
    {"op": "scope_of"}
  ]
}
```

`binding_of` returns the binding of the occurrence's name that is in effect at its exact position, computed from activation intervals and scope ancestry rather than from source-order co-presence. Every row it produces carries `reached_from_ast_id`, the AST identity of the occurrence the answer is about, so a caller that captured that token joins the binding back to its own capture instead of guessing; one binding reached from two occurrences is therefore two rows. When more than one binding of the name is in effect, the winner is returned alone unless `include_shadowed` is `true`, in which case the losers follow with `shadowed: true`. When no binding is in effect the answer is an empty one and complete: the name resolves to something other than a lexical binding. When the file's intervals cannot be stated the run reports `environment_derivation_incomplete` instead.

`binding-occurrence` walks back from a binding to the binder-class occurrence row of its declaring token, so a binding and a capture over the same token join by `ast_id`.

A **resolution candidate** is one thing the resolver considered for one reference:

<!-- code-query-test:json:candidates-of -->
```json
{
  "languages": ["java"],
  "occurrences": {"class": ["reference"]},
  "steps": [
    {"op": "candidates_of", "tier": ["lexical_binding"], "outcome": ["selected"]}
  ]
}
```

Each candidate row carries the `ast_id` of the *reference* it explains, an `ordinal` within that reference's trace, an optional `tier`, an `outcome` (`selected` or `rejected`) with an optional typed `rejection_reason`, a `boundary`, a `visibility`, a `trace_completeness`, and a `candidate` object whose `candidate_kind` is `unit`, `modeled`, `intrinsic`, `lexical`, `binding`, `import_binder`, or `external_route`. An `intrinsic` candidate names the canonical language type (for example, `java.lang.String`) and its binding tier without claiming a source declaration or location.

Three honesty rules govern candidate rows, and none of them can be read off an empty answer:

- An **absent `tier`** means the seam that recorded the candidate could not name one. It is *unattributed*, never "the weakest tier"; a policy comparing tiers must treat it as inconclusive. The `:tier` filter spells this value `unattributed`.
- A `trace_completeness` of `selection_only` means the language's resolver reports only what it selected, so an absent rejection row says nothing. Asking for rejected rows over such a trace reports `resolution_trace_incomplete`.
- `candidate_target` projects only `unit` candidates to declarations. A `binding` or `external_route` candidate carries no workspace declaration by construction, so the step is partial -- it returns fewer rows than it received, and that is the answer rather than a gap.

Where an adapter declares a lexical-environment axis unsupported, the run reports `environment_axis_unsupported` with `incomplete` impact rather than a clean empty answer, exactly as for occurrence roles.

Seed with the roles you need rather than with a class. `{"class": ["reference"]}` requires *every* reference role, so an adapter gap in an unrelated part of a file -- such as a pattern position it does not classify -- makes the whole run incomplete. Java and Rust qualifiers using `path_prefix` are supported, not missing namespace classifications. `{"role": ["receiver_position"]}` asks only for what the question is about, and reports incompleteness only when that role is genuinely unavailable.

The **package clause** is fields on the file row rather than a fourth row kind, because it is exactly one row per file. `package_fq` and `package_syntactic` appear together; `package_syntactic` is `true` when the language spells the package in the source (Java's `package a.b;`) and `false` when it is derived from the file's path (Python, Rust, JavaScript). Both being absent means no package could be named at all, which is not the same as "the file is in the root package".

### Canonical reference edges

Bifrost derives "X uses Y" twice: the resolver derives it forward, from one classified token to the declaration it resolved to, and the usage index derives it backward, from one declaration to the sites that point at it. Reference edges state both in one row shape, so the two answers can be compared.

`edges_of` is the inverse projection and `edges_from` the forward one:

<!-- code-query-test:json:edges-of -->
```json
{
  "languages": ["java"],
  "match": {"kind": "callable", "name": "register"},
  "steps": [
    {"op": "enclosing_decl"},
    {"op": "edges_of", "usage": ["reference"], "site_class": ["use_site"]}
  ]
}
```

<!-- code-query-test:json:edges-from -->
```json
{
  "languages": ["java"],
  "occurrences": {"class": ["reference"]},
  "steps": [
    {"op": "edges_from", "reference_kinds": ["method_call"]},
    {"op": "edge_target"}
  ]
}
```

Each edge row carries `id`, an optional `ast_id`, `path`, `language`, `range`, `start_byte`, `end_byte`, a `target` declaration, an optional `enclosing_declaration`, an optional `reference_kind`, a `proof`, a `usage_kind`, a `site_class`, an `owner_relation`, an `edge_provenance`, and a `generation`. Both steps accept `reference_kinds`, `proof`, `surface`, `usage`, `relation`, and `site_class`.

`edge_provenance` is the field the whole domain exists for: `forward` for a resolver-derived row and `inverse` for a usage-index-derived one. It is spelled `edge_provenance` on the wire because every result item already owns `provenance` for its branch trace. It is data on every row rather than something read off which step produced the set, so a parity comparison is a comparison across a field. `generation` is the workspace generation the derivation ran in; two rows from two generations describe two workspaces and must not be related.

Four absences here are answers rather than gaps:

- An **absent `ast_id`** means the producer could not address the site token as a facts-arena node, not that the edge is weaker. Where it is present, string equality with a capture's or an occurrence's `ast_id` is the correlation join.
- An **absent `reference_kind`** means the producer classified no structured kind. It is not a kind of its own and must not be compared against one.
- An `owner_relation` of `unknown` means the classifier could not relate the site's owner to the target's. It is never silently equal to `external`: an assertion over unknown relations is inconclusive, not clean.
- A `site_class` of `declaration_site` is editor-visible navigation, not a runtime usage. The whole-workspace edge build drops such sites by design, so the classification is a field rather than a missing edge.

`surface` is optional and has **no default**, unlike `references_of`. The canonical edge answer includes editor-only rows, and silently defaulting to `external_usages` would narrow the compared ground set without the author saying so.

Only Java, Kotlin, Rust, Python, JavaScript, and TypeScript answer the forward projection. `edges_from` in any other language reports `edge_axis_unsupported` with `incomplete` impact rather than a clean empty answer, and a derivation that was truncated, cancelled or failed reports `edge_derivation_incomplete`.

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

Reference steps accept optional `reference_kinds`, `proof`, and `surface` fields. `reference_kinds` is a non-empty array drawn from `method_call`, `constructor_call`, `field_read`, `field_write`, `type_reference`, `self_type_alias` (a reference through a `Self`-style type alias), `static_reference`, `super_call`, and `inheritance`. `proof` is `proven` or `unproven`. `surface` is `external_usages` (the default) or `lsp_references`. Omitted kind and proof fields include both tiers; a kind filter excludes unclassified structured hits. See the executable [Reference Traversal](/code-query-tutorials/reference-traversal/) recipes.

Call traversal is direct by default. `callers` and `callees` accept a positive finite `depth`; there is deliberately no unbounded `transitive` form. Traversal is iterative and cycle-safe. A real recursive or cyclic edge is returned, but Bifrost stops expanding when the next declaration is already present on that provenance path. The same declaration may still be expanded through a different path, preserving alternate provenance within the execution budget. Every declaration reached by a call step records the proving `call_site` under provenance `via`.

`callers` is exhaustive by default: an omitted related declaration produces an incomplete diagnostic and prevents a complete-negative conclusion. A match policy that only needs positive, resolved callers may opt in to `{"op":"callers","depth":2,"proof":"proven","completeness":"proven_subset"}`. This form is accepted only with `proof: "proven"`; it preserves `call_relation_candidates_omitted` as a `declared_non_exhaustive` diagnostic and reports a proven subset rather than all callers. It is not available for `callees`, and it never relaxes budget, parser, cancellation, or analyzer-failure diagnostics.

`call_sites_to` and `call_sites_from` expose the full call range, callee range, caller and callee declarations, call kind, proof tier, optional explicit receiver, and arguments. `call_input` requires exactly one of `{"receiver":true}`, `{"parameter_index":0}`, or `{"parameter_name":"payload"}`. Parameter indexes are zero-based formal slots and exclude receiver-bound parameters; keyword/named arguments bind by the callee's declared parameter name. A variadic slot may yield several expression rows. Spreads/splats are retained on the call-site result but are not guessed into a formal slot. An implicit receiver has no synthetic expression row.

The three receiver-analysis steps return one row for every input, including unknown and unsupported cases. `receiver_targets` and `points_to` return `receiver_analysis` rows. Each includes `analysis_kind`, input path, language, range, text, and kind, `outcome`, and recursive `values`. `member_targets` returns `member_target_analysis` rows, which carry `outcome`, `coverage`, `target_count`, `site_id`, `site_ast_id`, and the exact member declarations under `member_targets` when they are resolved. Allocation values include their exact type declaration and allocation site. Factory returns include the exact factory declaration plus a nested returned value. Unsupported shapes/providers add `reason`; budget exits add `limit`.

The `member_selection` projection emits exactly one summary row per input occurrence, from the same resolver candidate trace `candidates_of` exposes: a stable domain-separated `id`, the exact `site_ast_id` join key, the decoded `member` spelling and `role`, an `outcome` of `selected`/`unresolved`/`untraced`, `selected_count` and `candidate_count`, `trace_completeness` (`full`, `selection_only`, or `absent`), and `coverage` (`exhaustive` only for a full trace, `open` for a selection-only trace, `unsupported` when the language records no trace). Selected `resolution_candidate` rows additionally carry `canonical_member_id`, a digest of the structured canonical identity (kind-tagged segments, namespace, language, recorded generic arity) -- same-spelling members of different owners always hash apart. Member-position occurrence support is per language: Rust records a full trace; TypeScript and Python record selection-only traces; Java summarizes its trace; Go, C#, C++, PHP, and Ruby do not classify member-position occurrences yet and state that as an `occurrence_role_unsupported` incomplete diagnostic, which makes policies over their rows unreliable rather than clean.

The `receiver_outcome` and `receiver_evidence` steps expose the same analysis as flat typed rows for policy correlation. They may consume an existing receiver-analysis row or perform `receiver_targets` analysis directly from an ordinary call/member site, so a relational binding needs only the one authored step. `receiver_outcome` always emits exactly one row per analyzed site with `outcome`, `coverage` (`exhaustive`, `open`, `truncated`, `unknown`, or `unsupported`), `candidate_count`, `candidates_truncated`, and stable `site_id`/`site_ast_id` keys. `receiver_evidence` emits zero or more rows keyed by `site_id`, each with its own stable `id`, source `range`, `ordinal`, `chain_hop`, `evidence_kind`, resolved declaration identity, and per-row `proof`/`completeness`; model-backed declarations also expose exact `model_id` and `pack_id` string fields for policy predicates. Factory chains are parent-linked through `parent_evidence_id` instead of nesting. An empty evidence set is meaningful only next to its outcome row. See [Receiver Traversal](/code-query-tutorials/receiver-traversal/#typed-receiver-rows) for executed examples.

Stable outcomes are `precise`, `ambiguous`, `unknown`, `unsupported`, and `exceeded_budget`. Ordinary bounded ambiguity retains every candidate and does not set top-level `truncated`. Candidate-cap truncation and `exceeded_budget` do set `truncated` and emit an aggregated limit diagnostic. Adapters return structured candidates where their neutral facts prove them and preserve dynamic, unmodeled, or non-receiver source forms as `ambiguous`, `unknown`, or `unsupported`. `receiver_analysis` rows may feed `file_of`, `receiver_outcome`, or `receiver_evidence`. `member_target_analysis` rows may feed `file_of`, `receiver_outcome`, or `field_write_value`, but not `receiver_evidence`. The flat terminal rows may feed `file_of`.

An optional `capture` is valid only when the preceding domain is a structural match. It must be between 1 and 128 bytes and name a positive capture declared by the structural query; every unique bound range is analyzed. Without a capture, `points_to` analyzes the match or the normalized `right` side of assignment/binding shapes, `receiver_targets` extracts the call `receiver` or field-access `object`, and `member_targets` extracts the receiver plus terminal member. See [Receiver Traversal](/code-query-tutorials/receiver-traversal/) for exact JSON/RQL/output triples.

These steps use normalized tree-sitter call shapes and the selected adapter's existing definition and usage resolvers. Resolution precision still varies with the available structured evidence: unresolved calls are omitted, ambiguous edges are `unproven`, and formal input projection appears only when Bifrost can pair the resolved callee with structured parameter syntax. This is direct call-site projection, not local or interprocedural data flow.

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


### Dispatch and method families

`dispatch_outcome` emits exactly one row per input site, so zero target rows never read as a proven-empty target set. The row carries the semantic `outcome` (`resolved`, `ambiguous`, `unproven`, `unknown`, `unsupported`, `exceeded_budget`, or `cancelled`), the oracle's candidate `coverage`, the retained `target_count`, and the unsupported capability or exceeded budget lane. `exceeded_limit` is nullable and its domain is exactly `source`, `rows`, `retained_bytes`, and `files`. Scans and traversal visits are non-refusing work telemetry; resident admissions and discovery retain their own bounds.

`dispatch_targets` emits zero or more rows per site: one per retained candidate, plus one per boundary arm that names a target. Each row keeps the oracle's own `proof` and `completeness`, repeats the site `coverage`, and states `dispatch` as `proven_dispatch` only for a proven, complete arm inside an exhaustive set. An unresolved or truncated residual arm names no target and emits no row; the site's coverage already states it.

`member_family` emits exactly one row per input declaration: `outcome` (`proven`, `no_family`, `incomplete`, or `unsupported`), the typed `reason` when it is not proven, the measured `capability`, the `coverage`, the `family_id` when the family is proven, and the per-relation edge counts. `family_id` is a digest of this member's own proven family roots. Two members carry the same ID exactly when their root closures are the same. A member that redeclares one root shares that root's ID. A member that redeclares several roots, such as a class method that implements the same method from two interfaces, carries an ID of its own.

`family_edges` returns the forward `overrides` and `implements` edges the analyzer proves from the real hierarchy walk, plus the inverse `overridden_by` and `implemented_by` edges. The same two declarations appear from either end with the relation reversed. `family_id` is the ID of the row's own member, so both ends match only when both members prove the same roots. `proof` is `proven` when the ancestor held exactly one member with that name and recorded arity, and `unproven` when only recorded parameter-type spellings separated an overload set. Edges are emitted only from a proven family.

`candidate_hierarchy` returns the hierarchy hops through which each traced member candidate was found. Each row's `candidate_id` equals the `id` of its `resolution_candidate` row, so the two domains join on that field. A direct candidate emits no hop rows, and neither does a candidate recorded without member attribution. Zero rows never claim that no hierarchy was walked; the per-occurrence outcome is `member_selection`'s.

### Flow-sensitive state and flow relations

`state_events_of` derives one row per establishment, kill, or read of a binding or of a property of a canonical binding base, anchored to a program point of the seed procedure's control-flow graph. `flow_relations_of` relates two of those events.

<!-- code-query-test:json:state-events -->
```json
{
  "languages": ["javascript"],
  "match": {"kind": "function", "name": "handler"},
  "steps": [
    {"op": "procedure_of"},
    {"op": "state_events_of", "event_class": ["establish", "read"], "subject": ["binding"]}
  ]
}
```

<!-- code-query-test:json:flow-relations -->
```json
{
  "languages": ["javascript"],
  "match": {"kind": "function", "name": "handler"},
  "steps": [
    {"op": "procedure_of"},
    {"op": "state_events_of"},
    {"op": "flow_relations_of", "flow_relation": ["reaching"], "certainty": ["exact"]},
    {"op": "flow_target"}
  ]
}
```

`event_class` accepts `establish`, `kill`, and `read`; `subject` accepts `binding` and `property`; `flow_relation` accepts `reaching`, `dominates`, and `same_evaluation`; `certainty` accepts `exact` and `may`.

The production CFG is the only evidence source. A write that appears above a read in the source but that no CFG path carries there produces no reaching row, and structural containment is never presented as any of the three relations. A reaching row is `exact` when the establishment is the only definition of its subject in the read's IN set **and** dominates the read's program point; anything else is `may`.

Every row carries `completeness` (`complete` or `partial`, for that row's own axis) and, when partial, `uncovered_axes`. A partial derivation also reports `flow_state_axis_unsupported` or `flow_state_derivation_incomplete` with `incomplete` impact -- an exhausted control-flow budget emits no rows for its relation rather than a shortened set, and a file that does not lower reports the gap rather than an empty complete answer.

### Bounded rewrite paths

`rewrite_paths_of` enumerates the bounded chases a production analysis engaged over one file. Today one domain is declared: `rust_import_alias`, the `use <module> as <alias>` chase in the Rust resolver. Its semantic state key is the specifier's root, because the rewrite replaces only the root and the specifier grows every hop; its declared bound is the importing file's rewritable root count.

<!-- code-query-test:json:rewrite-paths -->
```json
{
  "languages": ["rust"],
  "match": {"kind": "function", "name": "use_alias"},
  "steps": [
    {"op": "file_of"},
    {"op": "rewrite_paths_of", "domain": ["rust_import_alias"], "rewrite_outcome": ["cycle"]}
  ]
}
```

`domain` accepts `rust_import_alias`; `rewrite_outcome` accepts `converged`, `cycle`, and `exceeded_budget`.

Each row carries `declared_bound`, `step_count`, and the ordered `steps` (`state_key`, `input`, `output`, `rule`), so a reader can replay the chase. The outcome's own payload travels with it: `fixed_point` for `converged`, the ordered `witness` for `cycle` (its last state repeats its first and closes the loop), and `explored` for `exceeded_budget`. The three are distinct claims -- a cycle is a concrete counterexample, while budget exhaustion is absence of evidence and must never be read as either a cycle or a convergence.

A file no declared domain applies to answers empty and complete. A derivation that could not run -- a cancelled query, a workspace without the domain's analyzer -- reports `rewrite_domain_unsupported` or `rewrite_path_derivation_incomplete` with `incomplete` impact instead.

### Qualified paths and their segments

A **qualified path** is one linear chain of segments (`java.util.Map`, `crate::util::Widget`), anchored at its terminal segment token's AST identity. `paths` is a source of its own:

<!-- code-query-test:json:path-seed -->
```json
{
  "languages": ["rust"],
  "paths": {"min_segments": 3}
}
```

Each path row carries `id`, `ast_id` (the terminal segment's identity, the equijoin key with captures and occurrence rows over that token), `path`, `language`, `range`, `start_byte`, `end_byte`, and `segment_count`. A path always has at least two segments; one segment is a bare identifier, not a path.

`segments_of` returns each path's ordered **segment** rows; with `"resolved": true`, one resolver batch per file also answers every segment's own position:

<!-- code-query-test:json:segments-of -->
```json
{
  "languages": ["rust"],
  "paths": {},
  "steps": [
    {"op": "segments_of", "resolved": true}
  ]
}
```

Each segment row carries `path_ast_id` (the group key back to its path), `ordinal`, decoded `text` (a quoted or raw identifier stays one segment and is never re-split), an optional `namespace`, an optional `generic_arity` (the argument count the source spells at that segment: `Map<String, Integer>` spells 2 at `Map`), and -- when resolution was derived -- `resolution_status` (`resolved`, `ambiguous`, `unresolved`, `incomplete`) with `target_count`. `ast_id` is absent for a segment whose token is not a fact (Rust's `crate`/`self`/`super` path keywords): its position in the path is real, its structural identity is genuinely absent. `namespace` is stated only by the adapter's own classification or by what the segment's resolution decides -- a mixed target set decides nothing -- and is otherwise absent, never guessed.

`segment_target` projects each segment's own resolution onto workspace declarations, so "what is `util` in `crate::util::Widget`" is answerable at the segment rather than only at the terminal. A language whose adapter does not answer the path axes reports `identity_axis_unsupported` rather than returning an empty complete answer.

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

Every diagnostic has a `code`, an `impact`, a `language`, and a `message`. The impact says what the diagnostic means for your conclusion:

- `invalid`: the query could not run as written.
- `incomplete`: some work was skipped, unsupported, cut short, or cancelled. Positive rows stay valid, but an empty or short answer does not prove absence.
- `declared_non_exhaustive`: the query asked for a proven subset, such as `callers` with `completeness: "proven_subset"`. The rows are proven but are not all the answers.
- `advisory`: guidance only, such as `broad_query`.

The [diagnostic code table](/reference/code-query/#diagnostic-codes) lists every code with its impact and meaning.

## Limits And Validation Errors

The engine enforces fixed limits on query shape, scanning, pipeline rows, provenance, semantic work, and registered analyses. The [limit tables](/reference/code-query/#limits) list each value. Exceeding a scan limit sets `truncated: true` and adds `execution_budget_exhausted`; exceeding the seed and edge row limit sets `truncated: true` and adds `pipeline_budget_exhausted`.

The semantic limits are a separate typed sub-budget. They are charged only when a semantic step reads a source file; structural-only queries and `explain` mode do not materialize semantic artifacts. `profile` reports materialization attempts, successful unique files, request-cache hits, source/row/retained/traversal work, and budget exhaustion on the physical pipeline step that performed the work.

Public semantic budget failures use five coarse lanes: `source` for input source
bytes, `rows` for retained semantic records, `retained_bytes` for retained text
and artifact storage, `steps` for traversal work, and `files` for file work.
The `dispatch_outcome.exceeded_limit` field reports a lane when the semantic
provider identifies the exceeded limit; it remains null when that information
is unavailable. A null limit does not override an `exceeded_budget` outcome.
Semantic diagnostics, semantic-IR budget text, and semantic extension completion
use the same lane vocabulary across CLI, MCP, LSP, and policy results. Internal
ledger dimension names are not result values. Work counters in profile output
continue to describe the measured work independently of this vocabulary.

Validation failures carry a JSON path so agents can correct the precise field. For example, this misspelling:

```json
{
  "match": {
    "kind": "call",
    "calee": { "name": "eval" }
  }
}
```

reports `unknown field in pattern object` at `match.calee`. The message does not list the accepted fields; see the [pattern field table](/reference/code-query/#patterns). Invalid regexes report paths such as `match.callee.name.regex`; malformed kind arrays include the failing index, such as `match.kind[1]`.

## RQL Interoperability

The same semantic query can be written in [Rune Query Language](/rune-query-language/) while exploring interactively, then inspected with `:json`. JSON and RQL are peer frontends over `CodeQuery`; neither has separate matching semantics.
