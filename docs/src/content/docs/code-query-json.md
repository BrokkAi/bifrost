---
title: JSON CodeQuery
description: Use the canonical JSON representation for Bifrost's query_code engine.
---

JSON `CodeQuery` is the canonical machine-facing representation accepted by Bifrost's `query_code` tool. MCP hosts and the Python client send this shape directly. The RQL REPL prints the same representation with `:json`.

The single supported schema version is 1; it carries the complete vocabulary below. A taint query names only a registered immutable result; it cannot load a policy, compile selectors, run propagation, reconstruct witnesses, or perform policy classification.

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
| `schema_version` | integer | Optional. Version `1` is the only supported version; omit it or pin it explicitly. Other versions are rejected. |
| `match` | pattern | Required root pattern. |
| `where` | string array | Optional project-relative globs. Absolute paths or globs inside the active workspace are normalized by MCP and CLI entrypoints. |
| `languages` | string array | Optional language labels such as `python`, `typescript`, `cpp`, or `csharp`. Empty means every structural adapter. |
| `inside` | pattern | Require the root match to be lexically inside a matching ancestor. |
| `inside_decl` | pattern | Require containment in a matching ancestor without crossing a nested callable declaration. |
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

loop
├── for_loop
└── while_loop
```

The remaining kinds are independent leaves: `call`, `assignment`, `field_access`, `identifier`, `return`, `throw`, `catch`, `if`, `decorator`, and `block`. `block` matches a statement list that opens a lexical scope of its own — a method body, a bare block, a loop or conditional body, a `switch` body — and never a class or interface member list. `for_loop` covers the for-each family (iteration over a collection, iterator, or range); `while_loop` covers condition-controlled loops including do-while and until. Loop forms a language cannot refine lexically — Go's single `for` construct, C-style counting `for`, and Rust's bare `loop` — remain plain `loop`, so query `loop` when every form must match.

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

Each `args` pattern must match a distinct positional argument in source order, but the matches need not be contiguous and do not assert exact arity. For exact positions or arity, narrow the surrounding source shape in a follow-up query; there is no positional-index operator.

`kwargs` support is adapter-specific. Python, PHP, Scala, C#, Ruby, and Kotlin expose normalized named arguments; languages without that role return a capability diagnostic.

## Captures And Results

`capture` adds a named entry to the result. Captures include their text and start line in compact mode; full mode also includes their normalized kind and byte/line/column range when available.

The same capture label may appear more than once in a query. Every occurrence must bind exactly the same source text, allowing equality constraints such as “both arguments use the same expression.”

The response contains a `results` array. Every item has a `result_type`: `structural_match`, `declaration`, `procedure`, `program_point`, `control_edge`, `reference_site`, `call_site`, `expression_site`, `receiver_analysis`, `occurrence`, `lexical_scope`, `binding`, `resolution_candidate`, `reference_edge`, or `file`. A query without steps returns structural matches with path, language, kind, line range, a bounded text snippet, captures, and a best-effort `enclosing_symbol`.

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
| `procedure_of` | structural match or declaration | procedure | Unique smallest source-backed executable procedure enclosing the exact input range. |
| `cfg_entry` | procedure | program point | Validated entry boundary. |
| `cfg_exits` | procedure | program point | Validated normal then exceptional exit boundaries. |
| `cfg_successor_edges` | program point | control edge | One-hop outgoing control edges. |
| `cfg_predecessor_edges` | program point | control edge | One-hop incoming control edges. |
| `cfg_edge_source` | control edge | program point | Source endpoint of an edge. |
| `cfg_edge_target` | control edge | program point | Target endpoint of an edge. |
| `typestate` | procedure | typestate finding | Run the host-registered protocol/binding pair named by `protocol_ref` once for the exact procedure. |
| `value_flow` | procedure | flow endpoint | Run the host-registered `ValueFlowPlan` named by `plan_ref` once for the exact procedure. |
| `taint` | procedure | taint finding | Project the retained production `TaintFindingReport` named by `taint_ref` for the exact procedure. |
| `witness` | typestate finding or flow endpoint | matching witness domain | Project already-retained evidence, optionally reducing it with non-negative `max_steps` and `max_bytes`. |
| `references_of` | declaration | reference site | Exact structured source sites targeting the declaration. |
| `used_by` | declaration | declaration | Smallest exact declaration enclosing each matching site. |
| `uses` | declaration | declaration | Exact indexed declarations referenced by this semantic owner. |
| `callers` | declaration | declaration | Resolved incoming call edges; accepts positive `depth`, optional `proof`, and explicit `proven_subset` completeness. |
| `callees` | declaration | declaration | Resolved outgoing call edges; accepts positive `depth` and optional `proof`. |
| `call_sites_to` | declaration | call site | Structured incoming sites; accepts optional `proof`. |
| `call_sites_from` | declaration | call site | Structured outgoing sites; accepts optional `proof`. |
| `call_input` | call site | expression site | Direct receiver or formal-parameter input selected by exactly one selector. |
| `receiver_targets` | structural match, reference site, call site, expression site, or occurrence | receiver analysis | Receiver values extracted from a call/member site or supplied as an exact expression. |
| `points_to` | structural match, reference site, expression site, or occurrence | receiver analysis | Bounded value, allocation, type, module, current-receiver, and factory provenance. |
| `member_targets` | structural match, reference site, or occurrence | receiver analysis | Exact indexed declarations selected by a receiver-qualified member access. |
| `receiver_outcome` | receiver analysis | receiver outcome | The mandatory terminal row per analyzed site: outcome, coverage, candidate accounting, and stable `site_id`/`site_ast_id`. |
| `receiver_evidence` | receiver analysis | receiver evidence | One flat row per retained receiver observation, parent-linked for factory chains and keyed by `site_id`. |
| `member_selection` | occurrence | member selection | The mandatory selection summary per reference occurrence, projected from the production resolver's candidate trace. |
| `file_of` | structural match, declaration, procedure, program point, control edge, typestate finding, typestate witness, flow endpoint, flow witness, reference site, call site, expression site, receiver analysis, receiver outcome, receiver evidence, occurrence, lexical scope, or binding | file | Exact project file containing the analyzed input value. |
| `imports_of` | file | file | Direct project-local files imported by the input file. |
| `importers_of` | file | file | Direct project-local files importing the input file. |
| `supertypes` | declaration | declaration | Direct ancestors by default, or a bounded/full indexed ancestor closure. |
| `subtypes` | declaration | declaration | Direct descendants by default, or a bounded/full indexed descendant closure. |
| `members` | declaration | declaration | Real direct declaration children of a type. |
| `owner` | declaration | declaration | Exact declaring type of a direct member. |
| `occurrences_in` | structural match or file | occurrence | Classified identifier occurrences lexically inside the node or file; accepts `class`, `role`, and `namespace`. |
| `occurrences_of` | declaration | occurrence | The declaration's own name occurrence plus every reference-class occurrence resolving to it. |
| `occurrence_target` | occurrence | declaration | Resolved semantic targets of reference-class occurrences. |
| `scope_of` | binding, occurrence, or structural match | lexical scope | Innermost lexical scope owning the input. |
| `scope_ancestors` | lexical scope | lexical scope | Enclosing scopes, innermost first, excluding the scope itself. |
| `bindings_in` | lexical scope or structural match | binding | Bindings declared in the scope, or whose binder token is inside the match; accepts `kind`, `name`, and `hoisting`. |
| `reaching_binding` | occurrence | binding | The binding of the occurrence's name in effect at its exact position; accepts `include_shadowed`. |
| `binding_occurrence` | binding | occurrence | The binder-class occurrence row of the binding's declaring token. |
| `candidates_of` | occurrence | resolution candidate | Candidates the resolver considered; accepts `tier`, `outcome`, and `boundary`. |
| `candidate_hierarchy` | occurrence | candidate hop | The exact hierarchy hops each traced member candidate was found through. Each row's `candidate_id` equals the `id` of the `resolution_candidate` row it belongs to, so the two domains join on that field. A depth-zero (direct) candidate emits zero hop rows, and a candidate the resolver recorded without member attribution emits none either -- zero rows is never a claim that no hierarchy was walked, and the mandatory per-occurrence outcome stays `member_selection`'s. |
| `dispatch_outcome` | structural match, call site, reference site, or occurrence | dispatch outcome | The mandatory bounded-dispatch outcome for the site: the semantic outcome (`resolved`, `ambiguous`, `unproven`, `unknown`, `unsupported`, `exceeded_budget`, or `cancelled`), the oracle's candidate `coverage`, the retained `target_count`, and the unsupported capability or exceeded budget dimension. Exactly one row per input site, so zero target rows never read as a proven-empty target set. |
| `dispatch_targets` | structural match, call site, reference site, or occurrence | dispatch target | Zero or more bounded dispatch arms of the site: one per retained candidate, plus one per boundary arm that names a target. Each row keeps the oracle's own `proof` and `completeness`, repeats the site `coverage`, and states `dispatch` as `proven_dispatch` only for a proven, complete arm inside an exhaustive set. An unresolved or truncated residual arm names no target and emits no row; it is already stated by the site's coverage. |
| `member_family` | declaration | member family | The mandatory canonical method-family outcome for the member declaration: `outcome` (`proven`, `no_family`, `incomplete`, or `unsupported`), the typed `reason` when it is not proven, the measured `capability`, the `coverage`, the `family_id` when the family is proven, and the per-relation edge counts. `family_id` digests this member's own proven family roots: two members carry the same id exactly when their root closures coincide, so a member that redeclares one root shares that root's id, and a member that redeclares several roots (a class implementing two interfaces that declare the same method) carries an id of its own. Exactly one row per input declaration, so an unsupported language or an unprovable overload identity is stated rather than silently empty. |
| `family_edges` | declaration | member family edge | The typed method-family edges of the member: the forward `overrides` and `implements` edges the analyzer proves from the real hierarchy walk, plus the bounded inversion of those same edges as `overridden_by` and `implemented_by`. The edge round-trips: the same two declarations appear from either end with the relation reversed. `family_id` is the id of the row's own member, so both ends match only when both members prove the same roots. `proof` is `proven` when the ancestor held exactly one member of that name and recorded arity, and `unproven` when only recorded parameter-type spellings separated an overload set. Emitted only from a proven family. |
| `candidate_target` | resolution candidate | declaration | Workspace declarations of unit-backed candidates; partial by construction. |
| `edges_of` | declaration | reference edge | The inverse projection: every usage site the usage index enumerates for the declaration; accepts `reference_kinds`, `proof`, `surface`, `usage`, `relation`, and `site_class`. |
| `edges_from` | occurrence | reference edge | The forward projection: the resolver's own resolved targets for that exact token; accepts the same six filters. |
| `edge_target` | reference edge | declaration | Exact indexed target declaration of each edge. |

Repeat an import step for multiple hops. Traversal is cycle-safe and deterministic; it does not silently compute a transitive closure.

### Procedure-local CFG inspection

This query starts from a structural function match, resolves its executable procedure, enters its CFG, follows one outgoing edge, and projects the target point:

<!-- code-query-test:json:cfg-entry-successor -->
```json
{
  "schema_version": 1,
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

Every semantic row carries `evidence.proof` (`proven` or `unproven`) and `evidence.completeness` (`complete` or `partial`), with a bounded reason when either status is degraded. Public IDs never expose dense semantic arena IDs and remain stable for identical indexed content mounted at different absolute checkout paths. Diagnostics distinguish unsupported/partial capability, provider failure, missing workspace services, no enclosing procedure, cancellation, and budget exhaustion. An incomplete diagnostic prevents a complete-negative conclusion even when the result array is empty.

Each edge operation is exactly one hop. Compose more steps for a finite traversal; the CFG surface does not provide an unbounded closure, ICFG, data-flow, taint, typestate, finding, or witness endpoint. The registered typestate adapter described next is the only typestate entry point.

### Registered typestate findings and witnesses

An embedding first registers an in-memory compiled protocol and its pre-resolved binding plan under a namespaced reference. The JSON request supplies only that reference; it never supplies a protocol path, binding JSON, policy severity, or query-time mode override.

<!-- code-query-test:json:typestate-witness -->
```json
{
  "schema_version": 1,
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
  "schema_version": 1,
  "match": {"kind": "method", "name": "run"},
  "steps": [
    {"op": "procedure_of"},
    {"op": "value_flow", "plan_ref": "embedding:request-to-sink"},
    {"op": "witness", "max_steps": 32, "max_bytes": 16384}
  ]
}
```

`flow_endpoint` rows keep reachability (`reached`, `not_reached`, or `inconclusive`), exact/may certainty, ambiguity, completion, must-status (`not_established`), and solver termination as separate fields. `flow_witness` rows contain bounded ordered source-backed steps plus truncation metadata. The adapter consumes the existing plan and solver, caches one solve per procedure/plan tuple within the request, and never performs policy classification.

### Retained production taint findings

The host registers immutable results produced by the production taint policy compiler, batch planner, solver, collector, and public projector. A query selects the exact procedure root and projects only retained evidence:

```json
{
  "schema_version": 1,
  "match": {"kind": "method", "name": "run"},
  "steps": [
    {"op": "procedure_of"},
    {"op": "taint", "taint_ref": "request:http-to-database"}
  ]
}
```

`taint_finding` rows preserve stable IDs, reached labels, origins, witnesses, proof/completeness, ambiguity, and truncation metadata. Registration aliases never enter those IDs. Matching projection limits produce rows field-for-field equal to the production policy outcome's public taint findings.

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

Occurrence support is declared per language and per role. Where a language's adapter does not classify a role a query names -- or classifies it but cannot place it in a namespace, as Rust and Java cannot for `path_segment` -- the run reports `occurrence_role_unsupported` with `incomplete` impact instead of returning a clean empty answer. A role the adapter *does* support is not degraded by an unsupported sibling role.

### The lexical environment and resolution candidates

An occurrence says *what* an identifier resolved to. Schema v9 adds the rows that say *why*, and why not.

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

<!-- code-query-test:json:reaching-binding -->
```json
{
  "languages": ["java"],
  "occurrences": {"role": ["receiver_position"]},
  "steps": [
    {"op": "reaching_binding"},
    {"op": "scope_of"}
  ]
}
```

`reaching_binding` returns the binding of the occurrence's name that is in effect at its exact position, computed from activation intervals and scope ancestry rather than from source-order co-presence. Every row it produces carries `reached_from_ast_id`, the AST identity of the occurrence the answer is about, so a caller that captured that token joins the binding back to its own capture instead of guessing; one binding reached from two occurrences is therefore two rows. When more than one binding of the name is in effect, the winner is returned alone unless `include_shadowed` is `true`, in which case the losers follow with `shadowed: true`. When no binding is in effect the answer is an empty one and complete: the name resolves to something other than a lexical binding. When the file's intervals cannot be stated the run reports `environment_derivation_incomplete` instead.

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

Each candidate row carries the `ast_id` of the *reference* it explains, an `ordinal` within that reference's trace, an optional `tier`, an `outcome` (`selected` or `rejected`) with an optional typed `rejection_reason`, a `boundary`, a `visibility`, a `trace_completeness`, and a `candidate` object whose `candidate_kind` is `unit`, `lexical`, `binding`, `import_binder`, or `external_route`.

Three honesty rules govern candidate rows, and none of them can be read off an empty answer:

- An **absent `tier`** means the seam that recorded the candidate could not name one. It is *unattributed*, never "the weakest tier"; a policy comparing tiers must treat it as inconclusive. The `:tier` filter spells this value `unattributed`.
- A `trace_completeness` of `selection_only` means the language's resolver reports only what it selected, so an absent rejection row says nothing. Asking for rejected rows over such a trace reports `resolution_trace_incomplete`.
- `candidate_target` projects only `unit` candidates to declarations. A `binding` or `external_route` candidate carries no workspace declaration by construction, so the step is partial -- it returns fewer rows than it received, and that is the answer rather than a gap.

Where an adapter declares a lexical-environment axis unsupported, the run reports `environment_axis_unsupported` with `incomplete` impact rather than a clean empty answer, exactly as for occurrence roles.

Seed with the roles you need rather than with a class. `{"class": ["reference"]}` requires *every* reference role, so an adapter gap in an unrelated part of a file -- a pattern position it does not classify, a path segment whose namespace it cannot name -- makes the whole run incomplete and the answer unreadable. `{"role": ["receiver_position"]}` asks only for what the question is about, and reports incompleteness only when that role is genuinely unavailable.

The **package clause** is fields on the file row rather than a fourth row kind, because it is exactly one row per file. `package_fq` and `package_syntactic` appear together; `package_syntactic` is `true` when the language spells the package in the source (Java's `package a.b;`) and `false` when it is derived from the file's path (Python, Rust, JavaScript). Both being absent means no package could be named at all, which is not the same as "the file is in the root package".

### Canonical reference edges

Bifrost derives "X uses Y" twice: the resolver derives it forward, from one classified token to the declaration it resolved to, and the usage index derives it backward, from one declaration to the sites that point at it. Schema v11 states both in one row shape so the two answers can be compared instead of merely coexisting.

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

Only Java, Rust, Python, JavaScript and TypeScript answer the forward projection today. `edges_from` in any other language reports `edge_axis_unsupported` with `incomplete` impact rather than a clean empty answer, and a derivation that was truncated, cancelled or failed reports `edge_derivation_incomplete`.

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

`callers` is exhaustive by default: an omitted related declaration produces an incomplete diagnostic and prevents a complete-negative conclusion. A match policy that only needs positive, resolved callers may opt in to `{"op":"callers","depth":2,"proof":"proven","completeness":"proven_subset"}`. This form is accepted only with `proof: "proven"`; it preserves `call_relation_candidates_omitted` as a `declared_non_exhaustive` diagnostic and reports a proven subset rather than all callers. It is not available for `callees`, and it never relaxes budget, parser, cancellation, or analyzer-failure diagnostics.

`call_sites_to` and `call_sites_from` expose the full call range, callee range, caller and callee declarations, call kind, proof tier, optional explicit receiver, and arguments. `call_input` requires exactly one of `{"receiver":true}`, `{"parameter_index":0}`, or `{"parameter_name":"payload"}`. Parameter indexes are zero-based formal slots and exclude receiver-bound parameters; keyword/named arguments bind by the callee's declared parameter name. A variadic slot may yield several expression rows. Spreads/splats are retained on the call-site result but are not guessed into a formal slot. An implicit receiver has no synthetic expression row.

The three receiver steps return a tagged `receiver_analysis` row for every input, including unknown and unsupported cases. Each row includes `analysis_kind`, input path/language/range/text/kind, and `outcome`. `receiver_targets` and `points_to` use recursive `values`; `member_targets` uses exact `CodeQueryDeclaration` values under `member_targets`. Allocation values include their exact type declaration and allocation site. Factory returns include the exact factory declaration plus a nested returned value. Unsupported shapes/providers add `reason`; budget exits add `limit`.

The `member_selection` projection emits exactly one summary row per input occurrence, from the same resolver candidate trace `candidates_of` exposes: a stable domain-separated `id`, the exact `site_ast_id` join key, the decoded `member` spelling and `role`, an `outcome` of `selected`/`unresolved`/`untraced`, `selected_count` and `candidate_count`, `trace_completeness` (`full`, `selection_only`, or `absent`), and `coverage` (`exhaustive` only for a full trace, `open` for a selection-only trace, `unsupported` when the language records no trace). Selected `resolution_candidate` rows additionally carry `canonical_member_id`, a digest of the structured canonical identity (kind-tagged segments, namespace, language, recorded generic arity) -- same-spelling members of different owners always hash apart. Member-position occurrence support is per language: Rust records a full trace; TypeScript and Python record selection-only traces; Java summarizes its trace; Go, C#, C++, PHP, and Ruby do not classify member-position occurrences yet and state that as an `occurrence_role_unsupported` incomplete diagnostic, which makes policies over their rows unreliable rather than clean.

The `receiver_outcome` and `receiver_evidence` projections expose the same analysis as flat typed rows for policy correlation. `receiver_outcome` always emits exactly one row per analyzed site with `outcome`, `coverage` (`exhaustive`, `open`, `truncated`, `unknown`, or `unsupported`), `candidate_count`, `candidates_truncated`, and stable `site_id`/`site_ast_id` keys. `receiver_evidence` emits zero or more rows keyed by `site_id`, each with its own stable `id`, `ordinal`, `chain_hop`, `evidence_kind`, resolved declaration identity, and per-row `proof`/`completeness`; factory chains are parent-linked through `parent_evidence_id` instead of nesting. An empty evidence set is meaningful only next to its outcome row. See [Receiver Traversal](/code-query-tutorials/receiver-traversal/#typed-receiver-rows) for executed examples.

Stable outcomes are `precise`, `ambiguous`, `unknown`, `unsupported`, and `exceeded_budget`. Ordinary bounded ambiguity retains every candidate and does not set top-level `truncated`. Candidate-cap truncation and `exceeded_budget` do set `truncated` and emit an aggregated limit diagnostic. Adapters return structured candidates where their neutral facts prove them and preserve dynamic, unmodeled, or non-receiver source forms as `ambiguous`, `unknown`, or `unsupported`. Receiver-analysis rows are terminal except for `file_of`.

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

## Limits And Validation Errors

The engine enforces these budgets:

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
| Semantic materialized files | `256` |
| Semantic source bytes | `16 MiB` |
| Semantic retained rows per dimension | `1,000,000` |
| Semantic retained artifact/source bytes | `64 MiB` |
| Semantic traversal steps | `1,000,000` |

The semantic limits are a separate typed sub-budget. They are charged only when a v3 semantic step reaches a source file; structural-only queries and `explain` mode do not materialize semantic artifacts. `profile` reports materialization attempts, successful unique files, request-cache hits, source/row/retained/traversal work, and budget exhaustion on the physical pipeline step that performed the work.

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
