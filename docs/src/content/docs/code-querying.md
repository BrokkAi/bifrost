---
title: Code Querying
description: Understand Bifrost's structural code-querying model and its query representations.
---

Bifrost's composable code-query engine is `query_code`. The single supported schema version is `"1"`; it carries the complete query vocabulary, including host-registered retained production taint findings. It answers questions such as “find calls to this callee,” “which exact control edge leaves this entry?”, “does this registered resource protocol reach an error transition?”, and “which retained production taint findings belong to this procedure?” across the active workspace.

The CFG surface remains deliberately procedure-local. A narrow registered typestate adapter, declaration-bounded containment, and registered value flow are part of the same vocabulary. The `taint` step resolves an exact procedure within an immutable retained production result and invokes only the existing public projector. It never loads or compiles a policy, runs propagation, reconstructs witnesses, or performs policy classification.

## Choose The Right Tool

Use the narrowest tool that directly answers the question:

| Question | Tool | Why |
| --- | --- | --- |
| “Where is `Parser.parse` declared?” | `search_symbols` | Searches indexed declarations by name. |
| “Who references this exact symbol?” | `scan_usages_by_reference` or `scan_usages_by_location` | Resolves a known declaration to reference sites from a symbol or source location. |
| “What is the workspace caller/callee graph?” | `usage_graph` | Returns the existing whole-workspace resolved usage graph. |
| “Which code has this shape, enclosing declaration, import/type relationship, or procedure-local control-flow relationship?” | `query_code` | Matches normalized kinds and applies typed structural and semantic steps. |
| “Where does this literal text occur?” | `search_file_contents` | Searches source text without structural interpretation. |

Start with `search_symbols` or the mode-appropriate scan-usages tool when you already know the symbol. Use `query_code` when the shape matters more than symbol identity. A useful workflow is to capture structural candidates with `query_code`, then pass their locations or enclosing symbols to exact navigation tools.

## Rune IR

Language adapters map grammar-specific tree-sitter nodes and fields into **Rune IR**, Bifrost's normalized source-side representation. The matcher evaluates typed `CodeQuery` queries against those facts rather than against raw grammar node names.

See [Rune IR](/rune-ir/) for the representation, `.rune` files and VS Code previews, query-by-example workflow, limits, and the complete per-language adapter mapping.

## Typed Pipelines and Declaration-Bounded Containment

`query_code` validates the structural seed query, lowers it to a shared logical dependency graph, selects physical operators, and then applies an ordered typed pipeline. Queries without steps return tagged structural matches. Complete compatible pipelines can be combined with `union`, `intersect`, and `except`, then passed through another common typed suffix. `enclosing_decl` returns exact indexed declarations; `procedure_of` enters the source-backed semantic domain; `cfg_*` traverses procedure-local boundaries and edges; `typestate` consumes one registered solver capability; and `witness` projects its retained evidence. Derived results retain seed-and-edge provenance, including the contributing branch path after composition.

Semantic declaration steps intentionally stop at the analyzer's indexed declaration boundary. Seeing a reference or usage into a dependency is not evidence that the dependency declaration is indexed. Until Bifrost can target library code for indexing, unindexed library declarations are omitted rather than reconstructed from names, and their absence is not reported as a capability error.

Steps come in families. Each RQL wrapper has a JSON step whose name uses underscores, such as `enclosing-decl` and `enclosing_decl`. The table names the families and some typical steps; follow a family link for its complete step table.

| Family | Typical steps | Use it to |
| --- | --- | --- |
| [Row operations](/reference/code-query/#row-operations) | `filter`, `project` | Keep rows by typed predicates, or publish selected fields to a relational binding. |
| [Declarations, files, and imports](/reference/code-query/#declarations-files-and-imports) | `enclosing-decl`, `file-of`, `imports-of`, `importers-of`, `python-import-site`, `python-import-cycles` | Move from code to its declaration or file, follow direct imports, and inspect Python import facts or confirmed cycles. |
| [Type hierarchy and members](/reference/code-query/#type-hierarchy-and-members) | `supertypes`, `subtypes`, `members`, `owner`, `member-family` | Walk indexed type relations and method families. |
| [References and calls](/reference/code-query/#references-and-calls) | `references-of`, `used-by`, `callers`, `call-sites-to`, `call-input` | Follow exact references and resolved call edges. |
| [Reference edges](/reference/code-query/#reference-edges) | `edges-of`, `edges-from`, `edge-target` | Compare forward and inverse "X uses Y" edges in one row shape. |
| [Occurrences, scopes, bindings, and resolution](/reference/code-query/#occurrences-scopes-bindings-and-resolution) | `occurrences-in`, `binding-of`, `scope-of`, `candidates-of`, `overload-selection` | See what each identifier is, which binding is in effect, and why the resolver chose a target. |
| [Qualified paths](/reference/code-query/#qualified-paths) | `segments-of`, `segment-target` | Resolve each segment of a qualified path. |
| [Receivers and dispatch](/reference/code-query/#receivers-and-dispatch) | `receiver-targets`, `points-to`, `member-targets`, `receiver-outcome`, `dispatch-targets` | Analyze receiver values, member targets, and dispatch, within bounds. |
| [Call shape, bindings, and signatures](/reference/code-query/#call-shape-bindings-and-signatures) | `call-shape`, `call-bindings`, `resolved-call`, `call-argument`, `resolved-value`, `callable-signature` | Map written arguments to formal parameters, select calls by resolved identity, and identify exact declarations used as values. |
| [Effects and result contracts](/reference/code-query/#effects-and-result-contracts) | `call-effects`, `procedure-effects`, `call-result-contracts`, `result-contract-operation-uses` | Read declared effects and check uses of results against reviewed contracts. |
| [Procedures, control flow, and branch and loop relations](/reference/code-query/#procedures-control-flow-and-branch-and-loop-relations) | `procedure-of`, `cfg-entry`, `cfg-successor-edges`, `control-relations`, `guards-of`, `branch-relations` | Inspect one procedure's control-flow graph and derived relations. |
| [Flow, state, taint, and typestate](/reference/code-query/#flow-state-taint-and-typestate) | `state-events-of`, `flow-relations-of`, `value-flow`, `taint`, `typestate`, `witness`, `absent-member` | Read flow-sensitive state, and run or project registered analyses. |
| [Values](/reference/code-query/#values) | `jsx-attribute-value`, `keyed-read-value`, `field-write-value` | Resolve specific value expressions, such as JSX attribute values or runtime environment reads. |
| [Build topology](/reference/code-query/#build-topology) | `target-of`, `source-set-of`, `topology-edges-of` | Read build targets, source sets, and declared target dependencies. |
| [Materialization](/reference/code-query/#materialization) | `generated-by`, `declaration-state-of`, `implementation-of`, `export-target` | Explain generated, declaration-only, recovered, and exported declarations. |
| [Rewrite paths](/reference/code-query/#rewrite-paths) | `rewrite-paths-of` | Show bounded rewrite chases and how they ended. |

Some queries start from a seed source instead of a structural pattern: `occurrences`, `scopes`, `bindings`, `paths`, `generation-sites`, `exports`, `dependency-evidence`, and `configuration-facts`. A seed source is wrapped by steps; it does not wrap a query. The [query plan field table](/reference/code-query/#query-plan-fields) lists each source and its filters.

Row-local steps are schema checked before execution. In RQL, `(filter :where
((target_count gt 0)) QUERY)` uses unqualified field names because the pipeline
has one current row. `(project :columns (ast_id (target_count candidates))
QUERY)` publishes `ast_id` and renamed `candidates` fields to a relational
binding; later filters use those projected names. JSON uses typed literal
objects and `{ "field": "NAME" }` for a second-field operand. See the RQL and
JSON references for the full operator, literal, and bound tables.

For example, `(importers-of (file-of (function :name "target")))` answers “which project files directly import the file declaring `target`?” It is deliberately a file relationship: it does not prove that an importer uses that particular declaration, resolve an out-of-scope library's members, or manufacture external declarations. The `references-of`, `used-by`, and `uses` steps provide that exact declaration relationship separately, and `references-of` can compose through `file-of` when both symbol and import-file provenance matter. See [Typed Set Composition](/code-query-tutorials/set-composition/) for executable union, intersection, and subtraction over import traversal, and [Reference Traversal](/code-query-tutorials/reference-traversal/) for exact declaration edges. For bounded receiver values and members, see the executable [Receiver Traversal](/code-query-tutorials/receiver-traversal/) cookbook.

Rust import edges follow `pub use` re-exports. A Rust `use` creates an edge to
the module file that its path names. It also creates an edge to the file that defines
the item, when the path reaches the item through re-exports. This covers
single-name, chained, glob, and module re-exports, also across Cargo crates.
The edge can point past the file that holds the re-export. Provenance keeps
every `file-of`, `imports-of`, and `importers-of` step. The edge still does
not show that the importing file uses a particular declaration.

For CFG inspection, `(cfg-edge-target (cfg-successor-edges (cfg-entry (procedure-of (function :name "run")))))` returns the target point of every edge leaving `run`'s entry. Procedure, point, and edge rows carry checkout-independent content-scoped IDs, exact ranges, proof/completeness, and ordinary CodeQuery provenance. Each edge step is one hop and shares a separate finite semantic file/source/row/retained-byte/traversal budget. Explain mode shows the requested semantic facets without materialization; profile mode attributes actual semantic work to the physical pipeline steps.

For registered typestate, `(witness :max-steps 32 :max-bytes 16384 (typestate :protocol-ref "embedding:resource-lifecycle" (procedure-of (function :name "lifecycle"))))` returns only the bounded witnesses retained by the same solver run. Findings and witnesses carry stable protocol/binding hashes, canonical subjects, certainty, proof/completeness, uncertainty, exact ranges, and omission metadata, but no severity or policy presentation. Only an in-process Rust host can register the alias, against the current workspace generation and exact procedure root. Otherwise, including in the CLI, REPL, and MCP server, results and profile mode return an `unresolved_protocol_reference` diagnostic with `incomplete` impact. See [Data Flow, Taint, and Typestate](/data-flow-and-typestate/). Explain mode can still plan the query without resolving or running the registration.

For typed occurrences, `(occurrences :role binder (language "rust"))` is not the spelling: `occurrences` is a *source*, so it is wrapped rather than wrapping, as in `(language "rust" (occurrences :role binder))`. Each row says what the parser thinks one identifier token is at one exact position, with the resolved target for reference-class rows. Its `ast_id` is the content-scoped identity of the underlying AST node, equal to the `ast_id` a full-detail structural capture over the same node reports, so captures and occurrences join on one opaque string instead of on coincident ranges or spellings. Occurrence support is declared per language and per role; a query naming a role an adapter does not classify is reported incomplete rather than answered with zero rows.

For the lexical environment, `(scope-of (binding-of (occurrences :role receiver_position)))` answers the question the whole family exists for: which binding of this name is actually in effect at this position, and where was it declared? The binding-of answer is computed from activation intervals and scope ancestry, never from source-order co-presence, so a rebinding, a shadowing outer name and a read before a declaration all give different answers. `scopes` and `bindings` are *sources* like `occurrences`, so they are wrapped rather than wrapping.

For resolution candidates, `(candidates-of :outcome selected (occurrences :class reference))` lists what the resolver considered for each reference, with a precedence tier, an outcome, and a boundary status. Three things are deliberately not inferable from an empty answer: a candidate with no tier is *unattributed* rather than weakest (the `:tier unattributed` filter selects those rows); a trace whose `trace_completeness` is `selection_only` says nothing by omitting a rejection; and `candidate-target` answers only for unit-backed candidates, because a lexical binding and an external route carry no workspace declaration at all. Each of the three reports an `incomplete` diagnostic rather than a clean empty result where it matters.

For canonical reference edges, `(edges-of :usage [reference] (enclosing-decl (function :name "register")))` and `(edges-from (occurrences :class reference))` state the same kind of fact from opposite ends, in one row shape, so the two derivations can be compared rather than merely coexisting. Every classification a comparison depends on -- the reference kind, the proof tier, the usage kind, the site class, the owner relation, the derivation direction and the workspace generation -- is an explicit field, never inferred from which step produced the set or from how many rows came back. `:surface` is optional with no default, because the complete edge answer includes editor-only rows. Only Java, Kotlin, Rust, Python, JavaScript, and TypeScript answer the forward projection; `edges-from` in any other language reports `edge_axis_unsupported` rather than an empty answer.

For flow-sensitive state, `(flow-relations-of :relation [reaching] :certainty [exact] (state-events-of (procedure-of (function :name "handler"))))` answers "has an assignment to this binding actually executed before this read?". The production control-flow graph is the only evidence source: source order, file co-presence and structural containment are never presented as a reaching-definition, a dominance, or a same-evaluation relation. A write that appears one line above a read but that no CFG path carries there produces no reaching row. `exact` means the establishment is the only definition of that subject in the read's IN set *and* dominates the read's program point; anything else is `may`. Where the lowering does not model an axis -- a language without CFG lowering, a field access with no binding-rooted base, a local the adapter declares but never establishes -- the rows say `completeness: partial`, name the uncovered axes, and the response carries `flow_state_axis_unsupported` or `flow_state_derivation_incomplete`. An empty answer is never silently a complete one, and an exhausted control-flow budget emits no rows rather than a shortened relation set.

For bounded termination, `(rewrite-paths-of :outcome [cycle] (file-of (function :name "use_alias")))` answers "does this file make a supported rewrite chase loop?". A rewrite domain is a declared finite state space with a rewrite rule; the row states the semantic state key of every step, the bound the domain declared for itself, and how the chase ended. The three outcomes are separate claims and are never blurred: `converged` names the fixed point, `cycle` carries the ordered repeated-state witness that closes the loop, and `exceeded-budget` names only the work performed. Budget exhaustion is absence of evidence -- it is never reported as a cycle, and never as a clean convergence.

The engine has one semantic query model: `CodeQuery`. The `query_code` operation
executes that model; it is not the name of a second query language. Different
input forms must become a validated `CodeQuery` before planning and execution.

## Query Representations

The terminology describes three layers:

| Form | Prefer it when | Trade-off and execution path |
| --- | --- | --- |
| [Rune Query Language (RQL)](/rune-query-language/) | A person is exploring, reviewing, or maintaining a query. Its compact S-expression nesting, comments, multiline input, and REPL/editor assistance favor hand authoring. | RQL is the single authoring syntax. It decodes to a validated `CodeQuery`, which can generate canonical JSON. MCP cannot accept raw RQL inline, but `query_file` can name a saved workspace `.rql` file. |
| [JSON `CodeQuery`](/code-query-json/) | An agent, script, Python client, or other protocol client needs an explicit, schema-versioned payload. | JSON is generated from a decoded `CodeQuery` and remains the stable machine-facing serialization. MCP accepts its fields inline through `query_code`, and `query_file` can name a saved `.json` query. |
| Rust `CodeQuery` value | An in-process Rust embedding already owns query construction and execution. | The caller can parse or construct the typed model and use the lower-level execution API without a wire-format round trip. Deployed protocol-style behavior goes through `SearchToolsService`; protocol clients use JSON. |

RQL compiles to the typed model; generated JSON serializes that same model. Both
execution paths share the planner, executor, result types, budgets, and
completeness rules. Author queries in RQL; generate canonical JSON from the
decoded model for machine integration. Rust embedders can construct the typed
model directly. `.rql` files and editor buffers accept RQL text only.

See [JSON CodeQuery](/code-query-json/) for the complete schema, validation
rules, result model, and machine payload examples. See
[Rune Query Language](/rune-query-language/) for interactive authoring and
canonical JSON inspection, and the Query and RQL Availability section of
[MCP](/mcp/) for the exact inline and saved file surfaces. Use [Explain and Profile
CodeQuery](/code-query-explain-profile/) to inspect logical sharing and physical
selection before execution or collect opt-in operator, cache, budget, wait, and
concurrency observations from one execution.

For source-first walkthroughs, see the [per-language `query_code` tutorials](/code-query-tutorials/). Their fixtures, RQL and JSON forms, and exact results are exercised against the real structural adapters. To call `query_code` from an embedding application rather than from MCP or the REPL, see [Library Integration](/code-query-tutorials/library-integration/): it runs one canonical query through both `SearchToolsService::query_code_result(...)` and `SearchToolsClient.query_code(...)` and shows how each caller reads diagnostics, `truncated`, provenance completeness, and receiver `outcome` before making a completeness-sensitive claim.

## CLI Mini Tutorial

The examples below use one-shot CLI mode. They were validated against a toy workspace containing the small per-language shapes on the [Rune IR adapter-mapping page](/rune-ir/#language-adapter-mappings), with one file for each supported language. The [JSON reference](/code-query-json/) contains the complete, test-parsed input examples.

### Saved Queries

For a reusable query, save the authored RQL query or generated canonical JSON under the workspace and run it directly:

```bash
bifrost --query-file queries/audit.rql
bifrost --root ./code-query-toy --query-file queries/audit.json
```

The current directory is the default workspace root. Query files must stay within that workspace after symlinks resolve. `--query-file` selects the complete query and does not merge command-line filters or inline JSON.

Find calls to `audit` across every structural adapter:

```bash
bifrost --root ./code-query-toy --tool query_code --args '{"match":{"kind":"call","callee":{"name":"audit"}},"limit":20}'
```

The result contains one `call` match for each current analyzable language and no diagnostics. Representative rows look like:

```json
{"result_type":"structural_match","language":"python","path":"python/app.py","kind":"call","text":"audit(code)"}
{"result_type":"structural_match","language":"typescript","path":"typescript/app.ts","kind":"call","text":"audit(code)"}
{"result_type":"structural_match","language":"ruby","path":"ruby/app.rb","kind":"call","text":"audit(code)"}
```

Find assignments to `password` whose right-hand side is a string literal, and capture the value:

```bash
bifrost --root ./code-query-toy --tool query_code --args '{"match":{"kind":"assignment","left":{"name":"password"},"right":{"kind":"string_literal","capture":"value"}},"limit":20}'
```

The result contains one assignment match per language. The captured `value` is `"hunter2"` in each match, even though the source syntax varies:

```json
{"result_type":"structural_match","language":"java","text":"password = \"hunter2\"","captures":[{"name":"value","text":"\"hunter2\""}]}
{"result_type":"structural_match","language":"php","text":"$password = \"hunter2\"","captures":[{"name":"value","text":"\"hunter2\""}]}
{"result_type":"structural_match","language":"rust","text":"let password = \"hunter2\";","captures":[{"name":"value","text":"\"hunter2\""}]}
```

Limit a query to one adapter while debugging a mapping:

```bash
bifrost --root ./code-query-toy --tool query_code --args '{"languages":["typescript"],"match":{"kind":"call","callee":{"name":"audit"},"args":[{"capture":"argument"}]},"result_detail":"full"}'
```

This searches only TypeScript files and returns the matched call plus deterministic byte and line ranges because `result_detail` is `full`.

## Where To Start

Use RQL when you are exploring a repository interactively:

```bash
bifrost --root /path/to/project --repl
```

Use JSON `CodeQuery` when a host, script, or MCP client needs a stable machine-facing payload for the `query_code` tool.
