---
title: Code Querying
description: Understand Bifrost's structural code-querying model and its query representations.
---

Bifrost's composable code-query engine is `query_code`. The compatible head is schema version 7: it retains versions 2-6 and adds host-registered retained production taint findings. It answers questions such as “find calls to this callee,” “which exact control edge leaves this entry?”, “does this registered resource protocol reach an error transition?”, and “which retained production taint findings belong to this procedure?” across the active workspace.

Version 3's CFG surface remains deliberately procedure-local. Version 4 adds a narrow registered typestate adapter, version 5 adds declaration-bounded containment, and version 6 adds registered value flow. Version 7 adds `taint`, which resolves an exact procedure within an immutable retained production result and invokes only the existing public projector. It never loads or compiles a policy, runs propagation, reconstructs witnesses, or performs policy classification. Explicit version pins remain supported and reject later operations.

## Choose The Right Tool

Use the narrowest tool that directly answers the question:

| Question | Tool | Why |
| --- | --- | --- |
| “Where is `Parser.parse` declared?” | `search_symbols` | Searches indexed declarations by name. |
| “Who references this exact symbol?” | `scan_usages_by_reference` or `scan_usages_by_location` | Resolves a known declaration to reference sites from a symbol or source location. |
| “What is the workspace caller/callee graph?” | `usage_graph` | Returns the existing whole-workspace resolved usage graph. |
| “Which code has this shape, enclosing declaration, import/type relationship, or procedure-local control-flow relationship?” | `query_code` | Matches normalized kinds and applies typed structural and semantic steps. |
| “Which code is conceptually about retry policy?” | `semantic_search` | Retrieves code by meaning rather than exact structure. |
| “Where does this literal text occur?” | `search_file_contents` | Searches source text without structural interpretation. |

Start with `search_symbols` or the mode-appropriate scan-usages tool when you already know the symbol. Use `query_code` when the shape matters more than symbol identity. A useful workflow is to capture structural candidates with `query_code`, then pass their locations or enclosing symbols to the more semantic tools.

## Rune IR

Language adapters map grammar-specific tree-sitter nodes and fields into **Rune IR**, Bifrost's normalized source-side representation. The matcher evaluates typed `CodeQuery` queries against those facts rather than against raw grammar node names.

See [Rune IR](/rune-ir/) for the representation, `.rune` files and VS Code previews, query-by-example workflow, limits, and the complete per-language adapter mapping.

## Typed Pipelines and Declaration-Bounded Containment

`query_code` validates the structural seed query, lowers it to a shared logical dependency graph, selects physical operators, and then applies an ordered typed pipeline. Queries without steps return tagged structural matches. Complete compatible pipelines can be combined with `union`, `intersect`, and `except`, then passed through another common typed suffix. `enclosing_decl` returns exact indexed declarations; `procedure_of` enters the source-backed semantic domain; `cfg_*` traverses procedure-local boundaries and edges; `typestate` consumes one registered solver capability; and `witness` projects its retained evidence. Derived results retain seed-and-edge provenance, including the contributing branch path after composition.

Semantic declaration steps intentionally stop at the analyzer's indexed declaration boundary. Seeing a reference or usage into a dependency is not evidence that the dependency declaration is indexed. Until Bifrost can target library code for indexing, unindexed library declarations are omitted rather than reconstructed from names, and their absence is not reported as a capability error.

| RQL wrapper | JSON step | Input → output | Use it to |
| --- | --- | --- | --- |
| `enclosing-decl` | `enclosing_decl` | structural match → indexed declaration | Find the smallest real declaration that contains a matching expression. |
| `procedure-of` | `procedure_of` | structural match or declaration → procedure | Resolve the unique smallest executable procedure enclosing the exact input range. |
| `cfg-entry` | `cfg_entry` | procedure → program point | Return the validated entry boundary. |
| `cfg-exits` | `cfg_exits` | procedure → program point | Return normal then exceptional exits. |
| `cfg-successor-edges` | `cfg_successor_edges` | program point → control edge | Return one-hop outgoing edges. |
| `cfg-predecessor-edges` | `cfg_predecessor_edges` | program point → control edge | Return one-hop incoming edges. |
| `cfg-edge-source` | `cfg_edge_source` | control edge → program point | Project an edge to its source. |
| `cfg-edge-target` | `cfg_edge_target` | control edge → program point | Project an edge to its target. |
| `typestate` | `typestate` | procedure → typestate finding | Resolve `protocol_ref` against the host snapshot and run the bounded existing typestate client once. |
| `witness` | `witness` | typestate finding → typestate witness | Project retained source-backed steps, optionally reducing them with `max_steps` and `max_bytes`. |
| `references-of` | `references_of` | declaration → reference site | Return exact structured sites targeting a declaration. |
| `used-by` | `used_by` | declaration → declaration | Return each smallest exact semantic user, with its proving site under `via`. |
| `uses` | `uses` | declaration → declaration | Return exact indexed targets used by one semantic declaration, with `via`. |
| `callers` | `callers` | declaration → declaration | Follow incoming calls, direct by default or through a positive `depth`. |
| `callees` | `callees` | declaration → declaration | Follow outgoing calls, direct by default or through a positive `depth`. |
| `call-sites-to` | `call_sites_to` | declaration → call site | Return incoming call sites with caller, callee, proof, receiver, and bound arguments. |
| `call-sites-from` | `call_sites_from` | declaration → call site | Return call sites lexically owned by the declaration. |
| `call-input` | `call_input` | call site → expression site | Select `receiver: true`, a zero-based `parameter_index`, or `parameter_name`. |
| `receiver-targets` | `receiver_targets` | structural match, reference site, call site, or expression site → receiver analysis | Analyze the receiver extracted from a call/member site or an exact receiver expression. |
| `points-to` | `points_to` | structural match, reference site, or expression site → receiver analysis | Return bounded value/allocation/factory provenance for an expression. |
| `member-targets` | `member_targets` | structural match or reference site → receiver analysis | Return exact member declarations selected through the receiver candidates. |
| `occurrences` | `occurrences` | (source) → occurrence | Seed classified identifier occurrences straight from workspace facts, filtered by `class`, `role`, and `namespace`. |
| `occurrences-in` | `occurrences_in` | structural match or file → occurrence | Return the occurrences lexically inside a matching node or a file. |
| `occurrences-of` | `occurrences_of` | declaration → occurrence | Return the declaration's own name occurrence plus every reference-class occurrence resolving to it. |
| `occurrence-target` | `occurrence_target` | occurrence → declaration | Walk a reference-class occurrence back to what it resolved to. |
| `scopes` | `scopes` | (source) → lexical scope | Seed lexical scope rows straight from workspace facts, filtered by `kind`. |
| `bindings` | `bindings` | (source) → binding | Seed lexical binding rows straight from workspace facts, filtered by `kind`, `name`, and `hoisting`. |
| `scope-of` | `scope_of` | binding, occurrence, or structural match → lexical scope | Return the innermost lexical scope that owns the input. |
| `scope-ancestors` | `scope_ancestors` | lexical scope → lexical scope | Walk outward through the enclosing scopes, excluding the scope itself. |
| `bindings-in` | `bindings_in` | lexical scope or structural match → binding | Return the bindings declared in the scope, or whose binder token lies inside the match. |
| `reaching-binding` | `reaching_binding` | occurrence → binding | Return the binding of the occurrence's name in effect at its exact position. |
| `binding-occurrence` | `binding_occurrence` | binding → occurrence | Walk back to the binder-class occurrence of the binding's declaring token. |
| `candidates-of` | `candidates_of` | occurrence → resolution candidate | Return the candidates the resolver considered, with tier, outcome, and boundary. |
| `candidate-target` | `candidate_target` | resolution candidate → declaration | Project unit-backed candidates to declarations; partial by construction. |
| `file-of` | `file_of` | structural match or semantic source value → file | Move from code, a declaration, reference, call, input expression, or receiver analysis to its project file. |
| `imports-of` | `imports_of` | file → file | Follow one resolved direct project-local import. |
| `importers-of` | `importers_of` | file → file | Find every project file with a resolved direct import of that file. |

For example, `(importers-of (file-of (function :name "target")))` answers “which project files directly import the file declaring `target`?” It is deliberately a file relationship: it does not prove that an importer uses that particular declaration, resolve an out-of-scope library's members, or manufacture external declarations. The schema-v2 `references-of`, `used-by`, and `uses` steps provide that exact declaration relationship separately, and `references-of` can compose through `file-of` when both symbol and import-file provenance matter. See [Typed Set Composition](/code-query-tutorials/set-composition/) for executable union, intersection, and subtraction over import traversal, and [Reference Traversal](/code-query-tutorials/reference-traversal/) for exact declaration edges. For bounded receiver values and members, see the executable [Receiver Traversal](/code-query-tutorials/receiver-traversal/) cookbook.

For CFG inspection, `(cfg-edge-target (cfg-successor-edges (cfg-entry (procedure-of (function :name "run")))))` returns the target point of every edge leaving `run`'s entry. Procedure, point, and edge rows carry checkout-independent content-scoped IDs, exact ranges, proof/completeness, and ordinary CodeQuery provenance. Each edge step is one hop and shares a separate finite semantic file/source/row/retained-byte/traversal budget. Explain mode shows the requested semantic facets without materialization; profile mode attributes actual semantic work to the physical pipeline steps.

For registered typestate, `(witness :max-steps 32 :max-bytes 16384 (typestate :protocol-ref "embedding:resource-lifecycle" (procedure-of (function :name "lifecycle"))))` returns only the bounded witnesses retained by the same solver run. Findings and witnesses carry stable protocol/binding hashes, canonical subjects, certainty, proof/completeness, uncertainty, exact ranges, and omission metadata, but no severity or policy presentation. The host must pre-register the alias against the current workspace generation and exact procedure root; otherwise results/profile mode returns a typed incomplete diagnostic. Explain mode can still plan the query without resolving or running the registration.

For typed occurrences, `(occurrences :role binder (language "rust"))` is not the spelling: `occurrences` is a *source*, so it is wrapped rather than wrapping, as in `(language "rust" (occurrences :role binder))`. Each row says what the parser thinks one identifier token is at one exact position, with the resolved target for reference-class rows. Its `ast_id` is the content-scoped identity of the underlying AST node, equal to the `ast_id` a full-detail structural capture over the same node reports, so captures and occurrences join on one opaque string instead of on coincident ranges or spellings. Occurrence support is declared per language and per role; a query naming a role an adapter does not classify is reported incomplete rather than answered with zero rows.

For the lexical environment, `(scope-of (reaching-binding (occurrences :role receiver_position)))` answers the question the whole family exists for: which binding of this name is actually in effect at this position, and where was it declared? The reaching binding is computed from activation intervals and scope ancestry, never from source-order co-presence, so a rebinding, a shadowing outer name and a read before a declaration all give different answers. `scopes` and `bindings` are *sources* like `occurrences`, so they are wrapped rather than wrapping.

For resolution candidates, `(candidates-of :outcome selected (occurrences :class reference))` lists what the resolver considered for each reference, with a precedence tier, an outcome, and a boundary status. Three things are deliberately not inferable from an empty answer: a candidate with no tier is *unattributed* rather than weakest (the `:tier unattributed` filter selects those rows); a trace whose `trace_completeness` is `selection_only` says nothing by omitting a rejection; and `candidate-target` answers only for unit-backed candidates, because a lexical binding and an external route carry no workspace declaration at all. Each of the three reports an `incomplete` diagnostic rather than a clean empty result where it matters.

The engine has one semantic query model: `CodeQuery`. Different input formats must lower into that same model before execution.

## Query Representations

Bifrost currently has two representations for `CodeQuery`:

- [Rune Query Language](/rune-query-language/) is the experimental S-expression syntax used by the human REPL.
- [JSON CodeQuery](/code-query-json/) is the canonical JSON representation used by `query_code` over MCP and by `:json` output in the REPL.

JSON is not a separate query language. It is the stable serialization of the `CodeQuery` model. RQL is a convenience language that compiles to that JSON-shaped model.

See [JSON CodeQuery](/code-query-json/) for the complete schema, validation rules, result model, and copy-paste examples. See [Rune Query Language](/rune-query-language/) for interactive authoring and canonical JSON inspection. Use [Explain and Profile CodeQuery](/code-query-explain-profile/) to inspect logical sharing and physical selection before execution or collect opt-in operator, cache, budget, wait, and concurrency observations from one execution.

For source-first walkthroughs, see the [per-language `query_code` tutorials](/code-query-tutorials/). Their fixtures, RQL and JSON forms, and exact results are exercised against the real structural adapters.

## CLI Mini Tutorial

The examples below use one-shot CLI mode. They were validated against a toy workspace containing the small per-language shapes on the [Rune IR adapter-mapping page](/rune-ir/#language-adapter-mappings), with one file for each supported language. The [JSON reference](/code-query-json/) contains the complete, test-parsed input examples.

### Saved Queries

For a reusable query, save the complete RQL or canonical JSON query under the workspace and run it directly:

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
