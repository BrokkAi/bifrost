---
title: Code Querying
description: Understand Bifrost's structural code-querying model and its query representations.
---

Bifrost's composable code-query engine is `query_code`. Version 2 searches normalized syntactic structure and can transform matches through enclosing declarations, exact source references and semantic users, resolved call edges and call-site inputs, direct import-file edges, indexed type hierarchies, declaration ownership, and bounded JavaScript/TypeScript receiver analysis. It answers questions such as “find calls to this callee,” “which declarations call this function,” “what enters this sensitive formal parameter,” “what may this receiver denote,” “which exact member does it select,” and “which types derive from this type” across supported languages.

The broader name is intentional. Future versions may add more steps backed by future control-flow and data-flow analyses. Version 2 does not resolve arbitrary aliases or prove control/data flow. `call_input` projects only the expression written directly at the call site. JavaScript/TypeScript `points_to` may analyze that exact expression through the bounded receiver provider, but it does not become whole-program points-to or general value flow.

## Choose The Right Tool

Use the narrowest tool that directly answers the question:

| Question | Tool | Why |
| --- | --- | --- |
| “Where is `Parser.parse` declared?” | `search_symbols` | Searches indexed declarations by name. |
| “Who references this exact symbol?” | `scan_usages_by_reference` or `scan_usages_by_location` | Resolves a known declaration to reference sites from a symbol or source location. |
| “What is the workspace caller/callee graph?” | `usage_graph` | Returns the existing whole-workspace resolved usage graph. |
| “Which code has this shape, enclosing declaration, import relationship, or indexed type/member relationship?” | `query_code` | Matches normalized kinds and applies typed declaration/file steps. |
| “Which code is conceptually about retry policy?” | `semantic_search` | Retrieves code by meaning rather than exact structure. |
| “Where does this literal text occur?” | `search_file_contents` | Searches source text without structural interpretation. |

Start with `search_symbols` or the mode-appropriate scan-usages tool when you already know the symbol. Use `query_code` when the shape matters more than symbol identity. A useful workflow is to capture structural candidates with `query_code`, then pass their locations or enclosing symbols to the more semantic tools.

## Rune IR

Language adapters map grammar-specific tree-sitter nodes and fields into **Rune IR**, Bifrost's normalized source-side representation. The matcher evaluates typed `CodeQuery` queries against those facts rather than against raw grammar node names.

See [Rune IR](/rune-ir/) for the representation, `.rune` files and VS Code previews, query-by-example workflow, limits, and the complete per-language adapter mapping.

## Version 2 Typed Pipelines

`query_code` validates the structural seed query, lowers it to a shared logical dependency graph, selects physical operators, and then applies an ordered typed pipeline. Queries without steps return tagged structural matches. Complete compatible pipelines can be combined with `union`, `intersect`, and `except`, then passed through another common typed suffix. `enclosing_decl` returns exact indexed declarations; `references_of`, `used_by`, and `uses` traverse exact structured references; `callers`, `callees`, and the call-site steps traverse only AST-confirmed calls; `receiver_targets`, `points_to`, and `member_targets` produce terminal receiver-analysis rows; `file_of`, `imports_of`, and `importers_of` navigate project files; `supertypes` and `subtypes` traverse indexed hierarchy edges; and `members` / `owner` navigate exact declaration ownership. Derived results retain seed-and-edge provenance, including the contributing branch path after composition.

Semantic declaration steps intentionally stop at the analyzer's indexed declaration boundary. Seeing a reference or usage into a dependency is not evidence that the dependency declaration is indexed. Until Bifrost can target library code for indexing, unindexed library declarations are omitted rather than reconstructed from names, and their absence is not reported as a capability error.

| RQL wrapper | JSON step | Input → output | Use it to |
| --- | --- | --- | --- |
| `enclosing-decl` | `enclosing_decl` | structural match → indexed declaration | Find the smallest real declaration that contains a matching expression. |
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
| `file-of` | `file_of` | structural match or semantic source value → file | Move from code, a declaration, reference, call, input expression, or receiver analysis to its project file. |
| `imports-of` | `imports_of` | file → file | Follow one resolved direct project-local import. |
| `importers-of` | `importers_of` | file → file | Find every project file with a resolved direct import of that file. |

For example, `(importers-of (file-of (function :name "target")))` answers “which project files directly import the file declaring `target`?” It is deliberately a file relationship: it does not prove that an importer uses that particular declaration, resolve an out-of-scope library's members, or manufacture external declarations. The schema-v2 `references-of`, `used-by`, and `uses` steps provide that exact declaration relationship separately, and `references-of` can compose through `file-of` when both symbol and import-file provenance matter. See [Typed Set Composition](/code-query-tutorials/set-composition/) for executable union, intersection, and subtraction over import traversal, and [Reference Traversal](/code-query-tutorials/reference-traversal/) for exact declaration edges. For bounded JavaScript/TypeScript values and members, see the executable [Receiver Traversal](/code-query-tutorials/receiver-traversal/) cookbook.

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
