---
title: Language and Analysis Capabilities
description: Compare Bifrost language coverage, precision, and known analysis boundaries.
---

Bifrost supports the same broad analysis categories across its languages, but language syntax and resolution rules affect what can be proved. This page is a suitability map, not a promise that every possible program construct resolves. Capability and execution diagnostics remain authoritative for a particular query and workspace.

## How To Read The Matrix

**Structural** means `query_code` can match language-neutral parsed shapes such as declarations, calls, assignments, imports, literals, and containment. **Exact graph** means an indexed declaration identity can be connected to source references, semantic users, and resolved calls without resolving a display name by text. **Proven** means the analyzer established the target from structured language facts. **Unproven** is an explicit best-effort graph candidate used when a dynamic language leaves identity incomplete; it is never silently upgraded to proven.

Named arguments refer to call-site syntax represented by the normalized `kwargs` role. Import-file edges are direct, project-local file relationships used by `imports_of` and `importers_of`; matching an `import` node structurally is a separate, broader capability. Hierarchy means indexed direct `supertypes` and `subtypes`, not compiler-complete effective-member lookup. **Bounded receiver provenance** means the `receiver_targets`, `points_to`, and `member_targets` query steps return explicit analysis outcomes and bounded candidates; it is separate from ordinary call/reference receiver resolution.

## Language Matrix

| Language | Structural | Exact references and calls | Call and receiver precision | Named arguments | Direct import-file edges | Indexed hierarchy |
| --- | --- | --- | --- | --- | --- | --- |
| Python | Yes | Yes | Resolved functions, methods, and properties; dynamic candidates may be `unproven` | Yes | Yes | Yes |
| Java | Yes | Yes | Receiver identity, overloads, constructors, fields, and types | No | Yes | Yes |
| JavaScript | Yes | Yes | Module and method identity; `this` references are separated by result surface | No | Yes | Yes |
| TypeScript | Yes | Yes | JavaScript forms plus typed declaration and module identity | No | Yes | Yes |
| Go | Yes | Yes | Package-scoped functions, methods, fields, and types | No | Yes | Yes, including indexed type relationships |
| C | Yes, through the `cpp` query label | Yes | Functions, fields, and types; method receivers and class inheritance do not apply | No | Yes, through structured includes | Not applicable |
| C++ | Yes, through the `cpp` query label | Yes | Functions, members, fields, types, includes, and structured receiver resolution | No | Yes, through structured includes | Yes |
| Rust | Yes | Yes | Functions, impl members, fields, types, and explicit `self` surface handling | No | Yes | Yes |
| PHP | Yes | Yes | Namespaces, functions, methods, fields, types, static receivers, and `$this` ownership | Yes | No; unsupported traversal returns a diagnostic | Yes |
| Scala | Yes | Yes | Receiver and overload resolution across methods, fields, types, and inheritance | Yes | Yes | Yes |
| C# | Yes | Yes | Receiver and overload resolution across methods, constructors, fields, and types | Yes | Yes | Yes |
| Ruby | Yes | Yes | Resolved methods, fields, and constants; dynamic candidates may be `unproven` | Yes | Yes, for conservative static imports | Yes |

### Bounded Receiver Provenance

| Query languages | `receiver_targets`, `points_to`, and `member_targets` |
| --- | --- |
| JavaScript and TypeScript | Bounded values, allocation/factory provenance, and exact member declarations with explicit outcomes. |
| Python, Java, Go, C/C++, Rust, PHP, Scala, C#, and Ruby | An explicit `unsupported` analysis row plus an aggregated capability diagnostic. |

The executable [language tutorials](/code-query-tutorials/) prove structural vocabulary against fixtures. [Reference Traversal](/code-query-tutorials/reference-traversal/#cross-language-support) exercises inbound and outbound graph pipelines across every graph-backed adapter, [Import Traversal](/code-query-tutorials/import-traversal/#direct-import-forms-by-language) records direct-edge support and the PHP diagnostic boundary, and [Receiver Traversal](/code-query-tutorials/receiver-traversal/) locks the JavaScript/TypeScript provider's exact outcomes and provenance.

## Precision And Completeness

Structural matching is syntax-precise: Bifrost matches normalized Tree-sitter nodes and roles rather than regex or substring approximations. It does not make a structural call match equivalent to a resolved callee identity. Use reference and call traversal when identity matters.

Graph results preserve a proof tier. Filter to `proven` when an answer must contain only analyzer-established identities. Include `unproven` when a dynamic-language best effort is useful, and describe those candidates as possible rather than exact. A proven edge is precise evidence for that returned edge; it is not by itself proof that all possible runtime edges were found.

A zero-result is conclusive only within the reported capability, workspace, filters, and budgets. Before claiming “no matches” or “all callers,” check `truncated`, capability and execution diagnostics, proof tiers, and `provenance_truncated`. [Agent Result Safety](/agent-result-safety/) gives the complete decision rule; the JSON reference sections on [diagnostics](/code-query-json/#planner-and-capability-diagnostics) and [limits](/code-query-json/#limits-and-validation-errors) define the underlying contract.

## Imports, Types, And Dependencies

Import traversal follows resolved direct edges between project files. It can identify candidate importer files, but an importer edge is not proof that a file calls or references a particular member. Compose an exact reference step when the symbol use itself must be proved.

Hierarchy traversal returns indexed direct type relationships. Repeating a bounded step can walk farther, but Bifrost does not currently compute a language's complete effective-member surface with override selection, hiding, access control, or every compiler rule. Member and owner steps navigate exact indexed declaration ownership.

External package imports can be matched structurally, and source references to library code may be visible. External declarations appear as query targets only when their source is genuinely inside the indexed workspace and has a renderable declaration range. Bifrost does not synthesize external declarations from import names, installed package metadata, or runtime objects.

## Analyses Not Currently Provided

Bifrost does not currently provide:

- control-flow graphs or path feasibility;
- whole-program points-to or complete allocation-site analysis (the JavaScript/TypeScript query provider is bounded and demand-driven);
- general alias sets or receiver provenance outside the bounded JavaScript/TypeScript provider;
- general interprocedural data-flow or taint tracking; or
- compiler-complete external dependency indexing.

`call_input` can project the expression written at a resolved call site, and JavaScript/TypeScript `points_to` can analyze that exact expression under a bounded receiver budget. Neither operation is a general value-flow engine. Structural `inside` and `has` constraints prove syntax-tree containment, not runtime control or data flow. Choose another analysis engine when the required claim depends on one of these unsupported guarantees.
