---
title: Language and Analysis Capabilities
description: Compare Bifrost language coverage, precision, and known analysis boundaries.
---

Bifrost supports the same broad analysis categories across its languages, but language syntax and resolution rules affect what can be proved. This page is a suitability map, not a promise that every possible program construct resolves. Capability and execution diagnostics remain authoritative for a particular query and workspace.

The [Languages reference](/reference/languages/) has the complete tables: language labels and file extensions, the full capability matrix, project and build inputs, structural kinds and roles per language, and semantic IR support per language.

## How To Read The Matrix

**Structural** means `query_code` can match language-neutral parsed shapes such as declarations, calls, assignments, imports, literals, and containment. **Exact graph** means an indexed declaration identity can be connected to source references, semantic users, and resolved calls without resolving a display name by text. **Proven** means the analyzer established the target from structured language facts. **Unproven** is an explicit best-effort graph candidate. Any language adapter can return one when the receiver type or target identity is incomplete or ambiguous, for example an unknown receiver type or an interface call with several implementations. Bifrost never upgrades an unproven candidate to proven. Check the proof tier in every language, not only in Python and Ruby.

Named arguments refer to call-site syntax represented by the normalized `kwargs` role. Import-file edges are resolved, project-local file relationships used by `imports_of` and `importers_of`; matching an `import` node structurally is a separate, broader capability. Hierarchy means indexed direct `supertypes` and `subtypes`, not compiler-complete effective-member lookup. **Bounded receiver provenance** means the `receiver_targets`, `points_to`, and `member_targets` query steps return explicit analysis outcomes and bounded candidates; it is separate from ordinary call/reference receiver resolution.

**Direct value-flow baseline** means the production semantic adapter has a
source-backed helper-flow case that agrees across the direct solver, JSON
CodeQuery, and RQL. It proves the shared adapter contract for that fixture, not
complete precision for every language construct.

## Language Matrix

Every language supports structural matching, exact references and calls, the bounded receiver steps, and the direct value-flow baseline. C and C++ share the `cpp` query label. The table shows the capabilities that differ by language. The [Languages reference](/reference/languages/#capability-matrix) adds call and receiver precision, the forms that create import edges, build topology, and semantic-pack ecosystems.

| Language | Named arguments | Import-file edges | Indexed hierarchy | Class-set type flow |
| --- | --- | --- | --- | --- |
| Python | Yes | Yes | Yes | Yes |
| Java | No | Yes | Yes | No |
| JavaScript | No | Yes | Yes | Yes |
| TypeScript | No | Yes | Yes | Yes |
| Go | No | Yes | Yes, including indexed type relationships | No |
| C | No | Yes, through structured includes | Not applicable | No |
| C++ | No | Yes, through structured includes | Yes | No |
| Rust | No | Yes, including edges through `pub use` re-exports to the file that defines the item | Yes | No |
| PHP | Yes | Yes, from namespace `use` clauses and class type references; `require` and `include` paths do not create edges | Yes | Yes |
| Scala | Yes | Yes | Yes | No |
| C# | Yes | Yes | Yes | No |
| Ruby | Yes | Yes, for literal `require`, `require_relative`, `load`, and `autoload` paths | Yes | Yes |
| Kotlin | Yes | Yes | Yes | No |

Class-set type flow powers the `class_set` and `absent_member` query steps. For a language without it, those steps return no rows and the `semantic_capability_unsupported` diagnostic.

Some language behavior limits what the index contains:

- C# `#if` chains: Bifrost parses one branch of each chain, the first one whose condition is not the literal `false`. It does not model defined symbols. Declarations in other branches are not indexed, and the file's semantic diagnostics are marked incomplete.
- Go build constraints are not evaluated. Bifrost indexes every `.go` file, including files that only build on some platforms.
- Bifrost does not analyze `.vue`, `.svelte`, `.razor`, or `.cshtml` templates, or extensions outside the supported list such as `.pyi` and `.mts`. `scan_usages` adds a note when template files are present.
- Build topology steps (`target_of`, `source_set_of`, `topology_edges_of`) read Maven `pom.xml` files only. Gradle builds are not read for topology.

### Bounded Receiver Provenance

`receiver_targets`, `points_to`, and `member_targets` share one adapter-neutral result contract. When an input site exposes structured receiver facts, the steps return bounded values, allocation or factory provenance where represented, and exact owner-scoped members where the analyzer can prove them. Open dispatch, dynamic behavior, metaprogramming, unsupported syntax, and source forms without receiver semantics remain explicit through `ambiguous`, `unknown`, or `unsupported` outcomes.

Receiver availability is not defined by a static language allowlist. The selected adapter, exact source shape, workspace evidence, budgets, and cancellation state determine the result. Treat each `receiver_analysis` row and its diagnostics as authoritative for that input.

The executable [language tutorials](/code-query-tutorials/) prove structural vocabulary against fixtures. [Reference Traversal](/code-query-tutorials/reference-traversal/) exercises inbound and outbound graph pipelines across every graph-backed adapter, [Import Traversal](/code-query-tutorials/import-traversal/) records direct-edge support, and [Receiver Traversal](/code-query-tutorials/receiver-traversal/) locks the shared outcome and provenance contract.

### Bounded Data Flow And Typestate

Every language in the matrix has the direct value-flow baseline described
above; C and C++ share the C-family semantic adapter. Advanced field,
receiver, exceptional-flow, dynamic-dispatch, and external-model precision
still varies by adapter and source shape. The
[semantic IR table](/reference/languages/#semantic-ir-capabilities) lists,
for each adapter, which features are complete, partial, or unsupported.

The public query vocabulary exposes procedure-local CFG inspection plus
value-flow, typestate, and retained taint projections. Only a Rust host that
embeds the [Rust library](/rust-library/) can register the inputs that these
projections read. `.rqlp`
taint policies use the production compiler, set-oriented batch planner, solver,
retained report, and human/JSON/SARIF projection. Typestate policies execute
finite-state protocols over the bounded semantic graph. See [Data Flow, Taint,
and Typestate](/data-flow-and-typestate/) for the execution and registration
boundaries.

## Precision And Completeness

Structural matching is syntax-precise: Bifrost matches normalized Tree-sitter nodes and roles rather than regex or substring approximations. It does not make a structural call match equivalent to a resolved callee identity. Use reference and call traversal when identity matters.

Graph results preserve a proof tier. Filter to `proven` when an answer must contain only analyzer-established identities. Include `unproven` when a best-effort candidate is useful, and describe those candidates as possible rather than exact. This applies to every language: statically typed languages also return `unproven` edges when a receiver type is unknown or several targets remain. A proven edge is precise evidence for that returned edge; it is not by itself proof that all possible runtime edges were found.

A zero-result is conclusive only within the reported capability, workspace, filters, and budgets. Before claiming “no matches” or “all callers,” check `truncated`, capability and execution diagnostics, proof tiers, and `provenance_truncated`. [Agent Result Safety](/agent-result-safety/) gives the complete decision rule; the [Code Query Reference](/reference/code-query/) lists every diagnostic code and execution limit.

## Imports, Types, And Dependencies

Import traversal follows resolved direct edges between project files. It can identify candidate importer files, but an importer edge is not proof that a file calls or references a particular member. Compose an exact reference step when the symbol use itself must be proved.

Hierarchy traversal returns indexed direct type relationships. Repeating a bounded step can walk farther, but Bifrost does not currently compute a language's complete effective-member surface with override selection, hiding, access control, or every compiler rule. Member and owner steps navigate exact indexed declaration ownership.

External package imports can be matched structurally, and source references to library code may be visible. External declarations appear as query targets only when their source is genuinely inside the indexed workspace and has a renderable declaration range. Bifrost does not synthesize external declarations from import names, installed package metadata, or runtime objects.

## Remaining Analysis Boundaries

Bifrost does not currently claim:

- SMT-backed or otherwise path-sensitive feasibility;
- whole-program points-to or complete allocation-site analysis (the receiver-query implementations are bounded and demand-driven);
- general alias sets or receiver provenance beyond the structured facts published by each bounded adapter;
- an arbitrary unregistered data-flow query assembled from structural matches,
  or an unbounded public ICFG traversal;
- compiler-complete external dependency indexing.

`call_input` can project the expression written at a resolved call site, and the selected adapter's `points_to` step can analyze that exact expression under a bounded receiver budget. Neither operation by itself invokes the data-flow engine. Structural `inside` and `has` constraints prove syntax-tree containment, not runtime control or data flow. Use a registered value-flow plan, a taint policy, or a typestate protocol when the required claim is supported by those bounded analyses; choose another analysis engine when it depends on one of the remaining boundaries above.
