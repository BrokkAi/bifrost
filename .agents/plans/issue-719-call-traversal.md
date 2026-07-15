# Add strict call traversal and composable call inputs to query_code

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this document in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

After this change, `query_code` can start from an exact indexed callable, walk only real call edges to callers or callees, inspect the exact call sites proving those edges, and project the expression supplied to one formal parameter or to the explicit receiver. This enables queries such as “show every direct value passed to the `payload` parameter of this sensitive method,” including calls that spell the argument positionally or by keyword. The first version returns the source expressions supplied directly at resolved call sites; following assignments, aliases, or values through multiple call frames remains separate dataflow work.

The public operations are `callers`, `callees`, `call_sites_to`, `call_sites_from`, and `call_input`. JSON and RQL lower to the same schema-version-2 typed pipeline. The implementation must use tree-sitter and exact analyzer resolution, must not turn general definition/reference edges into calls, and must not add regex, source splitting, delimiter scanning, or name-only source fallbacks.

## Progress

- [x] (2026-07-14 16:55Z) Fetched the live repository and rebased the clean issue branch onto `origin/master` at `bfffb6e5`.
- [x] (2026-07-14 16:55Z) Inspected issue #719, the typed query pipeline, proof-bearing reference traversal, call hierarchy, call-site parsing, structural call roles, lexical parameter collection, public consumers, and executable cookbook harness.
- [x] (2026-07-14 16:55Z) Confirmed the pre-change baseline: 44 `code_query_pipelines` tests and 10 focused call-hierarchy tests pass.
- [x] (2026-07-14 16:55Z) Created this self-contained implementation plan and fixed the public operations, domains, proof policy, recursion policy, and formal-slot semantics.
- [x] (2026-07-14 18:02Z) Milestone 1: added the analyzer-owned call relation, structured call shapes, syntax-derived formal slots, positional/keyword binding, Python bound/static receiver handling, and a resolved Ruby bare-call shape.
- [x] (2026-07-14 18:02Z) Milestone 2: added typed JSON/RQL call steps, `call_site` / `expression_site` results, finite breadth-first traversal, cycle-closing results, call-site provenance, receiver/formal projection, `file_of` composition, and schema-driven validation/help.
- [x] (2026-07-14 18:02Z) Milestone 3: migrated LSP call hierarchy to the shared service, removed the Ruby guard, updated MCP/CLI/Python/VS Code consumers, and documented direct call-input and cross-language precision boundaries.
- [x] (2026-07-14 18:02Z) Milestone 4: reviewed the relation/query/consumer diff, fixed self-receiver inclusion, canonical PHP formal names, named-value AST extraction, RQL token priority, and stale docs; completed focused and repository-wide validation.
- [x] (2026-07-15 07:20Z) Ran the Brokk guided review and applied all twelve queued findings: bounded exact incoming discovery, symmetric recursion, correct Python unbound and constructor binding, keyword-variadic binding, cancellation and work budgets, alternate-path provenance, shared structural call facts, schema-owned parameter-name validation, lazy LSP binding, and shared callable-ancestor helpers.
- [x] (2026-07-15 09:15Z) Fixed the ARM CI call-hierarchy regression for qualified Java constructor calls by preserving the terminal name of `scoped_type_identifier` structural facts; all 182 LSP tests, 57 query-pipeline tests, formatting, and all-feature Clippy pass.
- [x] (2026-07-15 09:20Z) Restored the documented reference-provenance contract after the generalized `PipelineVia` refactor: `references_of` returns the supporting site directly and no longer duplicates it under `via`, while declaration-producing reference and call traversals retain their supporting sites.

## Surprises & Discoveries

- Observation: the Bifrost MCP navigation endpoints named by the installed skills are not exposed in this Codex task.
  Evidence: the active tool catalog contains no `search_symbols`, `get_symbol_sources`, `scan_usages_by_location`, or related Bifrost endpoint, so exploration uses the skills' prescribed targeted `rg` and exact-source fallback.

- Observation: normalized structural calls already carry `callee`, `receiver`, ordered positional `args`, and named `kwargs`, but positional matching is an ordered subsequence rather than an exact index selector.
  Evidence: `src/analyzer/structural/kinds.rs`, `facts.rs`, and `matcher.rs` expose those roles; `Pattern.args` deliberately skips unmatched arguments.

- Observation: proof-bearing reference traversal resolves exact targets and sites but retains only the reference focus, not the containing call or its argument-to-parameter bindings.
  Evidence: `ReferenceSiteValue` in `src/analyzer/structural/search.rs` stores the target, enclosing declaration, focus range, proof, and reference kind without a call range, receiver, or arguments.

- Observation: the LSP call hierarchy has the correct semantic split but duplicates analyzer work and still hard-disables all Ruby outgoing calls even though ordinary Ruby get-definition now works.
  Evidence: `src/lsp/handlers/call_hierarchy.rs` separately filters incoming usage hits with AST call classification, batch-resolves outgoing call leaves, and returns early for `Language::Ruby`.

- Observation: the existing lexical parameter collector already handles receiver parameters and language-specific binding leaves without persistence.
  Evidence: `src/analyzer/lexical_definitions.rs` distinguishes `ReceiverParameter`, ordinary parameters, destructuring, and per-language parameter owners from current tree-sitter syntax.

- Observation: tree-sitter-ruby represents a no-parentheses bare invocation used as a statement as an `identifier`, not a `call` node.
  Evidence: the focused syntax test renders `(body_statement (identifier))` for `def caller; target; end`; exact definition resolution still proves that the node targets a callable, so the shared service treats only that structured expression-statement shape as a zero-argument call.

- Observation: normalizing every incoming reference by rescanning and re-resolving every call in its enclosing caller both amplified LSP work and let unrelated calls consume the target's discovery cap.
  Evidence: `incoming_call_discovery_is_not_limited_by_unrelated_calls` fails under the old per-caller rescan and passes when the exact usage hit is normalized directly against the already-known target; LSP now consumes that same bounded relation without formal-parameter parsing.

- Observation: PHP and C# named arguments attach the name as a field but leave the value as an unfielded expression child, while Scala represents a named argument as an assignment expression with `left` and `right` fields.
  Evidence: the adapter node-type registries and the cross-language named-input test required a structured fallback to the non-name child for PHP/C# and explicit `left`/`right` handling for Scala.

- Observation: the local shell resolves `cargo`/`rustc` from rustup but `clippy-driver` from Homebrew, whose LLVM 22.1.6 build is artifact-incompatible with rustup's LLVM 22.1.2 build despite sharing Rust 1.96.0 version strings.
  Evidence: ordinary and isolated clippy runs failed with E0514; placing `/Users/dave/.rustup/toolchains/1.96.0-aarch64-apple-darwin/bin` first in `PATH` selected the matching driver and completed all-target/all-feature clippy with warnings denied.

- Observation: call syntax had two independent cross-language normalizers: structural adapters for `query_code` and a second tree-sitter decomposition in definition lookup.
  Evidence: call relations now read callee, receiver, ordered arguments, keyword names, and spread metadata from `FileFacts`; Ruby bare calls and Scala infix/postfix calls enter through their structural adapters, and the duplicate argument/receiver parser was removed.

- Observation: tree-sitter Java does not expose a `name` field on every `scoped_type_identifier` shape, including `new pkg.Service()`.
  Evidence: definition lookup resolved both qualified constructor reference leaves to `pkg.Service`, but the Java structural adapter emitted a call fact without a terminal name, so the shared relation could not correlate either reference with the call. Falling back to the rightmost named AST child restores the exact `Service` span without parsing source text.

- Observation: generalizing provenance from reference-only `via` values to `PipelineVia` accidentally made `references_of` render the same reference site twice: once as the step result and again as `via`.
  Evidence: both Linux CI jobs and the local executable reference tutorial showed the duplicated field-read site. Keeping `via` on declaration-producing `used_by`, `uses`, `callers`, and `callees` expansions preserves its role as supporting evidence without changing the established `references_of` output contract.

- Observation: the full macOS Python-feature test link needs the same dynamic-lookup flags used by CI, and several unrelated tests need normal user-cache, subprocess, and git/GPG access.
  Evidence: `RUSTFLAGS='-C link-arg=-undefined -C link-arg=dynamic_lookup' cargo test --all-features --lib` passed 797 tests outside the sandbox after the sandbox run identified only six environment-restricted failures.

- Observation: rendered docs inspection found a stale JSON-reference sentence claiming version 2 did not traverse call graphs.
  Evidence: the fresh Astro preview showed the contradiction above the new call-step documentation; the rebuilt page now describes resolved call edges and contains no stale claim.

## Decision Log

- Decision: introduce first-class `call_site` and `expression_site` pipeline domains rather than projecting arguments from arbitrary `reference_site` rows.
  Rationale: typed composition should make non-call inputs impossible at validation time and should expose the exact semantic edge independently of its caller/callee projection.
  Date/Author: 2026-07-14 / user and Codex

- Decision: keep `callers` and `callees` as callable-to-callable operations, and add `call_sites_to` and `call_sites_from` for site-producing traversal.
  Rationale: the issue's direct call-graph contract remains simple while callers that need receiver or argument data can continue through an explicit call-site value.
  Date/Author: 2026-07-14 / user and Codex

- Decision: `call_input` accepts exactly one of `receiver: true`, zero-based `parameter_index`, or canonical `parameter_name`.
  Rationale: callers care about the callee's semantic slot, not how one call happened to spell it. Receiver-bound declarations such as Python or Rust `self` and Go receivers are excluded from formal indexes and use the receiver slot instead.
  Date/Author: 2026-07-14 / user and Codex

- Decision: stop at direct call-site expressions.
  Rationale: local origin tracking and interprocedural taint/dataflow require distinct value-flow facts and budgets; folding them into call traversal would blur the issue boundary and silently overpromise precision.
  Date/Author: 2026-07-14 / user and Codex

- Decision: query traversal includes proven and unproven relations by default, preserves proof on every site/provenance path, and accepts an explicit proof filter. LSP call hierarchy consumes proven relations only.
  Rationale: security-oriented discovery needs recall and visible uncertainty, while the LSP wire shape cannot represent proof tiers.
  Date/Author: 2026-07-14 / Codex

- Decision: real self-recursive and cycle-closing edges are results. Bounded breadth-first traversal uses path-local cycle detection, retains distinct paths to the same declaration, and never offers unbounded transitive traversal.
  Rationale: recursion is a genuine call relation, and alternate call paths are security-relevant provenance. Parent-linked path nodes avoid cloning complete paths while file, source, candidate, pipeline-row, and provenance-step budgets bound the additional work.
  Date/Author: 2026-07-14 / Codex

- Decision: do not expand override families implicitly.
  Rationale: exact proven runtime targets remain exact edges; analyzer-supported possible dynamic targets remain separate unproven edges that callers can filter. Type-hierarchy steps already provide explicit family traversal.
  Date/Author: 2026-07-14 / Codex

- Decision: structural `FileFacts` are the single call-shape boundary, while formal-slot binding remains a lazy query-only enrichment.
  Rationale: adapters already own grammar-specific call syntax, so relations and structural matching must not parse the same call twice. LSP call hierarchy needs caller/callee edges but not argument binding, so delaying formal extraction and Python receiver resolution avoids unnecessary interactive work.
  Date/Author: 2026-07-15 / Codex

- Decision: constrained query-step strings use a declarative schema value shape.
  Rationale: `parameter_name` previously had runtime and MCP length checks but weaker JSON/RQL live validation. `ValueShape::ParameterName` now supplies one constraint to decoding, source diagnostics, and MCP schema generation.
  Date/Author: 2026-07-15 / Codex

## Outcomes & Retrospective

The issue behavior is implemented and the guided-review queue is exhausted. JSON and RQL traverse direct or finite-depth callers/callees, return exact call sites, and project an explicit receiver or one formal parameter by zero-based index/name. The shared service powers query traversal and LSP call hierarchy, including Ruby bare calls and real recursive/cycle-closing relations. Incoming discovery retains valid sample hits under caps, recursion is symmetric, Python bound/unbound/static calls consume the correct formal slots, constructors bind only a unique structured initializer, and unmatched named inputs reach keyword variadics. Alternate provenance paths survive transitive traversal without eager path cloning.

Call relations now consume the same structural facts as `query_code`, including named and spread arguments, rather than maintaining a second cross-language call parser. Work is charged before materializing rows or provenance, cancellation reaches relation discovery, zero remaining relation budget is diagnostic, and LSP avoids formal binding it does not render. Parameter-name limits are owned by the declarative schema and enforced consistently by runtime decoding, JSON/RQL live validation, and MCP schema generation.

Validation is complete for the review diff: `cargo fmt --all` and `git diff --check` pass; all 57 `code_query_pipelines` tests and all 22 query-source validation tests pass; matching-toolchain `cargo clippy --all-targets --all-features -- -D warnings` passes; and the CI-configured all-feature library suite passes 797 tests with 3 intentionally ignored. The implementation intentionally omits a call-input row when structured formal binding is unavailable or an argument is a spread/splat, and it does not perform dataflow beyond the written expression.

## Context and Orientation

The query language lives in `src/analyzer/structural/query/`. `ir.rs` defines `QueryValueKind`, `QueryStep`, and static domain validation. `schema.rs` is the only authority for public operation names, fields, signatures, descriptions, and constrained values. `decode.rs`, `json.rs`, `sexp.rs`, and `source.rs` implement JSON/RQL parsing, canonical rendering, diagnostics, hover, and completions. Visible RQL vocabulary must also be recognized by `editors/vscode/syntaxes/bifrost-rql.tmLanguage.json`.

`src/analyzer/structural/search.rs` executes structural seeds and typed semantic steps. It retains exact `CodeUnit` and `ProjectFile` identities internally, deduplicates rows deterministically, caps provenance, accounts for source/reference/pipeline budgets, and renders tagged result variants. Existing `references_of`, `used_by`, and `uses` traversal is a useful source of proof-bearing exact reference rows, but it does not model complete calls.

The reusable call capability belongs under `src/analyzer/usages/`, not under `src/lsp/`. `src/analyzer/usages/get_definition/call_sites.rs` already locates per-language call nodes and callee leaves for signature help and call hierarchy. `src/analyzer/lexical_definitions.rs` already identifies formal bindings and receiver parameters from current syntax. `src/lsp/handlers/call_hierarchy.rs` shows the current incoming/outgoing behavior that must migrate to the shared capability.

A call relation is one exact source call edge. It identifies the smallest real indexed caller, exact indexed callee, full call-expression range, callee-focus range, `function_call`, `method_call`, `constructor_call`, or `super_call` kind, proof tier, optional explicit receiver expression, and structured arguments. A formal slot is a call-bound parameter after removing receiver-bound declarations. An expression site is the exact receiver or argument value range selected from one call relation.

## Plan of Work

Milestone 1 adds an analyzer-owned `CallRelationService` under `src/analyzer/usages/`. Refactor call-node discovery out of the LSP-specific path and expose structured per-language call shapes: full call node, logical callee focus, optional explicit receiver, positional values, and keyword name/value pairs. Refactor the lexical parameter machinery to expose query-local formal slots without persisting them. Each slot records a zero-based call-bound index, optional canonical name, accepted positional/keyword modes, and variadic behavior.

Define `CallRelation`, `CallArgument`, `FormalParameterSlot`, `CallExpression`, and a result containing relations, diagnostics, and truncation. Build outgoing relations by scanning only the exact caller body, excluding nested callables/types, then batch-resolving call focuses with current analyzer source. Build incoming relations from target-aware proof-bearing reference hits, validate each hit against an AST call, and add explicit self-source scanning so recursion is not lost to external-usage filtering. Normalize both directions into the same identity and cache outbound work by source/caller and inbound work by target.

Argument binding is structured and language-aware. Positional arguments bind to the next positional-capable slot. Named arguments bind by canonical formal name. Defaults yield no expression when omitted. Variadic slots may bind multiple expressions. Python positional-only/keyword-only markers, bound/class/static methods, Rust/Go/Java receiver parameters, C# extension invocation versus static invocation, Scala parameter lists, PHP sigils, and Ruby keyword and `send`/`public_send` logical arguments must be interpreted from AST fields. Spreads, splats, malformed calls, or shapes whose exact mapping is unavailable produce aggregated diagnostics and no guessed binding.

Milestone 2 extends the typed query pipeline. Keep schema version 2. Add `CallSite` and `ExpressionSite` value kinds and result variants. Add JSON operations `callers`, `callees`, `call_sites_to`, `call_sites_from`, and `call_input`, with hyphenated RQL wrappers. `callers`/`callees` accept optional positive `depth` and `proof`; site steps accept optional `proof`; `call_input` requires exactly one selector. Extend `file_of` for both new domains.

Render a terminal call site with path/language, full range, callee range, caller/callee declarations, call kind, proof, receiver, and arguments including syntax plus bound slot metadata. Render an expression site with path/language/range/text, optional normalized kind, selected slot, argument syntax, and compact call-site identity. `callers` and `callees` return declarations and retain the proving call site under provenance `via`.

Implement direct site expansion and iterative breadth-first callable traversal. Depth one is the default. Depth N returns nodes reached by one through N call edges. Emit a seed when a real self/cycle edge reaches it, stop only cycles already present on the current path, and retain alternate paths to the same declaration. Store parent links instead of cloning whole paths. Account for files, source bytes, examined sites, pipeline rows, and provenance steps before expensive work; cancellation discards partial relations.

Milestone 3 migrates consumers. Replace LSP incoming/outgoing discovery with the shared service and remove the blanket Ruby guard. LSP filters to proven relations, includes proven recursion, and retains its existing range/grouping shape. Update MCP schema/help, CLI/REPL rendering, Python result models, VS Code result unions/tree navigation, live RQL diagnostics, hover/completion, and the conservative TextMate grammar.

Document the operations in the canonical JSON, RQL, overview, and Python-client references, including exact selectors, recursion policy, direct-expression boundary, all-adapter support, and precision caveats. Keep the behavior-focused inline integration tests as the executable examples rather than adding an implementation-shaped tutorial fixture solely to mirror the new registry entries.

Milestone 4 reviews and validates the complete change. Inspect for source mini-parsers, accidental whole-usage-graph reuse, overlay-unsafe disk reads, unbounded work, recursive Rust traversal, nondeterministic ordering, duplicated schema vocabulary, result-consumer drift, and path portability. Fix every finding, update this plan, and commit the reviewed checkpoint.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/3b06/bifrost` on `719-add-call-only-callers-and-callees-traversal-steps-to-query_code`.

After each milestone, run its focused tests, update this plan, inspect `git diff --check` and `git status --short`, stage only the milestone files, and commit a multiline checkpoint describing the reason for the design. Do not push or open a pull request.

Run focused implementation tests with commands such as:

    cargo test analyzer::structural::query
    cargo test --test code_query_pipelines
    cargo test --test code_query_call_traversal
    cargo test --test bifrost_lsp_server call_hierarchy
    cargo test --test code_query_docs --test code_query_tutorials --features nlp,python
    npm --prefix editors/vscode test
    scripts/test_python.sh

Run final repository gates:

    cargo fmt
    cargo clippy --all-targets --all-features -- -D warnings
    cargo test --features nlp,python
    npm --prefix docs run check
    npm --prefix docs run build
    git diff --check

Start a fresh Astro preview after the docs build and inspect the rendered cookbook page and navigation. Do not trust an older preview process.

## Validation and Acceptance

An exact callable seed followed by `callers` returns only exact calling callables. `callees` returns only exact called callables. Field reads, field writes, type references, inheritance, imports, overrides, and ordinary name references never become call edges. Static calls remain calls even if older reference classification labeled the qualifier as static.

Direct traversal is deterministic. A depth-two query returns one-hop and two-hop callables, does not recurse indefinitely, and includes the seed only if a real recursive or cycle-closing edge reaches it. Overloads remain separate by exact `CodeUnit`; override families do not widen silently. Proven and unproven paths are visible and filterable.

`call_sites_to` and `call_sites_from` return navigable full call and callee-focus ranges plus exact caller/callee identity. `call_input` by index and by canonical name returns the same expression when one site is positional and another uses a keyword. Receiver projection returns the explicit object for receiver-aware/dynamic dispatch and does not invent an implicit receiver expression.

All eleven language adapters must pass direct caller/callee and positional-slot coverage. Python, Ruby, Scala, C#, and PHP must pass named-argument coverage. Focused first-version cases cover defaults, variadics, Python bound/static methods, recursion, nested callables, unsupported spread/splat mapping, proof filters, and pipeline budgets. More specialized invocation sugar such as Ruby `public_send`, C# extension-method rebinding, and interprocedural dataflow remains follow-up work; this version exposes the written receiver independently and never guesses a formal mapping from source text.

MCP, Rust JSON, RQL, Python, CLI, LSP, VS Code, and executable docs must agree on operation names, result tags, ranges, proof, and formal-slot metadata. Existing reference traversal, usage graph, scan usages, rename, dead-code, and non-call LSP behavior must remain unchanged.

## Idempotence and Recovery

All analyzer and query work is read-only over indexed sources. No database migration or third-party dependency is required. Formal parameters are derived per query and never persisted. Re-running tests is safe and produces only normal build artifacts.

If a language shape cannot be mapped exactly, retain the structured relation, omit only the uncertain slot projection, and emit a diagnostic; do not use source text or a name-only guess. If a milestone exposes a design flaw, revise this ExecPlan and its Decision Log before continuing. Checkpoint commits isolate milestones and may be inspected independently without resetting unrelated work.

## Artifacts and Notes

Canonical operations and domains:

    declaration --callers----------> declaration
    declaration --callees----------> declaration
    declaration --call_sites_to----> call_site
    declaration --call_sites_from--> call_site
    call_site  --call_input--------> expression_site
    call_site|expression_site --file_of--> file

Example sensitive-parameter query:

    (call-input :parameter-name "payload"
      (call-sites-to
        (enclosing-decl
          (method :name "execute"))))

Equivalent JSON step suffix:

    [
      {"op":"enclosing_decl"},
      {"op":"call_sites_to"},
      {"op":"call_input","parameter_name":"payload"}
    ]

Revision note (2026-07-14): Created the initial self-contained plan after rebasing onto live master, inspecting the current reference/call/query/parameter seams, and locking the user-selected direct-input and formal-slot behavior.

Revision note (2026-07-14): Completed the shared relation, query, and consumer milestones. The design now normalizes incoming hits through the same outgoing call-site builder, handles resolved Ruby bare expression calls, and records Python `staticmethod` versus bound-method receiver semantics from decorator syntax.

Revision note (2026-07-14): Completed final review and validation. Added all-adapter positional and five-adapter named-input coverage, fixed structured PHP/C#/Scala named-value extraction and RQL token precedence, verified the rendered docs, and recorded the local Rust/uv environment constraints encountered by broad tests.

Revision note (2026-07-15): Applied all twelve findings from the Brokk guided review. Consolidated call syntax on structural facts, made formal binding lazy, corrected capped discovery/recursion/Python/constructor/variadic semantics, bounded and cancelled graph/provenance work, preserved alternate paths, centralized parameter-name constraints, and refreshed validation evidence with the CI-equivalent all-feature run.

## Interfaces and Dependencies

Add an analyzer-owned service with the conceptual interface:

    struct CallRelationResult {
        relations: Vec<CallRelation>,
        diagnostics: Vec<CallRelationDiagnostic>,
        truncated: bool,
    }

    impl CallRelationService {
        fn incoming(&mut self, analyzer: &dyn IAnalyzer, target: &CodeUnit, limits: ..., cancellation: ...) -> CallRelationResult;
        fn outgoing(&mut self, analyzer: &dyn IAnalyzer, caller: &CodeUnit, limits: ..., cancellation: ...) -> CallRelationResult;
    }

Internal identities retain `ProjectFile`, `CodeUnit`, and byte `Range`; public paths and line/column ranges are rendered only at the serialization boundary. Reuse existing tree-sitter grammars, definition lookup, targeted usage resolution, structural facts, lexical binding helpers, query budgets, cancellation tokens, serde models, and path utilities. Add no dependency, persistence schema, regex fallback, or LSP-to-query call.
