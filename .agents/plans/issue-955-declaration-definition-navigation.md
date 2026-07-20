# Distinguish declaration and definition navigation

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this document in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost currently exposes only definition navigation, but its internal resolver intentionally returns the broad set of semantically related declarations and definitions needed by hover, references, rename, and call analysis. After this change, MCP, the Python client, and LSP clients can explicitly request either the declaration contract or the concrete definition body without weakening those internal consumers. A user can ask for a C++ header prototype separately from its source body, distinguish a Rust trait associated type from an implementation item, and use `textDocument/declaration` in an editor.

The behavior is observable through analyzer contract tests, MCP response JSON, Python model rendering, and LSP click-around tests. Every location-navigation result also reports the requested `operation`, so consumers can validate that a declaration or definition selector produced it.

## Progress

- [x] (2026-07-20 12:06Z) Re-read repository instructions, inspected the clean issue branch, fetched `origin`, and confirmed HEAD matches its upstream at `3fdaa719`.
- [x] (2026-07-20 12:21Z) Implemented the shared navigation operation and operation-aware analyzer selector while preserving the broad resolver.
- [x] (2026-07-20 12:21Z) Added passing Java, C++, and Rust inline-project navigation contract coverage, including serialized operations.
- [ ] Expose declaration navigation through MCP, path normalization, Python models/client/exports, and public documentation (completed: Rust MCP models, descriptor, registry, dispatch, and path normalization; remaining: MCP test expansion, Python, and docs).
- [ ] Advertise and dispatch LSP declaration navigation and extend the click-test harness.
- [ ] Run focused tests, Python tests, formatting, clippy, full feature tests, and `git diff --check`.
- [ ] Run the guided specialist review, address required findings, rerun affected gates, and record the reviewed outcome.

## Surprises & Discoveries

- Observation: The existing resolver deliberately treats multiple physical candidates with the same semantic key as resolved, which is useful internally but cannot represent an explicit navigation choice.
  Evidence: `candidates_outcome` in `src/analyzer/usages/get_definition/mod.rs` derives status from distinct semantic keys rather than the physical target count.
- Observation: Rust implementation items are already linked to trait members and indexed beneath the implementation target type.
  Evidence: `RustAnalyzer::rust_trait_member_implementations` in `src/analyzer/rust/graph_support.rs` and the declaration-building logic added by commits `d8482b3f` and `bee5b084` provide the relations needed for structured qualified-associated-type selection.
- Observation: Tree-sitter Rust represents `<LocalRunner as Runner>` as a `qualified_type` whose trait contract is the `alias` field, wrapped by a `bracketed_type` in the enclosing `scoped_type_identifier` path.
  Evidence: The focused contract test initially returned `unresolvable_import_boundary`; inspecting the parsed S-expression showed `path: (bracketed_type (qualified_type type: ... alias: ...))`, after which field-based selection passed.
- Observation: Direct `cargo test --features nlp,python` linking in this shell currently lacks Python symbols on macOS.
  Evidence: The first focused all-feature invocation compiled but failed linking `libbrokk_bifrost.dylib` with undefined `Py*` symbols. Non-Python Rust contract tests pass; the repository Python script and prescribed final gates remain pending.

## Decision Log

- Decision: Add explicit navigation selection as a layer over the broad resolver instead of changing broad resolution semantics.
  Rationale: Hover, references, rename, and call analysis depend on the existing equivalent-candidate set; only MCP and LSP navigation require declaration/definition filtering.
  Date/Author: 2026-07-20 / Codex
- Decision: Define one shared serialized `NavigationOperation` type in a neutral crate module and pass it into analyzer navigation, MCP rendering, LSP dispatch, and Python serialization.
  Rationale: One vocabulary prevents protocol layers from drifting between `declaration` and `definition` spellings.
  Date/Author: 2026-07-20 / Codex
- Decision: Use indexed tree-sitter node kinds and fields for C++ and Rust selection, with no source-text parsing.
  Rationale: Repository policy requires structured analyzer support, and the index already retains the nodes and relations needed for the requested behavior.
  Date/Author: 2026-07-20 / Codex
- Decision: Keep `get_definitions_by_reference` unchanged and make no UsageBench edits.
  Rationale: Issue #955 explicitly limits the public addition to location navigation in Bifrost.
  Date/Author: 2026-07-20 / Codex

## Outcomes & Retrospective

Implementation is in progress. At completion this section will summarize the protocol surface, language-specific navigation behavior, validation evidence, specialist-review findings, and any remaining follow-up work.

Milestone 1 produced an explicit analyzer navigation path and the initial MCP location surface. Four focused contract tests pass: Java interface declaration selection, C++ prototype/body separation, C++ multi-body ambiguity, and Rust trait/implementation associated-type selection including qualified paths. Broad resolver entry points remain operation-free.

## Context and Orientation

`src/analyzer/usages/get_definition/mod.rs` owns the analyzer-wide location resolver. A candidate is an indexed `CodeUnit` plus a source classification and diagnostic metadata. The current `resolve_definition_batch` function returns a broad candidate set and must retain that behavior for internal callers. The new `resolve_navigation_batch` will invoke the same resolution machinery and then apply an operation-specific selector.

Language-specific behavior lives beside that resolver. `src/analyzer/usages/get_definition/cpp.rs` gathers C++ declarations and definitions that may represent one link-time entity. Its navigation selector must classify indexed tree-sitter declarations by whether callable or type nodes contain bodies. `src/analyzer/usages/get_definition/rust.rs` resolves Rust paths and associated items. It must use the existing trait-member implementation relation and indexed parent relation to distinguish a trait contract from an implementation item. Java needs no new heuristic because its receiver-type resolution already chooses an interface method for an interface-typed call.

`src/searchtools.rs`, `src/mcp_core.rs`, `src/searchtools_service.rs`, `src/mcp_registry.rs`, and `src/tool_arguments.rs` define MCP request/result models, descriptors, dispatch, tool discovery, and CLI path normalization. `bifrost_searchtools/` provides the Python models and client. `src/lsp/capabilities.rs`, `src/lsp/server.rs`, and `src/lsp/handlers/` provide editor capabilities and request handling. Public documentation is in `docs/src/content/docs/mcp.md`, `docs/src/content/docs/python-client.md`, and `bifrost_searchtools/README.md`.

In this plan, a declaration is the contract or prototype that introduces a symbol, while a definition is the concrete item with an implementation body. Entities such as fields and aliases that have no meaningful separate body are valid targets for both operations. A broad candidate set means the union deliberately retained for non-navigation analysis.

## Plan of Work

First, introduce `NavigationOperation` and an operation-aware analyzer entry point. Preserve `resolve_definition_batch` exactly as the broad entry point. Thread the optional operation through language resolution only where selection needs source context. For C++, inspect the indexed tree-sitter node associated with each candidate: declaration navigation prefers prototypes or forward declarations and falls back to a definition only when no declaration-only target exists; definition navigation accepts callable/type bodies and bodyless entities but never declaration-only callable/type targets. Recompute ambiguity from the selected physical targets and retain `unproven_cpp_link_unit` only when multiple unproven definition bodies remain. For Rust, keep the trait redirect for declaration navigation, return an impl-associated type as its own definition, and resolve a qualified associated type by using the AST `type`, `path`, and `name` fields plus existing analyzer relations to select the implementation whose indexed parent is the qualified owner.

Second, add inline-project analyzer tests in the existing definition-navigation integration test. Cover Java interface declaration lookup, the C++ prototype/body split and multiple-body ambiguity, Rust associated-type declaration/definition behavior, qualified Rust associated-type definition lookup, and serialized operation fields.

Third, extend MCP and Python surfaces. Add `get_declarations_by_location` with the existing location-reference input schema, separate declaration result models containing `declarations`, operation-aware statuses, descriptor and registry entries, service dispatch, line-number-mode visibility, CLI path normalization, Python deserialization/rendering/exports, and public documentation. Leave reference-based definition navigation unchanged.

Fourth, advertise `declarationProvider`, dispatch `textDocument/declaration`, and route both declaration and definition requests through one explicit LSP navigation handler. Add `ClickOperation::Declaration` and click-around cases for the same Java, C++, and Rust distinctions.

Finally, run all validation commands, then perform the five guided specialist reviews over the complete branch diff. Consolidate findings, fix all critical/high findings and sound lower-severity findings within scope, rerun affected checks, and checkpoint the reviewed state.

## Concrete Steps

Run all commands from `/Users/dave/.codex/worktrees/c9af/bifrost`.

After each milestone, update every living section in this file, run the focused checks named for that milestone, explicitly stage only files changed for that milestone, and create a multiline checkpoint commit that records both the behavior and why the design preserves the broad resolver.

For the completed implementation, run:

    BIFROST_SEMANTIC_INDEX=off cargo test --features nlp,python --test get_definition_test --test bifrost_mcp_server --test bifrost_lsp_server --test lsp_click_around_regression
    scripts/test_python.sh
    cargo fmt --all
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    BIFROST_SEMANTIC_INDEX=off scripts/with-isolated-cargo-target.sh cargo test --features nlp,python
    git diff --check

The focused command should report all named integration suites passing. The Python script should report the client tests passing. Clippy should exit without warnings, the full feature suite should pass, and `git diff --check` should print no output.

## Validation and Acceptance

The analyzer contract is accepted when an inline Java interface-typed call returns the interface method for declaration navigation; a C++ call returns only the header prototype for declaration and only the source body for definition; two C++ definition bodies remain ambiguous; a Rust impl-associated type returns itself for definition and its trait member for declaration; and `<LocalRunner as Runner>::Output` returns the `LocalRunner` implementation item for definition. Every result must serialize the matching operation.

The MCP contract is accepted when tool discovery exposes both location tools, both share the existing reference-list schema limits, dispatch returns `declarations` or `definitions` as appropriate, absent targets use `no_declaration` or `no_definition`, and line-number-mode filtering treats both tools identically. The Python contract is accepted when the new method dispatches, typed models deserialize and render the two result shapes, and all public types are exported.

The LSP contract is accepted when initialization advertises `declarationProvider`, `textDocument/declaration` dispatches, and click-around tests observe the same language-specific split as MCP navigation. Existing hover, reference, rename, and broad definition-by-reference tests must remain green, proving their candidate-set behavior did not change.

## Idempotence and Recovery

All edits and test commands are repeatable. Cargo commands that need isolation use `scripts/with-isolated-cargo-target.sh`, which cleans its managed temporary target on exit. Semantic indexing is disabled during tests so validation neither downloads models nor starts background indexers. If a milestone test fails, keep the worktree on the current issue branch, update this plan with the failure evidence, repair the implementation, and rerun only the affected focused checks before the full suite. Do not switch branches, rebase, push, or open a pull request.

## Artifacts and Notes

Initial repository state:

    branch: 955-expose-distinct-declaration-and-definition-navigation-through-mcp
    HEAD:   3fdaa7196951688c3829fbd06de9ef265c3aba92
    upstream matched after git fetch
    worktree clean

The final review artifact will record changed-file count, diff size, consolidated severity-ranked findings, fixes taken, and post-review validation.

## Interfaces and Dependencies

Define a shared serde-backed enum with serialized values `declaration` and `definition`:

    pub enum NavigationOperation {
        Declaration,
        Definition,
    }

Expose an analyzer entry point shaped like `resolve_navigation_batch(analyzer, requests, operation)` alongside the existing broad `resolve_definition_batch`. Add MCP `get_declarations_by_location` using `GetDefinitionParams` or a neutrally renamed compatible location request model. Definition lookup results retain `definitions`; declaration lookup results use `declarations`; both contain `operation`. Add Python equivalents and an async `BifrostClient.get_declarations_by_location` method. Add LSP `textDocument/declaration` support and `ClickOperation::Declaration` without changing `get_definitions_by_reference`.

Plan revision note (2026-07-20 12:06Z): Created the living ExecPlan from the user-approved issue #955 implementation contract so work can be resumed from this file alone.

Plan revision note (2026-07-20 12:21Z): Recorded milestone 1 implementation, focused passing evidence, the structured Rust AST field discovery, and the local PyO3 linker constraint before checkpointing.
