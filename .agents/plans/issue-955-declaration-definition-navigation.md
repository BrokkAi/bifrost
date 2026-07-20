# Distinguish declaration and definition navigation

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this document in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost currently exposes only definition navigation, but its internal resolver intentionally returns the broad set of semantically related declarations and definitions needed by hover, references, rename, and call analysis. After this change, MCP, the Python client, and LSP clients can explicitly request either the declaration contract or the concrete definition body without weakening those internal consumers. A user can ask for a C++ header prototype separately from its source body, distinguish a Rust trait associated type from an implementation item, and use `textDocument/declaration` in an editor.

The behavior is observable through analyzer contract tests, MCP response JSON, Python model rendering, and LSP click-around tests. Every location-navigation result also reports the requested `operation`, so consumers can validate that a declaration or definition selector produced it.

## Progress

- [x] (2026-07-20 12:06Z) Re-read repository instructions, inspected the clean issue branch, fetched `origin`, and confirmed HEAD matches its upstream at `3fdaa719`.
- [x] (2026-07-20 12:21Z) Implemented the shared navigation operation and operation-aware analyzer selector while preserving the broad resolver.
- [x] (2026-07-20 12:21Z) Added passing Java, C++, and Rust inline-project navigation contract coverage, including serialized operations.
- [x] (2026-07-20 12:41Z) Exposed declaration navigation through MCP, path normalization, Python models/client/exports, and public documentation, with distinct serialized result fields and operations.
- [x] (2026-07-20 12:42Z) Advertised and dispatched LSP declaration navigation through the shared selector and extended the click-test harness with declaration operations.
- [x] (2026-07-20 14:27Z) Ran the focused Rust suites, all 44 Python client tests, formatting, all-target/all-feature clippy, the complete all-feature Rust suite including doc tests, and `git diff --check`.
- [x] (2026-07-20 14:27Z) Completed the five guided specialist reviews, addressed the high/medium findings within scope, reran affected tests and full gates, and recorded the one range-model follow-up below.
- [x] (2026-07-20 15:12Z) Extended explicit navigation outcomes with physical declaration ranges so same-file C++ prototypes and bodies remain distinct without changing broad `CodeUnit` identity.
- [x] (2026-07-20 15:18Z) Merged current `origin/master`, confirmed the branch is zero commits behind, and passed focused Rust, Python, formatting, all-feature clippy, the complete isolated all-feature Rust suite, and diff checks.
- [x] (2026-07-20 15:27Z) Ran the named guided specialist review against the synchronized `master` merge base and prepared a deduplicated findings index for interactive triage.
- [x] (2026-07-20 15:29Z) Merged the one additional master cache-isolation commit that landed during review, reran all 187 LSP integration tests, and confirmed the reviewed issue diff and seven findings are unchanged against the refreshed base.
- [x] (2026-07-20 16:18Z) Applied all seven guided-review findings: restored broad LSP ambiguity behavior, isolated physical C++ navigation occurrences from general ranges, centralized physical selection/status/diagnostics, retained later declarations, bounded target expansion, and cached LSP rendering inputs.
- [x] (2026-07-20 19:21Z) Reran focused and complete validation after the seven-finding repair: 188 LSP, 18 MCP, 538 analyzer navigation, and 17 click tests passed; all 44 Python tests, formatting, isolated all-feature clippy, the complete isolated all-feature Rust suite, doc tests, and diff checks passed.
- [x] (2026-07-20 19:38Z) Fetched and merged `origin/master` at `c59d6f61`, resolved the two Python public-surface conflicts by retaining both APIs, and passed 188 LSP, 18 MCP, 541 analyzer navigation, 17 click, Python, formatting, isolated clippy, complete all-feature Rust, doc-test, and diff-check gates.
- [x] (2026-07-20 19:42Z) Merged the five additional master commits that landed during the full-suite run, including the overlapping C++ declarator fix, and passed the affected navigation gates with 188 LSP, 18 MCP, 543 analyzer navigation, and 17 click tests plus 2 ignored stress tests.
- [ ] Push the synchronized branch and publish a ready-for-review pull request.

## Surprises & Discoveries

- Observation: The existing resolver deliberately treats multiple physical candidates with the same semantic key as resolved, which is useful internally but cannot represent an explicit navigation choice.
  Evidence: `candidates_outcome` in `src/analyzer/usages/get_definition/mod.rs` derives status from distinct semantic keys rather than the physical target count.
- Observation: Rust implementation items are already linked to trait members and indexed beneath the implementation target type.
  Evidence: `RustAnalyzer::rust_trait_member_implementations` in `src/analyzer/rust/graph_support.rs` and the declaration-building logic added by commits `d8482b3f` and `bee5b084` provide the relations needed for structured qualified-associated-type selection.
- Observation: Tree-sitter Rust represents `<LocalRunner as Runner>` as a `qualified_type` whose trait contract is the `alias` field, wrapped by a `bracketed_type` in the enclosing `scoped_type_identifier` path.
  Evidence: The focused contract test initially returned `unresolvable_import_boundary`; inspecting the parsed S-expression showed `path: (bracketed_type (qualified_type type: ... alias: ...))`, after which field-based selection passed.
- Observation: Direct `cargo test --features nlp,python` linking in this shell needs the same macOS dynamic-lookup linker flag used by CI for the PyO3 extension module.
  Evidence: The first focused all-feature invocation failed linking `libbrokk_bifrost.dylib` with undefined `Py*` symbols; rerunning with `RUSTFLAGS='-C link-arg=-undefined -C link-arg=dynamic_lookup'` passed all named focused suites and the complete suite.
- Observation: The first Python-suite run encountered two transient analyzer-store EOF failures in unrelated temporary Python fixtures, but an immediate isolated rerun passed all 44 tests.
  Evidence: `classify_test_files` and `usage_graph` initially failed while hydrating temporary `.py` files; the unchanged rerun completed `Ran 44 tests ... OK`.
- Observation: The local PATH mixes rustup `cargo`/`rustc` (LLVM 22.1.2) with Homebrew `rustdoc`/`clippy-driver` (LLVM 22.1.6), despite all reporting Rust 1.96.0.
  Evidence: Unpinned clippy and rustdoc reported incompatible crate metadata. Pinning the full Homebrew toolchain for clippy and the rustup `rustdoc` for tests made both isolated gates pass.
- Observation: The full suite contained legacy C++ tests that used definition navigation as a broad forward-resolution oracle for declaration-only fixtures.
  Evidence: Persistence, clangd parity, macro-arity, and usage-graph tests initially expected prototypes in `definitions`. Fixtures that intended body navigation now contain bodies; usage tests that intentionally target prototypes use declaration navigation; multi-target explicit navigation now asserts `ambiguous`.
- Observation: Same-file C++ prototype/body pairs are collapsed by the current per-file `CodeUnit` replacement identity before navigation selection receives them.
  Evidence: Specialist review traced `replace_code_unit` and the range-only result model: the selector can separate header/source physical candidates, but cannot return different ranges for a prototype and body represented by one same-file `CodeUnit`.
- Observation: The decisive information loss occurred when C++ indexing replaced a prototype `CodeUnit` with its body and deleted the prototype's previously indexed range.
  Evidence: The initial range-aware navigation regression still selected line 2 for declaration navigation. Updating the two C++ body-replacement paths to preserve prior ranges made declaration select line 1 and definition select line 2 while retaining one semantic `CodeUnit`.
- Observation: The post-follow-up guided review found that storing preserved physical ranges in the general analyzer range collection leaks navigation-only semantics into existing definition-oriented tools.
  Evidence: Existing consumers such as `get_symbol_locations` and `get_definitions_by_reference` choose the earliest general range, so a same-file prototype/body pair can now render the prototype where the pre-follow-up behavior rendered the body.
- Observation: The physical-range layer exposed two older logical-selection assumptions that must now be removed rather than duplicated: broad LSP consumers should still fail closed on ambiguity, and C++ status/link-unit diagnostics must be derived from typed physical targets rather than raw target cardinality.
  Evidence: The architecture, senior, and duplication reviewers independently traced these failures to `broad_symbol.rs`, the two selectors in `get_definition/cpp.rs`, and the second finalization pass in `get_definition/mod.rs`.
- Observation: Preserving physical C++ occurrences does not require changing persisted analyzer state or broad `IAnalyzer::ranges` semantics.
  Evidence: A bounded request-time `CppNavigationIndex` can re-run the existing structured declaration visitor over the cached indexed source/tree, retain prototype/body occurrences separately, and leave `get_symbol_locations`, summaries, and `get_definitions_by_reference` definition-oriented.
- Observation: The public location request limit bounds references but not the number of physical targets produced by each reference.
  Evidence: A generated file containing 300 repeated prototypes expanded into 300 navigation targets before this repair. Per-result and per-batch budgets now cap the response at 256 and 1,024 targets respectively and serialize `navigation_targets_truncated`.
- Observation: Several full-suite tests that spawn subprocesses, invoke the Python sidecar, or create signed Git commits cannot run inside the workspace sandbox even though the implementation is sound.
  Evidence: The first isolated full-suite run passed 1,456 library tests but reported six permission/GPG environment failures. The unchanged privileged rerun passed the library suite (1,462 passed, 4 ignored), every integration suite, and doc tests with exit code 0, then removed its isolated Cargo target.
- Observation: The final master refresh advanced by 61 commits and overlapped the Python package exports/tests, but not the declaration-navigation semantics.
  Evidence: Git produced only two content conflicts, in `bifrost_searchtools/__init__.py` and `python_tests/test_searchtools_client.py`. Both were additive export/import conflicts and were resolved by retaining master's new container-listing types alongside `DeclarationLookupResult`, `DefinitionLookupResult`, and `NavigationOperation`; all Rust navigation files merged automatically and the complete gates passed.
- Observation: Master advanced by another five commits while the complete post-merge suite was running, including a C++ declarator-resolution change in this issue's hotspot.
  Evidence: The second merge at `a86ae862` applied without conflicts. The refreshed C++-aware analyzer navigation suite grew from 541 to 543 tests and passed in full, alongside all 188 LSP, 18 privileged MCP, and 17 non-stress click-around tests.

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
- Decision: Preserve declaration-site self navigation except when C++ AST classification proves the site is a declaration-only callable or type during definition navigation.
  Rationale: Existing LSP no-movement behavior remains useful for fields, aliases, and other indivisible declarations, while a C++ prototype must not masquerade as an implementation body.
  Date/Author: 2026-07-20 / Codex
- Decision: Return every operation-filtered candidate through LSP for both `Resolved` and `Ambiguous` outcomes.
  Rationale: LSP location arrays can represent ambiguity, and discarding a valid ambiguous set contradicted the public navigation contract.
  Date/Author: 2026-07-20 / Codex
- Decision: Treat unclassifiable C++ callable/type candidates as `Unknown` and exclude them from definition navigation with an explicit diagnostic.
  Rationale: Failing closed avoids presenting an unproven prototype as an implementation body while preserving structured diagnostics for missing indexed syntax.
  Date/Author: 2026-07-20 / Codex
- Decision: Defer same-file C++ prototype/body separation to a range-aware navigation-target or index-identity follow-up.
  Rationale: Fixing it here would require changing the analyzer's declaration identity or returning operation-specific ranges, a larger architectural change than the approved cross-file candidate selector. Header/source separation—the issue contract—is fully implemented.
  Date/Author: 2026-07-20 / Codex
- Decision: Resolve the follow-up with a range-aware target type owned by explicit navigation, leaving `CodeUnit` identity and `DefinitionLookupOutcome` unchanged.
  Rationale: The index already retains all declaration ranges. Carrying the selected physical range through MCP and LSP preserves broad resolver semantics, represents multiple same-file bodies, and avoids widening a navigation concern into analyzer identity, hover, references, rename, or call analysis.
  Date/Author: 2026-07-20 / Codex
- Decision: Queue and apply every finding from the synchronized guided review as one architectural repair milestone.
  Rationale: The user explicitly requested all findings be fixed. A separate on-demand C++ physical-occurrence index removes the global range leak and makes the remaining filtering, declaration-order, diagnostic, resource-bound, and duplication findings parts of one coherent selector rather than independent patches.
  Date/Author: 2026-07-20 / Codex
- Decision: Resolve the final master conflicts by unioning the two additive Python public surfaces.
  Rationale: Master added container-listing exports while this issue added declaration-navigation exports; neither supersedes the other, and retaining both preserves the intended public API without semantic conflict.
  Date/Author: 2026-07-20 / Codex

## Outcomes & Retrospective

Implementation and review are complete on the current issue branch. The branch adds a shared `NavigationOperation`, explicit analyzer selection layered over the unchanged broad resolver, the `get_declarations_by_location` MCP/Python surface, operation-tagged declaration/definition result models, and `textDocument/declaration` LSP support. Java interface calls, C++ prototype/body selection and genuine multi-body ambiguity, and Rust trait/implementation associated-type navigation are covered end to end.

Milestone 1 produced an explicit analyzer navigation path and the initial MCP location surface. Four focused contract tests pass: Java interface declaration selection, C++ prototype/body separation, C++ multi-body ambiguity, and Rust trait/implementation associated-type selection including qualified paths. Broad resolver entry points remain operation-free.

Milestone 2 completed the public MCP and Python surface. MCP discovery, schema limits, line-number visibility, and live dispatch pass in 17 integration tests; the Python client exposes typed declaration and definition models and passes all 44 client tests. Public MCP and Python documentation now describes operation-specific fields and statuses while leaving reference-based definition lookup unchanged.

Milestone 3 completed LSP support. Initialization advertises `declarationProvider`, both declaration and definition requests use the explicit analyzer selector, and the click harness covers Java, C++, and Rust distinctions. All 187 LSP server tests and 17 non-stress click-around tests pass; the C++ click contract also proves a prototype is not returned as its own definition.

The guided review ran security, DevOps, duplication, architecture, and senior-engineering specialists. Security and DevOps reported no findings. Review fixes consolidated LSP target construction, reused shared C++ exact-range and Rust associated-type helpers, returned ambiguous LSP candidates instead of discarding them, made unknown C++ structure fail closed, narrowed stale ambiguity-diagnostic cleanup to C++, and extended C++ multi-body and wrong-arity coverage. Its sole deferred finding was the same-file C++ prototype/body range separation now completed below.

The architectural follow-up is now implemented. C++ definition replacement preserves earlier physical declaration ranges, while a new navigation-only target pairs the semantic `CodeUnit` with the exact range chosen from tree-sitter structure. MCP and LSP render the identifier within that range. Same-file prototype/body calls, prototype-to-body declaration-site navigation, and multiple same-file bodies are covered; the focused all-feature suites pass with 187 LSP server tests, 18 MCP tests, 525 analyzer tests, and 17 click tests plus 2 ignored stress tests.

The branch was then synchronized by merging current `origin/master` at `273dd103`; it was zero commits behind master. Post-merge focused suites pass with 187 LSP, 18 MCP, 532 analyzer, and 17 click tests plus 2 ignored stress tests. All 44 Python tests pass, formatting and diff checks are clean, isolated all-target/all-feature clippy passes, and the complete isolated `cargo test --features nlp,python` run passes including doc tests. When one additional master commit landed during review, it was merged cleanly at `7ee06e18`; that commit only isolates LSP test caches and documents the override. All 187 LSP integration tests pass after the refresh, and the branch is again zero commits behind `origin/master`.

The requested guided review completed its security, duplication, senior-engineering, DevOps, and architecture passes over `master...HEAD`. After scoping and deduplication, all seven findings—two high, four medium, and one low—were applied. Broad LSP consumers again fail closed on ambiguity while explicit navigation retains ambiguous target arrays. Physical C++ occurrences now live in a bounded request-time index rather than general analyzer ranges; the one typed physical selector owns filtering, status, ambiguity, truncation, and link-unit diagnostics; later prototypes and forward declarations are retained; and LSP renders all targets from a per-file source/tree cache. The obsolete preserving-range wrappers and their quadratic merge logic were removed.

Post-repair focused validation passes with 188 LSP server tests, 18 MCP tests, 538 analyzer navigation tests, and 17 click-around tests plus 2 ignored stress tests. New regressions cover definition-oriented broad range consumers, mixed same/cross-file prototypes, declaration-after-definition ordering for functions and types, per-result and per-batch target budgets, overload ambiguity without a false link-unit diagnostic, and broad LSP ambiguity behavior.

The final synchronization merged 61 newer master commits at `c59d6f61`, including Rust associated-item and receiver-resolution work, then five more commits at `a86ae862` that landed during validation and included overlapping C++ declarator work. The complete suite at `c59d6f61` passes with 1,471 library tests plus every integration target and doc tests; Python, formatting, isolated all-target/all-feature clippy, and diff checks also pass. After the final five-commit delta, the affected gates pass with 188 LSP server tests, 18 MCP tests, 543 analyzer navigation tests, and 17 click-around tests plus 2 ignored stress tests.

Final validation passed:

    focused all-feature Rust suites after final master merge: 188 LSP, 18 MCP, 543 analyzer, 17 click tests passed; 2 stress tests ignored
    scripts/test_python.sh: 44 passed
    cargo fmt --all: clean
    all-target/all-feature clippy: clean in an isolated target
    complete cargo test --features nlp,python after the 61-commit master merge: passed in a privileged isolated target, including 1,471 library tests and 0 doc-test failures
    git diff --check: clean

The final issue diff against synchronized `origin/master` is 37 files, 2,374 insertions, and 247 deletions. No UsageBench files were changed, and no branch switch or rebase was performed.

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

As an architectural follow-up, add a navigation-only target that pairs a `CodeUnit` with the exact indexed declaration range selected for the requested operation. Classify each C++ physical range from its tree-sitter node, prefer declaration-only ranges for declaration navigation, select body ranges for definition navigation, and recompute ambiguity from the physical targets. Teach MCP rendering and LSP locations to derive the identifier range within that selected declaration range. Do not change broad lookup outcomes or the persisted `CodeUnit` identity.

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

Final review artifact:

    base: 3fdaa7196951688c3829fbd06de9ef265c3aba92
    issue diff: 34 files, +1480/-201 before the final plan bookkeeping line changes
    reviewers: security, DevOps, duplication, architecture, senior engineering
    critical findings: 0
    high findings: 1 fixed (ambiguous LSP results were discarded)
    medium findings: shared-helper duplication fixed; unknown C++ classification fixed; same-file C++ range separation deferred
    lower findings: stale C++ ambiguity diagnostic fixed; focused regressions added
    final gates: focused Rust, Python, fmt, clippy, complete all-feature Rust including doc tests, diff check

## Interfaces and Dependencies

Define a shared serde-backed enum with serialized values `declaration` and `definition`:

    pub enum NavigationOperation {
        Declaration,
        Definition,
    }

Expose an analyzer entry point shaped like `resolve_navigation_batch(analyzer, requests, operation)` alongside the existing broad `resolve_definition_batch`. Add MCP `get_declarations_by_location` using `GetDefinitionParams` or a neutrally renamed compatible location request model. Definition lookup results retain `definitions`; declaration lookup results use `declarations`; both contain `operation`. Add Python equivalents and an async `BifrostClient.get_declarations_by_location` method. Add LSP `textDocument/declaration` support and `ClickOperation::Declaration` without changing `get_definitions_by_reference`.

Plan revision note (2026-07-20 12:06Z): Created the living ExecPlan from the user-approved issue #955 implementation contract so work can be resumed from this file alone.

Plan revision note (2026-07-20 12:21Z): Recorded milestone 1 implementation, focused passing evidence, the structured Rust AST field discovery, and the local PyO3 linker constraint before checkpointing.

Plan revision note (2026-07-20 12:41Z): Recorded the completed MCP/Python/documentation milestone, its passing integration evidence, and the transient analyzer-store failure that disappeared on isolated rerun before checkpointing.

Plan revision note (2026-07-20 12:42Z): Recorded the completed LSP milestone, including explicit declaration dispatch, operation-aware declaration-site fallback, and passing server/click-around evidence before checkpointing.

Plan revision note (2026-07-20 14:27Z): Recorded the completed specialist review, fixes and deferred same-file range-model follow-up, compatibility updates to legacy C++ tests, coherent-toolchain validation commands, and final passing gates before the reviewed checkpoint commit.

Plan revision note (2026-07-20 15:04Z): Reopened the plan for the requested architectural follow-up, chose a navigation-only physical-range target over a global index-identity change, and added synchronization plus guided-review milestones.

Plan revision note (2026-07-20 15:12Z): Recorded the completed range-aware navigation milestone, the C++ replacement-range root cause, new same-file call/declaration-site/multi-body coverage, and passing focused all-feature suites before checkpointing.

Plan revision note (2026-07-20 15:18Z): Recorded the clean `origin/master` merge, zero-behind state, post-merge focused and full validation evidence, and the clippy-driven LSP expression cleanup before checkpointing the synchronized state.

Plan revision note (2026-07-20 15:27Z): Recorded the five-reviewer guided review against synchronized master, its deduplicated severity totals and principal findings, and the deliberate pause for interactive triage.

Plan revision note (2026-07-20 15:29Z): Recorded the final master cache-isolation merge that landed during review, its passing affected LSP suite, the restored zero-behind state, and confirmation that the issue findings remain unchanged against the refreshed base.

Plan revision note (2026-07-20 15:42Z): Queued all seven guided-review findings at the user's direction and reopened implementation/validation/publication milestones for a ready pull request.

Plan revision note (2026-07-20 16:18Z): Recorded all seven review findings as applied, the request-time physical-occurrence architecture, bounded target and cached LSP rendering behavior, and the passing post-repair focused suites before checkpointing.

Plan revision note (2026-07-20 19:21Z): Recorded final post-repair validation, including the sandbox-only subprocess/GPG failures and clean privileged rerun, current focused counts, formatting, Python, clippy, full-suite, doc-test, and diff-check evidence before the synchronization/publication milestone.

Plan revision note (2026-07-20 19:38Z): Recorded the 61-commit final master refresh, the additive Python export/test conflict resolution, updated focused counts, clean post-merge Python, formatting, clippy, complete all-feature Rust and doc-test gates, and the final synchronized issue diff before publication.

Plan revision note (2026-07-20 19:42Z): Recorded the five additional master commits that landed during full validation, the conflict-free overlapping C++ merge, the final 543-test analyzer-navigation count, and passing affected LSP, MCP, and click-around gates at `a86ae862`.
