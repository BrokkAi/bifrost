# Burn down symbol-tool resolution and freshness regressions

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this document in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Five benchmark reports describe cases where Bifrost either fails to resolve a symbol selector, cannot prove a direct call, gives an unhelpful result for generated Java code, or returns source from an older workspace generation. After this work, users should be able to use the same canonical selectors across symbol tools, obtain structured proof for direct JavaScript/TypeScript and Java calls where the analyzer has enough information, receive actionable guidance for Lombok-generated accessors, and trust that `get_symbol_sources` reflects one current analyzer snapshot. Each report must first be reproduced or otherwise validated against the current code; invalid or obsolete reports must be documented rather than patched speculatively.

## Progress

- [x] (2026-07-11 19:00Z) Read the five local issue reports, current Git state, canonical ExecPlan instructions, and relevant resolver/service entry points.
- [x] (2026-07-12 02:05Z) Validated and fixed #638 with public Java lambda-call coverage and JS factory-return receiver coverage; unknown JS receivers remain unproven.
- [x] (2026-07-12 02:08Z) Validated and fixed #639 by adding C# metadata generic-arity variants to shared client selector interpretation.
- [x] (2026-07-12 02:15Z) Validated and fixed #640 by reusing the structured Lombok accessor-to-field relation in source lookup, including boolean and anchored selectors.
- [x] (2026-07-12 02:15Z) Validated #641 independently from the service sequence and fixed the disk-read/session-lock race; the exact benchmark checkout timing was not reconstructed.
- [x] (2026-07-12 02:08Z) Validated and fixed #642 across source, location, and definition-by-reference tools through shared file-selector interpretation.
- [x] (2026-07-12 02:20Z) Reviewed and integrated delegated patches; corrected one outdated JS test that still expected a now-proven factory receiver in the unproven bucket.
- [x] (2026-07-12 02:26Z) Passed formatting, clippy, library tests, definition tests, and all affected integration suites.
- [ ] Commit only the implementation, tests, and this ExecPlan on the current branch with a multiline rationale.

## Surprises & Discoveries

- Observation: The current branch is exactly the benchmarked commit `102b6a0c`, and already contains watch-mode source freshness checks plus tests for changed, added, and deleted C# declarations.
  Evidence: `git log -1` is `102b6a0c Resolve Go module-prefixed file inputs`; `src/searchtools_service.rs::handle_get_symbol_sources` compares indexed and on-disk candidate sources before rendering the final result.

- Observation: The five issue reports already exist as untracked files under `.agents/docs/`; they are user-owned inputs and are not part of this plan's edits.
  Evidence: `git status --short` listed `.agents/docs/bifrost102-*.md` before implementation began.

- Observation: Java lambda declarations are synthetic function `CodeUnit` values whose names cannot be parented reliably by the default name-derived `IAnalyzer::parent_of` implementation.
  Evidence: Delegating `JavaAnalyzer::parent_of` to the tree-sitter analyzer's stored structural parent relation and iteratively climbing function parents changes two ShardingSphere-shaped lambda calls from unproven to proven.

- Observation: JS/TS already had structured factory-return receiver analysis, but `member_object_match_status` returned `Unproven` for every call-expression receiver before invoking it.
  Evidence: Removing that early return proves `duration().toISOString()` and `duration().asDays()`, while the existing unknown-receiver regression remains unproven.

- Observation: The #641 benchmark proves that two tools returned different generations, but it does not by itself reveal the checkout/watcher timing. Independently, the old service ordering contained a race: it read candidate contents before acquiring the session lock, then could compare an old snapshot to that old read after the file changed.
  Evidence: The deterministic `candidate_files_are_rechecked_after_the_source_changes` test changes the file after candidate discovery and confirms that the locked freshness check detects it.

## Decision Log

- Decision: Treat each issue as a hypothesis and require a focused behavior reproduction before changing production code.
  Rationale: Several reports come from long benchmark trajectories where workspace mutation and selector syntax changes can mimic analyzer defects. The user explicitly requested validity evaluation first.
  Date/Author: 2026-07-11 / Codex

- Decision: Centralize selector spelling equivalence in the existing symbol lookup and definition-selector structures, while keeping file anchoring separate from language-specific name normalization.
  Rationale: `src/analyzer/symbol_lookup.rs` already owns cross-tool fuzzy selector interpretations, while `src/searchtools.rs` already owns path anchors. Extending those structures avoids tool-specific point fixes.
  Date/Author: 2026-07-11 / Codex

- Decision: Never promote source-text search candidates to proven usage hits.
  Rationale: The repository requires tree-sitter/analyzer-backed resolution. Fixes for #638 must improve AST/type/call-edge resolution or explicitly retain an unproven diagnostic.
  Date/Author: 2026-07-11 / Codex

- Decision: Reuse Java get-definition's Lombok accessor relation rather than indexing synthetic methods or adding source-text getter guesses.
  Rationale: The existing relation already validates class/field annotations, JavaBean names, and boolean `isX` semantics against structured declarations. Returning its backing field gives `get_symbol_sources` honest source without inventing a method body.
  Date/Author: 2026-07-12 / Codex

- Decision: Linearize source freshness at the candidate reread performed under the exclusive service session lock after watcher reconciliation.
  Rationale: This closes the pre-lock observation race and ensures any necessary reparse happens before final rendering. A filesystem change after that authoritative read belongs to a later generation and cannot be atomically prevented by the service.
  Date/Author: 2026-07-12 / Codex

## Outcomes & Retrospective

All five reports were valid against current code, with the benchmark-lifecycle qualification noted for #641. #638 now proves structured JS factory-return calls and unqualified Java calls nested in lambdas. #639 accepts valid C# metadata arity spellings without changing indexed source names. #640 returns annotated backing-field source for Lombok-generated accessors and preserves ordinary missing-getter behavior. #641 rereads candidates at the service's locked freshness boundary. #642 shares file-anchor interpretation across source, location, and definition-reference paths, including nested dotted JS/TS members.

The affected suites pass: 43 selector tests, 117 service integration tests, 47 Java usage tests, 71 JS/TS usage tests with two existing ignores, 398 definition tests, and 617 library tests with three existing ignores. `cargo clippy-no-cuda`, `cargo fmt --all -- --check`, and `git diff --check` also pass.

## Context and Orientation

`src/analyzer/symbol_lookup.rs` interprets client-provided symbol names and resolves them to indexed `CodeUnit` declarations. A `CodeUnit` is Bifrost's structured record for a class, function, method, field, module, or similar declaration. `src/searchtools.rs` implements the symbol tools and file-anchor syntax such as `src/core.ts#ProcessPromise.pipe`. `src/searchtools_service.rs` owns the active `WorkspaceAnalyzer` snapshot and watch-mode refresh behavior. Language-specific usage proof lives below `src/analyzer/` and feeds `scan_usages_by_reference` through the shared `UsageFinder`.

The relevant behavior tests are primarily in `tests/searchtools_definition_selectors.rs`, `tests/get_definition_test.rs`, the language usage graph tests, and service-local tests in `src/searchtools_service.rs`. Small ad hoc projects must use `tests/common/inline_project.rs` and `InlineTestProject` unless a service lifecycle test requires direct filesystem mutation.

Issue #638 concerns direct JavaScript method calls such as `dayjs.duration(...).toISOString()` and a Java method passed through a lambda body. Issue #639 concerns C# metadata spelling such as `TypeName` followed by a backtick and generic arity, while source declarations are indexed without that suffix. Issue #640 concerns Java methods generated by Lombok annotations, which have no method declaration range but do have an annotated backing field. Issue #641 concerns a source block whose text disagrees with another tool in the same trajectory. Issue #642 concerns file-qualified JavaScript/TypeScript selectors expressed with dotted, hash, or colon separators.

## Plan of Work

First add focused failing tests for each independently reproducible report. For selectors, route spelling variants through existing structured selector interpretation and preserve ambiguity: normalization may select a declaration only when the resulting structured match is unique, and a file anchor must continue to restrict resolution to that file. Exercise both source lookup and definition-by-reference so the tools do not maintain separate accidental grammars.

For usage proof, inspect the tree-sitter call shapes and current receiver/argument resolution. Extend shared structured resolution when the missing edge is general, such as method calls whose receiver is itself a call expression or direct calls nested inside lambda bodies. Preserve `unproven` results where receiver identity is genuinely ambiguous.

For Lombok, reuse Java annotation and field structures already used by definition resolution. Prefer resolving a generated getter selector to its annotated backing field source. If source lookup cannot safely establish the mapping, return an explicit generated-code note naming the backing-field or owner selector rather than a bare `not_found`.

For freshness, reproduce watch-mode file mutation without relying on an operating-system watcher, as the existing service tests do. Ensure candidate discovery includes every file that could satisfy both successful and unsuccessful inputs, refresh all mismatched files into one final snapshot, and render only from that snapshot. Do not read a current body using declaration ranges from an older snapshot.

Finally, review all changes as one system, run targeted behavior tests, format, and run non-CUDA clippy unless `nvcc` is available. Commit the verified changes directly to the current branch without staging unrelated `.agents/docs/` or `.brokk/` files.

## Concrete Steps

Work from `/home/jonathan/Projects/bifrost`.

Inspect and run focused tests during development:

    cargo test --test searchtools_definition_selectors
    cargo test --test get_definition_test lombok
    cargo test --test usages_javascript_graph_test
    cargo test --test usages_java_graph_test
    cargo test searchtools_service::tests::get_symbol_sources

Discover the exact usage test target names with `rg --files tests | rg 'usages.*(java|javascript|typescript)'` and use the existing target names rather than creating a parallel test binary.

After integration, run:

    cargo fmt
    cargo test --test searchtools_definition_selectors
    cargo test --test get_definition_test
    cargo test --test searchtools_service
    cargo test --test usages_java_graph_test
    cargo test --test usages_js_ts_graph_test
    cargo test --lib
    cargo clippy-no-cuda

Run additional targeted usage suites named by the implemented #638 changes. Expect all tests to pass and clippy to emit no warnings.

## Validation and Acceptance

#638 is accepted only if direct, structurally resolvable JavaScript/TypeScript method calls and Java calls inside lambda bodies appear as proven usage hits in focused inline projects. Cases with unknown receiver types must remain unproven rather than becoming false positives.

#639 is accepted if an unambiguous C# source declaration can be selected with metadata-style generic arity spelling and ambiguity remains explicit when more than one declaration could match.

#640 is accepted if requesting a Lombok-generated getter no longer yields unexplained `not_found`: it must return the annotated backing field source or a specific generated-code recovery note, while an ordinary missing getter without Lombok remains missing.

#641 is accepted if a watch-mode service whose source file changes between indexing and `get_symbol_sources` returns text and declaration ranges from the refreshed generation. If the reported trajectory cannot reproduce a stale response under current service semantics, document the report as invalid or already fixed and retain regression coverage for the closest lifecycle.

#642 is accepted if supported JS/TS file-qualified spellings resolve the same declaration across source and definition tools, while an incorrect anchor reports the valid recovery selector and same-named declarations in different files remain ambiguous without an anchor.

## Idempotence and Recovery

All tests create temporary projects and are safe to rerun. Formatting is idempotent. Do not delete or reset user-owned untracked files. If delegated edits overlap, inspect the combined diff and reconcile manually through `apply_patch`; never discard one contributor's work wholesale. Stage only paths changed for this task.

## Artifacts and Notes

The issue evidence is stored in the existing untracked `.agents/docs/bifrost102-*.md` files. Those inputs were not modified and are not included in the task commit.

The final verification transcript is summarized as:

    cargo test --test searchtools_definition_selectors  # 43 passed
    cargo test --test searchtools_service               # 116 passed, 1 ignored
    cargo test --test usages_java_graph_test             # 47 passed
    cargo test --test usages_js_ts_graph_test            # 69 passed, 2 ignored
    cargo test --test get_definition_test                # 398 passed
    cargo test --lib                                     # 614 passed, 3 ignored
    cargo clippy-no-cuda                                 # passed, no warnings

## Interfaces and Dependencies

Keep `resolve_codeunit_fuzzy` and its `CodeUnitResolution` result as the shared symbol-name resolution entry point unless validation establishes that a narrower existing helper owns the behavior. Keep `split_definition_selector` and `split_path_qualified_definition_selector` as the file-anchor interpretation layer. Keep `SearchToolsService::handle_get_symbol_sources` as the freshness boundary. Do not add regex or source-string parsing for declarations, calls, Java annotations, C# types, or JS/TS paths when tree-sitter nodes, `CodeUnit` fields, `ProjectFile`, or `WorkspaceFileResolver` can supply the structure.

Revision note (2026-07-11): Created the initial self-contained plan after reading all five reports and current resolver/service code. Validity and concrete implementation details remained intentionally open until focused reproductions finished.

Revision note (2026-07-12): Recorded that all five reports are valid, the generalized implementation decisions, the #641 lifecycle qualification, and complete verification evidence after integration review.
