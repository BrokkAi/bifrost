# Scala Inverse Ranks 6-10 Issue Fixes

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

The Scala inverse usage graph already covers many companion-apply, wildcard-import, and singleton cases, but the ranks 6-10 replay still shows missing references in the remaining inverse-only families. After this change, Scala `usage_graph` and `find_usages` should emit exact edges/hits for selector-import references, imported member bindings, singleton/case-object stable references, companion applies, and exact function/value references represented by the replay rows, while still failing closed on wrong-owner, shadowing, or ambiguous decoys.

## Progress

- [x] (2026-07-29 14:00Z) Read `.agents/PLANS.md`, inspected the Scala inverse pipeline, and confirmed the work must stay in `src/analyzer/usages/scala_graph/inverted.rs` plus Scala usage tests.
- [x] (2026-07-29 14:20Z) Corrected the Scala ranks 6-10 audit mapping so the two selector rows now land in `#1287`; regenerated `/mnt/optane/tmp/bifrost-fird/scala-task-ranks6-10-aeea9eec-audit.{md,tsv,json}` with `#1287 = 8`, `legit inverse omission = 58`, and `artifact / uncovered = 0`.
- [x] (2026-07-29 14:15Z) Started the first inverse code patch in `src/analyzer/usages/scala_graph/inverted.rs` for exact selector-import references, including hidden selectors (`name => _`).
- [x] (2026-07-29 14:35Z) Added replay-shaped reducers in the owned Scala tests for every nonzero legitimate inverse bucket in the 58-row set: `#1286`, `#1287`, `#1288`, `#1289`, `#1291`, and `#1316`.
- [x] (2026-07-29 14:35Z) Reinspected the inverse resolver against those reducers. The only new resolver gap identified in this pass was selector-import reference recording (`#1287`), now patched in `src/analyzer/usages/scala_graph/inverted.rs`; the remaining bucket reducers sit on already-structured inverse paths and needed no additional code changes in this handoff.
- [x] (2026-07-29 15:10Z) Extended the exact import-token resolver to record wildcard-owner spans for `import Owner._` / `import Owner.*` (`#1288`) and split the replay coverage into mechanism-specific inverse reducers for wildcard-owner imports, companion applies, bare stable members, singleton terminals, and imported HOF references.
- [x] (2026-07-29 15:30Z) Added a second resolver patch for the remaining Scala 3 extension-scope `#1316` cluster: bare parameterless sibling references inside an active `extension (...)` block now resolve against that block's receiver-typed extension methods before global fallback, with a dedicated production-shaped inverse reducer.
- [x] (2026-07-29 17:10Z) Root review changed exact import-token hits to the import surface, made the targeted query catalog reject same-FQN physical replicas, and replaced an invalid ambiguity negative with two wildcard-visible roots followed by one genuinely ambiguous selector.
- [x] (2026-07-29 17:25Z) Root review replaced visibility-based extension discovery with exact indexed declarations physically contained by the active `extension_definition`, preserving receiver and callable-shape checks.
- [x] (2026-07-29 17:40Z) Ran `cargo test --test usage_graph_scala_test --test usages_scala_graph_test` at niceness 10 with normal Cargo storage: 59/59 graph tests and 170/170 targeted usage tests pass.

## Surprises & Discoveries

- Observation: `record_import_declaration` currently walks identifier nodes inside Scala imports, but the sink path it calls (`record_import_name`) only materializes wildcard-owner edges, not exact named-selector/member edges.
  Evidence: `src/analyzer/usages/scala_graph/inverted.rs` currently resolves `record_import_name` only through `resolve_scala_wildcard_import_environment`.

- Observation: Scala parser support already preserves structured selector paths and lexical scopes for named selectors, but `scala_import_selector_info` intentionally drops hidden selectors (`alias.kind() == "wildcard"`), which is why `Right => _` / `Image => _` were initially misclassified as artifacts.
  Evidence: `src/analyzer/scala/imports.rs` returns `None` for wildcard aliases in `scala_import_selector_info`.

- Observation: The durable audit rewrite only needed row-classification changes; the replay row inventory itself stayed at 111 rows with zero-count buckets still `#1290` and `#1292`.
  Evidence: `/mnt/optane/tmp/bifrost-fird/scala-task-ranks6-10-aeea9eec-audit.json` now reports `by_issue['1287'] == 8`, no `uncovered` bucket, and the same per-repo totals as before.

## Decision Log

- Decision: Keep the fix on the inverse side by teaching the import-declaration walker to resolve selector references directly from the AST instead of broadening shared import models first.
  Rationale: The task is explicitly scoped to Scala inverse/usage graph behavior, and the missing rows are reference hits on import-selector tokens themselves. A local inverse fix avoids collateral changes to get-definition or other languages.
  Date/Author: 2026-07-29 / Codex

- Decision: Treat the selector-import patch as the first reducer, not the whole fix, and require a replay-shaped regression surface for every nonzero inverse bucket (`#1286`, `#1287`, `#1288`, `#1289`, `#1291`, `#1316`) before handoff.
  Rationale: The acceptance target is the full 58-row legitimate-inverse set. Existing nearby tests lower the risk for some families, but the handoff needs explicit reducers that name and exercise the replay shapes rather than assuming old adjacent coverage is enough.
  Date/Author: 2026-07-29 / Codex

## Outcomes & Retrospective

The durable audit is corrected. The new inverse code teaches import-declaration scanning to emit exact selector-import references, including hidden selectors that were previously dropped. Exact selector and wildcard-owner tokens remain import hits rather than leaking onto the external-reference surface, and the targeted query catalog now rejects same-FQN physical replicas. The owned Scala tests include replay-shaped reducers for every nonzero legitimate inverse bucket in the ranks 6-10 set: bare stable field, selector/imported-member, wildcard owner, companion apply, singleton/case-object, and exact function/value reference shapes.

Review follow-up changed one implementation detail and one testing detail. On the implementation side, the same exact import-token path now records the owner token for wildcard-owner imports instead of skipping `namespace_wildcard`, while still failing closed for ambiguous owners and same-FQN physical replicas. On the testing side, the prior omnibus replay test was replaced by mechanism-specific inverse reducers so each nonzero bucket has an explicit production-shaped witness in the Scala inverse suite.

The final review also uncovered a live `#1316` resolver gap that the omnibus reducer had hidden: Scala 3 extension-scope bare sibling references such as `enabled = isLichess` and `flipped = invert` were not owned by the active extension receiver scope. That path now resolves only the extension methods declared inside the enclosing `extension_definition` whose receiver type matches the current extension, and it consumes ambiguity instead of falling through to unrelated global members.

Root execution validation passes: the whole-workspace Scala graph suite is 59/59 and the targeted Scala usage suite is 170/170 at niceness 10 with normal Cargo storage. Clean-head corpus replay remains the campaign-level acceptance gate outside this focused implementation plan.

## Context and Orientation

Scala whole-workspace inverse edges are built in `src/analyzer/usages/scala_graph/inverted.rs`. That file owns both the per-file scan (`ScalaScan`) and the binder that turns visible imports, visible members, stable paths, companion applications, and lexical singletons into exact targets.

Scala import parsing lives in `src/analyzer/scala/imports.rs`. It already emits structured import paths, lexical prefix/scope metadata, and selector-specific `ImportInfo` values for ordinary named selectors and wildcard imports. The inverse scan uses `scala_import_infos_from_node` when it sees an `import_declaration`.

The main Scala end-to-end inverse tests live in `tests/usage_graph_scala_test.rs` and `tests/usages_scala_graph_test.rs`. The first exercises the whole-workspace graph surface. The second exercises `UsageFinder` against exact `CodeUnit` targets and is the right place to prove that exact selector-token references show up for a chosen target while shadowed or ambiguous decoys stay out.

## Plan of Work

First correct the audit ledger. The durable files in `/mnt/optane/tmp/bifrost-fird/scala-task-ranks6-10-aeea9eec-audit.{md,tsv,json}` must move the two selector rows from `uncovered` to `#1287`, which changes the aggregate counts to `#1287 = 8`, `legit inverse omission = 58`, and `artifact / uncovered = 0`.

Then patch the inverse scan. In `src/analyzer/usages/scala_graph/inverted.rs`, keep the existing wildcard-owner recording for `import Owner._`, but add a selector-aware path for named selectors. That path should use structured AST fields to resolve the selector’s exact imported declaration or member and record a reference on the selector token span itself. Hidden selectors such as `Either.{Right => _}` must still count as references to the imported source member even though they do not bind a visible local name. The implementation must remain structured: no text splitting or regex recovery.

After the selector work, add replay reducers for every nonzero bucket in the current ranks 6-10 inverse set. `#1286` needs a bare stable field reducer, `#1287` needs selector-import and imported-member reducers, `#1288` needs wildcard-owner reducers, `#1289` needs companion-apply reducers, `#1291` needs singleton/case-object reducers, and `#1316` needs exact function/value-reference reducers. Where existing tests already exercise the same mechanism, keep them and add a replay-shaped test only when the replay witness is still not explicitly pinned.

Finally re-run the mental audit against those reducers: if any bucket’s replay shape is still not obviously owned by the current structured resolver path, extend the inverse resolver before handoff rather than deferring it. This review found one concrete gap, selector-import references, and that path is now patched.

## Concrete Steps

From `/mnt/optane/bifrost-fird`:

1. Edit `.agents/plans/scala-inverse-ranks6-10-issue-fixes.md` as progress changes.
2. Edit `src/analyzer/usages/scala_graph/inverted.rs` to add exact selector-import reference recording and any additional inverse fixes revealed by the replay reducers.
3. Edit `tests/usage_graph_scala_test.rs` and `tests/usages_scala_graph_test.rs` to add replay reducers for each nonzero inverse bucket.
4. Regenerate the audit ledger files under `/mnt/optane/tmp/bifrost-fird/`.
5. Run the complete Scala graph and targeted-usage suites at niceness 10 with normal Cargo storage.

## Validation and Acceptance

Acceptance is code-and-test based:

1. The corrected audit files report `#1287 = 8`, `legit inverse omission = 58`, and no artifact bucket.
2. The new Scala tests make the intended behavior obvious from their source markers:
   the target symbol’s hits or edges include replay-shaped positives for `#1286`, `#1287`, `#1288`, `#1289`, `#1291`, and `#1316`, while same-name decoys, wrong owners, ambiguous imports, and shadows stay excluded.
3. The complete Scala graph and targeted-usage suites pass.

## Idempotence and Recovery

The audit regeneration is idempotent: rerunning the emitter should overwrite the same three files with the corrected counts. The code changes are confined to Scala inverse resolution and tests, so recovery means reverting only the touched Scala files if a later reviewer needs to back out the patch.

## Artifacts and Notes

The durable replay artifacts live under `/mnt/optane/tmp/bifrost-fird/` and are intentionally outside the repository tree.

## Interfaces and Dependencies

The implementation must stay inside existing Scala inverse interfaces:

- `record_import_declaration` in `src/analyzer/usages/scala_graph/inverted.rs` remains the entry point for import-token references.
- `ScalaScan`, `NameResolver`, and `ProjectTypes` remain the structured helpers for visible symbol resolution.
- `scala_import_infos_from_node` in `src/analyzer/scala/imports.rs` remains the parser-backed source of selector structure.

Revision note: broadened the ExecPlan after review to require explicit replay reducers for every nonzero inverse bucket in the 58-row set, not just selector-import references.
