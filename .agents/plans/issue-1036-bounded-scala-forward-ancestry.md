# Keep Scala forward ancestry bounded and live-snapshot correct

This ExecPlan is a living document maintained under `.agents/PLANS.md`. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must stay current while issue #1036 is implemented.

## Purpose / Big Picture

Warm persisted Scala symbol queries must resolve inherited members, constructors, extension methods, and types without rebuilding the workspace-wide Scala inverse-usage model or hydrating unrelated files. After this change, the nine `tests/analyzer_persistence.rs` regressions remain functionally correct for dirty overlays and stale blobs while reporting fewer than 32 candidate hydrations, no workspace scan, and zero Scala project-types builds.

## Progress

- [x] (2026-07-21 17:00Z) Reproduced the dirty-overlay and stale-owner failures and confirmed their definition results are correct while boundedness counters fail.
- [x] (2026-07-21 17:05Z) Confirmed issues #661-#664 do not cover this persistence regression; issue #1036 is assigned to Jonathan.
- [x] (2026-07-21 18:02Z) Mapped the 34-file bulk hydration to the lexical-type ancestor callback and enumerated every `project_types()` call reachable from forward Scala definition lookup.
- [x] (2026-07-21 18:22Z) Replaced forward hierarchy and callable-shape reads with request-bounded live owner/source facts; `get_definition/scala.rs` no longer calls `project_types()`.
- [x] (2026-07-21 18:34Z) Passed the full 42-test persistence target, the 74 Scala definition tests, 21 hierarchy tests, and both Scala usage suites (55 and 139 tests). Formatting, clippy, and the repository-wide feature-enabled suite remain release gates owned by the parent campaign plan.
- [x] (2026-07-21 19:20Z) Corrected the unrestricted-suite LSP regression so exact same-depth inherited trait conflicts return all resolved definitions; the exact click-around regression and the 74-test Scala definition subset pass.

## Surprises & Discoveries

- Observation: The reproduced lookups return the correct live definition and exclude the stale definition; failures are entirely boundedness regressions.
  Evidence: `scala_dirty_owner_overlay_supplies_live_ancestor_facts` fails only at `candidate_hydration_count_for_test() < 32`, while `scala_stale_owner_blob_is_excluded_from_ancestor_facts` fails only because the project-types build count is one.

- Observation: Commit `c665f8b5` established that public forward lookups must use bounded persisted facts and reserve global `ScalaProjectTypes` for inverse analysis.
  Evidence: Its commit message says it confines Scala `ProjectTypes` to explicit inverse usage analysis and adds the affected overlay and stale-blob regressions.

- Observation: The warm regression hydrated 36 Scala candidates: 34 in one global batch and two point reads.
  Evidence: The bulk path was `scala_seed_parameter` through exact lexical type namespace ancestry into `project_types().exact_direct_ancestor_resolution`, which called `bulk_file_states(analyzed_files(), Omit)`.

- Observation: The forward module depended on the inverse projection for more than ancestry.
  Evidence: Constructor applicability, method-value function arity, typed overload selection, callable roles and shapes, subtype checks, and namespace inheritance all contained direct `project_types()` calls. The final implementation removes all of them.

- Observation: Multiple exact ancestors at one inheritance depth are not an owner-resolution ambiguity.
  Evidence: `ConflictService extends Primary with Secondary` must return both exact `id` declarations. Import/name ambiguity is rejected while resolving each ancestor path; a later structural-parent-count check incorrectly converted this valid conflict to null.

## Decision Log

- Decision: Preserve the public forward resolver and add bounded owner/callable helpers instead of weakening the persistence thresholds.
  Rationale: The thresholds enforce user-visible warm-start scalability and live-generation correctness; raising them would conceal whole-workspace hydration.
  Date/Author: 2026-07-21 / Codex

- Decision: Resolve ancestors through exact `BoundedDefinitionLookup` candidates and generation-coherent per-owner facts, never by initializing `ScalaAnalyzer::project_types()`.
  Rationale: This keeps dirty overlays authoritative, excludes stale OIDs, and limits work to the reachable owner chain.
  Date/Author: 2026-07-21 / Codex

- Decision: Decode parser-recorded callable alternatives from only the declaration's current indexed source, then resolve parameter type identities with the declaration's bounded name resolver.
  Rationale: Forward constructor, overload, and method-value behavior still needs exact callable roles and shapes, but the inverse projection's workspace-wide cache is unnecessary for a queried declaration.
  Date/Author: 2026-07-21 / Codex

- Decision: Return all same-depth member definitions from distinct, already-exact ancestor declarations while retaining fail-closed resolution for ambiguous imports, duplicate physical owner candidates, and unresolved type paths.
  Rationale: The former is the public definition contract for Scala trait conflicts; the latter are cases where no exact physical owner has been proven.
  Date/Author: 2026-07-21 / Codex

## Outcomes & Retrospective

Forward Scala lookup now obtains ancestor facts from the exact live owner and callable facts from the exact declaration source. It preserves explicit-import and wildcard ambiguity, dirty-overlay authority, stale-OID exclusion, physical owner identity, constructor roles, typed overloads, and method-value shapes without constructing the inverse `ScalaProjectTypes` model.

The full `analyzer_persistence` target passes 42/42, including all seven warm Scala queries plus dirty-overlay and stale-owner cases. The complete definition target passes 580/580, Scala precedence passes 43/43, residual Scala scope passes 8/8, hierarchy passes 21/21, and the forward/inverse usage suites pass 55/55 and 139/139. The exact Scala extension/trait click-around regression also passes after preserving both definitions for a valid same-depth inherited trait conflict. No thresholds or semantic assertions were weakened.

## Context and Orientation

`src/analyzer/usages/get_definition/scala.rs` implements public forward definition lookup. It receives a `BoundedDefinitionLookup`, which performs exact persisted queries against the current live file-to-content snapshot. `src/analyzer/scala/mod.rs` exposes per-owner source and persisted facts. `src/analyzer/usages/scala_graph/inverted.rs` contains `ScalaProjectTypes`, a workspace-wide model intended for inverse usage scans. Forward code previously called that global model for ancestor and callable alternatives, which bulk-hydrated unrelated file states; the implementation now confines it to inverse analysis.

A dirty overlay is an uncommitted source snapshot newer than the stored blob. A stale OID is the old content hash formerly associated with a path. Correct forward resolution must read the dirty state when present and must never re-admit declarations from a stale OID.

## Plan of Work

First, run the complete feature-enabled `analyzer_persistence` integration suite to capture all nine failing test names and classify each entry path. Trace the forward resolver from each test to its `project_types()` call.

Second, introduce request-bounded helpers that expose a callable declaration's parser-recorded role, parameter-list shape, defaults, parameter types, extension receiver, and return type from only that declaration's current file state. Reuse existing parser-backed Scala source facts rather than rebuilding syntax with text parsing. Ancestor traversal will resolve each parser-recorded supertype path with the current owner's package prefixes, lexical scopes, and visible imports, query exact declarations through `BoundedDefinitionLookup`, and preserve ambiguity instead of selecting an arbitrary physical owner.

Third, replace every forward `project_types()` use in `get_definition/scala.rs`, including callable filtering, constructor matching, typed overload selection, type namespace inheritance, and subtype traversal. The inverse graph remains unchanged.

Finally, validate the exact persistence regressions and the broader Scala definition/hierarchy suites. Update this plan with concrete results and any design changes.

## Concrete Steps

Work from `/mnt/optane/tmp/bifrost-burndown-3`.

Run the persistence suite:

    cargo test --features nlp,python --test analyzer_persistence -- --nocapture

After implementation, rerun each previously failing test with `--exact`, then run:

    cargo test --features nlp,python --test get_definition_test
    cargo test --features nlp,python --test scala_type_hierarchy_test
    cargo fmt
    cargo clippy --all-targets --all-features -- -D warnings

## Validation and Acceptance

All nine persistence tests must pass their existing functional and boundedness assertions. In particular, dirty `Base.scala` must resolve `lib.Base.replacement`, committed stale `oldValue` must remain unresolved, candidate hydrations must remain below the existing threshold, workspace path scans must remain zero, and `scala_project_types_build_count_for_test()` must remain zero. The complete Scala definition and hierarchy suites must remain green.

## Idempotence and Recovery

The tests create isolated temporary repositories and may be rerun safely. Source edits are confined to the Scala analyzer and tests. No migrations or destructive operations are required.

## Artifacts and Notes

Original failing evidence:

    scala_dirty_owner_overlay_supplies_live_ancestor_facts: assertion failed: candidate_hydration_count_for_test() < 32
    scala_stale_owner_blob_is_excluded_from_ancestor_facts: left project-types builds 1, right 0

## Interfaces and Dependencies

Keep `BoundedDefinitionLookup` as the only declaration-query dependency of forward ancestry. New Scala helpers must return explicit resolved, ambiguous, or unavailable outcomes rather than silently falling back to global state. Parser-derived facts must come from the exact `FileState` selected by the analyzer query snapshot.

Revision note (2026-07-21): Initial plan created after issue assignment and two exact reproductions.

Revision note (2026-07-21): Recorded the complete bounded implementation and focused validation results. Repository-wide formatting, clippy, and full-suite gates remain tracked by the parent differential campaign.

Revision note (2026-07-21): Recorded the same-depth trait-conflict correction found by the unrestricted suite and its exact plus Scala-definition validation.
