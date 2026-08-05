# Complete semantic-pack correctness and lifecycle gates

This ExecPlan is a living document. Maintain it in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Issue #1155 requires one reproducible gate for the complete semantic-pack lifecycle. The gate must prove correct results before it accepts performance results. It must also identify the lifecycle phase that caused a regression. After this work, a maintainer can run one focused benchmark campaign. The campaign reports pinned inputs, exact witnesses, phase costs, memory, SQL work, invalidation, reuse, corruption recovery, and garbage collection.

## Progress

- [x] (2026-08-05 10:20Z) Read `AGENTS.md` and `.agents/PLANS.md`.
- [x] (2026-08-05 10:22Z) Fetched `origin`, moved the clean detached HEAD to `origin/master`, and live-checked issues #1155 and #1144.
- [x] (2026-08-05 10:32Z) Reconciled the stale issue body with current master and recent semantic-pack history.
- [x] (2026-08-05 10:58Z) Added stable structured activation selection, decode, matcher, candidate, retained-byte, index, and SQL measurements.
- [ ] Add overlay publication timing and retained-overlay measurement to the structured lifecycle report.
- [ ] Add the correctness matrix and negative outcome gate with exact witnesses.
- [ ] Add lifecycle sample collection, aggregation, budgets, cross-process reuse, corruption recovery, and garbage-collection checks.
- [ ] Validate current published UsageBench cases and add only missing generated-behavior or negative coverage.
- [ ] Run focused tests, packaging checks, formatting, UsageBench validation, the policy gate, and proportionate CI checks.
- [ ] Complete the acceptance matrix and retrospective with measured artifacts and closeability results.

## Surprises & Discoveries

- Observation: Current master contains the work that the original #1155 body requested for published JDK and Scala packs.
  Evidence: commit `ddb435c16` added release bundles, exact pack producers, navigation tests, and release measurements.

- Observation: Current master also contains the initial shipped generated-behavior packs and their end-to-end navigation tests.
  Evidence: commit `31a39a1d9` ships Scala case-class, exact Lombok 1.18.42, and Rust getset 0.1.7 models.

- Observation: Release bundle measurement already times pack generation, activation, cold lookup, warm lookup, sizes, and retained model bytes.
  Evidence: `crates/bifrost-semantic-packs/src/release_bundle.rs` defines `ReleasePackMeasurement` and `measure_runtime`.

- Observation: The old catalog storage benchmark compares storage forms. It does not exercise the production catalog lifecycle.
  Evidence: `tests/suite_semantic/measure_semantic_pack_catalog.rs` uses a private benchmark-only SQLite schema.

- Observation: One durable activation uses five catalog SQL statements for this fixture.
  Evidence: Two selector queries plus lease acquisition, object load, and lease release produced `catalog_sql_statements = 5`; three in-memory matches did not change the counter.

## Decision Log

- Decision: Do not add another model format, pack compiler, generated model, or navigation adapter.
  Rationale: Master already contains these results. Repeating them would not close the lifecycle measurement gap.
  Date/Author: 2026-08-05 / Codex

- Decision: Extend production lifecycle instrumentation and use one new benchmark campaign as the gate.
  Rationale: Issue #1155 owns activation, matcher, overlay, catalog, and lifecycle measurements. Stable structured measurements can also serve issue #1628.
  Date/Author: 2026-08-05 / Codex

- Decision: Keep the separate procedure-summary taint lifecycle benchmark out of this lane.
  Rationale: It measures policy execution and diagnostics. This lane measures semantic-pack infrastructure.
  Date/Author: 2026-08-05 / Codex

- Decision: A timed case must first validate a nonempty exact witness set.
  Rationale: An inactive, empty, corrupt, incompatible, cancelled, or exhausted model must not pass because it is fast.
  Date/Author: 2026-08-05 / Codex

- Decision: Count statements at the production catalog methods that issue them.
  Rationale: This gives stable exact activation counts without a process-global SQLite trace callback. The matcher cannot access the catalog.
  Date/Author: 2026-08-05 / Codex

## Outcomes & Retrospective

The reconciliation milestone and the activation instrumentation milestone are complete. The focused runtime suite passes 13 tests.

## Context and Orientation

A semantic-model pack is a deterministic compiled artifact. It contains external API declarations or modeled generated behavior. `crates/bifrost-analysis/src/analyzer/semantic_model/compiler.rs` compiles authored input. `catalog/mod.rs` installs immutable objects and selects candidates with SQLite. `runtime.rs` decodes selected shards and builds in-memory matcher indexes. `overlay.rs` publishes external or synthetic declarations for search and navigation. `crates/bifrost-semantic-packs` owns shipped packs and release bundles.

Current master satisfies these stale #1155 items: published JDK and Scala UsageBench coverage; semantic-model authoring and conformance tools; shipped Scala, Lombok, workspace, and Rust getset models; Kotlin/JVM API packs; and published-pack navigation with provenance and portable model URIs. The separate production procedure-summary taint lifecycle benchmark also exists. It is not evidence for this issue's pack lifecycle gate.

The remaining acceptance work is one combined semantic-pack gate. It must cover one published standard-library pack, one shipped behavior pack, and one explicit workspace model. It must prove exact type, member, signature, hierarchy, navigation, provenance, completeness, activation identity, and URI results. It must reject wrong-package, unsupported-version, absent-dependency, stale, corrupt, incompatible, cancelled, exhausted, inactive, and empty cases. It must prove real declarations win.

## Plan of Work

First, add a stable structured measurement object at the existing runtime boundaries. Record catalog selection, shard loading and decode, matcher construction, and overlay publication separately. Count catalog SQL statements for activation. Matching must report zero SQL statements. Reuse existing retained-byte and candidate counters. Do not add LSP or diagnostic counters.

Second, add `tests/suite_semantic/measure_semantic_pack_lifecycle.rs`. Use `InlineTestProject`, embedded generated packs, and existing published-pack fixtures. Build exact witnesses for the three positive pack classes. Run indexed and reference lookup paths and compare their normalized answers. Reject every timed case before recording performance if its exact witnesses do not match.

Third, add a campaign script and aggregator. Each sample must include the Bifrost commit, dirty-tree fingerprint, Rust toolchain, pack digests, dependency versions, cache state, witness digest, and phase values. The aggregator must require identical provenance and witnesses across samples. It must report median and p95 for warm matching. It must enforce documented phase, size, SQL, memory, and candidate budgets.

Fourth, exercise persistent catalogs in separate processes. Measure cold reuse, targeted dependency or model invalidation, corrupt-object recovery, and garbage collection. Do not download artifacts. Do not add benchmark-only persistence.

Fifth, inspect the sibling UsageBench repository and its `AGENTS.md`. Run `usagebench validate` and the exact affected published-pack cases. Change UsageBench only if current cases lack one required generated-behavior or negative assertion. Commit UsageBench changes separately.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/f79e/bifrost`.

Run focused development checks with:

    cargo fmt
    cargo test --test suite_semantic -- semantic_model_runtime::
    cargo test --test suite_semantic -- semantic_model_overlay::
    cargo test --test suite_semantic -- generated_behavior_models::
    cargo test --test suite_semantic -- jvm_standard_library_pack::
    cargo test --test suite_persistence -- semantic_pack_catalog::

Run the lifecycle smoke and aggregation checks through the new campaign script. Use the production catalog and runtime. The expected aggregate status is `pass`. Each positive case must contain nonempty witnesses. Each negative case must contain its exact typed outcome.

## Validation and Acceptance

The positive matrix passes only when exact results match. The standard-library case checks a type, member, signature, hierarchy, navigation location, provenance, completeness, active-set hash, and portable URI. The generated-behavior case checks a generated member and its exact dependency-qualified activation. The workspace case checks explicit source control and model identity.

The negative matrix passes only when all unsupported or failed states stay non-successful. A real declaration must take precedence over a modeled conflict. A same-name wrong-package trigger must emit no modeled declaration. Unsupported versions and missing dependencies must stay inactive. Corrupt, stale, incompatible, cancelled, and budget-exhausted activation must not publish a complete empty overlay.

The measurements must separate authoring compile and generation, raw and compressed shard size, catalog install, activation selection, cold decode and hydration, matcher construction, overlay publication, warm matching, candidate counts, retained bytes or RSS, overlay bytes, activation and matching SQL statements, targeted invalidation, process reuse, corruption recovery, and garbage collection.

Run `cargo fmt`, focused tests, packaging checks, `usagebench validate`, affected UsageBench cases, and the repository policy gate. Run broader featureless workspace checks in proportion to the final diff.

## Idempotence and Recovery

The benchmark uses temporary directories unless it intentionally checks cross-process reuse. The campaign script creates a unique temporary root and removes it on exit. Repeated runs do not download, build, or install external dependencies. If a sample fails, keep its JSON artifact and rerun only that case.

## Artifacts and Notes

The first pinned Bifrost revision is `2bf15296f` from `origin/master` on 2026-08-05. `BIFROST_MCP_RMCP=on` for this session.

## Interfaces and Dependencies

Use the existing `SemanticPackCatalog`, `SemanticModelActivationRequest`, `SemanticModelActivationReport`, `ResolvedActiveSemanticModels`, and `SemanticModelOverlay`. Add measurement fields or a closely related stable measurement value only where the production boundary supplies exact data. Use `rusqlite` tracing or a production catalog statement counter for SQL counts. Do not make matcher queries call the catalog.

Revision note: Created after the current-master reconciliation. It limits this lane to the remaining lifecycle gate and its evidence.

Revision note: Updated after activation instrumentation. It records the exact SQL boundary and leaves overlay timing for the next milestone.
