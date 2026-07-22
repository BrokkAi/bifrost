# Complete Scala reference identity for issue 661

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain it in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

After this change, the public Scala symbols usage tools will find three kinds of real references that forward definition lookup already resolves: uses of abstract type members refined inside anonymous instances, unqualified construction through a type alias, and same-source companion constants in repositories that carry JVM and native declarations with the same fully qualified name. A user can observe the improvement through `scan_usages_by_reference` and the internal usage finder: exact references appear, while unrelated same-name symbols and genuinely ambiguous third-file imports remain absent.

## Progress

- [x] (2026-07-22 12:03Z) Confirmed clean head `19c92da5a1e542bdbfb697023f25c2a5e41b99d1` and reviewed the repository planning rules.
- [x] (2026-07-22 12:26Z) Added faithful red tests for anonymous refinement type members, unqualified type-alias construction, and duplicate physical companion imports; observed 0 refinement hits, 1/2 alias hits, and no same-source platform hit respectively.
- [x] (2026-07-22 12:48Z) Implemented the three structured resolution changes and expanded the tests with ambiguity, shadowing, identity, renamed-import, declaration-name, and before-declaration cases.
- [x] (2026-07-22 13:56Z) Ran the focused graph/public-symbol tests and replayed all thirteen production coordinates from the final release candidate with ephemeral caches; all thirteen were `consistent` with inverse hits and zero missing rows.
- [x] (2026-07-22 13:53Z) After all review fixes, ran formatting and `cargo test --features nlp,python --test usages_scala_graph_test`; all 144 tests passed.
- [x] (2026-07-22 13:54Z) Ran `cargo clippy --all-targets --all-features -- -D warnings`; it completed without warnings.
- [x] (2026-07-22 13:57Z) Completed independent review and limited the final commit scope to this plan, the two Scala graph implementation files, and the behavior test file.

## Surprises & Discoveries

- Observation: The FS2 `Key` witness is the second `Key` on its line, under `new Key[JBoolean]`, while the preceding annotation is a separate reference that already works.
  Evidence: The recorded byte range is `3916..3919`, which is column 52 in `SocketOptionPlatform.scala` line 100.

- Observation: The ZIO `PollingMetric.In` witness is nested below two additional anonymous instances, so immediate-parent inspection cannot solve the production case.
  Evidence: `type In = Chunk[Any]` belongs to the outer anonymous `PollingMetric`; the missing parameter type is inside anonymous `Metric` and `UnsafeAPI` bodies.

- Observation: The existing constructed-value inference deliberately validates explicit constructor application shape before retaining a receiver type.
  Evidence: Factoring the helper directly through lexical declaration lookup would bypass `resolve_type_application`; the final helper instead returns that resolver's exact `type_target` and keeps the original validation semantics.

- Observation: Named classes declared inside an anonymous template do not receive indexed `CodeUnit` identities, even though `ClassRangeIndex::enclosing_unit` can return an outer indexed owner at their byte positions.
  Evidence: `refinement.Uses$.DirectNamed.State` has no definition in the inline precedence fixture. Exact-span lookup therefore deliberately fails closed at that named boundary instead of letting the outer anonymous refinement steal the reference. Indexed intervening anonymous inherited aliases and nested classes retain positive exact-target coverage.

- Observation: An intervening anonymous base can itself be an inherited nested type whose ordinary lexical constructor lookup has no owner context.
  Evidence: ZIO's `new UnsafeAPI` is inherited from the surrounding anonymous `Metric`; resolving the nearest exact surrounding template namespace first recovers `Metric.UnsafeAPI`, after which ordinary constructor validation retains the same exact `CodeUnit`.

## Decision Log

- Decision: Keep anonymous refinement identity attached to the indexed abstract base type member instead of creating public byte-derived anonymous declarations.
  Rationale: The forward tool already returns the base member, and stable public symbol identity must not depend on a source offset. The AST can prove the anonymous type definition and constructed base relationship.
  Date/Author: 2026-07-22 / Codex

- Decision: Resolve duplicate physical companion imports by exact source-file identity only after global uniqueness fails.
  Rationale: JVM/native replicas have identical logical names but each same-file class imports its own companion. A third-file importer has no source-local declaration and must remain ambiguous.
  Date/Author: 2026-07-22 / Codex

- Decision: Treat an anonymous alias as a refinement only when the exact constructed target and exactly one member through its exact hierarchy are both proven.
  Rationale: This preserves valid indirect inheritance and outward anonymous-template lookup while making duplicate physical bases, mixins, abstract declarations, and same-level duplicate members authoritative misses.
  Date/Author: 2026-07-22 / Codex

- Decision: Interleave intervening anonymous constructed bases and exact named template owners before accepting an outer anonymous refinement.
  Rationale: A nearer anonymous inherited member or named direct/inherited member owns the unqualified type name. Named local templates without an indexed exact span fail closed because their member identity cannot be proven.
  Date/Author: 2026-07-22 / Codex

## Outcomes & Retrospective

The inverse scanner now preserves exact identity for anonymous refined type members, unqualified type-alias construction, and same-source JVM/native companion constants. The focused behavior matrix covers direct, inherited, outward-nested, before-declaration, renamed-import, physical-duplicate, mixin, local-shadow, and third-file ambiguity cases through both `UsageFinder` and `scan_usages_by_reference`.

The final feature-enabled Scala graph integration target passed all 144 tests, and clippy passed with all targets, all features, and warnings denied. All thirteen production witnesses completed as `consistent` with a non-null inverse hit and zero missing/actionable rows. The final ephemeral report is `/tmp/issue-661-exact-final2-19c92da5.jsonl`, with SHA-256 `f05a63500e3b6393106b26923977e0da94a06f23c6b858f6a8c64df2823a453e`.

## Context and Orientation

Scala usage edges are built in `src/analyzer/usages/scala_graph/inverted.rs`. A usage edge maps one exact source token to an indexed `CodeUnit`, Bifrost's declaration identity. `ScalaScan` maintains the active package, imports, enclosing named declarations, and local term bindings while walking the tree-sitter syntax tree. `ProjectTypes` supplies exact declaration, hierarchy, field, callable, and type-alias facts.

The shared lexical type helpers live in `src/analyzer/usages/scala_graph/namespace.rs`. The existing `scala_unindexed_type_binding_shadows` function treats method-local aliases and type parameters as authoritative barriers because those bindings deliberately have no public `CodeUnit`. Anonymous instance template members need a richer outcome: a direct `type_definition` such as `type State = Boolean` can be proven to refine the indexed `State` member inherited from the exact constructed base.

Unqualified type references are processed by `record_reference` in `inverted.rs`. Qualified explicit construction already records a type alias before class-constructor lowering. The unqualified branch currently sends the alias to `resolve_type_application`, whose candidates are classes, thereby losing the alias.

Explicit imports are assembled by `NameResolver::for_file_with_facts_impl` in `inverted.rs`. `ProjectTypes::importable_member_by_normalized_fqn` currently accepts only globally unique fields or functions. This rejects JVM/native constant replicas even while the scanner knows which source file it is analyzing.

Behavior tests belong in `tests/usages_scala_graph_test.rs`, which uses `tests/common/inline_project.rs::InlineTestProject` and contains both direct `UsageFinder` assertions and calls through the public search-tools service. The production proof comes from `/mnt/optane/tmp/reference-differential/scala-task-top5-c2ed033d-baseline.jsonl` against pinned ZIO and FS2 checkouts under `/mnt/T9/repo-clones`.

## Milestones

The first milestone is a faithful red behavior suite. Three inline Scala projects will reproduce the anonymous refinement, unqualified alias constructor, and duplicate physical companion-import shapes. Each test will exercise exact `UsageFinder` identity and the public `scan_usages_by_reference` result, while explicit negatives prove that local aliases, unrelated same-name declarations, opposite-platform declarations, and third-file imports do not leak. This milestone is complete when the new tests compile and fail only at the intended missing assertions on the unmodified implementation.

The second milestone is the structured implementation. The inverse scanner will classify the nearest lexical type binding from tree-sitter structure, bridge an anonymous refinement only when one exact constructed base member is proven, record exact aliases before unqualified constructor lowering, and select a duplicate imported member only when the globally unique path failed and one exact same-source stable companion owns it. This milestone is complete when all three focused tests pass and the pre-existing lexical, alias, and physical-identity tests remain green.

The third milestone is production replay and acceptance. The release differential binary will be rebuilt from the changed head and rerun in ephemeral mode against all thirteen pinned ZIO and FS2 coordinates. Formatting and the complete feature-enabled Scala usage graph integration binary will then run. This milestone is complete when every feasible exact row is consistent, the requested test gate passes, and the final diff contains only the plan, structured implementation, and behavior tests for issue 661.

## Plan of Work

First add three behavior tests. The refinement test will model a base trait with an abstract type, an inherited anonymous implementation with direct parameter, return, and value type uses, a deeply nested anonymous use, and local or pure-alias shadows that must not leak. The alias-constructor test will place an annotation and `new Key[...]` on one line and require two exact hits for the alias while excluding the underlying trait and a same-name decoy. The replica test will create JVM and native companion/class pairs, query each physical constant singly and as one logical group, and retain a third-file ambiguity negative. Each family will also exercise `scan_usages_by_reference` so the MCP symbols contract is covered.

Next extend the lexical binding helper to distinguish ordinary unindexed barriers from anonymous refinement bindings using tree-sitter node kinds and fields. In the inverse scanner, interleave intervening anonymous and exact named template namespaces, resolve inherited nested anonymous bases through the nearest exact surrounding namespace, and retain the outer refinement only when one corresponding stable alias member is proven. Ambiguity, unindexed named boundaries, and pure local anonymous aliases remain authoritative misses.

Then mirror the qualified type-alias constructor fast path in the unqualified constructor branch. An exact alias records a `Type` reference and returns before class application lowering.

Finally pass the active source file into explicit-member import selection. Preserve the global unique case; otherwise select exactly one same-source term member whose exact structural parent is a same-source stable object. Do not infer platforms from paths. Preserve coalesced Scala type-and-value identities by checking term declaration facts rather than excluding all aliases.

## Concrete Steps

Work from `/mnt/optane/tmp/bifrost-burndown-3`.

Add the tests and run each by name:

    cargo test --features nlp,python --test usages_scala_graph_test scala_usage_finder_bridges_anonymous_refinement_type_members -- --exact
    cargo test --features nlp,python --test usages_scala_graph_test scala_usage_finder_records_unqualified_type_alias_constructor -- --exact
    cargo test --features nlp,python --test usages_scala_graph_test scala_explicit_companion_imports_keep_same_fqn_targets_source_exact -- --exact

After implementation, run:

    cargo fmt
    cargo test --features nlp,python --test usages_scala_graph_test

For each of the thirteen production locations, run `target/release/bifrost_reference_differential run-repo` with `--cache-mode ephemeral`, the pinned repository root, language `scala`, and exact `--path`, `--start-byte`, and `--end-byte`. Each report should classify the row as `consistent` rather than `missing`.

## Validation and Acceptance

Acceptance requires all three new behavior tests to pass through the direct usage finder and public `scan_usages_by_reference` surface. The refinement target must receive direct and deeply nested type references but no method-local, pure anonymous local, or unrelated same-name references. The type alias must receive both the annotation and constructor token on the faithful line. Each JVM/native constant target must receive only its same-source uses when queried singly; their logical group must contain both platforms, and a third-file importer must remain absent.

The complete `usages_scala_graph_test` integration binary must pass with features `nlp,python`. Formatting must leave no diff. Exact production reruns should make all thirteen task-ranked rows consistent; if building the release binary or pinned checkouts prevents a replay, record the precise limitation and complete every feasible representative.

## Idempotence and Recovery

All tests and exact differential runs are read-only with respect to repository sources. Exact runs use ephemeral cache mode. Apply edits with small file-scoped patches and never discard unrelated working-tree changes. If a test exposes a conflicting resolver invariant, keep the fail-closed behavior, update this plan's discovery and decision sections, and refine the structured proof rather than adding text or path fallbacks.

## Artifacts and Notes

The thirteen production witnesses are six ZIO `Schedule.State` references, ZIO `PollingMetric.In`, FS2 `Context`, FS2 `Repr`, FS2 unqualified `new Key`, and three ZIO `RingBuffer` constant references. The corpus file and pinned source checkouts named above are the authoritative replay inputs.

## Interfaces and Dependencies

No public API shape changes are required. The implementation uses tree-sitter `Node` relationships, existing `CodeUnit` identity, `ProjectTypes::stable_type_member_for_owner_unit`, `ProjectTypes::exact_structural_parent`, `ProjectTypes::type_is_stable_owner`, `NameResolver`, and the existing `ScalaResolvedReference` and `ScalaReferenceRole::Type` event path. The Python client and LSP consume the same symbols results and need no new parameters.

Revision note: 2026-07-22 added independently verifiable red-test, structured-implementation, and production-replay milestones after review of the canonical planning requirements.
