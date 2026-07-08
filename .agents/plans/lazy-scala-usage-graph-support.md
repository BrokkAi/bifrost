# Lazily Build Scala Usage Graph Support for Scoped Calls

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agents/PLANS.md` from the repository root. It is self-contained and describes the implementation needed to speed up Scala `usage_graph` calls that pass a `paths` filter without changing the graph edges those calls return.

## Purpose / Big Picture

The `usage_graph` search tool builds caller-to-callee edges for source code. In Scala repositories, even a path-scoped call such as `usage_graph({"paths":["src/Foo.scala"]})` currently pays for whole-repository Scala support indexes before scanning the requested file. This hurts callers like brokkbench that need only the references from a few changed files per commit.

After this change, path-scoped Scala `usage_graph` calls should preserve existing behavior while avoiding two eager whole-workspace passes: scanning every extension method up front and precomputing override edges for every method. A human can see the behavior by running Scala usage graph tests that cover extension-method calls, trait override edges, and path-filtered graph calls.

## Progress

- [x] (2026-07-07) Read `.agents/PLANS.md` and the relevant Scala usage graph code in `src/analyzer/usages/scala_graph/{shared.rs,inverted.rs}`.
- [x] (2026-07-07) Confirmed production bottleneck shape: `ScalaEdgeResolver::try_new` calls `scala.project_types()` and `build_method_override_targets(scala, &types)` before path filtering applies.
- [x] (2026-07-07) Replace eager extension-method discovery with per-file, per-member, per-import owner lookup.
- [x] (2026-07-07) Replace eager `build_method_override_targets` with a lazy cache queried only for function definitions encountered in scanned files.
- [x] (2026-07-07) Keep package type lookup lazy so `ProjectTypes::build` no longer clones every package type at construction time.
- [x] (2026-07-07) Add path-filtered Scala graph coverage proving imported extension methods still resolve from scanned files.
- [x] (2026-07-07) Run focused tests, formatting, and non-CUDA clippy.

## Surprises & Discoveries

- Observation: `DefinitionLookupIndex` already stores direct children by exact and normalized owner FQN, and exposes `members_for_owner_name(owner, normalized_owner, name)`.
  Evidence: `src/analyzer/definition_lookup_index.rs` contains `members_for_owner_name`, which can find a candidate extension method named `slug` under an imported owner such as `app.Syntax$`.
- Observation: `UsageFactsIndex` is already built during analyzer indexing from all declarations and signatures.
  Evidence: `TreeSitterAnalyzer::index_state` builds `UsageFactsIndex::build_from_declarations(...)` after merging signatures, so arity and return-type facts are already available before `usage_graph`.
- Observation: The current eager extension index exists only to answer visible extensions for a file import and member name.
  Evidence: `NameResolver::for_file` iterates `types.extension_methods_by_name.values()` only for wildcard imports, and looks up `types.extension_methods_by_name.get(scala_member_name(&member_fqn))` only for direct member imports.
- Observation: The inverted Scala usage graph records extension calls through the call-expression scanner, while property-style no-argument extension access is covered by the per-symbol usage graph tests rather than by `usage_graph` edges.
  Evidence: The new path-filtered `usage_graph` regression uses `def slug(): String` and `"Hello World".slug()` so it exercises the existing inverted call path without broadening semantics.

## Decision Log

- Decision: Preserve `usage_graph` semantics and do not weaken brokkbench’s `DEF` signal.
  Rationale: The user explicitly rejected disabling Scala `DEF`; this work must remain inside Bifrost and keep behavior intact.
  Date/Author: 2026-07-07 / Codex.
- Decision: Use lazy lookup over `DefinitionLookupIndex` and `UsageFactsIndex` instead of adding a persistent analyzer-level extension-method index in this pass.
  Rationale: Each commit analyzer is loaded once in the motivating workload, so caching for repeated commits is not the main win. The important win is avoiding a duplicate all-declarations/signatures scan after analyzer construction.
  Date/Author: 2026-07-07 / Codex.
- Decision: Keep `ProjectTypes` as a thin shared support object, but make its expensive members lazy.
  Rationale: Existing call sites already pass `&ProjectTypes`; changing it into a lazy façade keeps the blast radius smaller while allowing path-scoped calls to compute only what they use.
  Date/Author: 2026-07-07 / Codex.
- Decision: Preserve direct and wildcard extension-import semantics by storing direct imported extension methods on the file resolver and storing wildcard import owners for later member-specific lookup.
  Rationale: This avoids the all-extension-method scan while still resolving only declarations visible through the file's imports.
  Date/Author: 2026-07-07 / Codex.
- Decision: Cache override targets by method FQN plus arity in `ProjectTypes` and compute them from the scanned declaration site.
  Rationale: This keeps the old arity-sensitive trait override edge behavior, but avoids visiting every project method before path filtering has selected files.
  Date/Author: 2026-07-07 / Codex.

## Outcomes & Retrospective

Implemented lazy Scala graph support in `src/analyzer/usages/scala_graph/inverted.rs` and removed the eager override-target field from `src/analyzer/usages/scala_graph/shared.rs`. `ScalaEdgeResolver::try_new` no longer calls `build_method_override_targets`, and `ProjectTypes::build` no longer iterates all package types or all extension declarations.

Validation so far:

    cargo fmt --check
    cargo test --test usage_graph_scala_test -- --nocapture
    cargo test --test usages_scala_graph_test scala_graph_resolves_visible_extension_method_usage -- --nocapture
    cargo test --test usages_scala_graph_test scala_graph_connects_trait_methods_to_overrides_and_receiver_calls -- --nocapture
    cargo test --test usages_scala_graph_test -- --nocapture
    cargo clippy-no-cuda

One attempted command used multiple Cargo test filters in a single invocation; Cargo rejected the syntax before running tests. The full `usages_scala_graph_test` run replaced that attempt.

## Context and Orientation

The relevant tool is `usage_graph`, implemented in `src/searchtools.rs`. It dispatches Scala work to `crate::analyzer::usages::scala_graph::build_scala_usage_edges`, which creates a `ScalaEdgeResolver` in `src/analyzer/usages/scala_graph/shared.rs`.

The current eager work happens in `ScalaEdgeResolver::try_new`. It obtains `types = scala.project_types()`, which calls `ProjectTypes::build` in `src/analyzer/usages/scala_graph/inverted.rs`, and then calls `build_method_override_targets(scala, &types)`. A path filter is applied later in `build_scala_edges` through the language-agnostic `build_edges` helper, so path-scoped calls still pay these upfront costs.

`ProjectTypes` currently contains:

- `index`: an `Arc<DefinitionLookupIndex>`. This global lookup index maps fully qualified names and owner/member pairs to declarations.
- `facts`: an `Arc<UsageFactsIndex>`. This global facts index stores callable arity and return type information extracted from signatures.
- `package_types_by_package`: an eagerly cloned map from package name to type declarations.
- `extension_methods_by_name`: an eagerly cloned map from method name to Scala extension methods.

A Scala extension method is a method declared with syntax like `extension (value: String) def slug: String = ...`. Current code treats it as visible when a scanned file imports its owner with a wildcard import such as `import app.Syntax.*`, or imports the method directly.

A trait override edge is an edge from an overriding method declaration to the trait method it overrides. Current code precomputes these for every Scala function in the project. The lazy replacement should compute the target list only for method declarations encountered while scanning files that pass the path filter.

## Plan of Work

Edit `src/analyzer/usages/scala_graph/inverted.rs`. Remove the eager extension-method map from `ProjectTypes` and replace eager `package_types_by_package` with a mutex-protected lazy package cache. Add methods on `ProjectTypes` that answer `package_types_in(package)`, `extension_methods_for_owner_member(owner_fqn, member)`, `direct_extension_method(normalized_fqn)`, and `override_targets_for_method(scala, method_fqn, arity)`.

Change `NameResolver` so it no longer stores pre-expanded `visible_extensions`. Instead it should store wildcard extension owner FQNs and direct extension method aliases. `NameResolver::for_file` should populate those sets from imports without scanning all extension methods. When resolving a member call, `visible_extensions` should ask `ProjectTypes` for only the candidate owner/member pairs relevant to that call.

Change `ScalaScan` to remove `override_targets_by_method_fqn` and call the new lazy override-target method from `record_override_declaration`. This computes override targets only for function declarations in scanned files.

Edit `src/analyzer/usages/scala_graph/shared.rs` to remove the eager `override_targets_by_method_fqn` field and the call to `build_method_override_targets` in `ScalaEdgeResolver::try_new`.

Add tests in `tests/usage_graph_scala_test.rs` if current coverage is not enough. Existing tests already cover path-filtered usage graph, extension methods, and trait override edges; add a path-filtered extension-method graph test if needed to exercise the new lazy path through `usage_graph`, not only per-symbol `find_usages`.

## Concrete Steps

1. From `/home/jonathan/Projects/bifrost`, edit `src/analyzer/usages/scala_graph/inverted.rs` and `shared.rs`.
2. Run `cargo fmt`.
3. Run focused tests:

    cargo test --test usage_graph_scala_test -- --nocapture
    cargo test --test usages_scala_graph_test scala_graph_resolves_visible_extension_method_usage -- --nocapture
    cargo test --test usages_scala_graph_test scala_graph_returns_all_matching_ambiguous_extension_methods -- --nocapture

4. If the environment supports non-CUDA clippy for this repo, run:

    cargo clippy-no-cuda

## Validation and Acceptance

Acceptance requires behavior and structure:

- Behavior: existing Scala `usage_graph` and Scala usage resolver tests pass.
- Behavior: a path-filtered `usage_graph` over a Scala file that imports and calls an extension method still emits an edge from the scanned caller to the extension method.
- Behavior: trait override declaration edges still appear for scanned files.
- Structure: `ScalaEdgeResolver::try_new` no longer calls `build_method_override_targets`; extension methods are not discovered by iterating every declaration in `ProjectTypes::build`.

## Idempotence and Recovery

The implementation is source-only and safe to retry. If a test fails, use `git diff` to inspect the current patch and edit only the files named in this plan. Do not reset the worktree because unrelated user changes may exist. The focused tests can be rerun repeatedly.

## Artifacts and Notes

The original hotspot evidence came from profiling a brokkbench Scala worker. The active stack was:

    prefilter._referenced_fqns
    bifrost_searchtools.client.usage_graph(paths=changed_files)
    brokk_bifrost::analyzer::usages::scala_graph::inverted::ProjectTypes::build

The native profile showed about one third of sampled cycles directly in `ProjectTypes::build`, with additional allocator, hash, string formatting, and tree-sitter signature work below it.

## Interfaces and Dependencies

In `src/analyzer/usages/scala_graph/inverted.rs`, `ProjectTypes` should remain visible as `ScalaProjectTypes` through `src/analyzer/usages/scala_graph.rs`. It should provide methods needed by `NameResolver` and `ScalaScan` without requiring callers to know whether data is eager or lazy.

No new external dependencies are required. Use standard library synchronization such as `std::sync::Mutex` for lazy caches if needed. Keep path handling OS-agnostic by continuing to use `ProjectFile` and existing analyzer APIs.
