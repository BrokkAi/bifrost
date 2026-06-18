# Add On-Demand get_definition for Usage References

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan follows `.agent/PLANS.md` in this repository. It is self-contained so a future contributor can resume the work from this file and the current working tree alone.

## Purpose / Big Picture

Bifrost currently exposes `scan_usages`, which answers "where is this definition used?", and `usage_graph`, which builds a whole-workspace caller-to-callee graph. Editor and agent workflows also need the opposite narrow operation: given a reference in a source file, resolve the workspace definition it names.

This work adds a `get_definition` searchtools/MCP tool for that on-demand lookup. The tool must not build the whole `usage_graph` for a single reference. It should inspect the queried source location, reuse the same language-specific import and reference-resolution machinery that powers usage analysis, and return definition metadata or a precise terminal state such as `no_definition`, `unresolvable_import_boundary`, or `unsupported_language`.

## Progress

- [x] (2026-06-17T21:55Z) Confirmed the worktree is on branch `193-add-on-demand-get_definition-for-usage-references` tracking `origin/193-add-on-demand-get_definition-for-usage-references`.
- [x] (2026-06-17T21:55Z) Ran `git fetch`; `origin/master` and the feature branch both point at `dc75b81`.
- [x] (2026-06-17T21:56Z) Ran `git rebase`; Git reported the current branch is up to date.
- [x] (2026-06-17T22:00Z) Created this living ExecPlan before code edits.
- [x] (2026-06-17T22:25Z) Added the public `get_definition` schema, MCP descriptor, service dispatch, registry exposure, baseline diagnostics, and focused service-level tests.
- [x] (2026-06-17T22:25Z) Added the shared on-demand lookup driver and initial Rust reference resolution.
- [x] (2026-06-17T22:25Z) Added initial JS/TS reference resolution.
- [x] (2026-06-17T22:25Z) Added initial Go reference resolution.
- [x] (2026-06-17T22:25Z) Ran `cargo test --test get_definition_test`; all 7 tests passed.
- [x] (2026-06-17T22:35Z) Attempted the requested guided-review step; specialist reviewer agents were not exposed in this session, so performed a local guided-review-style diff review and fixed one concrete Rust boundary bug before final validation.
- [x] (2026-06-17T22:40Z) Ran `cargo test --test searchtools_service`; 39 passed, 1 ignored.
- [x] (2026-06-17T22:40Z) Ran `cargo test --test bifrost_mcp_server`; all 13 tests passed.
- [x] (2026-06-17T22:43Z) Ran `cargo fmt`; it completed cleanly.
- [x] (2026-06-17T22:45Z) Ran `cargo test mcp_registry`; the 5 relevant registry unit tests passed and Cargo enumerated the remaining filtered targets successfully.
- [x] (2026-06-17T22:47Z) Ran `cargo clippy --all-targets --all-features -- -D warnings`; it completed cleanly after fixing a `clippy::ptr_arg` warning.
- [x] (2026-06-17T22:48Z) Ran `git diff --check`; it completed cleanly.
- [x] (2026-06-18T18:10Z) Recorded pre-benchmark-slice worktree status: `## 193-add-on-demand-get_definition-for-usage-references...origin/193-add-on-demand-get_definition-for-usage-references` with the initial `get_definition` implementation still uncommitted.
- [x] (2026-06-18T18:12Z) Re-ran focused validation for the existing tool slice before checkpointing: `cargo test --test get_definition_test`, `cargo test --test searchtools_service`, and `cargo test --test bifrost_mcp_server` all passed.
- [x] (2026-06-18T18:15Z) Checkpoint-committed the existing tool implementation as `accc688 Add on-demand get_definition tool`.
- [x] (2026-06-18T18:16Z) Ran `git fetch` and `git rebase`; Git reported the current branch is up to date.
- [x] (2026-06-18T19:26Z) Added `get_definition` as a first-class benchmark scenario with per-query expected status and optional expected FQN assertions.
- [x] (2026-06-18T19:26Z) Added one checked-in `get_definition` benchmark query for each target repo/language and documented manually inspected results in `benchmark/get_definition_observations.md`.
- [x] (2026-06-18T19:26Z) Ran `cargo test --test benchmark_manifest`, `cargo test --test bifrost_benchmark_run`, and `cargo run --bin bifrost_benchmark -- validate --manifest benchmark/targets.toml`; all passed.
- [x] (2026-06-18T19:26Z) Smoke-ran `get_definition` coverage through `bifrost_benchmark run --repo <name> --max-files 80` for all ten benchmark repos; all scenario entries passed after tightening supported-language FQN assertions.
- [x] (2026-06-18T19:33Z) Ran a guided-review-style multi-agent review over the benchmark-slice diff. Review findings were fixed by adding per-repo manifest coverage assertions, pinning definition-query files in subset mode, adding successful and failing FQN assertion tests, and moving JS/Rust benchmark probes from declarations to real references.
- [x] (2026-06-18T19:34Z) Re-ran `cargo test --test benchmark_manifest`, `cargo test --test bifrost_benchmark_run`, `cargo run --bin bifrost_benchmark -- validate --manifest benchmark/targets.toml`, and focused `express-js` / `serde-json-rs` smoke runs after review fixes; all passed.
- [x] (2026-06-18T19:52Z) Added Java `get_definition` support for resolvable type references, static imports, same-owner bare method calls, and explicit Java import-boundary diagnostics.
- [x] (2026-06-18T19:52Z) Added focused Java tests covering imported type resolution, static import resolution, external import boundaries, and local-value `no_definition`.
- [x] (2026-06-18T19:52Z) Updated the Java benchmark probe from `unsupported_language` to a resolved `com.google.gson.TypeAdapter` reference and smoke-ran `google-gson --max-files 80`; the `get_definition` scenario passed.
- [x] (2026-06-18T20:05Z) Ran a guided-review-style multi-agent review over the Java slice. Review findings were fixed by adding typed local/field/parameter receiver inference, `this`/`super` member resolution, and workspace-wildcard import classification that returns `no_definition` instead of an external-boundary diagnostic.
- [x] (2026-06-18T20:08Z) Added Java regression tests for typed receiver methods, `this` field access, and workspace wildcard missing-type behavior.
- [x] (2026-06-18T20:12Z) Re-ran `cargo test --test get_definition_test`, `cargo test --test bifrost_benchmark_run`, `cargo run --bin bifrost_benchmark -- validate --manifest benchmark/targets.toml`, `cargo run --bin bifrost_benchmark -- run --manifest benchmark/targets.toml --repo google-gson --max-files 80`, `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, and `git diff --check`; all passed.
- [x] (2026-06-18T20:38Z) Added PHP `get_definition` support for namespaced type references, function aliases, constants, static member references, `$this` member references, typed local/parameter receiver calls, and external namespace boundary diagnostics.
- [x] (2026-06-18T20:38Z) Updated the FastRoute benchmark probe from `unsupported_language` to a resolved `FastRoute.RouteCollector.addRoute` `$this->addRoute(...)` reference and recorded the manual observation plus typed-property follow-up.
- [x] (2026-06-18T20:44Z) Ran the requested guided review checkpoint over the uncommitted PHP slice with parallel reviewer agents. Review findings were fixed by reusing PHP qualified-name candidate text, resolving `parent::member` through a proven declared parent instead of the current class, narrowing PHP helper visibility to `crate::analyzer::usages`, and requiring exact indexed namespaces before downgrading missing PHP definitions from `unresolvable_import_boundary` to `no_definition`.
- [x] (2026-06-18T20:50Z) Added PHP regression tests for fully qualified type lookups from the final segment, `parent::run()` selecting the parent definition, prefix-only external imports reporting `unresolvable_import_boundary`, imported types, function aliases, typed receivers, external imports, and local values.
- [x] (2026-06-18T20:54Z) Re-ran `cargo test --test get_definition_test`, `cargo test --test bifrost_benchmark_run`, `cargo run --bin bifrost_benchmark -- validate --manifest benchmark/targets.toml`, `cargo run --bin bifrost_benchmark -- run --manifest benchmark/targets.toml --repo fastroute-php --max-files 80`, `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, and `git diff --check`; all passed.
- [x] (2026-06-18T21:18Z) Added Python `get_definition` support for same-file references, named imports, namespace imports, plain dotted imports, typed parameter receivers, inherited receiver methods, `self`/`cls` receivers, local-shadow `no_definition`, and external package boundary diagnostics.
- [x] (2026-06-18T21:18Z) Updated the Click benchmark probe from `unsupported_language` to a resolved same-file `_complete_visible_commands` reference and documented the `Command.main` overload ambiguity as follow-up.
- [x] (2026-06-18T21:27Z) Ran the requested guided review checkpoint over the uncommitted Python slice with parallel reviewer agents. Review findings were fixed by preserving the original focus token range for AST classification, preventing object-side attribute clicks from resolving to the member, resolving plain dotted imports such as `import pkg.util`, disabling broad workspace fallback for typed receiver annotations, and checking ancestor methods for typed receiver calls.
- [x] (2026-06-18T21:34Z) Added Python regression tests for object-side namespace lookups, plain dotted imports, inherited receiver methods, unimported receiver annotations, named imports, namespace imports, typed receivers, external imports, and local values.
- [x] (2026-06-18T21:38Z) Re-ran `cargo test --test get_definition_test`, `cargo test --test bifrost_benchmark_run`, `cargo run --bin bifrost_benchmark -- validate --manifest benchmark/targets.toml`, `cargo run --bin bifrost_benchmark -- run --manifest benchmark/targets.toml --repo click-py --max-files 80`, `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, and `git diff --check`; all passed.
- [x] (2026-06-18T09:05Z) Added C# `get_definition` support for visible type references, typed receiver methods, `this`/`base` members, same-owner unqualified member calls, ambiguous visible type candidates, local-shadow `no_definition`, and alias/static/namespace using boundary diagnostics.
- [x] (2026-06-18T09:05Z) Updated the Dapper benchmark probe from `unsupported_language` to a resolved `Dapper.SqlMapper$CacheInfo` nested type reference and documented the manual result in `benchmark/get_definition_observations.md`.
- [x] (2026-06-18T09:05Z) Ran the requested guided review checkpoint over the uncommitted C# slice with parallel reviewer agents. Review findings were fixed by adding scoped local-binding inference for on-demand lookup, preventing delegate parameters and local functions from resolving as class methods, reporting alias/static external usings as `unresolvable_import_boundary`, and preserving ambiguous visible type candidates instead of collapsing them to `no_definition`.
- [x] (2026-06-18T09:05Z) Added C# regression tests for imported types, typed receivers, `this` members, external namespace/alias/static usings, ambiguous type imports, delegate/local-function shadows, and local values.
- [x] (2026-06-18T09:05Z) Re-ran `cargo test --test get_definition_test`, `cargo run --bin bifrost_benchmark -- validate --manifest benchmark/targets.toml`, `cargo run --bin bifrost_benchmark -- run --manifest benchmark/targets.toml --repo dapper-csharp --max-files 80`, `cargo test --test bifrost_benchmark_run`, `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, and `git diff --check`; all passed.
- [x] (2026-06-18T09:20Z) Added C++ `get_definition` support for include-visible type references, relative namespace-qualified free function calls, typed receiver methods, `this` receivers, `auto x = new Type()` receiver inference, local-value `no_definition`, and conservative unresolved include-boundary diagnostics.
- [x] (2026-06-18T09:20Z) Updated the fmt benchmark probe from `unsupported_language` to a resolved `detail.vformat_to` call reference at `include/fmt/base.h:2798:11`, and documented the manual result in `benchmark/get_definition_observations.md`.
- [x] (2026-06-18T09:20Z) Ran the requested guided review checkpoint over the uncommitted C++ slice with parallel reviewer agents. Review findings were fixed by preventing declaration sites from resolving as references, restricting type fallback to classes/type aliases, requiring lexical-namespace proof for relative qualified calls, adding `auto new` receiver inference, and avoiding broad boundary diagnostics for unqualified typos in files with angle includes.
- [x] (2026-06-18T09:20Z) Added C++ regression tests for include-visible types, typed receiver calls, relative namespace calls, declaration-site clicks, same-named function/type confusion, wrong-namespace qualified calls, `auto new` receivers, unresolved external includes, unqualified typos with angle includes, and local values.
- [x] (2026-06-18T09:20Z) Re-ran `cargo test --test get_definition_test`, `cargo run --bin bifrost_benchmark -- validate --manifest benchmark/targets.toml`, `cargo run --bin bifrost_benchmark -- run --manifest benchmark/targets.toml --repo fmt-cpp --max-files 80`, `cargo test --test bifrost_benchmark_run`, `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, and `git diff --check`; all passed.
- [x] (2026-06-18T09:31Z) Added Scala `get_definition` support for same-package type references, companion-object `apply` calls, typed receiver methods, local-value `no_definition`, and direct external import-boundary diagnostics.
- [x] (2026-06-18T09:31Z) Updated the scala-xml benchmark probe from `unsupported_language` to a resolved `scala.xml.Elem$.apply` companion-object call at `shared/src/main/scala/scala/xml/Elem.scala:107:13`, and documented the manual result in `benchmark/get_definition_observations.md`.
- [x] (2026-06-18T09:31Z) Ran the requested guided review checkpoint over the uncommitted Scala slice with parallel reviewer agents. Review findings were fixed by preferring enclosing members over same-name visible objects for ordinary unqualified calls, preserving companion `apply` lookup for owner self-name constructor-style calls, classifying external constructor/function calls as `unresolvable_import_boundary`, honoring uppercase local term shadowing, and adding source-token symbol-filter coverage.
- [x] (2026-06-18T09:31Z) Added Scala regression tests for same-package types, companion `apply`, source-token symbol filtering and mismatch diagnostics, member-vs-object precedence, typed receivers, external constructor/function/type boundaries, uppercase local shadowing, and local values.
- [x] (2026-06-18T09:31Z) Re-ran `cargo test --test get_definition_test`, `cargo test --test bifrost_benchmark_run`, `cargo run --bin bifrost_benchmark -- validate --manifest benchmark/targets.toml`, `cargo run --bin bifrost_benchmark -- run --manifest benchmark/targets.toml --repo scala-xml --max-files 80`, `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, and `git diff --check`; all passed.

## Surprises & Discoveries

- Observation: The worktree was not detached when implementation began; it was already on the issue branch.
  Evidence: `git status --short --branch` printed `## 193-add-on-demand-get_definition-for-usage-references...origin/193-add-on-demand-get_definition-for-usage-references`.

- Observation: This Rust worktree has no Gradle wrapper, so the Brokk Gradle quality commands in the user-level instructions do not apply here.
  Evidence: prior repository inspection found no `./gradlew` in this worktree; final validation will use Rust commands.

- Observation: The specialist reviewer agent interface required by `brokk:brokk-guided-review` was not exposed by tool discovery in this session.
  Evidence: `tool_search` for reviewer agents returned GitHub connector tools rather than an Agent/subagent tool. A local guided-review-style pass over the uncommitted diff was performed instead.

- Observation: A Rust external-looking reference must be classified as an import boundary before using fallback symbol search.
  Evidence: local review found that `serde::Serialize::serialize` could otherwise resolve to an unrelated workspace symbol named `serialize`; `resolve_rust` now returns `unresolvable_import_boundary` before the global analyzer search for scoped external-looking references.

- Observation: The inline Rust analyzer indexes a helper in `util.rs` as `format_value`, not `util.format_value`.
  Evidence: `cargo test --test get_definition_test` returned definition metadata with `fqn: "format_value"` and `path: "util.rs"` for the named-import lookup.

- Observation: The benchmark compare path already treats added candidate scenarios as `NewCandidate`, so the blessed Ubuntu baseline does not need to be updated in this slice.
  Evidence: `BenchmarkCompareReport::from_reports` indexes baseline and candidate scenario keys separately and reports `(None, Some(candidate))` as `ScenarioCompareOutcome::NewCandidate` with `is_regression: false`.

- Observation: Express property-assigned methods such as `app.listen` are not resolved by the current JavaScript `get_definition` implementation.
  Evidence: a direct call against the pinned Express subset for `lib/application.js:598` returned `no_definition` for `app.listen`; the final benchmark smoke probe uses the real `tryRender` call at `lib/application.js:574`, which resolves to the same-file function declaration.

- Observation: Benchmark subset mode must pin `definition_queries.path`, not just `summary_targets` and `seed_file_paths`.
  Evidence: guided review noted that future definition probes outside existing summary/seed files could otherwise become `not_found` only in `--max-files` runs; `src/benchmark/subset_workspace.rs` now includes definition-query paths and the subset test uses a separate `E.java` query file.

- Observation: The benchmark smoke probes are stronger when supported-language entries target real reference sites, not declaration sites.
  Evidence: guided review flagged the initial Express `app` and Rust `to_value` declaration probes; the checked-in manifest now uses Express `tryRender` at a call site and Rust `Value::Number` at a match arm reference.

- Observation: Java comment references should not be used as benchmark `get_definition` probes.
  Evidence: the original Gson `fromJson` row pointed at a Javadoc example and returned `no_definition` with a `block_comment` diagnostic once Java support was enabled. The benchmark now uses the production `TypeAdapter` type reference in `Gson.getAdapter`.

- Observation: Java member resolution needs local type inference for simple named receivers to avoid under-reporting valid workspace member references.
  Evidence: guided review found that `target.run()` and `target.field` would return `no_definition` unless the receiver itself was a type literal; `java_typed_receiver_method_resolves_to_definition` now covers a parameter-typed receiver.

- Observation: Java wildcard imports should only report `unresolvable_import_boundary` when the imported package is absent from the indexed workspace.
  Evidence: guided review found `import pkg.*; MissingType` was over-classified as an external boundary even when package `pkg` exists locally; `java_workspace_wildcard_missing_type_returns_no_definition` now locks this down as `no_definition`.

- Observation: PHP line/column lookup on a fully qualified name can land on the terminal `name` node rather than the wrapping `qualified_name`.
  Evidence: guided review reproduced `\App\Service` returning `unsupported_php_reference_shape` before the fix; `php_fully_qualified_type_resolves_from_final_segment` now covers this path and `get_definition` reuses the existing PHP `qualified_candidate_text` behavior.

- Observation: PHP `parent::member` must not be treated like `self::member`.
  Evidence: guided review found a false positive where `parent::run()` could resolve to the child override. The resolver now inspects the enclosing class declaration's parent type and `php_parent_static_call_resolves_to_parent_definition` locks the expected parent target.

- Observation: PHP namespace-boundary classification needs exact indexed namespaces, not descendant-prefix matches.
  Evidence: guided review found that an indexed `Vendor.Package.Controller` namespace could mask a missing imported `Vendor.Package.Service`; `php_prefix_only_external_import_reports_boundary` now keeps that as `unresolvable_import_boundary`.

- Observation: FastRoute's original `$this->dataGenerator->addRoute(...)` line needs typed-property receiver inference that the PHP slice does not yet implement.
  Evidence: manual direct calls showed the same-class `$this->addRoute(...)` probe resolves accurately while property-promotion receiver chains remain `no_definition`; the benchmark observation documents this as follow-up rather than using it as the smoke query.

- Observation: Python location fidelity needs both the normalized reference range and the original focus token range.
  Evidence: guided review found that clicking `util` in `util.helper()` would otherwise classify the full attribute and jump to `helper`; `ResolvedReferenceSite` now keeps internal focus bytes and `python_attribute_object_resolves_to_namespace_not_member` covers object-side lookup.

- Observation: Python receiver annotations must not fall back to arbitrary same-named classes elsewhere in the workspace.
  Evidence: guided review flagged the inverted graph's explicit avoidance of broad workspace fallback; `python_unimported_receiver_annotation_returns_no_definition` now prevents unimported `Service` annotations from resolving to unrelated workspace classes.

- Observation: Python typed receiver methods need ancestor lookup for inherited members.
  Evidence: guided review found `Child` receiver calls to `Base.run` would miss inherited definitions; `python_typed_receiver_inherited_method_resolves_to_base_definition` now covers the hierarchy path.

- Observation: Click's `Command.main` is not a good benchmark smoke target for a unique resolved FQN because overload declarations and the implementation all share the same FQN.
  Evidence: direct `get_definition` against `self.main` returned `ambiguous` with three `click.core.Command.main` candidates; the benchmark uses `_complete_visible_commands` instead and documents overload disambiguation as follow-up.

- Observation: Dapper's `CacheInfo` benchmark reference resolves across partial class files.
  Evidence: the checked-in benchmark probe at `Dapper/SqlMapper.cs:1862:28` returns `Dapper.SqlMapper$CacheInfo` with the definition in `Dapper/SqlMapper.CacheInfo.cs:10..18`.

- Observation: C# unqualified invocation lookup must account for local value and local-function shadows before falling back to the enclosing class.
  Evidence: guided review found that delegate parameters and local functions named `Run` could otherwise make `Run()` falsely resolve to `App.Run`; `csharp_delegate_parameter_shadow_returns_no_definition` and `csharp_local_function_shadow_returns_no_definition` now cover those cases.

- Observation: `CSharpAnalyzer::resolve_visible_type` intentionally hides ambiguous visible type candidates, which is not sufficient for `get_definition`.
  Evidence: guided review found `using A; using B; Service service;` would return `no_definition`; `get_definition` now uses `visible_type_candidates` and `csharp_ambiguous_using_type_returns_ambiguous` locks down the `ambiguous` status.

- Observation: C# alias and static usings need explicit boundary handling.
  Evidence: guided review found `using Svc = External.Service;` and `using static External.Helpers;` could fall through to `no_definition`; the resolver now reports `unresolvable_import_boundary` for those external import forms.

- Observation: fmt's benchmark C++ probe resolves a call through an included implementation file.
  Evidence: `include/fmt/base.h:2798:11` on `detail::vformat_to(...)` returns `detail.vformat_to` at `include/fmt/format-inl.h:1467..1474`, and the `fmt-cpp --max-files 80` benchmark run passes with the expected FQN.

- Observation: C++ declaration-site filtering must inspect both the original focused node and the promoted reference shape.
  Evidence: guided review found out-of-line definitions such as `void Service::run() {}` could otherwise promote to `Service::run` and resolve as a reference; `cpp_out_of_line_definition_name_is_not_reference` now locks this down.

- Observation: C++ relative qualified lookup cannot use a raw suffix match.
  Evidence: guided review found global-scope `detail::helper()` could falsely resolve to `ns::detail::helper`; `cpp_qualified_call_does_not_cross_unrelated_namespace` now requires lexical namespace context for that relative match.

- Observation: C++ unresolved include-boundary diagnostics should not be based solely on the presence of an angle include for every unresolved name.
  Evidence: guided review found `#include <vector>` plus `typo();` would be over-classified as `unresolvable_import_boundary`; `cpp_unqualified_typo_with_angle_include_returns_no_definition` keeps ordinary local misses as `no_definition`.

- Observation: C++ out-of-line method lookups may legitimately return declaration and definition candidates with the same FQN.
  Evidence: `cpp_typed_receiver_method_resolves_to_definition` returns `ambiguous` for `ns.Service.run` when both `target.h` and `target.cpp` contain indexed candidates; this is documented as a follow-up for body/signature preference rather than hidden.

- Observation: Scala owner self-name calls inside a class can look like ordinary unqualified method calls but should still be allowed to resolve through a same-package companion object's `apply`.
  Evidence: the scala-xml benchmark call `Elem(...)` inside `class Elem` initially resolved to a constructor-like `scala.xml.Elem.Elem` candidate after the member-precedence review fix. The resolver now skips owner self-name member precedence so the benchmark returns `scala.xml.Elem$.apply` while a distinct same-name method such as `Controller.Factory()` still wins over `object Factory.apply`.

- Observation: Scala source-token symbol filtering is needed for companion `apply` targets.
  Evidence: the benchmark query carries `symbol = "Elem"` while the target definition FQN is `scala.xml.Elem$.apply`. Focused tests now preserve the resolved candidate when the source token matches the requested symbol and still report `symbol_filter_mismatch` for unrelated symbols.

## Decision Log

- Decision: Treat unresolved dependency/library/module boundaries as a first-class terminal state, separate from `no_definition`.
  Rationale: Bifrost performs partial-program analysis. A reference that crosses into an external crate, package, or module not present in the workspace is different from a local symbol that simply has no indexed definition.
  Date/Author: 2026-06-17 / Codex

- Decision: Keep `get_definition` separate from `usage_graph` edge aggregation.
  Rationale: `usage_graph` intentionally drops or aggregates references for graph centrality, while `get_definition` needs source-location fidelity, ambiguity reporting, and diagnostics for one queried reference site.
  Date/Author: 2026-06-17 / Codex

- Decision: Support Rust, JavaScript/TypeScript, and Go first; return `unsupported_language` for Java, C#, C++, PHP, Scala, Python, and unknown files in this issue.
  Rationale: Issue #193 names Rust, JS/TS, and Go as the initial languages with reusable inverted resolver paths. The analyzer-backed languages should wait until their adapters settle instead of forcing a broad generic resolved-reference event model.
  Date/Author: 2026-06-17 / Codex

- Decision: Make `get_definition` a required benchmark scenario but keep unsupported-language probes as `unsupported_language` assertions.
  Rationale: This catches regressions in the tool's public status contract across every benchmark target language without pretending unimplemented language resolvers are accurate.
  Date/Author: 2026-06-18 / Codex

- Decision: Land Java as the next full-language-support slice after the initial Rust/JS/TS/Go implementation.
  Rationale: Java has mature analyzer import/type-resolution APIs and a benchmark target that can assert a real resolved workspace FQN immediately.
  Date/Author: 2026-06-18 / Codex

- Decision: Land PHP after Java with conservative support for the same reference forms already handled by the PHP inverted usage graph.
  Rationale: PHP already had reusable namespace/use-alias resolution and local receiver inference primitives. The on-demand path can now return accurate metadata for common workspace PHP references while explicitly documenting unsupported property receiver chains as a follow-up gap.
  Date/Author: 2026-06-18 / Codex

- Decision: Land Python after PHP with conservative support for import-bound, same-file, and typed-receiver reference forms.
  Rationale: Python's analyzer already exposes import binders, module declarations, scope facts, and hierarchy providers. The on-demand path can reuse those pieces for common editor lookups while keeping unresolved packages and local shadowing distinct from indexed definitions.
  Date/Author: 2026-06-18 / Codex

- Decision: Land C# after Python with conservative support for analyzer-visible types and the member forms already supported by the C# usage graph.
  Rationale: C# has mature indexed declarations, visible-type resolution, local binding inference, and type hierarchy support. The on-demand path can now resolve common workspace C# references while keeping overload/signature-sensitive member disambiguation as a documented follow-up.
  Date/Author: 2026-06-18 / Codex

- Decision: Land C++ after C# with include-visibility and lexical-namespace safeguards.
  Rationale: The C++ usage graph already has include-closure visibility and local receiver inference primitives. The on-demand path can reuse those semantics for common workspace C++ references while staying conservative about declaration sites, unrelated namespace suffixes, unqualified typos, and declaration/definition ambiguity.
  Date/Author: 2026-06-18 / Codex

- Decision: Land Scala after C++ with conservative support for analyzer-visible package/type, companion `apply`, and typed receiver forms.
  Rationale: Scala has enough indexed declarations, import analysis, and graph-local inference to cover useful benchmark and workspace lookups, but overloaded methods, inherited receiver members, and signature-sensitive disambiguation should remain documented follow-up work rather than being guessed in the on-demand path.
  Date/Author: 2026-06-18 / Codex

## Outcomes & Retrospective

The first implementation is complete for issue #193's initial language scope. `get_definition` is now a public searchtools/MCP tool with one result per query, explicit terminal statuses, definition metadata rendered from indexed `CodeUnit`s, and focused coverage for Rust, TypeScript, Go, unsupported languages, `no_definition`, and external import boundaries.

The implementation is intentionally conservative. It resolves definitions when analyzer state or straightforward import parsing proves the target, and otherwise reports `no_definition`, `unresolvable_import_boundary`, or `unsupported_language` instead of guessing. Future work can deepen language-specific precision by extracting more helpers from the existing inverted graph scanners without changing the public response shape.

## Context and Orientation

The repository root is `/Users/dave/.codex/worktrees/53b1/bifrost`. Searchtools public request and response types live in `src/searchtools.rs`. Runtime tool dispatch lives in `src/searchtools_service.rs`. MCP descriptors live in `src/mcp_core.rs`, and mode-specific tool allowlists live in `src/mcp_registry.rs`.

The existing usage-resolution subsystem lives under `src/analyzer/usages/`. The relevant starting points are:

- Rust: `src/analyzer/usages/rust_graph/inverted.rs` walks Rust references and resolves bare and scoped names through `RustAnalyzer::reference_context_of(file)`.
- JS/TS: `src/analyzer/usages/js_ts_graph/resolver.rs` builds `JsTsProjectGraph`, including parsed files, import binders, export indices, and module-resolution edges.
- Go: `src/analyzer/usages/go_graph/resolver.rs` builds `GoProjectGraph`, including parsed files, package names, imports, and workspace module resolution.
- `src/analyzer/usages/inverted_edges.rs` owns graph-only edge accounting. It should remain graph-only.

A "reference site" in this plan means the source token or qualified expression named by the user's query location, such as `format_value` in Rust, `util.formatValue` in TypeScript, or `pkg.Symbol` in Go. A "definition candidate" means an indexed `CodeUnit` from the analyzer, rendered with fully qualified name, file path, source line range, kind, signature, and language.

## Plan of Work

First, add the public tool schema and baseline service wiring. `GetDefinitionParams` contains `references` and `include_tests`. Each `DefinitionReferenceQuery` contains a project-relative `path`, optional line/column, optional byte range, and optional `symbol` disambiguator. `GetDefinitionResult` returns one `DefinitionLookupResult` per input query in the original order. Each result includes the input, normalized reference location if available, extracted reference text if available, a `status` string, zero or more definition candidates, and structured diagnostics. Baseline statuses are `resolved`, `no_definition`, `unresolvable_import_boundary`, `ambiguous`, `unsupported_language`, `invalid_location`, and `not_found`.

Next, add an on-demand resolver module under `src/analyzer/usages/`. It should expose one batch function used by `searchtools::get_definition`. The driver should resolve query paths through the project, reject excluded test files when `include_tests` is false, normalize byte or line/column inputs to a byte range, extract the token at the query point, group work by language and file, and dispatch only to supported languages.

Then implement Rust support. Reuse `RustAnalyzer::reference_context_of(file)` to resolve bare and scoped references without building `usage_graph`. For external crate paths such as `serde::Serialize` when no workspace definition is available, return `unresolvable_import_boundary`. For valid local variables, parameters, literals, or unsupported receiver method forms, return `no_definition` or a diagnostic that describes the unsupported shape.

Then implement JS/TS support. Reuse `JsTsProjectGraph` and import/export indices for the queried file's language. Preserve file-scoped identity when the same exported name exists in multiple files. Relative imports and path aliases that resolve to workspace files can produce candidates; bare packages, unresolved aliases, and external modules return `unresolvable_import_boundary`. Local variables and values without indexed declarations return `no_definition`.

Then implement Go support. Reuse `GoProjectGraph` over workspace Go files, including package-name and import resolution. Same-package references, import aliases, dot imports, and selectors should resolve when the existing graph machinery supports them. Imports outside the workspace module return `unresolvable_import_boundary`; valid but non-indexed references return `no_definition`.

After each implementation slice, run `brokk:brokk-guided-review` on the intended uncommitted diff for that slice, queue and apply relevant findings, and re-run focused validation before continuing. If the review tooling is unavailable in this environment, record that in `Surprises & Discoveries`, run a local adversarial self-review against the uncommitted diff, and continue.

## Concrete Steps

Work from the repository root:

    cd /Users/dave/.codex/worktrees/53b1/bifrost

Branch setup evidence:

    git status --short --branch
    ## 193-add-on-demand-get_definition-for-usage-references...origin/193-add-on-demand-get_definition-for-usage-references

    git fetch

    git rebase
    Current branch 193-add-on-demand-get_definition-for-usage-references is up to date.

For the API skeleton slice, edit:

- `src/searchtools.rs` for request/response structs and `get_definition`.
- `src/searchtools_service.rs` for dispatch.
- `src/mcp_core.rs` for the tool descriptor.
- `src/mcp_registry.rs` and MCP tests for accepted tool lists.
- `tests/searchtools_service.rs` and `tests/bifrost_mcp_server.rs` for baseline behavior.

For the resolver slices, edit `src/analyzer/usages/` and add focused tests using `tests/common/inline_project.rs`.

## Validation and Acceptance

The API skeleton is accepted when:

- `get_definition` appears in the MCP symbol/searchtools tool list.
- Empty, invalid, unsupported-language, `no_definition`, and `unresolvable_import_boundary` cases return structured per-query results rather than panics.
- Existing `scan_usages` and `usage_graph` schemas are unchanged.

The Rust slice is accepted when focused tests show named imports, namespace imports, same-file references, associated/static references, shadowing, external crate boundaries, and local no-definition cases.

The JS/TS slice is accepted when focused tests show named imports, namespace imports, same-file declarations, duplicate export names across files, ambiguous exports, package import boundaries, unresolved path aliases, and local no-definition cases.

The Go slice is accepted when focused tests show package selectors, import aliases, dot imports, same-package references, supported local receiver inference, outside-module import boundaries, and valid non-indexed no-definition cases.

Final validation should run:

    cargo fmt
    cargo test --test searchtools_service
    cargo test --test bifrost_mcp_server
    cargo test --test get_definition
    cargo clippy --all-targets --all-features -- -D warnings
    git diff --check

If `cargo clippy --all-targets --all-features -- -D warnings` is too slow for the active iteration, run focused tests first and only run clippy after code editing is complete.

## Idempotence and Recovery

The tool is additive. Re-running tests and formatters is safe. If an implementation slice becomes too broad, stop at the last passing focused test, update `Progress` and `Surprises & Discoveries`, and keep unsupported languages returning explicit diagnostics rather than partial behavior.

If a guided review flags a finding outside the active uncommitted slice, verify whether it is pre-existing or stale-base noise before widening scope. The intended review target between milestones is the current slice diff plus this ExecPlan when it changed, not the full branch history unless explicitly requested.

## Artifacts and Notes

Validation evidence:

    cargo test --test get_definition_test
    test result: ok. 7 passed; 0 failed

    cargo test --test searchtools_service
    test result: ok. 39 passed; 0 failed; 1 ignored

    cargo test --test bifrost_mcp_server
    test result: ok. 13 passed; 0 failed

    cargo test mcp_registry
    test result: ok. 5 passed; 0 failed

    cargo clippy --all-targets --all-features -- -D warnings
    Finished `dev` profile

    git diff --check
    no output
