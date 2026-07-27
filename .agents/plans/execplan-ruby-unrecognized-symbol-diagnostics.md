# Add high-confidence Ruby unrecognized-symbol diagnostics

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

After this change, an editor with `unrecognizedSymbolDiagnostics` enabled reports a Ruby error only when Bifrost can prove that a constant path has no indexed project-local definition. For example, a clean Ruby file containing `Billing::Missing` will identify `Missing` as an unresolved Ruby constant. The same feature stays silent for method calls, dynamic lookups, `autoload`, and Rails/Zeitwerk projects because those forms can legally provide names outside Bifrost's closed project-local index.

## Progress

- [x] (2026-07-27 07:30Z) Inspected issue #365, the clean issue branch, the existing LSP gate, Ruby import support, and Ruby constant resolver.
- [x] (2026-07-27 07:42Z) Created this ExecPlan and selected a constant-only, analyzer-owned collector.
- [x] (2026-07-27 08:18Z) Added the Ruby collector, analyzer hook, bounded explicit-require closure, and project-local-only resolver path.
- [x] (2026-07-27 08:28Z) Added analyzer regressions, LSP opt-in coverage, and LSP documentation.
- [ ] Run focused and repository Rust validation, then update this plan with evidence.

## Surprises & Discoveries

- Observation: The LSP handler already suppresses semantic diagnostics when a document has parser errors and invokes the language analyzer only when the opt-in is enabled.
  Evidence: `src/lsp/handlers/diagnostic.rs` calls `semantic_diagnostics` only after its parse-error list is empty.
- Observation: Ruby navigation already computes the transitive project-local `require` closure and resolves constant paths against that closure, explicit `autoload` targets, and the indexed declarations.
  Evidence: `RubySemanticIndex::visible_files_from` and `RubySemanticIndex::resolve_constant` in `src/analyzer/usages/ruby_graph/resolver.rs`.
- Observation: Zeitwerk consumers deliberately see a broad convention-derived visibility set for navigation.
  Evidence: `RubyAnalyzer::zeitwerk_visible_files_for` in `src/analyzer/ruby/imports.rs` returns all Zeitwerk autoload files for consumer files. That is useful best-effort navigation but is not proof of absence for diagnostics.
- Observation: The navigation resolver's autoload lookup can initialize a workspace-wide autoload index.
  Evidence: `RubySemanticIndex::resolve_constant` calls `RubyAnalyzer::autoload_visible_files_for_constant`, whose backing index scans project files in `src/analyzer/ruby/imports.rs`.
- Observation: Ruby dynamic definition can affect constant availability through `eval`, `const_missing`, and dynamic method definitions, including in a transitive required file.
  Evidence: Adversarial review fixtures cover `eval`, `define_method`, and `define_singleton_method` defining `const_missing`.

## Decision Log

- Decision: Keep the new pass inside the Ruby analyzer and reuse the existing `SemanticDiagnostic` to LSP conversion.
  Rationale: Ruby confidence rules rely on Ruby AST nodes, project-local import edges, and Ruby visibility facts. The LSP layer should remain language-neutral.
  Date/Author: 2026-07-27 / Codex.
- Decision: Diagnose only explicit `scope_resolution` paths with an indexed project-local module owner that has no inheritance or mixin lookup edge; never diagnose bare constants, methods, or members.
  Rationale: Bare constant lookup can resolve Ruby core constants or ancestors that this slice does not model exhaustively. Explicit module paths preserve a small, defensible positive surface.
  Date/Author: 2026-07-27 / Codex.
- Decision: Treat any known dynamic convention (`autoload`, Zeitwerk, unresolved/dynamic loading, dynamic evaluation or constant lookup, `const_missing`, or malformed syntax) in the bounded require closure as a reason to suppress rather than a reason to infer absence.
  Rationale: The issue prioritizes false-positive avoidance and LSP latency over coverage.
  Date/Author: 2026-07-27 / Codex.
- Decision: Cap diagnostic require closures at 64 files and 2 MiB of parsed source, and resolve via a no-autoload variant of the structured resolver.
  Rationale: The LSP invokes diagnostics while editing. The navigation-oriented autoload index and unbounded dependency parsing are not suitable for that hot path.
  Date/Author: 2026-07-27 / Codex.

## Outcomes & Retrospective

Implementation is complete pending Rust validation. The collector is intentionally more conservative than Ruby navigation: it uses explicit project-local requires only, avoids the workspace-wide autoload index, and fails closed across dynamic runtime boundaries or bounded-resource limits. No LSP server protocol work was required.

## Context and Orientation

`src/lsp/handlers/diagnostic.rs` is the shared LSP bridge. It reads an open document, emits parser diagnostics when syntax is malformed, and otherwise asks the active `IAnalyzer` for `SemanticDiagnostic` values when the existing runtime option is true. `MultiAnalyzer` delegates that hook to the language selected for the file, so Ruby needs only to override the existing default-empty method in `IAnalyzer`.

Ruby implementation code is in `src/analyzer/ruby`. `RubyAnalyzer` wraps the generic tree-sitter analyzer and owns caches for supported `require` paths, explicit `autoload` calls, and Zeitwerk conventions. Its structured import analysis is in `src/analyzer/ruby/imports.rs`. `src/analyzer/usages/ruby_graph/resolver.rs` defines `RubySemanticIndex`; its `visible_files_from` method follows supported `require_relative` and project-local `require` edges, and `resolve_constant` resolves AST-derived constant paths only when an indexed declaration is visible.

A semantic diagnostic is a crate-internal value with a byte range, source, stable code, and message. The existing LSP bridge turns it into an editor error. A `scope_resolution` is tree-sitter Ruby's structured node for a namespace expression such as `A::B`; use its `scope` and `name` fields instead of splitting source text. A constant reference is a capitalized Ruby name node or a namespace path; it is distinct from an identifier method call, a symbol, or a string.

## Plan of Work

Create `src/analyzer/ruby/diagnostics.rs`. Define a Ruby-specific diagnostic record plus stable code `ruby_unrecognized_symbol` and source `bifrost-ruby`. Its collector must first reject files over a bounded size, sources that fail tree-sitter parsing, and files whose project conventions make absence unknowable. It must use an iterative AST walk and shared AST helpers, never regex or string splitting.

The collector will build `RubySemanticIndex` once, compute a bounded project-local explicit-require closure once, and consider only reference-shaped `scope_resolution` nodes. It must ignore declaration names, assignment targets, the arguments to `autoload`, symbols, strings, `const_get` and other dynamic constant lookup calls, and all `identifier` method-call nodes. For an eligible explicit path, call the project-local no-autoload resolver. Emit the terminal constant token only when it cannot resolve and the path is not protected by a dynamic escape hatch. Do not make navigation less permissive: this new collector is intentionally stricter than definition lookup.

Update `src/analyzer/ruby/mod.rs` to declare the module, import the shared `SemanticDiagnostic` type, and implement `RubyAnalyzer::semantic_diagnostics` by mapping collector results. If the collector needs a visibility predicate unavailable outside `imports.rs` or the resolver, expose one small crate-visible structured helper; do not duplicate the require/autoload parser or edit generic LSP code.

Write analyzer tests beside the collector using `InlineTestProject`. Cover an unknown explicit constant path, a same-file namespace constant, direct and transitive `require_relative`, supported root-relative `require`, explicit `autoload`, a Zeitwerk-like Gemfile plus `app/` convention, `const_get`, symbols, declarations, bare method calls, and malformed Ruby. Assertions must prove both the exact diagnostic code/range when emitted and no diagnostics when confidence is incomplete.

Extend `tests/bifrost_lsp_server.rs` with Ruby pull-diagnostic coverage using the existing test server. The positive case must enable `unrecognizedSymbolDiagnostics` and assert the code, source, message, and terminal constant range. The negative case must prove an uncertain dynamic/zeitwerk file produces no Ruby semantic diagnostic. Update `docs/src/content/docs/lsp.md` to say Ruby currently diagnoses only high-confidence project-local constant paths and deliberately defers method/member diagnostics.

## Concrete Steps

From `/Users/dave/.codex/worktrees/e040/bifrost`:

    cargo test --test ruby_semantic_diagnostics
    cargo test --test bifrost_lsp_server ruby_semantic_diagnostics --features nlp,python
    cargo fmt
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    git diff --check

The first command must exercise collector unit tests. The LSP command must show the Ruby positive and suppression cases passing. `cargo fmt`, clippy, and `git diff --check` must complete without changes, warnings, or whitespace errors.

## Validation and Acceptance

With `unrecognizedSymbolDiagnostics` enabled, a clean Ruby document containing an unresolved explicit path such as `Billing::Missing` must publish one error with source `bifrost-ruby`, code `ruby_unrecognized_symbol`, and a range that selects `Missing`, not the entire expression. A declaration from a supported required project file must produce no error.

No Ruby semantic diagnostic may be emitted for a method call, symbol, string, bare constant, `const_get`, `eval`, dynamic `const_missing`, explicit `autoload`, Zeitwerk/Rails-style project, malformed file, or any file where the collector cannot close the visible project-local namespace within its file/source bounds. Existing syntax diagnostics and Ruby navigation behavior must remain unchanged.

## Idempotence and Recovery

All changes are additive source, tests, and documentation. Re-running the tests is safe. If a fixture exposes an uncertain Ruby form, make the collector more conservative and add that fixture as a permanent suppression regression; do not add text-search fallbacks or infer runtime names from source strings.

## Artifacts and Notes

Before implementation, the relevant evidence is:

    src/lsp/handlers/diagnostic.rs: semantic diagnostics run only after parse diagnostics are empty.
    src/analyzer/usages/ruby_graph/resolver.rs: visible_files_from follows supported project-local requires.
    src/analyzer/ruby/imports.rs: explicit autoload and Zeitwerk conventions are already recognized structurally.

## Interfaces and Dependencies

In `src/analyzer/ruby/diagnostics.rs`, define an analyzer-local record analogous to the existing Go/Python collectors and expose:

    pub(crate) const RUBY_UNRECOGNIZED_SYMBOL: &str = "ruby_unrecognized_symbol";
    pub(crate) const RUBY_SEMANTIC_DIAGNOSTIC_SOURCE: &str = "bifrost-ruby";

    pub(crate) fn collect_ruby_semantic_diagnostics(
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        source: &str,
    ) -> Vec<RubySemanticDiagnostic>

`RubyAnalyzer::semantic_diagnostics` must map those values into `crate::analyzer::SemanticDiagnostic`. The implementation may depend on the existing Ruby parser, `RubySemanticIndex`, project-local import facilities, `InlineTestProject`, and the current LSP test harness. It must not run Ruby, index gems, add dependencies, or alter the `IAnalyzer` or LSP protocol interfaces.

## Revision Notes

- 2026-07-27: Initial plan created from issue #365 diagnosis before implementation. It records the constant-only confidence boundary and existing structured Ruby resolution facilities.
- 2026-07-27: Review tightened the implementation: bare constants were deferred, all `autoload` uses became suppression boundaries, dynamic evaluation/`const_missing` definition suppression was added, and the diagnostic closure now has file/source budgets without the navigation autoload index.
