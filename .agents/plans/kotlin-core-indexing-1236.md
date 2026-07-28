# Kotlin: parsing, declarations, signatures, and persisted indexing (#1236)

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document must be maintained in accordance with `.agents/PLANS.md` (repository root relative path), the canonical rules for ExecPlans.

Tracking issue: https://github.com/BrokkAi/bifrost/issues/1236 (child of epic #1234).

## Purpose / Big Picture

Bifrost is a code-intelligence engine: it parses source files with tree-sitter grammars, extracts a language-neutral model of declarations (`CodeUnit`s: classes, functions, fields, modules), and serves search, summaries, skeletons, and navigation over that model, with results persisted in a SQLite blob store so re-opening a workspace is incremental instead of a full re-parse.

Today Bifrost has no Kotlin analyzer. A pinned production Kotlin tree-sitter grammar was vendored by issue #1235 (commit `f9dbcb4c`) under `vendor/tree-sitter-kotlin/`, exposed to Rust as `crate::analyzer::kotlin::language::LANGUAGE`, but nothing consumes it: `.kt` files are invisible to indexing, search, and every product surface.

After this change, Kotlin is a real analyzer language: a workspace containing `.kt` (and `.kts`) files gets them detected, parsed, and indexed; `get_definitions("com.example.Foo.bar")` returns the Kotlin function; summaries/skeletons render Kotlin signatures; edits re-index incrementally; and a reopened workspace restores Kotlin state from the persisted store without re-parsing unchanged files. Sibling issues own the later tiers: #1237 (packages/imports/hierarchy/JVM artifacts), #1238 (navigation), #1239 (usage graphs), #1240 (RQL), #1241 (CFG), #1242 (data-flow), #1243 (diagnostics/quality), #1244 (product/benchmarks). This plan must leave those capabilities explicitly unsupported rather than half-wired.

## Progress

- [x] (2026-07-28 15:20Z) Explored architecture: `LanguageAdapter`/`TreeSitterAnalyzer` framework, Scala/Ruby precedents, epoch persistence, workspace routing.
- [x] (2026-07-28 15:40Z) ExecPlan written.
- [x] (2026-07-28 16:30Z) M1: `Language::Kotlin` variant added; compiler-driven sweep of 23 exhaustive-match sites complete; parser + epoch registered; crate compiles with `cargo check --all-targets --all-features`.
- [x] (2026-07-28 17:10Z) M2+M3 (interleaved): `src/analyzer/kotlin/{declarations,adapter,mod}.rs` extraction + analyzer, wired through delegate/workspace/multi-analyzer with the explicit-unsupported semantics provider; 10 module tests pass.
- [x] (2026-07-28 17:50Z) M4: 18 behavior tests in `tests/kotlin_analyzer_test.rs` (declaration forms, duplicate-name owners, constructors, `.kts` limits, skeletons, incremental updates, mixed-language via InlineTestProject); 3 persistence tests (warm hydration without reparse, dirty-file delta, Kotlin-scoped epoch bump leaving Java warm); capability-parity expectations updated.
- [ ] Validation: `cargo fmt` done; isolated clippy `-D warnings` and full `--features nlp` gate running (completed: targeted kotlin/persistence/parity suites green; remaining: full-suite result).

## Surprises & Discoveries

- Observation: `LanguageAdapter::query_directory()` and `file_extension()` are declared by the trait but never consumed anywhere in the codebase (queries are hand-written Rust tree walks; file routing uses `Language::extensions()`).
  Evidence: `grep -rn "query_directory()" src/` only hits the trait declaration site.
- Observation: The `.scm` files under `resources/treesitter/kotlin/` (highlights, tags) are upstream reference queries retained by #1245, not analyzer inputs. The epoch's `EMBEDDED_QUERIES` list only needs entries for files the analyzer actually depends on; Kotlin has none yet, so its epoch rests on the grammar fingerprint + salt.
- Observation: `structural_search_providers()` on `TreeSitterAnalyzer` self-gates on `adapter.structural_spec()`, and the default `structural_spec()` consults `structural_spec_for(language)`; returning `None` for Kotlin cleanly defers RQL to #1240 with no extra code.
- Observation: `AnalyzerDelegate::program_semantics_provider()` is infallible (returns `&dyn ProgramSemanticsProvider` for every variant), so Kotlin cannot simply opt out; it needs a manual trait impl that reports `SemanticOutcome::Unsupported` until #1241.
- Observation: the fwcd grammar wraps an `object` expression body (`val x = object : T {}`) in `object_literal`, distinct from `object_declaration`, which keeps anonymous objects out of the declaration walk for free.
- Observation: `enum_entry` bodies (`enum_class_body > enum_entry > class_body`) can declare methods; these are owned by the entry Field unit's *class* parent in JVM terms, but source-structurally by the entry. Decision below.
- Observation: `InlineTestProject` needed no changes for Kotlin — language inference goes through `Language::from_extension`, so registering `kt`/`kts` in `model.rs` was sufficient.
- Observation: `collect_parse_errors` walks named nodes, so error recovery that materializes only a *hidden* `MISSING _alpha_identifier` token (e.g. a dangling `when` arm) yields `has_error() == true` but an empty `ParseError` list. Kotlin recovery tests must use fixtures that produce a real `ERROR` node (a stray `]]]` run works) when they assert on `parse_errors`.
  Evidence: probe test printed `has_error=true collected=0` for the dangling-`when` fixture and `has_error=true collected=1` for the stray-bracket fixture.
- Observation: this machine has both a Homebrew Rust and rustup Rust of the same version; `cargo clippy` resolved Homebrew's `cargo-clippy` from PATH and produced E0514 mixed-compiler errors. Fix: prefix PATH with `~/.rustup/toolchains/1.96.0-aarch64-apple-darwin/bin` for clippy runs (via `scripts/with-isolated-cargo-target.sh`).
- Observation: the `python` cargo feature builds pyo3 with `extension-module`, which cannot link test binaries on macOS; CI's test gates use `--features nlp` (Linux and macOS), with the Python extension exercised by `scripts/test_python.sh`. The local full gate here is therefore `cargo test --features nlp`.

## Decision Log

- Decision: Register `.kt` and `.kts` as `Language::Kotlin` extensions and analyze both with the single Kotlin grammar (the vendored parser handles scripts; #1245 validated a `.kts` fixture).
  Rationale: The issue requires `.kts` to be "supported or explicitly capability-scoped"; parsing + top-level declaration indexing works identically, so support it, and scope the semantic limits (no script-receiver modeling, statement-level code is not a declaration) in tests + doc comments rather than refusing the extension.
  Date/Author: 2026-07-28 / Claude + dave.
- Decision: Kotlin FQ names are source-level: dotted package + simple type names + member names (`com.example.Outer.Inner.method`). No `FooKt` file facade classes, no `$` object encoding, no JVM binary names. Companion objects use their declared name, defaulting to `Companion` (`com.example.Owner.Companion.of`), with `SegmentKind::Companion` for the companion segment.
  Rationale: Acceptance criterion "Stable source identities do not depend on absolute paths or compiler-generated JVM names". Top-level functions/properties attach directly under the package (like Go/Python top-level units), which keeps identity stable under `@file:JvmName` and file renames.
  Date/Author: 2026-07-28 / Claude.
- Decision (revised during M2): companion segments use `SegmentKind::Type`, NOT `SegmentKind::Companion` as first planned — `Companion` is the *Scala* `$`-suffix rendering rule (`Foo$`), which would corrupt Kotlin's plain-dot `Owner.Companion` spelling and trip the FqName round-trip assertion.
  Rationale: `FqName::render` appends `$` to every `Companion`-kind segment; Kotlin has no such source spelling.
  Date/Author: 2026-07-28 / Claude.
- Decision (revised during M2): `typealias` maps to `CodeUnitType::Field` plus `mark_type_alias`, not `Class` as first planned.
  Rationale: Scala's `type` aliases already use Field + type-alias mark, and the summary/skeleton/lookup pipelines are built around that shape; diverging for Kotlin would split the alias handling paths.
  Date/Author: 2026-07-28 / Claude.
- Decision (revised during M4): all of a class's constructors — the synthetic primary unit and every secondary constructor — share one synthetic Function identity `Owner.Owner`, accumulating ranges and signatures like ordinary overloads.
  Rationale: `CodeUnit` equality includes the `synthetic` flag, so a non-synthetic secondary unit would split the constructor identity into two units under one FQ name; single-identity matches the overload model and the JVM view.
  Date/Author: 2026-07-28 / Claude.
- Decision: Declaration kind mapping — `class_declaration` (incl. `enum class`, `annotation class`, `data class`, `value class`, `interface`), `object_declaration`, `companion_object`, and `type_alias` map to `CodeUnitType::Class` (with `type_alias` also recorded in `ParsedFile::type_aliases`); `function_declaration`, `secondary_constructor`, and a synthetic unit for a parameterful `primary_constructor` map to `CodeUnitType::Function`; `property_declaration` and `class_parameter`s declared `val`/`var` map to `CodeUnitType::Field`; `enum_entry` maps to `CodeUnitType::Field` (Java enum-constant precedent) unless it has a body, in which case it still maps to Field and its body members are indexed under the enum class.
  Rationale: Matches the documented `CodeUnitType` contract in `src/analyzer/model.rs` and JVM sibling precedents (Java constants, Scala class parameters); keeps the enum lean per its doc comment.
  Date/Author: 2026-07-28 / Claude.
- Decision: Constructors are named after the class (Scala precedent): `com.example.Foo.Foo` — a synthetic Function unit for a `primary_constructor` with parameters, and non-synthetic Function units for `secondary_constructor`s.
  Rationale: Duplicate-name-owner acceptance criterion needs constructor identity distinct from the type; Scala's `Class.Class` shape already flows through summaries/lookup correctly.
  Date/Author: 2026-07-28 / Claude.
- Decision: Property accessors (`getter`/`setter` nodes inside `property_declaration`) do not become separate CodeUnits; the property is one Field whose signature includes accessor presence. Local functions, lambdas, and anonymous functions inside bodies are not indexed as declarations in this issue.
  Rationale: Accessors share the property's identity in source navigation; JVM `getX`/`setX` names are compiler-generated (excluded by acceptance criteria). Local callables belong with usage/CFG tiers; indexing them now would create identity churn for #1239/#1241. Tests document both boundaries explicitly.
  Date/Author: 2026-07-28 / Claude.
- Decision: Extension functions/properties index under their lexical owner (package or enclosing type), named by the function name, with the receiver type preserved in the signature text (`fun String.shout(): String`) — not under the receiver type.
  Rationale: The receiver may not resolve within this tier (navigation is #1238); lexical ownership is the stable source identity, and the signature keeps the receiver visible for summaries.
  Date/Author: 2026-07-28 / Claude.
- Decision: Imports in this tier are raw statements only (`ParsedFile::import_statements`); structured `ImportInfo` stays empty until #1237 models packages/imports.
  Rationale: Issue scope split; `import_statements` powers `import_statements()` display without committing to resolution semantics.
  Date/Author: 2026-07-28 / Claude.
- Decision: `KotlinAnalyzer` is a thin wrapper over `TreeSitterAnalyzer<KotlinAdapter>` (like the simpler analyzers), implementing `IAnalyzer` by delegation plus a Scala-style recursive skeleton renderer; no caches or JVM-external index yet.
  Rationale: The heavy Scala machinery serves capabilities owned by sibling issues; adding empty scaffolding now would be dead code.
  Date/Author: 2026-07-28 / Claude.
- Decision: `ProgramSemanticsProvider` for `KotlinAnalyzer` is implemented manually: `current_artifact_source` returns `Ok(None)` and `materialize` returns `SemanticOutcome::Unsupported { capability: Procedures }`.
  Rationale: The delegate contract requires a provider; explicit-unsupported is the epic's mandated boundary until #1241.
  Date/Author: 2026-07-28 / Claude.
- Decision: Kotlin epoch registered via `lang_epoch!(Kotlin, "kotlin", "treesitter/kotlin/", "<initial salt naming the vendored revision>")`, with the vendored grammar revision (`fwcd/tree-sitter-kotlin@c8ac3d2`) named in the salt.
  Rationale: The live grammar fingerprint does not include parser tables (same caveat as Scala's comment in `epoch.rs`); pinning the revision in the salt makes conflict-resolution-only grammar swaps invalidate persisted rows.
  Date/Author: 2026-07-28 / Claude.
- Decision (enum entry bodies): members declared inside an `enum_entry`'s `class_body` are indexed with the *enum class* as parent, not the entry.
  Rationale: The entry is a Field; Fields do not own children anywhere else in the model, and skeleton/summary rendering assumes class-like owners. The entry-body member remains reachable and correctly ranged; per-entry override semantics are dispatch concerns owned by later tiers.
  Date/Author: 2026-07-28 / Claude.

## Outcomes & Retrospective

(To be written at milestone completions and at the end.)

## Context and Orientation

Everything below names repository-relative paths.

Core framework: `src/analyzer/tree_sitter_analyzer.rs` defines `LanguageAdapter` (trait, ~line 307) and `TreeSitterAnalyzer<A: LanguageAdapter>` — the shared engine that enumerates project files by language, parses them, calls `adapter.parse_file(file, source, tree) -> ParsedFile`, persists per-file state (`FileState`) into the SQLite blob store, and serves `IAnalyzer` queries (declarations, definitions by FQ name, ranges, signatures, sources, incremental `update`). `ParsedFile` (~line 1100) is the per-file extraction result: `package_name`, `top_level_declarations`, `declarations`, `signatures`, `signature_metadata`, `ranges`, `children` (ownership), `import_statements`, `type_aliases`, etc., populated via helpers `add_code_unit`, `add_code_unit_with_range`, `add_signature`, `add_signature_with_metadata`, `set_type_alias`.

Model: `src/analyzer/model.rs` defines `Language` (enum + `ANALYZABLE` list + `config_label`/`extensions` registries), `CodeUnit` (`CodeUnit::new_fq(file, CodeUnitType, package_name, short_name, FqName)`), `CodeUnitType` (Class/Function/Field/Module/Macro/FileScope), `Range`, `SignatureMetadata`. `src/analyzer/fq_name.rs` provides interned structured names (`SegmentKind::{Package, Type, Companion, Member, ...}`).

Registries touched by a new language: `src/analyzer/mod.rs` (`parser_language_for_flavor`, `structural_spec_for`, re-exports), `src/analyzer/workspace.rs` (`build_delegate!` match, `analyzer()` match), `src/analyzer/multi_analyzer.rs` (`AnalyzerDelegate` enum + ~10 match methods), `src/analyzer/store/epoch.rs` (`epoch_for` match + `lang_epoch!`), `src/analyzer/common.rs`, plus every other exhaustive `match language` in the crate — the compiler enumerates them once the variant exists (that is the M1 method). Sites whose capability belongs to a sibling issue get an explicit conservative arm (e.g. Kotlin grouped with the `_ => {}`/default behavior), never a panic.

Grammar: `crate::analyzer::kotlin::language::LANGUAGE` (in `src/analyzer/kotlin/language.rs`, currently `#[cfg(test)]`-only module registration in `src/analyzer/mod.rs` — M1 makes the module unconditional). Key node kinds (from `vendor/tree-sitter-kotlin/src/node-types.json`): `source_file` → { `package_header` (child `identifier`), `import_list` → `import_header`s, declarations }. Declarations: `class_declaration` (children: `type_identifier` name, `modifiers`, `primary_constructor` → `class_parameter`s, `delegation_specifier`s, `class_body` | `enum_class_body`), `object_declaration`, `companion_object` (both: `type_identifier`?, `class_body`), `function_declaration` (field `receiver`, children: `simple_identifier` name, `function_value_parameters`, return type nodes, `function_body`), `property_declaration` (field `receiver`, children: `binding_pattern_kind` (val/var), `variable_declaration` (name+type) or `multi_variable_declaration`, optional `getter`/`setter`), `secondary_constructor` (`function_value_parameters`, `statements`), `type_alias` (`type_identifier`, aliased type), `enum_class_body` → `enum_entry` (name `simple_identifier`, optional `value_arguments`, optional `class_body`). `class_body` can also nest `class_declaration`, `object_declaration`, `companion_object`, `function_declaration`, `property_declaration`, `secondary_constructor`, `type_alias`, `getter`, `setter`, `anonymous_initializer`. The word "interface" is spelled inside `class_declaration` via its keyword token (check `child(0)`/keyword text), and `enum`/`annotation`/`data`/`sealed`/`value` appear as modifier/keyword tokens — signature text should come from the source header slice, not reconstructed keyword-by-keyword.

Precedents: `src/analyzer/scala/declarations.rs` (`parse_scala_file`, iterative visitor with explicit work stack — required by CLAUDE.md stack-safety rule), `src/analyzer/scala/adapter.rs` (adapter shape), `src/analyzer/scala/mod.rs` (analyzer wrapper + skeleton renderer), `src/analyzer/ruby/` and `src/analyzer/go/` (thinner analyzers).

Tests: `tests/common/inline_project.rs` (`InlineTestProject` — mandated harness for small inline multi-file tests), `tests/scala_analyzer_test.rs` / `tests/scala_skeleton_test.rs` (behavior-test style), `tests/analyzer_persistence.rs` (persisted store round-trip + epoch invalidation patterns), `tests/analyzer_capability_parity.rs` (per-language capability expectations), `tests/multi_analyzer_test.rs` (mixed-language routing).

Validation commands (workspace root): `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings` (expanded form — the `clippy-no-cuda` alias breaks in nested worktrees), `cargo test --features nlp,python --test kotlin_analyzer_test`, `cargo test --features nlp,python` for the full gate. Use `scripts/with-isolated-cargo-target.sh` for isolated builds if needed.

## Plan of Work

Milestone 1 (registration): Make the crate compile with `Language::Kotlin` existing everywhere. Add `Kotlin` to the `Language` enum (after `Ruby`), `ANALYZABLE`, `config_label` ("kotlin"), `extensions` (`["kt", "kts"]`) in `src/analyzer/model.rs`. Make `mod kotlin;` unconditional in `src/analyzer/mod.rs`; register the parser in `parser_language_for_flavor` (`Language::Kotlin => crate::analyzer::kotlin::language::LANGUAGE.into()`); return `None` from `structural_spec_for` for Kotlin (RQL is #1240). Register the epoch (`lang_epoch!` + `epoch_for` arm) in `src/analyzer/store/epoch.rs`. Then run `cargo check --all-targets --all-features` repeatedly and resolve every non-exhaustive `match`: core-indexing sites get real Kotlin behavior; sibling-issue sites get explicit conservative arms with the sibling issue number in a comment where non-obvious. Commit checkpoint.

Milestone 2+3 (extractor + analyzer; interleaved so tests can execute): Create `src/analyzer/kotlin/declarations.rs` with `parse_kotlin_file(file, source, tree) -> ParsedFile`: read `package_header` → dotted package name; collect `import_header` raw text into `import_statements`; iterative work-stack visitor over `source_file` and nested bodies producing CodeUnits per the Decision Log mapping, with signatures sliced from source headers (declaration start through the name/parameter/return-type header, excluding bodies), `SignatureMetadata` with parameter labels + `CallableArity` for callables, ranges from node byte/line spans, ownership via parent links, and recovery: on `ERROR` subtrees, still index recognizable declaration headers beneath them (walk into error nodes). Create `src/analyzer/kotlin/adapter.rs` (`KotlinAdapter: LanguageAdapter`: language Kotlin, `query_directory` "resources/treesitter/kotlin", `file_extension` "kt", `extract_call_receiver` dot-split like Scala's, `parse_file` → `parse_kotlin_file`, `callable_arity` from metadata). Create `KotlinAnalyzer` in `src/analyzer/kotlin/mod.rs` wrapping `TreeSitterAnalyzer<KotlinAdapter>` with `new/new_with_config/new_with_config_store_context/clone_with_project`, delegated `IAnalyzer`, Scala-style skeleton rendering (indent children, close classes with `}`), manual explicit-unsupported `ProgramSemanticsProvider`. Wire `AnalyzerDelegate::Kotlin` through every `multi_analyzer.rs` match (import/type-hierarchy/type-alias providers: type-alias yes via store flag; import + hierarchy `None` until #1237), `workspace.rs` `build_delegate!`/`analyzer()`. Commit checkpoint per coherent step.

Milestone 4 (tests): `tests/kotlin_analyzer_test.rs` using `InlineTestProject`: packages; top-level functions/properties; classes/interfaces/objects/companions (default + named); nested types; constructors (primary/secondary + duplicate-name owner assertions); methods; properties with accessors; enums (+ entries, + entry bodies); annotation classes; type aliases (`is_type_alias`); extension functions/properties; local-callable non-indexing documented; malformed-source recovery; `.kts` top-level declarations + script-statement scoping; skeleton/summary rendering; incremental `update` (edit changes declarations, unchanged identity stability). Persistence: extend `tests/analyzer_persistence.rs` with Kotlin round-trip (build persisted → reopen → identical declarations without re-parse) and epoch-invalidation, mixed-language (Kotlin+Java) coverage via `InlineTestProject`. Update `tests/analyzer_capability_parity.rs` expectations for Kotlin. Commit.

Validation: fmt + clippy + targeted suites + full `--features nlp,python` gate; fix regressions in other suites caused by the new variant (e.g. tests iterating `Language::ANALYZABLE`).

## Concrete Steps

All commands run at the repository worktree root.

    cargo check --all-targets --all-features        # M1 driver: lists every non-exhaustive match
    cargo test --features nlp,python --lib analyzer::kotlin    # M2 module tests
    cargo test --features nlp,python --test kotlin_analyzer_test
    cargo test --features nlp,python --test analyzer_persistence
    cargo test --features nlp,python --test analyzer_capability_parity
    cargo test --features nlp,python --test multi_analyzer_test
    cargo fmt
    cargo clippy --all-targets --all-features -- -D warnings
    cargo test --features nlp,python                # full gate

Expected: all suites pass; the new Kotlin tests fail before their milestone lands and pass after.

## Validation and Acceptance

Acceptance is behavioral, matching the issue:

1. Detection/indexing: an `InlineTestProject` with `a/b/Sample.kt` (`package a.b`, a class with members) yields `get_definitions("a.b.Sample")` → one Class unit; `top_level_declarations` for the file includes it; `analyzed_files()` contains the file.
2. Update: editing the inline file and calling `update` re-indexes only the changed file, and renamed declarations change identity while untouched ones keep theirs (assert FQ equality across generations).
3. Persistence: `WorkspaceAnalyzer::build_persisted` on a Kotlin fixture, drop, rebuild → declarations identical and re-parse counters/progress show hydration, not parsing (follow the existing pattern in `tests/analyzer_persistence.rs`); a salt/epoch change (simulated per existing tests) invalidates.
4. Identity stability: FQ names contain no absolute paths, no `Kt`-suffixed facade names, no `$` encodings; asserted directly in tests.
5. Declaration-form coverage and duplicate-name owners: two types in different packages with same short name, a method and a property with the same name in sibling owners, constructor-vs-class name — all resolvable to distinct units.
6. `.kts`: top-level `fun`/`val`/`class` in a script are indexed; loose statements are not declarations; documented limits in the test names/comments.

## Idempotence and Recovery

All edits are additive code changes on branch `dave/vendored-kotlin-grammar-ec41ea`; each milestone ends in a compiling, test-passing commit, so recovery is `git log` + resume from the last checkpoint. Persisted-store schema is untouched (Kotlin uses the existing per-language rows keyed by `config_label` + epoch); a wrong epoch salt during development only causes re-analysis, never corruption. Tests use temp dirs via `InlineTestProject` and never write into the repo.

## Artifacts and Notes

Key trait signatures the milestones must satisfy (abbreviated):

    impl LanguageAdapter for KotlinAdapter {
        fn language(&self) -> Language;            // Language::Kotlin
        fn query_directory(&self) -> &'static str; // "resources/treesitter/kotlin"
        fn file_extension(&self) -> &'static str;  // "kt"
        fn extract_call_receiver(&self, reference: &str) -> Option<String>;
        fn parse_file(&self, file: &ProjectFile, source: &str, tree: &Tree) -> ParsedFile;
    }

    pub struct KotlinAnalyzer { inner: TreeSitterAnalyzer<KotlinAdapter> }
    // + IAnalyzer by delegation, skeleton rendering, clone_with_project,
    //   new_with_config_store_context, manual ProgramSemanticsProvider (Unsupported).

## Interfaces and Dependencies

No new crate dependencies: the grammar is already vendored and compiled by `build.rs` (from #1245). New modules: `src/analyzer/kotlin/{mod,adapter,declarations}.rs` (`language.rs` exists). Public surface added to `src/analyzer/mod.rs`: `pub use kotlin::KotlinAnalyzer;`. Everything else is arms added to existing exhaustive matches and registries.

---

Revision note (2026-07-28, plan authoring): initial version, written after architecture exploration and before M1, capturing scope boundaries against sibling issues and the identity/`.kts` decisions up front, because those drive both the extractor design and the acceptance tests.

Revision note (2026-07-28, M1–M4): recorded the three mid-implementation decision revisions (companion segment kind, typealias unit kind, unified synthetic constructor identity) with their triggers, plus the parse-error-collection, toolchain-shadowing, and macOS `python`-feature discoveries. Milestone plan held otherwise; M2 and M3 landed together (as one commit) because the delegate wiring was needed for the extractor's integration harness to compile.
