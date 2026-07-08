# Fix Scala Renamed Member Imports and Extension Methods

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agents/PLANS.md`.

## Purpose / Big Picture

After this change, users of the Scala analyzer can go to definition and find usages through two Scala constructs that are currently missed. A renamed member import such as `import ConsoleRenderer.{default => renderer}` should make `renderer` resolve to `ConsoleRenderer.default`. A Scala 3 extension method such as `extension (value: String) def slug` inside object `Syntax` should be indexed as `Syntax.slug`, and calls like `"Hello World".slug` should resolve to that method when it is uniquely visible. The behavior is proven with focused get-definition and find-usages tests.

## Progress

- [x] (2026-07-01 20:10Z) Read `.agents/PLANS.md` and created this living plan.
- [x] (2026-07-01 20:10Z) Inspected `src/analyzer/usages/scala_graph/inverted.rs`, `resolver.rs`, `extractor.rs`, `syntax.rs`, `src/analyzer/scala/declarations.rs`, and Scala import parsing.
- [x] (2026-07-01 20:18Z) Discovered exact tree-sitter-scala node kinds for Scala 3 extension definitions and calls.
- [x] (2026-07-01 20:34Z) Implemented declaration indexing for extension methods.
- [x] (2026-07-01 20:34Z) Implemented shared renamed member import resolution for goto and usage graph.
- [x] (2026-07-01 20:34Z) Implemented extension call fallback with receiver-type gating when possible and unique-candidate behavior when not.
- [x] (2026-07-01 20:34Z) Added focused tests for issues #420 and #421.
- [x] (2026-07-01 20:43Z) Ran requested Rust tests, `cargo fmt`, and `cargo clippy-no-cuda`.

## Surprises & Discoveries

- Observation: Scala import parsing already recognizes grouped aliases and both alias spellings.
  Evidence: `parse_scala_import_infos` converts `import A.{b => c}` to raw snippet `import A.b as c` with `identifier = c`, and `scala_import_path` strips either ` as ` or ` => `.
- Observation: The Scala 3 extension snippet parses as an `extension_definition` inside the enclosing object's `template_body`.
  Evidence: A temporary ignored parser test printed `extension_definition parameters: (parameters (parameter name: (identifier) type: (type_identifier))) body: (function_definition name: (identifier) ...)`; the call `"Hello World".slug` parsed as `field_expression value: (string) field: (identifier)`.
- Observation: Template-body imports were not included in `ScalaAnalyzer.import_info_of`, so object-local imports were invisible to the per-file resolver.
  Evidence: The renamed import goto test initially returned `no_indexed_definition` for `renderer` until `import_declaration` handling was added to `process_template_body`.
- Observation: Extension signatures are stored in the analyzer signature table, not necessarily in `CodeUnit::signature()`.
  Evidence: `scala_extension_method_call_resolves_to_extension_definition` returned `unsupported_scala_receiver` until `ProjectTypes` and `TargetSpec` consulted `scala.signatures(unit)`.

## Decision Log

- Decision: Keep the fix in the existing Scala graph and get-definition paths instead of adding text-search fallbacks.
  Rationale: The repository rules prohibit using source-text mini parsers as a substitute for tree-sitter or analyzer structures. The existing `ImportInfo`, declaration index, and field-expression AST nodes carry the relevant information.
  Date/Author: 2026-07-01 / Codex.
- Decision: Store extension receiver context in the generated signature label as `extension (...) def ...`.
  Rationale: The declaration model does not have a custom extension metadata slot. The signature label is analyzer-owned data already consumed by resolver code for arity, so it can also preserve receiver type text without changing declaration identity.
  Date/Author: 2026-07-01 / Codex.
- Decision: Treat `extension_definition` as a transparent declaration container under the surrounding object/class.
  Rationale: Scala extension methods are called as members but are declared inside an owner object/class; indexing inner `def`s as `Owner.method` matches the target FQN expected by goto and usages.
  Date/Author: 2026-07-01 / Codex.

## Outcomes & Retrospective

Implemented the requested behavior and tests. Focused validation passed for `BIFROST_SEMANTIC_INDEX=off cargo test --test usages_scala_graph_test` and `BIFROST_SEMANTIC_INDEX=off cargo test --test get_definition_test`. The full requested validation command, `cargo fmt`, and `cargo clippy-no-cuda` all passed.

## Context and Orientation

The Scala analyzer indexes declarations in `src/analyzer/scala/declarations.rs`. It produces `CodeUnit` entries for classes, objects, traits, enums, methods, and fields. Scala usage resolution has a graph-oriented find-usages implementation in `src/analyzer/usages/scala_graph/`. `inverted.rs` builds whole-workspace caller-to-callee edges and owns `NameResolver`, a per-file map from visible names to fully qualified names. `resolver.rs` owns `TargetSpec` and `Visibility`, used by the scanner in `extractor.rs` to decide whether a syntax node is a usage of a requested target. Goto definition for Scala is in `src/analyzer/usages/get_definition/scala.rs` and reuses `ScalaNameResolver` and `ScalaProjectTypes` exported from the graph module.

A fully qualified name, or FQN, is the analyzer's stable name for a declaration, such as `app.Syntax$.slug` for method `slug` in object `Syntax`. A wildcard import is an import that exposes all eligible names from a package or object, such as `import Syntax.*`. A direct member import is an import of one member, possibly renamed, such as `import ConsoleRenderer.{default => renderer}`.

## Plan of Work

The parser discovery is complete: `extension_definition` has `parameters` and `body` fields; its `body` is either a direct `function_definition` / `function_declaration` or a block containing definitions. Update `src/analyzer/scala/declarations.rs` so an extension definition inside a template body contributes its inner `function_definition` declarations as members of the enclosing object or class.

Next, extend `ProjectTypes` and `NameResolver` in `src/analyzer/usages/scala_graph/inverted.rs` so import paths whose prefix resolves to an object or type can bind member aliases to the member FQN. This must cover both renamed and plain member imports. The same resolver is exported to get-definition, so direct identifier lookup can use it.

Then update find-usages `Visibility` in `src/analyzer/usages/scala_graph/resolver.rs` and scanning in `extractor.rs` so direct renamed member imports count ordinary identifier references but import-line mentions are classified as import hits, not external usage hits. Extension methods should be visible through direct member imports or wildcard object imports, with collision handling for same-name wildcard extensions.

Finally, add tests in `tests/get_definition_test.rs` and `tests/usages_scala_graph_test.rs`, run the requested validation commands, and update this plan with results.

## Concrete Steps

Run commands from `/home/jonathan/Projects/bifrost`.

Use `cargo test` for focused tests while developing, then run:

    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_scala_graph_test --test usage_graph_scala_test --test get_definition_test --test metals_goto_definition --test metals_find_references --test intellij_scala_goto_definition --test scala_analyzer_test --test cross_language_import_hits
    cargo fmt
    cargo clippy-no-cuda

## Validation and Acceptance

Acceptance requires `renderer` in the renamed import scenario to go to `ConsoleRenderer.default`, find-usages of `ConsoleRenderer.default` to include real `renderer` expression sites but not count the import line as an external usage, `Syntax.slug` to be indexed and resolved from `"Hello World".slug`, and two visible same-name extensions to produce no wrong usage hit. The commands in `Concrete Steps` should pass.

## Idempotence and Recovery

All edits are normal source and test changes under the repository root. Re-running tests and formatters is safe. The worktree already contains an unrelated untracked native-library backup; leave it untouched.

## Artifacts and Notes

Artifacts will be filled in with concise parser and test evidence as work proceeds.

Parser evidence captured from `cargo test --test scala_analyzer_test dump_scala_extension_tree_for_issue_421 -- --ignored --nocapture` before removing the temporary test:

    (compilation_unit (object_definition name: (identifier) body: (template_body (extension_definition parameters: (parameters (parameter name: (identifier) type: (type_identifier))) body: (function_definition name: (identifier) return_type: (type_identifier) body: (field_expression value: (identifier) field: (identifier)))))) (object_definition name: (identifier) body: (template_body (import_declaration path: (identifier) (namespace_wildcard)) (val_definition pattern: (identifier) value: (field_expression value: (string) field: (identifier))))))

Focused validation:

    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_scala_graph_test
    test result: ok. 25 passed; 0 failed

    BIFROST_SEMANTIC_INDEX=off cargo test --test get_definition_test
    test result: ok. 334 passed; 0 failed

Full requested validation:

    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_scala_graph_test --test usage_graph_scala_test --test get_definition_test --test metals_goto_definition --test metals_find_references --test intellij_scala_goto_definition --test scala_analyzer_test --test cross_language_import_hits
    result: passed

    cargo fmt
    result: passed

    cargo clippy-no-cuda
    result: passed

## Interfaces and Dependencies

No new external dependencies are planned. The implementation uses existing tree-sitter-scala parsing, `ImportInfo`, `CodeUnit`, `ProjectTypes`, `NameResolver`, `TargetSpec`, `Visibility`, and `LocalInferenceEngine`.

Revision note, 2026-07-01 / Codex: Initial plan created to satisfy the repository ExecPlan requirement for a multi-file analyzer change.

Revision note, 2026-07-01 / Codex: Added tree-sitter-scala extension node evidence so the declaration and usage changes are grounded in observed AST shapes.

Revision note, 2026-07-01 / Codex: Updated progress, decisions, discoveries, and focused validation after implementing the Scala renamed import and extension method fixes.

Revision note, 2026-07-01 / Codex: Recorded final validation results after the requested test suite, formatter, and clippy all passed.
