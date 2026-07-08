# Ruby autoload and module-function resolution fixes

This ExecPlan is a living document. It follows `.agents/PLANS.md` and must keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current while work proceeds.

## Purpose / Big Picture

Ruby users should be able to navigate and find references through two common Ruby idioms: `autoload :Const, "path"` and module/class singleton methods declared with `class << self` or `module_function`. After this change, get-definition on an autoload symbol resolves to the constant declaration, cross-file constant paths can see autoloaded files, class-receiver calls find `class << self` declarations, and `module_function` methods are indexed for `Module.method` dispatch.

## Progress

- [x] (2026-07-01 15:25Z) Read the Ruby declaration visitor, Ruby usage graph, Ruby get-definition resolver, import helper, and existing Ruby tests.
- [x] (2026-07-01 15:43Z) Add structural autoload constant-symbol recognition and autoload-aware constant visibility.
- [x] (2026-07-01 15:46Z) Add module-function singleton classification and ensure class-receiver usage scans cover `class << self`.
- [x] (2026-07-01 15:48Z) Add focused tests in `tests/get_definition_test.rs` and `tests/usages_ruby_test.rs`.
- [x] (2026-07-01 15:53Z) Run the requested Ruby test set, `cargo fmt`, and `cargo clippy-no-cuda`.

## Surprises & Discoveries

- Observation: `autoload` calls are already emitted as generic Ruby imports, but `resolve_required_file` only follows `require` and `require_relative`, so the data never reaches visibility.
  Evidence: `src/analyzer/ruby/declarations.rs` sends `"autoload"` through `parse_ruby_require_call`; `src/analyzer/ruby/imports.rs` ignores it in `resolve_required_file`.
- Observation: `class << self` is recognized by `is_singleton_method_declaration`, but the usage scan can still miss it if declaration matching and receiver lookup diverge.
  Evidence: `src/analyzer/usages/ruby_graph.rs` has parent-walk singleton detection and separate class-receiver lookup filtering.
- Observation: Bare `module_function` is parsed as an `identifier`, while argument forms are represented as calls.
  Evidence: The initial implementation only looked for a `call` node and the new `ruby_get_definition_resolves_module_function_class_receiver_call` test failed with `Ruby method tax_rate did not resolve to an indexed definition`; handling the identifier shape made it pass.

## Decision Log

- Decision: Treat `autoload :Const, "path"` as a narrow visibility edge for the named constant rather than making every declaration in the autoloaded file visible for all lookups.
  Rationale: This matches Ruby autoload semantics and avoids widening unrelated constant resolution.
  Date/Author: 2026-07-01 / Codex.
- Decision: Model `module_function` in the shared singleton-method predicate, scoped to the enclosing module body.
  Rationale: Bare `module_function` changes subsequent `def` declarations in that lexical body; the final implementation records this in `is_singleton_method_declaration`, which is the shared predicate used by both get-definition and usage lookup to decide whether `Owner.method` is a class/singleton dispatch target.
  Date/Author: 2026-07-01 / Codex.

## Outcomes & Retrospective

Implemented both requested Ruby fixes without committing. `autoload :Const, "path"` now contributes an exact constant-to-file visibility edge, and its first symbol argument is treated as a constant reference in get-definition and usage scanning. Bare `module_function` now marks later module methods as singleton/class-receiver methods for lookup, and explicit `module_function :name` is supported by the same structural scanner when it appears before the method. The `class << self` class-receiver usage case is covered by a regression test and resolves through the existing singleton method detector.

## Context and Orientation

The relevant implementation files are `src/analyzer/ruby/declarations.rs`, which walks tree-sitter Ruby ASTs and emits `CodeUnit` declarations; `src/analyzer/ruby/imports.rs`, which turns Ruby require-like calls into file visibility; `src/analyzer/usages/ruby_graph.rs`, which resolves Ruby references during find-usages; and `src/analyzer/usages/get_definition/ruby.rs`, which resolves a single editor reference to declarations. Ruby type and constant `CodeUnit` short names join nested constants with `$`, while methods use `Owner.method`.

## Plan of Work

First, add helpers that structurally recognize an autoload call's first symbol argument and derive its constant name without string scanning. Use that in get-definition and usage scanning so `:Discount` behaves like a constant reference under the current lexical stack. Extend the Ruby semantic index to discover autoload edges from parsed import info, resolve the autoload path as a project require target, and include the autoloaded file only when the constant candidate matches the autoloaded constant.

Second, thread module-function state through the Ruby declaration visitor. When a bare `module_function` appears in a module body, subsequent ordinary `def` nodes in that body should be indexed like singleton methods for class-receiver lookup. Keep ordinary instance definitions available only where existing behavior expects them if tests show it is needed. Also verify and, if necessary, adjust class-receiver matching for `class << self` declarations.

Finally, add regression tests for both issues and run the requested verification commands from `/home/jonathan/Projects/bifrost`.

## Validation and Acceptance

Run:

    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_ruby_test --test get_definition_test --test ruby_lsp_goto_definition --test ruby_lsp_find_references
    cargo fmt
    cargo clippy-no-cuda

Acceptance is that all commands complete successfully and the new tests fail before the implementation but pass after it.

Validation results from 2026-07-01:

    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_ruby_test --test get_definition_test --test ruby_lsp_goto_definition --test ruby_lsp_find_references
    Result: passed. get_definition_test: 332 passed. ruby_lsp_find_references: 2 passed. ruby_lsp_goto_definition: 4 passed. usages_ruby_test: 37 passed.

    cargo fmt
    Result: passed.

    cargo clippy-no-cuda
    Result: passed.

## Idempotence and Recovery

All edits are ordinary source and test changes. Re-running tests and formatting is safe. The existing untracked backup file `bifrost_searchtools/_native.abi3.so.bak-stale-0014` is unrelated and should remain untouched.

## Artifacts and Notes

Artifacts will be added after implementation and validation.

New regression tests:

    tests/get_definition_test.rs:
    ruby_get_definition_resolves_autoload_symbol_to_constant
    ruby_get_definition_resolves_cross_file_autoload_constant_path
    ruby_get_definition_resolves_module_function_class_receiver_call

    tests/usages_ruby_test.rs:
    resolves_autoload_symbol_and_cross_file_constant_usages
    resolves_class_receiver_calls_to_singleton_class_methods
    resolves_module_function_class_receiver_usages

## Interfaces and Dependencies

Use tree-sitter `Node` fields and named children for Ruby call parsing. Do not use regexes or delimiter splitting to parse Ruby syntax. Reuse `parse_ruby_tree`, `extract_name_path`, `symbol_or_string_value`, and `RubySemanticIndex::resolve_constant` where possible.
