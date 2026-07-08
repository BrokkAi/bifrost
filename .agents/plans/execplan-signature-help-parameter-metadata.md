# Add Structured SignatureHelp Parameter Metadata

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agents/PLANS.md` from the repository root. Any contributor who changes this work must update this file so it remains self-contained and accurate.

## Purpose / Big Picture

Bifrost already answers LSP `textDocument/signatureHelp` requests with a signature label and an active parameter index. Editors can show a better signature-help popup when each parameter has its own label range and when declaration documentation is attached to the signature. This plan adds structured parameter metadata to the analyzer layer so the LSP handler can return richer payloads without parsing displayed skeleton strings.

The first working slice is Java and TypeScript. A user can observe the change by running the LSP integration tests and seeing Java and TypeScript signature help include `parameters` arrays with label offsets plus `documentation` values.

## Progress

- [x] (2026-06-28 00:00Z) Planned slice 1 for Java and TypeScript plus follow-up language rollout.
- [x] (2026-06-28 00:00Z) Added this ExecPlan as the language rollout source of truth.
- [x] (2026-06-28 00:00Z) Added analyzer-owned signature metadata storage, trait access, and persisted payload support.
- [x] (2026-06-28 00:00Z) Populated Java signature metadata from Java parser declaration nodes.
- [x] (2026-06-28 00:00Z) Populated TypeScript signature metadata from TypeScript parser declaration nodes.
- [x] (2026-06-28 00:00Z) Returned signature parameter label offsets and docs from `textDocument/signatureHelp`.
- [x] (2026-06-28 00:00Z) Added LSP integration coverage for Java and TypeScript payload shape.
- [x] (2026-06-28 00:00Z) Ran focused tests, formatting, and clippy.
- [x] (2026-06-28 00:00Z) Populated JavaScript signature metadata for declarations, methods, variable-backed functions, and assignment-backed functions.
- [x] (2026-06-28 00:00Z) Added JavaScript LSP integration coverage for parameter offsets and JSDoc docs.
- [x] (2026-06-28 00:00Z) Addressed Milestone 2 guided-review findings for JavaScript default-call parameters, rest parameters, and singular arrow parameters.
- [x] (2026-06-28 00:00Z) Populated Go signature metadata for functions, methods, and interface methods.
- [x] (2026-06-28 00:00Z) Added Go LSP integration coverage for parameter offsets and Go doc comments.
- [x] (2026-06-28 00:00Z) Addressed Milestone 3 guided-review findings for Go method receiver collisions and anonymous variadic parameters.
- [x] (2026-06-28 00:00Z) Populated C# signature metadata for methods and constructors.
- [x] (2026-06-28 00:00Z) Added C# LSP integration coverage for parameter offsets and XML doc comments.
- [x] (2026-06-28 00:00Z) Populated C++ signature metadata for function declarations and definitions.
- [x] (2026-06-28 00:00Z) Added C++ LSP integration coverage for parameter offsets and block comments.
- [x] (2026-06-28 00:00Z) Addressed Milestone 4 guided-review findings for C++ unnamed parameters and multi-declarator declarations.
- [x] (2026-06-28 00:00Z) Populated Python signature metadata for function declarations.
- [x] (2026-06-28 00:00Z) Populated Rust signature metadata for function items and trait function signatures.
- [x] (2026-06-28 00:00Z) Populated PHP signature metadata for functions and methods.
- [x] (2026-06-28 00:00Z) Populated Scala signature metadata for functions and primary constructors.
- [x] (2026-06-28 00:00Z) Added Python, Rust, PHP, and Scala LSP integration coverage for parameter offsets and docs.
- [x] (2026-06-28 00:00Z) Addressed Milestone 5 review finding for Rust pattern parameters.

## Surprises & Discoveries

- Observation: SignatureHelp already resolves the callee with structured definition lookup and already computes `activeParameter`.
  Evidence: `src/lsp/handlers/signature_help.rs` calls `call_signature_context` and `resolve_definition_batch_with_source` before building `SignatureInformation`.

- Observation: Hover already has reusable doc-comment cleanup that strips Javadoc/JSDoc markers.
  Evidence: `src/lsp/handlers/util.rs` exposes `extract_leading_doc_comment`, and `src/lsp/handlers/hover.rs` uses it for hover markdown.

- Observation: Analyzer file state can be hydrated from persisted payloads, so signature metadata must be persisted or cached startup behavior would differ from fresh parse behavior.
  Evidence: `src/analyzer/persistence/payload.rs` serializes `FileState.signatures`, and `TreeSitterAnalyzer::signature_metadata` must be able to read metadata from the same state shape.

- Observation: Storing only parameter names made LSP offset recovery ambiguous when a parameter name also appeared earlier in the signature label.
  Evidence: The Java and TypeScript signatureHelp tests now use `sum(int sum, ...)` and `function combine(combine, ...)`; the returned ranges must slice to the parameter labels inside the parameter list, not the callable name.

- Observation: JavaScript parser support exposes function, method, variable-backed, and assignment-backed declarations through the same tree-sitter `parameters` field shape.
  Evidence: `src/analyzer/javascript/mod.rs` now collects labels from `identifier`, `assignment_pattern`, `rest_pattern`, `object_pattern`, and `array_pattern` parameter nodes without parsing rendered signature strings.

- Observation: JavaScript arrow functions can expose a singular `parameter` field, and default parameter values can contain nested calls whose `)` appears before later parameters.
  Evidence: Milestone 2 guided review found `value => value`, `left = factory(), right`, and `...rest` cases; the JavaScript metadata builder now anchors offset lookup to the exact rendered parameter segment from tree-sitter rather than the first closing parenthesis.

- Observation: Go doc comments use bare `//`, while the shared doc extractor intentionally rejects bare `//` by default to avoid noisy C-family false positives.
  Evidence: `leading_doc_comment_for_code_unit` now enables bare `//` extraction only when `language_for_file(candidate.source()) == Language::Go`, and unit tests keep the default extractor conservative.

- Observation: Go method signatures include a receiver parameter list before the callable parameter list, and those texts can be identical.
  Evidence: Milestone 3 guided review found `func (box Box) Use(box Box)` could anchor offsets to the receiver when using a first string match; Go metadata now derives the parameter-list offset from the tree-sitter `parameters` node byte position and has analyzer regressions for receiver collisions and anonymous `...int` labels.

- Observation: C++ declaration nodes can contain more than one function declarator, and unnamed pointer/function-pointer parameters need the whole parameter text to produce useful labels.
  Evidence: Milestone 4 guided review found `void a(int value), b(int value);` and `void consume(int*, int (*)());`; C++ metadata now searches from the specific function declarator position and falls back to the full parameter declaration when no name node exists.

- Observation: Python's signatureHelp label comes from the skeleton header and preserves the declaration colon before the synthetic ellipsis.
  Evidence: The Python analyzer regression compares `get_skeleton_header` to stored metadata; metadata now records `def combine(...): ...` so the LSP handler can match it exactly.

- Observation: Python typed rest parameters are nested as `typed_parameter` containing `list_splat_pattern`, not as a direct `list_splat_pattern` child of `parameters`.
  Evidence: The Python analyzer regression covers `*rest: int`; the label helper now descends through typed parameter wrappers to reach the identifier node.

- Observation: Rust function parameters can be full patterns, not just identifiers, `mut`, `ref`, or `self`.
  Evidence: The post-milestone review found tuple and wildcard patterns would shorten the metadata list. Rust now falls back to the parser-owned `pattern` node when there is no simpler identifier label, and `tests/rust_analyzer_test.rs` covers `(left, right)` plus `_`.

## Decision Log

- Decision: Keep Java and TypeScript as slice 1 and document all other languages as follow-up milestones.
  Rationale: Issue acceptance explicitly requires Java and TypeScript tests, while the analyzer supports more languages that should receive the same structured metadata in smaller safe slices.
  Date/Author: 2026-06-28 / Codex

- Decision: Store signature metadata in the analyzer layer, not in the LSP handler.
  Rationale: The LSP handler should not parse source text or skeleton labels. Parser visitors already own declaration structure and can collect ordered parameter labels from tree-sitter nodes.
  Date/Author: 2026-06-28 / Codex

- Decision: Emit `ParameterLabel::LabelOffsets` rather than simple string labels when a structured parameter label can be located in the rendered signature label.
  Rationale: Label offsets give clients the exact range to highlight while preserving the existing signature display string.
  Date/Author: 2026-06-28 / Codex

- Decision: Store parameter label ranges in `SignatureMetadata` instead of recomputing them in the LSP handler.
  Rationale: SignatureHelp should consume analyzer-owned ranges directly. This prevents duplicate names in callable names, return types, or other signature text from being mistaken for parameter labels.
  Date/Author: 2026-06-28 / Codex

- Decision: Bump the persisted analyzer payload version when adding signature metadata.
  Rationale: Older cache rows do not contain the new metadata. Treating them as dirty avoids a split where fresh analysis returns parameter labels but hydrated state does not.
  Date/Author: 2026-06-28 / Codex

## Outcomes & Retrospective

Slice 1 is complete for Java and TypeScript, Milestone 2 is complete for JavaScript, Milestone 3 is complete for Go, Milestone 4 is complete for C# and C++, and the non-Ruby portion of Milestone 5 is complete for Python, Rust, PHP, and Scala. The analyzer now stores structured signature metadata with parameter label ranges, persists it with payload version 2, and exposes it through `IAnalyzer`. Java, TypeScript, JavaScript, Go, C#, C++, Python, Rust, PHP, and Scala declaration visitors populate parameter labels from tree-sitter nodes, and LSP signatureHelp returns stored label offsets plus declaration docs for the covered cases. Remaining language: Ruby.

Validation completed:

    cargo test --test bifrost_lsp_server signature_help --features nlp
    result: 16 passed; 0 failed

    cargo test --test python_analyzer_test signature_metadata --features nlp
    result: 1 passed; 0 failed

    cargo test --test rust_analyzer_test signature_metadata --features nlp
    result: 1 passed; 0 failed

    cargo fmt --check
    result: passed

    cargo clippy-no-cuda
    result: passed

## Context and Orientation

`textDocument/signatureHelp` is handled in `src/lsp/handlers/signature_help.rs`. It reads the current document, finds the surrounding call expression, resolves the callee to analyzer declarations, and returns LSP `SignatureHelp`.

Analyzer declarations are represented by `CodeUnit` in `src/analyzer/model.rs`. Rendered signature strings are collected by language-specific parser visitors into `ParsedFile.signatures` in `src/analyzer/tree_sitter_analyzer.rs`, then indexed into immutable analyzer state. Java parser code lives in `src/analyzer/java/declarations.rs`. TypeScript parser code lives in `src/analyzer/typescript/mod.rs`. Other languages follow similar language-specific analyzer modules.

Parameter metadata means ordered facts about the parameters of one rendered callable signature. For this plan, each parameter fact starts with the user-visible parameter label, such as `left` or `right`. The LSP handler maps those labels into offsets inside the already-rendered signature label.

Documentation means the leading doc comment attached to a declaration. Bifrost already has `extract_leading_doc_comment` in `src/lsp/handlers/util.rs`; it removes comment markers from shapes such as `/** ... */`, `///`, and `#`.

## Plan of Work

First, add `SignatureMetadata` and `ParameterMetadata` to `src/analyzer/model.rs` and export them from `src/analyzer/mod.rs`. Add `signature_metadata` maps beside existing `signatures` maps in `ParsedFile`, `FileState`, and `AnalyzerState` in `src/analyzer/tree_sitter_analyzer.rs`. Add `ParsedFile::add_signature_with_metadata` so rendered labels and metadata are recorded together, index the maps when building analyzer state, expose `TreeSitterAnalyzer::signature_metadata_of`, and add a defaulted `IAnalyzer::signature_metadata` method in `src/analyzer/i_analyzer.rs`. Route it through `src/analyzer/multi_analyzer.rs`, `src/analyzer/java/mod.rs`, and `src/analyzer/typescript/mod.rs`.

Second, update persistence in `src/analyzer/persistence/payload.rs`. Add `signature_metadata` to `PersistedFileState`, serialize and hydrate it, and bump `PAYLOAD_VERSION`. This makes old cached rows re-analyze instead of silently missing metadata.

Third, populate Java metadata. In `src/analyzer/java/declarations.rs`, `visit_callable` already sees the method or constructor node and its `parameters` field. Use tree-sitter child fields to collect parameter names from `formal_parameter` and `spread_parameter` nodes. Store metadata with the same rendered label produced by `callable_signature`.

Fourth, populate TypeScript metadata. In `src/analyzer/typescript/mod.rs`, reuse the existing `ts_parameter_name_node` helper to collect ordered parameter labels from function, method, and variable-function nodes. Attach metadata at the same call sites that currently call `parsed.add_signature` for top-level functions, class methods, and variable-backed functions. Future constructor-specific improvements can extend this path when constructor resolution returns class-level signatures.

Fifth, update `src/lsp/handlers/signature_help.rs`. Keep the existing definition resolution and active-parameter logic. After choosing the rendered label, find matching analyzer signature metadata by exact trimmed label. For each stored parameter range, emit `ParameterInformation { label: ParameterLabel::LabelOffsets([start, end]), documentation: None }` after converting byte offsets in the label to UTF-16 offsets. If the metadata cannot be matched, omit `parameters` instead of guessing. Use the shared `leading_doc_comment_for_code_unit` helper to populate `SignatureInformation.documentation`.

Sixth, add tests in `tests/bifrost_lsp_server.rs`. Extend the Java and TypeScript signatureHelp tests with doc comments and assert that the returned signature has `parameters` label offsets for `left` and `right`, has documentation text, and still reports `activeParameter == 1`.

## Language Rollout Milestones

Milestone 1 is Java and TypeScript. Java updates `src/analyzer/java/declarations.rs`; TypeScript updates `src/analyzer/typescript/mod.rs`. Acceptance is the focused LSP test command passing with Java and TypeScript parameter offsets plus docs.

Milestone 2 should add JavaScript in `src/analyzer/javascript/mod.rs`. Reuse the same metadata model for function declarations, methods, assignment-backed functions, and variable-backed functions. Acceptance is a JavaScript LSP signatureHelp test that verifies parameter offsets and JSDoc docs.

Milestone 2 status: complete. JavaScript now records signature metadata from parser parameter nodes for function declarations, methods, variable-backed functions, and assignment-backed functions. The LSP tests cover a JSDoc-backed function whose callable name and first parameter share the same text, a default value containing a nested call followed by later parameters, a rest parameter, and an unparenthesized single-parameter arrow function.

Milestone 3 should add Go in `src/analyzer/go/declarations.rs` or the Go declaration visitor module that records signatures. Acceptance is a Go LSP signatureHelp test with parameter offsets. Go doc comments should be included if `extract_leading_doc_comment` recognizes the attached comment block for the declaration.

Milestone 3 status: complete. Go now records signature metadata for function declarations, method declarations, and interface method elements. The LSP test covers a duplicate callable/parameter name, a `func()` parameter type with nested parentheses, a variadic parameter, and a bare `//` Go doc comment. Analyzer regressions cover method receiver/parameter text collisions and anonymous variadic labels.

Milestone 4 should add C# and C++ in `src/analyzer/csharp/declarations.rs` and `src/analyzer/cpp/declarations.rs`. Acceptance is one LSP signatureHelp test per language with offsets for a two-parameter function or method and docs where the existing comment extraction can cleanly attach them.

Milestone 4 status: complete. C# now records signature metadata for method and constructor declarations. The C# LSP test covers a duplicate callable/parameter name, a nested `Func<int>` parameter type, a defaulted later parameter, and XML doc comments. C++ now records signature metadata for function declarations and definitions. The C++ LSP test covers a duplicate callable/parameter name, a named function-pointer parameter, a pointer parameter, and a block doc comment. Analyzer regressions cover unnamed pointer/function-pointer parameter labels and multi-declarator anchoring.

Milestone 5 should add Python, Rust, PHP, Scala, and Ruby in their declaration modules under `src/analyzer/<language>/`. Acceptance is one LSP signatureHelp test per language where signatureHelp already resolves calls today. If a language lacks reliable signatureHelp resolution, document that as a prerequisite in this ExecPlan before adding metadata.

Milestone 5 status: Python, Rust, PHP, and Scala are complete. Python records function declaration metadata, including typed defaults and typed rest parameters. Rust records metadata for function items and trait signatures from parameter pattern nodes, including non-identifier pattern fallbacks. PHP records metadata for functions and methods from PHP parameter nodes. Scala records metadata for functions and primary constructors from parameter/class-parameter nodes. The LSP tests cover offsets and docs for all four completed languages, and the existing Scala brace-argument test now asserts parameter offsets. Ruby remains the only Milestone 5 language still outstanding.

## Concrete Steps

Work from the repository root:

    cd /Users/dave/.codex/worktrees/aa85/bifrost

After implementation, run the focused LSP tests:

    cargo test --test bifrost_lsp_server signature_help --features nlp

Then run formatting and clippy:

    cargo fmt --check
    cargo clippy-no-cuda

If `cargo fmt --check` fails only because formatting is needed, run:

    cargo fmt

Then rerun the focused test and `cargo fmt --check`.

## Validation and Acceptance

The Java test must show that a call such as `sum(1, 2)` returns `activeParameter` equal to `1`, a signature label containing `sum`, two parameter label ranges that slice to `left` and `right`, and documentation containing the Java doc comment body.

The TypeScript test must show that a call such as `combine(1, 2)` returns `activeParameter` equal to `1`, a signature label containing `combine`, two parameter label ranges that slice to `left` and `right`, and documentation containing the JSDoc body.

Existing signatureHelp tests for constructor, Go, Scala, null outside call arguments, and open-document overlays must remain green.

## Idempotence and Recovery

The edits are additive and can be repeated safely. Bumping `PAYLOAD_VERSION` makes old analyzer cache rows invalid; the analyzer should re-parse files and write new payloads. If a test fails because old cached state is unexpectedly reused, remove the local analyzer cache for the temporary test project or rerun the test so it starts from a fresh temp directory.

No branch switch, rebase, commit, or push is part of this plan unless the user asks for those operations.

## Artifacts and Notes

The key expected JSON shape for one signature is:

    "signatures": [{
      "label": "int sum(int left, int right)",
      "documentation": {"kind": "markdown", "value": "Adds two values."},
      "parameters": [
        {"label": [12, 16]},
        {"label": [22, 27]}
      ]
    }],
    "activeParameter": 1

Exact offset numbers depend on the rendered label. Tests should verify that slicing the returned label by the offsets yields `left` and `right`.

## Interfaces and Dependencies

At the end of slice 1, `src/analyzer/model.rs` defines:

    pub struct ParameterMetadata { ... } // includes the label and byte range inside the rendered signature label
    pub struct SignatureMetadata { ... }

At the end of slice 1, `src/analyzer/i_analyzer.rs` exposes:

    fn signature_metadata<'a>(&'a self, _code_unit: &CodeUnit) -> &'a [SignatureMetadata]

At the end of slice 1, `src/analyzer/tree_sitter_analyzer.rs` provides:

    ParsedFile::add_signature_with_metadata(code_unit, metadata)
    TreeSitterAnalyzer::signature_metadata_of(code_unit)

The LSP handler must only consume these analyzer facts and existing doc-comment helpers. It must not split parameter lists, scan delimiters, or parse source text to infer function parameters.

## Revision Note

2026-06-28 / Codex: Created the initial ExecPlan because issue #319 is being implemented as a Java/TypeScript first slice while preserving an explicit rollout plan for the remaining analyzer languages.

2026-06-28 / Codex: Updated progress and outcomes after completing slice 1 and running the focused signatureHelp test, formatting check, and no-CUDA clippy gate.

2026-06-28 / Codex: Updated the plan after guided review fixes changed metadata from name-only labels to stored label ranges and moved doc-comment lookup into a shared capped helper.

2026-06-28 / Codex: Completed Milestone 2 for JavaScript and reran the focused signatureHelp LSP tests.

2026-06-28 / Codex: Addressed Milestone 2 guided-review findings by deriving JavaScript parameter offsets inside the exact rendered parameter segment and covering default-call, rest, and singular-arrow cases.

2026-06-28 / Codex: Completed Milestone 3 for Go, including Go-only bare `//` doc extraction and a signatureHelp regression covering nested function-type parameters plus variadic parameters.

2026-06-28 / Codex: Addressed Milestone 3 guided-review findings by anchoring Go parameter metadata to the tree-sitter `parameters` node and preserving anonymous variadic labels such as `...int`.

2026-06-28 / Codex: Completed the C# half of Milestone 4 with method/constructor metadata and focused LSP coverage.

2026-06-28 / Codex: Completed the C++ half of Milestone 4 with function declaration/definition metadata and focused LSP coverage for function-pointer parameters.

2026-06-28 / Codex: Addressed Milestone 4 guided-review findings by anchoring C++ metadata to the specific function declarator and preserving unnamed pointer/function-pointer parameter text.

2026-06-28 / Codex: Completed Python, Rust, PHP, and Scala signature metadata with focused LSP coverage; Ruby remains pending.

2026-06-28 / Codex: Addressed a post-milestone review finding by preserving Rust tuple and wildcard pattern parameters as metadata labels.
