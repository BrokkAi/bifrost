# Add Structured SignatureHelp Parameter Metadata

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md` from the repository root. Any contributor who changes this work must update this file so it remains self-contained and accurate.

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

## Surprises & Discoveries

- Observation: SignatureHelp already resolves the callee with structured definition lookup and already computes `activeParameter`.
  Evidence: `src/lsp/handlers/signature_help.rs` calls `call_signature_context` and `resolve_definition_batch_with_source` before building `SignatureInformation`.

- Observation: Hover already has reusable doc-comment cleanup that strips Javadoc/JSDoc markers.
  Evidence: `src/lsp/handlers/util.rs` exposes `extract_leading_doc_comment`, and `src/lsp/handlers/hover.rs` uses it for hover markdown.

- Observation: Analyzer file state can be hydrated from persisted payloads, so signature metadata must be persisted or cached startup behavior would differ from fresh parse behavior.
  Evidence: `src/analyzer/persistence/payload.rs` serializes `FileState.signatures`, and `TreeSitterAnalyzer::signature_metadata` must be able to read metadata from the same state shape.

- Observation: Storing only parameter names made LSP offset recovery ambiguous when a parameter name also appeared earlier in the signature label.
  Evidence: The Java and TypeScript signatureHelp tests now use `sum(int sum, ...)` and `function combine(combine, ...)`; the returned ranges must slice to the parameter labels inside the parameter list, not the callable name.

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

Slice 1 is complete for Java and TypeScript. The analyzer now stores structured signature metadata with parameter label ranges, persists it with payload version 2, and exposes it through `IAnalyzer`. Java and TypeScript declaration visitors populate parameter labels from tree-sitter nodes, and LSP signatureHelp returns stored label offsets plus declaration docs for the covered cases. Remaining languages are JavaScript, Go, C#, C++, Python, Rust, PHP, Scala, and Ruby.

Validation completed:

    cargo test --test bifrost_lsp_server signature_help --features nlp
    result: 7 passed; 0 failed

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

Milestone 3 should add Go in `src/analyzer/go/declarations.rs` or the Go declaration visitor module that records signatures. Acceptance is a Go LSP signatureHelp test with parameter offsets. Go doc comments should be included if `extract_leading_doc_comment` recognizes the attached comment block for the declaration.

Milestone 4 should add C# and C++ in `src/analyzer/csharp/declarations.rs` and `src/analyzer/cpp/declarations.rs`. Acceptance is one LSP signatureHelp test per language with offsets for a two-parameter function or method and docs where the existing comment extraction can cleanly attach them.

Milestone 5 should add Python, Rust, PHP, Scala, and Ruby in their declaration modules under `src/analyzer/<language>/`. Acceptance is one LSP signatureHelp test per language where signatureHelp already resolves calls today. If a language lacks reliable signatureHelp resolution, document that as a prerequisite in this ExecPlan before adding metadata.

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
