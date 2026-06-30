# LSP Document Formatting With Workspace-Aware Formatter Commands

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md` from the repository root. It is self-contained so a future contributor can resume the work from this file and the current tree alone.

## Purpose / Big Picture

Bifrost's LSP server currently offers navigation, symbols, diagnostics, rename, hierarchy, and related code-intelligence features, but it does not answer `textDocument/formatting`. After this work, an editor can ask Bifrost to format a document and receive ordinary LSP text edits. Bifrost will not implement formatting rules itself; it will delegate to real project formatter commands selected from workspace-aware configuration or conservative built-in discovery.

The user-visible behavior is: start `bifrost --lsp`, initialize with optional `formatterCommands`, open or edit a supported file, send `textDocument/formatting`, and receive either an empty edit list when the formatter made no change or one full-document edit containing the formatter's stdout. The implementation must not mutate source files directly. The client remains responsible for applying edits.

## Progress

- [x] (2026-06-30 10:59Z) Created this ExecPlan after confirming the branch is `42-lsp-document-formatting-with-workspace-aware-formatter-commands` and the tree is clean.
- [x] (2026-06-30 11:06Z) Implemented the formatter command model, ordered rule matching, placeholder expansion, conservative built-in discovery, and stdin/stdout executor. Evidence: `cargo test formatting --lib --features nlp` passed 8 focused formatter tests.
- [ ] Wire `textDocument/formatting` into LSP capabilities, request dispatch, and a dedicated handler that returns full-document edits.
- [ ] Add VS Code settings for `bifrost.formatterCommands` and forward them through LSP initialization options.
- [ ] Add unit, LSP integration, and ignored opt-in real-tool tests.
- [ ] Run formatting, focused tests, and `cargo clippy-no-cuda`; update this ExecPlan with outcomes.

## Surprises & Discoveries

- Observation: `lsp-types` 0.97 names the document formatting request `lsp_types::request::Formatting`.
  Evidence: local registry source at `lsp-types-0.97.0/src/request.rs` defines `pub enum Formatting {}` with method `textDocument/formatting`.

- Observation: macOS temp directories may compare as `/var/...` in test setup but `/private/var/...` after project canonicalization.
  Evidence: the first focused formatter test run failed only on path equality; canonicalizing temp roots in tests fixed it.

## Decision Log

- Decision: Use a stdin/stdout-only formatter contract for v1.
  Rationale: This lets Bifrost format unsaved overlay content and avoids mutating files on disk before the client accepts edits.
  Date/Author: 2026-06-30 / Codex.

- Decision: Treat "all analyzer languages" as resolver coverage plus override support for every language, with built-in discovery only where a safe stdout-capable command is unambiguous.
  Rationale: Some ecosystems have common formatters that are in-place or project-task oriented. A fake universal built-in would either mutate disk or run surprising project commands.
  Date/Author: 2026-06-30 / Codex.

- Decision: Use ordered formatter command rules from initialization options and VS Code settings.
  Rationale: Monorepos often need subdirectory-specific commands, and ordered include/exclude rules are more precise than one language-to-command map.
  Date/Author: 2026-06-30 / Codex.

- Decision: Keep range formatting and on-type formatting out of this plan.
  Rationale: GitHub issues #368 and #369 track those different LSP contracts separately; this plan builds the reusable resolver/executor they can use later.
  Date/Author: 2026-06-30 / Codex.

## Outcomes & Retrospective

This section is intentionally empty at creation. Update it after each major milestone and at completion.

## Context and Orientation

The LSP server is launched by `src/bin/bifrost.rs` when passed `--lsp`. Capabilities are built in `src/lsp/capabilities.rs`. The main server loop and request dispatch live in `src/lsp/server.rs`. Per-request handlers live under `src/lsp/handlers/`.

`OverlayProject` stores unsaved editor content from `didOpen` and `didChange`. Handler code should read through `crate::lsp::handlers::util::read_document_for_uri`, which resolves an LSP URI to a project file and uses the current overlay-aware project source. This is required so formatting uses unsaved buffers.

`ProjectFile` exposes both an absolute path and a workspace-relative path. Formatter command selection should use the relative path for include/exclude globs and the absolute path for command placeholders.

The repository supports analyzer languages defined in `src/analyzer/model.rs`: Java, Go, Cpp, JavaScript, TypeScript, Python, Rust, Php, Scala, CSharp, and Ruby. `Language::None` means unsupported.

VS Code extension settings are declared in `editors/vscode/package.json`, read in `editors/vscode/src/extension.ts`, and typed in `editors/vscode/src/lifecycle.ts`. Existing settings `bifrost.roots` and `bifrost.exclude` are forwarded through `initializationOptions` and parsed by `BifrostInitializationOptions` in `src/lsp/server.rs`; formatter commands should follow that path.

## Plan of Work

First, add a formatter module under `src/lsp/handlers/formatting.rs` or a sibling private submodule if the resolver grows. Define the public-to-server data shape `FormatterCommandRule` with optional `include`, `exclude`, `language`, `args`, and `cwd`, plus required `command`. Deserialize it from LSP initialization options with camelCase field names. Store the parsed rules in `ServerState`.

Implement rule matching as an ordered first match. Include/exclude patterns are workspace-relative globs matched against forward-slash relative paths. A rule matches when the language filter is empty or equals the file language, at least one include pattern matches if includes are present, and no exclude pattern matches. Expand placeholders only in args and cwd. Do not expand placeholders in command, because command should be an executable name or path, not a shell string. Resolve relative cwd values against the active workspace root or discovered tool root.

Implement conservative built-in discovery as a fallback after rules. For Rust use `rustfmt --edition 2024 --emit stdout`; for Go use `gofmt`; for C/C++ use `clang-format --assume-filename {file}`; for Python use `black --quiet -` plus `--stdin-filename {file}` if the command supports it. For JavaScript and TypeScript, inspect the nearest `package.json` and only use explicit scripts whose names indicate document formatting, invoking them through the package manager with stdin if the script is written for stdin/stdout; otherwise return "no formatter configured". For Java and Scala, inspect Gradle manifests only for explicit formatter tasks documented by user override rules in v1; do not synthesize broad Gradle invocations. For C#, PHP, and Ruby return no built-in formatter in v1 and require override rules.

Implement execution with `std::process::Command`: set `stdin` and `stdout` to pipes, write the current document text to stdin, wait for output, and fail with a clear message when the process cannot start, exits unsuccessfully, or writes non-UTF-8 stdout. Include stderr and exit status in errors, truncated to a reasonable length. The executor must not invoke a shell.

Wire `textDocument/formatting` by adding `document_formatting_provider: Some(OneOf::Left(true))` in `src/lsp/capabilities.rs`, importing `lsp_types::request::Formatting` in `src/lsp/server.rs`, and dispatching to the new handler. The handler should return `Option<Vec<TextEdit>>` or `Vec<TextEdit>` according to `lsp-types` 0.97's request type. It should produce an empty vector when formatted text equals original text. When text differs, compute a range from the start of the document to the end of the original document using existing conversion helpers and return one `TextEdit`.

Extend the VS Code extension with a `bifrost.formatterCommands` setting. The setting is an array of objects with `include`, `exclude`, `language`, `command`, `args`, and `cwd`. `include`, `exclude`, and `args` are arrays of strings; `language`, `command`, and `cwd` are strings. Forward non-empty settings to `initializationOptions.formatterCommands`.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/7ad1/bifrost`.

After each milestone, update this file's `Progress`, `Surprises & Discoveries`, and `Decision Log` sections. Because this branch follows an ExecPlan, stage only files touched in the milestone and commit a multiline checkpoint describing the why.

Milestone 1 implements and tests formatter resolution and execution without LSP request dispatch. Run:

    cargo test formatting --lib --features nlp
    cargo fmt --check

Milestone 2 wires LSP document formatting and end-to-end stub formatter tests. Run:

    cargo test --test bifrost_lsp_server formatting --features nlp
    cargo fmt --check

Milestone 3 wires VS Code settings and opt-in real-tool tests. Run:

    cd editors/vscode && npm test
    cargo test formatting --features nlp
    cargo fmt --check

Final validation runs:

    cargo fmt --check
    cargo test --test bifrost_lsp_server formatting --features nlp
    cargo clippy-no-cuda

On macOS or any machine without CUDA, use `cargo clippy-no-cuda` rather than enabling all features.

## Validation and Acceptance

Acceptance requires the LSP initialize response to advertise `documentFormattingProvider: true`. A formatting request for a file with a configured stub formatter must return one text edit replacing the full document with the stub formatter's stdout. A request where the stub echoes the input must return an empty list. A request where the formatter exits non-zero must return a JSON-RPC error that includes the command failure and stderr.

Tests must prove overlay behavior: write an unformatted file to disk, send `didOpen` or `didChange` with different in-memory text, request formatting, and assert the stub formatter saw the in-memory text.

No test may download formatter binaries by default. Real formatter tests must be marked ignored or gated behind `BIFROST_FORMATTER_INTEGRATION_TESTS=1`.

## Idempotence and Recovery

Formatter execution is read-only with respect to source files. Re-running tests should be safe because they create temp directories and stub executables. If a formatter rule points at a missing command, Bifrost should return an LSP error rather than panic or mutate files.

If a milestone fails, keep the current diff, update this ExecPlan with the failed command and discovery, then fix forward. Do not revert unrelated user changes.

## Artifacts and Notes

Important expected LSP behavior for a changed document:

    request: textDocument/formatting
    result: [
      {
        "range": {
          "start": {"line": 0, "character": 0},
          "end": {"line": <original-end-line>, "character": <original-end-character>}
        },
        "newText": "<formatted document>"
      }
    ]

Important expected LSP behavior for no change:

    request: textDocument/formatting
    result: []

## Interfaces and Dependencies

Use existing dependencies `glob`, `serde`, `serde_json`, and `tempfile` in tests. Do not add shell parsing dependencies.

The final Rust interface should include a reusable command type similar to:

    #[derive(Clone, Debug, serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct FormatterCommandRule {
        #[serde(default)]
        pub include: Vec<String>,
        #[serde(default)]
        pub exclude: Vec<String>,
        pub language: Option<String>,
        pub command: String,
        #[serde(default)]
        pub args: Vec<String>,
        pub cwd: Option<String>,
    }

The handler should expose a function shaped like:

    pub(crate) fn handle(
        project: &dyn Project,
        params: &DocumentFormattingParams,
        rules: &[FormatterCommandRule],
    ) -> Result<Vec<TextEdit>, String>

Keep symbols crate-private unless tests require a narrower `pub(crate)` seam.
