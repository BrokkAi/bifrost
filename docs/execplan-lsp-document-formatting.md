# LSP Document Formatting With Workspace-Aware Formatter Commands

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md` from the repository root. It is self-contained so a future contributor can resume the work from this file and the current tree alone.

## Purpose / Big Picture

Bifrost's LSP server currently offers navigation, symbols, diagnostics, rename, hierarchy, and related code-intelligence features, but it does not answer `textDocument/formatting`. After this work, an editor can ask Bifrost to format a document and receive ordinary LSP text edits. Bifrost will not implement formatting rules itself; it will delegate to real project formatter commands selected from workspace-aware configuration or conservative built-in discovery.

The user-visible behavior is: start `bifrost --lsp`, initialize with optional `formatterCommands`, open or edit a supported file, send `textDocument/formatting`, and receive either an empty edit list when the formatter made no change or one full-document edit containing the formatter's stdout. The implementation must not mutate source files directly. The client remains responsible for applying edits.

## Progress

- [x] (2026-06-30 10:59Z) Created this ExecPlan after confirming the branch is `42-lsp-document-formatting-with-workspace-aware-formatter-commands` and the tree is clean.
- [x] (2026-06-30 11:06Z) Implemented the formatter command model, ordered rule matching, placeholder expansion, conservative built-in discovery, and stdin/stdout executor. Evidence: `cargo test formatting --lib --features nlp` passed 8 focused formatter tests.
- [x] (2026-06-30 11:17Z) Wired `textDocument/formatting` into LSP capabilities, request dispatch, and the formatter handler. Evidence: `cargo test --test bifrost_lsp_server formatting --features nlp` passed 5 focused LSP tests covering capability advertisement, overlay text, no-op edits, cwd, and formatter failure.
- [x] (2026-06-30 11:24Z) Added VS Code settings for `bifrost.formatterCommands` and forwarded non-empty rules through LSP initialization options. Evidence: `npm test` passed after installing local VS Code dependencies.
- [x] (2026-06-30 11:24Z) Added unit, LSP integration, and ignored opt-in real-tool tests. Evidence: `cargo test formatting --lib --features nlp` passed 8 tests with 1 ignored opt-in rustfmt integration test; `cargo test --test bifrost_lsp_server formatting --features nlp` passed 5 LSP tests.
- [x] (2026-06-30 11:29Z) Ran formatting, focused tests, VS Code tests, and `cargo clippy-no-cuda`; updated this ExecPlan with outcomes. Evidence: `cargo fmt --check`, `cargo test formatting --lib --features nlp`, `cargo test --test bifrost_lsp_server formatting --features nlp`, `npm test`, and `cargo clippy-no-cuda` all passed.
- [x] (2026-06-30 12:14Z) Ran guided review with security, DRY, senior-dev intent, DevOps, and architecture reviewers. Evidence: reviewers reported issues around multi-root formatter roots, Rust stdin edition, hung formatters, JS/TS discovery boundaries, Windows npm command resolution, unbounded output, and overly broad npm script auto-discovery; DRY reported no findings.
- [x] (2026-06-30 12:39Z) Addressed guided-review findings in the formatter layer. Evidence: `cargo test formatting --lib --features nlp` passed 14 tests with 1 ignored opt-in rustfmt integration test after adding multi-root root selection, Rust edition discovery, formatter timeout/process-group termination, bounded formatter output, Windows `npm.cmd`, safe JS/TS script filtering, and manifest discovery stop bounds.
- [x] (2026-06-30 12:50Z) Ran final post-review validation. Evidence: `cargo fmt --check`, `cargo test formatting --lib --features nlp`, `cargo test --test bifrost_lsp_server formatting --features nlp`, `npm test` in `editors/vscode`, and `cargo clippy-no-cuda` all passed.
- [x] (2026-06-30 13:17Z) Ran a second guided review against `origin/master`. Evidence: reviewers reported remaining issues around streaming formatter deadlock, npm lifecycle script bypass, malformed formatter config dropping roots/excludes, synchronous formatting on the LSP loop, nested workspace root selection, duplicated language mapping, and duplicate capability-test startup.
- [x] (2026-06-30 13:34Z) Addressed the second guided-review findings. Evidence: formatter stdin writing now runs concurrently with stdout/stderr draining and timeout; JS/TS package discovery rejects formatter lifecycle hooks; formatting requests run on a worker thread; invalid formatter configuration no longer discards roots/excludes; nested multi-root selection chooses the deepest root; formatter language labels moved to `Language`; duplicate LSP capability test was removed.
- [x] (2026-06-30 13:42Z) Ran final validation after second-review fixes. Evidence: `cargo fmt --check`, `cargo test formatting --lib --features nlp`, `cargo test --test bifrost_lsp_server formatting --features nlp`, `cargo test invalid_formatter_commands_do_not_discard_roots_or_exclude --lib --features nlp`, `npm test` in `editors/vscode`, and `cargo clippy-no-cuda` all passed.
- [x] (2026-06-30 14:06Z) Ran a third guided review against `origin/master`. Evidence: reviewers reported remaining issues around async overlay snapshot races, JS/TS workspace script execution, unqualified built-in executable lookup on Windows, `ScopedProject` dropping owning roots, unbounded formatting workers, Windows process-tree cleanup, missing JS formatter file paths, and minor duplicated test helpers.
- [x] (2026-06-30 14:24Z) Addressed the third guided-review findings. Evidence: formatting now snapshots document text and command resolution before spawning worker execution; formatting workers are bounded; JS/TS built-in package-script discovery was removed in favor of explicit override rules; built-in command lookup resolves trusted absolute paths on Windows; Windows timeout cleanup uses `taskkill /T /F`; `ScopedProject` delegates `workspace_root_for_file`; request-time snapshot and scoped-project regressions were added.
- [x] (2026-06-30 14:38Z) Ran final validation after third-review fixes. Evidence: `cargo fmt --check`, `cargo test formatting --lib --features nlp`, `cargo test --test bifrost_lsp_server formatting --features nlp`, `cargo test lsp::server::tests --lib --features nlp`, `npm test` in `editors/vscode`, and `cargo clippy-no-cuda` all passed.

## Surprises & Discoveries

- Observation: `lsp-types` 0.97 names the document formatting request `lsp_types::request::Formatting`.
  Evidence: local registry source at `lsp-types-0.97.0/src/request.rs` defines `pub enum Formatting {}` with method `textDocument/formatting`.

- Observation: macOS temp directories may compare as `/var/...` in test setup but `/private/var/...` after project canonicalization.
  Evidence: the first focused formatter test run failed only on path equality; canonicalizing temp roots in tests fixed it.

- Observation: the VS Code extension worktree did not have `node_modules` installed.
  Evidence: the first `npm test` failed with `sh: tsc: command not found`; `npm install` added local dependencies and the following `npm test` passed 13 unit tests.

- Observation: `MultiRootProject` stores files relative to a common ancestor for analyzer-wide identity, but formatter commands need the owning workspace folder root.
  Evidence: guided review pointed out that globs like `src/**/*.ts`, `{workspaceRoot}`, and relative `cwd` values were evaluated against the common parent in multi-root workspaces; `Project::workspace_root_for_file` now exposes the owning root for formatter use.

- Observation: `rustfmt` defaults stdin input to Rust 2015 unless an edition is supplied.
  Evidence: guided review reproduced `printf 'async fn f() {}\n' | rustfmt --emit stdout` failing with E0670; the Rust built-in now passes the nearest `Cargo.toml` package edition, falling back to 2024.

- Observation: a formatter child can block the LSP request loop if it never exits, emits unbounded output, or leaves inherited pipes open through descendants.
  Evidence: guided review flagged `wait_with_output()` and unbounded pipe reads; the executor now enforces a timeout, output caps, Unix process-group termination, and a bounded reader grace period.

- Observation: draining stdout/stderr after writing all stdin is still unsafe for streaming formatters.
  Evidence: the second guided review pointed out that a formatter like `cat` can fill stdout while Bifrost is still blocked in `stdin.write_all`; stdin writing now runs concurrently with output readers, covered by a large-input `cat` test.

- Observation: `npm run` executes `pre<script>` and `post<script>` lifecycle hooks even when the target script body is safe.
  Evidence: the second guided review showed that `preformat:stdin` could bypass the built-in script-body filter; package-script discovery now rejects formatter scripts with lifecycle hooks.

- Observation: formatter execution should not occupy the single LSP dispatch loop.
  Evidence: the second guided review flagged synchronous process execution in `handle_request`; formatting requests now clone the overlay project and rules, execute on a worker thread, and send the response asynchronously.

- Observation: moving formatter execution to a worker is not sufficient unless the request input is snapshotted first.
  Evidence: the third guided review showed that a `didChange` arriving before the worker read the overlay could make an older formatting request format newer text; the server now prepares the formatter command and document content on the LSP loop before spawning execution.

- Observation: safe JS/TS package-script autodiscovery is not practical without a workspace-trust prompt.
  Evidence: the third guided review showed that even constrained `npm run` scripts can load project-controlled Prettier plugins or otherwise execute workspace code; JS/TS now requires explicit `formatterCommands`.

- Observation: wrapper projects must delegate formatter root ownership.
  Evidence: the third guided review found that `ScopedProject` fell back to the trait default for `workspace_root_for_file`, losing multi-root ownership whenever excludes wrapped the project.

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

- Decision: JS/TS has no built-in formatter autodiscovery in v1.
  Rationale: Running workspace `package.json` scripts or project-local Prettier plugins is not conservative without a trust/approval UI. Project-specific JS/TS formatting remains supported through explicit `formatterCommands`.
  Date/Author: 2026-06-30 / Codex.

- Decision: Add a project-level owning-root query instead of changing analyzer file identity.
  Rationale: Analyzer multi-root identity intentionally uses the common ancestor, but formatter behavior is workspace-root-sensitive. A small `Project::workspace_root_for_file` method lets formatting use the correct root without destabilizing existing analyzer paths.
  Date/Author: 2026-06-30 / Codex.

- Decision: Ignore invalid formatter command configuration while preserving other initialization options.
  Rationale: `connection.initialize` has already replied before workspace setup sees initialization options, so failing there would terminate after a nominal initialize response. Logging and dropping only invalid formatter commands preserves `roots` and `exclude` and avoids accidental broad indexing.
  Date/Author: 2026-06-30 / Codex.

- Decision: Move formatter-facing language labels onto `Language`.
  Rationale: Formatter rule parsing and `{language}` placeholders should not maintain a separate language alias table from analyzer language metadata.
  Date/Author: 2026-06-30 / Codex.

- Decision: Bound formatter execution instead of allowing unbounded detached workers.
  Rationale: Formatting should not block ordinary LSP traffic, but a client should also not be able to create unbounded formatter processes and helper threads. The server rejects requests over the in-flight limit.
  Date/Author: 2026-06-30 / Codex.

## Outcomes & Retrospective

Completed #42's document-formatting slice. Bifrost now advertises and handles `textDocument/formatting`, resolves formatter commands from ordered configuration rules before conservative built-ins, formats overlay-aware document text through stdin/stdout commands, and returns ordinary full-document LSP edits. VS Code now exposes `bifrost.formatterCommands` and forwards rules to the server. Range formatting and on-type formatting remain separate follow-up issues.

The initial validation bundle passed on 2026-06-30, then guided review found several concrete safety and workspace-root issues. After addressing those findings, the first post-review validation bundle also passed: `cargo fmt --check`, `cargo test formatting --lib --features nlp`, `cargo test --test bifrost_lsp_server formatting --features nlp`, `npm test` in `editors/vscode`, and `cargo clippy-no-cuda`. A second guided review found additional process, npm lifecycle, initialization parsing, nested-root, and cleanup findings; after fixing those, the final validation bundle also passed: `cargo fmt --check`, `cargo test formatting --lib --features nlp`, `cargo test --test bifrost_lsp_server formatting --features nlp`, `cargo test invalid_formatter_commands_do_not_discard_roots_or_exclude --lib --features nlp`, `npm test`, and `cargo clippy-no-cuda`. A third guided review found remaining async snapshot, JS/TS autodiscovery, Windows execution, scoped-root, and worker-bound issues; after fixing those, the final validation bundle passed again: `cargo fmt --check`, `cargo test formatting --lib --features nlp`, `cargo test --test bifrost_lsp_server formatting --features nlp`, `cargo test lsp::server::tests --lib --features nlp`, `npm test`, and `cargo clippy-no-cuda`.

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
