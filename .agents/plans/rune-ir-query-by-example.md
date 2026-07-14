# Expose Rune IR for query-by-example

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document is maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

After this change, someone learning or debugging Bifrost structural queries can paste source code into the query REPL or invoke a VS Code command at a source selection and see the exact normalized structure that `query_code` matches. Bifrost calls that source-side representation **Rune IR**: the stable, language-neutral intermediate representation produced by each structural language adapter. The output also includes a conservative RQL starter query that parses through the real `CodeQuery` frontend. This makes query-by-example possible without exposing tree-sitter grammar node names or requiring a workspace index for the REPL path.

The observable REPL workflow is `:ir rust`, followed by multiline Rust source and `:end`; it prints a bounded S-expression tree and a copyable RQL pattern. The observable editor workflow is **Bifrost: Show Rune IR**, which asks the server to render the smallest enclosing indexed declaration from the unsaved overlay and opens the same server-rendered text in a new editor.

## Progress

- [x] (2026-07-14 12:00Z) Read issue #733, refreshed the current issue branch, inspected the existing structural facts, query frontend, REPL, LSP overlay, and VS Code extension seams, and selected the public name Rune IR.
- [x] (2026-07-14 14:05Z) Implemented and tested a bounded, deterministic Rune IR renderer and starter-RQL generator over the existing `FileFacts` arena; 5 focused library tests pass for Rust, Python, TypeScript, selection, escaping, parseable starters, errors, and all four limits.
- [x] (2026-07-14 14:25Z) Added the index-free multiline `:ir <language>` REPL workflow with explicit `:end`, actionable input errors, colon-preserving source capture, lazy-service isolation, help/completion metadata, 15 passing binary tests, and a successful real scripted Rust smoke run.
- [x] (2026-07-14 14:50Z) Added `bifrost/runeIr` with overlay-aware source reads, exclusive cursor/range params, smallest-enclosing indexed `CodeUnit` selection, primary-range Rune IR roots, UTF-16 response ranges, opaque display text, unit coverage, and a passing end-to-end Rust/TypeScript LSP test.
- [x] (2026-07-14 15:05Z) Added **Bifrost: Show Rune IR** for supported source editors, using selection-or-cursor request params and opening the server-provided display text verbatim; TypeScript and manifest tests pass as part of all 48 VS Code tests.
- [x] (2026-07-14 15:25Z) Documented Rune IR as the source-side representation matched by `CodeQuery`, documented both query-by-example surfaces, passed Astro content checks and the production build, and visually verified the rendered code-querying page in the in-app browser.
- [x] (2026-07-14 12:14Z) Reviewed the complete branch diff, repaired truncation so every bounded Rune IR result remains a balanced S-expression, passed `cargo fmt --check`, 7 focused library tests, 15 REPL tests, the overlay LSP integration test, all 48 VS Code tests, and all-target/all-feature clippy with warnings denied. The full `nlp,python` test binary remains un-linkable in this local PyO3 environment as recorded below.

## Surprises & Discoveries

- Observation: “Rune” is already the expanded name of RQL in the documentation and VS Code grammar.
  Evidence: `docs/src/content/docs/code-querying.md` calls RQL “Rune Query Language,” and `editors/vscode/syntaxes/bifrost-rql.tmLanguage.json` uses the same name. This makes Rune IR a coherent paired name for the source representation that Rune queries inspect, but the docs must still distinguish Rune IR from the query-side `CodeQuery` IR.
- Observation: The Bifrost code-intelligence skills are installed but their MCP tools are not exposed in this session.
  Evidence: the available tool inventory contained no `search_symbols`, `get_summaries`, `get_symbol_sources`, `scan_usages`, or filename-search endpoint, so repository exploration used bounded `rg` and direct source reads.
- Observation: The local all-feature Rust link gate cannot resolve PyO3 symbols on this macOS environment.
  Evidence: `cargo test rune_ir --features nlp,python` compiled the Rune IR code, then failed while linking `libbrokk_bifrost.dylib` with undefined `_Py*` symbols. `cargo test --lib rune_ir` avoids the unrelated optional Python bridge while still parsing Python through the always-available tree-sitter adapter and passes all 5 tests.
- Observation: `cargo clippy` and `cargo test` are selecting incompatible local Rust compiler identities while sharing `target/` artifacts, even though both report Rust 1.96.0.
  Evidence: after the focused tests passed, the first clippy attempts rejected dependency metadata with E0514. `type -a cargo-clippy` showed Homebrew's subcommand before rustup's even though `cargo` itself came from rustup. Running with `/Users/dave/.cargo/bin` first on `PATH` and a fresh target directory passed `cargo clippy --all-targets --all-features -- -D warnings`; deleting the shared target directory was unnecessary.
- Observation: a truncation marker alone was not enough to preserve Rune IR's S-expression contract when a node or depth limit interrupted nested output.
  Evidence: the complete-diff review showed open node forms could remain unclosed. The renderer now reserves space for compact closing parentheses, and every bounded-dimension test verifies balanced parentheses while respecting the byte limit.

## Decision Log

- Decision: Name the public source-side representation “Rune IR,” described on first use as “Bifrost’s normalized structural intermediate representation.” Retain `FileFacts` and `NormalizedNode` as storage implementation names unless a local API name becomes misleading.
  Rationale: Rune matches the existing Rune Query Language and Brokk’s Norse theme, is concise in commands and UI, and avoids the opaque acronym NSIR. Avoiding a fabricated expansion for RUNE keeps the terminology honest. `CodeQuery` remains the separate typed query-side IR.
  Date/Author: 2026-07-14 / Codex
- Decision: Put extraction, selection, rendering, and starter generation behind one Rust module used by both REPL and LSP.
  Rationale: The UI must not duplicate vocabulary or renderer behavior, and identical source should produce byte-for-byte identical Rune IR across surfaces.
  Date/Author: 2026-07-14 / Codex
- Decision: Render containment as nested node forms and role edges as explicit `(role-label ...)` child forms, including a span-only target form when the adapter has no normalized target node.
  Rationale: The distinction is matcher-visible, deterministic, and preserves role targets that cannot be represented as containment nodes or a single RQL pattern.
  Date/Author: 2026-07-14 / Codex

## Outcomes & Retrospective

The issue is implemented end to end under the public name Rune IR. Callers can render bounded, balanced Rune IR and a validated starter RQL directly from source for every registered structural language without constructing a workspace analyzer; the REPL exposes that path through `:ir <language>` without initializing its lazy workspace service; the private LSP request returns identical Rune IR from unsaved overlay content with indexed declaration selection and UTF-16 ranges; and VS Code displays the opaque server response from a source-editor command. The documentation builds cleanly and its rendered preview presents the architecture and workflows correctly. Formatting, focused Rust/LSP tests, extension tests, and all-target/all-feature clippy pass. The only unavailable gate is the full `nlp,python` test link in this machine's existing PyO3 environment; its undefined Python symbols are unrelated to Rune IR.

## Context and Orientation

Structural adapters translate grammar-specific tree-sitter nodes into language-neutral facts. `src/analyzer/structural/extract.rs` performs that translation and creates a flat pre-order arena called `FileFacts`, defined in `src/analyzer/structural/facts.rs`. Each `NormalizedNode` records a canonical `NormalizedKind`, a byte range, optional derived name, containment parent, typed role targets, and the end of its contiguous descendant range. The matcher reads only these facts, so Rune IR must render this arena directly and never walk or print the raw parse tree.

Canonical kind and role spellings live in `src/analyzer/structural/kinds.rs`. RQL is the Rune Query Language S-expression frontend. It and canonical JSON both compile into the typed `CodeQuery` model under `src/analyzer/structural/query/`; `CodeQuery::from_source` is the acceptance boundary for generated starter queries.

The interactive query shell is `src/bin/bifrost/code_query_repl.rs`. It already recognizes colon commands and maintains multiline query state. The new `:ir <language>` mode must capture arbitrary source until a line containing only `:end`; it must resolve the language with `Language::from_config_label`, use the language’s real grammar and `StructuralSpec`, and avoid constructing `SearchToolsService` for extraction.

The LSP server in `src/lsp/server.rs` owns an overlay project containing unsaved document text. Existing helpers in `src/lsp/handlers/util.rs`, `broad_symbol.rs`, and `document_symbol.rs` demonstrate overlay reads, point/range conversion, and indexed `CodeUnit` hierarchy selection. The private `bifrost/runeIr` request will accept a text document and either cursor position or selection range. It returns the selected code-unit label, UTF-16 range, rendered Rune IR, starter RQL, and one already-formatted display document. If no exact normalized node covers the code unit, the renderer selects top-level facts wholly contained in its primary source range.

The VS Code extension in `editors/vscode/src/extension.ts` owns the `LanguageClient`. `editors/vscode/package.json` declares commands and source-editor context menus. TypeScript should send the request using the active editor’s URI and cursor or selection, then open the returned display text. It must not parse S-expressions, translate kinds, or generate RQL.

## Plan of Work

First add `src/analyzer/structural/rune_ir.rs`. Define public request-independent types for render limits, a rendered result, and an optional byte selection. Add a language registry function that returns the existing grammar and structural spec for a `Language`; it should use the same adapter implementations as workspace analysis rather than a second normalization table. Extract `FileFacts`, choose roots in source order, and iteratively render nested containment plus explicit role forms. Track node count, depth, source bytes copied, and output bytes. Escape source-derived strings as valid JSON string literals inside the S-expression, sanitize control characters, and append an explicit `(truncated "reason")` form when a cap is reached. Generate `(kind (name "exact"))` or `(kind)` from the selected/top-level root and prove it parses with `CodeQuery::from_source` before returning it.

Add unit tests beside the renderer for escaping, deterministic role/containment ordering, span-only role targets, root selection, every limit, and starter parsing. Add adapter-backed tests for representative Rust, Python, and TypeScript source covering declarations, calls, positional and keyword arguments where supported, decorators, imports, assignments, and field access. Assertions should focus on canonical labels and absence of raw grammar names rather than duplicating every adapter table.

Next extend the REPL state machine. `:ir <language>` enters a dedicated source-capture state; `:end` extracts and renders immediately. Empty input, unsupported labels, and adapters without structural support return actionable errors. Source lines beginning with ordinary colon text remain source. Tests should drive the state machine without a workspace service and compare its Rune IR payload with the shared renderer.

Then add serializable LSP parameter and response structs and private request dispatch. Read the URI through the overlay, resolve its analyzer language, and use indexed `CodeUnit`s to find the smallest declaration whose primary range encloses the requested point or selection. Convert that byte range against the overlay text, render facts within it, and return precise UTF-16 positions. For a point outside any usable declaration, attempt a direct smallest-fact selection; if no fact is usable, return an actionable protocol error. Tests must open and change a document to prove unsaved content wins, cover function/method/type/field/constructor-like `CodeUnit`s across representative adapters, and compare the `nsir`/Rune IR string to direct rendering of the same source.

Finally register `bifrost.showRuneIr` in VS Code and contribute a command-palette and source-editor context entry for supported source language IDs. The handler sends `bifrost/runeIr`, passes either the non-empty selection or active position, and opens a language-neutral text document containing the server-provided display string. Add focused TypeScript tests for parameter construction, readiness/error handling, and verbatim display behavior. Update the structural querying documentation and navigation so “Rune IR” is defined before RQL/`CodeQuery` are contrasted.

## Concrete Steps

All commands run from `/Users/dave/.codex/worktrees/3ec0/bifrost`.

After the shared renderer milestone, run:

    cargo test rune_ir --features nlp,python
    cargo fmt --check

After the REPL milestone, run the focused binary tests and an interactive smoke input equivalent to:

    printf ':ir rust\nfn greet(name: &str) { println!("{name}"); }\n:end\n:quit\n' | cargo run --bin bifrost -- code-query-repl

The output must contain canonical `function` and `call` Rune IR forms and a starter query accepted by `CodeQuery::from_source`; it must not contain Rust grammar labels such as `function_item` or `call_expression`.

After the LSP and editor milestones, run:

    cargo test --test bifrost_lsp_server --features nlp,python rune_ir
    npm --prefix editors/vscode test
    npm --prefix editors/vscode run compile

At completion run:

    cargo fmt
    cargo clippy --all-targets --all-features -- -D warnings
    cargo test --features nlp,python

If the full suite is too slow for an iteration, keep the focused commands green and record the full-suite result or remaining gate in `Progress` and `Outcomes & Retrospective`.

## Validation and Acceptance

`:ir rust` must accept multiline source through `:end` without indexing a workspace and print deterministic Rune IR followed by a copyable RQL starter. Unsupported language, empty source, no structural adapter, and no usable facts must each produce a specific error that tells the user what to change.

The renderer must show canonical labels from `NormalizedKind::label` and `Role::label`, preserve source-order containment, distinguish role forms from nested containment, include exact names and keyword names when present, and include span-only role targets. Tests must demonstrate output truncation for every bounded dimension and safe escaping of quotes, backslashes, newlines, terminal controls, and invalid range boundaries.

The LSP request must use unsaved overlay text, choose the smallest enclosing indexed code unit where one exists, and return UTF-16 ranges that select the same source in VS Code. Direct rendering and LSP rendering of identical selected source must be equal. The VS Code command must display the server’s text verbatim and contain no client-side normalized vocabulary table.

Documentation must present the pipeline as source to language adapter to Rune IR, and RQL to `CodeQuery`, followed by matcher evaluation. It must explicitly say Rune IR is not a raw tree-sitter tree and `CodeQuery` is not Rune IR.

## Idempotence and Recovery

Extraction and rendering are pure operations over source text and can be rerun safely. The REPL command holds captured source only until `:end` or cancellation. LSP requests do not mutate the overlay or workspace index. If a milestone fails, retain the shared renderer API and remove only the uncommitted surface integration; each completed milestone is committed separately on the current branch as required by `.agents/PLANS.md` and the repository instructions.

## Artifacts and Notes

The intended architecture is:

    source -> language adapter -> Rune IR
    RQL    -> CodeQuery
    matcher(CodeQuery, Rune IR)

The canonical public phrase is “Rune IR, Bifrost’s normalized structural intermediate representation.” “RUNE” is not an acronym.

## Interfaces and Dependencies

`src/analyzer/structural/rune_ir.rs` will expose a pure entry point shaped like:

    pub fn render_source_rune_ir(
        language: Language,
        source: &str,
        selection: Option<Range<usize>>,
        limits: RuneIrLimits,
    ) -> Result<RenderedRuneIr, RuneIrError>;

`RenderedRuneIr` contains the complete bounded S-expression string, starter RQL string, selected byte range, and truncation metadata. The exact ownership types may change to fit existing error and range conventions, but both REPL and LSP must call this one entry point.

The private LSP method is `bifrost/runeIr`. Its result contains `codeUnit`, `sourceRange`, `runeIr`, `starterRql`, and `displayText`. `runeIr` is server-rendered text; the extension treats it as opaque.

No new third-party Rust or npm dependency is expected. JSON string escaping should use existing `serde_json`; grammar and structural adapters are already dependencies of the analyzer.

Revision note (2026-07-14): Created the initial self-contained plan after issue and codebase orientation; recorded the Rune IR naming decision and the unavailable Bifrost MCP tooling.

Revision note (2026-07-14 14:05Z): Marked the shared renderer milestone complete and recorded the focused test evidence plus the local PyO3 all-feature linker limitation.

Revision note (2026-07-14 14:25Z): Marked the REPL milestone complete after focused tests and a real piped `bifrost --repl` smoke run proved index-free rendering.

Revision note (2026-07-14 14:50Z): Marked the LSP milestone complete after unit tests and an end-to-end overlay test proved direct-render parity, UTF-16 correctness, and class/field/constructor/method selection.

Revision note (2026-07-14 15:05Z): Marked the VS Code milestone complete after lint, bundle compilation, and all 48 extension tests passed, including verbatim display and manifest context coverage.

Revision note (2026-07-14 15:25Z): Marked documentation complete after Astro checks, production build, and an in-app rendered-page inspection; separated final repository gates into their own remaining milestone.

Revision note (2026-07-14 12:14Z): Completed the final review and validation milestone, recorded the rustup/Homebrew clippy collision and workaround, and strengthened bounded rendering so truncation always leaves balanced S-expressions.
