# Add schema-driven live RQL linting and hover help

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document must be maintained in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

Bifrost users can run `.rql` query files from VS Code, but mistakes are currently discovered only after pressing Play. After this work, an unsaved `bifrost-rql` document receives quiet, debounced diagnostics for completed syntax and static query errors, and hovering any recognized query token explains its meaning and expected value. Validation is source-only: it does not execute structural search or access indexed workspace data. A JSON-shaped CodeQuery is supported only inside a document already identified as `bifrost-rql`; ordinary JSON documents are never inspected.

The implementation also removes the current maintenance trap in which the S-expression parser, JSON decoder, REPL help, and editor grammar each carry partially overlapping key lists. A declarative Rust schema requires every accepted form or property to declare its spellings, value shape, help text, and handling category. Generated enums and exhaustive matches make a newly registered key fail compilation until its behavior is handled.

## Progress

- [x] (2026-07-13 10:37Z) Investigated issue #711, the RQL parser/decoder, REPL metadata, LSP custom-request path, VS Code query action, and extension tests; refreshed remote refs and confirmed the issue branch is 0/0 against its upstream and `origin/master`.
- [x] (2026-07-13 10:37Z) Milestone 0: created this ExecPlan with the source-schema, diagnostic, hover, LSP, and extension design.
- [x] (2026-07-13 10:57Z) Milestone 1: centralized query vocabulary/help metadata and added byte-spanned RQL/JSON source analysis, multi-diagnostic validation, `CodeQuery::from_source`, schema-backed REPL help/completion, and focused Rust tests.
- [ ] Milestone 2: expose non-executing validation and hover requests through LSP, make query execution use the shared source parser, and add integration tests.
- [ ] Milestone 3: add debounced/cancellable VS Code diagnostics and hover integration with pure unit-tested lifecycle logic.
- [ ] Milestone 4: document the maintenance contract in `AGENTS.md`, run focused/full validation, manually inspect the Extension Development Host, and complete review fixes.

## Surprises & Discoveries

- Observation: The Bifrost MCP code-intelligence endpoints named by the repository skills are not exposed in this session.
  Evidence: Repository exploration uses the skills' documented targeted `rg` and exact-source fallback.

- Observation: The server sends its initialize response before workspace construction but enters the request loop only after workspace indexing completes.
  Evidence: `src/lsp/server.rs::run_with_connection` calls `initialize_finish`, constructs `ServerState`, and only then calls `main_loop`. This issue keeps validation independent of analyzer data but does not refactor cold-start request servicing.

- Observation: The current REPL duplicates incomplete query help in `FORMS` and `role_doc`, while the S-expression and JSON decoders keep separate raw accepted-key lists.
  Evidence: `src/bin/bifrost/code_query_repl.rs`, `src/analyzer/structural/query/sexp.rs`, and `src/analyzer/structural/query/decode.rs` each encode overlapping vocabulary.

- Observation: The required `git rebase` was rejected by the execution environment because the issue branch was already 0/0 with its upstream.
  Evidence: A subsequent permitted `git fetch` confirmed `HEAD...@{upstream}` and `HEAD...origin/master` are both `0 0`; no history update is needed.

- Observation: `json-spanned-value` preserves exact half-open ranges for both object keys and nested values, and rejects duplicate object fields by default.
  Evidence: Source validation tests assert key/value slices directly, while the dependency's default `Settings` keeps `allow_duplicate_keys` false.

## Decision Log

- Decision: Use declarative `macro_rules!` registries, not a procedural field attribute.
  Rationale: RQL wrappers, aliases, predicate forms, kind heads, and role properties do not map one-to-one to `CodeQuery` struct fields. Declarative registries can require metadata and generate exhaustive enums/lookups without adding a proc-macro crate.
  Date/Author: 2026-07-13 / dave + Codex.

- Decision: Validate JSON-shaped text only inside `bifrost-rql` documents.
  Rationale: The language identifier is a reliable ownership signal; heuristics over ordinary `.json` files would create false positives.
  Date/Author: 2026-07-13 / dave + Codex.

- Decision: Use `json-spanned-value` 0.2.2 for JSON syntax and path spans.
  Rationale: Building a partial JSON parser would violate the repository's structured-parser policy. The crate represents object keys and nested values with byte spans while remaining compatible with serde JSON values.
  Date/Author: 2026-07-13 / dave + Codex.

- Decision: Suppress genuinely incomplete source and report completed invalid source as errors.
  Rationale: Empty input, an open delimiter, an unfinished string, a trailing property, or serde's EOF category are normal intermediate editor states. Extra closing delimiters, unknown forms/properties, invalid completed values, and semantic CodeQuery failures are actionable.
  Date/Author: 2026-07-13 / dave + Codex.

- Decision: Hover covers wrappers, predicate forms, normalized kinds, roles/properties, aliases, and constrained values in both RQL and JSON-shaped query text.
  Rationale: The same metadata can provide broad useful help without duplicating descriptions in TypeScript.
  Date/Author: 2026-07-13 / dave + Codex.

## Outcomes & Retrospective

Milestone 1 is complete. A required-metadata macro registry now owns RQL forms/properties and JSON fields, while the kind/role registries own their help and shapes. Parser and decoder dispatch use generated enums with exhaustive matches, the REPL consumes the same descriptions, and source APIs provide byte ranges, independent diagnostics, hover tokens, and JSON-or-RQL execution. The 38 focused library tests and 11 focused REPL tests pass.

## Context and Orientation

`CodeQuery` is the validated, language-neutral query used by structural search. Its Rust types and JSON decoder live under `src/analyzer/structural/query/`. The experimental Rune Query Language (RQL) parser in `sexp.rs` currently lowers an unspanned hand-written `Expr` tree into `serde_json::Value`, then calls `CodeQuery::from_json`. Errors are strings for RQL and `QueryError { path, message }` for JSON, so neither route can currently produce precise editor ranges.

The normalized kind and role vocabulary lives in `src/analyzer/structural/kinds.rs`. It already uses declarative macros to generate enums, labels, and all-entry slices. The REPL binary in `src/bin/bifrost/code_query_repl.rs` separately defines help for selected forms and every role. This plan moves language help into library metadata so both REPL and LSP use the same descriptions.

The LSP server in `src/lsp/server.rs` already handles the private `bifrost/queryCode` request. That request accepts unsaved query text but immediately executes it against `WorkspaceAnalyzer`. The new validation and hover requests will be separate handlers whose signatures do not receive a workspace. They return normal LSP ranges, whose character offsets count UTF-16 code units; existing helpers in `src/lsp/conversion.rs` convert byte offsets correctly.

The VS Code extension in `editors/vscode/src/extension.ts` owns the language client and the Play command. Pure query-request types and helpers live in `rql_query.ts`, and Node's built-in test runner tests the compiled TypeScript without loading the `vscode` module. New lifecycle logic must therefore remain dependency-injected and unit-testable outside the extension host.

## Plan of Work

Milestone 1 creates a query-schema module beside the decoders. Declarative entries generate typed identifiers, accepted spellings/aliases, signatures, descriptions, and value-shape/handler categories for query wrappers and pattern predicates. The existing kind and role declarations gain descriptions and role value shapes. Parser dispatch and decoder known-field checks use typed lookup rather than raw string lists; handler matches are exhaustive. The macro syntax requires help and shape fields, while behavior tests assert unique spellings and useful metadata.

The RQL parser becomes token-based and span-aware. Every token and expression carries a half-open UTF-8 byte range. Parser failures distinguish `Incomplete` from `Invalid`; public `from_sexp` retains its current string-error contract while the new source analysis API preserves structured failures. Syntactically complete expressions are traversed with schema metadata, accumulating independent unknown-field, duplicate-field, and value-shape diagnostics and lowering valid fragments to canonical JSON. A path-to-span table maps later `QueryError.path` failures back to the closest exact property/value or enclosing form.

JSON-shaped source is selected only when the first non-whitespace byte is `{`. `json-spanned-value` parses a recursively spanned value, which is converted to `serde_json::Value` while recording JSON-path spans for keys and values. EOF parse errors are incomplete; other parse errors become source diagnostics. Both syntaxes call the same CodeQuery decoder after structural checks. `CodeQuery::from_source` returns a query for execution, while `validate_query_source` returns all attributable diagnostics and `query_source_help_at` returns the recognized token range plus Markdown-ready signature/help.

Milestone 2 moves private query request types and handlers into a focused LSP module. `bifrost/validateQuery` accepts `{ query }` and returns diagnostics with UTF-16 ranges, error severity, stable codes, and source `Bifrost RQL`. `bifrost/queryHover` accepts `{ query, position }` and returns a standard `Hover` or null. Neither handler receives `ServerState`, `WorkspaceAnalyzer`, or `Project`. `bifrost/queryCode` switches from `from_sexp` to `from_source`, keeping the editor's validation and Play interpretation aligned.

Milestone 3 adds an `RqlValidationController` in TypeScript. It tracks a timer, cancellation source, and generation/version per document URI. Open and change schedule validation after 300 milliseconds; a newer edit cancels scheduled and in-flight work. Responses publish only when URI, language identifier, document version, and generation remain current. Closing, stopping the client, or changing away from `bifrost-rql` cancels work and deletes diagnostics. Background cancellation and transport errors never show user notifications. A registered RQL hover provider sends current unsaved text and cursor position to the hover request and honors VS Code's cancellation token.

Milestone 4 adds an `AGENTS.md` RQL maintenance paragraph requiring schema-first additions and synchronized grammar/behavior tests. Focused Rust, LSP, and Node suites run first, followed by formatting, all-target/all-feature clippy, and the full `nlp,python` suite with semantic indexing disabled where appropriate. An Extension Development Host verifies inline squiggles, Problems entries, hover Markdown, quiet incomplete edits, stale-response behavior, JSON-shaped `.rql` queries, ignored ordinary JSON, and Play consistency. Review findings are fixed and revalidated before completion.

## Concrete Steps

From the repository root, implement and verify Milestone 1 with:

    cargo fmt
    BIFROST_SEMANTIC_INDEX=off cargo test analyzer::structural::query --lib
    BIFROST_SEMANTIC_INDEX=off cargo test --bin bifrost code_query_repl
    git diff --check

Implement and verify Milestone 2 with focused names added to `tests/bifrost_lsp_server.rs`:

    BIFROST_SEMANTIC_INDEX=off cargo test --test bifrost_lsp_server rql_query
    git diff --check

Implement and verify Milestone 3 from the extension directory:

    npm test

Run final repository gates from the root:

    cargo fmt
    cargo clippy --all-targets --all-features -- -D warnings
    BIFROST_SEMANTIC_INDEX=off cargo test --all-targets --features nlp,python
    npm --prefix editors/vscode test
    git diff --check

After each milestone, update all living sections in this plan, stage only files changed for that milestone, and commit with a multiline message explaining the user-visible result and why the design preserves a single schema authority. Do not push or open a pull request.

## Validation and Acceptance

In a `.rql` editor, `(call :calle (name "run") :args "bad")` produces precise errors for unknown `:calle` and the wrong `:args` value shape. `(call :callee` and an unfinished quoted string produce no transient Problems entry. Closing the expression with an invalid value produces an error, and fixing it clears the collection after the debounce.

Hovering `call`, `:callee`, `name`, `result-detail`, `full`, a normalized kind, role alias, or language label returns the relevant signature and description over the exact token. Hovering a comment, string body, punctuation, or unknown token returns no result. The same schema documentation applies to keys and constrained values in JSON-shaped text saved as `.rql`.

A JSON-shaped CodeQuery inside `.rql` receives precise syntax/static diagnostics and runs through Play. A document whose language identifier is `json` triggers neither validation nor hover even when it contains `match`, `kind`, or other CodeQuery-looking keys.

Rapid edits never allow an older response to overwrite newer diagnostics. Closing a document removes its Problems entries. Restarting/stopping the language client cancels validation cleanly. Server validation and hover functions can be tested without constructing or indexing a workspace, demonstrating that they do not execute structural search.

## Idempotence and Recovery

Parser, LSP, and extension tests use in-memory strings or temporary projects and are safe to rerun. Cargo and npm commands write only ignored build artifacts. If the new JSON dependency cannot provide recursively spanned keys/values on all supported targets, stop rather than write a JSON mini-parser; record the evidence and choose another structured parser. If a milestone introduces a semantic regression in `CodeQuery::from_json` or `from_sexp`, revert that milestone's local edits or fix the shared decoder before continuing.

Keep milestone commits bisectable. Never stage unrelated files or use `git add -A`. A semantic merge conflict is a blocker; do not resolve it by changing query behavior without recording the decision here.

## Artifacts and Notes

The branch began at commit `0018134b` and was 0/0 against both `origin/711-add-live-rql-query-linting-in-vs-code` and `origin/master` after the 2026-07-13 fetch. Store focused test results, manual Extension Development Host observations, review findings, and milestone commit hashes in the living sections above.

## Interfaces and Dependencies

The library exposes source-oriented query analysis types that contain UTF-8 byte ranges and no LSP dependency. The intended public shape is `CodeQuery::from_source(&str) -> Result<CodeQuery, QuerySourceError>`, `validate_query_source(&str) -> Vec<QuerySourceDiagnostic>`, and `query_source_help_at(&str, byte_offset) -> Option<QuerySourceHelp>`. Exact supporting type names may be refined while keeping these responsibilities separate.

The private LSP wire contracts are:

    bifrost/validateQuery
    params: { query: string }
    result: { diagnostics: Array<{ range, severity, code, source, message }> }

    bifrost/queryHover
    params: { query: string, position: { line, character } }
    result: Hover | null

Add `json-spanned-value = "0.2.2"` to the Rust dependencies. Do not add a TypeScript schema copy or a generic JSON-language selector.

Revision note, 2026-07-13: Initial ExecPlan created from issue #711, the existing query/parser/LSP/extension implementation, and the approved schema-driven diagnostics, all-token hover, `.rql`-only JSON ownership, and milestone-commit decisions.

Revision note, 2026-07-13: Milestone 1 completed with macro-generated schema metadata, exhaustive parser/decoder handling, spanned RQL and JSON source analysis, shared execution parsing, and schema-backed REPL documentation.
