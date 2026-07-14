# Add schema-driven RQL diagnostic suggestions and quick fixes

This ExecPlan is a living document. Maintain it according to `.agents/PLANS.md`.

## Purpose / Big Picture

RQL authors will receive conservative spelling suggestions and standard editor quick fixes for schema mistakes in `.rql` documents. JSON-shaped CodeQuery content is supported only inside those owned RQL documents; ordinary JSON remains untouched.

## Progress

- [x] (2026-07-14) Confirmed the issue branch is current and mapped validation, schema, and LSP document-sync seams.
- [x] (2026-07-14) Added schema-backed spelling selection, structured source fixes, and registry iteration for constrained values.
- [x] (2026-07-14) Served current-buffer `bifrost-rql` quick fixes through `textDocument/codeAction`.
- [x] (2026-07-14) Added focused source/LSP regression coverage and ran Rust checks. The VS Code suite could not run because this worktree has no installed TypeScript toolchain.
- [x] (2026-07-14) Addressed guided-review findings: RQL buffers now participate in normal LSP sync, edits carry the current document version, ranges are end-exclusive, and wrapping is limited to fully recognizable values.
- [x] (2026-07-14) Corrected the CI test fixture for an ambiguous language-extension typo: `.rts` ties Rust's `.rs` with TypeScript's `.ts`, so it now verifies suppression while `.rss` verifies the unambiguous Rust fix.

## Decision Log

- Decision: depend directly on `strsim` 0.11.1 for Damerau-Levenshtein distance.
  Rationale: it is already present transitively and avoids maintaining a typo metric locally.
  Date/Author: 2026-07-14 / Codex
- Decision: compute standard code actions from the current versioned open document instead of custom diagnostic data.
  Rationale: the extension owns the diagnostic collection, so current source is the reliable stale-safe authority.
  Date/Author: 2026-07-14 / Codex
- Decision: only wrap scalar values where the enclosing list structure is unambiguous.
  Rationale: automatic fixes must not invent semantic objects or map entries.
  Date/Author: 2026-07-14 / Codex
- Decision: validate a candidate pattern or query step before offering a container-wrapping fix.
  Rationale: a syntactically object-shaped value can still contain unknown fields, invalid roles, or malformed nested patterns that must remain manual fixes.
  Date/Author: 2026-07-14 / Codex

## Context and Orientation

`src/analyzer/structural/query/source.rs` validates RQL and JSON-shaped source while retaining byte ranges. `schema.rs` and `kinds.rs` are the authoritative vocabulary registries. `src/lsp/server.rs` stores open, versioned buffers and converts diagnostics to UTF-16 LSP positions. The VS Code extension limits validation to `bifrost-rql` documents.

## Plan of Work

Add a candidate selector that compares only labels valid in the current syntax position, deduplicates aliases by canonical spelling, and emits a fix only for a unique candidate within the conservative threshold. Add replacement and paired-delimiter source fixes to diagnostics. Extend LSP capability and dispatch to revalidate an open `bifrost-rql` buffer during a code-action request, generating standard quickfix workspace edits from its current diagnostics. Cover spelling, ambiguity, syntax-specific wrapping, UTF-16 conversion, aliases, and stale unsaved text.

## Validation and Acceptance

Run `cargo fmt`, focused source and `bifrost_lsp_server` tests with `--features nlp,python`, `cargo clippy --all-targets --all-features -- -D warnings`, and `npm test` in `editors/vscode`. A malformed `(call :calle ...)` should offer a `:callee` quick fix, while a regular JSON document should receive neither diagnostics nor fixes.

## Outcomes & Retrospective

Validation now emits canonical schema suggestions only when a unique nearby spelling exists, and it carries replacement or paired wrapping edits without changing the unsaved source. The LSP server advertises `quickfix` code actions, retains the document language id, and recomputes fixes from the latest open RQL buffer so stale editor diagnostics cannot produce edits. The VS Code client now synchronizes `bifrost-rql` documents to that server; returned edits use `documentChanges` with the current version, and wrapping is withheld unless the value itself validates as a single pattern or query step.

## Surprises & Discoveries

- Observation: the existing extension publishes a private diagnostic collection, so generic LSP diagnostic data is not a suitable source of code-action state.
  Evidence: `vscodeDiagnostic` copies only range, message, code, and source.
- Observation: all-feature tests link the Python feature into a missing arm64 Python runtime in this worktree.
  Evidence: `cargo test --features nlp,python` failed during linking on unresolved `_Py*` symbols; feature-enabled `cargo check` and strict all-feature Clippy passed in an isolated matching toolchain target.
- Observation: `editors/vscode` has no local `node_modules` or `tsc` binary.
  Evidence: `npm test` reached the lint script and failed with `tsc: command not found`.
