# Canonical Searchtools Rendering Across MCP and Python

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

Bifrost currently exposes the same searchtools results through two user-facing text surfaces: the MCP server’s `content[0].text` field and the Python client’s `render_text()` methods. Today those surfaces do not share a renderer. MCP falls back to pretty-printed JSON, while Python formats structured results into human-readable text and can optionally prefix line numbers into source and summary output. After this change, both surfaces will use one canonical Rust renderer for the overlapping searchtools outputs, so agents and humans see the same intentional text and the line-number policy lives in one place.

The user-visible proof is straightforward. Calling a source-returning tool over MCP should produce human-readable text instead of pretty JSON, and the Python client should render the same text for the same tool result. When line numbers are disabled, both surfaces should omit per-line numeric prefixes while leaving machine-readable structured fields intact.

## Progress

- [x] (2026-05-21 16:35Z) Confirmed the current split: `src/mcp_server.rs` pretty-prints structured JSON into MCP text, while `bifrost_searchtools/models.py` owns the Python human-readable formatting.
- [x] (2026-05-21 17:08Z) Added `src/searchtools_render.rs` and threaded canonical rendered text through the shared searchtools service output type for the overlapping searchtools results.
- [x] (2026-05-21 17:12Z) Switched the MCP server to consume canonical rendered text for the overlapping searchtools tools while preserving structured payloads and pass-through string tools.
- [x] (2026-05-21 17:16Z) Switched the Python native bridge and `bifrost_searchtools` models to reuse canonical Rust-rendered text while preserving the public Python API and structured field access.
- [x] (2026-05-21 17:35Z) Validated the Rust surfaces with `cargo fmt --check`, `cargo test --test searchtools_service --test bifrost_mcp_server`, and `cargo clippy --all-targets --all-features -- -D warnings`.
- [x] (2026-05-21 17:49Z) Installed clean Python prerequisites through uv (`CPython 3.12.11` plus `maturin`) and verified the Python client with a direct smoke test against the editable extension build.
- [ ] (2026-05-21 17:49Z) Remaining validation gap: `python_tests.test_searchtools_client` still shells out to `cargo build --lib --features python`, which fails on this machine without maturin’s extension-module link path.

## Surprises & Discoveries

- Observation: the raw source in structured searchtools payloads is already unnumbered; the bad behavior is confined to presentation layers.
  Evidence: `src/mcp_server.rs` currently turns structured tool results into `serde_json::to_string_pretty(...)`, while `bifrost_searchtools/models.py` adds the visible `N:` prefixes inside its own `render_text()` helpers.

- Observation: the repository’s direct Python unittest harness is more fragile than the actual editable-extension path.
  Evidence: `python_tests/test_searchtools_client.py` invokes `cargo build --lib --features python`, which failed locally with unresolved Python symbols, while `uv run --python 3.12 --with maturin maturin develop` built and installed the same extension successfully and the client smoke test passed.

## Decision Log

- Decision: treat text rendering as a shared Rust concern for the overlapping searchtools outputs, and keep structured payloads as the machine-readable source of truth.
  Rationale: this removes duplicated presentation policy across MCP and Python without changing the public structured result schema.
  Date/Author: 2026-05-21 / Codex

- Decision: keep Python dataclass parsing intact and attach canonical rendered text as supplemental result metadata rather than replacing the result model layer.
  Rationale: this preserves existing Python field access and minimizes public API churn while still centralizing text rendering.
  Date/Author: 2026-05-21 / Codex

- Decision: keep the MCP fallback to pretty JSON only for unaffected structured tool families instead of forcing every tool through the new renderer immediately.
  Rationale: the user asked to remove conceptual duplication for the overlapping searchtools outputs; limiting the canonical renderer to those outputs keeps the refactor scoped and safe.
  Date/Author: 2026-05-21 / Codex

## Outcomes & Retrospective

The core goal landed. MCP `content[0].text` for the shared searchtools outputs is now intentional human-readable text produced by Rust, and the Python client’s top-level `render_text()` reuses that same canonical rendering instead of recomputing it independently. Structured search results remain unchanged and still carry raw source plus line metadata separately.

The remaining gap is environmental rather than behavioral. The repo’s Python unittest harness still tries to prove the extension by invoking raw `cargo build --lib --features python`, and that path fails locally without maturin’s extension-module link configuration. A uv-managed CPython 3.12 environment plus `maturin develop` verified that the actual extension build and client behavior work correctly, so the feature itself is complete even though that specific local harness path remains brittle.

## Context and Orientation

The shared searchtools behavior starts in `src/searchtools_service.rs`. That module owns a live `WorkspaceAnalyzer`, decodes JSON-like tool arguments, runs Rust handlers, and currently returns either a structured `serde_json::Value` or a plain `String`. The MCP adapter in `src/mcp_server.rs` wraps that output into MCP envelopes. Structured results currently become a pretty-printed JSON text block plus `structuredContent`. String results pass straight through as MCP text. The pure-Python package in `bifrost_searchtools/` talks to Rust through the native PyO3 module in `src/python_module.rs`. It currently requests structured JSON only, then `bifrost_searchtools/models.py` formats that structured data into readable text.

The overlapping user-facing searchtools outputs are the ones the Python client exposes directly: `search_symbols`, `get_symbol_locations`, `get_symbol_summaries`, `get_symbol_sources`, `get_summaries`, `list_symbols`, and `most_relevant_files`. Their Rust result structs live in `src/searchtools.rs`. Non-overlapping tools such as git-history and quality-report tools already produce intentional strings, so they should keep their existing pass-through behavior.

## Plan of Work

Introduce a small render module on the Rust side that knows how to turn the searchtools result structs from `src/searchtools.rs` into the same human-readable text the Python client has been producing. The renderer must accept a `render_line_numbers` option and cover the overlapping outputs only. Keep its behavior intentionally aligned with the existing Python renderings so that the migration changes ownership of the policy rather than the visible format.

In `src/searchtools_service.rs`, replace the loose “structured-or-string” convention with an explicit internal output type that can carry structured JSON plus optional rendered text, or plain text alone. Add helper paths for “decode, run, serialize, and render” for the overlapping searchtools handlers, while leaving existing string-returning tools unchanged. Keep `call_tool_json(...)` returning the historical structured JSON for current callers, and add a second method for the Python bridge that returns both structured JSON and canonical rendered text in one payload.

In `src/mcp_server.rs`, stop pretty-printing structured JSON for the overlapping searchtools results. Instead, consume the shared output type from the service and use the canonical rendered text in MCP `content[0].text`. Keep `structuredContent` unchanged. For tools that still return plain text, keep the existing behavior. For structured tools without a canonical renderer, continue to fall back to pretty JSON so the MCP server remains safe for unaffected tool families.

In `src/python_module.rs` and `bifrost_searchtools/client.py`, add a native call path that retrieves both structured JSON and canonical rendered text. Thread that rendered text into the Python dataclass results as hidden optional state. Update the top-level result classes in `bifrost_searchtools/models.py` so `render_text()` returns the stored canonical text when present and falls back to the existing pure-Python formatting only when older payloads are constructed manually.

## Concrete Steps

Work from `/Users/jonathan/Projects/bifrost`.

Run these commands as validation checkpoints:

    cargo fmt --check
    cargo test --test searchtools_service --test bifrost_mcp_server
    cargo clippy --all-targets --all-features -- -D warnings
    uv run --python 3.12 --with maturin maturin develop
    uv run --python 3.12 python - <<'PY'
    from bifrost_searchtools import SearchToolsClient, SymbolKindFilter
    with SearchToolsClient("tests/fixtures/testcode-java") as client:
        assert "3..52: public class A" in client.get_summaries(["A.java"]).render_text()
        assert "A.method2 (A.java:8..10)" in client.get_symbol_sources(
            ["A.method2"], kind_filter=SymbolKindFilter.FUNCTION
        ).render_text()
    with SearchToolsClient("tests/fixtures/testcode-java", render_line_numbers=False) as client:
        assert "3..52:" not in client.get_summaries(["A.java"]).render_text()
    PY

The repository also contains `python_tests/test_searchtools_client.py`, but on this machine that file’s internal `cargo build --lib --features python` step fails without maturin’s extension-module link path.

The expected outcome is that the MCP tests prove source/summaries now render as human-readable text instead of JSON, and the uv+maturin smoke test proves `render_text()` still matches the established line-number behavior in both modes.

## Validation and Acceptance

Acceptance is behavioral. After the change, an MCP call to `get_symbol_sources` should expose raw source text under `structuredContent.sources[*].text` and a human-readable `content[0].text` that starts with a header like `A.method2 (A.java:8..10)` instead of a JSON object dump. Running the same query through `SearchToolsClient(...).get_symbol_sources(...).render_text()` should yield the same text. Re-running both flows with line numbers disabled should remove the per-line numeric prefixes from rendered source while preserving the structured `start_line` and `end_line` fields.

## Idempotence and Recovery

These edits are additive and safe to retry. The only stateful side effect is rebuilding the native Python extension in `target/`, which can be repeated freely. If the Python bridge fails after the refactor, the rollback path is to inspect the service output type first, because both the MCP server and the Python native module will depend on it.

## Artifacts and Notes

The most relevant existing code paths are:

    src/mcp_server.rs: tool_success_result currently pretty-prints structured JSON into MCP text.
    src/python_module.rs: SearchToolsNativeSession currently exposes only call_tool_json.
    bifrost_searchtools/models.py: render_text() methods currently define the human-readable format and line-number policy.

## Interfaces and Dependencies

In `src/searchtools_service.rs`, define an explicit internal output enum plus a small render-options struct. The enum must distinguish between plain text outputs and structured outputs with optional canonical rendered text. It must be the only output shape used by `src/mcp_server.rs` and the Python bridge for overlapping searchtools tools.

In the shared Rust render module, define a trait or equivalent helper functions that accept the concrete searchtools result structs from `src/searchtools.rs` and a `render_line_numbers` flag, and return `String`.

In `src/python_module.rs`, expose a native method that returns a JSON object containing both the structured result and the canonical rendered text so the Python client does not need a second round-trip.

Revision note: updated after implementation to record the new shared Rust renderer, the successful MCP and service validation, and the local Python build discovery that `maturin develop` succeeds while the repo’s direct cargo-based Python unittest harness remains environment-sensitive.
