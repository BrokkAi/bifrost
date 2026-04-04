# Replace Python MCP transport with PyO3 JSON FFI for `bifrost_searchtools`

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/home/jonathan/Projects/bifrost/.agent/PLANS.md).

## Purpose / Big Picture

After this change, Python consumers can call `bifrost_searchtools` without spawning the `bifrost` MCP server. The Python package still exposes the same typed result models and renderer behavior, but it now crosses into Rust through a native Python extension that accepts JSON arguments and returns JSON results. A user can still run `bifrost --server searchtools` as a standalone MCP server, and a Python user can still call `SearchToolsClient(...).get_file_summaries(...)` and observe the same line-numbered output as before.

## Progress

- [x] (2026-04-03 16:05Z) Confirmed the existing split: `src/mcp_server.rs` owned analyzer session state and tool dispatch, while `bifrost_searchtools/client.py` owned the Python MCP transport and the typed result API.
- [x] (2026-04-03 16:22Z) Chosen implementation direction: keep the standalone Rust MCP server, replace only the Python transport with a PyO3 native module, and keep JSON serialization as the only Python/Rust boundary contract.
- [x] (2026-04-03 16:50Z) Added `src/searchtools_service.rs` as the shared Rust service layer that owns workspace state and runs the existing searchtools functions behind `call_tool_value(...)` and `call_tool_json(...)`.
- [x] (2026-04-03 16:58Z) Reworked `src/mcp_server.rs` into a thin MCP adapter over the shared service so standalone MCP behavior remains available.
- [x] (2026-04-03 17:12Z) Added the PyO3 module in `src/python_module.rs`, updated Cargo and Python packaging metadata for a mixed Python/Rust package, and rewrote `bifrost_searchtools/client.py` around the native session.
- [x] (2026-04-03 17:20Z) Updated local Rust/Python tests and repository documentation for the new FFI-backed Python client.
- [ ] Update the sibling `../mistral-vibe` wrappers to remove the old `server_path` terminology and assume an installed `bifrost_searchtools` package instead of a checkout fallback import path.

## Surprises & Discoveries

- Observation: the existing searchtools layer already had the right abstraction boundary for FFI because all public arguments and results are plain `serde` data structures.
  Evidence: `src/searchtools.rs` defines parameter and result structs for every public tool, and the old MCP server already serialized those structs to JSON before sending them over stdio.

- Observation: Python tests that import directly from the repository root need an explicit escape hatch to load a built native library because the source tree does not contain the compiled extension artifact.
  Evidence: the old tests used `sys.path.insert(0, ROOT)` and talked to a subprocess binary; the new client therefore keeps an explicit `library_path=` override for repo-local development and test execution.

## Decision Log

- Decision: keep the standalone `bifrost --server searchtools` MCP server.
  Rationale: external tools still need a standard MCP endpoint, but Python no longer needs subprocess transport overhead.
  Date/Author: 2026-04-03 / Codex

- Decision: use PyO3 rather than `ctypes` or `cffi`.
  Rationale: PyO3 gives a normal Python import surface, exception mapping, and a single native session object without inventing a separate C ABI shim.
  Date/Author: 2026-04-03 / Codex

- Decision: preserve JSON serialization at the Python/Rust boundary.
  Rationale: JSON keeps the FFI simple, avoids exposing Rust analyzer object lifetimes to Python, and reuses the existing `serde` request/response shapes that already power the MCP server.
  Date/Author: 2026-04-03 / Codex

- Decision: use full workspace refreshes for the Python-native path instead of file watching.
  Rationale: it keeps the PyO3 session object simple and avoids coupling Python calls to watcher thread/lifetime behavior, while the existing `refresh()` call pattern in downstream wrappers already tolerates eager refreshes.
  Date/Author: 2026-04-03 / Codex

## Outcomes & Retrospective

The local bifrost repository now has one shared searchtools service that can be reached two ways: through MCP for standalone clients and through PyO3 for Python callers. The public Python API remains synchronous and typed, and the renderer behavior stays in Python. The remaining gap is downstream cleanup in `../mistral-vibe`, which still refers to `server_path` and still assumes it can import `bifrost_searchtools` straight from a sibling checkout.

## Context and Orientation

The Rust analyzer lives under `src/analyzer/` and is wrapped for source-search features in `src/searchtools.rs`. Before this change, `src/mcp_server.rs` owned both the MCP wire protocol and the analyzer session state. The Python package under `bifrost_searchtools/` started a long-lived `bifrost` subprocess, talked to the MCP server, and converted the JSON-shaped result payloads into Python dataclasses defined in `bifrost_searchtools/models.py`.

PyO3 is the Rust library used to expose Rust code as a native Python extension module. In this repository it produces `bifrost_searchtools._native`, which is imported by Python code like any other module. A native session object is a Python-visible wrapper around Rust-owned state. Here that state is the analyzer workspace and optional file watcher, not raw analyzer references or borrowed Rust values.

The new shared service lives in `src/searchtools_service.rs`. It owns the analyzer workspace, optionally owns a file watcher, and accepts one tool name plus one JSON-like arguments value at a time. The standalone MCP server stays in `src/mcp_server.rs`, but it now acts only as a protocol adapter that translates `tools/call` into service calls and wraps the result back into an MCP `structuredContent` payload.

## Plan of Work

First, move the analyzer-session and tool-dispatch logic out of `src/mcp_server.rs` into `src/searchtools_service.rs`. That module must construct the workspace from a project root, decide whether it uses file watching or full refreshes, decode JSON arguments into the existing `src/searchtools.rs` parameter structs, run the existing searchtools functions, and serialize the result structs back into JSON values or JSON strings.

Next, keep `src/mcp_server.rs` but reduce it to JSON-RPC request parsing, tool schema publication, and result wrapping. It should call the shared service for all tool execution so the MCP path and the Python FFI path always return the same machine-readable shapes.

Then add `src/python_module.rs` and update `Cargo.toml` so the crate builds a PyO3 extension module. The native module should expose one Python-visible class, `SearchToolsNativeSession`, with a constructor from the project root, a `call_tool_json(name, arguments_json)` method, and a `close()` method. It should own Rust state behind a mutex and translate Rust service errors into Python exceptions.

After that, rewrite `bifrost_searchtools/client.py` so it no longer imports MCP libraries or starts a subprocess. It should import `bifrost_searchtools._native` when installed normally and optionally load a built debug library from `library_path=` during local testing. The public methods stay the same apart from `server_path` becoming `library_path`, and the typed result/dataclass rendering logic stays untouched in `bifrost_searchtools/models.py`.

Finally, update `pyproject.toml`, `README.md`, and local tests. The packaging metadata must use `maturin` for the mixed Python/Rust build. The documentation must say clearly that the Python package is now native-extension-backed while the standalone MCP server remains available. The Python tests should build the Rust library and pass `library_path=` so they can run from a source checkout. The new Rust test should verify that the shared service returns the same JSON shapes that Python expects.

## Concrete Steps

From `/home/jonathan/Projects/bifrost`, implement the Rust service and PyO3 module by editing:

    Cargo.toml
    src/lib.rs
    src/searchtools_service.rs
    src/python_module.rs
    src/mcp_server.rs

Then update the Python package and tests by editing:

    pyproject.toml
    bifrost_searchtools/client.py
    python_tests/test_searchtools_client.py
    README.md

Finally, add the Rust JSON-boundary test:

    tests/searchtools_service.rs

The sibling-repo follow-up, when access is available, is:

    ../mistral-vibe/vibe/core/tools/builtins/bifrost_searchtools.py

## Validation and Acceptance

Build the Rust library and binary from `/home/jonathan/Projects/bifrost`:

    cargo build --lib --bin bifrost

Acceptance for the standalone path is that `./target/debug/bifrost --root tests/fixtures/testcode-java --server searchtools` still starts and answers valid MCP requests with the same tool list and structured results.

Acceptance for the Python path is that after installing with `maturin develop`, or when passing `library_path=target/debug/libbrokk_analyzer.so` from a checkout, this script:

    python - <<'PY'
    from bifrost_searchtools import SearchToolsClient
    with SearchToolsClient("tests/fixtures/testcode-java") as client:
        print(client.get_file_summaries(["A.java"]).render_text())
    PY

prints line-ranged summaries such as `3..3: public class A` and `8..8: public String method2(String input)` rather than an MCP transport error.

Acceptance for the shared service boundary is that the Rust test `tests/searchtools_service.rs` can call `SearchToolsService::call_tool_json(...)`, parse the returned JSON, and find the same structured fields Python depends on.

## Idempotence and Recovery

These edits are additive and safe to repeat. Rebuilding the Rust crate or rerunning `maturin develop` should replace the native extension in place. If the Python extension import fails, retry by rebuilding the library and either reinstalling with `maturin develop` or passing an explicit `library_path=` to the built debug library. If the standalone MCP server fails after the refactor, the safest recovery path is to inspect `src/searchtools_service.rs` first, because both the MCP adapter and the PyO3 wrapper now depend on it.

## Artifacts and Notes

Important expected Python call shape:

    client._call_tool("get_file_summaries", {"file_patterns": ["A.java"]})

Important expected Rust service call shape:

    service.call_tool_json("get_file_summaries", r#"{"file_patterns":["A.java"]}"#)

Important expected standalone MCP wrapping shape:

    {
      "structuredContent": { ...existing JSON result... },
      "content": [{"type": "text", "text": "{ ...pretty JSON... }"}],
      "isError": false
    }

## Interfaces and Dependencies

In `src/searchtools_service.rs`, define:

    pub struct SearchToolsService { ... }
    impl SearchToolsService {
        pub fn new(root: PathBuf) -> Result<Self, String>;
        pub fn new_for_python(root: PathBuf) -> Result<Self, String>;
        pub fn call_tool_value(&mut self, name: &str, arguments: serde_json::Value)
            -> Result<serde_json::Value, SearchToolsServiceError>;
        pub fn call_tool_json(&mut self, name: &str, arguments_json: &str)
            -> Result<String, SearchToolsServiceError>;
    }

In `src/python_module.rs`, define a PyO3 class:

    #[pyclass(name = "SearchToolsNativeSession")]
    struct SearchToolsNativeSession { ... }

with methods:

    #[new] fn new(root: &str) -> PyResult<Self>;
    fn call_tool_json(&self, name: &str, arguments_json: &str) -> PyResult<String>;
    fn close(&self) -> PyResult<()>;

The required new build dependency is `pyo3` with `abi3-py312` and `extension-module`. The required Python build backend is `maturin`. The Python package keeps using the existing dataclasses in `bifrost_searchtools/models.py`; no renderer logic should move into Rust.

Revision note: this ExecPlan was added because the repository already had an MCP-based searchtools implementation and now needs a second transport for Python. The design intentionally keeps MCP for standalone use while replacing only the Python transport with JSON-over-PyO3.
