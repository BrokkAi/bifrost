# Add Analyzer-Backed SearchTools API and Vibe Integration

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

After this change, `bifrost` will expose a long-lived machine-facing searchtools server backed by the Rust analyzers, and `../mistral-vibe` will consume that functionality through a typed Python API and built-in search tools. A user will be able to run Vibe in a codebase and call analyzer-backed tools such as symbol search, symbol source lookup, file summaries, and skim without shelling out to Brokk or relying on grep-only exploration. The proof is a real `bifrost --server searchtools` subprocess, a Python client package in this repository, and Vibe built-in tools that pass their tests.

## Progress

- [x] (2026-03-24 22:32Z) Re-read `.agent/PLANS.md`, inspected the current `bifrost` tree, and confirmed the worktree was clean before starting.
- [x] (2026-03-24 22:32Z) Inspected Brokk `SearchTools`, `SearchToolsTest`, `AlmostGrep`, `SummaryFragment`, `UsageFinder`, and `BrokkExternalMcpServer` to lock scope and formatting behavior.
- [x] (2026-03-24 22:32Z) Locked scope with the user: analyzer-backed tools only; `scanUsages` out of scope; binary name is `bifrost`; summary/source outputs must use original file line numbers rather than Brokk MCP's snippet-local numbering.
- [x] (2026-03-24 23:18Z) Added filesystem-root project loading, workspace analyzer construction, and the first typed Rust searchtools result layer.
- [x] (2026-03-24 23:44Z) Moved exhaustive searchtools operations onto Rust-side parallel execution paths and parallelized the obvious `MultiAnalyzer` aggregate searches while keeping deterministic output ordering.
- [x] (2026-03-24 23:18Z) Added a real filesystem-backed `Project` implementation and analyzer factory that can build one or many analyzers for an arbitrary root.
- [x] (2026-03-24 23:18Z) Added the JSONL searchtools server mode to the `bifrost` binary.
- [x] (2026-03-24 23:57Z) Added the pure-Python `bifrost_searchtools` package in this repository with a subprocess client, typed result models, and renderers.
- [x] (2026-03-24 23:58Z) Added Vibe built-in tools in `../mistral-vibe` that call the Python client and refresh before each invocation.
- [x] (2026-03-24 23:59Z) Added fixture-backed tests for ranged summaries and end-to-end Python client smoke coverage against the real `bifrost` binary.
- [ ] Run final validation and commit the work in logical units.

## Surprises & Discoveries

- Observation: Brokk `SearchTools` depends on much more than the analyzer, but the analyzer-backed subset is cleanly separable.
  Evidence: `../brokk/app/src/main/java/ai/brokk/tools/SearchTools.java` mixes analyzer methods with git, regex, jq, and XML helpers; the requested scope can ignore the non-analyzer methods.
- Observation: Brokk MCP formatting only line-numbers source-bearing outputs, and it uses snippet-local numbering, not original file numbering.
  Evidence: `../brokk/app/src/main/java/ai/brokk/mcpserver/BrokkExternalMcpServer.java` applies `withLineNumbers(...)` only in `getFileContents`, `getClassSources`, `getMethodSources`, and usage examples; `withLineNumbers` numbers lines from `1..N`.
- Observation: The current `bifrost` code can analyze arbitrary languages, but only test-oriented `Project` implementations exist, so server startup cannot yet point at a normal repository root.
  Evidence: `src/analyzer/project.rs` only defines `TestProject`, which assumes a single language and test fixture semantics.
- Observation: `get_source(..., true)` already expands comments inside analyzers, so correct original line numbering cannot be reconstructed in Python unless Rust also returns enough range metadata.
  Evidence: `src/analyzer/tree_sitter_analyzer.rs` and `src/analyzer/python_analyzer.rs` both adjust source start offsets when comments are included.
- Observation: the first Rust searchtools layer still performs several exhaustive whole-workspace scans serially above the analyzer, even though the analyzer snapshot and current search operations are `Send + Sync`.
  Evidence: `src/searchtools.rs` iterates serially over symbols and files for `search_symbols`, `get_symbol_locations`, `get_symbol_summaries`, `get_symbol_sources`, `get_file_summaries`, and `skim_files`; `TreeSitterAnalyzer::search_definitions` also filters declarations serially.

## Decision Log

- Decision: Use a long-lived stdio subprocess instead of PyO3 for the first Python integration.
  Rationale: the user accepted the subprocess model after discussing the tradeoff, and it keeps the Rust analyzer fully native while still allowing a typed Python API and later reuse for MCP or other integrations.
  Date/Author: 2026-03-24 / Codex + user
- Decision: The machine-facing executable will be named `bifrost` and the searchtools transport will be selected with `--server searchtools`.
  Rationale: the user prefers the short executable name; the explicit mode flag preserves room for future CLI roles without inventing another binary name.
  Date/Author: 2026-03-24 / Codex + user
- Decision: Exclude Brokk compatibility alias names from the Python API.
  Rationale: the user explicitly asked to omit compatibility aliases and wants a pythonic API around `bifrost`, not a Java-era wrapper surface.
  Date/Author: 2026-03-24 / Codex + user
- Decision: Use original file line numbers for both source blocks and summary lines, even though Brokk MCP currently numbers returned source snippets from `1`.
  Rationale: the user called out the snippet-local numbering as a bug and wants every summarized or source-rendered line to map back to the real file line.
  Date/Author: 2026-03-24 / Codex + user
- Decision: Keep `scanUsages` out of scope for this feature.
  Rationale: the user does not want to tackle the LLM-backed usage path right now, and the remaining analyzer-backed surface is still large enough to be useful in Vibe.
  Date/Author: 2026-03-24 / Codex + user
- Decision: exhaustive searchtools operations should be parallelized on the Rust side, preferably inside analyzer or searchtools helpers rather than in Python/Vibe wrappers.
  Rationale: the user explicitly wants Brokk-like multithreaded exhaustive searches, and the immutable analyzer snapshots already support safe parallel reads.
  Date/Author: 2026-03-24 / Codex + user

## Outcomes & Retrospective

The feature is implemented across Rust, Python, and Vibe. The remaining work is administrative: finish the final validation pass, then split the changes into logical commits. The main behavior risks found during implementation were a Rust-regex incompatibility in `strip_params`, overloaded-source duplication in `get_symbol_sources`, and the need to keep ranged summaries independent from opaque analyzer skeleton strings; each of those is now covered by tests.

## Context and Orientation

This repository already contains the Rust analyzers under `src/analyzer/`, including every single-language analyzer and `src/analyzer/multi_analyzer.rs`. The current public binaries only include `src/bin/summarize.rs`, which is Java-only and fixture-oriented. There is no server mode, no general-purpose project loader for arbitrary workspaces, and no Python package in this repository.

The target consumer is `../mistral-vibe`, a Python application with built-in tool classes under `../mistral-vibe/vibe/core/tools/builtins/`. Those tool classes are thin wrappers around typed Python APIs and return Pydantic result models for UI display. The Vibe tool registry auto-discovers built-in tool files, and the chat/explore agent profiles choose which built-ins are first-class by name in `../mistral-vibe/vibe/core/agents/models.py`.

“Searchtools server” in this document means a long-lived subprocess that reads and writes one JSON object per line on stdio. “Original file line numbers” means the line numbers from the source file in the repository being analyzed, not `1..N` numbering relative to a returned snippet. “Summary line” means a rendered line in the summary output, such as a declaration header or summarized member line.

## Plan of Work

First, add runtime support in `bifrost` for analyzing a real filesystem root. Extend `src/analyzer/project.rs` with a normal project implementation for arbitrary roots. It must enumerate all files under the root, filter analyzable files by language extension, and allow server code to build single-language analyzers or a `MultiAnalyzer` from the same root. Add a small factory layer in the Rust crate so the server does not need language-specific construction logic scattered through the binary.

Next, add a searchtools module on the Rust side that defines the JSON protocol and the typed result structures. The server should return structured results, not pre-rendered text. The result structures must include file paths, code unit identity, kinds, and original source ranges. For source-returning methods, compute source text and original start/end lines in Rust so the Python layer does not need to guess where comment-expanded text began. For summary-returning methods, return already-split summary lines paired with their original line numbers. This avoids trying to reverse-map rendered skeleton blocks back to the file in Python.

Then add the new machine-facing `bifrost` mode. The existing `src/bin/summarize.rs` should remain, and a new binary entry point should be created for `bifrost`. Its job is to parse `--root` and `--server searchtools`, build the analyzer once, then loop on stdin handling JSONL requests until EOF. `refresh` replaces the stored analyzer with `update_all()`. All other methods delegate to the structured searchtools helpers. Exhaustive search methods must use Rust-side parallel traversal when they need to touch many files or declarations, but they must still normalize final output ordering deterministically before responding.

After the Rust side is stable, add a pure-Python package at the repository root named `bifrost_searchtools`. It should use only the standard library for the subprocess transport and typed dataclasses for result models. The client owns subprocess lifecycle, request IDs, JSON serialization, error translation, and all text rendering. Renderers should follow the policy locked with the user: `search_symbols`, `get_symbol_locations`, and `skim_files` remain compact and unnumbered; summary outputs prefix each summarized line with the original file line number; source outputs prefix each source line with the original file line number.

Finally, wire the client into `../mistral-vibe`. Add one built-in tool file per public operation or a single module containing the tool classes, following Vibe’s normal `BaseTool`/Pydantic patterns. Each tool should create or reuse a client for `Path.cwd()`, call `refresh()`, invoke the underlying client method, and return a result model that mostly contains rendered text. Add concise UI formatting hooks and update the agent profiles so these tools are built in to chat and explore flows. Because there is no portable relative path dependency format in `pyproject.toml`, the Vibe integration should attempt a normal `import bifrost_searchtools` first and then fall back to loading it from the sibling `../bifrost` checkout when running in a sibling-repo development setup.

## Concrete Steps

Work from `/home/jonathan/Projects/bifrost` unless noted otherwise.

1. Add `FilesystemProject` and analyzer-construction helpers in `src/analyzer/project.rs` and a new small factory module.

2. Add Rust searchtools protocol and server code, then create the new `src/bin/bifrost.rs` binary.

3. Add Python packaging files and the `bifrost_searchtools` package at the repository root.

4. Switch to `/home/jonathan/Projects/mistral-vibe` and add built-in tools plus tests that exercise the new package.

5. Run validation commands:

       cd /home/jonathan/Projects/bifrost
       cargo test
       cargo fmt --check
       cargo clippy --all-targets --all-features -- -D warnings

       cd /home/jonathan/Projects/bifrost
       python -m unittest discover -s python_tests -p 'test_*.py'

       cd /home/jonathan/Projects/mistral-vibe
       uv run pytest tests/tools/test_bifrost_searchtools.py

If `uv run pytest` fails because dependencies are unavailable locally, document that failure and validate the Vibe module with the narrowest available local command instead.

## Validation and Acceptance

Acceptance is behavioral. After implementation:

- Running `bifrost --root tests/fixtures/testcode-java --server searchtools` should start a quiet JSONL server that replies to `search_symbols` and `get_symbol_sources` requests with structured JSON.
- A Python script that imports `bifrost_searchtools`, opens `SearchToolsClient(root=...)`, and calls `get_symbol_sources(["A"])` should return source text whose left margin line numbers match the real file lines in `tests/fixtures/testcode-java/A.java`.
- The same Python client calling `get_file_summaries(["A.java"])` should return summary lines prefixed with real source line numbers rather than `1..N`.
- Vibe should discover the new built-in tools, and the chat/explore tool lists should include them by name.
- Running the Vibe tool tests should demonstrate that each tool refreshes the analyzer and returns rendered text successfully.

## Idempotence and Recovery

All implementation steps are additive and safe to repeat. The server should rebuild analyzer state from the repository root each time it starts, and `refresh` should be safe to call repeatedly. If the sibling-repo import fallback in Vibe fails, the tools should raise a clear error telling the user that `bifrost_searchtools` could not be imported or the sibling `bifrost` checkout could not be found. If a validation command fails midway, fix the underlying issue and rerun the same command; no migration or destructive cleanup is required.

## Artifacts and Notes

Expected manual server transcript shape:

    {"id":"1","method":"search_symbols","params":{"patterns":[".*A.*"],"include_tests":false,"limit":20}}
    {"id":"1","ok":true,"result":{"files":[...]}}

Expected rendered summary shape:

    15: class A {
    17:   int value;
    22:   void run()

Expected rendered source shape:

    ```java
    15: class A {
    16:     int value;
    17:
    18:     void run() {
    19:         ...
    20:     }
    21: }
    ```

## Interfaces and Dependencies

In the Rust crate, add a new public module that defines the protocol-facing types. The exact file name can be chosen for clarity, but the end state must include:

    pub struct SearchtoolsRequest { pub id: String, pub method: String, pub params: serde_json::Value }
    pub struct SearchtoolsSuccess<T> { pub id: String, pub ok: bool, pub result: T }
    pub struct SearchtoolsError { pub code: String, pub message: String }

The Rust crate must also expose a factory function that can build either a single analyzer delegate or a `MultiAnalyzer` from an `Arc<dyn Project>` and `AnalyzerConfig`.

The Python package must export:

    class SearchToolsClient:
        def __init__(self, root: Path | str, server_path: Path | str | None = None) -> None: ...
        def refresh(self) -> None: ...
        def search_symbols(...) -> SearchSymbolsResult: ...
        def get_symbol_locations(...) -> SymbolLocationsResult: ...
        def get_symbol_summaries(...) -> SymbolSummariesResult: ...
        def get_symbol_sources(...) -> SymbolSourcesResult: ...
        def get_file_summaries(...) -> FileSummariesResult: ...
        def skim_files(...) -> SkimFilesResult: ...

The Vibe built-in tools must remain thin wrappers over this client. They should not duplicate analyzer logic, line-number logic, or rendering logic that already lives in `bifrost_searchtools`.

Revision note: this initial ExecPlan records the final scope after design discussion, including the decision to use the `bifrost` subprocess transport, to exclude `scanUsages`, and to diverge from Brokk MCP by rendering original file line numbers instead of snippet-local numbering.
