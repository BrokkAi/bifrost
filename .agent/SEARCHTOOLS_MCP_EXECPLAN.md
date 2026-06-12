# Replace Ad Hoc SearchTools RPC With MCP While Keeping Vibe Tools Built-In

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

After this change, `bifrost` will expose its analyzer-backed search functionality as a real Model Context Protocol (MCP) stdio server instead of a private newline-delimited JSON remote procedure call protocol. The pure-Python `bifrost_searchtools` client in this repository will still present a typed API, and the built-in Vibe tools in `../mistral-vibe` will still exist as first-class built-ins, but the transport between Python and Rust will be standardized. A human should be able to prove this in three ways: run `bifrost` under the official MCP Inspector and see the search tools, run the Python client and get the same rendered summaries and sources as today, and run `uv run vibe` in `../mistral-vibe` and use the built-in `search_symbols`, `get_symbol_summaries`, and related tools successfully.

## Progress

- [x] (2026-03-24T23:05Z) Confirmed the current transport shape: `src/bin/bifrost.rs` implements `--server searchtools` as an ad hoc JSONL request/response loop, and `bifrost_searchtools/client.py` speaks that protocol over `subprocess.Popen`.
- [x] (2026-03-24T23:06Z) Confirmed the current Python rendering and result model split: structured results are produced in Rust by `src/searchtools.rs`, while text formatting and original line/range rendering live in `bifrost_searchtools/models.py`.
- [x] (2026-03-24T23:07Z) Confirmed the current Vibe integration model: the built-in tools in `../mistral-vibe/vibe/core/tools/builtins/bifrost_searchtools.py` call `bifrost_searchtools` directly and should remain built-ins after the transport migration.
- [x] (2026-03-24T23:08Z) Confirmed that Vibe already depends on the official Python MCP SDK package `mcp>=1.14.0`, so the ecosystem pieces for a Python MCP client are already present in the sibling repository.
- [x] (2026-03-24T23:09Z) Chosen manual validation client: the official MCP Inspector will be the known-good external client used to test `bifrost` stdio behavior during this migration.
- [x] (2026-03-24T23:35Z) Replaced the custom request loop in `src/bin/bifrost.rs` with a real MCP stdio server implemented in `src/mcp_server.rs`. The server now handles `initialize`, `notifications/initialized`, `ping`, `tools/list`, and `tools/call`, and publishes `refresh`, `search_symbols`, `get_symbol_locations`, `get_symbol_summaries`, `get_symbol_sources`, `get_file_summaries`, and `skim_files`.
- [x] (2026-03-24T23:38Z) Replaced the private JSONL client logic in `bifrost_searchtools/client.py` with a synchronous MCP client over the same long-lived subprocess. The public Python API and result models stayed unchanged.
- [x] (2026-03-24T23:38Z) Kept the Python typed API and renderers stable. No Vibe built-in arguments or rendered text changed.
- [x] (2026-03-24T23:46Z) Added end-to-end MCP coverage in `tests/bifrost_mcp_server.rs` and kept the existing Python client tests passing against the new server. Direct Vibe runtime checks still show the bifrost built-ins in `chat` and `explore` and confirm wrapper behavior.
- [ ] Validate the final server with the official MCP Inspector and document the exact manual commands in this plan.

## Surprises & Discoveries

- Observation: Vibe-side tool registration was not the problem when the new bifrost tools first appeared to be missing. `ToolManager.available_tools` and the built-in `CHAT` and `EXPLORE` profiles both already include `search_symbols`, `get_symbol_locations`, `get_symbol_sources`, `get_symbol_summaries`, `get_file_summaries`, and `skim_files`.
  Evidence: direct `ToolManager` probes in `../mistral-vibe` with a stub API key reported those six tools in both profiles.

- Observation: the current bifrost transport is a private protocol with its own request envelope and error envelope.
  Evidence: `src/bin/bifrost.rs` currently deserializes `SearchtoolsRequest { id, method, params }` and writes `SearchtoolsSuccess` / `SearchtoolsFailure` as newline-delimited JSON.

- Observation: the Python client is stateful in a way that maps well to MCP. It already owns one long-lived subprocess per project root and serializes all requests behind a lock.
  Evidence: `bifrost_searchtools/client.py` uses one `subprocess.Popen`, a `threading.Lock`, and monotonically increasing request ids.

- Observation: the Python API is generic and multi-language already, so the transport can change without renaming Vibe tools.
  Evidence: `SearchToolsClient` exposes `search_symbols`, `get_symbol_locations`, `get_symbol_summaries`, `get_symbol_sources`, `get_file_summaries`, and `skim_files`; the Vibe built-ins call those exact methods.

- Observation: the official Python MCP stdio client in the installed SDK uses newline-delimited JSON-RPC messages rather than `Content-Length` framing.
  Evidence: `uv run python` inspection of `mcp.client.stdio` in `../mistral-vibe` showed `stdio_client()` reading and writing one JSON-RPC message per line.

- Observation: the targeted Vibe pytest invocation aborts in this sandbox before printing a traceback, but direct runtime import and wrapper checks succeed under a writable `VIBE_HOME`.
  Evidence: `uv run python -m pytest ...` exited with code 134 even with `-n 0`, while a plain `uv run python` script successfully imported `vibe.core.tools.builtins.bifrost_searchtools`, executed `SearchSymbols.run(...)` against a fake client, and confirmed `search_symbols` remained enabled in `CHAT_AGENT_TOOLS` and `EXPLORE`.

## Decision Log

- Decision: switch the Python-to-Rust transport from the current ad hoc JSONL protocol to MCP stdio rather than keeping the private RPC protocol.
  Rationale: the user explicitly wants MCP, and MCP gives a standard server surface that can later be reused by external tools without changing the Python or Vibe APIs.
  Date/Author: 2026-03-24 / Codex + user

- Decision: keep the Vibe tools built-in instead of exposing the bifrost server directly as Vibe MCP tools.
  Rationale: the user wants the search functionality hardwired into Vibe. The MCP boundary will exist between the Python package and the Rust server, not between Vibe and the user.
  Date/Author: 2026-03-24 / Codex + user

- Decision: preserve the current typed Python API and its renderer ownership.
  Rationale: `bifrost_searchtools` already owns line-numbered source rendering and line-ranged summary rendering. MCP should replace only the transport, not force the Vibe tools to learn MCP result formatting.
  Date/Author: 2026-03-24 / Codex

- Decision: use the official MCP Inspector as the manual external validation client and the official Python MCP SDK as the bifrost Python-side transport.
  Rationale: the user explicitly asked not to keep a hand-rolled MCP client because matching mistakes on both sides would be too easy. The final implementation therefore uses the SDK-backed client and only keeps the Rust server transport implementation local.
  Date/Author: 2026-03-24 / Codex + user

- Decision: keep the built-in tool names and arguments unchanged.
  Rationale: the Vibe-side contract is already user-visible and working. The transport migration should be invisible to callers except for better interoperability.
  Date/Author: 2026-03-24 / Codex

## Outcomes & Retrospective

This migration is implemented on the bifrost side. `bifrost --server searchtools` now speaks MCP stdio, `bifrost_searchtools` now uses the official Python MCP SDK over a long-lived subprocess, and the existing Python result models still render the same analyzer-backed summaries and sources. The remaining open item is manual validation with the official MCP Inspector in an environment where `npx @modelcontextprotocol/inspector` is available. Direct Vibe runtime checks still confirm that the built-in wrappers and the `chat` and `explore` tool lists are intact.

## Context and Orientation

This repository already contains the analyzer implementation, a searchtools result layer, a Rust command-line binary, and a pure-Python client package. The current Rust binary entrypoint is `src/bin/bifrost.rs`. In `--server searchtools` mode it creates a `FilesystemProject`, builds a `WorkspaceAnalyzer`, reads JSON lines from stdin, calls functions from `src/searchtools.rs`, and writes JSON lines back to stdout. The searchtools module is where structured result types such as `SearchSymbolsResult`, `SymbolLocationsResult`, `SummaryResult`, `SymbolSourcesResult`, and `SkimFilesResult` are defined. Those results already contain the original line metadata needed by the Python renderers.

The pure-Python package lives in `bifrost_searchtools/`. `bifrost_searchtools/client.py` currently starts `bifrost` as a subprocess and talks to the custom JSON protocol directly. `bifrost_searchtools/models.py` defines the typed Python result objects and all text rendering. That rendering policy is already the desired policy: source blocks are rendered with original file line numbers, and summaries are rendered with original line ranges in the form `N..M: first line`, leaving following lines untouched.

The sibling Vibe repository is `../mistral-vibe`. Its built-in wrappers live in `../mistral-vibe/vibe/core/tools/builtins/bifrost_searchtools.py`. Those wrappers call `bifrost_searchtools.SearchToolsClient` and convert the rendered text into Vibe tool results. They should remain thin wrappers after this migration. Vibe already contains a full MCP stack under `../mistral-vibe/vibe/core/tools/mcp/` and already depends on the `mcp` Python package in `../mistral-vibe/pyproject.toml`. That is useful reference code, but this plan keeps the Vibe built-ins in place instead of registering bifrost as an MCP tool inside Vibe itself.

An MCP server is a process that speaks the Model Context Protocol over stdio or HTTP. In this plan, `bifrost` will become an MCP stdio server. An MCP client is the other side of that protocol. Here, `bifrost_searchtools/client.py` will become an MCP stdio client. The key practical difference from the current protocol is that requests and responses will follow the MCP handshake, tool discovery, and tool invocation rules instead of our custom `{id, method, params}` envelope.

## Plan of Work

The first milestone is the transport spike inside `bifrost`. Keep the existing `--server searchtools` flag surface, but change its behavior from the custom JSON loop to a real MCP stdio session. The server publishes the seven tools `refresh`, `search_symbols`, `get_symbol_locations`, `get_symbol_summaries`, `get_symbol_sources`, `get_file_summaries`, and `skim_files`. The server-side tool handlers continue to call the existing Rust functions in `src/searchtools.rs`, and the Rust result structs remain the source of truth for returned structured data. That part is complete in `src/mcp_server.rs`, which now handles `initialize`, `notifications/initialized`, `ping`, `tools/list`, and `tools/call`.

The second milestone is the Python transport migration. Replace the hand-written `_request()` logic in `bifrost_searchtools/client.py` with an SDK-backed MCP stdio session over the same long-lived subprocess. Do not rewrite the public Python API. `SearchToolsClient.search_symbols()` and the rest keep returning the same typed result objects from `bifrost_searchtools/models.py`. The client still resolves the `bifrost` binary in the same order it did before: explicit path, `BIFROST_SEARCHTOOLS_SERVER`, `PATH`, then repo-local `target/release` and `target/debug`. This part is complete, and the repository now has a minimal `pyproject.toml` declaring `mcp>=1.14.0` so the client and Python tests can be run repeatably with `uv`.

The third milestone is cleanup and stabilization across both repositories. Update the bifrost Python tests to assert MCP-backed client behavior rather than JSONL behavior. Add or update Rust integration tests so `src/bin/bifrost.rs` can be exercised as an MCP server on the vendored fixture projects. In `../mistral-vibe`, keep the built-in tool wrappers thin and ensure no Vibe tool argument or output changed because of the transport swap. If the current Vibe built-in imports `bifrost_searchtools` via a fallback path hack instead of a real dependency, decide whether to keep that for local development or replace it with a direct local dependency. The conservative choice is to keep the current fallback until the MCP migration is complete, then tighten packaging separately in another change.

The last milestone is external validation and documentation. Add the exact command lines to launch `bifrost` under the MCP Inspector and to run a small Python client snippet manually. The manual checks must show the tool list and a successful invocation against `tests/fixtures/testcode-java`. This plan should end with those commands and the expected observable outputs so a future contributor can prove the server still works without relying only on automated tests.

## Concrete Steps

Work from `/home/jonathan/Projects/bifrost` unless a step explicitly says otherwise.

Start by inspecting the current transport and tests again before editing:

    sed -n '1,220p' src/bin/bifrost.rs
    sed -n '1,240p' src/searchtools.rs
    sed -n '1,220p' bifrost_searchtools/client.py
    sed -n '1,220p' bifrost_searchtools/models.py

Implement the MCP server in `src/mcp_server.rs` and route `src/bin/bifrost.rs` to it. No external Rust MCP crate was required because the MCP stdio transport in use here is simple line-delimited JSON-RPC.

Run the Rust checks after the server compiles:

    cargo test
    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings

Add or update Python tests under `python_tests/` to exercise the new MCP-backed client. Use `uv run python` so the `mcp` dependency declared in `pyproject.toml` is present.

Run the Python checks from `/home/jonathan/Projects/bifrost`:

    uv run python -m unittest discover -s python_tests -p 'test_*.py'

Then validate manually with the official MCP Inspector. The exact command will depend on the final MCP server argument shape, but the expected form is:

    npx -y @modelcontextprotocol/inspector /home/jonathan/Projects/bifrost/target/debug/bifrost --root /home/jonathan/Projects/bifrost/tests/fixtures/testcode-java --server searchtools

The Inspector must show at least the six search tools and allow one successful invocation, such as `get_file_summaries` for `A.java`.

After the bifrost side passes, work from `/home/jonathan/Projects/mistral-vibe` to confirm the built-in tool wrappers still behave. In this sandbox the logging path under `~/.vibe` is read-only, so set `VIBE_HOME` to a writable directory first:

    VIBE_HOME=/tmp/vibe-test-home MISTRAL_API_KEY=dummy uv run python -m pytest tests/tools/test_bifrost_searchtools.py tests/core/test_agents.py

For a final manual smoke test, export the binary path and run Vibe:

    export BIFROST_SEARCHTOOLS_SERVER=/home/jonathan/Projects/bifrost/target/debug/bifrost
    cd /home/jonathan/Projects/mistral-vibe
    uv run vibe

Inside the UI, verify that `search_symbols` and `get_symbol_summaries` still appear and return analyzer-backed results.

## Validation and Acceptance

The change is complete only when all of the following are true.

First, the official MCP Inspector can launch `bifrost` in server mode and list the bifrost search tools. A human must be able to invoke at least one tool, such as `get_file_summaries`, against `/home/jonathan/Projects/bifrost/tests/fixtures/testcode-java` and get a structured result instead of a transport error.

Second, the Python client must still be able to do the same work it does today. A human must be able to run a short Python snippet from `/home/jonathan/Projects/bifrost`:

    from bifrost_searchtools import SearchToolsClient
    with SearchToolsClient("tests/fixtures/testcode-java") as client:
        print(client.get_file_summaries(["A.java"]).render_text())

and observe ranged summaries with original source line numbers, not a protocol object dump or a failed MCP handshake.

Third, the Vibe built-ins must still appear in the `chat` and `explore` profiles and still work. Preferred automated proof is `VIBE_HOME=/tmp/vibe-test-home MISTRAL_API_KEY=dummy uv run python -m pytest tests/tools/test_bifrost_searchtools.py tests/core/test_agents.py` from `../mistral-vibe`. In this sandbox that pytest invocation aborts before printing a traceback, so direct runtime proof is also recorded: importing `vibe.core.tools.builtins.bifrost_searchtools`, executing `SearchSymbols.run(...)` against a fake client, and checking that `search_symbols` remains enabled in `CHAT_AGENT_TOOLS` and `EXPLORE`.

Fourth, repository validation must be clean:

    cargo test
    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings
    uv run python -m unittest discover -s python_tests -p 'test_*.py'
    cd /home/jonathan/Projects/mistral-vibe && VIBE_HOME=/tmp/vibe-test-home MISTRAL_API_KEY=dummy uv run python -m pytest tests/tools/test_bifrost_searchtools.py tests/core/test_agents.py

## Idempotence and Recovery

This migration should be implemented additively and kept retry-safe. The safest path is to land the Rust MCP server while the Python client still uses the old transport, then switch the Python client in a second change, then delete the old transport only after both sides pass. If a midpoint change breaks the Python client, point it temporarily back to the old JSON handler and rerun the tests; do not leave the repository in a half-migrated state where the binary only speaks MCP and the client still expects the private protocol.

If the MCP Inspector cannot connect, first run the Rust binary manually and confirm it starts without crashing. Then run the Python client tests locally to determine whether the failure is protocol setup or server startup. Because the tool wrappers in `../mistral-vibe` are intentionally thin, any transport bug should be fixed in `bifrost` or `bifrost_searchtools`, not patched around in the Vibe built-ins.

## Artifacts and Notes

Expected current tool names exposed by the built-in Vibe wrappers:

    search_symbols
    get_symbol_locations
    get_symbol_summaries
    get_symbol_sources
    get_file_summaries
    skim_files

Expected current direct `ToolManager` probe output in `../mistral-vibe`:

    CHAT ['ask_user_question', 'get_file_summaries', 'get_symbol_locations', 'get_symbol_sources', 'get_symbol_summaries', 'grep', 'read_file', 'search_symbols', 'skim_files', 'task']
    EXPLORE ['get_file_summaries', 'get_symbol_locations', 'get_symbol_sources', 'get_symbol_summaries', 'grep', 'read_file', 'search_symbols', 'skim_files']

These outputs matter because they prove the Vibe built-ins are already registered correctly. If they disappear during the migration, the bug is in the transport integration or import path, not in the core Vibe tool registry.

## Interfaces and Dependencies

In `src/bin/bifrost.rs`, there must remain a machine-facing server mode reachable as `bifrost --root PROJECT_ROOT --server searchtools`. After this migration, that mode now starts an MCP stdio server implemented in `crate::mcp_server`.

In `src/searchtools.rs`, keep the existing structured result types as the server-side result payloads:

    SearchSymbolsResult
    SymbolLocationsResult
    SummaryResult
    SymbolSourcesResult
    SkimFilesResult
    RefreshResult

The MCP tool handlers return those shapes through the MCP `tools/call` result path, using `structuredContent` for machine-readable payloads and a pretty-printed `text` content block for human-readable inspection.

In `bifrost_searchtools/client.py`, `SearchToolsClient` must continue to expose these synchronous methods:

    def refresh(self) -> dict[str, Any]
    def search_symbols(self, patterns: list[str], *, include_tests: bool = False, limit: int = 20) -> SearchSymbolsResult
    def get_symbol_locations(self, symbols: list[str], *, kind_filter: SymbolKindFilter = SymbolKindFilter.ANY) -> SymbolLocationsResult
    def get_symbol_summaries(self, symbols: list[str], *, kind_filter: SymbolKindFilter = SymbolKindFilter.ANY) -> SymbolSummariesResult
    def get_symbol_sources(self, symbols: list[str], *, kind_filter: SymbolKindFilter = SymbolKindFilter.ANY) -> SymbolSourcesResult
    def get_file_summaries(self, file_patterns: list[str]) -> FileSummariesResult
    def skim_files(self, file_patterns: list[str]) -> SkimFilesResult

Those methods may change their internals to call MCP, but their signatures and return types should stay stable.

In `bifrost_searchtools/models.py`, preserve the current renderer behavior:

    SourceBlock.render_text() numbers every returned source line with the original file line number.
    SummaryElement.render_text() renders the first line as `N..M: ...` and leaves following lines untouched.

In `../mistral-vibe/vibe/core/tools/builtins/bifrost_searchtools.py`, the built-in classes `SearchSymbols`, `GetSymbolLocations`, `GetSymbolSummaries`, `GetSymbolSources`, `GetFileSummaries`, and `SkimFiles` must remain present and continue to call `SearchToolsClient`.

Revision note: this plan was added after the searchtools feature already existed over a private JSONL transport. The goal of this plan is to replace only the Python-to-Rust transport with MCP stdio while keeping the user-facing Vibe tools and Python typed API stable. The final implementation uses the official Python MCP SDK on the client side and a local Rust server implementation on the server side.
