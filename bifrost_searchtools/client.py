from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import StrEnum
import os
from pathlib import Path
import shutil
import threading
from typing import Any

from mcp import ClientSession, McpError
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.types import Implementation

from .models import (
    FileSummariesResult,
    SearchSymbolsResult,
    SkimFilesResult,
    SymbolLocationsResult,
    SymbolSourcesResult,
    SymbolSummariesResult,
)


class SearchToolsError(RuntimeError):
    pass


class SymbolKindFilter(StrEnum):
    ANY = "any"
    CLASS = "class"
    FUNCTION = "function"
    FIELD = "field"
    MODULE = "module"


@dataclass(frozen=True)
class _RuntimeState:
    loop: asyncio.AbstractEventLoop
    session: ClientSession
    stop_event: asyncio.Event
    thread: threading.Thread


class SearchToolsClient:
    def __init__(
        self,
        root: Path | str,
        server_path: Path | str | None = None,
    ) -> None:
        self.root = Path(root).expanduser().resolve()
        self._server_path = self._resolve_server_path(server_path)
        self._lock = threading.Lock()
        self._ready = threading.Event()
        self._runtime: _RuntimeState | None = None
        self._startup_error: BaseException | None = None

    def __enter__(self) -> SearchToolsClient:
        self._ensure_started()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            runtime = self._runtime
            self._runtime = None
            self._ready.clear()

        if runtime is None:
            return

        runtime.loop.call_soon_threadsafe(runtime.stop_event.set)
        runtime.thread.join(timeout=5)
        if runtime.thread.is_alive():
            raise SearchToolsError("Timed out while shutting down the bifrost MCP client")

    def refresh(self) -> dict[str, Any]:
        return self._call_tool("refresh", {})

    def search_symbols(
        self,
        patterns: list[str],
        *,
        include_tests: bool = False,
        limit: int = 20,
    ) -> SearchSymbolsResult:
        return SearchSymbolsResult.from_dict(
            self._call_tool(
                "search_symbols",
                {
                    "patterns": patterns,
                    "include_tests": include_tests,
                    "limit": limit,
                },
            )
        )

    def get_symbol_locations(
        self,
        symbols: list[str],
        *,
        kind_filter: SymbolKindFilter = SymbolKindFilter.ANY,
    ) -> SymbolLocationsResult:
        return SymbolLocationsResult.from_dict(
            self._call_tool(
                "get_symbol_locations",
                {"symbols": symbols, "kind_filter": kind_filter.value},
            )
        )

    def get_symbol_summaries(
        self,
        symbols: list[str],
        *,
        kind_filter: SymbolKindFilter = SymbolKindFilter.ANY,
    ) -> SymbolSummariesResult:
        return SymbolSummariesResult.from_dict(
            self._call_tool(
                "get_symbol_summaries",
                {"symbols": symbols, "kind_filter": kind_filter.value},
            )
        )

    def get_symbol_sources(
        self,
        symbols: list[str],
        *,
        kind_filter: SymbolKindFilter = SymbolKindFilter.ANY,
    ) -> SymbolSourcesResult:
        return SymbolSourcesResult.from_dict(
            self._call_tool(
                "get_symbol_sources",
                {"symbols": symbols, "kind_filter": kind_filter.value},
            )
        )

    def get_file_summaries(self, file_patterns: list[str]) -> FileSummariesResult:
        return FileSummariesResult.from_dict(
            self._call_tool("get_file_summaries", {"file_patterns": file_patterns})
        )

    def skim_files(self, file_patterns: list[str]) -> SkimFilesResult:
        return SkimFilesResult.from_dict(
            self._call_tool("skim_files", {"file_patterns": file_patterns})
        )

    def _call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            runtime = self._ensure_started()
            future = asyncio.run_coroutine_threadsafe(
                self._call_tool_async(runtime.session, name, arguments),
                runtime.loop,
            )

        try:
            return future.result()
        except McpError as exc:
            raise SearchToolsError(str(exc)) from exc
        except Exception as exc:
            raise SearchToolsError(f"MCP tool call failed: {exc}") from exc

    async def _call_tool_async(
        self,
        session: ClientSession,
        name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        result = await session.call_tool(name, arguments)
        payload = result.model_dump(by_alias=True, mode="json", exclude_none=True)
        if payload.get("isError"):
            raise SearchToolsError(self._tool_error_message(payload))

        structured = payload.get("structuredContent")
        if not isinstance(structured, dict):
            raise SearchToolsError("MCP tool result did not include structuredContent")
        return structured

    def _ensure_started(self) -> _RuntimeState:
        if self._runtime is not None and self._runtime.thread.is_alive():
            return self._runtime

        self._ready.clear()
        self._startup_error = None
        thread = threading.Thread(target=self._thread_main, daemon=True)
        thread.start()
        self._ready.wait(timeout=10)

        if self._startup_error is not None:
            raise SearchToolsError(
                f"Failed to start bifrost MCP session: {self._startup_error}"
            ) from self._startup_error

        if self._runtime is None:
            raise SearchToolsError("Timed out while starting the bifrost MCP session")
        return self._runtime

    def _thread_main(self) -> None:
        try:
            asyncio.run(self._run_session())
        except BaseException as exc:
            self._startup_error = exc
            self._ready.set()

    async def _run_session(self) -> None:
        params = StdioServerParameters(
            command=str(self._server_path),
            args=["--root", str(self.root), "--server", "searchtools"],
        )

        async with stdio_client(params) as (read, write):
            async with ClientSession(
                read,
                write,
                client_info=Implementation(name="bifrost_searchtools", version="0.1.0"),
            ) as session:
                await session.initialize()
                runtime = _RuntimeState(
                    loop=asyncio.get_running_loop(),
                    session=session,
                    stop_event=asyncio.Event(),
                    thread=threading.current_thread(),
                )
                self._runtime = runtime
                self._ready.set()
                await runtime.stop_event.wait()

    def _tool_error_message(self, payload: dict[str, Any]) -> str:
        content = payload.get("content")
        if isinstance(content, list):
            texts = [
                block.get("text")
                for block in content
                if isinstance(block, dict) and isinstance(block.get("text"), str)
            ]
            if texts:
                return "\n".join(texts)
        return "MCP tool call failed without an error message"

    def _resolve_server_path(self, explicit: Path | str | None) -> Path:
        candidates: list[Path] = []
        if explicit is not None:
            candidates.append(Path(explicit).expanduser())

        env_path = os.environ.get("BIFROST_SEARCHTOOLS_SERVER")
        if env_path:
            candidates.append(Path(env_path).expanduser())

        path_binary = shutil.which("bifrost")
        if path_binary:
            candidates.append(Path(path_binary))

        repo_root = Path(__file__).resolve().parents[1]
        candidates.append(repo_root / "target" / "release" / "bifrost")
        candidates.append(repo_root / "target" / "debug" / "bifrost")

        for candidate in candidates:
            resolved = candidate.expanduser()
            if resolved.exists():
                return resolved.resolve()

        raise SearchToolsError(
            "Could not find the bifrost binary. Set BIFROST_SEARCHTOOLS_SERVER, pass "
            "server_path=..., put bifrost on PATH, or build it under target/debug or target/release."
        )
