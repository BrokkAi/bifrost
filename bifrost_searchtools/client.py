from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import importlib
import importlib.util
import json
from pathlib import Path
import sys
import threading
from types import ModuleType
from typing import Any

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


_NATIVE_MODULE_NAME = "bifrost_searchtools._native"
_NATIVE_MODULE_LOCK = threading.Lock()
_EXPLICIT_NATIVE_MODULE: ModuleType | None = None
_EXPLICIT_NATIVE_PATH: Path | None = None


class SymbolKindFilter(StrEnum):
    ANY = "any"
    CLASS = "class"
    FUNCTION = "function"
    FIELD = "field"
    MODULE = "module"


@dataclass(frozen=True)
class _RuntimeState:
    native: Any


class SearchToolsClient:
    def __init__(
        self,
        root: Path | str,
        library_path: Path | str | None = None,
    ) -> None:
        self.root = Path(root).expanduser().resolve()
        self._library_path = (
            Path(library_path).expanduser().resolve() if library_path is not None else None
        )
        self._lock = threading.Lock()
        self._native = _load_native_module(self._library_path)
        self._runtime: _RuntimeState | None = None

    def __enter__(self) -> SearchToolsClient:
        self._ensure_started()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            runtime = self._runtime
            self._runtime = None

        if runtime is None:
            return

        try:
            runtime.native.close()
        except Exception as exc:
            raise SearchToolsError(f"Failed to close the bifrost native session: {exc}") from exc

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

    def summarize_symbols(self, file_patterns: list[str]) -> SkimFilesResult:
        return SkimFilesResult.from_dict(
            self._call_tool("summarize_symbols", {"file_patterns": file_patterns})
        )

    def skim_files(self, file_patterns: list[str]) -> SkimFilesResult:
        return SkimFilesResult.from_dict(
            self._call_tool("skim_files", {"file_patterns": file_patterns})
        )

    def _call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            runtime = self._ensure_started()
            try:
                payload = runtime.native.call_tool_json(name, json.dumps(arguments))
            except Exception as exc:
                raise SearchToolsError(str(exc)) from exc

        try:
            structured = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise SearchToolsError(
                f"Native searchtools call returned invalid JSON: {exc}"
            ) from exc
        if not isinstance(structured, dict):
            raise SearchToolsError("Native searchtools call did not return a JSON object")
        return structured

    def _ensure_started(self) -> _RuntimeState:
        if self._runtime is not None:
            return self._runtime

        try:
            native = self._native.SearchToolsNativeSession(str(self.root))
        except Exception as exc:
            raise SearchToolsError(
                f"Failed to start the bifrost native session: {exc}"
            ) from exc
        self._runtime = _RuntimeState(native=native)
        return self._runtime


def _load_native_module(library_path: Path | None) -> ModuleType:
    if library_path is None:
        try:
            return importlib.import_module(_NATIVE_MODULE_NAME)
        except ImportError as exc:
            raise SearchToolsError(
                "Could not import bifrost_searchtools._native. Build/install the package "
                "with maturin, or pass library_path=... to a built native library."
            ) from exc

    if not library_path.exists():
        raise SearchToolsError(f"Native library not found: {library_path}")

    global _EXPLICIT_NATIVE_MODULE, _EXPLICIT_NATIVE_PATH
    with _NATIVE_MODULE_LOCK:
        if _EXPLICIT_NATIVE_MODULE is not None and _EXPLICIT_NATIVE_PATH == library_path:
            return _EXPLICIT_NATIVE_MODULE
        if _EXPLICIT_NATIVE_PATH is not None and _EXPLICIT_NATIVE_PATH != library_path:
            raise SearchToolsError(
                "A different bifrost native library is already loaded in this process"
            )

        spec = importlib.util.spec_from_file_location(_NATIVE_MODULE_NAME, library_path)
        if spec is None or spec.loader is None:
            raise SearchToolsError(f"Could not load native module from {library_path}")

        module = importlib.util.module_from_spec(spec)
        previous = sys.modules.get(_NATIVE_MODULE_NAME)
        sys.modules[_NATIVE_MODULE_NAME] = module
        try:
            spec.loader.exec_module(module)
        except Exception as exc:
            if previous is None:
                sys.modules.pop(_NATIVE_MODULE_NAME, None)
            else:
                sys.modules[_NATIVE_MODULE_NAME] = previous
            raise SearchToolsError(
                f"Failed to import native library from {library_path}: {exc}"
            ) from exc

        _EXPLICIT_NATIVE_MODULE = module
        _EXPLICIT_NATIVE_PATH = library_path
        return module
