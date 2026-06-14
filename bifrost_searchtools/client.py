from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import importlib
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import sys
import threading
from types import ModuleType
from typing import Any, overload

from .models import (
    FileSummariesResult,
    MostRelevantFilesResult,
    SemanticSearchResult,
    SemanticSearchStatus,
    ScanUsagesResult,
    SearchSymbolsResult,
    SkimFilesResult,
    SymbolAncestorsResult,
    SymbolLocationsResult,
    SymbolSourcesResult,
)


class SearchToolsError(RuntimeError):
    pass


_NATIVE_MODULE_NAME = "bifrost_searchtools._native"
_NATIVE_MODULE_LOCK = threading.Lock()
_EXPLICIT_NATIVE_MODULE: ModuleType | None = None
_EXPLICIT_NATIVE_PATH: Path | None = None
_UNSET = object()


class SymbolKindFilter(StrEnum):
    ANY = "any"
    CLASS = "class"
    FUNCTION = "function"
    FIELD = "field"
    MODULE = "module"


@dataclass(frozen=True)
class _RuntimeState:
    native: Any


@dataclass(frozen=True)
class _ToolPayload:
    structured: dict[str, Any]
    rendered_text: str | None


class SearchToolsClient:
    def __init__(
        self,
        root: Path | str,
        library_path: Path | str | None = None,
        render_line_numbers: bool = True,
    ) -> None:
        self.root = Path(root).expanduser().resolve()
        self._library_path = (
            Path(library_path).expanduser().resolve() if library_path is not None else None
        )
        self._render_line_numbers = render_line_numbers
        self._runtime_lock = threading.Lock()
        self._native = _load_native_module(self._library_path)
        self._runtime: _RuntimeState | None = None
        self._closed = False

    def __enter__(self) -> SearchToolsClient:
        self._ensure_started()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def close(self) -> None:
        with self._runtime_lock:
            runtime = self._runtime
            self._runtime = None
            self._closed = True

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
        payload = self._call_tool_payload(
            "search_symbols",
            {
                "patterns": patterns,
                "include_tests": include_tests,
                "limit": limit,
            },
        )
        return SearchSymbolsResult.from_dict(
            payload.structured,
            render_line_numbers=self._render_line_numbers,
            rendered_text=payload.rendered_text,
        )

    def get_symbol_locations(
        self,
        symbols: list[str],
        *,
        kind_filter: SymbolKindFilter = SymbolKindFilter.ANY,
    ) -> SymbolLocationsResult:
        payload = self._call_tool_payload(
            "get_symbol_locations",
            {"symbols": symbols, "kind_filter": kind_filter.value},
        )
        return SymbolLocationsResult.from_dict(
            payload.structured,
            render_line_numbers=self._render_line_numbers,
            rendered_text=payload.rendered_text,
        )

    def get_symbol_ancestors(
        self,
        symbols: list[str],
        *,
        kind_filter: SymbolKindFilter = SymbolKindFilter.CLASS,
    ) -> SymbolAncestorsResult:
        payload = self._call_tool_payload(
            "get_symbol_ancestors",
            {"symbols": symbols, "kind_filter": kind_filter.value},
        )
        return SymbolAncestorsResult.from_dict(
            payload.structured,
            rendered_text=payload.rendered_text,
        )

    def get_symbol_sources(
        self,
        symbols: list[str],
        *,
        kind_filter: SymbolKindFilter = SymbolKindFilter.ANY,
    ) -> SymbolSourcesResult:
        payload = self._call_tool_payload(
            "get_symbol_sources",
            {"symbols": symbols, "kind_filter": kind_filter.value},
        )
        return SymbolSourcesResult.from_dict(
            payload.structured,
            render_line_numbers=self._render_line_numbers,
            rendered_text=payload.rendered_text,
        )

    def get_summaries(self, targets: list[str]) -> FileSummariesResult:
        payload = self._call_tool_payload("get_summaries", {"targets": targets})
        return FileSummariesResult.from_dict(
            payload.structured,
            render_line_numbers=self._render_line_numbers,
            rendered_text=payload.rendered_text,
        )

    def list_symbols(self, file_patterns: list[str]) -> SkimFilesResult:
        payload = self._call_tool_payload(
            "list_symbols", {"file_patterns": file_patterns}
        )
        return SkimFilesResult.from_dict(
            payload.structured,
            render_line_numbers=self._render_line_numbers,
            rendered_text=payload.rendered_text,
        )

    def scan_usages(
        self,
        symbols: list[str],
        *,
        include_tests: bool = False,
        paths: list[str] | None = None,
    ) -> ScanUsagesResult:
        arguments: dict[str, Any] = {
            "symbols": symbols,
            "include_tests": include_tests,
        }
        if paths is not None:
            arguments["paths"] = paths
        payload = self._call_tool_payload("scan_usages", arguments)
        return ScanUsagesResult.from_dict(
            payload.structured,
            rendered_text=payload.rendered_text,
        )

    @overload
    def most_relevant_files(
        self,
        seed_files: list[str],
        *,
        limit: int = 20,
        seed_weights: list[float] | None = None,
    ) -> MostRelevantFilesResult: ...

    @overload
    def most_relevant_files(
        self,
        seed_files: list[str],
        *,
        limit: int = 20,
        seed_weights: list[float] | None = None,
        recency_half_life: float | None = None,
    ) -> MostRelevantFilesResult: ...

    def most_relevant_files(
        self,
        seed_files: list[str],
        *,
        limit: int = 20,
        seed_weights: list[float] | None = None,
        recency_half_life: float | None | object = _UNSET,
    ) -> MostRelevantFilesResult:
        arguments: dict[str, Any] = {"seed_file_paths": seed_files, "limit": limit}
        if seed_weights is not None:
            arguments["seed_weights"] = seed_weights
        if recency_half_life is not _UNSET:
            arguments["recency_half_life"] = recency_half_life
        payload = self._call_tool_payload(
            "most_relevant_files",
            arguments,
        )
        return MostRelevantFilesResult.from_dict(
            payload.structured,
            render_line_numbers=self._render_line_numbers,
            rendered_text=payload.rendered_text,
        )

    def semantic_search(self, query: str, *, k: int = 10) -> SemanticSearchResult:
        payload = self._call_tool_payload(
            "semantic_search",
            {"query": query, "k": k},
        )
        return SemanticSearchResult.from_dict(
            payload.structured,
            render_line_numbers=self._render_line_numbers,
            rendered_text=payload.rendered_text,
        )

    def semantic_search_status(self) -> SemanticSearchStatus:
        return SemanticSearchStatus.from_dict(
            self._call_tool("semantic_search_status", {})
        )

    def _call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
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

    def _call_tool_payload(self, name: str, arguments: dict[str, Any]) -> _ToolPayload:
        runtime = self._ensure_started()
        try:
            payload = runtime.native.call_tool_payload_json(
                name,
                json.dumps(arguments),
                self._render_line_numbers,
            )
        except Exception as exc:
            raise SearchToolsError(str(exc)) from exc

        try:
            decoded = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise SearchToolsError(
                f"Native searchtools call returned invalid JSON: {exc}"
            ) from exc
        if not isinstance(decoded, dict):
            raise SearchToolsError(
                "Native searchtools call did not return a JSON object payload"
            )
        structured = decoded.get("structured")
        if not isinstance(structured, dict):
            raise SearchToolsError(
                "Native searchtools payload did not include a structured JSON object"
            )
        rendered_text = decoded.get("rendered_text")
        if rendered_text is not None and not isinstance(rendered_text, str):
            raise SearchToolsError(
                "Native searchtools payload returned a non-string rendered_text"
            )
        return _ToolPayload(structured=structured, rendered_text=rendered_text)

    def _ensure_started(self) -> _RuntimeState:
        with self._runtime_lock:
            if self._closed:
                raise SearchToolsError("SearchToolsClient is closed")
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

        loader = importlib.machinery.ExtensionFileLoader(
            _NATIVE_MODULE_NAME, str(library_path)
        )
        spec = importlib.util.spec_from_file_location(
            _NATIVE_MODULE_NAME, library_path, loader=loader
        )
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
