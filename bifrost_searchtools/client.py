from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import itertools
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
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


class SymbolKindFilter(StrEnum):
    ANY = "any"
    CLASS = "class"
    FUNCTION = "function"
    FIELD = "field"
    MODULE = "module"


@dataclass(frozen=True)
class _ResponseError:
    code: str
    message: str


class SearchToolsClient:
    def __init__(
        self,
        root: Path | str,
        server_path: Path | str | None = None,
    ) -> None:
        self.root = Path(root).expanduser().resolve()
        self._server_path = self._resolve_server_path(server_path)
        self._process: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()
        self._request_ids = itertools.count(1)

    def __enter__(self) -> SearchToolsClient:
        self._ensure_started()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            if self._process is None:
                return
            process = self._process
            self._process = None

        if process.stdin:
            process.stdin.close()
        if process.stdout:
            process.stdout.close()
        if process.stderr:
            process.stderr.close()
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)

    def refresh(self) -> dict[str, Any]:
        return self._request("refresh", {})

    def search_symbols(
        self,
        patterns: list[str],
        *,
        include_tests: bool = False,
        limit: int = 20,
    ) -> SearchSymbolsResult:
        return SearchSymbolsResult.from_dict(
            self._request(
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
            self._request(
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
            self._request(
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
            self._request(
                "get_symbol_sources",
                {"symbols": symbols, "kind_filter": kind_filter.value},
            )
        )

    def get_file_summaries(self, file_patterns: list[str]) -> FileSummariesResult:
        return FileSummariesResult.from_dict(
            self._request("get_file_summaries", {"file_patterns": file_patterns})
        )

    def skim_files(self, file_patterns: list[str]) -> SkimFilesResult:
        return SkimFilesResult.from_dict(
            self._request("skim_files", {"file_patterns": file_patterns})
        )

    def _request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            process = self._ensure_started()
            request_id = str(next(self._request_ids))
            payload = {"id": request_id, "method": method, "params": params}

            assert process.stdin is not None
            process.stdin.write(json.dumps(payload) + "\n")
            process.stdin.flush()

            assert process.stdout is not None
            line = process.stdout.readline()
            if not line:
                raise SearchToolsError(self._process_failure_message(process))

        response = json.loads(line)
        if not response.get("ok"):
            error = _ResponseError(**response["error"])
            raise SearchToolsError(f"{error.code}: {error.message}")
        return response["result"]

    def _ensure_started(self) -> subprocess.Popen[str]:
        if self._process is not None and self._process.poll() is None:
            return self._process

        self._process = subprocess.Popen(
            [
                str(self._server_path),
                "--root",
                str(self.root),
                "--server",
                "searchtools",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        return self._process

    def _process_failure_message(self, process: subprocess.Popen[str]) -> str:
        stderr = ""
        if process.stderr is not None:
            stderr = process.stderr.read().strip()
        if stderr:
            return f"bifrost server exited unexpectedly: {stderr}"
        return "bifrost server exited unexpectedly without a response"

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
