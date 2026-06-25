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
    CodeQualityReport,
    FileSummariesResult,
    DefinitionByReferenceLookupResult,
    DefinitionLookupResult,
    FindFilenamesResult,
    FindFilesContainingResult,
    GetFileContentsResult,
    GitTextResult,
    JqResult,
    ListFilesResult,
    MostRelevantFilesResult,
    RefreshResult,
    SearchFileContentsResult,
    SemanticSearchResult,
    SemanticSearchStatus,
    ScanUsagesResult,
    SearchSymbolsResult,
    SkimFilesResult,
    SymbolAncestorsResult,
    SymbolLocationsResult,
    SymbolSourcesResult,
    TypeLookupResult,
    UsageGraphResult,
    WorkspaceResult,
    XmlSelectResult,
    XmlSkimResult,
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


class XmlSelectOutput(StrEnum):
    TEXT = "text"
    ATTRIBUTE = "attribute"
    OUTER_XML = "outer-xml"


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
        manual: bool = False,
    ) -> None:
        # manual=True: no file watcher; caller drives incremental updates via
        # update_paths(). For batch consumers reusing one session across revisions.
        self._manual = manual
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

    def refresh(self) -> RefreshResult:
        return RefreshResult.from_dict(self._call_tool("refresh", {}))

    def update_paths(self, paths: list[str]) -> RefreshResult:
        """Incrementally re-analyze only the given project-relative paths (O(changed)),
        reusing analysis for all other files. Pair with a `manual` client whose worktree
        has been updated to a new revision."""
        return RefreshResult.from_dict(
            self._call_tool("update_paths", {"paths": list(paths)})
        )

    def activate_workspace(self, workspace_path: Path | str) -> WorkspaceResult:
        """Switch the active workspace root for subsequent tool calls. A workspace is
        already active at startup, so use this only to move to a different repo,
        checkout, or worktree. Returns the resolved absolute path that was activated."""
        return WorkspaceResult.from_dict(
            self._call_tool(
                "activate_workspace", {"workspace_path": str(workspace_path)}
            )
        )

    def get_active_workspace(self) -> WorkspaceResult:
        """Return the current active workspace root (including after any prior switch)."""
        return WorkspaceResult.from_dict(self._call_tool("get_active_workspace", {}))

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

    def get_definition_by_location(
        self,
        path: str,
        *,
        line: int | None = None,
        column: int | None = None,
        start_byte: int | None = None,
        end_byte: int | None = None,
    ) -> DefinitionLookupResult:
        reference: dict[str, Any] = {"path": path}
        if line is not None:
            reference["line"] = line
        if column is not None:
            reference["column"] = column
        if start_byte is not None:
            reference["start_byte"] = start_byte
        if end_byte is not None:
            reference["end_byte"] = end_byte
        result = self._call_tool(
            "get_definition_by_location",
            {"references": [reference]},
        )
        return DefinitionLookupResult.from_dict(result["results"][0])

    def get_definition_by_reference(
        self,
        symbol: str,
        *,
        context: str,
        target: str,
    ) -> DefinitionByReferenceLookupResult:
        result = self._call_tool(
            "get_definition_by_reference",
            {
                "references": [
                    {"symbol": symbol, "context": context, "target": target}
                ]
            },
        )
        return DefinitionByReferenceLookupResult.from_dict(result["results"][0])

    def get_type_by_location(
        self,
        path: str,
        *,
        line: int | None = None,
        column: int | None = None,
        start_byte: int | None = None,
        end_byte: int | None = None,
    ) -> TypeLookupResult:
        reference: dict[str, Any] = {"path": path}
        if line is not None:
            reference["line"] = line
        if column is not None:
            reference["column"] = column
        if start_byte is not None:
            reference["start_byte"] = start_byte
        if end_byte is not None:
            reference["end_byte"] = end_byte
        result = self._call_tool(
            "get_type_by_location",
            {"references": [reference]},
        )
        return TypeLookupResult.from_dict(result["results"][0])

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

    def contains_tests(self, file_paths: list[str]) -> dict[str, bool]:
        """Per file: whether the language analyzer detects test code in it
        (tree-sitter based, not a path heuristic). Keyed by workspace-relative
        path; inputs that do not resolve to a single existing repo file are
        omitted from the returned mapping."""
        structured = self._call_tool("contains_tests", {"file_paths": list(file_paths)})
        result = structured.get("contains_tests", {})
        if not isinstance(result, dict):
            raise SearchToolsError(
                "Native contains_tests did not return a JSON object mapping"
            )
        return {str(path): bool(flag) for path, flag in result.items()}

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

    def usage_graph(
        self,
        *,
        include_tests: bool = False,
        paths: list[str] | None = None,
    ) -> UsageGraphResult:
        """Build the whole-workspace caller -> callee reference graph.

        Returns classes and functions as nodes and resolved references as
        weighted edges, ready to feed into a graph library for ranking (e.g.
        PageRank for a code map). Each edge carries its reference locations in
        ``UsageGraphEdge.sites`` (``{path, line}``, with ``len(edge.sites) ==
        edge.weight``), so a consumer can map call sites without re-scanning.
        This is the bulk counterpart to a per-symbol ``scan_usages``; expect to
        cache the result and rebuild on change.

        Args:
            include_tests: Include references that live in detected test files.
            paths: Optional project-relative paths or globs bounding the search.
                Omit to graph the whole workspace.
        """
        arguments: dict[str, Any] = {"include_tests": include_tests}
        if paths is not None:
            arguments["paths"] = paths
        payload = self._call_tool_payload("usage_graph", arguments)
        return UsageGraphResult.from_dict(
            payload.structured,
            rendered_text=payload.rendered_text,
        )

    # ------------------------------------------------------------------
    # File tools
    # ------------------------------------------------------------------

    def get_file_contents(self, file_paths: list[str]) -> GetFileContentsResult:
        """Read whole files by project-relative (or in-workspace absolute) path."""
        return GetFileContentsResult.from_dict(
            self._call_tool("get_file_contents", {"file_paths": list(file_paths)})
        )

    def find_filenames(
        self, patterns: list[str], *, limit: int | None = None
    ) -> FindFilenamesResult:
        """Find files whose path matches any of the given glob patterns."""
        arguments: dict[str, Any] = {"patterns": list(patterns)}
        if limit is not None:
            arguments["limit"] = limit
        return FindFilenamesResult.from_dict(
            self._call_tool("find_filenames", arguments)
        )

    def search_file_contents(
        self,
        patterns: list[str],
        *,
        file_path: str | None = None,
        context_lines: int | None = None,
        case_insensitive: bool = False,
    ) -> SearchFileContentsResult:
        """Grep file contents with regex patterns, returning matches with context lines.

        ``file_path`` optionally restricts the search to a glob, or an absolute
        path/glob inside the active workspace.
        """
        arguments: dict[str, Any] = {
            "patterns": list(patterns),
            "case_insensitive": case_insensitive,
        }
        if file_path is not None:
            arguments["file_path"] = file_path
        if context_lines is not None:
            arguments["context_lines"] = context_lines
        return SearchFileContentsResult.from_dict(
            self._call_tool("search_file_contents", arguments)
        )

    def find_files_containing(
        self,
        patterns: list[str],
        *,
        limit: int | None = None,
        case_insensitive: bool = False,
    ) -> FindFilesContainingResult:
        """Find files whose contents match any of the given regex patterns."""
        arguments: dict[str, Any] = {
            "patterns": list(patterns),
            "case_insensitive": case_insensitive,
        }
        if limit is not None:
            arguments["limit"] = limit
        return FindFilesContainingResult.from_dict(
            self._call_tool("find_files_containing", arguments)
        )

    def list_files(
        self, directory_path: str = "", *, max_entries: int | None = None
    ) -> ListFilesResult:
        """List files under a directory. Empty ``directory_path`` lists the workspace root."""
        arguments: dict[str, Any] = {"directory_path": directory_path}
        if max_entries is not None:
            arguments["max_entries"] = max_entries
        return ListFilesResult.from_dict(self._call_tool("list_files", arguments))

    # ------------------------------------------------------------------
    # Git tools
    # ------------------------------------------------------------------

    def search_git_commit_messages(
        self, pattern: str, *, limit: int | None = None
    ) -> GitTextResult:
        """Regex search across git commit messages. Returns XML-shaped ``<commit>`` blocks."""
        arguments: dict[str, Any] = {"pattern": pattern}
        if limit is not None:
            arguments["limit"] = limit
        return GitTextResult.from_text(
            self._call_tool_text("search_git_commit_messages", arguments)
        )

    def get_git_log(
        self, *, file_path: str | None = None, limit: int | None = None
    ) -> GitTextResult:
        """Return recent commits, optionally filtered to those touching ``file_path``."""
        arguments: dict[str, Any] = {}
        if file_path is not None:
            arguments["file_path"] = file_path
        if limit is not None:
            arguments["limit"] = limit
        return GitTextResult.from_text(self._call_tool_text("get_git_log", arguments))

    def get_commit_diff(
        self,
        revision: str,
        *,
        max_files: int | None = None,
        lines_per_file: int | None = None,
    ) -> GitTextResult:
        """Return the unified diff for a single commit (``revision``: hash, branch, or tag)."""
        arguments: dict[str, Any] = {"revision": revision}
        if max_files is not None:
            arguments["max_files"] = max_files
        if lines_per_file is not None:
            arguments["lines_per_file"] = lines_per_file
        return GitTextResult.from_text(
            self._call_tool_text("get_commit_diff", arguments)
        )

    # ------------------------------------------------------------------
    # Structured data tools
    # ------------------------------------------------------------------

    def jq(
        self,
        file_path: str,
        filter_expr: str,
        *,
        max_files: int | None = None,
        matches_per_file: int | None = None,
    ) -> JqResult:
        """Run a jq filter over JSON file(s) matched by ``file_path`` (path or glob)."""
        arguments: dict[str, Any] = {"file_path": file_path, "filter": filter_expr}
        if max_files is not None:
            arguments["max_files"] = max_files
        if matches_per_file is not None:
            arguments["matches_per_file"] = matches_per_file
        return JqResult.from_dict(self._call_tool("jq", arguments))

    def xml_skim(self, file_path: str, *, max_files: int | None = None) -> XmlSkimResult:
        """Summarize the element structure of XML file(s) matched by ``file_path``."""
        arguments: dict[str, Any] = {"file_path": file_path}
        if max_files is not None:
            arguments["max_files"] = max_files
        return XmlSkimResult.from_dict(self._call_tool("xml_skim", arguments))

    def xml_select(
        self,
        file_path: str,
        xpath: str,
        *,
        output: XmlSelectOutput = XmlSelectOutput.TEXT,
        attr_name: str | None = None,
        max_files: int | None = None,
    ) -> XmlSelectResult:
        """Evaluate an XPath 3.1 ``xpath`` over XML file(s) matched by ``file_path``.

        ``attr_name`` is required when ``output`` is ``XmlSelectOutput.ATTRIBUTE``.
        """
        arguments: dict[str, Any] = {
            "file_path": file_path,
            "xpath": xpath,
            "output": XmlSelectOutput(output).value,
        }
        if attr_name is not None:
            arguments["attr_name"] = attr_name
        if max_files is not None:
            arguments["max_files"] = max_files
        return XmlSelectResult.from_dict(self._call_tool("xml_select", arguments))

    # ------------------------------------------------------------------
    # Code quality (slopcop) tools
    # ------------------------------------------------------------------
    #
    # Each tool renders its own report text (surfaced as ``CodeQualityReport``).
    # The common arguments are typed; the long tail of per-rule tuning weights
    # is accepted via ``options`` (keys map 1:1 to the Rust tool arguments).

    def compute_cyclomatic_complexity(
        self, file_paths: list[str], *, threshold: int | None = None
    ) -> CodeQualityReport:
        """Per-function heuristic cyclomatic complexity; flag those over ``threshold``."""
        arguments: dict[str, Any] = {"file_paths": list(file_paths)}
        if threshold is not None:
            arguments["threshold"] = threshold
        return CodeQualityReport.from_dict(
            self._call_tool("compute_cyclomatic_complexity", arguments)
        )

    def compute_cognitive_complexity(
        self, file_paths: list[str], *, threshold: int | None = None
    ) -> CodeQualityReport:
        """Per-function heuristic cognitive complexity; flag those over ``threshold``."""
        arguments: dict[str, Any] = {"file_paths": list(file_paths)}
        if threshold is not None:
            arguments["threshold"] = threshold
        return CodeQualityReport.from_dict(
            self._call_tool("compute_cognitive_complexity", arguments)
        )

    def report_comment_density_for_code_unit(
        self, fq_name: str, *, max_lines: int | None = None
    ) -> CodeQualityReport:
        """Comment density for a single symbol identified by fully qualified name."""
        arguments: dict[str, Any] = {"fq_name": fq_name}
        if max_lines is not None:
            arguments["max_lines"] = max_lines
        return CodeQualityReport.from_dict(
            self._call_tool("report_comment_density_for_code_unit", arguments)
        )

    def report_comment_density_for_files(
        self,
        file_paths: list[str],
        *,
        max_top_level_rows: int | None = None,
        max_files: int | None = None,
    ) -> CodeQualityReport:
        """Comment density tables for the given source files."""
        arguments: dict[str, Any] = {"file_paths": list(file_paths)}
        if max_top_level_rows is not None:
            arguments["max_top_level_rows"] = max_top_level_rows
        if max_files is not None:
            arguments["max_files"] = max_files
        return CodeQualityReport.from_dict(
            self._call_tool("report_comment_density_for_files", arguments)
        )

    def report_exception_handling_smells(
        self,
        file_paths: list[str],
        *,
        min_score: int | None = None,
        max_findings: int | None = None,
        options: dict[str, Any] | None = None,
    ) -> CodeQualityReport:
        """Flag suspicious exception handlers (generic/empty/log-only catches).

        ``options`` accepts the per-rule weight knobs (e.g. ``empty_body_weight``);
        keys map directly to the Rust tool arguments.
        """
        arguments: dict[str, Any] = {"file_paths": list(file_paths)}
        if min_score is not None:
            arguments["min_score"] = min_score
        if max_findings is not None:
            arguments["max_findings"] = max_findings
        if options:
            arguments.update(options)
        return CodeQualityReport.from_dict(
            self._call_tool("report_exception_handling_smells", arguments)
        )

    def report_test_assertion_smells(
        self,
        file_paths: list[str],
        *,
        min_score: int | None = None,
        max_findings: int | None = None,
        options: dict[str, Any] | None = None,
    ) -> CodeQualityReport:
        """Flag low-value or brittle test assertions.

        ``options`` accepts the per-rule weight knobs; keys map directly to the
        Rust tool arguments.
        """
        arguments: dict[str, Any] = {"file_paths": list(file_paths)}
        if min_score is not None:
            arguments["min_score"] = min_score
        if max_findings is not None:
            arguments["max_findings"] = max_findings
        if options:
            arguments.update(options)
        return CodeQualityReport.from_dict(
            self._call_tool("report_test_assertion_smells", arguments)
        )

    def report_structural_clone_smells(
        self,
        file_paths: list[str],
        *,
        min_score: int | None = None,
        max_findings: int | None = None,
        options: dict[str, Any] | None = None,
    ) -> CodeQualityReport:
        """Detect suspicious structural clones via token shingles plus AST refinement.

        ``options`` accepts the detection knobs (e.g. ``shingle_size``); keys map
        directly to the Rust tool arguments.
        """
        arguments: dict[str, Any] = {"file_paths": list(file_paths)}
        if min_score is not None:
            arguments["min_score"] = min_score
        if max_findings is not None:
            arguments["max_findings"] = max_findings
        if options:
            arguments.update(options)
        return CodeQualityReport.from_dict(
            self._call_tool("report_structural_clone_smells", arguments)
        )

    def report_long_method_and_god_object_smells(
        self,
        file_paths: list[str],
        *,
        max_findings: int | None = None,
        max_files: int | None = None,
        options: dict[str, Any] | None = None,
    ) -> CodeQualityReport:
        """Detect oversized functions, god classes, and god modules.

        ``options`` accepts the threshold knobs (e.g. ``long_method_span_lines``);
        keys map directly to the Rust tool arguments.
        """
        arguments: dict[str, Any] = {"file_paths": list(file_paths)}
        if max_findings is not None:
            arguments["max_findings"] = max_findings
        if max_files is not None:
            arguments["max_files"] = max_files
        if options:
            arguments.update(options)
        return CodeQualityReport.from_dict(
            self._call_tool("report_long_method_and_god_object_smells", arguments)
        )

    def report_dead_code_and_unused_abstraction_smells(
        self,
        *,
        file_paths: list[str] | None = None,
        fq_names: list[str] | None = None,
        min_score: int | None = None,
        max_findings: int | None = None,
        options: dict[str, Any] | None = None,
    ) -> CodeQualityReport:
        """Detect likely dead declarations and one-call abstractions (Rust).

        Provide ``file_paths`` and/or ``fq_names`` to bound the search; pass an
        empty ``file_paths`` (the default) to let the tool discover candidates.
        ``options`` accepts the guardrail knobs (e.g. ``max_candidate_symbols``).
        """
        # The Rust tool requires file_paths (it is not serde-defaulted); send an
        # empty list for discovery mode.
        arguments: dict[str, Any] = {
            "file_paths": list(file_paths) if file_paths is not None else []
        }
        if fq_names is not None:
            arguments["fq_names"] = list(fq_names)
        if min_score is not None:
            arguments["min_score"] = min_score
        if max_findings is not None:
            arguments["max_findings"] = max_findings
        if options:
            arguments.update(options)
        return CodeQualityReport.from_dict(
            self._call_tool("report_dead_code_and_unused_abstraction_smells", arguments)
        )

    def report_secret_like_code(
        self,
        *,
        max_findings: int | None = None,
        max_commits: int | None = None,
        include_history_only: bool = False,
        include_low_confidence: bool = False,
    ) -> CodeQualityReport:
        """Scan current files and git history for secret-looking strings (redacted)."""
        arguments: dict[str, Any] = {
            "include_history_only": include_history_only,
            "include_low_confidence": include_low_confidence,
        }
        if max_findings is not None:
            arguments["max_findings"] = max_findings
        if max_commits is not None:
            arguments["max_commits"] = max_commits
        return CodeQualityReport.from_dict(
            self._call_tool("report_secret_like_code", arguments)
        )

    def analyze_git_hotspots(
        self,
        *,
        since_days: int | None = None,
        since_iso: str | None = None,
        until_iso: str | None = None,
        max_commits: int | None = None,
        max_files: int | None = None,
    ) -> CodeQualityReport:
        """Correlate recent commit churn with complexity to surface hotspots.

        ``since_iso``/``until_iso`` (ISO-8601) bound the window; ``since_iso``
        overrides ``since_days`` when set.
        """
        arguments: dict[str, Any] = {}
        if since_days is not None:
            arguments["since_days"] = since_days
        if since_iso is not None:
            arguments["since_iso"] = since_iso
        if until_iso is not None:
            arguments["until_iso"] = until_iso
        if max_commits is not None:
            arguments["max_commits"] = max_commits
        if max_files is not None:
            arguments["max_files"] = max_files
        return CodeQualityReport.from_dict(
            self._call_tool("analyze_git_hotspots", arguments)
        )

    def _call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
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
            raise SearchToolsError("Native searchtools call did not return a JSON object")
        structured = decoded.get("structured")
        if not isinstance(structured, dict):
            raise SearchToolsError(
                "Native searchtools payload returned a non-object structured result"
            )
        return structured

    def _call_tool_text(self, name: str, arguments: dict[str, Any]) -> str:
        # Some tools (the git tools) render their own text rather than structured
        # JSON; the native boundary returns that as a bare JSON string.
        runtime = self._ensure_started()
        try:
            payload = runtime.native.call_tool_json(name, json.dumps(arguments))
        except Exception as exc:
            raise SearchToolsError(str(exc)) from exc

        try:
            decoded = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise SearchToolsError(
                f"Native searchtools call returned invalid JSON: {exc}"
            ) from exc
        if not isinstance(decoded, str):
            raise SearchToolsError("Native searchtools call did not return a JSON string")
        return decoded

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
                native = self._native.SearchToolsNativeSession(str(self.root), self._manual)
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
