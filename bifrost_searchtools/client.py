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
from typing import Any, get_args, overload

from .models import (
    BlastRadiusResult,
    CyclomaticComplexityDiffResult,
    DiffAnalysisResult,
    CodeQualityReport,
    CodeQueryExecutionMode,
    FileSummariesResult,
    DefinitionByReferenceLookupResult,
    DeclarationLookupResult,
    DefinitionLookupResult,
    FindFilesContainingResult,
    GetFileContentsResult,
    MostRelevantFilesResult,
    MissingTestsResult,
    RefreshResult,
    RenameSymbolResult,
    CodeQueryResponse,
    SearchFileContentsResult,
    ScanUsagesResult,
    SearchSymbolsResult,
    SkimFilesResult,
    SymbolAncestorsResult,
    SymbolLocationsResult,
    SymbolSourcesResult,
    TypeLookupResult,
    UsageGraphResult,
    WorkspaceResult,
    parse_code_query_response,
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


class MostRelevantFilesRankingMode(StrEnum):
    CASCADE = "cascade"
    HISTORY_IMPORTS = "history_imports"
    USAGE_GRAPH = "usage_graph"
    USAGE_GRAPH_EXACT = "usage_graph_exact"


_CODE_QUERY_EXECUTION_MODES = frozenset(get_args(CodeQueryExecutionMode))


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
        sources: list[str] | None = None,
        revision: str | None = None,
    ) -> None:
        # manual=True: no file watcher; caller drives incremental updates via
        # update_paths(). For batch consumers reusing one session across revisions.
        if sources is not None and manual:
            raise ValueError(
                "manual=True cannot be combined with sources; scoped sessions are already manual"
            )
        if revision is not None and sources is None:
            raise ValueError("revision requires sources for a scoped session")
        self._manual = manual
        self._sources = list(sources) if sources is not None else None
        self._revision = revision
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

    def gc(self) -> None:
        """Force a Git-reachability collection of the persisted Bifrost cache."""
        runtime = self._ensure_started()
        try:
            runtime.native.gc()
        except Exception as exc:
            raise SearchToolsError(f"Failed to garbage-collect the bifrost cache: {exc}") from exc

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

    def query_code(
        self,
        pattern: dict[str, Any] | None = None,
        *,
        union: list[dict[str, Any]] | None = None,
        intersect: list[dict[str, Any]] | None = None,
        except_: list[dict[str, Any]] | None = None,
        inside: dict[str, Any] | None = None,
        inside_decl: dict[str, Any] | None = None,
        not_inside: dict[str, Any] | None = None,
        where: list[str] | None = None,
        languages: list[str] | None = None,
        steps: list[dict[str, Any]] | None = None,
        limit: int | None = None,
        result_detail: str | None = None,
        schema_version: int | None = None,
        execution_mode: CodeQueryExecutionMode | None = None,
    ) -> CodeQueryResponse:
        """Query normalized code structure across supported languages.

        ``schema_version`` is optional. Version ``1`` is the only supported
        version; omit it or pin it explicitly. Other versions are rejected.
        A query starts with normalized syntactic
        structure or a typed set of complete query branches, then optionally
        applies typed semantic ``steps`` such as ``enclosing_decl``, ``file_of``,
        ``imports_of``, ``supertypes``, ``subtypes``, ``members``, and ``owner``.
        The vocabulary also provides ``procedure_of``, ``cfg_entry``,
        ``cfg_exits``, ``cfg_successor_edges``, ``cfg_predecessor_edges``,
        ``cfg_edge_source``, and ``cfg_edge_target`` for bounded,
        procedure-local control-flow inspection; a
        host-registered ``typestate`` step and pure retained ``witness``
        projection where callers send only ``protocol_ref`` and finite
        reductions; ``inside_decl`` for containment that stops at nested
        callable declarations;
        a host-registered ``value_flow`` step from procedures to
        diagnostic-neutral flow endpoints that reuses ``witness`` for bounded
        retained flow paths (callers send only ``plan_ref``; reachability,
        exact/may certainty, ambiguity, completion, and budget status remain
        separate typed result fields); and ``taint`` with a host-registered
        ``taint_ref``, which only
        projects retained production taint findings and never compiles or
        solves taint, reconstructs witnesses, or performs policy classification.
        The ``occurrences`` source pairs with the ``occurrences_in``,
        ``occurrences_of``, and ``occurrence_target`` steps. The ``scopes``
        and ``bindings`` sources pair with the ``scope_of``,
        ``scope_ancestors``, ``bindings_in``, ``binding_of``,
        ``binding_occurrence``, ``candidates_of``, and ``candidate_target``
        steps, and the package clause sits on the file row. The ``paths``
        source pairs with the ``segments_of`` and ``segment_target`` steps
        over qualified-path rows. The ``generation_sites`` and ``exports``
        sources pair with the ``generates``, ``generated_by``,
        ``declaration_state_of``, ``implementation_of``, ``stubs_of``, and
        ``export_target`` steps over recorded declaration-materialization
        provenance; ``stubs_of`` is the inverse of ``implementation_of``, so
        composed with ``except_`` it lists the declaration-only stubs no
        implementation answers.
        The canonical reference-edge domain provides
        ``edges_of``, ``edges_from``, and ``edge_target`` over
        canonical ``CodeQueryReferenceEdge`` rows. ``edges_of`` is the inverse
        projection (every usage site the usage index enumerates for a
        declaration) and ``edges_from`` is the forward one (the resolver's own
        resolved targets for one exact token); both accept ``reference_kinds``,
        ``proof``, ``surface``, ``usage``, ``relation``, and ``site_class``.
        ``surface`` is optional with no default, because the complete edge
        answer includes editor-only rows. A forward query in a language whose
        adapter has no forward projection reports ``edge_axis_unsupported``
        rather than an empty answer.
        The flow-sensitive state domain provides ``state_events_of``,
        ``flow_relations_of``, ``flow_source``, and ``flow_target`` over
        ``CodeQueryStateEvent`` and ``CodeQueryFlowRelation`` rows.
        ``state_events_of`` derives establishment, kill, and read events of
        bindings and properties from the production control-flow graph and
        accepts ``event_class`` and ``subject``; ``flow_relations_of`` relates
        them as ``reaching``, ``dominates``, or ``same_evaluation`` with
        ``exact`` or ``may`` certainty and accepts ``flow_relation`` and
        ``certainty``. Source order and containment are never presented as any
        of the three relations, and a derivation that cannot answer an axis
        reports ``flow_state_axis_unsupported`` or
        ``flow_state_derivation_incomplete`` rather than an empty answer.
        The bounded rewrite domain provides ``rewrite_paths_of`` over
        ``CodeQueryRewritePath`` rows: one row per bounded chase a production
        analysis engaged in a declared finite rewrite domain (today
        ``rust_import_alias``), with its ordered steps, the bound the domain
        declared for itself, and the terminal outcome. It accepts ``domain``
        and ``rewrite_outcome``. ``converged`` carries the fixed point,
        ``cycle`` carries the ordered repeated-state witness, and
        ``exceeded_budget`` is absence of evidence rather than a proven cycle.
        Receiver and member analysis adds ``receiver_outcome``,
        ``receiver_evidence``, and ``member_selection`` rows.
        ``receiver_outcome`` is the mandatory per-site outcome row that states
        the coverage of an empty evidence set, ``receiver_evidence`` rows are
        parent-linked chain hops rather than nested values, and
        ``member_selection`` is the mandatory per-occurrence selection summary,
        which exists even when the language records no candidate trace.
        Hierarchy steps are direct by default and accept a positive ``depth`` or
        ``transitive=True``. Declaration results are limited to declarations
        indexed by the workspace analyzer. Pass exactly one of ``pattern``,
        ``union``, ``intersect``, or ``except_``. Set operands are complete
        canonical query-plan dictionaries and must produce the same typed
        domain. ``pattern`` is sent as the tool's ``match`` object. Structural
        scope arguments apply only with ``pattern``. ``where`` accepts project-relative globs or absolute
        in-workspace paths/globs. ``result_detail="full"`` adds stable IDs and
        precise ranges; compact mode retains minimal pipeline provenance.
        ``execution_mode="results"`` returns ordinary matches,
        ``execution_mode="explain"`` returns the parsed, logical, and selected
        physical plan without executing it, and ``execution_mode="profile"``
        executes the query and returns both results and structured observations.
        """
        if (
            execution_mode is not None
            and execution_mode not in _CODE_QUERY_EXECUTION_MODES
        ):
            accepted = ", ".join(sorted(_CODE_QUERY_EXECUTION_MODES))
            raise ValueError(f"execution_mode must be one of: {accepted}")
        sources = {
            "match": pattern,
            "union": union,
            "intersect": intersect,
            "except": except_,
        }
        selected = [(name, value) for name, value in sources.items() if value is not None]
        if len(selected) != 1:
            raise ValueError(
                "query_code requires exactly one of pattern, union, intersect, or except_"
            )
        source_name, source_value = selected[0]
        if source_name != "match" and any(
            value is not None
            for value in (inside, inside_decl, not_inside, where, languages)
        ):
            raise ValueError(
                "inside, inside_decl, not_inside, where, and languages apply only to a pattern query; "
                "put structural scope fields inside each set branch"
            )
        arguments: dict[str, Any] = {source_name: source_value}
        if inside is not None:
            arguments["inside"] = inside
        if inside_decl is not None:
            arguments["inside_decl"] = inside_decl
        if not_inside is not None:
            arguments["not_inside"] = not_inside
        if where is not None:
            arguments["where"] = list(where)
        if languages is not None:
            arguments["languages"] = list(languages)
        if steps is not None:
            arguments["steps"] = list(steps)
        if limit is not None:
            arguments["limit"] = limit
        if result_detail is not None:
            arguments["result_detail"] = result_detail
        if schema_version is not None:
            arguments["schema_version"] = schema_version
        if execution_mode is not None:
            arguments["execution_mode"] = execution_mode
        payload = self._call_tool_payload("query_code", arguments)
        return parse_code_query_response(
            payload.structured,
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

    def get_definitions_by_location(
        self,
        references: list[dict[str, Any]],
    ) -> list[DefinitionLookupResult]:
        result = self._call_tool(
            "get_definitions_by_location",
            {"references": references},
        )
        return [DefinitionLookupResult.from_dict(item) for item in result["results"]]

    def get_declarations_by_location(
        self,
        references: list[dict[str, Any]],
    ) -> list[DeclarationLookupResult]:
        result = self._call_tool(
            "get_declarations_by_location",
            {"references": references},
        )
        return [DeclarationLookupResult.from_dict(item) for item in result["results"]]

    def get_definitions_by_reference(
        self,
        references: list[dict[str, str]],
    ) -> list[DefinitionByReferenceLookupResult]:
        result = self._call_tool(
            "get_definitions_by_reference",
            {"references": references},
        )
        return [
            DefinitionByReferenceLookupResult.from_dict(item)
            for item in result["results"]
        ]

    def get_type_by_location(
        self,
        path: str,
        *,
        line: int | None = None,
        column: int | None = None,
    ) -> TypeLookupResult:
        reference: dict[str, Any] = {"path": path}
        if line is not None:
            reference["line"] = line
        if column is not None:
            reference["column"] = column
        result = self._call_tool(
            "get_type_by_location",
            {"references": [reference]},
        )
        return TypeLookupResult.from_dict(result["results"][0])

    def rename_symbol(
        self,
        path: str,
        *,
        new_name: str,
        line: int | None = None,
        column: int | None = None,
    ) -> RenameSymbolResult:
        arguments: dict[str, Any] = {"path": path, "new_name": new_name}
        if line is not None:
            arguments["line"] = line
        if column is not None:
            arguments["column"] = column
        result = self._call_tool("rename_symbol", arguments)
        return RenameSymbolResult.from_dict(result)

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

    def classify_test_files(self, file_paths: list[str]) -> dict[str, dict[str, Any]]:
        """Per file: classify as test, test_support, production, or ambiguous.
        Each entry also includes contains_test_code, the semantic test-code bit.
        Inputs that do not resolve to a single existing repo file are omitted
        from the returned mapping."""
        structured = self._call_tool(
            "classify_test_files", {"file_paths": list(file_paths)}
        )
        result = structured.get("classifications", {})
        if not isinstance(result, dict):
            raise SearchToolsError(
                "Native classify_test_files did not return a JSON object mapping"
            )
        classifications: dict[str, dict[str, Any]] = {}
        for path, classification in result.items():
            if not isinstance(classification, dict):
                raise SearchToolsError(
                    "Native classify_test_files returned a non-object classification"
                )
            classifications[str(path)] = dict(classification)
        return classifications

    def scan_usages_by_reference(
        self,
        symbols: list[str],
        *,
        include_tests: bool = False,
        paths: list[str] | None = None,
    ) -> ScanUsagesResult:
        arguments: dict[str, Any] = {
            "include_tests": include_tests,
        }
        arguments["symbols"] = symbols
        if paths is not None:
            arguments["paths"] = paths
        payload = self._call_tool_payload("scan_usages_by_reference", arguments)
        return ScanUsagesResult.from_dict(
            payload.structured,
            rendered_text=payload.rendered_text,
        )

    def scan_usages_by_location(
        self,
        targets: list[dict[str, Any]],
        *,
        include_tests: bool = False,
        paths: list[str] | None = None,
    ) -> ScanUsagesResult:
        arguments: dict[str, Any] = {
            "targets": targets,
            "include_tests": include_tests,
        }
        if paths is not None:
            arguments["paths"] = paths
        payload = self._call_tool_payload("scan_usages_by_location", arguments)
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
        ranking_mode: MostRelevantFilesRankingMode = MostRelevantFilesRankingMode.CASCADE,
    ) -> MostRelevantFilesResult: ...

    @overload
    def most_relevant_files(
        self,
        seed_files: list[str],
        *,
        limit: int = 20,
        seed_weights: list[float] | None = None,
        recency_half_life: float | None = None,
        ranking_mode: MostRelevantFilesRankingMode = MostRelevantFilesRankingMode.CASCADE,
    ) -> MostRelevantFilesResult: ...

    def most_relevant_files(
        self,
        seed_files: list[str],
        *,
        limit: int = 20,
        seed_weights: list[float] | None = None,
        recency_half_life: float | None | object = _UNSET,
        ranking_mode: MostRelevantFilesRankingMode = MostRelevantFilesRankingMode.CASCADE,
    ) -> MostRelevantFilesResult:
        arguments: dict[str, Any] = {
            "seed_file_paths": seed_files,
            "ranking_mode": ranking_mode.value,
            "limit": limit,
        }
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

    def usage_graph(
        self,
        *,
        include_tests: bool = False,
        paths: list[str] | None = None,
        depth: int = 1,
    ) -> UsageGraphResult:
        """Build a rooted caller -> callee reference graph.

        With ``paths``, declarations in those files are roots and ``depth``
        bounds outbound expansion. Without ``paths``, every workspace
        declaration is a root and depth one is the complete workspace graph.
        Each edge carries its reference locations in ``UsageGraphEdge.sites``
        (``{path, line}``, with ``len(edge.sites) == edge.weight``).

        Args:
            include_tests: Include references that live in detected test files.
            paths: Optional project-relative root paths or globs.
            depth: Maximum outbound caller-to-callee hops. Must be positive.
        """
        if depth < 1:
            raise ValueError("usage_graph depth must be at least 1")
        arguments: dict[str, Any] = {
            "include_tests": include_tests,
            "depth": depth,
        }
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

    def analyze_diff(
        self,
        target: str | None = None,
        *,
        base: str | None = None,
        include_tests: bool = True,
    ) -> DiffAnalysisResult:
        """Diff two endpoints and return semantic effects.

        With both endpoints omitted, the target is the live working tree and
        the base is the merge base of ``HEAD`` and the default branch advertised
        by ``origin/HEAD`` (falling back to ``HEAD`` when unavailable). An
        explicit commit ``target`` still defaults to its first parent. Merge and
        root commits require an explicit ``base``.
        """
        arguments: dict[str, Any] = {"include_tests": include_tests}
        if target is not None:
            arguments["target"] = target
        if base is not None:
            arguments["base"] = base
        return DiffAnalysisResult.from_dict(self._call_tool("analyze_diff", arguments))

    def blast_radius(
        self,
        target: str | None = None,
        *,
        base: str | None = None,
        max_scopes: int | None = None,
    ) -> BlastRadiusResult:
        """Suggest test scopes from structured file-import dependencies.

        The endpoint defaults match :meth:`analyze_diff`. The result is not a
        method-call graph or runtime coverage report.
        """
        arguments: dict[str, Any] = {}
        if target is not None:
            arguments["target"] = target
        if base is not None:
            arguments["base"] = base
        if max_scopes is not None:
            arguments["max_scopes"] = max_scopes
        payload = self._call_tool_payload("blast_radius", arguments)
        return BlastRadiusResult.from_dict(payload.structured, payload.rendered_text)

    def cyclomatic_complexity(
        self,
        target: str | None = None,
        *,
        base: str | None = None,
        include_tests: bool = False,
    ) -> CyclomaticComplexityDiffResult:
        """Compare complexity for functions introduced or edited by a diff.

        Endpoint defaults match :meth:`analyze_diff`. Deleted functions and
        pure moves are omitted; edited functions remain present when their
        complexity delta is zero.
        """
        arguments: dict[str, Any] = {"include_tests": include_tests}
        if target is not None:
            arguments["target"] = target
        if base is not None:
            arguments["base"] = base
        payload = self._call_tool_payload("cyclomatic_complexity", arguments)
        return CyclomaticComplexityDiffResult.from_dict(
            payload.structured, payload.rendered_text
        )

    def missing_tests(
        self,
        target: str | None = None,
        *,
        base: str | None = None,
    ) -> MissingTestsResult:
        """Find changed functions with no structured call path from tests.

        The file dependency graph bounds exact usage analysis. Incomplete
        negative evidence is returned separately as indeterminate functions;
        this is static reachability rather than runtime coverage.
        """
        arguments: dict[str, Any] = {}
        if target is not None:
            arguments["target"] = target
        if base is not None:
            arguments["base"] = base
        payload = self._call_tool_payload("missing_tests", arguments)
        return MissingTestsResult.from_dict(payload.structured, payload.rendered_text)

    # ------------------------------------------------------------------
    # Structured data tools
    # ------------------------------------------------------------------

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
                native = self._native.SearchToolsNativeSession(
                    str(self.root),
                    self._manual,
                    self._sources,
                    self._revision,
                )
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


def tool_descriptors(
    toolset: str = "core",
    *,
    render_line_numbers: bool = True,
    library_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    native = _load_native_module(
        Path(library_path).expanduser().resolve() if library_path is not None else None
    )
    payload = native.tool_descriptors_json(toolset, render_line_numbers)
    decoded = json.loads(payload)
    if not isinstance(decoded, list):
        raise SearchToolsError("Native tool descriptor call did not return a JSON array")
    return decoded


def code_query_variant_inventory(
    *, library_path: Path | str | None = None
) -> dict[str, list[str]]:
    """The complete ``query_code`` vocabulary the loaded native build emits.

    The four lists are ``result_types``, ``diagnostic_codes``,
    ``diagnostic_impacts`` and ``completion_kinds``, each read live from the
    producing registry rather than from a copy. ``models.py`` mirrors every
    name, so comparing the two is how a client learns it is behind the engine
    before a user's call raises (#2898).

    The lists name the vocabularies, not the fields of a row: a row's shape
    is what its dataclass in ``models.py`` states.
    """
    native = _load_native_module(
        Path(library_path).expanduser().resolve() if library_path is not None else None
    )
    decoded = json.loads(native.code_query_variant_inventory_json())
    if not isinstance(decoded, dict):
        raise SearchToolsError(
            "Native code-query inventory call did not return a JSON object"
        )
    return decoded
