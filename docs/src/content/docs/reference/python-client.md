---
title: Python Client API
description: Every public name in the bifrost_searchtools package, with signatures, defaults, return types, result fields, enum values, and errors.
---

This page lists the public API of the `bifrost_searchtools` package. The
distribution name on PyPI is `brokk-bifrost-searchtools`. The package version
is the Bifrost release version (0.12.0 for this page). For a task-oriented
introduction, see [Python Client](/python-client/).

The package can print its own export list and signatures:

```bash
python -c "import bifrost_searchtools; print(sorted(bifrost_searchtools.__all__))"
python -c "import bifrost_searchtools, inspect; print(inspect.signature(bifrost_searchtools.SearchToolsClient.query_code))"
```

## Requirements and Platforms

| Item | Value |
| --- | --- |
| Python version | 3.12 or later (`requires-python = ">=3.12"`). The client uses `enum.StrEnum`. |
| Wheel tag | `cp312-abi3`. One wheel serves Python 3.12 and every later 3.x release. |
| Wheel platforms | Linux x86_64 and aarch64 (manylinux2014), macOS x86_64 and arm64, Windows x86_64 (amd64). |
| Other platforms | Install from the sdist. The build needs a Rust toolchain (Rust 1.97 or later) and maturin 1.7 or later. |
| Python dependencies | None. |
| Native module | `bifrost_searchtools._native`, a compiled extension built with PyO3. |

## Module Contents

These names are importable from `bifrost_searchtools`.

| Name | Kind | Meaning |
| --- | --- | --- |
| `SearchToolsClient` | class | One in-process analysis session over one project root. |
| `SearchToolsError` | exception | Raised for every failure inside the native module. Subclass of `RuntimeError`. |
| `SymbolKindFilter` | enum | Declaration kind filter for symbol lookups. |
| `MostRelevantFilesRankingMode` | enum | Ranking algorithm for `most_relevant_files`. |
| `tool_descriptors` | function | Return the MCP tool descriptors for a toolset. |
| `code_query_variant_inventory` | function | Return the CodeQuery vocabulary that the loaded native build emits. |
| `extensions_for_paths` | function | Return every file extension for the languages present in a list of paths. |
| `parse_code_query_response` | function | Decode a `query_code` JSON payload into a typed response. |
| Result classes | dataclasses | Listed under [Result Classes](#result-classes) and [CodeQuery Result Types](#codequery-result-types). |
| Enums for result fields | enums | Listed under [Enums](#enums). |

Some classes exist only in `bifrost_searchtools.models` and are not exported
from the top-level package. Import them from `bifrost_searchtools.models`. They
are marked "models only" in the tables below.

## SearchToolsClient Constructor

```python
SearchToolsClient(
    root: Path | str,
    library_path: Path | str | None = None,
    render_line_numbers: bool = True,
    manual: bool = False,
    sources: list[str] | None = None,
    revision: str | None = None,
)
```

| Parameter | Type | Default | Meaning |
| --- | --- | --- | --- |
| `root` | `Path` or `str` | required | Project root. The client expands `~` and resolves the path to an absolute path. |
| `library_path` | `Path`, `str`, or `None` | `None` | Path to a built native library. `None` imports `bifrost_searchtools._native`. One process can load only one explicit library path. |
| `render_line_numbers` | `bool` | `True` | Whether rendered text includes line numbers. Structured line fields are present either way. |
| `manual` | `bool` | `False` | `True` starts a session with no file watcher. The caller reports changes through `update_paths`. |
| `sources` | `list[str]` or `None` | `None` | Restricts the session to the named files, directories, or globs. This makes a scoped session. |
| `revision` | `str` or `None` | `None` | Reads the `sources` files from this Git revision instead of the working tree. Requires `sources`. |

The constructor loads the native module but does not start the session. The
session starts on the first method call, or when a `with` block starts. Leaving
the `with` block calls `close()`.

Session modes:

| Mode | How to select it | File changes | Index build |
| --- | --- | --- | --- |
| Watched | default | A file watcher applies changes before each query. | On first use. |
| Manual | `manual=True` | Only `update_paths(...)` and `refresh()` apply changes. | When the session starts. |
| Scoped | `sources=[...]`, optionally `revision=...` | Only `update_paths(...)` and `refresh()` apply changes. Scoped sessions are always manual. | When the session starts. |

All three modes use the repository's persisted analyzer cache. A scoped
session shares stored file facts with the full workspace but keeps its own file
list. Cross-file results from a scoped session carry `session_subset` (a
`SessionSubset` with the field `files`). `session_subset` is `None` when the
session covers the whole workspace.

Each `sources` entry is a project-relative file, directory, or glob. Session
start fails with `SearchToolsError` when a path does not exist, a directory has
no analyzer-visible files, or a glob matches no files. With `revision`, the
client reads each selected file from that revision and skips binary files.

Constructor errors:

| Condition | Exception |
| --- | --- |
| `sources` and `manual=True` together | `ValueError` |
| `revision` without `sources` | `ValueError` |
| Native module cannot be imported or loaded | `SearchToolsError` |
| A different `library_path` is already loaded in this process | `SearchToolsError` |

## Session Methods

| Method | Returns | Meaning |
| --- | --- | --- |
| `close() -> None` | `None` | Closes the native session. Later calls raise `SearchToolsError("SearchToolsClient is closed")`. Calling `close()` again does nothing. |
| `gc() -> None` | `None` | Forces a Git-reachability garbage collection of the persisted analyzer cache and waits until it finishes. |
| `refresh() -> RefreshResult` | `RefreshResult` | Rescans the project from disk and re-analyzes it. |
| `update_paths(paths: list[str]) -> RefreshResult` | `RefreshResult` | Re-analyzes only the given project-relative paths. Use it with a manual or scoped session. |
| `activate_workspace(workspace_path: Path \| str) -> WorkspaceResult` | `WorkspaceResult` | Switches the session to another project root. |
| `get_active_workspace() -> WorkspaceResult` | `WorkspaceResult` | Returns the current project root. |

## Query Methods

Each method calls the Bifrost tool with the same name, unless the Notes column
says otherwise. The tool's own limits and argument rules are listed in the
[MCP tools reference](/reference/mcp-tools/). Parameters after `*` are
keyword-only. `kind_filter` and `ranking_mode` take enum members, not plain
strings.

### Symbols and Summaries

| Signature | Returns | Notes |
| --- | --- | --- |
| `search_symbols(patterns: list[str], *, include_tests: bool = False, limit: int = 20)` | `SearchSymbolsResult` | |
| `get_symbol_locations(symbols: list[str], *, kind_filter: SymbolKindFilter = SymbolKindFilter.ANY)` | `SymbolLocationsResult` | |
| `get_symbol_ancestors(symbols: list[str], *, kind_filter: SymbolKindFilter = SymbolKindFilter.CLASS)` | `SymbolAncestorsResult` | The default filter is `CLASS`, not `ANY`. |
| `get_symbol_sources(symbols: list[str], *, kind_filter: SymbolKindFilter = SymbolKindFilter.ANY)` | `SymbolSourcesResult` | |
| `get_summaries(targets: list[str])` | `FileSummariesResult` | Directory and package targets return entries in `listings`. A glob that matches too many files is reported in `too_broad`, and an ambiguous path in `ambiguous_paths`. |
| `list_symbols(file_patterns: list[str])` | `SkimFilesResult` | Not exposed to MCP agents. |
| `classify_test_files(file_paths: list[str])` | `dict[str, dict[str, Any]]` | Maps each resolved path to `{"kind": ..., "contains_test_code": bool}`. `kind` is `test`, `test_support`, `production`, or `ambiguous`. Inputs that do not resolve to exactly one file are left out. Not exposed to MCP agents. |

### Navigation

| Signature | Returns | Notes |
| --- | --- | --- |
| `get_declarations_by_location(references: list[dict[str, Any]])` | `list[DeclarationLookupResult]` | Each reference is `{"path": str, "line": int, "column": int}`. `line` and `column` are 1-based. |
| `get_definitions_by_location(references: list[dict[str, Any]])` | `list[DefinitionLookupResult]` | Same reference shape. |
| `get_definitions_by_reference(references: list[dict[str, str]])` | `list[DefinitionByReferenceLookupResult]` | Each reference is `{"symbol": str, "context": str, "target": str}`: copied source context and the target token. |
| `get_type_by_location(path: str, *, line: int \| None = None, column: int \| None = None)` | `TypeLookupResult` | Sends one reference and returns its single result. |
| `rename_symbol(path: str, *, new_name: str, line: int, column: int)` | `RenameSymbolResult` | Returns the edit set. It does not change files. `line` and `column` are 1-based and required. |

### Usages and Relevance

| Signature | Returns | Notes |
| --- | --- | --- |
| `scan_usages_by_reference(symbols: list[str], *, include_tests: bool = False, include_same_owner: bool = False, paths: list[str] \| None = None)` | `ScanUsagesResult` | `paths` narrows where usages are searched. `include_same_owner` lists the same-owner sites (`self`/`this` receivers and own-type static calls) that are otherwise only counted in `same_owner_sites`. |
| `scan_usages_by_location(targets: list[dict[str, Any]], *, include_tests: bool = False, include_same_owner: bool = False, paths: list[str] \| None = None)` | `ScanUsagesResult` | Each target is `{"path": str, "line": int, "column": int (optional), "symbol": str (optional)}`. `include_same_owner` is as for `scan_usages_by_reference`. |
| `usage_graph(*, include_tests: bool = False, paths: list[str] \| None = None, depth: int = 1)` | `UsageGraphResult` | `depth` below 1 raises `ValueError`. Without `paths`, every declaration is a root. |
| `most_relevant_files(seed_files: list[str], *, limit: int = 20, seed_weights: list[float] \| None = None, recency_half_life: float \| None = <unset>, ranking_mode: MostRelevantFilesRankingMode = MostRelevantFilesRankingMode.CASCADE)` | `MostRelevantFilesResult` | Sends `seed_files` as the tool argument `seed_file_paths`. `recency_half_life` is a Git recency half-life in commits. Omit it for the default of 250 commits. Pass `None` for uniform weighting. |

### Diff Review

With both `target` and `base` omitted, the diff runs from the merge base of
`HEAD` and the default branch named by `origin/HEAD` to the live working tree.
An explicit commit `target` without `base` compares that commit with its first
parent.

| Signature | Returns | Notes |
| --- | --- | --- |
| `analyze_diff(target: str \| None = None, *, base: str \| None = None, include_tests: bool = True)` | `DiffAnalysisResult` | The default for `include_tests` is `True`. |
| `blast_radius(target: str \| None = None, *, base: str \| None = None, max_scopes: int \| None = None)` | `BlastRadiusResult` | |
| `cyclomatic_complexity(target: str \| None = None, *, base: str \| None = None, include_tests: bool = False)` | `CyclomaticComplexityDiffResult` | |
| `missing_tests(target: str \| None = None, *, base: str \| None = None)` | `MissingTestsResult` | |

### Code Query

```python
query_code(
    pattern: dict[str, Any] | None = None,
    *,
    occurrences: dict[str, Any] | None = None,
    scopes: dict[str, Any] | None = None,
    bindings: dict[str, Any] | None = None,
    generation_sites: dict[str, Any] | None = None,
    exports: dict[str, Any] | None = None,
    dependency_evidence: dict[str, Any] | None = None,
    configuration_facts: dict[str, Any] | None = None,
    correlate: dict[str, Any] | None = None,
    require_both: dict[str, Any] | None = None,
    paths: dict[str, Any] | None = None,
    union: list[dict[str, Any]] | None = None,
    intersect: list[dict[str, Any]] | None = None,
    except_: list[dict[str, Any]] | None = None,
    query_file: str | None = None,
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
) -> CodeQueryResponse
```

| Parameter | Tool field | Meaning |
| --- | --- | --- |
| `pattern` | `match` | Structural pattern source. |
| `occurrences`, `scopes`, `bindings`, `generation_sites`, `exports`, `dependency_evidence`, `configuration_facts`, `paths` | same | Root source objects. Each takes the filter fields of its source. The [Code Query reference](/reference/code-query/) lists them. |
| `correlate`, `require_both` | same | Cross-domain sources. `correlate` pairs code and configuration rows through a registered relation. `require_both` requires both inputs to produce rows, without pairing them. |
| `union`, `intersect`, `except_` | `union`, `intersect`, `except` | Set sources. Each operand is a complete CodeQuery plan dictionary. |
| `query_file` | `query_file` | Workspace-relative `.rql` or `.json` file that holds the complete query. It is exclusive: pass no other query argument with it. |
| `inside`, `inside_decl`, `not_inside` | same | Structural scope. Valid only with `pattern`. |
| `where` | `where` | Project-relative globs or absolute paths inside the workspace. Applies to every source. |
| `languages` | `languages` | Language filter. Not valid with `dependency_evidence` or `configuration_facts`, which have no programming-language axis. |
| `steps` | `steps` | Semantic steps that run after the source. |
| `limit` | `limit` | Maximum terminal results. The tool default is 100 and the maximum is 1000. |
| `result_detail` | `result_detail` | `"compact"` (tool default) or `"full"`. |
| `schema_version` | `schema_version` | Optional. `1` is the only accepted value. |
| `execution_mode` | `execution_mode` | `"results"` (default), `"explain"`, or `"profile"`. |

`query_code` raises `ValueError` when:

- the call gives no query source, or more than one, and no `query_file`;
- `query_file` is given with any other query argument;
- `execution_mode` is not `"results"`, `"explain"`, or `"profile"`.

The engine rejects other invalid arguments, such as `inside` with a
non-`pattern` source or `languages` with `configuration_facts`. Those raise
`ValueError` with the engine's message.

The return type depends on `execution_mode`: `CodeQueryResult` for
`"results"`, `CodeQueryExplain` for `"explain"`, and `CodeQueryProfile` for
`"profile"`.

The complete source and step vocabulary is in the
[Code Query reference](/reference/code-query/).

The `taint`, `typestate`, and `value_flow` steps read results that a host
registered in the same process. Only the Rust `SearchToolsService` can register
them (see the [Rust API reference](/reference/rust-api/)). The Python client
has no registration method, so from Python these steps always return an
`unresolved_*_reference` diagnostic and no rows.

### Files

| Signature | Returns | Notes |
| --- | --- | --- |
| `get_file_contents(file_paths: list[str])` | `GetFileContentsResult` | Paths are project-relative or absolute inside the workspace. |
| `search_file_contents(patterns: list[str], *, file_path: str \| None = None, context_lines: int \| None = None, case_insensitive: bool = False)` | `SearchFileContentsResult` | `patterns` are regular expressions. `file_path` is a glob, or an absolute path or glob inside the workspace. |
| `find_files_containing(patterns: list[str], *, limit: int \| None = None, case_insensitive: bool = False)` | `FindFilesContainingResult` | `patterns` are regular expressions. |

### Code Quality

Every method in this group returns `CodeQualityReport`. `options` is a
dictionary whose keys are merged into the tool arguments unchanged. The
accepted keys for each tool are listed in the [MCP tools
reference](/reference/mcp-tools/).

| Signature | Notes |
| --- | --- |
| `compute_cyclomatic_complexity(file_paths: list[str], *, threshold: int \| None = None)` | Per-function cyclomatic complexity. Flags functions above `threshold`. |
| `compute_cognitive_complexity(file_paths: list[str], *, threshold: int \| None = None)` | Per-function cognitive complexity. Flags functions above `threshold`. |
| `report_comment_density_for_code_unit(fq_name: str, *, max_lines: int \| None = None)` | Comment density for one symbol, named by fully qualified name. |
| `report_comment_density_for_files(file_paths: list[str], *, max_top_level_rows: int \| None = None, max_files: int \| None = None)` | Comment density tables for files. |
| `report_exception_handling_smells(file_paths: list[str], *, min_score: int \| None = None, max_findings: int \| None = None, options: dict[str, Any] \| None = None)` | Generic, empty, or log-only exception handlers. |
| `report_test_assertion_smells(file_paths: list[str], *, min_score: int \| None = None, max_findings: int \| None = None, options: dict[str, Any] \| None = None)` | Weak or brittle test assertions. |
| `report_structural_clone_smells(file_paths: list[str], *, min_score: int \| None = None, max_findings: int \| None = None, options: dict[str, Any] \| None = None)` | Structural clones. |
| `report_long_method_and_god_object_smells(file_paths: list[str], *, max_findings: int \| None = None, max_files: int \| None = None, options: dict[str, Any] \| None = None)` | Oversized functions, classes, and modules. |
| `report_dead_code_and_unused_abstraction_smells(*, file_paths: list[str] \| None = None, fq_names: list[str] \| None = None, min_score: int \| None = None, max_findings: int \| None = None, options: dict[str, Any] \| None = None)` | Likely dead declarations and single-use abstractions. With no `file_paths`, the client sends an empty list and the tool finds candidates itself. |
| `report_secret_like_code(*, max_findings: int \| None = None, max_commits: int \| None = None, include_history_only: bool = False, include_low_confidence: bool = False)` | Secret-like strings in current files and Git history. Values are redacted. |
| `analyze_git_hotspots(*, since_days: int \| None = None, since_iso: str \| None = None, until_iso: str \| None = None, max_commits: int \| None = None, max_files: int \| None = None)` | Commit churn combined with complexity. `since_iso` overrides `since_days`. |

## Tools Without a Python Method

The client has no general-purpose tool call. These MCP tools have no Python
method:

| MCP tool | Use instead |
| --- | --- |
| `score_diff` | The CLI (`bifrost --tool score_diff`), MCP, or Rust `SearchToolsService`. |
| `list_policies` | The CLI (`bifrost --list-policies` or `bifrost --tool list_policies`), MCP, or Rust. |
| `run_policy` | The CLI (`bifrost --policy ...` or `bifrost --tool run_policy`), MCP, or Rust. |
| `explain_policy` | The CLI (`bifrost --tool explain_policy`), MCP, or Rust. |

These Python methods have no MCP tool in the default toolsets:

| Python method | Availability |
| --- | --- |
| `list_symbols` | CLI `--tool`, Rust, and Python only. MCP uses it internally to shorten oversized `get_summaries` responses. |
| `classify_test_files` | CLI `--tool`, Rust, and Python only. |
| `update_paths` | CLI `--tool`, Rust, and Python only. |
| `get_definitions_by_reference`, `scan_usages_by_reference` | MCP advertises these only when the server runs with `--no-line-numbers`, in place of `get_definitions_by_location`, `get_declarations_by_location`, and `scan_usages_by_location`. |

## Module Functions

| Signature | Returns | Meaning |
| --- | --- | --- |
| `tool_descriptors(toolset: str = "core", *, render_line_numbers: bool = True, library_path: Path \| str \| None = None)` | `list[dict[str, Any]]` | The MCP tool descriptors (name, description, input schema) for `toolset`. Valid toolsets are `core`, `searchtools`, `symbol`, `workspace`, `diff`, `extended`, `text`, `slopcop`, and `\|`-joined combinations such as `"symbol\|text"`. An unknown toolset raises `ValueError`. |
| `code_query_variant_inventory(*, library_path: Path \| str \| None = None)` | `dict[str, list[str]]` | The keys are `result_types`, `diagnostic_codes`, `diagnostic_impacts`, and `completion_kinds`. Each list is read from the loaded native build. Compare it with the Python models to detect a client that is older than the engine. |
| `extensions_for_paths(paths: list[str], *, library_path: Path \| str \| None = None)` | `list[str]` | Every file extension of every language present in `paths`, including extensions that the language reads for references only (for example `.vue` and `.svelte` for TypeScript). Sorted. Opens no workspace. Use it to build `sources` for a scoped session. |
| `parse_code_query_response(data: dict[str, Any], rendered_text: str \| None = None)` | `CodeQueryResponse` | Decodes a `query_code` structured payload. Returns `CodeQueryExplain` or `CodeQueryProfile` when `data["format"]` names one of them, and `CodeQueryResult` otherwise. |

## Errors

| Exception | When |
| --- | --- |
| `SearchToolsError` | Every failure inside the native module except invalid arguments: unknown tools, deadlines, internal errors, session start failures, cache collection failures, and calls after `close()`. The message is the engine's message. |
| `ValueError` | Argument checks in the Python client: the constructor rules, the `query_code` rules, `usage_graph(depth < 1)`, and an unknown toolset in `tool_descriptors`. Also invalid tool arguments that the engine rejects, and stale workspace generations. The message is the engine's message. |
| `AttributeError` | A plain string passed as `kind_filter` or `ranking_mode`. Pass the enum member. |

## Enums

All enums are `StrEnum` subclasses, so each member compares equal to its
string value.

| Enum | Values |
| --- | --- |
| `SymbolKindFilter` | `ANY = "any"`, `CLASS = "class"`, `FUNCTION = "function"`, `FIELD = "field"`, `MODULE = "module"` |
| `MostRelevantFilesRankingMode` | `CASCADE = "cascade"`, `HISTORY_IMPORTS = "history_imports"`, `USAGE_GRAPH = "usage_graph"`, `USAGE_GRAPH_EXACT = "usage_graph_exact"`. See the table below. |
| `NavigationOperation` | `declaration`, `definition` |
| `ContainerKind` | `directory`, `package` |
| `CodeQueryDiagnosticImpact` | `advisory`, `declared_non_exhaustive`, `incomplete`, `invalid` |
| `CodeQueryCompletionKind` | `complete`, `proven_subset`, `incomplete`, `cancelled`, `invalid` |
| `CodeQueryDiagnosticCode` | 99 diagnostic codes. The list and meanings are in the [Code Query reference](/reference/code-query/). `code_query_variant_inventory()["diagnostic_codes"]` prints the live list. |
| `CodeQuerySemanticProof` | `proven`, `unproven` |
| `CodeQuerySemanticCompleteness` | `complete`, `partial` |
| `CodeQueryFlowCertainty` | `exact`, `may` |
| `CodeQueryFlowStatus` | `complete`, `partial`, `ambiguous`, `unknown`, `unproven`, `unsupported`, `semantic_budget_exhausted`, `solver_budget_exhausted`, `semantic_cancelled`, `solver_cancelled`, `query_cancelled` |
| `CodeQueryFlowReachability` | `reached`, `not_reached`, `inconclusive` |
| `CodeQueryAbsentMemberWitnessStatus` | `available`, `truncated`, `unavailable` |
| `CodeQueryClassSetStatus` | `known`, `partial`, `no_information`, `inconclusive` |
| `CodeQueryTypestateCertainty` | `may`, `must`, `inconclusive` |
| `CodeQueryTypestateFindingKindType` | `error_transition`, `terminal_expectation` |
| `CodeQueryTypestateUncertainty` | `ambiguous_dispatch`, `unknown_call`, `external_call`, `escape`, `incomplete_analysis`, `unmatched_event` |
| `CodeQueryTypestateWitnessStepKindType` | `seed`, `edge`, `end_summary_gap` |
| `CodeQueryProgramPointBoundary` | `entry`, `normal_exit`, `exceptional_exit` |
| `CodeQueryLogicalOperationKind` | `seed`, `step`, `set`, `limit` |
| `CodeQueryPhysicalOperator` | `seed_scan`, `pipeline_step`, `sequential_union`, `parallel_union`, `sequential_intersection`, `sequential_except`, `limit` |
| `CodeQuerySchedulingPolicy` | `auto` |
| `CodeQuerySelectedScheduling` | `sequential`, `parallel` |
| `CodeQueryOperatorDisposition` | `completed`, `skipped`, `cancelled` |
| `CodeQueryOperatorTermination` | `cancellation_before_work`, `cancellation_during_work`, `dependency_cancelled`, `dependency_pipeline_halted`, `terminal_cap`, `result_limit`, `execution_budget`, `pipeline_budget`, `import_graph_budget`, `analysis_limit`, `unsupported_analysis`, `analysis_incomplete` |
| `CodeQueryCacheLayerKind` | `seed_result`, `seed_structural_facts`, `inbound_reference`, `outbound_reference`, `incoming_call`, `outgoing_call`, `import_forward`, `import_reverse`, `direct_import_topology` |
| `CodeQueryCacheMetricsKind` | `complete_value`, `structural_facts` |

`MostRelevantFilesRankingMode` values:

| Value | Ranking |
| --- | --- |
| `cascade` | Default. Priority tiers over test and source mirrors, shared base names, Git co-edits, directory membership, and import adjacency. Works in a repository with no usable Git history. |
| `history_imports` | Git co-edit history first, then import adjacency fills the remaining slots. |
| `usage_graph` | PageRank over the fast structured file graph. The `history_imports` ranking fills the remaining slots. |
| `usage_graph_exact` | Ranking over the exact symbol-level caller-to-callee graph. The `history_imports` ranking fills the remaining slots. |

If a usage graph build is cancelled or exceeds the interactive time budget,
the result has `complete=False`, an `incomplete_reason`, and the
`history_imports` ranking.

Some result fields use a `Literal` type instead of an enum:

| Type alias (in `bifrost_searchtools.models`) | Values |
| --- | --- |
| `CodeQueryExecutionMode` (exported) | `results`, `explain`, `profile` |
| `MostRelevantFilesIncompleteReasonValue` | `cancelled`, `time_budget` |
| `SymbolSourcesIncompleteReasonValue` | `cancelled` |
| `DefinitionLookupIncompleteReasonValue` (models only) | `cancelled`, `time_budget`, `resolution_budget`, `analysis_failure`, `structure_unavailable`, `navigation_targets` |
| `TooBroadMatchValue` (models only) | `files`, `declarations` |
| `TestFileKindValue` | `test`, `test_support`, `production`, `ambiguous` |
| `FileGraphCompletionValue` | `complete`, `incomplete` |
| `BlastRadiusBaseRecoveryValue` | `not_needed`, `complete`, `cancelled` |
| `BlastRadiusIncompleteReasonValue` | `target_graph_cancelled`, `base_graph_cancelled`, `compilation_scope_unresolved`, `unresolved_changed_paths`, `unresolved_base_paths` |
| `BlastRadiusCallableChangeValue` | `edited`, `introduced`, `deleted`, `moved`, `signature_changed` |
| `BlastRadiusScopeKindValue` | `file`, `directory` |
| `MissingTestsModeValue` (exported) | `file_imports_then_exact_usages`, `file_graph_narrowed_binding_reachability` |
| `MissingTestsIncompleteReasonValue` (exported) | `target_graph_cancelled`, `compilation_scope_unresolved`, `unresolved_changed_path`, `changed_function_unresolved`, `usage_cancelled`, `usage_time_budget`, `usage_candidate_files`, `usage_source_bytes`, `usage_callsites`, `usage_response_budget`, `usage_resolution_candidates`, `usage_target_not_found`, `usage_target_ambiguous`, `usage_analysis_failure`, `usage_analysis_incomplete`, `unproven_references`, `usage_site_without_enclosing_declaration`, `unresolved_changed_target`, `open_binding_frontier`, `unsupported_binding_boundary`, `unproven_binding_edge`, `reference_graph_cancelled`, `reference_graph_stale` |
| `CyclomaticComplexityChangeValue` (exported) | `introduced`, `edited` |
| `MostRelevantFilesRankingModeValue` | `cascade`, `history_imports`, `usage_graph`, `usage_graph_exact` |

## Result Classes

All result classes are frozen dataclasses. A class with `render_text()`
returns readable text. When the engine rendered the text, `render_text()`
returns that text unchanged. A class with a `count` property returns the
number of items in its main list.

### Top-Level Results

| Class | Returned by | `render_text()` | Fields |
| --- | --- | --- | --- |
| `RefreshResult` | `refresh`, `update_paths` | yes | `languages: list[str]`, `analyzed_files: int`, `declarations: int` |
| `WorkspaceResult` | `activate_workspace`, `get_active_workspace` | yes | `workspace_path: str`, `session_subset: SessionSubset \| None` |
| `SearchSymbolsResult` | `search_symbols` | yes, `count` | `patterns: list[str]`, `truncated: bool`, `total_files: int`, `files: list[SearchSymbolsFile]`, `session_subset: SessionSubset \| None` |
| `SymbolLocationsResult` | `get_symbol_locations` | yes, `count` | `locations: list[SymbolLocation]`, `not_found: list[str]` |
| `SymbolAncestorsResult` | `get_symbol_ancestors` | yes, `count` | `ancestors: list[SymbolAncestors]`, `not_found: list[str]`, `ambiguous: list[AmbiguousSymbol]` |
| `SymbolSourcesResult` | `get_symbol_sources` | yes, `count` | `sources: list[SourceBlock]`, `not_found: list[str]`, `ambiguous: list[AmbiguousSymbol]`, `complete: bool`, `incomplete: list[SymbolSourcesIncomplete]` |
| `FileSummariesResult` (alias of `SymbolSummariesResult`) | `get_summaries` | yes, `count` | `summaries: list[SummaryBlock]`, `listings: list[ContainerListing]`, `compact_symbols: SkimFilesResult \| None`, `not_found: list[str]`, `ambiguous: list[AmbiguousSymbol]`, `ambiguous_paths: list[AmbiguousPath]`, `too_broad: list[TooBroadScope]` |
| `SkimFilesResult` | `list_symbols` | yes, `count` | `truncated: bool`, `total_files: int`, `files: list[SkimFile]` |
| `DeclarationLookupResult` | `get_declarations_by_location` (one per reference) | yes | `query: dict`, `operation: NavigationOperation`, `status: str`, `complete: bool`, `incomplete_reason: DefinitionLookupIncompleteReasonValue \| None`, `reference: DefinitionReferenceSite \| None`, `declarations: list[DefinitionCandidate]`, `diagnostics: list[DefinitionDiagnostic]` |
| `DefinitionLookupResult` | `get_definitions_by_location` (one per reference) | yes | `query: dict`, `operation: NavigationOperation`, `status: str`, `complete: bool`, `incomplete_reason: DefinitionLookupIncompleteReasonValue \| None`, `reference: DefinitionReferenceSite \| None`, `definitions: list[DefinitionCandidate]`, `diagnostics: list[DefinitionDiagnostic]` |
| `DefinitionByReferenceLookupResult` | `get_definitions_by_reference` (one per reference) | yes | `query: dict`, `status: str`, `complete: bool`, `incomplete_reason: DefinitionLookupIncompleteReasonValue \| None`, `definitions: list[DefinitionCandidate]`, `diagnostics: list[DefinitionDiagnostic]` |
| `TypeLookupResult` | `get_type_by_location` | yes | `query: dict`, `status: str`, `reference: DefinitionReferenceSite \| None`, `types: list[TypeLookupCandidate]`, `diagnostics: list[DefinitionDiagnostic]` |
| `RenameSymbolResult` | `rename_symbol` | yes | `query: dict`, `status: str`, `target: RenameSymbolTarget \| None`, `old_name: str \| None`, `edits: list[RenameFileEdits]`, `diagnostics: list[DefinitionDiagnostic]` |
| `ScanUsagesResult` | `scan_usages_by_reference`, `scan_usages_by_location` | yes | `structured: dict`, the tool's JSON result without a typed model. `rendered_text: str \| None`. |
| `UsageGraphResult` | `usage_graph` | yes | `nodes: list[UsageGraphNode]`, `edges: list[UsageGraphEdge]`, `truncated_symbols: list[UsageGraphTruncatedSymbol]`, `session_subset: SessionSubset \| None` |
| `MostRelevantFilesResult` | `most_relevant_files` | yes, `count` | `files: list[MostRelevantFile]`, `not_found: list[str]`, `duplicates: list[str]`, `complete: bool`, `ranking_mode_used: str`, `incomplete_reason: str \| None` (`cancelled` or `time_budget`), `session_subset: SessionSubset \| None` |
| `DiffAnalysisResult` | `analyze_diff` | no | `endpoints: DiffEndpoints`, `file_changes: list[FileChange]`, `patch_symbols: PatchSymbols`, `dependency_symbols: list[CommitSymbol]`, `import_changes: list[ImportChange]`, `unattributed_call_edge_changes: list[CallEdgeChange]`, `large_callsite_symbols: list[LargeCallsiteSymbol]` |
| `BlastRadiusResult` | `blast_radius` | yes | `endpoints: DiffEndpoints`, `analysis: BlastRadiusAnalysis`, `changed_callables: list[ChangedCallable]`, `test_scopes: list[TestScope]` |
| `CyclomaticComplexityDiffResult` | `cyclomatic_complexity` | yes | `endpoints: DiffEndpoints`, `summary: CyclomaticComplexitySummary`, `functions: list[CyclomaticComplexityChange]`, `analysis: CyclomaticComplexityAnalysis` |
| `MissingTestsResult` | `missing_tests` | yes | `endpoints: DiffEndpoints`, `analysis: MissingTestsAnalysis`, `missing_functions: list[MissingTestFunction]`, `indeterminate_functions: list[MissingTestFunction]` |
| `GetFileContentsResult` | `get_file_contents` | no, `count` | `files: list[FileContent]`, `not_found: list[str]`, `ambiguous_paths: list[AmbiguousPath]` |
| `SearchFileContentsResult` | `search_file_contents` | no, `count` | `matches: list[FileMatchGroup]`, `truncated: bool`, `invalid_patterns: list[str]`, `ambiguous_paths: list[AmbiguousPath]` |
| `FindFilesContainingResult` | `find_files_containing` | no, `count` | `files: list[str]`, `truncated: bool`, `invalid_patterns: list[str]` |
| `CodeQualityReport` | all code-quality methods | yes | `report: str` (the engine's rendered report), `truncated: bool`, `ambiguous_paths: list[AmbiguousPath]`. `str(report)` returns `report`. |

Result classes that hold a rendered-text field also carry `rendered_text: str
| None`. Classes that render line numbers also carry `render_line_numbers:
bool`. These two fields are omitted from the table.

`complete` is `False` only when the engine reports the lookup as incomplete,
and `incomplete_reason` then names the cause. Read `status` and `diagnostics`
for detail.

Fields that the Rust result reports but the Python model drops:

- `FileSummariesResult.compact_symbols` is always `None` for Python callers.
  Only the MCP server replaces oversized summaries with a compact symbol list.

`status` on the navigation results is an open string set. Current values are
`resolved`, `no_definition`, `no_declaration`, `unresolvable_import_boundary`,
`ambiguous`, `unsupported_language`, `invalid_location`, `not_found`,
`incomplete`, `cancelled`, and `exceeded_budget`.

### Nested Classes

| Class | Fields |
| --- | --- |
| `SessionSubset` | `files: int`, the number of files in the scoped session. |
| `AmbiguousSymbol` | `target: str`, `matches: list[str]` |
| `AmbiguousPath` | `input: str`, `matches: list[str]` |
| `TooBroadScope` | `target: str`, `matched: int`, `cap: int`, `matched_kind: str` (`files` or `declarations`), `sample: list[str]`, `note: str` |
| `SearchSymbolsFile` | `path: str`, `loc: int`, `classes`, `functions`, `fields`, `modules` (each `list[SearchSymbolHit]`) |
| `SearchSymbolHit` | `symbol: str`, `signature: str`, `line: int` |
| `SymbolLocation` | `symbol: str`, `path: str`, `loc: int`, `start_line: int`, `end_line: int` |
| `SymbolAncestors` | `symbol: str`, `ancestors: list[str]` |
| `SymbolSourcesIncomplete` | `target: str`, `reason: str` (`cancelled`) |
| `SourceBlock` | `label: str`, `path: str`, `start_line: int`, `end_line: int`, `text: str` |
| `SummaryBlock` | `label: str`, `path: str`, `preamble: str`, `elements: list[SummaryElement]` |
| `SummaryElement` | `path: str`, `symbol: str`, `kind: str`, `start_line: int`, `end_line: int`, `text: str`, `parent_symbol: str \| None` |
| `ContainerListing` | `target: str`, `kind: ContainerKind`, `languages: list[str]`, `entries: list[ContainerListingEntry]`, `total_entries: int`, `truncated: bool` |
| `ContainerListingEntry` | Union of the four entry classes below. Each has a class attribute `kind`. |
| `DirectoryListingEntry` | `kind = "directory"`. `name: str`, `path: str` |
| `FileListingEntry` | `kind = "file"`. `name: str`, `path: str` |
| `PackageListingEntry` | `kind = "package"`. `name: str`, `qualified_name: str`, `languages: list[str]` |
| `TypeListingEntry` | `kind = "type"`. `name: str`, `symbol: str`, `language: str`, `path: str`, `start_line: int`, `end_line: int` |
| `SkimFile` | `path: str`, `loc: int`, `lines: list[str]` |
| `DefinitionReferenceSite` | `path: str`, `target: str` |
| `DefinitionCandidate` | `name: str`, `fqn: str \| None`, `path: str`, `start_line: int`, `start_column: int \| None`, `end_line: int`, `end_column: int \| None`, `kind: str`, `signature: str \| None`, `language: str` |
| `DefinitionDiagnostic` | `kind: str`, `message: str` |
| `TypeLookupCandidate` | `fqn: str`, `kind: str \| None`, `language: str \| None`, `definitions: list[DefinitionCandidate]` |
| `RenameSymbolTarget` | `symbol: str`, `kind: str`, `path: str` |
| `RenameFileEdits` | `path: str`, `edits: list[RenameTextEdit]` |
| `RenameTextEdit` | `old_text: str`, `start_line: int`, `start_column: int`, `end_line: int`, `end_column: int`, `new_text: str` |
| `UsageGraphNode` | `fqn: str`, `language: str`, `path: str`, `start_line: int`, `kind: str`, `signature: str \| None` |
| `UsageGraphEdge` | `from_fqn: str`, `to_fqn: str`, `language: str`, `weight: int`, `sites: list[UsageGraphCallSite]`. `len(sites) == weight`. |
| `UsageGraphCallSite` | `path: str`, `line: int` |
| `UsageGraphTruncatedSymbol` | `fqn: str`, `language: str`, `total_callsites: int`, `limit: int` |
| `MostRelevantFile` | `path: str`, `test: str` (`test`, `test_support`, `production`, or `ambiguous`) |
| `DiffEndpoints` | `base: str`, `target: str` |
| `FileChange` | `old_path: str \| None`, `path: str \| None`, `status: str`, `insertions: int`, `deletions: int`, `is_binary: bool`, `is_test: bool`, `is_parseable: bool` |
| `PatchSymbols` | `edited: list[EditedSymbolPair]`, `introduced: list[IntroducedSymbol]`, `deleted: list[DeletedSymbol]`, `moved: list[MovedSymbol]`, `signature_changes: list[SignatureChange]` |
| `CommitSymbol` | `fqn: str`, `name: str`, `kind: str`, `signature: str`, `path: str`, `start_line: int`, `end_line: int`, `language: str`, `is_test: bool` |
| `EditedSymbolPair` | `before: CommitSymbol`, `after: CommitSymbol`, `touched_old_lines: list[int]`, `touched_new_lines: list[int]`, `added_calls: list[CalleeChange]`, `removed_calls: list[CalleeChange]` |
| `IntroducedSymbol` | `after: CommitSymbol`, `touched_new_lines: list[int]`, `calls: list[CalleeChange]` |
| `DeletedSymbol` | `before: CommitSymbol`, `touched_old_lines: list[int]`, `called: list[CalleeChange]` |
| `MovedSymbol` | `before: CommitSymbol`, `after: CommitSymbol`, `added_calls: list[CalleeChange]`, `removed_calls: list[CalleeChange]` |
| `SignatureChange` | `before: CommitSymbol`, `after: CommitSymbol` |
| `CalleeChange` | `to_fqn: str`, `language: str`, `weight: int`, `sites: list[UsageGraphCallSite]` |
| `CallEdgeChange` | `change: str`, `from_fqn: str`, `to_fqn: str`, `language: str`, `weight: int`, `sites: list[UsageGraphCallSite]` |
| `ImportChange` | `path: str`, `added: list[str]`, `removed: list[str]` |
| `LargeCallsiteSymbol` | `fqn: str`, `language: str`, `total_callsites: int`, `limit: int` |
| `BlastRadiusAnalysis` | `mode: str` (`file_imports`), `graph_completion: str`, `base_recovery: str`, `reached_test_file_count: int`, `paths_outside_file_graph: list[str]`, `analyzer_changed_test_paths: list[str]`, `unresolved_changed_paths: list[str]`, `unavailable_removed_test_count: int`, `incomplete_reasons: list[str]` |
| `ChangedCallable` | `before: BlastRadiusCallableSymbol \| None`, `after: BlastRadiusCallableSymbol \| None`, `changes: list[str]` |
| `BlastRadiusCallableSymbol` | `fqn: str`, `name: str`, `kind: str`, `signature: str`, `path: str`, `start_line: int`, `end_line: int`, `language: str`, `in_test_context: bool` |
| `TestScope` | `path: str`, `kind: str` (`file` or `directory`), `reached_file_count: int`, `covered_analyzable_file_count: int`, `minimum_dependency_distance: int`, `maximum_dependency_distance: int`, `sample_reached_files: list[str]` |
| `CyclomaticComplexitySummary` | `introduced: int`, `edited: int`, `increased: int`, `decreased: int`, `unchanged: int` |
| `CyclomaticComplexityChange` | `change: str` (`introduced` or `edited`), `before: CyclomaticComplexityFunction \| None`, `after: CyclomaticComplexityFunction`, `delta: int \| None` |
| `CyclomaticComplexityFunction` | `fqn: str`, `name: str`, `signature: str`, `path: str`, `start_line: int`, `end_line: int`, `language: str`, `is_test: bool`, `complexity: int` |
| `CyclomaticComplexityAnalysis` | `paths_outside_analysis: list[str]`, `unresolved_changed_paths: list[str]` |
| `MissingTestsAnalysis` | `mode: str`, `file_graph_completion: str`, `exact_usage_completion: str`, `candidate_function_count: int`, `reached_function_count: int`, `missing_function_count: int`, `indeterminate_function_count: int`, `paths_outside_file_graph: list[str]`, `unresolved_changed_paths: list[str]`, `incomplete_reasons: list[str]` |
| `MissingTestFunction` | `before: BlastRadiusCallableSymbol \| None`, `after: BlastRadiusCallableSymbol`, `changes: list[str]`, `incomplete_reasons: list[str]` |
| `FileContent` | `path: str`, `content: str`, `truncated: bool`, `total_lines: int \| None`, `head_lines: int \| None`, `tail_lines: int \| None` |
| `FileMatchGroup` | `path: str`, `matches: list[LineMatch]`, `truncated: bool` |
| `LineMatch` | `line: int`, `text: str`, `before: list[str]`, `after: list[str]` |
| `JqFileResult` | `path: str`, `matches: list[str]`, `truncated: bool`, `error: str \| None` |
| `XmlSelectFile` | `path: str`, `matches: list[str]`, `error: str \| None` |
| `XmlSkimFile` | `path: str`, `elements: list[XmlSkimElement]`, `error: str \| None` |
| `XmlSkimElement` | `tag: str`, `depth: int`, `attribute_count: int` |

`JqFileResult`, `XmlSelectFile`, `XmlSkimFile`, and `XmlSkimElement` are
exported, but no current client method returns them.

## CodeQuery Responses

| Class | Returned for | Fields |
| --- | --- | --- |
| `CodeQueryResult` | `execution_mode="results"` | `results: list[CodeQueryResultItem]`, `diagnostics: list[CodeQueryDiagnostic]`, `truncated: bool`, `session_subset: SessionSubset \| None`, `rendered_text: str \| None` |
| `CodeQueryExplain` | `execution_mode="explain"` | `format: str`, `query_schema_version: int`, `parsed_query`, `logical_plan: CodeQueryLogicalPlan`, `physical_plan`, `scheduling: CodeQueryExplainScheduling`, `rendered_text`, `extra: dict` |
| `CodeQueryProfile` | `execution_mode="profile"` | `format: str`, `result: CodeQueryResult`, `explain: CodeQueryExplain`, `timings_ns`, `work`, `cache_layers: list`, `access_path: CodeQueryAccessPathProfile`, `scheduling`, `operators: list[CodeQueryOperatorObservation]`, `rendered_text`, `extra: dict` |
| `CodeQueryDiagnostic` | inside every result | `code: CodeQueryDiagnosticCode`, `impact: CodeQueryDiagnosticImpact`, `message: str`, `language: str`, `branch: list[int]`, `exhausted_roots: list` |

`CodeQueryResponse` is the type alias `CodeQueryResult | CodeQueryExplain |
CodeQueryProfile`. `CodeQueryResultItem` is the union of the 75 row classes in
the next table. The profile and explain report formats are described in
[Explain and Profile CodeQuery](/code-query-explain-profile/).

## CodeQuery Result Types

Each row in `CodeQueryResult.results` is an instance of the class that matches
its `result_type`. The mapping comes from
`bifrost_searchtools._generated_query_models.CODE_QUERY_RESULT_ITEM_TYPES`.
The fields of each row type are listed in the [Code Query
reference](/reference/code-query/). In Python, `dataclasses.fields(cls)` lists
them for any class.

"Top level" means `from bifrost_searchtools import <class>` works. "Models
only" means you must import the class from `bifrost_searchtools.models`.

| `result_type` | Python class | Import |
| --- | --- | --- |
| `structural_match` | `CodeQueryMatch` (alias of `CodeQueryStructuralMatch`) | top level |
| `declaration` | `CodeQueryDeclaration` | top level |
| `procedure` | `CodeQueryProcedure` | top level |
| `program_point` | `CodeQueryProgramPoint` | top level |
| `control_edge` | `CodeQueryControlEdge` | top level |
| `typestate_finding` | `CodeQueryTypestateFinding` | top level |
| `typestate_witness` | `CodeQueryTypestateWitness` | top level |
| `flow_endpoint` | `CodeQueryFlowEndpoint` | top level |
| `flow_witness` | `CodeQueryFlowWitness` | top level |
| `class_set_row` | `CodeQueryClassSetRow` | top level |
| `absent_member_finding` | `CodeQueryAbsentMemberFinding` | top level |
| `absent_member_witness` | `CodeQueryAbsentMemberWitness` | top level |
| `taint_finding` | `CodeQueryTaintFinding` | top level |
| `file` | `CodeQueryFile` | top level |
| `configuration_fact` | `CodeQueryConfigurationFact` | top level |
| `reference_site` | `CodeQueryReferenceSite` | top level |
| `call_site` | `CodeQueryCallSite` | top level |
| `expression_site` | `CodeQueryExpressionSite` | top level |
| `jsx_attribute_value` | `CodeQueryJsxAttributeValue` | top level |
| `receiver_analysis` | `CodeQueryReceiverAnalysis` | top level |
| `member_target_analysis` | `CodeQueryMemberTargetAnalysis` | top level |
| `receiver_outcome` | `CodeQueryReceiverOutcome` | top level |
| `receiver_evidence` | `CodeQueryReceiverEvidence` | top level |
| `field_write_value` | `CodeQueryFieldWriteValue` | top level |
| `keyed_read_value` | `CodeQueryRuntimeKeyedReadValue` (alias of `CodeQueryKeyedReadValue`) | top level |
| `call_shape` | `CodeQueryCallShape` | top level |
| `call_result` | `CodeQueryCallResult` | top level |
| `call_argument_group` | `CodeQueryCallArgumentGroup` | top level |
| `call_argument` | `CodeQueryCallShapeArgument` | top level |
| `call_binding` | `CodeQueryCallBinding` | top level |
| `call_effect` | `CodeQueryCallEffect` | top level |
| `call_result_contract` | `CodeQueryCallResultContract` | top level |
| `call_result_obligation` | `CodeQueryCallResultObligation` | top level |
| `result_subject_use` | `CodeQueryResultSubjectUse` | top level |
| `result_contract_use` | `CodeQueryResultContractUse` | top level |
| `result_contract_failure_use` | `CodeQueryResultContractFailureUse` | top level |
| `nilness_operation` | `CodeQueryNilnessOperation` | top level |
| `switch_coverage` | `CodeQuerySwitchCoverage` | top level |
| `assignment_relation` | `CodeQueryAssignmentRelation` | top level |
| `detached_task_transfer` | `CodeQueryDetachedTaskTransfer` | top level |
| `procedure_effect` | `CodeQueryProcedureEffect` | top level |
| `callable_signature` | `CodeQueryCallableSignature` | top level |
| `signature_parameter` | `CodeQuerySignatureParameter` | top level |
| `decorated_parameter` | `CodeQueryDecoratedParameter` | top level |
| `callable_applicability` | `CodeQueryCallableApplicability` | top level |
| `overload_selection` | `CodeQueryOverloadSelection` | top level |
| `member_selection` | `CodeQueryMemberSelection` | top level |
| `dispatch_outcome` | `CodeQueryDispatchOutcome` | top level |
| `dispatch_target` | `CodeQueryDispatchTarget` | top level |
| `member_family` | `CodeQueryMemberFamily` | top level |
| `member_family_edge` | `CodeQueryMemberFamilyEdge` | top level |
| `occurrence` | `CodeQueryOccurrence` | top level |
| `lexical_scope` | `CodeQueryLexicalScope` | top level |
| `binding` | `CodeQueryBinding` | top level |
| `resolution_candidate` | `CodeQueryResolutionCandidate` | top level |
| `candidate_hop` | `CodeQueryCandidateHop` | top level |
| `generation_site` | `CodeQueryGenerationSite` | top level |
| `export` | `CodeQueryExport` | top level |
| `declaration_state` | `CodeQueryDeclarationState` | top level |
| `reference_edge` | `CodeQueryReferenceEdge` | top level |
| `state_event` | `CodeQueryStateEvent` | top level |
| `flow_relation` | `CodeQueryFlowRelation` | top level |
| `control_relation` | `CodeQueryControlRelation` | top level |
| `branch_relation` | `CodeQueryBranchRelation` | top level |
| `loop_relation` | `CodeQueryLoopRelation` | top level |
| `failure_handler_state` | `CodeQueryFailureHandlerState` | top level |
| `statement_reachability` | `CodeQueryStatementReachability` | top level |
| `guard` | `CodeQueryGuard` | top level |
| `rewrite_path` | `CodeQueryRewritePath` | top level |
| `qualified_path` | `CodeQueryQualifiedPath` | top level |
| `path_segment` | `CodeQueryPathSegment` | top level |
| `source_set` | `CodeQuerySourceSet` | top level |
| `build_target` | `CodeQueryBuildTarget` | top level |
| `topology_edge` | `CodeQueryTopologyEdge` | top level |

`code_query_variant_inventory()["result_types"]` returns the same 75 labels
from the loaded native build. If the engine emits a `result_type` that the
Python models do not know, decoding raises `ValueError`.
