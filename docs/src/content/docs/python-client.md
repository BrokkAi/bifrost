---
title: Python Client
description: Use Bifrost from Python through the native searchtools package.
---

The Python distribution is `brokk-bifrost-searchtools`. Import it as `bifrost_searchtools`.

```bash
pip install brokk-bifrost-searchtools
```

The package requires Python 3.12 or later. Wheels are `cp312-abi3`, so one
wheel serves Python 3.12 and every later 3.x release. Wheels exist for Linux
x86_64 and aarch64 (manylinux2014), macOS x86_64 and arm64, and Windows x86_64.
On other platforms, pip builds the package from the sdist, which needs a Rust
toolchain. pip does not install the package on Python 3.11 or earlier.

For repository-local development, build the extension in place with maturin:

```bash
uv run --python 3.12 --with maturin maturin develop
```

Every class, method, argument, default, and result field is listed in the
[Python Client API reference](/reference/python-client/).

## Quick Start

```python
from bifrost_searchtools import MostRelevantFilesRankingMode, SearchToolsClient

with SearchToolsClient("/path/to/project") as client:
    print(client.get_summaries(["src/main.py"]).render_text())

    for file in client.search_symbols(["parse_*"], limit=10).files:
        print(file.path)

    print(client.most_relevant_files(["src/main.py"]).render_text())

    print(client.most_relevant_files(
        ["src/main.py"],
        limit=10,
        ranking_mode=MostRelevantFilesRankingMode.USAGE_GRAPH,
    ).render_text())
```

The client talks directly to Rust through a native extension module. It does
not start an MCP subprocess. Results are typed dataclasses from
`bifrost_searchtools.models`. Most of them have a `render_text()` method that
returns readable text.

Pass `render_line_numbers=False` to `SearchToolsClient(...)` to omit line
numbers from rendered text. The structured line fields stay in the result
objects.

## Runnable Example

The repository includes a runnable Python demo at [`examples/searchtools_demo.py`](https://github.com/BrokkAi/bifrost/blob/master/examples/searchtools_demo.py). It uses PEP 723 inline dependencies, so `uv run` fetches the published wheel into an isolated environment:

```bash
uv run examples/searchtools_demo.py --root /path/to/repo Calculator compute
```

Omit the symbol patterns to print a directory overview:

```bash
uv run examples/searchtools_demo.py --root /path/to/repo
```

See the [`examples/README.md`](https://github.com/BrokkAi/bifrost/blob/master/examples/README.md) for the published-wheel validation script and notes on when the demo imports the PyPI wheel versus local checkout sources.

## Sessions and Workspace Updates

The session starts on the first method call, or when the `with` block starts.
Leaving the `with` block closes it. Outside a `with` block, call `close()`.

By default, the client indexes the project on first use, keeps the index warm
for the session, and watches the file system so later queries see edits.

`refresh()` rescans the project from disk and re-analyzes it. Query methods
already apply changes that the file watcher detected, so use `refresh()` to
recover or to force a full rescan, not before every request.

Use `manual=True` with `update_paths(...)` when the caller wants to control
incremental updates. A manual session has no file watcher.

Use `sources=[...]` to analyze only some files. Each entry is a
project-relative file, directory, or glob. Add `revision="<git revision>"` to
read those files at a Git revision instead of the working tree. A session with
`sources` is always manual, so `sources` together with `manual=True` raises
`ValueError`, and `revision` without `sources` raises `ValueError`. Results
from a scoped session carry `session_subset`, which gives the number of files
in the session. Read it before you treat an empty result as proof of absence:
the result covers only those files. `extensions_for_paths(paths)` returns the
file extensions of the languages in a list of paths, which helps you choose
`sources` for a diff.

```python
from bifrost_searchtools import SearchToolsClient

with SearchToolsClient("/path/to/project", sources=["src/billing"], revision="HEAD~1") as client:
    result = client.search_symbols(["Invoice*"])
    print(result.session_subset)
```

All session types use the repository's persisted analyzer cache. Linked Git
worktrees share the primary worktree's cache. `gc()` forces a collection of
that cache and waits until it finishes. See [Data and Trust
Boundaries](/data-boundaries/) for where the cache lives.

## What the Client Covers

| Area | Methods |
| --- | --- |
| Session | `close()`, `gc()`, `refresh()`, `update_paths(...)`, `activate_workspace(...)`, `get_active_workspace()` |
| Symbols and summaries | `search_symbols(...)`, `get_symbol_locations(...)`, `get_symbol_ancestors(...)`, `get_symbol_sources(...)`, `get_summaries(...)`, `list_symbols(...)`, `classify_test_files(...)` |
| Declarations, definitions, and types | `get_declarations_by_location(...)`, `get_definitions_by_location(...)`, `get_definitions_by_reference(...)`, `get_type_by_location(...)` |
| Usages and graph | `scan_usages_by_reference(...)`, `scan_usages_by_location(...)`, `rename_symbol(...)`, `usage_graph(...)`, `most_relevant_files(...)` |
| Diff review | `list_function_sources(...)`, `analyze_diff(...)`, `blast_radius(...)`, `cyclomatic_complexity(...)`, `missing_tests(...)` |
| Code query | `query_code(...)` |
| Files | `get_file_contents(...)`, `search_file_contents(...)`, `find_files_containing(...)` |
| Code quality | `compute_cyclomatic_complexity(...)`, `compute_cognitive_complexity(...)`, `report_comment_density_for_code_unit(...)`, `report_comment_density_for_files(...)`, `report_exception_handling_smells(...)`, `report_test_assertion_smells(...)`, `report_structural_clone_smells(...)`, `report_long_method_and_god_object_smells(...)`, `report_dead_code_and_unused_abstraction_smells(...)`, `report_secret_like_code(...)`, `analyze_git_hotspots(...)` |

The client wraps most MCP tools. It does not wrap `score_diff`,
`list_policies`, `run_policy`, or `explain_policy`; use the CLI, MCP, or the
Rust `SearchToolsService` for those. `list_symbols`, `classify_test_files`, and
`update_paths` are available through the CLI, Rust, and Python, but not to MCP
agents.

Code-quality methods return `CodeQualityReport`, whose `report` field holds the
engine's rendered report. The many per-rule tuning settings on the smell
reports go in an `options` dictionary. Its keys are passed to the Rust tool
arguments unchanged.

`analyze_diff`, `get_file_contents`, `search_file_contents`, and
`find_files_containing` return dataclasses without `render_text()`. Usage scans
return `ScanUsagesResult`, which holds the tool's JSON result in `structured`
and has `render_text()`.

## Errors

Every failure inside the native module raises `SearchToolsError`, a subclass of
`RuntimeError`. This includes arguments that the engine rejects, session start
failures, and calls after `close()`. Argument checks in the Python client raise
`ValueError`: the `sources` and `revision` rules above, the `query_code` source
and scope rules, and `usage_graph(depth=0)`. `kind_filter` and `ranking_mode`
take enum members such as `SymbolKindFilter.CLASS`; a plain string raises
`AttributeError`.

## Diff Review

With both `target` and `base` omitted, the diff runs from the merge base of
`HEAD` and the default branch named by `origin/HEAD` to the live working tree.
An explicit commit target without a base means that single commit.

`blast_radius(target=None, *, base=None, max_scopes=None)` uses the same
endpoint defaults as `analyze_diff` and returns `BlastRadiusResult`. Its typed
analysis state, changed callables, and file and directory `TestScope` records
are structured file-dependency evidence. The graph includes ordinary imports and
language-owned file relations such as Rust external `mod` declarations. It is
not an exhaustive test-impact claim, a list of test-runner IDs, a method-call
graph, or runtime coverage. Changed files that contain tests appear at
dependency distance zero. Directory compaction never changes
`analysis.reached_test_file_count`.

`analysis.analyzer_changed_test_paths` contains the changed target files that
the analyzer classified as containing test code. They are seeded at distance
zero even when scope compaction returns a parent directory. The paths are not
runner-specific test identifiers.

Callable symbols use `in_test_context` for declarations nested in test code or
located under a recognized test-tree path. It describes context only. It does
not say that the declaration is a runnable test or that its file is a
`TestScope`.

`analysis.graph_completion` describes only the construction and traversal of
the file graph. Read it together with `paths_outside_file_graph`,
`analyzer_changed_test_paths`, and `incomplete_reasons`. Zero reached tests
does not prove that no build, data, or workflow validation applies to changed
paths outside analyzer coverage. The `compilation_scope_unresolved` reason
keeps the proven partial evidence and reports that a language compilation
boundary could not be fully established.

`list_function_sources(paths=None, *, include_tests=True)` returns the structured
function inventory as a dictionary: `records` contain identities, indexed blob
OIDs, declaration coordinates, and exact source including attached comments;
`summary` reports file/record counts and skipped files.

`cyclomatic_complexity(target=None, *, base=None, include_tests=False)` returns
`CyclomaticComplexityDiffResult` for functions that the selected endpoints
introduce or edit. Introduced records have only an `after` score. Edited
records have `before`, `after`, and a signed `delta`, which can be zero.
Deleted functions and pure moves are omitted. The result also reports changed
paths outside analyzer support and analyzer paths that could not be resolved.

`missing_tests(target=None, *, base=None)` returns `MissingTestsResult`. Its
file graph bounds batched exact usage scans. A function called through direct
or transitive enclosing callers counts as reached. An uncalled sibling in the
same file stays a missing candidate. Read `indeterminate_functions` before you
act on an empty or partial result: Bifrost puts every cancelled, incomplete,
unresolved, ambiguous, or unproven negative there instead of claiming that the
function has no test path. This is static structured reachability, not runtime
coverage.

## Navigation Results

`get_declarations_by_location(...)` returns a list of `DeclarationLookupResult`
objects with `operation` set to `NavigationOperation.DECLARATION` and a typed
`declarations` list. `get_definitions_by_location(...)` returns a list of
`DefinitionLookupResult` objects with `operation` set to
`NavigationOperation.DEFINITION` and a typed `definitions` list. Their
`status` values include `no_declaration`, `no_definition`, and `ambiguous`.
`get_definitions_by_reference(...)` returns a list of
`DefinitionByReferenceLookupResult` objects, one per reference.

Exact source positions use 1-based lines and 1-based Unicode code-point
columns, with exclusive ends. Individual usage hits expose `line`, `column`,
`end_line`, and `end_column`. Definition, declaration, and nested type
candidates expose `start_line`, `start_column`, `end_line`, and `end_column`.
Columns are omitted for aggregate rows and for candidates without a proven
exact token span. Public results do not expose byte offsets.

## Summaries

`get_summaries(...)` accepts files, globs, classes, modules, directories, and
packages in one call. A directory or package target returns a
`ContainerListing` entry in `listings`, with `kind` set to `directory` or
`package`. This is the same for MCP, Rust, and Python callers.

One behavior differs by caller: only the MCP server replaces an oversized
summary response with a compact symbol list (`compact_symbols`). For Python
callers, `compact_symbols` is always `None`. A glob target that matches too
many files is reported under `too_broad`, as in the other surfaces.

## Code Query

[Library Integration](/code-query-tutorials/library-integration/) is the executable walkthrough: it runs one canonical query through `SearchToolsClient.query_code(...)` against a checked-in fixture, consumes the typed `CodeQueryResponse`, and shows how to read `diagnostics`, `truncated`, `provenance_truncated`, and receiver `outcome` before making a completeness-sensitive claim. The same page runs the same query through the Rust `SearchToolsService`, so the two integrations can be compared side by side.

`query_code(...)` takes exactly one source: the positional `pattern`, one of
the other root-source parameters (`occurrences`, `scopes`, `bindings`,
`generation_sites`, `exports`, `dependency_evidence`, `configuration_facts`,
`correlate`, `require_both`, `paths`), or `union=[...]`, `intersect=[...]`,
or `except_=[...]`. Alternatively, `query_file` names a workspace query file
and takes no other query argument. The `steps` list runs after the source.
`inside`, `inside_decl`, and `not_inside` apply only to `pattern`; for set
queries, put them inside each branch. `where` and `languages` apply to the
other sources too. `schema_version` is optional, and
`schema_version=1` is the only accepted pin.
Bifrost rejects every other value.

Every source in the JSON CodeQuery format has a `query_code` parameter, so a
Python query can use any of them as its root source. `bifrost --query-file`
also accepts every source. See [Code Querying](/code-querying/), [JSON CodeQuery](/code-query-json/),
and the [Code Query reference](/reference/code-query/) for the complete source
and step vocabulary.

The `taint`, `typestate`, and `value_flow` steps read a result or plan that a
host registered in the same process. Only the Rust `SearchToolsService` can
register them, through `register_query_taint_results`,
`register_query_protocol`, and `register_query_value_flow_plan`. The Python
client has no registration method, so these steps always return an
`unresolved_*_reference` diagnostic from Python.

`CodeQueryResult.results` contains typed result classes selected by each item's `result_type`. The result classes are `CodeQueryMatch`, `CodeQueryDeclaration`, `CodeQueryProcedure`, `CodeQueryProgramPoint`, `CodeQueryControlEdge`, `CodeQueryTypestateFinding`, `CodeQueryTypestateWitness`, `CodeQueryFlowEndpoint`, `CodeQueryFlowWitness`, `CodeQueryAbsentMemberWitness`, `CodeQueryClassSetRow`, `CodeQueryAbsentMemberFinding`, `CodeQueryTaintFinding`, `CodeQueryFile`, `CodeQueryReferenceSite`, `CodeQueryCallSite`, `CodeQueryExpressionSite`, `CodeQueryJsxAttributeValue`, `CodeQueryReceiverAnalysis`, `CodeQueryMemberTargetAnalysis`, `CodeQueryReceiverOutcome`, `CodeQueryReceiverEvidence`, `CodeQueryFieldWriteValue`, `CodeQueryRuntimeKeyedReadValue`, `CodeQueryCallShape`, `CodeQueryCallResult`, `CodeQueryCallArgumentGroup`, `CodeQueryCallShapeArgument`, `CodeQueryCallBinding`, `CodeQueryCallEffect`, `CodeQueryCallResultContract`, `CodeQueryResultContractUse`, `CodeQueryResultContractFailureUse`, `CodeQueryNilnessOperation`, `CodeQuerySwitchCoverage`, `CodeQueryDetachedTaskTransfer`, `CodeQueryProcedureEffect`, `CodeQueryCallableSignature`, `CodeQuerySignatureParameter`, `CodeQueryDecoratedParameter`, `CodeQueryCallableApplicability`, `CodeQueryOverloadSelection`, `CodeQueryMemberSelection`, `CodeQueryDispatchOutcome`, `CodeQueryDispatchTarget`, `CodeQueryMemberFamily`, `CodeQueryMemberFamilyEdge`, `CodeQueryOccurrence`, `CodeQueryLexicalScope`, `CodeQueryBinding`, `CodeQueryResolutionCandidate`, `CodeQueryCandidateHop`, `CodeQueryGenerationSite`, `CodeQueryExport`, `CodeQueryDeclarationState`, `CodeQueryReferenceEdge`, `CodeQueryStateEvent`, `CodeQueryFlowRelation`, `CodeQueryControlRelation`, `CodeQueryGuard`, `CodeQueryRewritePath`, `CodeQueryQualifiedPath`, `CodeQueryPathSegment`, `CodeQuerySourceSet`, `CodeQueryBuildTarget`, `CodeQueryTopologyEdge`, `CodeQueryConfigurationFact`, and `CodeQueryCrossDomain`, plus generated classes for other row types, such as branch and loop relations. Typestate, flow, and taint models are frozen. They reject missing identity or evidence fields and unknown enum values. Findings and flow endpoints do not classify severity. Retained taint witnesses use ordered `CodeQueryFlowWitnessStep` values and report their own truncation.

The [Python Client API reference](/reference/python-client/) maps every result type to its class and import path. Some classes, such as `CodeQueryGenerationSite` and the generated row classes, are importable only from `bifrost_searchtools.models`. `CodeQueryFile` rows carry `package_fq` and `package_syntactic`. `package_syntactic` is `True` when the source spells the package and `False` when Bifrost derives it from the file path. When both fields are absent, no package could be named.

Read these fields before you consume rows:

- `truncated` on the result, and every entry in `diagnostics`. A diagnostic
  with impact `incomplete` or `invalid` means the row set is not complete.
- On rows that carry semantic evidence, the `evidence` field (a
  `CodeQuerySemanticEvidence` with `proof`, `completeness`, and an optional
  `reason`). Witness models use the same field name.
- On `CodeQueryFlowEndpoint`, `status` (a `CodeQueryFlowStatus`) and its
  optional `reason`, which carries semantic, solver, or query limit detail.

`code_query_variant_inventory()` returns the engine's own lists of result
types, diagnostic codes, diagnostic impacts, and completion kinds. Compare
them with the Python models to check that the client is not older than the
engine it loaded.

Compact output is the default. Pass `result_detail="full"` when you need
stable IDs and exact ranges.

Absent-member witnesses expose a typed `witness_status`: `available`,
`truncated`, or `unavailable`. An unavailable witness carries its reason and no
invented steps. It does not cancel the independently proven finding. Query
limits bound the retained step prefix, and profile responses report type-flow
witness work.

`CodeQueryOccurrence` rows expose `class_` (the JSON field `class`, also
readable as `occurrence_class`), `role`, and `namespace`, exact byte and line
ranges, `raw_spelling`, an optional `decoded_spelling`, and a
`CodeQueryOccurrenceTarget` whose `target_kind` is `none`, `resolved`,
`lexical`, or `unresolved`. The `effective_spelling` property gives the
spelling to compare with a declared name. The row's `ast_id` identifies the AST node by
content and equals the `ast_id` that a full-detail structural capture over the
same node reports. Join on that string, not on ranges or spellings. A role that
a language adapter does not declare produces an `occurrence_role_unsupported`
diagnostic with `incomplete` impact. An empty occurrence result is trustworthy
only when the diagnostics are clean.

The optional `execution_mode` selects the response type:

- Omit it or pass `"results"` to get `CodeQueryResult`.
- `"explain"` returns `CodeQueryExplain` without running the query. It exposes
  `parsed_query`, `logical_plan`, `physical_plan`, and the scheduling choice.
- `"profile"` runs the query and returns `CodeQueryProfile`. Its `.result` is
  the ordinary result. It also has `.explain`, `.timings_ns`, `.work`,
  `.cache_layers`, `.scheduling`, and per-operator observations.

Timings are elapsed nanoseconds. The per-operator
`temporary_capacity_bytes_lower_bound` is a lower bound on container capacity,
not peak process memory. In the profile format
(`bifrost_code_query_profile/v2`), top-level and per-operator `.cache_layers`
are lists of `{layer, metrics}` records. Each `metrics` object has
`kind="structural_facts"` for the `seed_structural_facts` layer and
`kind="complete_value"` for every other layer. The `direct_import_topology`
layer reports snapshot build files, edges, time, retained bytes, cancellation
or unavailability, and request-local fallbacks. See [Explain and Profile
CodeQuery](/code-query-explain-profile/) for the full report format.

## Tests

Run the Python test suite with:

```bash
scripts/public/test_python.sh
```

`scripts/public/test_python.sh` provisions Python 3.12 through `uv`. The default Xcode Python may be older than the package requires.
