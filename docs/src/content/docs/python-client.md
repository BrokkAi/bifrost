---
title: Python Client
description: Use Bifrost from Python through the native searchtools package.
---

The Python distribution is `brokk-bifrost-searchtools`. Import it as `bifrost_searchtools`.

```bash
pip install brokk-bifrost-searchtools
```

For repository-local development, build the extension in place with maturin:

```bash
uv run --python 3.12 --with maturin maturin develop
```

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
        include_tests=False,
        ranking_mode=MostRelevantFilesRankingMode.USAGE_GRAPH,
    ).render_text())
```

The client talks directly to Rust through a native extension module. It does not start an MCP subprocess. Results are typed dataclasses from `bifrost_searchtools.models` plus ready-to-render text helpers.

Pass `render_line_numbers=False` to `SearchToolsClient(...)` to omit line numbers from rendered text while keeping structured line metadata in the result objects.

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

## Workspace Updates

The client indexes on first use, keeps the index warm for the session, and watches the filesystem so later queries see edits.

`SearchToolsClient.refresh()` forces a full rebuild. Query methods already apply watcher-detected file changes automatically, so treat `refresh()` as a recovery or explicit full-rescan operation rather than a step before every request.

Use `manual=True` with `update_paths(...)` when the caller wants to control incremental updates explicitly. Manual sessions reuse the repository's persisted analyzer cache; linked Git worktrees share the primary worktree's cache.

## Methods

`SearchToolsClient(root, library_path=None, render_line_numbers=True, manual=False)` exposes the same tool families as MCP:

| Family | Methods |
| --- | --- |
| Workspace | `refresh()`, `update_paths(...)`, `activate_workspace(...)`, `get_active_workspace()` |
| Symbols and summaries | `search_symbols(...)`, `get_symbol_locations(...)`, `get_symbol_ancestors(...)`, `get_symbol_sources(...)`, `get_summaries(...)`, `list_symbols(...)`, `classify_test_files(...)` |
| Declarations, definitions, and types | `get_declarations_by_location(...)`, `get_definitions_by_location(...)`, `get_definitions_by_reference(...)`, `get_type_by_location(...)` |
| Usages and graph | `scan_usages_by_reference(...)`, `scan_usages_by_location(...)`, `rename_symbol(...)`, `usage_graph(...)`, `most_relevant_files(...)` |
| Diff review | `analyze_diff(...)`, `blast_radius(...)`, `cyclomatic_complexity(...)`, `missing_tests(...)` |
| Code query | `query_code(...)` |
| Files | `get_file_contents(...)`, `search_file_contents(...)`, `find_files_containing(...)` |
| Code quality | `compute_cyclomatic_complexity(...)`, `compute_cognitive_complexity(...)`, `report_comment_density_for_code_unit(...)`, `report_comment_density_for_files(...)`, `report_exception_handling_smells(...)`, `report_test_assertion_smells(...)`, `report_structural_clone_smells(...)`, `report_long_method_and_god_object_smells(...)`, `report_dead_code_and_unused_abstraction_smells(...)`, `report_secret_like_code(...)`, `analyze_git_hotspots(...)` |

Code-quality tools return `CodeQualityReport` with `.report`. Most other tools return structured dataclasses with `render_text()`.

`blast_radius(target=None, *, base=None, max_scopes=None)` shares
`analyze_diff` endpoint defaults and returns `BlastRadiusResult`. Its typed
analysis state, changed callables, and file/directory `TestScope` records are
structured file-dependency evidence. The graph includes ordinary imports and
language-owned file relations such as Rust external `mod` declarations. It is
not an exhaustive test-impact claim, individual test-runner IDs, a method-call
graph, or runtime coverage. Changed files containing tests appear at dependency
distance zero. Directory compaction never changes
`analysis.reached_test_file_count`.
`analysis.analyzer_changed_test_paths` contains the changed target files that
the analyzer structurally classified as containing test code. They are seeded
at distance zero even if scope compaction returns a parent directory; the paths
are not runner-specific test identifiers.
Callable symbols use `in_test_context` for declarations structurally nested in
test code or located under a recognized test-tree path. It is contextual and
does not assert that the declaration is a runnable test or that its file is a
`TestScope`.
`analysis.graph_completion` describes only construction and traversal of the
file graph. Inspect it together with `paths_outside_file_graph` and
`analyzer_changed_test_paths` and `incomplete_reasons`; zero reached tests does
not prove that no build, data, or workflow validation applies to changed paths
outside analyzer coverage. The typed `compilation_scope_unresolved` reason
preserves proven partial evidence while reporting that a language compilation
boundary could not be established completely.

`cyclomatic_complexity(target=None, *, base=None, include_tests=False)` returns
`CyclomaticComplexityDiffResult` for functions introduced or patch-edited by
the selected endpoints. Introduced records have only an `after` score; edited
records have `before`, `after`, and a signed `delta`, including zero. Deleted
functions and pure moves are omitted. The result also reports changed paths
outside analyzer support and analyzer paths that could not be resolved.

`missing_tests(target=None, *, base=None)` returns `MissingTestsResult`. Its
file graph bounds batched exact usage scans, so functions called through direct
or transitive enclosing callers are counted as reached while an uncalled
sibling in the same file remains a missing candidate. Inspect
`indeterminate_functions` before acting on an empty or partial result: Bifrost
places every cancelled, incomplete, unresolved, ambiguous, or unproven negative
there instead of claiming that the function lacks a test path. This is static
structured reachability rather than runtime coverage.

With both endpoints omitted, the diff runs from the merge base of `HEAD` and
the default branch advertised by `origin/HEAD` through the live working tree.
An explicit commit target without a base continues to mean that single commit.

`get_declarations_by_location(...)` returns `DeclarationLookupResult` objects with `operation is NavigationOperation.DECLARATION` and a typed `declarations` list. `get_definitions_by_location(...)` returns `DefinitionLookupResult` objects with `operation is NavigationOperation.DEFINITION` and a typed `definitions` list. Their statuses distinguish `no_declaration`, `no_definition`, and `ambiguous`; `get_definitions_by_reference(...)` is unchanged.

Exact source positions use 1-based lines and 1-based Unicode code-point columns, with exclusive ends. Individual usage hits expose `line`, `column`, `end_line`, and `end_column`; definition, declaration, and nested type candidates expose `start_line`, `start_column`, `end_line`, and `end_column`. Columns are omitted for aggregate rows or candidates without a proven exact token span, and public results do not expose byte offsets.

The many per-rule tuning knobs on code-quality smell reports are accepted through an `options` dict whose keys map 1:1 to the underlying Rust tool arguments.

`get_summaries(...)` is directory-aware for MCP callers: directory targets surface a `compact_symbols` inventory alongside ordinary summaries when mixed with file or class targets. The direct Rust `brokk_bifrost::searchtools::get_summaries(...)` API and the Python client are narrower and report directory targets in `not_found` instead of embedding directory inventory in `SummaryResult`.

## Code Query

[Library Integration](/code-query-tutorials/library-integration/) is the executable walkthrough: it runs one canonical query through `SearchToolsClient.query_code(...)` against a checked-in fixture, consumes the typed `CodeQueryResponse`, and shows how to read `diagnostics`, `truncated`, `provenance_truncated`, and receiver `outcome` before making a completeness-sensitive claim. The same page runs the same query through the Rust `SearchToolsService`, so the two integrations can be compared side by side.

`query_code(...)` speaks one schema version. `schema_version` is optional and `schema_version=1` is the only accepted pin; every other value is rejected. An additive vocabulary change keeps that version, so there is no version lineage and no earlier pin to hold; a new version is minted only when an existing query stops parsing or changes meaning. Pass exactly one source: positional `pattern`, `union=[...]`, `intersect=[...]`, or `except_=[...]`; common `steps` run after composition.

The step vocabulary reaches every retained domain. `{"op":"taint","taint_ref":"request:http-to-database"}` runs from an exact procedure to retained diagnostic-neutral `CodeQueryTaintFinding` rows; the connected in-process host must pre-register the referenced immutable production result for the current workspace, and the query never compiles or solves taint, reconstructs witnesses, or performs policy classification. The occurrence source pairs with `occurrences_in`, `occurrences_of`, and `occurrence_target`. The `scopes` and `bindings` sources pair with `scope_of`, `scope_ancestors`, `bindings_in`, `binding_of`, `binding_occurrence`, `candidates_of`, and `candidate_target`, parsed into `CodeQueryLexicalScope`, `CodeQueryBinding`, and `CodeQueryResolutionCandidate`; the file row carries `package_fq` and `package_syntactic`. `file_of` accepts occurrences, taint findings, and every other semantic source result, including the `inside_decl` structural traversal. The `paths` source pairs with `segments_of` and `segment_target`, parsed into `CodeQueryQualifiedPath` and `CodeQueryPathSegment`: qualified-path rows with ordered decoded segments and per-segment prefix resolution. The canonical reference-edge domain provides `edges_of` from a declaration, `edges_from` from an occurrence, and `edge_target` back to a declaration, parsed into `CodeQueryReferenceEdge`; both edge steps accept `reference_kinds`, `proof`, `surface`, `usage`, `relation`, and `site_class`, and `surface` is optional with no default because the complete edge answer includes editor-only rows. A forward query in a language whose adapter has no forward projection reports `edge_axis_unsupported` rather than an empty answer. The `generation_sites` and `exports` sources pair with `generates`, `generated_by`, `declaration_state_of`, `implementation_of`, and `export_target`, parsed into `CodeQueryGenerationSite`, `CodeQueryExport`, and `CodeQueryDeclarationState`: recorded declaration-materialization provenance with exact generated sets for literal inputs, explicit `dynamic` honesty, export forms, declaration origin/declaration-only/configuration-gate state, and overload-stub implementation linkage. See [Code Querying](../code-querying/) and [JSON CodeQuery](../code-query-json/) for the complete contract.

`CodeQueryResult.results` contains typed result classes selected by each item's `result_type`. The result classes are `CodeQueryMatch`, `CodeQueryDeclaration`, `CodeQueryProcedure`, `CodeQueryProgramPoint`, `CodeQueryControlEdge`, `CodeQueryTypestateFinding`, `CodeQueryConcurrentAccessConflict`, `CodeQueryTypestateWitness`, `CodeQueryFlowEndpoint`, `CodeQueryFlowWitness`, `CodeQueryTaintFinding`, `CodeQueryFile`, `CodeQueryReferenceSite`, `CodeQueryCallSite`, `CodeQueryExpressionSite`, `CodeQueryJsxAttributeValue`, `CodeQueryReceiverAnalysis`, `CodeQueryMemberTargetAnalysis`, `CodeQueryReceiverOutcome`, `CodeQueryReceiverEvidence`, `CodeQueryFieldWriteValue`, `CodeQueryCallShape`, `CodeQueryCallResult`, `CodeQueryCallArgumentGroup`, `CodeQueryCallShapeArgument`, `CodeQueryCallBinding`, `CodeQueryCallEffect`, `CodeQueryCallResultContract`, `CodeQueryResultContractUse`, `CodeQueryResultContractFailureUse`, `CodeQueryNilnessOperation`, `CodeQuerySwitchCoverage`, `CodeQueryDetachedTaskTransfer`, `CodeQueryProcedureEffect`, `CodeQueryCallableSignature`, `CodeQuerySignatureParameter`, `CodeQueryDecoratedParameter`, `CodeQueryCallableApplicability`, `CodeQueryOverloadSelection`, `CodeQueryMemberSelection`, `CodeQueryDispatchOutcome`, `CodeQueryDispatchTarget`, `CodeQueryMemberFamily`, `CodeQueryMemberFamilyEdge`, `CodeQueryOccurrence`, `CodeQueryLexicalScope`, `CodeQueryBinding`, `CodeQueryResolutionCandidate`, `CodeQueryCandidateHop`, `CodeQueryGenerationSite`, `CodeQueryExport`, `CodeQueryDeclarationState`, `CodeQueryReferenceEdge`, `CodeQueryStateEvent`, `CodeQueryFlowRelation`, `CodeQueryControlRelation`, `CodeQueryGuard`, `CodeQueryRewritePath`, `CodeQueryQualifiedPath`, `CodeQueryPathSegment`, `CodeQuerySourceSet`, `CodeQueryBuildTarget`, and `CodeQueryTopologyEdge`. Typestate, flow, and taint models are frozen and strict about required identity/evidence fields and enum values. Findings and flow endpoints remain diagnostic-neutral; retained taint witnesses reuse ordered `CodeQueryFlowWitnessStep` values and truncation metadata. `code_query_variant_inventory()` returns the engine's own list of result types, diagnostic codes, diagnostic impacts, and completion kinds, so a client can check that its models are not behind the engine it loaded. Always inspect result-level `truncated` and diagnostics before consuming candidates. Compact output is the default; pass `result_detail="full"` when deterministic provenance is required.

`CodeQueryOccurrence` rows expose `class`/`role`/`namespace`, exact byte and line ranges, `raw_spelling`, an optional `decoded_spelling` (with `effective_spelling` returning whichever a consumer should compare against a declared name), and a `CodeQueryOccurrenceTarget` whose `target_kind` is `none`, `resolved`, `lexical`, or `unresolved`. Its `ast_id` is the content-scoped identity of the underlying AST node and is equal to the `ast_id` a full-detail structural capture over the same node reports -- join on that string, never on ranges or spellings. Roles a language's adapter has not declared produce `occurrence_role_unsupported` diagnostics with `incomplete` impact, so an empty occurrence result is only trustworthy when the diagnostics are clean.

The optional `execution_mode` selects the response contract. Omit it or pass
`"results"` for `CodeQueryResult`. `"explain"` returns `CodeQueryExplain`
without executing the query; the response exposes `parsed_query`,
`logical_plan`, `physical_plan`, and the scheduling selection. `"profile"`
executes the query and returns `CodeQueryProfile`, whose typed `.result` is
accompanied by `.explain`, `.timings_ns`, `.work`, `.cache_layers`,
`.scheduling`, and per-operator observations. Timings are elapsed nanoseconds;
the per-operator `temporary_capacity_bytes_lower_bound` is a lower-bound
container-capacity estimate rather than peak process memory. In the public v2
profile contract, top-level and per-operator `.cache_layers` are lists of
`{layer, metrics}` records. Each nested `metrics` object has
`kind="structural_facts"` for `seed_structural_facts` and
`kind="complete_value"` for every other layer. The
`direct_import_topology` layer exposes snapshot build files, edges, time,
retained bytes, cancellation/unavailability, and request-local fallbacks.

## Tests

Run the Python test suite with:

```bash
scripts/public/test_python.sh
```

`scripts/public/test_python.sh` provisions Python 3.12 through `uv`; the default Xcode Python may be older than the package test requirements.
