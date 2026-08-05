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

Use `manual=True` with `update_paths(...)` when the caller wants to control incremental updates explicitly.

## Methods

`SearchToolsClient(root, library_path=None, render_line_numbers=True, manual=False)` exposes the same tool families as MCP:

| Family | Methods |
| --- | --- |
| Workspace | `refresh()`, `update_paths(...)`, `activate_workspace(...)`, `get_active_workspace()` |
| Symbols and summaries | `search_symbols(...)`, `get_symbol_locations(...)`, `get_symbol_ancestors(...)`, `get_symbol_sources(...)`, `get_summaries(...)`, `list_symbols(...)`, `classify_test_files(...)` |
| Declarations, definitions, and types | `get_declarations_by_location(...)`, `get_definitions_by_location(...)`, `get_definitions_by_reference(...)`, `get_type_by_location(...)` |
| Usages and graph | `scan_usages_by_reference(...)`, `scan_usages_by_location(...)`, `rename_symbol(...)`, `usage_graph(...)`, `most_relevant_files(...)`, `analyze_diff(...)` |
| Code query | `query_code(...)` |
| Semantic search | `semantic_search(...)`, `semantic_search_status()` |
| Files | `get_file_contents(...)`, `search_file_contents(...)`, `find_files_containing(...)` |
| Code quality | `compute_cyclomatic_complexity(...)`, `compute_cognitive_complexity(...)`, `report_comment_density_for_code_unit(...)`, `report_comment_density_for_files(...)`, `report_exception_handling_smells(...)`, `report_test_assertion_smells(...)`, `report_structural_clone_smells(...)`, `report_long_method_and_god_object_smells(...)`, `report_dead_code_and_unused_abstraction_smells(...)`, `report_secret_like_code(...)`, `analyze_git_hotspots(...)` |

Code-quality tools return `CodeQualityReport` with `.report`. Most other tools return structured dataclasses with `render_text()`.

`get_declarations_by_location(...)` returns `DeclarationLookupResult` objects with `operation is NavigationOperation.DECLARATION` and a typed `declarations` list. `get_definitions_by_location(...)` returns `DefinitionLookupResult` objects with `operation is NavigationOperation.DEFINITION` and a typed `definitions` list. Their statuses distinguish `no_declaration`, `no_definition`, and `ambiguous`; `get_definitions_by_reference(...)` is unchanged.

Exact source positions use 1-based lines and 1-based Unicode code-point columns, with exclusive ends. Individual usage hits expose `line`, `column`, `end_line`, and `end_column`; definition, declaration, and nested type candidates expose `start_line`, `start_column`, `end_line`, and `end_column`. Columns are omitted for aggregate rows or candidates without a proven exact token span, and public results do not expose byte offsets.

The many per-rule tuning knobs on code-quality smell reports are accepted through an `options` dict whose keys map 1:1 to the underlying Rust tool arguments.

`get_summaries(...)` is directory-aware for MCP callers: directory targets surface a `compact_symbols` inventory alongside ordinary summaries when mixed with file or class targets. The direct Rust `brokk_bifrost::searchtools::get_summaries(...)` API and the Python client are narrower and report directory targets in `not_found` instead of embedding directory inventory in `SummaryResult`.

## Code Query

`query_code(...)` defaults to the compatible-head version-10 typed query surface; the compatible-head version-7 vocabulary and every earlier one remain available as exact pins. Exact `schema_version=2`, `schema_version=3`, `schema_version=4`, `schema_version=5`, `schema_version=6`, and `schema_version=7` pins retain their earlier vocabularies. Pass exactly one source: positional `pattern`, `union=[...]`, `intersect=[...]`, or `except_=[...]`; common `steps` run after composition. Version 7 adds `{"op":"taint","taint_ref":"request:http-to-database"}` from an exact procedure to retained diagnostic-neutral `CodeQueryTaintFinding` rows. The connected in-process host must pre-register the referenced immutable production result for the current workspace. The query never compiles or solves taint, reconstructs witnesses, or performs policy classification. Version 8 adds the occurrence source and the `occurrences_in`, `occurrences_of`, and `occurrence_target` steps. Version 9 adds the `scopes` and `bindings` sources and the `scope_of`, `scope_ancestors`, `bindings_in`, `reaching_binding`, `binding_occurrence`, `candidates_of`, and `candidate_target` steps, parsed into `CodeQueryLexicalScope`, `CodeQueryBinding`, and `CodeQueryResolutionCandidate`; the file row gains `package_fq` and `package_syntactic`. Version 10 adds the canonical reference-edge domain: `edges_of` from a declaration, `edges_from` from an occurrence, and `edge_target` back to a declaration, parsed into `CodeQueryReferenceEdge`. Both edge steps accept `reference_kinds`, `proof`, `surface`, `usage`, `relation`, and `site_class`; `surface` is optional with no default, because the complete edge answer includes editor-only rows. A forward query in a language whose adapter has no forward projection reports `edge_axis_unsupported` rather than an empty answer. `file_of` accepts occurrences, taint findings, and every earlier semantic source result, including the `inside_decl` structural traversal. See [Code Querying](../code-querying/) and [JSON CodeQuery](../code-query-json/) for the complete contract.

`CodeQueryResult.results` contains sixteen possible classes according to each item's `result_type`: `CodeQueryMatch`, `CodeQueryDeclaration`, `CodeQueryReferenceSite`, `CodeQueryCallSite`, `CodeQueryExpressionSite`, `CodeQueryFile`, `CodeQueryProcedure`, `CodeQueryProgramPoint`, `CodeQueryControlEdge`, `CodeQueryTypestateFinding`, `CodeQueryTypestateWitness`, `CodeQueryFlowEndpoint`, `CodeQueryFlowWitness`, `CodeQueryTaintFinding`, `CodeQueryReceiverAnalysis`, and `CodeQueryOccurrence`. Typestate, flow, and taint models are frozen and strict about required identity/evidence fields and enum values. Findings and flow endpoints remain diagnostic-neutral; retained taint witnesses reuse ordered `CodeQueryFlowWitnessStep` values and truncation metadata. Always inspect result-level `truncated` and diagnostics before consuming candidates. Compact output is the default; pass `result_detail="full"` when deterministic provenance is required.

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
scripts/test_python.sh
```

`scripts/test_python.sh` provisions Python 3.12 through `uv`; the default Xcode Python may be older than the package test requirements.
