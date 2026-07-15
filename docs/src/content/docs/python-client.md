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
from bifrost_searchtools import SearchToolsClient

with SearchToolsClient("/path/to/project") as client:
    print(client.get_summaries(["src/main.py"]).render_text())

    for file in client.search_symbols(["parse_*"], limit=10).files:
        print(file.path)

    print(client.most_relevant_files(["src/main.py"]).render_text())
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
| Definitions and types | `get_definitions_by_location(...)`, `get_definitions_by_reference(...)`, `get_type_by_location(...)` |
| Usages and graph | `scan_usages_by_reference(...)`, `scan_usages_by_location(...)`, `rename_symbol(...)`, `usage_graph(...)`, `most_relevant_files(...)`, `analyze_commit(...)` |
| Code query | `query_code(...)` |
| Semantic search | `semantic_search(...)`, `semantic_search_status()` |
| Files | `get_file_contents(...)`, `find_filenames(...)`, `search_file_contents(...)`, `find_files_containing(...)`, `list_files(...)` |
| Git | `get_git_log(...)`, `get_commit_diff(...)`, `search_git_commit_messages(...)` |
| Structured data | `jq(...)`, `xml_skim(...)`, `xml_select(...)` |
| Code quality | `compute_cyclomatic_complexity(...)`, `compute_cognitive_complexity(...)`, `report_comment_density_for_code_unit(...)`, `report_comment_density_for_files(...)`, `report_exception_handling_smells(...)`, `report_test_assertion_smells(...)`, `report_structural_clone_smells(...)`, `report_long_method_and_god_object_smells(...)`, `report_dead_code_and_unused_abstraction_smells(...)`, `report_secret_like_code(...)`, `analyze_git_hotspots(...)` |

The git tools return `GitTextResult` with `.text`. Code-quality tools return `CodeQualityReport` with `.report`. Most other tools return structured dataclasses with `render_text()`.

The many per-rule tuning knobs on code-quality smell reports are accepted through an `options` dict whose keys map 1:1 to the underlying Rust tool arguments.

`get_summaries(...)` is directory-aware for MCP callers: directory targets surface a `compact_symbols` inventory alongside ordinary summaries when mixed with file or class targets. The direct Rust `brokk_bifrost::searchtools::get_summaries(...)` API and the Python client are narrower and report directory targets in `not_found` instead of embedding directory inventory in `SummaryResult`.

## Code Query

`query_code(...)` is the version-2 typed query surface. Omit `schema_version` for v2 or pass `schema_version=2` explicitly. Supply ordered `steps` such as `[{"op": "enclosing_decl"}, {"op": "members"}, {"op": "references_of", "proof": "proven"}]` to return typed `CodeQueryReferenceSite` rows, or use `used_by` / `uses` for declaration rows whose provenance carries the exact site under `via`. Call pipelines deserialize to `CodeQueryCallSite` and `CodeQueryExpressionSite`; for example, follow `enclosing_decl` with `call_sites_to` and `{"op":"call_input","parameter_name":"payload"}`. Call and hierarchy steps are direct by default; call traversal accepts finite `depth`, while hierarchy also accepts `transitive`. `file_of` accepts every semantic source result and can feed the import steps. Library declarations are absent unless the workspace analyzer indexed them. See [Reference Traversal](../code-query-tutorials/reference-traversal/), [Code Querying](../code-querying/), and [JSON CodeQuery](../code-query-json/) for the complete contract.

`CodeQueryResult.results` contains `CodeQueryMatch`, `CodeQueryDeclaration`, or `CodeQueryFile` objects according to each item's `result_type`. Compact output is the default and retains minimal provenance for derived results. Pass `result_detail="full"` when a rule, refactoring step, or follow-up tool call needs deterministic IDs, 1-based character columns, decorator ranges, and capture ranges.

## Tests

Run the Python test suite with:

```bash
scripts/test_python.sh
```

`scripts/test_python.sh` provisions Python 3.12 through `uv`; the default Xcode Python may be older than the package test requirements.
