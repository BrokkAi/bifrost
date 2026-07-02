# brokk-bifrost-searchtools

Fast, structured code search and analysis for Python, backed by a native Rust
extension. This is the Python distribution of [bifrost](https://github.com/BrokkAi/bifrost),
the Tree-sitter-backed analyzer suite that powers [Brokk](https://brokk.ai).

It gives you one in-process client that talks straight to the Rust analyzer (no
subprocess, no MCP server) and returns typed results plus ready-to-render text.
It understands Java, JavaScript, TypeScript, Rust, Go, Python, C++, C#, PHP, and
Scala.

- **Install:** `pip install brokk-bifrost-searchtools`
- **Import as:** `bifrost_searchtools`

## What it does

Index a project once, then ask fast structural questions:

- **Symbol search:** find classes, functions, and fields by name pattern.
- **Locations and sources:** jump to a symbol's definition or pull its source.
- **Summaries:** get a signature-level outline of a file or directory.
- **Usages and call graph:** scan references to a symbol, or build the
  whole-workspace caller/callee graph (feed it to PageRank for a code map).
- **Most-relevant files:** rank the files most related to one or more seed files.
- **Semantic search:** find code by meaning, using ONNX embeddings and a
  cross-encoder reranker (opt-in).

## Quick start

```python
from bifrost_searchtools import SearchToolsClient

with SearchToolsClient("/path/to/project") as client:
    # Signature-level outline of a file
    print(client.get_summaries(["src/main.py"]).render_text())

    # Find symbols by name pattern
    for file in client.search_symbols(["parse_*"], limit=10).files:
        print(file.path)

    # Rank the files most related to a seed file
    print(client.most_relevant_files(["src/main.py"]).render_text())
```

The client indexes on first use, keeps the index warm for the session, and
watches the filesystem so later queries see your edits. Every result has typed
fields plus a `render_text()` helper.

For a runnable end-to-end demo, [`examples/searchtools_demo.py`](https://github.com/BrokkAi/bifrost/tree/master/examples)
declares its dependency inline (PEP 723), so `uv` fetches the package and runs it
with no manual install:

```bash
uv run examples/searchtools_demo.py --root /path/to/repo Calculator compute
```

## API overview

`SearchToolsClient(root, library_path=None, render_line_numbers=True, manual=False)`
exposes:

| Method | Purpose |
| --- | --- |
| `search_symbols(patterns, *, include_tests=False, limit=20)` | Find symbols by name pattern. |
| `search_ast(pattern, *, inside=None, not_inside=None, where=None, languages=None, limit=None)` | Search normalized AST structure across supported languages. |
| `get_symbol_locations(symbols, *, kind_filter=...)` | Resolve symbols to definition sites. |
| `get_symbol_ancestors(symbols, *, kind_filter=...)` | Walk the enclosing type/scope chain. |
| `get_symbol_sources(symbols, *, kind_filter=...)` | Pull full source for symbols. |
| `get_definition_by_location(path, *, line=..., column=...)` | Resolve a reference at a known file location. |
| `get_definition_by_reference(symbol, *, context=..., target=...)` | Resolve a copied reference inside a symbol source block. |
| `get_type_by_location(path, *, line=..., column=...)` | Resolve the type of an expression or identifier at a known file location. |
| `get_summaries(targets)` | Signature-level outline of files / classes / directories. |
| `list_symbols(file_patterns)` | Skim the symbols declared in matching files. |
| `scan_usages(symbols, *, include_tests=False, paths=None)` | Find references to a symbol. |
| `rename_symbol(path, *, line=..., column=..., new_name=...)` | Return a non-mutating edit plan for a symbol rename. |
| `usage_graph(*, include_tests=False, paths=None)` | Whole-workspace caller/callee graph; each edge carries its `{path, line}` call sites. |
| `most_relevant_files(seed_files, *, limit=20, ...)` | Rank files related to seed files. |
| `semantic_search(query, *, k=10)` | Meaning-based code search (opt-in). |
| `semantic_search_status()` | Report whether the semantic index is ready. |
| `refresh()` | Force a full re-index (recovery escape hatch). |
| `update_paths(paths)` | Incrementally re-analyze specific paths (with `manual=True`). |
| `activate_workspace(path)` / `get_active_workspace()` | Switch / read the active workspace root. |
| `get_file_contents(file_paths)` | Read whole files by path. |
| `find_filenames(patterns, *, limit=None)` | Find files by path glob. |
| `search_file_contents(patterns, *, file_path=None, context_lines=None, case_insensitive=False)` | Grep contents with context. |
| `find_files_containing(patterns, *, limit=None, case_insensitive=False)` | Find files whose contents match. |
| `list_files(directory_path="", *, max_entries=None)` | List files under a directory. |
| `get_git_log(*, file_path=None, limit=None)` | Recent commits (optionally for one path). |
| `get_commit_diff(revision, *, max_files=None, lines_per_file=None)` | Unified diff for a commit. |
| `search_git_commit_messages(pattern, *, limit=None)` | Regex search over commit messages. |
| `jq(file_path, filter_expr, *, max_files=None, matches_per_file=None)` | Run a jq filter over JSON files. |
| `xml_skim(file_path, *, max_files=None)` | Summarize XML element structure. |
| `xml_select(file_path, xpath, *, output=XmlSelectOutput.TEXT, attr_name=None, max_files=None)` | Evaluate an XPath over XML files. |
| `compute_cyclomatic_complexity(file_paths, *, threshold=None)` | Per-function cyclomatic complexity. |
| `compute_cognitive_complexity(file_paths, *, threshold=None)` | Per-function cognitive complexity. |
| `report_comment_density_for_code_unit(fq_name, *, max_lines=None)` | Comment density for one symbol. |
| `report_comment_density_for_files(file_paths, *, max_top_level_rows=None, max_files=None)` | Comment density per file. |
| `report_exception_handling_smells(file_paths, *, min_score=None, max_findings=None, options=None)` | Suspicious exception handlers. |
| `report_test_assertion_smells(file_paths, *, min_score=None, max_findings=None, options=None)` | Low-value test assertions. |
| `report_structural_clone_smells(file_paths, *, min_score=None, max_findings=None, options=None)` | Structural code clones. |
| `report_long_method_and_god_object_smells(file_paths, *, max_findings=None, max_files=None, options=None)` | Oversized functions / god objects. |
| `report_dead_code_and_unused_abstraction_smells(*, file_paths=None, fq_names=None, min_score=None, max_findings=None, options=None)` | Likely dead code (Rust). |
| `report_secret_like_code(*, max_findings=None, max_commits=None, include_history_only=False, include_low_confidence=False)` | Secret-looking strings in files / history. |
| `analyze_git_hotspots(*, since_days=None, since_iso=None, until_iso=None, max_commits=None, max_files=None)` | Churn × complexity hotspots. |

Pass `render_line_numbers=False` to drop line numbers from rendered text while
keeping the structured line metadata on the result objects.

The git tools return a `GitTextResult` (`.text`), the slopcop tools return a
`CodeQualityReport` (`.report`), and the rest return structured dataclasses from
`bifrost_searchtools.models`. The per-rule tuning knobs on the smell reports are
passed through `options` (keys map 1:1 to the Rust tool arguments).

## Semantic search

`semantic_search(...)` searches code by meaning rather than name and returns the
three retrieval legs directly: function-oriented vector and BM25 rankings over
function-level chunks, plus a file-oriented co-edit ranking. It searches code,
not prose.

It is opt-in. Set `BIFROST_SEMANTIC_INDEX=auto` to enable background indexing;
the models load via ONNX and download from the HuggingFace hub on first use. The
[main bifrost README](https://github.com/BrokkAi/bifrost#semantic-search) lists
every environment override.

## License

LGPL-3.0-or-later. See [LICENSE.md](https://github.com/BrokkAi/bifrost/blob/master/LICENSE.md).
