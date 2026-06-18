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
| `get_symbol_locations(symbols, *, kind_filter=...)` | Resolve symbols to definition sites. |
| `get_symbol_ancestors(symbols, *, kind_filter=...)` | Walk the enclosing type/scope chain. |
| `get_symbol_sources(symbols, *, kind_filter=...)` | Pull full source for symbols. |
| `get_definition_by_location(path, *, line=..., column=...)` | Resolve a reference at a known file location. |
| `get_definition_by_reference(symbol, *, context=..., target=...)` | Resolve a copied reference inside a symbol source block. |
| `get_summaries(targets)` | Signature-level outline of files / classes / directories. |
| `list_symbols(file_patterns)` | Skim the symbols declared in matching files. |
| `scan_usages(symbols, *, include_tests=False, paths=None)` | Find references to a symbol. |
| `usage_graph(*, include_tests=False, paths=None)` | Whole-workspace caller/callee graph. |
| `most_relevant_files(seed_files, *, limit=20, ...)` | Rank files related to seed files. |
| `semantic_search(query, *, k=10)` | Meaning-based code search (opt-in). |
| `semantic_search_status()` | Report whether the semantic index is ready. |
| `refresh()` | Force a full re-index (recovery escape hatch). |
| `update_paths(paths)` | Incrementally re-analyze specific paths (with `manual=True`). |

Pass `render_line_numbers=False` to drop line numbers from rendered text while
keeping the structured line metadata on the result objects.

## Semantic search

`semantic_search(...)` finds files by meaning rather than name: function-level
chunks are embedded, fused with BM25 and git co-edit signals, then reranked by a
cross-encoder. It searches code, not prose.

It is opt-in. Set `BIFROST_SEMANTIC_INDEX=auto` to enable background indexing;
the models load via ONNX and download from the HuggingFace hub on first use. The
[main bifrost README](https://github.com/BrokkAi/bifrost#semantic-search) lists
every environment override.

## License

LGPL-3.0-or-later. See [LICENSE.md](https://github.com/BrokkAi/bifrost/blob/master/LICENSE.md).
