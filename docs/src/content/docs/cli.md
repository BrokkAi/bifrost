---
title: CLI
description: Use Bifrost from the terminal for one-shot code-intelligence queries.
---

Bifrost can run a single tool once and print the JSON result:

```bash
bifrost --root /path/to/project --tool search_symbols --args '{"patterns":["MyClass"]}'
```

`--tool` uses the same named tool implementations exposed by the MCP `searchtools` catalog. Use it when you want the MCP tool surface from a shell script or terminal session without starting a long-lived MCP server.

`--args` is inline JSON matching the selected tool's MCP argument object. Omit it for tools that accept an empty object, such as `get_active_workspace`.

For the available tool families and tool names, see [MCP Server](../mcp/). For a single tool's description and parameters, ask the CLI directly:

```bash
bifrost --help scan_usages
```

## Output Shape

Tool mode mirrors MCP's structured result shape, but keeps stdout machine-oriented by omitting rendered text content:

```json
{
  "structuredContent": {},
  "isError": false
}
```

Tools whose normal MCP response is text-only return only:

```json
{
  "isError": false
}
```

Use the MCP page as the catalog for what each tool does. Use `bifrost --help <tool>` for the exact input schema accepted by the installed binary.

`semantic_search` follows the same build and runtime rules in CLI tool mode as it does through MCP: Bifrost must be built with the `nlp` feature, semantic indexing must be enabled for the session, and the active root must be a git repository.

## Limit the Workspace

Use `--sources` when a one-shot query only needs part of a repository. Each value can be a file, directory, or glob under the selected root:

```bash
bifrost --root /path/to/project --tool get_symbol_sources --sources src --sources 'tests/**/*.rs' --args '{"symbols":["src/main.rs"]}'
```

File-bearing CLI tool arguments also accept git history paths in `<commit-ish>:<path>` form, such as `HEAD~2:src/main.rs`. Parser-backed tools build the one-shot analyzer workspace with that historical content.

## Rendering

Tool mode prints JSON by default. Pass `--no-line-numbers` to remove rendered line and line-range prefixes from text previews while keeping structured line metadata unchanged.

## Help

List modes and toolsets:

```bash
bifrost --help
```

## Related File Ranking

The repository also builds the `most_relevant_files` helper binary:

```bash
cargo build --bin most_relevant_files
./target/debug/most_relevant_files --root /path/to/project path/to/seed_file.py
```
