---
title: CLI
description: Use Bifrost from the terminal for one-shot code-intelligence queries and skill installation.
---

Bifrost can run a single tool once and print the JSON result:

```bash
bifrost --root /path/to/project --tool search_symbols --args '{"patterns":["MyClass"]}'
```

`--tool` uses the same named tool implementations exposed by the MCP `searchtools` catalog. Use it when you want the MCP tool surface from a shell script or terminal session without starting a long-lived MCP server.

`--args` is inline JSON matching the selected tool's MCP argument object. Omit it for tools that accept an empty object, such as `get_active_workspace`.

## Saved Code Queries

Run a complete RQL or JSON `query_code` query from a workspace file without the generic tool wrapper:

```bash
bifrost --query-file queries/audit.rql
bifrost --root /path/to/project --query-file queries/audit.json
```

`--query-file` accepts `.rql` and `.json` files only. The default workspace root is the current directory; query-file paths must stay inside that workspace, including after symlinks are resolved. The file contains the complete query, so it cannot be combined with `--tool`, `--args`, or `--sources`.

For the available tool families and tool names, see [MCP Server](../mcp/). For a single tool's description and parameters, ask the CLI directly:

```bash
bifrost --help scan_usages_by_location
bifrost --help scan_usages_by_reference
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

## Install Agent Skills

Some agent hosts, including Zed and Antigravity-style hosts, load reusable
Agent Skills from filesystem roots instead of from the Bifrost plugin package.
Use `--install-skills` to install Bifrost's generic skills into one of those
roots:

```bash
bifrost --root /path/to/project --install-skills --target project
```

With no explicit destination, `bifrost --install-skills` opens a numbered menu.
The built-in destinations are:

- `--target project`: install to `<root>/.agents/skills`
- `--target global`: install to `~/.agents/skills`
- `--skills-root /path/to/skills`: install to an explicit skill root

The default skill set installs the three Bifrost code-intelligence skills:

- `bifrost-code-navigation`
- `bifrost-code-reading`
- `bifrost-codebase-search`

Use `--skill-set all` to also install the Brokk workflow and review skills. Use
`--mode copy` for self-contained copies, `--mode symlink` for checkout-local
development links, or leave the default `--mode auto`.

The installer is safe to rerun. It leaves matching installs unchanged, marks
copied Bifrost-managed skills with `.bifrost-install.json`, and refuses to
overwrite unrelated user skills. Use `--dry-run` to preview the actions and
`--force` only to replace a drifted Bifrost-managed copy.

Skill installation does not configure MCP. Skills tell an agent when and how to
use Bifrost, while the MCP server makes Bifrost's analyzer tools available. Use
[MCP Server](../mcp/) or the host-specific setup pages for MCP configuration.

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
