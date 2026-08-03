---
title: Workspace Scope
description: Control which repository files Bifrost analyzes while keeping file-level inspection available.
---

Bifrost separates the files that belong to a workspace from the files that
receive code intelligence. This lets repositories keep generated, vendored, or
otherwise machine-authored build inputs available for file inspection without
paying to parse and index them.

## Exclude Files From Code Intelligence

Add a `.bifrostignore` file at the workspace root using Gitignore syntax:

```text
vendor/generated/
src/bindings/*.rs
!src/bindings/handwritten.rs
```

Nested `.bifrostignore` files apply relative to their own directories, with the
same precedence rules as nested `.gitignore` files. Bifrost applies these
patterns whether matching files are tracked by Git or not.

Matching files are excluded from analyzer-backed behavior. They contribute no
declarations or references to symbol search, summaries, navigation, usage
analysis, structural queries, policies, diagnostics, or the semantic index.

## File Tools Still See Excluded Files

`.bifrostignore` does not remove a path from the workspace's file inventory.
`find_filenames`, `list_files`, file-content tools, and text-level checks can
still locate and inspect matching files. This is useful for checks that verify a
generated artifact exists or contains a small expected marker.

This differs from `.gitignore`. Bifrost's workspace inventory follows Git's
ignore rules for untracked files but deliberately keeps tracked files visible.
`.bifrostignore` adds a separate, analysis-only boundary for tracked or
untracked content.

## Explicit One-Shot Sources Win

An explicit CLI `--sources` selection overrides `.bifrostignore`. For example,
this command analyzes the selected generated file even if an ambient ignore
pattern matches it:

```bash
bifrost --root /path/to/project \
  --tool get_symbol_sources \
  --sources vendor/generated/parser.c \
  --args '{"symbols":["vendor/generated/parser.c"]}'
```

Explicit selections are useful for one-off inspection. Ordinary whole-workspace
CLI, MCP, LSP, Python, and Rust-library analyzer construction continues to honor
`.bifrostignore`.

## Live Sessions

Long-running MCP and LSP sessions watch `.bifrostignore`. Creating, changing,
renaming, or removing a root or relevant nested file invalidates the configured
analysis scope and triggers a full re-analysis. File-level tools continue to use
the complete workspace inventory before and after that refresh.
