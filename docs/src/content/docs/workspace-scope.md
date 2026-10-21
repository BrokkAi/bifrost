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
analysis, structural queries, policies, or diagnostics.

## File Tools Still See Excluded Files

`.bifrostignore` does not remove a path from the workspace's file inventory.
File-content tools and text-level checks can
still locate and inspect matching files. This is useful for checks that verify a
generated artifact exists or contains a small expected marker.

This differs from `.gitignore`. Bifrost's workspace inventory follows Git's
ignore rules for untracked files but deliberately keeps tracked files visible.
`.bifrostignore` adds a separate, analysis-only boundary for tracked or
untracked content.

## Which Files Are in the Workspace

Bifrost builds the workspace file inventory this way:

- Inside a Git repository, the inventory is every tracked file that exists in
  the working tree, plus every untracked file that Git does not ignore. Files
  in initialized submodules are included. Bifrost reads the Git index and
  working tree; it does not fetch or initialize submodules.
- Outside a Git repository, Bifrost walks the directory tree. It honors
  `.gitignore` files, the global Git ignore file, and `.git/info/exclude`. It
  does not honor `.ignore` files.
- Hidden files and directories, such as `.github/`, are included.
- A `.git` directory is never walked.
- If the root is inside a Git repository whose ignore rules hide the whole
  root, Bifrost walks the root directly instead, without the ancestor
  repository's ignore files.

## Files That Are Never Parsed

Some files stay in the inventory but are never parsed, so they get no code
intelligence even when no ignore rule matches them:

- Binary files: a file that contains a NUL byte, unless
  `BIFROST_ADMIT_NUL_BYTES=1` is set.
- Files with overlong structural lines, such as minified JavaScript bundles.
  The default limit is 16000 bytes. Set `BIFROST_MAX_LINE_LENGTH` to apply a
  strict physical-line limit, or to `0` to turn the line limit off. See
  [Environment Variables](/reference/environment/).

At the default setting, C/C++ analysis can admit generated numeric tables.
The parser must prove that the excluded spans contain only numeric initializer
lists, including nested lists and signed numbers. Python also admits string
and bytes literals, including implicit concatenation, when they contain no
interpolation fields (for example, generated protobuf descriptors).
The remaining bytes on each
physical line must fit the default limit. The complete original source is still
analyzed, and any separate syntax recovery remains incomplete evidence.

This exception has finite limits: 1 MiB of source, 65536 syntax-tree nodes,
depth 128, 8 MiB of cumulative node spans, and 8192 nodes across all excluded
data subtrees. Parsing and admission share a 10-second deadline. An explicit positive
`BIFROST_MAX_LINE_LENGTH`, including `16000`, applies the strict physical-line
limit instead. Choose this setting before starting Bifrost; changing it between
runs invalidates C/C++ and Python facts admitted under the previous setting.

File-level tools can still read files that analysis refuses.

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

Explicit selections are useful for one-off inspection. Ordinary
whole-workspace CLI, MCP, Python, and Rust-library analyzer construction
continues to honor `.bifrostignore`.

## Live Sessions

Long-running MCP sessions watch `.bifrostignore`. Creating, changing, renaming,
or removing a root or nested `.bifrostignore` file invalidates the analysis
scope and starts a full re-analysis. File-level tools use the complete
workspace inventory before and after that refresh. When file watching is off
(`BIFROST_MCP_FILE_WATCHER=off`), call the `refresh` tool after you change a
`.bifrostignore` file.
