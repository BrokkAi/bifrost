---
name: bifrost-codebase-search
description: >-
  Discover symbols, structural code shapes, and files with Bifrost's
  search_symbols, query_code, find_filenames, list_files, scan_usages_by_location, and
  most_relevant_files tools, with shell grep for arbitrary text.
---

# Bifrost Codebase Search

Use these Bifrost MCP tools to find code in the active workspace. Pick the tool
that matches the thing you are looking for.

## Tools

| Goal | Tool |
|---|---|
| Find a symbol by name | `search_symbols` |
| Find callers, references, or usages | `scan_usages_by_location` |
| Find language-neutral code shapes | `query_code` |
| Find files by path or glob | `find_filenames` |
| List files under a directory | `list_files` |
| Expand from seed files to related code | `most_relevant_files` |
| Find arbitrary text | Host shell with `rg` or another built-in grep/search tool |

## Tips

- Use `search_symbols` for questions like "where is `parseRequest` defined?"
  or "which services match `.*Service`?". Pass `include_tests: true` when test
  declarations are relevant.
- Use `scan_usages_by_location` for references and call sites. It is the structured
  analyzer-backed path and should be preferred over grep for code references.
- Use `query_code` for normalized syntactic shapes such as calls by callee,
  assignments by left/right roles, imports, decorators, containment, or
  captures. Version 2 also supports typed enclosing-declaration, reference-site,
  semantic-user, hierarchy/member, and direct import-file steps. Use
  `references_of`, `used_by`, or `uses` when a structural seed should continue
  through exact indexed symbol identities; use `scan_usages_by_location` for a
  location-first lookup or `usage_graph` for the narrower whole-workspace graph. The schema reference
  is https://brokkai.github.io/bifrost/code-query-json/.
- Use `find_filenames` for path globs, basename searches, and repository file
  discovery.
- Use `list_files` when you need a bounded directory listing that respects the
  workspace file walker.
- Use `most_relevant_files` to broaden context from one known file into related
  source and tests.
- For log messages, string literals, comments, config keys, or any other text
  that is not an indexed declaration or reference, use `rg` through the host
  shell. The default Bifrost plugin does not expose the raw text MCP toolset.
