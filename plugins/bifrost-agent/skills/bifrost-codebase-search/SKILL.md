---
name: bifrost-codebase-search
description: >-
  Discover symbols, structural code shapes, and files with Bifrost's
  search_symbols, query_code, scan_usages_by_location, and most_relevant_files
  tools, with host file search for paths and arbitrary text.
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
| Expand from seed files to related code | `most_relevant_files` |
| Find files by path or glob | Host file search such as `rg --files` |
| Find arbitrary text | Host text search such as `rg` |

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
  is https://bifrost.brokk.ai/code-query-json/.
- Use the host's file-search support, such as `rg --files`, for path globs,
  basename searches, and repository file discovery.
- Use `most_relevant_files` to broaden context from one known file into related
  source and tests.
- For log messages, string literals, comments, config keys, or any other text
  that is not an indexed declaration or reference, use `rg` through the host
  shell. The default Bifrost plugin does not expose raw text-search MCP tools.
