# Bifrost Code Intelligence

When planning broad refactors, risky behavior changes, or edits to large classes
or modules, use Bifrost's structured code-intelligence tools before proposing a
plan or modifying code.

- Start with `get_summaries` for the target files, directories, classes, or
  modules so the plan is grounded in the actual API shape and neighboring code.
- Use `search_symbols` to find relevant classes, functions, methods, fields, and
  modules by name before opening files manually.
- Use `get_symbol_sources` when you need the exact body of a known symbol.
- Use the available `scan_usages_by_location` or `scan_usages_by_reference`
  tool before changing existing behavior so callers, references, and related
  tests are considered.
- Use `query_code` when the question starts from a language-neutral structural
  shape rather than a known symbol. MCP accepts canonical JSON inline or a
  saved workspace `.rql` file through the exclusive `query_file` field; it does
  not accept raw inline RQL.
- Prefer analyzer-backed summaries, symbols, definitions, and usages over raw
  grep or repeated file reads for code navigation decisions.
- Trust Bifrost for alias-aware and import-aware resolution. Text search may
  miss references that use aliases, re-exports, imports, or language-specific
  indirection.

Do not claim “all callers,” “all matches,” or “no matches” from `query_code`
until all of these checks pass:

- the tool call succeeded and the active workspace is the intended one;
- `truncated` is false and no capability or execution diagnostic makes the
  requested scope partial;
- proven and unproven reference/call edges are distinguished; and
- no result used for a path-completeness claim has `provenance_truncated: true`.

If a check fails, narrow or split the query, or report the returned rows as a
qualified partial result. An importer-file edge proves a direct file import,
not a concrete symbol usage or callsite.

Keep project-specific instructions in the existing `AGENTS.md`. Append this
section only to steer agents toward Bifrost context gathering before they make
implementation plans.
