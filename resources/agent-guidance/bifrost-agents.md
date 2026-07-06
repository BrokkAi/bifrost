# Bifrost Code Intelligence

When planning broad refactors, risky behavior changes, or edits to large classes
or modules, use Bifrost's structured code-intelligence tools before proposing a
plan or modifying code.

- Start with `get_summaries` for the target files, directories, classes, or
  modules so the plan is grounded in the actual API shape and neighboring code.
- Use `search_symbols` to find relevant classes, functions, methods, fields, and
  modules by name before opening files manually.
- Use `get_symbol_sources` when you need the exact body of a known symbol.
- Use `scan_usages` before changing existing behavior so callers, references,
  and related tests are considered.
- Prefer analyzer-backed summaries, symbols, definitions, and usages over raw
  grep or repeated file reads for code navigation decisions.
- Trust Bifrost for alias-aware and import-aware resolution. Text search may
  miss references that use aliases, re-exports, imports, or language-specific
  indirection.

Keep project-specific instructions in the existing `AGENTS.md`. Append this
section only to steer agents toward Bifrost context gathering before they make
implementation plans.
