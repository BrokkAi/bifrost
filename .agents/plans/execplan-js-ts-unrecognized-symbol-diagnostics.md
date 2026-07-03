# Add high-confidence JS/TS unrecognized-symbol diagnostics

Bifrost reports JavaScript and TypeScript semantic diagnostics through the existing
LSP diagnostic hook only when tree-sitter parsing succeeds. The first JS/TS slice is
deliberately conservative: it reports clear unresolved bare identifier and type
identifier references after local bindings, imports, aliases, and project-local
declarations have been considered.

This does not implement TypeScript compiler parity. Bare npm package resolution,
`package.json` `exports` / `main`, `.d.ts` ambient declaration modeling, JSX runtime
injection, and broad global modeling remain out of scope. When one of those features
could plausibly supply a name, the collector suppresses the semantic diagnostic.

Implementation notes:

- The analyzer entry point is `IAnalyzer::semantic_diagnostics`; JavaScript and
  TypeScript delegate to the shared JS/TS collector.
- Relative imports and supported `tsconfig.json` / `jsconfig.json` path aliases reuse
  the existing JS/TS module resolver.
- Property names, member expressions, JSX intrinsic elements, import/export clauses,
  labels, declarations, patterns, malformed files, and unresolved bare package imports
  are suppressed to avoid false positives.

