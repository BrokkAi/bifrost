# Issue 78 Close-Out Notes

Issue `#78` closes JS/TS export-usage semantic parity within `bifrost`'s current v1 result model.

What landed here:
- Expanded focused JS/TS parity coverage in `tests/usages_js_ts_graph_test.rs`.
- Local alias and namespace-import usage routing.
- Local barrel and chained barrel traversal through the shared usage graph.
- Dotted JS/TS module basename resolution such as `layout.service.ts`.
- Scope-aware local shadow suppression for imported bindings.
- Member-usage handling for direct constructed receivers, one-hop aliases, typed receivers, namespace static access, and negative shadowed or unresolved receivers.

Intentional non-goals for this issue:
- `tsconfig` `paths` and `baseUrl`
- bare-specifier and `package.json` export resolution
- CommonJS usage-graph traversal beyond existing import-analysis helpers
- richer external-frontier reporting
- cross-query caches, cache invalidation, and thread-safety hardening

Important v1 limitation:
- Top-level barrel re-export statements do participate in graph traversal, but they do not become `UsageHit` values unless they occur inside an enclosing code unit. The focused parity tests lock this in so issue `#78` stays honest about the current result shape instead of silently over-claiming parity.
