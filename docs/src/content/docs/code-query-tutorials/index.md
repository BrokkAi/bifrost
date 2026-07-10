---
title: Language Tutorials
description: Learn query_code through executable, per-language structural matching examples.
---

These tutorials start from recognizable source code and show the same query in [Rune Query Language](/rune-query-language/) and canonical [JSON `CodeQuery`](/code-query-json/). Their fixtures, queries, and complete expected results are executed by Bifrost's integration tests.

Each page builds from a broad structural query to narrower filters and exclusions. The examples stay within version 1's normalized syntax model: they do not claim type resolution, call-graph traversal, or data-flow reasoning.

Language pages will be added and marked with their last successful end-to-end verification date as their milestones complete.

## Tutorials

- [Python](./python/)
- [Java](./java/)
- [JavaScript](./javascript/)
- [TypeScript](./typescript/)
- [Go](./go/)
- [C and C++ through the `cpp` adapter](./cpp/)
- [Rust](./rust/)
- [PHP](./php/)
- [Scala](./scala/)
- [C#](./csharp/)
- Ruby (planned)

## What “Every Kind” Means

`query_code` works with a public language-neutral vocabulary, not raw tree-sitter grammar node names. The completed tutorial suite will exercise every normalized kind and role from that public vocabulary, including abstract subtype-aware queries such as `callable`, `declaration`, and `literal`.
