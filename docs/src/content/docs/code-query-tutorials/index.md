---
title: Language Tutorials
description: Learn query_code through executable, per-language structural matching examples.
---

These tutorials start from recognizable source code and show the same query in [Rune Query Language](/rune-query-language/) and canonical [JSON `CodeQuery`](/code-query-json/). Their fixtures, queries, and complete expected results are executed by Bifrost's integration tests.

Each page builds from a broad structural query to narrower filters and exclusions. [Import Traversal](./import-traversal/) shows version 2's typed enclosing-declaration and direct import-file steps across every adapter with structured import-file analysis. The examples do not claim arbitrary type resolution, call-graph traversal, or data-flow reasoning.

All language pages below are marked with the date of their last successful end-to-end verification.

## Tutorials

- [Import Traversal Across Languages](./import-traversal/)
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
- [Ruby](./ruby/)

## What “Every Kind” Means

`query_code` works with a public language-neutral vocabulary, not raw tree-sitter grammar node names. The completed tutorial suite exercises every normalized kind and role from that public vocabulary, including abstract subtype-aware queries such as `callable`, `declaration`, and `literal`. The aggregate integration test fails if a future vocabulary addition is not taught here.

## Coverage map

The pages deliberately spread the vocabulary across languages: calls and assignments appear in every adapter, decorators are demonstrated where the grammar exposes them, `kwargs` appears in Python, PHP, Scala, C#, and Ruby, and C/C++ share the `cpp` adapter. The executable coverage test is the authoritative map because it checks the canonical JSON cases and their exact results.
