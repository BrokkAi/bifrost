---
title: Language Tutorials
description: Learn query_code through executable, per-language structural matching examples.
---

These tutorials start from recognizable source code and show the same query in [Rune Query Language](/rune-query-language/) and canonical [JSON `CodeQuery`](/code-query-json/). Bifrost's integration tests run every marked fixture, query, and expected result on the language pages, [Library Integration](/code-query-tutorials/library-integration/), [Typed Set Composition](/code-query-tutorials/set-composition/), [Reference Traversal](/code-query-tutorials/reference-traversal/), and [Receiver Traversal](/code-query-tutorials/receiver-traversal/). Some explanatory blocks on Reference Traversal show a query form without a fixture or expected result. [Import Traversal](/code-query-tutorials/import-traversal/) shows templates with a `<language>` placeholder and has no expected results.

Each page builds from a broad structural query to narrower filters and exclusions. [Import Traversal](/code-query-tutorials/import-traversal/) covers direct project-file edges, [Typed Set Composition](/code-query-tutorials/set-composition/) combines those edges with union, intersection, and subtraction, [Reference Traversal](/code-query-tutorials/reference-traversal/) follows exact indexed declarations to source sites and semantic users, and [Receiver Traversal](/code-query-tutorials/receiver-traversal/) exercises bounded values and exact members through the shared adapter-neutral contract. Every language cookbook also executes `supertypes`, `subtypes`, `members`, and `owner`, with bounded and transitive hierarchy examples distributed across the suite. The receiver cookbook does not claim whole-program points-to, general alias, control-flow, taint, or data-flow reasoning.

Hierarchy recipes return only declarations indexed by the fixture's analyzer. Real projects may expose usages of library types whose declarations are not indexed; those library declarations remain outside the query result until library indexing can be targeted explicitly.

[Library Integration](/code-query-tutorials/library-integration/) is the odd one out: instead of teaching more query vocabulary, it runs one canonical query through the Rust and Python libraries and shows how an embedder reads the result's completeness signals.

Each page that has fixtures is marked with the date of its last successful end-to-end verification.

## Tutorials

- [Library Integration](/code-query-tutorials/library-integration/)
- [Import Traversal Across Languages](/code-query-tutorials/import-traversal/)
- [Typed Set Composition](/code-query-tutorials/set-composition/)
- [Reference Traversal Across Languages](/code-query-tutorials/reference-traversal/)
- [Bounded Receiver Traversal](/code-query-tutorials/receiver-traversal/)
- [Python](/code-query-tutorials/python/)
- [Python Parser Recovery](/code-query-tutorials/python-recovery/)
- [Java](/code-query-tutorials/java/)
- [JavaScript](/code-query-tutorials/javascript/)
- [TypeScript](/code-query-tutorials/typescript/)
- [Go](/code-query-tutorials/go/)
- [C and C++ through the `cpp` adapter](/code-query-tutorials/cpp/)
- [Rust](/code-query-tutorials/rust/)
- [PHP](/code-query-tutorials/php/)
- [Scala](/code-query-tutorials/scala/)
- [C#](/code-query-tutorials/csharp/)
- [Ruby](/code-query-tutorials/ruby/)
- [Kotlin](/code-query-tutorials/kotlin/)

## What “Every Kind” Means

`query_code` works with a public language-neutral vocabulary, not raw tree-sitter grammar node names. The completed tutorial suite exercises every normalized kind and role from that public vocabulary, including abstract subtype-aware queries such as `callable`, `declaration`, and `literal`. The aggregate integration test fails if a future vocabulary addition is not taught here.

## Coverage map

The pages deliberately spread the vocabulary across languages: calls and assignments appear in every adapter, decorators are demonstrated where the grammar exposes them, `kwargs` appears in Python, PHP, Scala, C#, Ruby, and Kotlin, and C/C++ share the `cpp` adapter. For the kinds and roles that each language supports, see [language support](/reference/languages/).
