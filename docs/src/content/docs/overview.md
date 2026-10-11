---
title: Overview
description: What Bifrost provides and how it fits into Brokk workflows.
---

Bifrost is Brokk's Rust-based static analysis engine for AI coding harnesses. It is built around structured repository facts rather than raw text search.

Bifrost can parse mixed-language workspaces, expose code intelligence through MCP, run one-shot queries and policy checks from the command line, and serve Rust or Python callers directly. Editors use the separate `bifrost-lsp` language server; see [LSP Server](/lsp/).

## Built for Large Repositories

Bifrost is designed to stay lean on real repositories, not just small demos. The workspace model indexes declarations and other durable repository facts first, while avoiding a permanently resident graph of every expensive analysis result.

More complex static analysis runs on demand when a tool call needs it. Results can be cached, but the source of truth stays incremental: file changes update the declaration index, and deeper relationship, usage, summary, or type analysis is recomputed only for the affected work. This architecture is intended to reduce long-lived memory and repeated work without trading correctness for raw text shortcuts; it is not itself a measured performance result. See [Evidence and Evaluation Methodology](/evaluation-evidence/) for the current public evidence and remaining benchmark gaps.

The [Design and Architecture guide](/design/) explains the system layers,
identity model, storage and cache strategy, usage and dataflow engines, semantic
models, result contract, design decisions, outlook, and related work.

## Language Coverage

Bifrost includes analyzers for Java, JavaScript, TypeScript, Rust, Go, Python, C, C++, C#, PHP, Scala, Ruby, and Kotlin. The [Languages reference](/reference/languages/) lists the file extensions each analyzer reads and the files it does not analyze, such as `.vue` templates and `.pyi` stubs.

Bifrost uses Tree-sitter parsers as the common syntax foundation across those
languages. The parsed trees are adapted into reusable analyzer concepts where
the structure really is shared, such as declarations, references, scopes, type
relationships, and call relationships. Where a language's semantics depend on
its compiler or interpreter model, Bifrost keeps language-specific modelling and
sub-analysis instead of flattening those rules into a lowest-common-denominator
abstraction.

See [Language and Analysis Capabilities](/capabilities/) for the language-by-capability matrix, precision tiers, external-dependency boundary, bounded receiver provenance, experimental data-flow and typestate baseline, and remaining whole-program precision boundaries. The [Languages reference](/reference/languages/) has the complete per-language tables. If you are deciding which Bifrost surface to use, start with [Choose Bifrost](/choose-bifrost/).

## Main Surfaces

- [MCP server](/mcp/): code-navigation tools for AI agents. The `bifrost` binary serves it.
- [CLI](/cli/): one-shot tool calls, saved queries, an interactive query prompt, and policy scans from the terminal.
- [Rust crate](/rust-library/) and [Python wheel](/python-client/): embedded analyzer APIs.
- [LSP server](/lsp/): code-navigation features for editors. The separate `bifrost-lsp` program serves it, not the `bifrost` binary.
