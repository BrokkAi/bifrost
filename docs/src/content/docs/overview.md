---
title: Overview
description: What Bifrost provides and how it fits into Brokk workflows.
---

Bifrost is Brokk's Rust-based static analysis engine for AI coding harnesses. It is built around structured repository facts rather than raw text search.

Bifrost can parse mixed-language workspaces, expose code intelligence through MCP, run as an LSP server for editors, and serve Rust or Python callers directly.

## Built for Large Repositories

Bifrost is designed to stay lean on real repositories, not just small demos. The workspace model indexes declarations and other durable repository facts first, while avoiding a permanently resident graph of every expensive analysis result.

More complex static analysis runs on demand when a tool call needs it. Results can be cached, but the source of truth stays incremental: file changes update the declaration index, and deeper relationship, usage, summary, or type analysis is recomputed only for the affected work. This architecture is intended to reduce long-lived memory and repeated work without trading correctness for raw text shortcuts; it is not itself a measured performance result. See [Evidence and Evaluation Methodology](/evaluation-evidence/) for the current public evidence and remaining benchmark gaps.

## Language Coverage

Bifrost includes analyzers for Java, JavaScript, TypeScript, Rust, Go, Python, C, C++, C#, PHP, Scala, and Ruby.

Bifrost uses Tree-sitter parsers as the common syntax foundation across those
languages. The parsed trees are adapted into reusable analyzer concepts where
the structure really is shared, such as declarations, references, scopes, type
relationships, and call relationships. Where a language's semantics depend on
its compiler or interpreter model, Bifrost keeps language-specific modelling and
sub-analysis instead of flattening those rules into a lowest-common-denominator
abstraction.

See [Language and Analysis Capabilities](/capabilities/) for the language-by-capability matrix, precision tiers, external-dependency boundary, bounded Java/JavaScript/TypeScript receiver provenance, and the remaining unsupported whole-program points-to, general alias, control-flow, taint, and data-flow analyses. If you are deciding which Bifrost surface to use, start with [Choose Bifrost](/choose-bifrost/).

## Main Surfaces

- MCP server: code-navigation tools for AI agents.
- LSP server: code-navigation features for editors.
- CLI tool mode: one-shot terminal access to individual Bifrost tools.
- Rust crate and Python wheel: embedded analyzer APIs.

## Internal Documentation Boundary

The rendered docs in this directory are for human readers. Internal agent notes live under `.agents/docs/`, and implementation ExecPlans live under `.agents/plans/`.
