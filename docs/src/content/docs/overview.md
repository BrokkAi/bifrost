---
title: Overview
description: What Bifrost provides and how it fits into Brokk workflows.
---

Bifrost is Brokk's Rust-based static analysis engine for AI coding harnesses. It is built around structured repository facts rather than raw text search.

Bifrost can parse mixed-language workspaces, expose code intelligence through MCP, run as an LSP server for editors, and serve Rust or Python callers directly.

## Built for Large Repositories

Bifrost is designed to stay lean on real repositories, not just small demos. The workspace model keeps memory usage capped by indexing declarations and other durable repository facts first, while avoiding a permanently resident graph of every expensive analysis result.

More complex static analysis runs on demand when a tool call needs it. Results can be cached, but the source of truth stays incremental: file changes update the declaration index, and deeper relationship, usage, summary, or type analysis is recomputed only for the affected work. This keeps the MCP server responsive without trading correctness for raw text shortcuts.

## Language Coverage

Bifrost includes analyzers for Java, JavaScript, TypeScript, Rust, Go, Python, C, C++, C#, PHP, Scala, and Ruby.

## Main Surfaces

- MCP server: code-navigation tools for AI agents.
- LSP server: code-navigation features for editors.
- CLI tool mode: one-shot terminal access to individual Bifrost tools.
- Rust crate and Python wheel: embedded analyzer APIs.

## Internal Documentation Boundary

The rendered docs in this directory are for human readers. Internal agent notes live under `.agents/docs/`, and implementation ExecPlans live under `.agents/plans/`.
