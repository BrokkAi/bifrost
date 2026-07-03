---
title: Overview
description: What Bifrost provides and how it fits into Brokk workflows.
---

Bifrost is Brokk's Rust-based static analysis engine for AI coding harnesses. It is built around structured repository facts rather than raw text search.

Bifrost can parse mixed-language workspaces, expose code intelligence through MCP, run as an LSP server for editors, and serve Rust or Python callers directly.

## Language Coverage

Bifrost includes analyzers for Java, JavaScript, TypeScript, Rust, Go, Python, C, C++, C#, PHP, Scala, and Ruby.

## Main Surfaces

- MCP server: code-navigation tools for AI agents.
- VS Code extension: LSP-backed editor navigation.
- CLI tool mode: one-shot terminal access to individual Bifrost tools.
- Rust crate and Python wheel: embedded analyzer APIs.

## Internal Documentation Boundary

The rendered docs in this directory are for human readers. Internal agent notes live under `.agents/docs/`, and implementation ExecPlans live under `.agents/plans/`.
