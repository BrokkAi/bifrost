---
title: Code Querying
description: Understand Bifrost's structural code-querying model and its query representations.
---

Bifrost's structural code-querying engine is `search_ast`. It searches source code through a normalized schema instead of exposing raw parser nodes from each language.

Each language adapter starts from tree-sitter parses, then maps grammar-specific nodes and fields into a shared structural model:

- normalized kinds such as `function`, `method`, `class`, `call`, `literal`, and `field_access`
- normalized roles such as `callee`, `receiver`, `args`, `left`, `right`, `module`, `decorators`, `object`, and `field`
- source ranges, names, parent links, and role edges that let the matcher reason about containment and relationships

The matcher only sees this normalized fact arena. Language-specific tree-sitter node names stop at the adapter boundary, so a query can ask for a `call` with a `callee` across supported languages without knowing each grammar's internal node labels.

## Query Engine

`search_ast` is the engine and MCP tool. It validates a query, chooses candidate files and facts, checks normalized kinds and roles, applies containment constraints, and returns structural matches with file ranges and optional captures.

The engine has one semantic query model: `AstQuery`. Different input formats must lower into that same model before execution.

## Query Representations

Bifrost currently has two representations for `AstQuery`:

- [Rune Query Language](/search-ast-repl/) is the experimental S-expression syntax used by the human REPL.
- [JSON AstQuery](/search-ast-json/) is the canonical JSON representation used by `search_ast` over MCP and by `:json` output in the REPL.

JSON is not a separate query language. It is the stable serialization of the `AstQuery` model. RQL is a convenience language that compiles to that JSON-shaped model.

## Where To Start

Use RQL when you are exploring a repository interactively:

```bash
bifrost --root /path/to/project --repl
```

Use JSON `AstQuery` when a host, script, or MCP client needs a stable machine-facing payload for the `search_ast` tool.
