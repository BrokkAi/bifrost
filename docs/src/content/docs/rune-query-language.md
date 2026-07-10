---
title: Rune Query Language
description: Use the experimental S-expression frontend for Bifrost's query_code engine.
---

RQL, the Rune Query Language, is the experimental S-expression frontend for Bifrost's `query_code` engine. It is designed for interactive use in the REPL:

```bash
bifrost --root /path/to/project --repl
```

The default `bifrost` command still starts the MCP stdio server. Use `--repl` when you want a human-facing prompt with completion, history, multiline input, query validation, and readable search results.

## Relationship To CodeQuery

RQL is only a query language. It is not a second matcher or query engine.

Every RQL expression lowers into [JSON `CodeQuery`](/code-query-json/) before validation and execution. MCP hosts call the same engine through the `query_code` tool, using JSON `CodeQuery` directly. See [Code Querying](/code-querying/) for the schema and engine overview.

Use `:json` in the REPL to inspect the canonical JSON generated for the current RQL query.

## Complete Example

This query finds calls to `eval` inside a function, captures the first positional argument, limits the search to Python source files, and requests full ranges:

<!-- code-query-test:rql:complete -->
```lisp
(result-detail full
  (limit 25
    (language python
      (where "src/**/*.py"
        (inside
          (function :capture "handler")
          (call
            :callee (name "eval")
            :args [(capture "argument")]))))))
```

Enter it at the prompt, run `:validate`, inspect the lowered version with `:json`, and execute it with `:run`.

## Syntax

RQL uses compact S-expressions. The following are independent forms, not one multi-expression query:

```lisp
(call :callee (name "eval") :args [(capture "arg")])
(function :name "handler")
(class :decorators [(name "Controller")])
(import :module "os")
(where "src/**/*.py" (call :callee (name "eval")))
(language python (call :callee (name "eval")))
(limit 25 (call :callee (name "eval")))
(result-detail full (call :callee (name "eval")))
(inside (function :name "handler") (call :callee (name "eval")))
```

Head symbols such as `call`, `function`, `class`, and `import` map to normalized structural kinds. Keyword fields such as `:callee`, `:args`, `:module`, and `:decorators` map to normalized roles.

Predicate forms constrain fields on a pattern:

```lisp
(name "handler")
(name/regex ".*Service")
(text/regex "eval\\(")
(capture "argument")
(has (call :callee (name "open")))
(not-has (call :callee (name "eval")))
(not-kind lambda)
```

Wrapper forms control the query around the root pattern:

```lisp
(where "src/**/*.py" (call :callee (name "eval")))
(language python (call :callee (name "eval")))
(limit 25 (call :callee (name "eval")))
(result-detail full (call :callee (name "eval")))
(inside (function :name "handler") (call :callee (name "eval")))
(not-inside (function :name "test") (call :callee (name "eval")))
```

RQL is not yet a stable external API. It is intended to make interactive exploration pleasant while preserving `query_code` and JSON `CodeQuery` as the stable integration surface.

## Commands

- `:help` shows command help and examples.
- `:doc <name>` shows documentation for commands, forms, kinds, roles, languages, and examples.
- `:examples` lists named examples.
- `:example <name>` loads a named example.
- `:kinds`, `:roles`, and `:languages` list the current vocabulary.
- `:validate` validates the current query without running it.
- `:json` prints canonical JSON for the current query.
- `:run` executes the current query.
- `:clear` clears the current query.
- `:quit` exits the REPL.

Press `Ctrl+C` once to cancel reflexively; press it twice in a row to quit.
