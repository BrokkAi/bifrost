---
title: RQL in VS Code
description: Run Rune Query Language files from VS Code and navigate their structural matches.
---

The Bifrost VS Code extension recognizes `.rql` files as **Bifrost RQL**. RQL,
the [Rune Query Language](/rune-query-language/), is Bifrost's experimental
S-expression frontend for structural `query_code` searches.

With the Bifrost language server running and indexed, use the Play button in
an RQL editor title to execute the current document. Unsaved edits are sent to
the active LSP session, so you can refine a query without first saving it.

```lisp
(result-detail full
  (where "src/lsp/server.rs"
    (function :name "handle_run_rql_query_request")))
```

The **Bifrost Query Results** Explorer view groups matches by file. Select a
match to open its file and highlight the matched source range.

![An RQL query in VS Code, grouped query results in Explorer, and the selected Rust match.](/images/rql-vscode-query-results.png)

## Query Scope

The query runs across every root indexed by the active Bifrost LSP session:

- all VS Code workspace folders by default; or
- the directories selected with `bifrost.roots`.

The `.rql` file itself may live outside the workspace. Only the code searched
by the query is limited to the active indexed roots.

The Play action does not start Bifrost or wait for indexing. Start or restart
the language server first, then run the query once it is ready. Use
`bifrost.serverPath` to point the extension at a local Bifrost build during
extension development.

For the RQL syntax and REPL workflow, see [Rune Query Language](/rune-query-language/).
