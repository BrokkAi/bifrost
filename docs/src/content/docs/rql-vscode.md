---
title: RQL in VS Code
description: Run Rune Query Language files from VS Code and navigate typed query results.
---

The Bifrost VS Code extension recognizes `.rql` files as **Bifrost RQL**. RQL,
the [Rune Query Language](/rune-query-language/), is Bifrost's experimental
S-expression frontend for structural `query_code` searches.

With the Bifrost language server running and indexed, use the Play button in
an RQL editor title to execute the current document. Unsaved edits are sent to
the active LSP session, so you can refine a query without first saving it.

Use VS Code's **Format Document** command to format `.rql` and saved `.rune`
files through the Bifrost language server. Bracketed forms remain on one line
through 120 columns. Longer forms place their entries on indented lines and
keep `:property value` pairs together when possible. The formatter preserves
comments and does not edit incomplete S-expressions.

This Play action is a VS Code language-server feature. It does not start an MCP server, expose `query_code` to an agent, or prove that an agent can run RQL. For agent access, configure a query-capable MCP toolset and use a saved workspace `.rql` file through `query_file`; MCP does not accept unsaved editor text or raw inline RQL. See [MCP query and RQL availability](/mcp/#query-and-rql-availability).

```lisp
(result-detail full
  (where "src/lsp/server.rs"
    (function :name "handle_run_rql_query_request")))
```

The **Bifrost Query Results** Explorer view groups tagged structural-match,
declaration, and file results by path. Select a structural match or declaration
to open its file and highlight the source range; selecting a file result opens
the file at its first line. Pipeline wrappers such as `enclosing-decl` and
`file-of` therefore remain navigable from the same view.

![An RQL query in VS Code, grouped query results in Explorer, and the selected Rust match.](../../assets/rql-vscode-query-results.png)

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
