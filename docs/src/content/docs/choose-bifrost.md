---
title: Choose Bifrost
description: Pick the Bifrost analysis and interface that match your question.
---

Bifrost has several interfaces because editor navigation, agent tools, structural queries, and embedded analysis have different jobs. Start with the question you need to answer, then choose where you want to answer it.

## Start With The Analysis

| Your question | Start with | Why |
| --- | --- | --- |
| “Where is this known symbol defined or referenced?” | `search_symbols`, then a mode-specific definition or usage tool | These tools preserve declaration identity, aliases, imports, and language-specific resolution. |
| “Which code has this syntactic shape?” | [`query_code`](/code-querying/) | It matches normalized calls, declarations, assignments, imports, literals, containment, and typed graph steps across languages. |
| “Which declarations call, use, inherit from, or import this result?” | A `query_code` typed pipeline | Start with a structural match, then traverse exact indexed declarations, reference/call edges, hierarchy, ownership, or project-file imports. |
| “Which code is conceptually about this topic?” | [`semantic_search`](/semantic-search/) | This optional feature retrieves by meaning when names and shapes are not known in advance. |
| “Where does this literal string occur?” | A text-search tool | Text search is the honest choice when the question is textual rather than structural or semantic. |
| “Can Bifrost prove control flow, aliasing, points-to, or general data flow?” | Do not use the current query engine for that proof | Those analyses are outside the current product boundary. Structural containment and resolved graph edges are not substitutes for them. |

When a question begins with a known declaration, prefer symbol and usage tools. When it begins with a language-neutral shape, prefer `query_code`. A common workflow is to find candidates structurally and then use exact locations or declarations for semantic follow-up.

## Then Choose The Interface

| Where you work | Best first surface | What it provides |
| --- | --- | --- |
| Coding agent | [MCP Server](/mcp/) with `symbol\|extended` | Symbol navigation plus inline JSON `query_code` and saved `.rql` through `query_file`. |
| VS Code | [VS Code LSP](/vscode/) | Definitions, references, hover, `.rql` editing, and execution of the current RQL buffer, including unsaved text. |
| Another editor | [LSP Server](/lsp/) | Editor-native definitions, references, hover, and workspace indexing; RQL editor features currently belong to the VS Code extension. |
| Terminal exploration | [CLI](/cli/) and [Rune Query Language](/rune-query-language/) | One-shot JSON queries, saved query files, and an interactive RQL prompt. |
| Rust application | [Rust Library](/rust-library/) | In-process analyzer APIs for a Rust integration. |
| Python application | [Python Client](/python-client/) | Native-backed Python access to Bifrost analysis and query results. |
| Instruction-only agent setup | [Agent Instructions](/agents/) | Guidance for using tools that are configured separately; skills and `AGENTS.md` text do not expose tools. |

MCP and LSP are separate Bifrost processes. A VS Code Play action proves that the extension's language server can execute RQL; it does not prove that an agent has MCP or `query_code`. Likewise, installing agent skills teaches a host how to use tools but does not start those tools. See the [MCP/RQL availability matrix](/mcp/#query-and-rql-availability) before configuring an agent.

## Routes By User Goal

### Evaluate Bifrost for research

Read [Language and Analysis Capabilities](/capabilities/) first. It distinguishes structural support, exact graph-backed references and calls, proof tiers, named arguments, imports, hierarchy, external-dependency limits, and unsupported whole-program analyses. Then complete the [ten-minute evaluation](/evaluate-bifrost/) and use the [executable language tutorials](/code-query-tutorials/) to inspect source, query, and exact expected output together.

### Build or study an agent platform

Start with the [MCP toolsets](/mcp/#toolsets), choose `symbol|extended`, and run both query-access smoke tests. Keep symbol tools, structural query results, and text search as different evidence sources. A successful symbol call does not establish that `query_code` is enabled, and a truncated or diagnostic-bearing result is not a completeness proof.

### Add Bifrost to an editor workflow

Choose an [LSP integration](/lsp/) for editor navigation. Add MCP separately only when an agent in that editor should call Bifrost tools. For VS Code query exploration, use the [RQL Play workflow](/rql-vscode/).

### Build a static-analysis integration

Begin with [Code Querying](/code-querying/), use RQL to explore, and inspect its canonical [JSON `CodeQuery`](/code-query-json/) before embedding the query through the CLI, Python, Rust, or MCP. Treat diagnostics, proof, truncation, and provenance as part of the result contract rather than optional metadata.

## Check Suitability Before Installation

Bifrost is a good fit when the answer can be grounded in parsed source structure, indexed declarations, exact source references, resolved call edges, direct project-file imports, or indexed type relationships. It is not currently a control-flow, points-to, general alias, taint, or whole-program data-flow engine. Read the [capability matrix](/capabilities/) for language-specific boundaries before relying on a zero-result or completeness claim.
