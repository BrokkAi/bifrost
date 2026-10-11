---
title: OpenCode
description: Configure and validate the Bifrost language server and MCP tools in OpenCode.
---

OpenCode can use Bifrost in two ways:

- OpenCode's LSP client can start the Bifrost language server, `bifrost-lsp`,
  for definitions, references, and other editor features.
- OpenCode's MCP client can start `bifrost --mcp` for Bifrost's analyzer
  tools, such as `get_summaries` and `query_code`.

:::caution[bifrost-lsp is not released yet]
Bifrost built after release 0.12.0 does not serve LSP: `bifrost --lsp` exits
with an error. The language server is now the separate `bifrost-lsp` program, and
`bifrost-lsp` has no release yet. The `lsp` configuration below is ready for
its first release. The `mcp` configuration works now. See
[LSP Server](/lsp/).
:::

For OpenCode's underlying host conventions, see the official
[LSP server](https://opencode.ai/docs/lsp/),
[tools](https://opencode.ai/docs/tools/),
[MCP server](https://opencode.ai/docs/mcp-servers/) documentation.

## Configure LSP and MCP

Install the Bifrost CLI for MCP. See [Install](/install/). The `lsp` entry
needs a `bifrost-lsp` binary instead.

Add a project-local `opencode.json` at the root of the repository you want
Bifrost to analyze. Use absolute paths for both executables and for the
project root:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "lsp": {
    "bifrost": {
      "command": [
        "/absolute/path/to/bifrost-lsp",
        "--root",
        "/absolute/path/to/project"
      ],
      "extensions": [
        ".java",
        ".go",
        ".c",
        ".cc",
        ".cpp",
        ".cxx",
        ".h",
        ".hin",
        ".hpp",
        ".hh",
        ".hxx",
        ".js",
        ".mjs",
        ".cjs",
        ".jsx",
        ".ts",
        ".tsx",
        ".py",
        ".rs",
        ".php",
        ".scala",
        ".cs",
        ".rb",
        ".kt",
        ".kts"
      ]
    }
  },
  "permission": {
    "lsp": "allow"
  },
  "mcp": {
    "bifrost": {
      "type": "local",
      "command": [
        "/absolute/path/to/bifrost",
        "--root",
        "/absolute/path/to/project",
        "--mcp",
        "symbol|extended"
      ],
      "enabled": true,
      "timeout": 300000
    }
  }
}
```

On Windows, use forward slashes in these JSON paths or escape each backslash.

The extensions above are the source files that Bifrost analyzes.
[Languages](/reference/languages/) is the source of this list. Bifrost
does not analyze `.vue`, `.svelte`, `.razor`, or `.cshtml` files, so do not add
them.

`--root` is the fallback workspace root. OpenCode also sends the workspace
root when it initializes the server. Absolute paths stop Bifrost from binding
to whatever directory OpenCode was started from.

### Expose LSP to the agent

OpenCode's agent-facing `lsp` tool is experimental in the tested OpenCode
1.18.3 release. Set the feature flag in the environment that starts OpenCode:

macOS and Linux:

```bash
OPENCODE_EXPERIMENTAL_LSP_TOOL=true opencode /absolute/path/to/project
```

PowerShell:

```powershell
$env:OPENCODE_EXPERIMENTAL_LSP_TOOL = "true"
opencode C:/absolute/path/to/project
```

The `permission.lsp` setting above lets the agent call the tool. The tool
supports definitions, references, hover, document and workspace symbols,
implementations, and incoming and outgoing call hierarchy. Its line and
character inputs are one-based even though returned LSP ranges are zero-based.

The LSP results on this page were checked with OpenCode 1.18.3 and the
language server that Bifrost 0.8.19 included. They have not been checked
against `bifrost-lsp`. Record both versions when you validate an installation:

```bash
opencode --version
/absolute/path/to/bifrost-lsp --version
```

OpenCode V2 currently accepts the `lsp` configuration shape but does not have
an active LSP runtime; do not treat a successfully parsed V2 configuration as
a working integration.

### Validate native LSP

OpenCode starts a configured language server lazily when it opens a file whose
extension matches. Run a file-specific debug command or ask the agent to make
an LSP call on a real source file before interpreting an empty workspace-symbol
result or checking for a server process.

The debug commands provide a model-independent smoke test:

```bash
opencode debug config
opencode debug lsp document-symbols file:///absolute/path/to/project/src/main.rs
opencode debug lsp diagnostics /absolute/path/to/project/src/main.rs
```

Then start OpenCode with the experimental flag and ask the agent to use only
the `lsp` tool on a declaration unique to that checkout:

```text
Use only the lsp tool. Call documentSymbol on src/main.rs, then call
goToDefinition and findReferences on unique_probe_symbol. Report the returned
file paths and ranges. Do not use file reading, text search, shell, or MCP.
```

A valid pass shows real `documentSymbol`, `goToDefinition`, and
`findReferences` tool events and returns paths under the configured project.
With Bifrost 0.8.19, OpenCode 1.18.3 also returned hover, workspace symbols,
implementation lookup, and incoming and outgoing call hierarchy. To check
diagnostics and edit synchronization, have OpenCode add a syntax error to a
temporary source file. A working integration reports an LSP error right after
the edit. With Bifrost 0.8.19, `opencode debug lsp diagnostics` named the
source `bifrost-tree-sitter`. A clean file with no diagnostics does not show
which server answered. Remove the probe after retaining the
evidence.

### Coexist with built-in servers

The object form of OpenCode's `lsp` configuration keeps matching built-in
servers enabled. This can be useful: a compiler-backed server can provide
build-aware diagnostics while Bifrost provides build-independent repository
navigation. Keep both unless overlap causes duplicate or ambiguous results or
unacceptable startup latency.

To prove that Bifrost handled a smoke test, or to avoid a concrete conflict,
disable only the matching built-in server. For example:

```json
{
  "lsp": {
    "rust": {
      "disabled": true
    },
    "bifrost": {
      "command": [
        "/absolute/path/to/bifrost-lsp",
        "--root",
        "/absolute/path/to/project"
      ],
      "extensions": [".rs"]
    }
  }
}
```

Do not disable all built-in servers globally just to add Bifrost.

### Troubleshoot LSP

- If no server starts, run a file-specific LSP debug command or ask the agent
  to make an LSP call on a configured source file first.
- If the agent has no `lsp` tool, restart OpenCode from an environment with
  `OPENCODE_EXPERIMENTAL_LSP_TOOL=true`.
- If the tool is denied, allow the `lsp` permission in the applicable config.
- If results come from the wrong checkout, replace relative command and root
  values with absolute paths and repeat the unique-declaration smoke.
- If the server exits at once with `the LSP server has moved out of this
  repository`, the command names the `bifrost` CLI. Point it at `bifrost-lsp`.
- If the wrong server version is running, set the command to the intended
  absolute binary instead of relying on `PATH`.
- If two servers produce overlap or slow startup, disable only the exact
  built-in server key for the affected language.
- Restart OpenCode after changing its configuration or launch environment.

The LSP tool does not give the agent `get_summaries`, `query_code`, policies,
or other Bifrost tools. Use the MCP setup below for those.

## Configure MCP

The `opencode.json` above has a project-local `mcp.bifrost` entry next to
`lsp.bifrost`. The MCP entry starts the `bifrost` CLI, not `bifrost-lsp`. You
can keep the MCP entry alone if you do not need the language server. If you already have an OpenCode configuration, merge those members
into the existing object instead of replacing the file or its other servers.

Use absolute paths for both the Bifrost binary and project root. OpenCode's
default MCP discovery timeout is five seconds; the longer timeout above allows
Bifrost to initialize and index a larger workspace on its first connection.

Quit and restart OpenCode after adding or changing MCP configuration. Then
verify the server connection from the project root:

```bash
opencode mcp list
```

The output should list `bifrost` as connected.

## Validate the Setup

Start OpenCode from the configured project root and use a prompt that requires
an actual Bifrost MCP result:

```text
Call the Bifrost get_summaries MCP tool on src/main.rs and report only the declared symbol names returned by that tool.
```

Replace `src/main.rs` with a source file that exists in the target repository.
A successful smoke shows a `bifrost_get_summaries` tool call before the answer.
Avoid prompts that only
ask about `README.md` or documentation files; those can pass through ordinary
file reading without proving that the analyzer-backed MCP server ran.

Apply the shared
[host-integration evidence contract](/mcp/#validate-host-integration): retain
the Bifrost tool event and structured result for a known workspace declaration,
verify its project-relative source path, and reject file-reading fallbacks.

## Can My Agent Run RQL?

The configuration above uses `symbol|extended`, so a fresh OpenCode session
should advertise Bifrost's `query_code` tool. Ask OpenCode to call it with the
inline canonical JSON fields:

```json
{"match":{"kind":"declaration"},"limit":1}
```

To validate saved RQL, add a workspace file named `bifrost-smoke.rql`:

```lisp
(limit 1 (declaration))
```

Then ask OpenCode to call Bifrost `query_code` with exactly:

```json
{"query_file":"bifrost-smoke.rql"}
```

The inline call is canonical JSON. MCP accepts RQL only from a workspace
`.rql` file through `query_file`. See
[MCP query and RQL availability](/mcp/#query-and-rql-availability) for the full
surface matrix and [Agent Result Safety](/agent-result-safety/) before making
completeness claims.
