---
title: OpenCode
description: Configure and validate Bifrost LSP, MCP tools, and Agent Skills in OpenCode.
---

OpenCode can use Bifrost in three complementary ways. Its native LSP client
provides definitions, references, hover, symbols, implementations, hierarchy,
and diagnostics. MCP exposes Bifrost-specific analyzer tools such as
`get_summaries` and `query_code`. Agent Skills separately teach OpenCode when
and how to use those MCP tools.

For OpenCode's underlying host conventions, see the official
[LSP server](https://opencode.ai/docs/lsp/),
[tools](https://opencode.ai/docs/tools/),
[MCP server](https://opencode.ai/docs/mcp-servers/) and
[Agent Skills](https://opencode.ai/docs/skills/) documentation.

## Configure LSP

Install Bifrost first:

```bash
cargo install brokk-bifrost --locked --force
```

Add a project-local `opencode.json` at the root of the repository you want
Bifrost to analyze. Use absolute paths for the executable and project root:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "lsp": {
    "bifrost": {
      "command": [
        "/absolute/path/to/bifrost",
        "--root",
        "/absolute/path/to/project",
        "--lsp"
      ],
      "extensions": [
        ".java",
        ".go",
        ".c",
        ".cc",
        ".cpp",
        ".cxx",
        ".h",
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

The extensions above are Bifrost's primary analyzable document types. Bifrost
can index `.vue`, `.svelte`, `.razor`, and `.cshtml` files as supporting
reference context, but those files are not primary LSP document types and
should not activate the server.

The `--root` value is a deterministic fallback. A valid `workspaceFolders`,
`rootUri`, or `rootPath` sent by OpenCode during LSP initialization takes
precedence. Absolute paths avoid accidentally binding Bifrost to another
launch directory.

For local Bifrost development, build the checkout and use the absolute debug
binary path in the command:

```bash
cargo build --bin bifrost
```

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

The evidence on this page was collected with OpenCode 1.18.3 and a Bifrost
0.8.19 checkout at commit `5c479d140d8a1452167a88863e070735faa8d400`.
Record both versions when validating another installation:

```bash
opencode --version
/absolute/path/to/bifrost --version
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
OpenCode 1.18.3 was also validated against Bifrost for hover, workspace
symbols, implementation lookup, and incoming and outgoing call hierarchy. For
diagnostics and edit synchronization, have OpenCode edit a temporary source
file to introduce a syntax error. A working integration reports an LSP error
immediately after the edit; `opencode debug lsp diagnostics` identifies its
source as `bifrost-tree-sitter`. A clean file returning no diagnostics does not
by itself prove which server answered. Remove the probe after retaining the
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
        "/absolute/path/to/bifrost",
        "--root",
        "/absolute/path/to/project",
        "--lsp"
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
- If an old Bifrost release is running, set the command to the intended
  absolute binary instead of relying on `PATH`.
- If two servers produce overlap or slow startup, disable only the exact
  built-in server key for the affected language.
- Restart OpenCode after changing its configuration or launch environment.

Native LSP does not expose `get_summaries`, `query_code`, policies, or other
Bifrost-specific tools. Keep the MCP setup below when you want that surface.

## Configure MCP

The canonical `opencode.json` above includes the project-local `mcp.bifrost`
entry alongside `lsp.bifrost`; keep both top-level members when you want both
surfaces. If you already have an OpenCode configuration, merge those members
into the existing object instead of replacing the file or its other servers.

Use absolute paths for both the Bifrost binary and project root. OpenCode's
default MCP discovery timeout is five seconds; the longer timeout above allows
Bifrost to initialize and index a larger workspace on its first connection.

For local Bifrost development, use the same absolute debug binary built in the
LSP setup above.

Quit and restart OpenCode after adding or changing MCP configuration. Then
verify the server connection from the project root:

```bash
opencode mcp list
```

The output should list `bifrost` as connected.

## Add Skills

Install Bifrost's four generic agent skills into the project path
that OpenCode discovers:

```bash
bifrost --root /absolute/path/to/project \
  --install-skills --target project --mode copy
```

This installs:

- `bifrost-code-navigation`
- `bifrost-code-reading`
- `bifrost-codebase-search`
- `bifrost-policy-checking`

Restart OpenCode after installing the skills. To inspect the skills OpenCode
discovered, run:

```bash
opencode debug skill
```

OpenCode also scans the global `~/.agents/skills/` root. Avoid keeping different
versions of the same Bifrost skill in both the project and global roots:
same-named global copies can be selected instead of the project copies. Check
the `location` reported for all four Bifrost skills and keep one intended
scope current. To use global skills instead, install or refresh that scope:

```bash
bifrost --root /absolute/path/to/project \
  --install-skills --target global --mode copy
```

If the installer reports local changes, review them before deciding whether to
replace them with `--force`.

Installing skills does not start Bifrost or expose analyzer tools by itself.
Keep the MCP configuration above enabled when you want OpenCode to call
Bifrost.

## Validate the Setup

Start OpenCode from the configured project root and use a prompt that requires
both a skill load and a Bifrost MCP result:

```text
Use the bifrost-code-reading skill. Call the Bifrost get_summaries MCP tool on src/main.rs and report only the declared symbol names returned by that tool.
```

Replace `src/main.rs` with a source file that exists in the target repository.
A successful smoke shows the `bifrost-code-reading` skill being loaded and a
`bifrost_get_summaries` tool call before the answer. Avoid prompts that only
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
