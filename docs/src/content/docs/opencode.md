---
title: OpenCode
description: Install and validate Bifrost MCP tools and Agent Skills in OpenCode.
---

OpenCode can use Bifrost through a project-local MCP server entry and can load
Bifrost's generic Agent Skills from the same workspace. MCP makes the analyzer
tools callable; the skills separately teach OpenCode when and how to use them.

For OpenCode's underlying host conventions, see the official
[MCP server](https://opencode.ai/docs/mcp-servers/) and
[Agent Skills](https://opencode.ai/docs/skills/) documentation.

## Configure MCP

Install Bifrost first:

```bash
cargo install brokk-bifrost --locked --force
```

Add a project-local `opencode.json` at the root of the repository you want
Bifrost to analyze:

```json
{
  "$schema": "https://opencode.ai/config.json",
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

Use absolute paths for both the Bifrost binary and project root. OpenCode's
default MCP discovery timeout is five seconds; the longer timeout above allows
Bifrost to initialize and index a larger workspace on its first connection.

For local Bifrost development, build this checkout and use the debug binary in
the `command` array:

```bash
cargo build --bin bifrost
```

Set the command's first element to the absolute path to
`target/debug/bifrost`.

Quit and restart OpenCode after adding or changing MCP configuration. Then
verify the server connection from the project root:

```bash
opencode mcp list
```

The output should list `bifrost` as connected.

## Add Skills

Install Bifrost's three generic code-intelligence skills into the project path
that OpenCode discovers:

```bash
bifrost --root /absolute/path/to/project \
  --install-skills --target project --mode copy
```

This installs:

- `bifrost-code-navigation`
- `bifrost-code-reading`
- `bifrost-codebase-search`

Restart OpenCode after installing the skills. To inspect the skills OpenCode
discovered, run:

```bash
opencode debug skill
```

OpenCode also scans the global `~/.agents/skills/` root. Avoid keeping different
versions of the same Bifrost skill in both the project and global roots:
same-named global copies can be selected instead of the project copies. Check
the `location` reported for all three Bifrost skills and keep one intended
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
