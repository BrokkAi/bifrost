---
title: Amp
description: Use Bifrost MCP tools from Amp.
---

Amp can use Bifrost as an MCP server. The recommended Amp pattern is to bundle MCP servers inside a skill so the tools stay hidden until the skill is loaded.

Install the Bifrost Amp skills from GitHub:

```bash
amp skill add BrokkAi/bifrost/plugins/bifrost-agent/amp-skills --global --overwrite
```

Keep `--overwrite` when upgrading an existing installation so Amp replaces an
older skill bundle. The bundle pins its supported Bifrost release—currently
v0.8.9—and its launcher automatically prepares that exact binary in a managed
cache when necessary. Bifrost does not need to be preinstalled on `PATH`.

Confirm that Amp resolves the global skill, then run the launcher's readiness
check from the path reported by `amp skill info`:

```bash
amp skill info bifrost-code-intelligence
node /absolute/path/from-skill-info/bin/bifrost-launcher.mjs doctor
```

For the current bundle, the readiness output should include `status=ready` and
`required=0.8.9`. If the binary has not been prepared yet, replace `doctor`
with `prepare`, then run `doctor` again.

For local development, set `BIFROST_BINARY_PATH` to an absolute path to a
matching-version binary. Using a `bifrost` executable from `PATH` is opt-in:
set `BIFROST_LAUNCHER_ALLOW_PATH=1`.

## Validate the Setup

Start Amp from the repository root so `--root .` points at the intended workspace:

```bash
amp
```

Then ask Amp to use the skill and call a Bifrost tool:

```text
Use the bifrost-code-intelligence skill. Call the Bifrost get_summaries tool on src/analyzer/usages and summarize the package structure in five bullets.
```

Use a source directory or source file for validation. Avoid a prompt that only asks about `README.md`, because that can pass through ordinary file reading without proving the MCP server ran.

Apply the shared
[host-integration evidence contract](/mcp/#validate-host-integration): retain
the Bifrost tool event and structured result for a known workspace declaration,
verify its project-relative source path, and reject file-reading fallbacks.

## Can My Agent Run RQL?

The installed `bifrost-code-intelligence` skill starts MCP with `symbol|extended`, but its tools remain hidden until Amp loads that skill. After loading it, confirm that `query_code` is available. Ask Amp to call `query_code` with the inline JSON fields `{"match":{"kind":"declaration"},"limit":1}`. Then check a workspace file named `bifrost-smoke.rql` containing `(limit 1 (declaration))` and call `query_code` with `{"query_file":"bifrost-smoke.rql"}`.

The inline call is canonical JSON. MCP does not accept inline RQL text; saved RQL is loaded through `query_file`. Installing some other skill without an MCP definition exposes instructions, not Bifrost tools. See [MCP query and RQL availability](/mcp/#query-and-rql-availability) for the full surface matrix and [Agent Result Safety](/agent-result-safety/) before making completeness claims.

## Direct MCP Shape

Bifrost's raw MCP command is:

```bash
bifrost --root /path/to/project --mcp "symbol|extended"
```

The skill wrapper above keeps the Bifrost tools hidden until the skill is loaded.

Use `--mcp core` only when you intentionally want navigation without `query_code`.
