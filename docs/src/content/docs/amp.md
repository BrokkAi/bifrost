---
title: Amp
description: Use Bifrost MCP tools from Amp.
---

Amp can use Bifrost as an MCP server. The recommended Amp pattern is to bundle MCP servers inside a skill so the tools stay hidden until the skill is loaded.

Install the Bifrost Amp skills from GitHub:

```bash
amp skill add BrokkAi/bifrost/plugins/bifrost-agent/amp-skills --global --overwrite
```

Bifrost must be available on `PATH` for the skill's MCP server to start. For local testing, install Bifrost with Cargo or use an absolute binary path in your local skill copy.

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

## Direct MCP Shape

Bifrost's raw MCP command is:

```bash
bifrost --root /path/to/project --mcp core
```

The skill wrapper above keeps the Bifrost tools hidden until the skill is loaded.
