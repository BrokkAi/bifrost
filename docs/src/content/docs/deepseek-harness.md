---
title: DeepSeek Harness
description: Install and validate Bifrost in DeepSeek Harness (dsh).
---

DeepSeek Harness (`dsh`) uses Bifrost through its built-in MCP client bridge.
The `@brokkai/dsh-plugin-bifrost` bundle configures the bridge and ships the
Bifrost launcher, which downloads and checksum-verifies the pinned native
binary on first use; no manual binary installation is needed.

## Install

Add the bundle to a dsh profile:

```sh
dsh plugin --profile <name> add @brokkai/dsh-plugin-bifrost
```

Verify the bundle joined the profile's configuration:

```sh
dsh --profile <name> --dump-config | grep -A2 dsh-plugin-bifrost
```

Start dsh from the project you want analyzed:

```sh
cd /path/to/your/project
dsh --profile <name>
```

Bifrost tools appear to the model under the `mcp__bifrost__` prefix (for
example `mcp__bifrost__search_symbols`), serving the `symbol|extended`
toolsets by default.

## Workspace Root

The analyzer binds to a project root chosen in this order: the `root` config
value on the plugin row, then the `BIFROST_WORKSPACE_ROOT` environment
variable, then the directory dsh was started from. Start dsh from your project
directory, or pin `root` explicitly. The analyzer never binds the plugin
install directory.

## Configuration

Override defaults by giving the row a `config` block in your profile's
`cordis.patch.yml` (a patch replaces the row's entire `config` value):

```yaml
- id: bifrost
  name: '@brokkai/dsh-plugin-bifrost'
  config:
    root: /absolute/path/to/project
    toolsets: symbol|extended
    toolCallTimeoutMs: 240000
```

Recognized keys: `root`, `toolsets` (a Bifrost toolset expression), `serverName`
(default `bifrost`; changes the `mcp__<serverName>__` tool prefix),
`toolCallTimeoutMs` (default 240000, sized for first-call binary download and
analyzer warm-up), `env` (extra environment variables for the server
subprocess), and `failOnStartupError`.

dsh scrubs secrets-like variables (`*KEY*`, `*PASSWORD*`, `*SECRET*`,
`*TOKEN*`) and all `DSH_*` variables from server subprocess environments. Any
such variable Bifrost needs must be listed explicitly under `env`.

For local development from a checkout, point the launcher at a debug binary:

```yaml
- id: bifrost
  name: '@brokkai/dsh-plugin-bifrost'
  config:
    env:
      BIFROST_BINARY_PATH: /path/to/bifrost-checkout/target/debug/bifrost
```

## Validate the Setup

Start dsh from the configured workspace, then ask it to call a Bifrost tool:

```text
Call the Bifrost search_symbols tool for a type you know exists in this project and report the returned locations.
```

Use a source symbol for validation. Avoid a prompt that only asks about
`README.md`, because that can pass through ordinary file reading without
proving that the MCP server ran.

Apply the shared [host-integration evidence contract](/mcp/#validate-host-integration):
retain the Bifrost tool event and structured result for a known workspace,
verify its project-relative source path, and reject file-reading fallbacks.

## Can My Agent Run RQL?

The default configuration uses `symbol|extended`, so `query_code` is
available. Ask dsh to call `query_code` with the inline JSON fields
`{"match":{"kind":"declaration"},"limit":1}`. To validate saved RQL, create
`bifrost-smoke.rql` with `(limit 1 (declaration))`, then call `query_code`
with `{"query_file":"bifrost-smoke.rql"}`. See
[MCP query and RQL availability](/mcp/#query-and-rql-availability) for the
full surface matrix.

## Direct MCP Shape

To connect without the bundle, insert a raw MCP client row in your profile's
`cordis.patch.yml` against a `bifrost` binary you installed yourself (for
example from npm: `npm install -g @brokkai/bifrost`):

```yaml
- id: mcp-bifrost
  name: '@deepseek-ai/dsh-mcp-client'
  config:
    serverName: bifrost
    transport: stdio
    command: bifrost
    args: ['--root', '/absolute/path/to/project', '--mcp', 'symbol|extended']
```

The bundle path is preferred because it provisions and verifies the pinned
binary automatically and keeps the workspace-root rules above. Do not add a
raw row and the bundle to the same profile: duplicate `serverName` values fail
the later plugin instance at load.

## Uninstall

```sh
dsh plugin --profile <name> remove @brokkai/dsh-plugin-bifrost
```
