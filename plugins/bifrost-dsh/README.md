# Bifrost for DeepSeek Harness

`@brokkai/dsh-plugin-bifrost` is a [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)
bundle that gives dsh sessions Bifrost code intelligence over MCP. It ships the
shared Bifrost launcher, which downloads and checksum-verifies the pinned
native `bifrost` binary on first use; no manual binary installation is needed.

Bifrost tools appear to the model as `mcp__bifrost__<tool>` (for example
`mcp__bifrost__search_symbols`), serving the `symbol|extended` toolsets by
default.

## Install

```sh
dsh plugin --profile <name> add @brokkai/dsh-plugin-bifrost
```

Verify the bundle joined the profile:

```sh
dsh --profile <name> --dump-config | grep -A2 dsh-plugin-bifrost
```

Then start dsh from your project directory:

```sh
cd /path/to/your/project
dsh --profile <name>
```

## Workspace root

The analyzer binds to a project root chosen in this order:

1. The `root` config value on the plugin row.
2. The `BIFROST_WORKSPACE_ROOT` environment variable.
3. The working directory dsh was started from.

Start dsh from the project you want analyzed, or pin `root` explicitly.

## Configuration

Override defaults by giving the plugin row a `config` block in your profile's
`cordis.patch.yml` (later layers win per row, and a patch replaces the row's
entire `config` value):

```yaml
- id: bifrost
  name: '@brokkai/dsh-plugin-bifrost'
  config:
    root: /absolute/path/to/project
    toolsets: symbol|extended
    toolCallTimeoutMs: 240000
    env:
      BIFROST_BINARY_PATH: /usr/local/bin/bifrost
```

Recognized keys: `root`, `toolsets` (a Bifrost toolset expression such as
`symbol|extended` or `core`), `serverName` (default `bifrost`; changes the
`mcp__<serverName>__` tool prefix), `toolCallTimeoutMs` (default 240000, sized
for first-call binary download and analyzer warm-up), `env` (extra environment
variables for the server subprocess), and `failOnStartupError`.

Note: dsh scrubs secrets-like variables (`*KEY*`, `*PASSWORD*`, `*SECRET*`,
`*TOKEN*`) and all `DSH_*` variables from server subprocess environments. Any
such variable Bifrost needs must be set explicitly under `env`.

## Uninstall

```sh
dsh plugin --profile <name> remove @brokkai/dsh-plugin-bifrost
```

## Development

The launcher (`bin/bifrost-launcher.mjs`) and release manifest
(`bifrost-release.json`) are vendored copies of the canonical files in
`plugins/bifrost-agent`; run `npm run sync-launcher` after changing the
originals. `npm test` runs the offline test suite, including a byte-identity
check of the vendored copies.
