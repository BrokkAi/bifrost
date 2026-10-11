---
title: Pi
description: Install and validate the native Bifrost extension for Pi.
---

Pi can use Bifrost through the `@brokk/bifrost-agent` package. Unlike hosts that
load Bifrost through a generic MCP plugin manifest, Pi loads a native extension
from the package. The extension starts one Bifrost MCP child for the session
workspace and shuts it down when the session closes or reloads.

## Install From GitHub

The package is not currently published to the public npm registry. Clone
Bifrost and install the package directory as a local Pi package:

```bash
git clone https://github.com/BrokkAi/bifrost.git
cd bifrost/plugins/bifrost-agent
npm install
pi install "$(pwd)" --approve
pi list
```

`pi list` should show the absolute path to `plugins/bifrost-agent`. The
`--approve` flag explicitly trusts the local package files that Pi is about to
load.

Start Pi from the repository you want Bifrost to analyze. If Pi does not
already have a model provider configured, run `/login` in the interactive TUI
and complete the provider sign-in before validating Bifrost. Provider
authentication belongs to Pi and is separate from the Bifrost setup.

Reload Pi after installation. Run `/bifrost` in the interactive TUI to choose
the Bifrost capabilities for the current workspace. Pi saves the choice for
each workspace under its agent directory, in `bifrost/workspaces/`.

| Capability | Default | Bifrost tools | Toolsets started |
| --- | --- | --- | --- |
| Symbols | On | `search_symbols`, `get_symbol_sources`, `get_summaries`, `rename_symbol`, `usage_graph`, `analyze_diff`, and either the location tools (`scan_usages_by_location`, `get_definitions_by_location`, `get_type_by_location`) or the reference tools (`scan_usages_by_reference`, `get_definitions_by_reference`) | `symbol`, `diff`, `slopcop` |
| Structural queries | On | `query_code`, `get_symbol_locations`, `get_symbol_ancestors` | `extended` |
| File discovery | On | `most_relevant_files` | `extended` |
| Policies | On | `list_policies`, `run_policy` | `extended` |
| Code quality | Off | The eleven `slopcop` report tools | `slopcop` |
| Text search | Off | `get_file_contents`, `search_file_contents`, `find_files_containing` | `text` |

The extension starts one Bifrost MCP server with the union of the toolsets,
in the order `symbol|extended|diff|slopcop|text`. With the default selection,
that is `symbol|extended|diff|slopcop`. It exposes to Pi only the tools of the
selected capabilities.

To update an existing checkout to the package version on the current branch,
pull the checkout, rerun `npm install` and `pi install "$(pwd)" --approve` from
`plugins/bifrost-agent`, then start a new Pi session.

The package uses the same pinned, checksum-verified Bifrost release launcher as
the other agent plugins. It can download that binary into a user cache on first
use. See [Data and Trust Boundaries](/data-boundaries/#plugin-launcher-downloads-and-cache)
for the resolution order, cache locations, and controls for automatic downloads.

The package also gives Pi four skills: `bifrost-code-navigation`,
`bifrost-code-reading`, `bifrost-codebase-search`, and
`bifrost-policy-checking`. See
[Packaged agent plugin](/mcp/#packaged-agent-plugin) for what each one covers.

## Tool Names And Workspace Scope

Pi-visible tools use a `bifrost_` prefix. For example, Bifrost's canonical
`get_summaries` and `query_code` tools appear as `bifrost_get_summaries` and
`bifrost_query_code`. The extension keeps Bifrost's canonical tool names behind
the `bifrost_` namespace.

The extension scopes its Bifrost child to Pi's explicit session workspace. It
does not analyze the installed package directory and does not expose Bifrost's
workspace-switching tools, because Pi owns the session workspace.

The extension also reads Bifrost's standard MCP server instructions. It adds them to Pi's model prompt before the namespace and workspace note.

This gives Pi the same routing guidance as generic MCP hosts. The extension sanitizes the text and limits it to 2,000 characters.

## Validate The Setup

Start a fresh Pi session in the repository you want to analyze, then ask it to
call `bifrost_get_summaries` for a source file or directory. Use a source
target rather than a README so the result proves that Bifrost ran instead of
ordinary file reading.

Apply the shared
[host-integration evidence contract](/mcp/#validate-host-integration): retain
the `bifrost_` tool event and structured result, verify the result belongs to
Pi's active workspace, and reject paths under the installed package.

To confirm structural-query access, ask Pi to call `bifrost_query_code` with
the inline canonical JSON fields:

```json
{"match":{"kind":"declaration"},"limit":1}
```

To validate saved RQL, add a workspace file named `bifrost-smoke.rql`:

```lisp
(limit 1 (declaration))
```

Then call `bifrost_query_code` with exactly:

```json
{"query_file":"bifrost-smoke.rql"}
```

Inline query input is canonical JSON, not RQL. RQL is accepted from a
workspace-relative file through `query_file`. See
[MCP query and RQL availability](/mcp/#query-and-rql-availability) for the full
surface matrix and [Agent Result Safety](/agent-result-safety/) before making
completeness claims.

## Local Binary Testing

To use the checkout's Rust binary instead of the pinned release, build Bifrost
from the repository root and launch Pi with the package as a local extension:

```bash
cargo build --bin bifrost
cd plugins/bifrost-agent
BIFROST_BINARY_PATH="$(cd ../.. && pwd)/target/debug/bifrost" pi -e "$(pwd)"
```
