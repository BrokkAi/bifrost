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
pi install "$(pwd)"
```

Reload Pi after installation. Run `/bifrost` in the interactive TUI to choose
the Bifrost capabilities for the current workspace. The default selection
enables symbol navigation, structural queries, and file discovery and ranking.
Additional selections expose code-quality reports, Git history, raw text
search, or JSON and XML transforms.

The package uses the same pinned, checksum-verified Bifrost release launcher as
the other agent plugins. It can download that binary into a user cache on first
use. See [Data and Trust Boundaries](/data-boundaries/#plugin-launcher-downloads-and-cache)
for the resolution order, cache locations, and controls for automatic downloads.

## Tool Names And Workspace Scope

Pi-visible tools use a `bifrost_` prefix. For example, Bifrost's canonical
`get_summaries` and `query_code` tools appear as `bifrost_get_summaries` and
`bifrost_query_code`. The bundled code-navigation, code-reading, and
codebase-search skills keep their canonical names.

The extension scopes its Bifrost child to Pi's explicit session workspace. It
does not analyze the installed package directory and does not expose Bifrost's
workspace-switching tools, because Pi owns the session workspace.

## Validate The Setup

Start Pi in the repository you want to analyze, then ask it to call
`bifrost_get_summaries` for a source file or directory. Use a source target
rather than a README so the result proves that Bifrost ran instead of ordinary
file reading.

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
