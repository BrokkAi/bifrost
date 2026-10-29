---
title: Environment Variables
description: Every environment variable that the bifrost binary, MCP server, policy runner, semantic-pack loader, agent plugins, bifrost-lsp, and install script read.
---

This page lists every environment variable that changes what Bifrost does.
Each entry gives the accepted values, the default, the effect, and what happens
when the value is invalid. Variables that exist only for benchmarks,
differential testing, fuzzing, profiling of Bifrost itself, or Bifrost's own
test suite are not listed.

Most variables on this page are read by the `bifrost` binary. The sections
[Agent Plugins](#agent-plugins), [Language Server](#language-server), and
[Install Script](#install-script) list variables that other programs read.

No command-line flag has an environment-variable equivalent. For flags, see
[CLI Reference](/reference/cli/).

## Analysis

| Variable | Values | Default | Effect | Invalid value |
| --- | --- | --- | --- | --- |
| `BIFROST_PARALLELISM` | Positive integer | Number of logical CPUs | Size of the analyzer worker pools in the CLI, MCP server, and libraries. | `0` or a non-integer is ignored, and the default applies. |
| `BIFROST_POLICY_PARALLELISM` | Positive integer | The analyzer pool width (`BIFROST_PARALLELISM`, otherwise the number of logical CPUs), at most `8` | Number of policies the policy coordinator evaluates concurrently, for `scan` and the MCP policy tools. Above eight workers, measured cold scans got no faster and used more CPU and memory, because the longest single policy sets the floor. A larger value is useful only for many short policies on a wide host. A smaller value lowers peak memory, and `1` forces strictly serial evaluation. | `0` or a non-integer is ignored, and the default applies. |
| `BIFROST_MAX_LINE_LENGTH` | Non-negative integer | `16000` | An explicit positive value rejects source files with longer physical lines. At the default setting, C/C++, Python, JavaScript and TypeScript analysis can exclude bounded literal data from line accounting; see [Workspace Scope](/workspace-scope/). `0` turns the line limit off. NUL bytes prevent parsing unless the parser proves they are string, comment or text payload; see [Workspace Scope](/workspace-scope/). Rune IR counts full physical lines and refuses over-limit input with an error. | A non-integer is ignored, and the default applies. |
| `BIFROST_CHA_CONCRETE_OVERRIDES` | Any value | Not set | When set, a call that resolves to a method with a body also lists the workspace methods that override it, as `unproven` candidates. Without it, Bifrost lists overrides only for a call to a method with no body, such as an interface or abstract method. The process reads the variable once. | Not possible; any value means on. |
| `BIFROST_TIMING` | Any value; empty, `0`, `false`, and `off` (any case) mean off | Off | Write `[bifrost-timing]` timing lines to stderr. When a query stops at an execution limit, also write its work counters, such as scanned files and fact nodes, to stderr. | Not possible; any other value means on. |

## Cache and Storage

The cache layout is described in [Data and Trust Boundaries](/data-boundaries/)
and [Configuration Files](/reference/configuration-files/).

| Variable | Values | Default | Effect | Invalid value |
| --- | --- | --- | --- | --- |
| `BIFROST_CACHE_DIR` | Directory | Not set | Use exactly this directory for the analyzer database `bifrost_cache.v<N>.db` and the semantic-pack catalog. Every repository that a process opens uses the same directory. Takes precedence over `BIFROST_CACHE_ROOT` for the repository cache. | An empty value is treated as not set. An unwritable directory is an error when the cache opens. |
| `BIFROST_CACHE_ROOT` | Directory | Not set | Relocate every Bifrost cache to one machine-local root. Each primary repository gets the child `<repository-name>-<hash>/`. The machine-level cache also moves to this root. | An empty value is treated as not set. |
| `BIFROST_ALLOW_UNSAFE_NETWORK_CACHE` | `1` | Not set | On Linux, allow the SQLite cache on NFS or SMB. Without it, Bifrost refuses to create the cache there. | Any other value is the same as not set. |
| `BIFROST_CACHE_GC` | `0`, `off`, or `disabled` turn it off | On | Turn off automatic collection of unreachable data in the analyzer cache. Use it for a cache that several repositories share on purpose. | Any other value leaves collection on. |
| `BIFROST_SQLITE_WRITER_CACHE_KIB` | Positive integer, in KiB, up to 2147483647 | `524288` (512 MiB) | Upper limit of the SQLite page cache for each connection to the analyzer database. Lower it to reduce memory use. | Opening the analyzer database fails with an error that names the variable. |
| `BIFROST_SEMANTIC_PACK_CACHE_ROOT` | Directory | Not set | Keep the semantic-pack catalog at `<value>/semantic-pack-catalog.v<N>` instead of beside the analyzer database. When set, generated packs are not shared through the machine-level cache. The binary's open-pack bootstrap supplies a cache-local default only when this variable is unset. | An empty value is treated as not set. |

## MCP Server and Tool Sessions

The first four variables apply to `bifrost --mcp` and to the no-argument
server. See [MCP Tools Reference](/reference/mcp-tools/) for the limits they
change.

The last three variables are read each time a tool session activates
semantic packs for a workspace. That happens in the MCP server, `--tool`,
`--query-file`, and `--repl`. See
[Semantic Packs Reference](/reference/semantic-packs/).

| Variable | Values | Default | Effect | Invalid value |
| --- | --- | --- | --- | --- |
| `BIFROST_MCP_REQUEST_BUDGET_SECS` | Positive integer number of seconds | Not set: 60 s for most tools, 240 s for `run_policy`, 4.5 s for most tools while the workspace is still building, and no budget for `refresh`, `activate_workspace`, `update_paths`, and `get_active_workspace` | One time budget for every analyzer request. | The server does not start; exit 1. |
| `BIFROST_MCP_TASK_TTL_MS` | Integer of 1 or more, in milliseconds | `600000` (10 minutes) | Lifetime and execution deadline of an MCP task for `run_policy`. | Ignored with a warning on stderr; the default applies. |
| `BIFROST_MCP_FILE_WATCHER` | `on` or `off` | `on` | `off` stops the server from watching workspace files. Call the `refresh` tool after edits. | The server does not start; exit 1. |
| `BIFROST_MCP_LOG` | `off`, `error`, `warn`, `info`, `debug`, or `trace` | `warn` | Level of MCP protocol diagnostics written to stderr. | The server does not start; exit 1. |
| `BIFROST_WORKSPACE_SEMANTIC_MODELS` | `on`, `1`, `enabled`, `off`, `0`, or `disabled` | Off | Load reviewed workspace models from `.bifrost/semantic-models/` when a workspace binds. | Semantic-pack activation is unavailable for the session, with a message on stderr. |
| `BIFROST_SEMANTIC_PACK_CATALOG` | Directory of a semantic-pack catalog | Not set | Activate packs from this catalog, using the evidence in `BIFROST_SEMANTIC_PACK_EVIDENCE`. Must be set together with that variable. Bifrost opens the catalog read-only. This older configuration cannot be combined with a workspace `.bifrost/packs.json`. | Semantic-pack activation is unavailable for the session, with a message on stderr. |
| `BIFROST_SEMANTIC_PACK_EVIDENCE` | Non-empty JSON array of evidence objects | Not set | Activation evidence for `BIFROST_SEMANTIC_PACK_CATALOG`. Each object has `language` and `ecosystem` (strings), optional `package`, `module`, and `toolchain` (each `{"name": ..., "version": ...}`, version optional), and optional `target`, `configuration`, and `artifactSha256` strings. Unknown fields are rejected. | Semantic-pack activation is unavailable for the session, with a message on stderr. An empty array is invalid. |

## Policies and Semantic Packs

| Variable | Values | Default | Effect | Invalid value |
| --- | --- | --- | --- | --- |
| `BIFROST_POLICY_PACK_ROOT` | Directory of an extracted policy rules tree, or several such directories as an OS path list (`:`-separated on Unix, `;` on Windows) | Not set | Replace the embedded built-in policy catalog for `--list-policies`, `--version`, `scan`, policy evaluation, and the MCP policy tools. Several roots, such as separately acquired public and premium releases, load as one catalog; a pack or policy ID that appears in two roots is an error. Manifests and authored hashes are verified. The former name `BIFROST_OPEN_POLICY_PACK_ROOT` is still read until v0.15.0; if both are set they must name the same roots. `prepare-open-packs` still writes the former name to its environment file until then. See [Policies Reference](/reference/policies/). | An empty value, an empty list entry, two names that disagree, a missing directory, or an invalid tree is an error: `scan` and policy runs exit 2, and `--version` exits 1. |
| `BIFROST_POLICY_BUNDLE_ROOT` | Directory of an extracted policy bundle (a `policy-bundle.json` index and its `.rqlp` files), or several as an OS path list | Not set | Make each bundle policy available to explicit selection by ID (`--policy-id`, or `policy_ids` in the MCP policy tools). Bundle policies never run through default, pack, category, or `scan` selection, and carry no catalog metadata. Every indexed file must match its SHA-256 and size, and each policy's index ID must equal its document `:id`. A bundle ID that the catalog also defines is an error. | An empty list entry, an unreadable bundle, or a verification failure is an error: policy runs exit 2. |
| `BIFROST_OPEN_SEMANTIC_PACK_BUNDLE` | Directory of a native semantic-pack bundle | Not set | Install the bundle's packs instead of the packs embedded in the binary. The bundle replaces the embedded packs; it is not merged with them. See [Semantic Packs Reference](/reference/semantic-packs/). | An empty value, an unreadable bundle, or a bundle with no compatible pack makes pack activation fail. A policy report shows `pack-activation-failed` and the run exits 2. |
| `BIFROST_OPEN_PACKS_OFFLINE` | `1` or `true` | Not set | Make the `bifrost` binary select open packs from its verified local cache only. If selection cannot be satisfied, it reports a diagnostic and uses embedded packs. | Any other value is the same as not set. |
| `BIFROST_OPEN_PACKS_DISABLE` | `1` or `true` | Not set | Disable open-pack acquisition. Commands make no network requests and do not read the open-pack cache. Explicit `BIFROST_POLICY_PACK_ROOT` and `BIFROST_OPEN_SEMANTIC_PACK_BUNDLE` values are still used; without them, commands use embedded packs. `prepare-open-packs` writes a failed outcome with class `invalid-configuration` and exits 1 without reading its cache. | Any other value is the same as not set. |
| `BIFROST_OPEN_PACKS_REFRESH` | `1` or `true` | Not set | Ignore the cached open-pack manifest inventory and discover releases again. The inventory is otherwise reused for one hour. Cannot be combined with offline mode. | Any other value is the same as not set. |

## Output

| Variable | Values | Default | Effect | Invalid value |
| --- | --- | --- | --- | --- |
| `NO_COLOR` | Any value | Not set | When set, `--color auto` produces plain human policy output. | Not applicable. |

## System Variables That Bifrost Reads

Bifrost reads these standard variables. It does not change them.

| Variable | Read by | Effect |
| --- | --- | --- |
| `HOME` (`USERPROFILE` on Windows) | Cache, JVM and .NET discovery, REPL, `--install`, `~/` in Git paths | Locates `~/.cache/bifrost`, `~/Library/Caches/bifrost`, `~/.m2/repository`, `~/.gradle/caches`, `~/.nuget/packages`, and `~/.bifrost_code_query_repl_history`. |
| `XDG_CACHE_HOME` | Machine-level cache on Linux and other Unix systems | Machine-level cache is `$XDG_CACHE_HOME/bifrost` when set. |
| `LOCALAPPDATA` | Machine-level cache on Windows | Machine-level cache is `%LOCALAPPDATA%\bifrost\cache`. |
| `JAVA_HOME` | JVM standard-library discovery | The JDK at `JAVA_HOME` is a candidate source of JDK declarations. It does not bind a JDK to source files; `.bifrost/jvm-toolchains.json` does that. |
| `GRADLE_USER_HOME` | JVM dependency discovery | Gradle module cache is `$GRADLE_USER_HOME/caches/modules-2/files-2.1` instead of `~/.gradle/caches/modules-2/files-2.1`. |
| `NUGET_PACKAGES` | C# dependency discovery | An additional approved NuGet package root. |
| `PATH`, `PATHEXT` | `--install`; `git` subprocesses | Find coding-host commands and the `git` executable. |
| `XDG_CONFIG_HOME`, `APPDATA` | `--install` for OpenCode | Locate `opencode/opencode.json`. |
| `PATH`, `HOME`, `USERPROFILE`, `LOCALAPPDATA`, `GOCACHE`, `TMPDIR`, `TEMP`, `TMP`, `SYSTEMROOT`, `WINDIR` | Go dependency discovery in a CLI policy run | Passed to the `go list` subprocess. Bifrost removes every other variable, including `GOPATH`, `GOMODCACHE`, and `GOFLAGS`, and sets `GOTOOLCHAIN=local`, `GOPROXY=off`, `GOSUMDB=off`, `GOENV=off`, `GOFLAGS=-buildvcs=false`, and `CGO_ENABLED=0`. `go list` therefore uses the default module cache under `HOME`. |

## Agent Plugins

The agent and dsh plugins ship the same launcher, which manages the `bifrost`
executable. The binary also honors `BIFROST_LAUNCHER_AUTO_INSTALL` as a
cache-only control and uses `BIFROST_LAUNCHER_CACHE_DIR` as the base for its
open-pack cache, including when started directly.

| Variable | Values | Default | Effect |
| --- | --- | --- | --- |
| `BIFROST_WORKSPACE_ROOT` | Directory | Not set | Workspace root for an MCP launch. The launcher passes it to `bifrost` as `--root`. It takes precedence over the launcher's `--root` or `--workspace-root` argument. A value that still contains an unexpanded placeholder such as `${...}` is ignored. The dsh plugin also reads it, when the plugin configuration sets no `root`. |
| `BIFROST_BINARY_PATH` | Path to a `bifrost` executable | Not set | Use this binary when its version is compatible with the plugin. |
| `BIFROST_LAUNCHER_ALLOW_PATH` | `1` or `true` (any case) | Not set | Allow a compatible `bifrost` found on `PATH`. |
| `BIFROST_LAUNCHER_AUTO_INSTALL` | `0` | Not set (downloads allowed) | `0` disables managed binary downloads in the launcher and makes pack-activating binary commands use only their verified open-pack cache. |
| `BIFROST_LAUNCHER_CACHE_DIR` | Directory | `~/Library/Caches/bifrost-agent` on macOS, `%LOCALAPPDATA%\Bifrost\AgentPlugin` on Windows, `$XDG_CACHE_HOME/bifrost-agent` or `~/.cache/bifrost-agent` elsewhere | Root for managed binaries and the binary's `open-pack-releases/` cache. |

The `bifrost` binary selects open packs before policy or MCP activation. Setting
either `BIFROST_OPEN_SEMANTIC_PACK_BUNDLE` or
`BIFROST_POLICY_PACK_ROOT` (or its former name) supplies host-owned content and prevents
automatic acquisition. If neither is set, the binary supplies both roots from
its verified cache; it does not overwrite an explicit
`BIFROST_SEMANTIC_PACK_CACHE_ROOT`.

## Language Server

The separate `bifrost-lsp` program reads these variables. The `bifrost`
binary does not. The VS Code extension sets them from its settings. See
[LSP Server](/lsp/).

| Variable | Effect |
| --- | --- |
| `BIFROST_LSP_DEBUG` | `1` logs the start and end of every LSP request and notification. |
| `BIFROST_LSP_SLOW_MS` | Logs LSP requests and notifications that take at least this many milliseconds. |

## Install Script

`install.sh` reads these variables. See [Install Bifrost](/install/#install-script).

| Variable | Values | Default | Effect |
| --- | --- | --- | --- |
| `BIFROST_INSTALL_DIR` | Directory | Not set | Install directory. Takes precedence over `INSTALL_DIR`. |
| `INSTALL_DIR` | Directory | `~/.local/bin` | Install directory. |
| `BIFROST_VERSION` | Release tag, for example `v0.8.17` | Latest release | Release to install. |
| `BIFROST_GITHUB_OWNER` | GitHub owner | `BrokkAi` | Owner of the release repository. |
| `GITHUB_TOKEN` | Token | Not set | Sent to the GitHub API to raise rate limits. |
| `PROFILE` | Shell profile path | Detected from the shell | Profile to update when the install directory is not on `PATH`. |
