---
title: Data and Trust Boundaries
description: Know what Bifrost reads, stores, downloads, executes, and returns to agent hosts.
---

Bifrost analyzes source on the machine where its process runs. An MCP host
receives Bifrost's tool results, and the host may send returned snippets,
paths, symbols, or diagnostics to its model provider. Review the data policy of
the host and of the model provider separately.

## Network Access and Telemetry

The `bifrost` CLI, MCP server, Python client, and Rust libraries send no
telemetry. During startup, the binary may contact GitHub to acquire verified
open packs for policy scans and MCP commands. Code analysis and Git operations
do not contact network services.

Network access happens only in these places:

- The agent-plugin launcher downloads a checksum-pinned Bifrost release, and
  the Bifrost binary downloads verified open-pack releases when needed. See
  [Plugin Launcher Downloads and Cache](#plugin-launcher-downloads-and-cache).
- The install script, npm, PyPI, Homebrew, and Cargo download Bifrost when you
  install it. See [Install Bifrost](/install/).
- The VS Code extension, which is not part of the `bifrost` binary, downloads
  its language server. The published version 0.11.5 downloads Bifrost 0.11.5.
  Later versions download the separate `bifrost-lsp` program. See
  [VS Code LSP](/vscode/) and [LSP Server](/lsp/).

## Boundary Map

| Component | Reads or receives | Writes, sends, or runs |
| --- | --- | --- |
| Bifrost analyzer, CLI, and MCP server | Files in the workspace inventory; the local Git repository; the dependency locations listed under [Reads Outside the Workspace](#reads-outside-the-workspace) | Results to stdout or stdio MCP; the repository cache and the machine-level cache; the subprocesses listed under [Subprocesses](#subprocesses) |
| Agent MCP host | Bifrost tool schemas and results, which can include source excerpts | May include those results in model requests, logs, transcripts, or host caches, depending on host configuration |
| Agent-plugin launcher | Pinned binary release metadata and environment or argument overrides | Downloads checksum-verified Bifrost releases into a user cache |
| Bifrost binary | Open-pack release metadata, workspace inputs, and environment overrides | Downloads and verifies compatible open semantic and policy packs during pack-activating commands |

## Workspace Scope

The process root is set by `--root`, by the packaged launcher's
`BIFROST_WORKSPACE_ROOT` override, by the MCP client's roots response, or by a
negotiated `codex/sandbox-state-meta` value. Without an explicit override, the
packaged launcher starts Bifrost without a workspace. A client that supports
roots supplies the first usable local filesystem root in its ordered response.
On a connection without roots, Bifrost offers the sandbox-state extension;
current Codex uses it to supply the active task directory on every analyzer
tool call. Bifrost does not take the workspace from the launcher's current
directory, because plugin hosts may start the launcher in the installed
package directory. A client that supports neither contract leaves the server
without a workspace. Confirm the effective root before you trust a query or
give an agent session access to a repository.

Workspace-relative query files cannot escape the configured root. Results can
still contain source excerpts from indexed files inside that root. Path filters
narrow an individual request; they do not limit what the process can read. See
[Workspace Scope](/workspace-scope/) for which files are in the workspace.

## Reads Outside the Workspace

To model dependencies, the analyzer reads these locations outside the
workspace. It only reads them; it never writes to them.

| Location | When |
| --- | --- |
| The JDK at `JAVA_HOME`, and JDKs named in `.bifrost/jvm-toolchains.json` | Java, Kotlin, and Scala workspaces, by default |
| `~/.m2/repository` | JVM workspaces, for coordinates found in Maven or Gradle build files, by default |
| `$GRADLE_USER_HOME/caches/modules-2/files-2.1`, or `~/.gradle/caches/modules-2/files-2.1` | JVM workspaces, for coordinates found in build files, by default |
| `$NUGET_PACKAGES` and `~/.nuget/packages` | C# workspaces whose restore output names packages there |
| Python standard library and site-packages directories | Only when `.bifrost/packs.json` configures a Python runtime environment |
| Go module metadata through `go list` | A CLI policy run in a Go workspace; see [Subprocesses](#subprocesses) |
| Semantic-pack bundles and policy roots named by `BIFROST_OPEN_SEMANTIC_PACK_BUNDLE` and `BIFROST_POLICY_PACK_ROOT` | When those variables are set |

## Subprocesses

| Program | When | Notes |
| --- | --- | --- |
| `git` | Building the workspace inventory, file status, history ranking (`most_relevant_files`), and `--diff-base` exports | Runs local commands such as `status`, `rev-list`, and `cat-file`. Bifrost sets `GIT_OPTIONAL_LOCKS=0` so that it does not take Git's optional index lock. |
| `mvn`, `gradle` | Only when an embedding selects offline build-tool JVM dependency discovery | Run with `--offline`. The default discovery mode reads build metadata and does not run them. |
| `go` | A CLI policy run (`bifrost scan` or the policy flags) in a Go workspace, to find the exact module versions that select compatible semantic packs | Runs `go list` with `-mod=readonly` (or `-mod=vendor` for a vendored module), `GOPROXY=off`, `GOTOOLCHAIN=local`, and `GOFLAGS=-buildvcs=false` in a cleared environment, so it does not download modules or toolchains. Other modes run `go` only when an embedding turns on Go dependency discovery. |
| Coding-host CLIs (`codex`, `claude`, `opencode2`, `kimi`, `hermes`, `omp`) | Only during `bifrost --install` | Registers the `brokk` MCP server. |

## Persistent Repository Cache

Analyzer facts are stored in `.bifrost/cache/bifrost_cache.v<N>.db` at the
primary Git repository root, where `<N>` is the cache schema version the
running build reads. Every entry point uses that one location: an explicit
`--root` process, an MCP process bound through client roots, and one bound
through Codex sandbox metadata all reach the same database. Every linked
worktree of a checkout shares the primary's content-addressed cache. A
workspace outside any repository keeps the cache under its own root. Cache
files written by older releases can also contain inactive tables from features
that no longer exist.

When the primary checkout is on a network filesystem, set `BIFROST_CACHE_ROOT`
to a machine-local directory. Bifrost then uses a stable
`<repository-name>-<path-hash>/` child of that directory. Linked worktrees still
share one database, and unrelated repositories do not compete for one SQLite
writer. The file name includes the schema version, so checkouts on different
Bifrost versions can share the directory without sharing a file. Each build
opens only its own file, seeds it once by copying the newest older store it can
migrate, and never writes the older file. Collection preserves the running
build's store and chooses at most one other versioned store by most recent use.
It removes extra stores regardless of age and removes the retained other store
after two weeks without use. A busy store stays until a later collection.
Results stay scoped to the bound root: the cache
is keyed by content, and answers are resolved against the bound worktree's
current blob object IDs. The cache is derived from workspace source and Git
objects. Protect and retain it with the same policy as the repository.

A process that cannot write the primary repository root fails with an error
that says so. On Linux, Bifrost refuses to create its SQLite WAL cache on NFS
or SMB, because their locking does not meet SQLite's WAL requirements.
`BIFROST_ALLOW_UNSAFE_NETWORK_CACHE=1` overrides this check at your own risk.
In a sandboxed shell, approve the local write the same way you approve a
sandboxed `git commit` that writes `.git`. Use `BIFROST_CACHE_ROOT` to move the
cache permanently. Set `BIFROST_CACHE_DIR` only when you need one exact
directory; the database is then `$BIFROST_CACHE_DIR/bifrost_cache.v<N>.db`, and
unrelated repositories that one process opens share that SQLite writer.

Only `.bifrost/cache/` and `.bifrost/suppressions.local.json` are local working
state. The other files under `.bifrost/` are project inputs that you review and
commit: `policies/`, `packs.json`, `semantic-models/`,
`jvm-toolchains.json`, `policy-scope.json`, `baseline.json`,
`suppressions.json`, and `suppressions.private.json`. Commit
`suppressions.private.json`, but do not publish it with an open-source release.
An ignore rule for the whole `.bifrost/` directory hides these inputs; replace it
with rules for `.bifrost/cache/` and `.bifrost/suppressions.local.json`. See
[Configuration Files](/reference/configuration-files/).

Older releases used `.bifrost/bifrost_cache.db`. Bifrost keeps that database
and its SQLite sidecar files in place, so it cannot delete files that an older
process is still using. An exact generated ignore rule for the whole directory
is narrowed automatically to those legacy file names. After every older
Bifrost process has stopped, you may delete `.bifrost/bifrost_cache.db` and its
`-wal`, `-shm`, and `-journal` files. The current cache under `.bifrost/cache/`
does not depend on them.

Deleting the database while Bifrost is stopped forces later work to rebuild it.
A running process can also hold source and analysis state in memory. If a test
needs a clean cache, stop Bifrost first and record the removal in the
evaluation method.

## Machine-Level Cache

Bifrost also keeps state that no single repository owns in a per-user cache.
By default it is `~/.cache/bifrost` on Linux, `~/Library/Caches/bifrost` on
macOS, and `%LOCALAPPDATA%\bifrost\cache` on Windows. See
[Configuration Files](/reference/configuration-files/) for the exact rules. It
contains:

- `generated-semantic-packs.v<N>/`: semantic packs that Bifrost generated from
  exact local dependency artifacts. Other repositories on the same machine
  reuse them. Packs unused for seven days are removed.
- `multiroot/<first-root-name>-<digest>/`: analyzer databases for multi-root
  workspaces that the Rust library creates.

`BIFROST_CACHE_ROOT` moves this cache. `BIFROST_SEMANTIC_PACK_CACHE_ROOT`
stops generated packs from being shared through it. The generated packs are
derived from dependency code, and the multi-root databases are derived from
workspace source, so treat this cache as repository-sensitive.

`bifrost --repl` also keeps its command history in
`~/.bifrost_code_query_repl_history`.

## Plugin Launcher Downloads and Cache

The agent plugin does not bundle the Bifrost executable. Release metadata names
a preferred, checksum-pinned binary and the minimum compatible binary in that
minor series. Stable patch releases in the range keep the existing MCP
contract: they may add tools or optional fields, but they do not remove tools
or change existing meanings. A breaking plugin-facing change requires a new
minor release, and skills that require a newer tool raise the declared minimum.

All Portable Agent Plugins v1/Codex, Claude Code, Cursor, Pi, and Amp adapters
use the same launcher for MCP. The Claude Code plugin also starts its LSP entry
through the launcher; that works only with Bifrost releases that still serve
LSP (see [LSP Server](/lsp/)). The launcher resolves the binary in this order:

1. `BIFROST_BINARY_PATH`, when it is set and the binary is compatible;
2. the exact preferred binary in the launcher cache;
3. the newest compatible cached patch release, chosen by version rather than
   directory order;
4. a compatible `bifrost` on `PATH`, only when `BIFROST_LAUNCHER_ALLOW_PATH=1`;
5. the exact preferred GitHub release, whose archive and checksum file are
   verified against pinned SHA-256 metadata.

Different major or minor versions are rejected. Prerelease versions are also
rejected unless the release metadata permits them. The launcher never downloads
an unpinned compatible fallback.

When the launcher starts a compatible fallback, it does not delay MCP
registration. If automatic installation is on, it starts a detached helper that
downloads and verifies only the checksum-pinned preferred release into the
cache. The running server stays on the compatible binary and keeps its
negotiated capabilities. A new host task selects the prepared preferred binary
and negotiates its current tool surface.

For policy scans and MCP commands, the Bifrost binary selects open semantic
packs and policy packs that match its
in-process engine profile during pack-activating commands. It downloads them
from the [BrokkAi/bifrost-packs](https://github.com/BrokkAi/bifrost-packs)
GitHub releases, verifies them, and caches them under `open-pack-releases/` in
the configured launcher cache. The release list is reused for one hour.
`BIFROST_OPEN_PACKS_OFFLINE=1` uses only cached packs, and
`BIFROST_OPEN_PACKS_REFRESH=1` ignores the cached release list. When no
compatible open packs are available, Bifrost runs with the packs built into
the binary.

Managed binaries and open packs share the launcher cache location. The
default root is `~/Library/Caches/bifrost-agent` on macOS,
`%LOCALAPPDATA%\Bifrost\AgentPlugin` on Windows, and
`$XDG_CACHE_HOME/bifrost-agent` or `~/.cache/bifrost-agent` on Linux. Set
`BIFROST_LAUNCHER_CACHE_DIR` to move it, or `BIFROST_LAUNCHER_AUTO_INSTALL=0`
to prohibit all launcher downloads. See
[Environment Variables](/reference/environment/).

Run the launcher's `doctor` command to see the preferred and selected
versions, the source, the compatibility mode, and the cache path. It does not
change the cache or download anything. It runs the selected binary with
`--version`, so inspect only trusted binary locations. Run `prepare` to perform
the same resolution and download before you start an MCP host. Both commands
accept `--json`. If preparation changes the available binary, start a new host
task so that the MCP tool list is negotiated again.

## Deployment Checklist

- Pin and verify the effective Bifrost binary and workspace root.
- Decide whether launcher downloads are allowed.
- Treat `.bifrost/cache/`, the machine-level cache, host transcripts, and
  model-provider logs as repository-sensitive data.
- Configure repository exclusions and request path filters, but do not treat
  filters as process isolation.
- Inspect representative tool output before you give an agent access. Source
  excerpts can leave the local process through the host.
- Start a new host session after MCP configuration changes, and check the
  advertised tool surface again.
