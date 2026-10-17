---
title: Configuration Files
description: Every project file and machine-level file or directory that Bifrost reads or writes, who writes it, whether to commit it, and where its fields are documented.
---

This page lists the files and directories that Bifrost reads or writes, in the
project and on the machine. Each entry says what the file is for, who writes
it, whether to commit it, and which page documents its fields.

Bifrost never reads a file in `.bifrost/` just because it exists, except where
this page says so. Policy files and saved queries run only when a command or
tool call names them.

## Project Files

| Path | Purpose | Written by | Commit it? | Fields |
| --- | --- | --- | --- | --- |
| `.bifrostignore` (workspace root and any subdirectory) | Exclude matching files from code intelligence. Gitignore syntax; a nested file applies relative to its directory. File tools still see excluded files. | You | Yes | [Workspace Scope](/workspace-scope/) |
| `.bifrost/cache/` | Generated analyzer cache. See [Repository cache](#repository-cache). | Bifrost | No. Bifrost writes `.bifrost/cache/.gitignore` containing `*`. | - |
| `.bifrost/packs.json` | Semantic-pack activation for the workspace: which dependency ecosystems to model, an optional workspace-relative catalog directory, and explicit enables. When it is absent, Bifrost selects compatible packs for the languages in the workspace. | You | Yes | [Semantic Packs Reference](/reference/semantic-packs/) |
| `.bifrost/semantic-models/` | Reviewed semantic models that you write for your own code: the `.json`, `.yaml`, and `.yml` files directly in this directory. At most 1,024 entries are read. Policy runs load them when the directory exists. The MCP server, `--tool`, `--query-file`, and `--repl` load them only with `BIFROST_WORKSPACE_SEMANTIC_MODELS=on`. | You | Yes | [Semantic Packs Reference](/reference/semantic-packs/) |
| `.bifrost/jvm-toolchains.json` | Binds workspace source roots to JDK installations, so that reviewed JDK models can apply to calls in those roots. Read as JVM configuration when the workspace is built; restart a running host after a change. | You | Yes, when the JDK paths are the same for everyone; otherwise keep it local | [Semantic Packs Reference](/reference/semantic-packs/) |
| `.bifrost/suppressions.json` | Accepted policy findings, with reasons and optional expiry. Read by default. Its records must name only files that you publish. | You, or an agent on your behalf | Yes | [Policies Reference](/reference/policies/) |
| `.bifrost/suppressions.private.json` | Accepted findings in files that the repository does not publish. Read by default, after `suppressions.json`. | You | Yes, but do not publish it | [Policies Reference](/reference/policies/) |
| `.bifrost/suppressions.local.json` | One person's or agent's working decisions. Read by default, after the other two. | You, or an agent | No. Add it to your ignore rules. | [Policies Reference](/reference/policies/) |
| `.bifrost/policy-scope.json` | Directory-level acceptances and root exclusions for policy findings. Read by default; `--scope-file` selects another file. | You | Yes | [Policies Reference](/reference/policies/) |
| `.bifrost/baseline.json` | Bulk acceptance of every finding that existed when you ran `--accept-current`. Read by default; `--baseline-file` selects another file. | `bifrost --accept-current` | Yes | [Policies Reference](/reference/policies/) |
| `.bifrost/endpoint-sets/stores/<language>-declared-store.rqlp`, `.bifrost/endpoint-sets/observations/<language>-declared-store-write.rqlp`, `.bifrost/endpoint-sets/kills/<language>-required-validator.rqlp` | Endpoint-set documents that the opt-in built-in declared-storage policies import from these fixed paths. They declare your store write and read calls and your validator. Read only when you select one of those policies with `--policy-id` or `policy_ids`. A selected policy whose file is missing fails, and the run exits 2. A workspace policy can also import endpoint-set documents from any workspace path. | You | Yes | [Policies Reference](/reference/policies/) |
| `.bifrost/policies/` | Conventional location for workspace `.rqlp` policies and endpoint files. Bifrost runs a file here only when `--policy-file` or a `run_policy` call names it. | You | Yes | [Policies Reference](/reference/policies/) |
| Saved query files (`.rql`, `.json`), at any workspace path, for example `queries/` | Saved code queries. Bifrost runs one only when `--query-file` or a `query_file` argument names it, or when a policy's `rql-file` selector names a `.rql` file. | You | Yes | [Code Query Reference](/reference/code-query/) |

`--suppressions-file PATH` replaces all three default suppression files with
one file. A missing default file means no records from that file. An invalid,
oversized, or unsafe file is a diagnostic, and the policy run exits 2.

If your ignore rules exclude the whole `.bifrost/` directory, they also hide
the project inputs above. Ignore `.bifrost/cache/` and
`.bifrost/suppressions.local.json` instead.

### Repository Cache

The repository cache directory is `.bifrost/cache/` at the primary Git
repository root. Every linked worktree of that repository uses the same
directory. A workspace outside any Git repository keeps the cache under its own
root. `BIFROST_CACHE_ROOT` and `BIFROST_CACHE_DIR` move it; see
[Environment Variables](/reference/environment/).

| Entry | Purpose |
| --- | --- |
| `bifrost_cache.v<N>.db` and its `-wal` and `-shm` files | SQLite analyzer database. `<N>` is the cache schema version that the running build reads. Different Bifrost versions use different files in the same directory. Collection preserves the running build's file and chooses at most one other by most recent use. Extra versioned files are removed regardless of age; the retained other file is removed after two weeks without use. A busy store stays until a later collection. |
| `bifrost_cache.v<N>.db.initial-build.lock` | Lock file that serializes the first build of a database. |
| `semantic-pack-catalog.v<N>/` | Semantic-pack catalog: packs that were installed, embedded, or generated for this repository. `BIFROST_SEMANTIC_PACK_CACHE_ROOT` moves it. |
| `.gitignore` | Contains `*`, so Git ignores the directory. |

Older releases used `.bifrost/bifrost_cache.db`. Bifrost does not delete that
file. You can delete it, and its `-wal`, `-shm`, and `-journal` files, after
every older Bifrost process has stopped.

Older releases also wrote a `.bifrost/.gitignore` that contains only `*`.
Bifrost replaces that file with one that ignores only itself and the old
database files. When the old database files exist and `.bifrost/.gitignore`
does not, Bifrost creates the same file. The repository cache does not open,
and Bifrost reports an error, in two cases:

- A `.bifrost/.gitignore` that you wrote has a line `*`, `/*`, `**`, or `/**`.
- The old database files exist, and a `.bifrost/.gitignore` that you wrote is
  not the file that Bifrost writes.

These checks apply only to the default cache location. They do not apply when
`BIFROST_CACHE_ROOT` or `BIFROST_CACHE_DIR` moves the cache.

Delete the cache only while Bifrost is stopped. The next run rebuilds it.

### Build and Package Files

Bifrost reads ordinary project files to assign identities, resolve imports,
and find dependencies. It parses these files. It does not run a build tool or
compiler while it indexes source. You write these files for your own build;
Bifrost does not need any of them.

The [Languages Reference](/reference/languages/#project-and-build-inputs)
gives the fields that Bifrost reads from each file and what it uses them for.

| Language | Files read during indexing | Files read for semantic-pack dependency discovery |
| --- | --- | --- |
| Python | `pyproject.toml`, `setup.py` (parsed, never run), `__init__.py` package layout | `pyproject.toml`, `.python-version`, and the `METADATA`, `RECORD`, and `top_level.txt` files of installed packages |
| Java, Kotlin, Scala | Maven `pom.xml` | `pom.xml`, `settings.xml`, `build.gradle`, `build.gradle.kts`, `settings.gradle`, `settings.gradle.kts`, `gradle.properties`, `gradle.lockfile`, `libs.versions.toml`, `gradle-wrapper.properties` |
| Go | The nearest `go.mod` | `go.mod`, `go.sum`, `go.work`, `go.work.sum`, `vendor/modules.txt` |
| Rust | `Cargo.toml` | `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml` |
| JavaScript, TypeScript | `tsconfig.json`, `jsconfig.json`, and every `package.json` outside `node_modules` | `package.json`, `package-lock.json`, `npm-shrinkwrap.json` |
| PHP | The root `composer.json` | `composer.json`, `composer.lock`, `installed.json` |
| Ruby | The root `Gemfile` or `Gemfile.lock` | `Gemfile`, `Gemfile.lock`, `gems.locked` |
| C, C++ | The root `compile_commands.json` | `compile_commands.json` |
| C# | Every `.csproj` file. The presence of `Directory.Build.props` or `Directory.Build.targets` marks project membership as incomplete; Bifrost does not interpret them. | `project.assets.json` |

To learn a declared CPython version, Bifrost also reads `.python-version`, the
`requires-python` field of `pyproject.toml`, and `python_requires` in
`setup.cfg` or `setup.py`.

Two dependency-discovery modes run a tool:

- A CLI policy run (`bifrost scan` or the policy flags) turns on Go discovery,
  which runs `go list`. An MCP server with a bound workspace, `--tool`,
  `--query-file`, and `--repl` do not run it.
- JVM discovery runs Maven and Gradle only in its offline build-tools mode,
  which only a Rust embedding selects. By default it reads build files.

See [Semantic Packs Reference](/reference/semantic-packs/).

### Files That Other Programs Write

The VS Code extension can offer to replace a `.gitignore` line that ignores
all of `.bifrost` with `.bifrost/cache/`. Its suppression command writes
records to a suppression file in `.bifrost/`. See [VS Code](/vscode/).

## Machine-Level Files

| Path | Purpose | Written by | Remove it? |
| --- | --- | --- | --- |
| Machine-level cache (see below) | State that no single repository owns. | `bifrost` | Yes, while Bifrost is stopped. Bifrost rebuilds it. |
| `<machine cache>/generated-semantic-packs.v<N>/` | Semantic packs that Bifrost generated from exact local dependency artifacts, shared across repositories. Packs unused for seven days are removed. Not used when `BIFROST_SEMANTIC_PACK_CACHE_ROOT` is set. | `bifrost` | Yes |
| `<machine cache>/multiroot/<first-root-name>-<digest>/` | Analyzer database for a multi-root workspace created through the Rust library. | Rust library | Yes |
| `~/.bifrost_code_query_repl_history` | Command history of `bifrost --repl`. | `bifrost --repl` | Yes |
| Agent plugin cache (see below) | Downloaded Bifrost binaries and verified open-pack releases used by the binary. | Agent plugin launcher and `bifrost` | Yes. The launcher or binary downloads again when allowed. |
| Coding-host configuration, such as `opencode/opencode.json` under the user configuration directory, or the file that `omp config path` names | `brokk` MCP server entry. For Codex, Claude Code, Kimi Code, Hermes, and OpenCode 2, Bifrost runs the host's own `mcp add` command instead of writing a file. | `bifrost --install` | Remove the `brokk` entry with the host's own commands. |

### Machine-Level Cache Location

| Platform | Default location |
| --- | --- |
| Linux and other Unix systems | `$XDG_CACHE_HOME/bifrost`, or `~/.cache/bifrost` when `XDG_CACHE_HOME` is not set |
| macOS | `~/Library/Caches/bifrost` |
| Windows | `%LOCALAPPDATA%\bifrost\cache` |

`BIFROST_CACHE_ROOT` replaces the default location on every platform.

### Agent Plugin and Open-Pack Cache Location

| Platform | Default location |
| --- | --- |
| Linux and other Unix systems | `$XDG_CACHE_HOME/bifrost-agent`, or `~/.cache/bifrost-agent` |
| macOS | `~/Library/Caches/bifrost-agent` |
| Windows | `%LOCALAPPDATA%\Bifrost\AgentPlugin` |

`BIFROST_LAUNCHER_CACHE_DIR` replaces the default location for plugin-managed
binaries and also supplies the base for the binary's open-pack cache. Verified
open-pack releases are under `open-pack-releases/` in this directory. See
[Data and Trust Boundaries](/data-boundaries/#plugin-launcher-downloads-and-cache).

## Sensitivity

The repository cache, the machine-level cache, and the REPL history contain
data derived from your source code. Protect them the same way as the
repository.
