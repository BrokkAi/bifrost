---
title: Data and Trust Boundaries
description: Know what Bifrost reads, stores, downloads, executes, and returns to agent hosts.
---

Bifrost analyzes source on the machine where its process runs. That local execution boundary does not mean source stays outside every networked service: an MCP or editor host receives Bifrost's tool results, and the host may send returned snippets, paths, symbols, or diagnostics to its configured model provider. Review the host and model provider's data policy separately.

## Boundary Map

| Component | Reads or receives | Writes or sends |
| --- | --- | --- |
| Bifrost analyzer, CLI, and LSP | Files under the configured workspace root plus local Git metadata needed for indexing | Structured results to stdout, stdio MCP, LSP, or the embedding caller; persistent cache data under `.brokk/`. |
| Agent MCP host | Bifrost tool schemas and returned results, which may include source excerpts | May include those results in model requests, logs, transcripts, or host caches according to host configuration. |
| Agent-plugin launcher | Pinned release metadata and explicit environment or argument overrides | May download a checksum-verified Bifrost release from GitHub into a user cache. |
| Optional semantic search | Workspace code chunks and a local embedding model | Downloads model files from Hugging Face on first use unless `BIFROST_EMBED_MODEL_DIR` points to local files; inference runs in a local Python sidecar and derived index data is cached. |
| Skills and agent instructions | Instruction text | No repository analysis and no tools by themselves. The agent host decides how instruction text is used. |

## Workspace Scope

The process root is explicit through `--root`, a packaged-launcher `BIFROST_WORKSPACE_ROOT` override, or the MCP client's standard roots response. Without an explicit override, the packaged launcher starts Bifrost unbound and the server accepts the first usable local filesystem root returned by the client. It does not infer analyzer scope from the launcher working directory, because plugin hosts may use the installed package directory there. A client without roots support leaves the server unbound. Confirm the effective root before trusting a query or exposing a repository to an agent session.

Workspace-relative query files cannot escape the configured root. Results can still contain source excerpts from indexed files inside that root. Path filters narrow an individual request; they are not an access-control boundary for the already configured process.

## Persistent Repository Cache

For an explicit `--root` process, analyzer facts and optional semantic-index data use `.brokk/bifrost_cache.db` at the primary Git repository root, so linked worktrees share that content-addressed database. Set `BIFROST_CACHE_DIR` to use an explicit cache directory for such a process, for example when running isolated workers. A rootless MCP process bound through client roots instead keeps its database under the exact approved root, including when that root is a linked worktree; it never broadens cache writes to the primary checkout. The cache is local persistent data derived from workspace source and Git objects; protect and retain it according to the same sensitivity policy as the repository.

Removing the database while Bifrost is stopped forces later work to rebuild it. A running process may also hold in-memory source and analysis state. If a test requires a clean cache, stop Bifrost first and record that removal in the evaluation method.

## Plugin Launcher Downloads and Cache

The agent plugin does not bundle the Bifrost executable. Its launcher resolves, in order:

1. `BIFROST_BINARY_PATH`;
2. a launcher-managed copy of the plugin's pinned release;
3. `bifrost` on `PATH` only when `BIFROST_LAUNCHER_ALLOW_PATH=1`;
4. a GitHub release download whose archive and checksum sidecar are verified against pinned SHA-256 metadata.

Managed binaries are versioned under the launcher cache. The default root is `~/Library/Caches/bifrost-agent` on macOS, `%LOCALAPPDATA%/Bifrost/AgentPlugin` on Windows, and `$XDG_CACHE_HOME/bifrost-agent` or `~/.cache/bifrost-agent` on Linux. Set `BIFROST_LAUNCHER_CACHE_DIR` to relocate it or `BIFROST_LAUNCHER_AUTO_INSTALL=0` to prohibit automatic downloads.

Run the package launcher's `doctor` command to inspect the required version,
selected source, and cache path without modifying the cache or downloading
anything. It executes the selected candidate with `--version`, so only inspect
trusted binary locations. Run `prepare` to perform the same exact-version,
checksum-verified resolution before starting an MCP host. Both commands accept
`--json`. If preparation changes the available binary, start a fresh host task
so the MCP tool list is negotiated again.

## Optional Semantic Model

Semantic search is off by default and requires the `nlp` feature. When enabled without `BIFROST_EMBED_MODEL_DIR`, Bifrost resolves `BIFROST_EMBED_MODEL_ID` (by default `voyageai/voyage-4-nano`) through the Hugging Face cache, downloading missing configuration, tokenizer, and weight files. Set `BIFROST_EMBED_MODEL_DIR` to an approved local model directory for an offline or pre-audited setup.

The PyTorch sidecar receives code chunks for local embedding inference. It is a child process, not a hosted embedding API. Accelerator and device environment variables affect local execution, not the MCP/model-host boundary.

## Deployment Checklist

- Pin and verify the effective Bifrost binary and workspace root.
- Decide whether launcher and semantic-model downloads are allowed.
- Treat `.brokk/bifrost_cache.db`, host transcripts, and model-provider logs as repository-sensitive artifacts.
- Configure repository exclusions and request path filters, but do not mistake filters for process isolation.
- Inspect representative tool output before granting an agent access; source excerpts can leave the local process through the host.
- Start a fresh host session after MCP configuration changes and re-check the advertised tool surface.
