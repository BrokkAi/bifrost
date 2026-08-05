# Route one rmcp Bifrost server across named workspaces

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must stay current while work proceeds.

Maintain this document as required by `.agents/PLANS.md` in the Bifrost repository.

## Purpose / Big Picture

An agent can currently analyze only one Bifrost workspace at a time. The old `activate_workspace` tool replaces that workspace. This rebuilds state, creates race conditions between parallel calls, and makes repository identity implicit.

After this change, one Bifrost process can serve a fixed set of named repositories. Every workspace-dependent tool call selects one repository with a required `workspace` argument. Mjolnir sends the named set to Anvil. Anvil starts Bifrost with that set and tells the model which names are available. The CodeScaleBench harness uses the same path and no longer creates a synthetic Git repository above several real repositories.

## Progress

- [x] (2026-08-05) Confirmed the current Bifrost, Anvil, Mjolnir, and Brokkbench data paths.
- [x] (2026-08-05) Created separate Anvil and Mjolnir worktrees from their evaluation branches.
- [x] (2026-08-05) Added named workspace parsing, schemas, lazy services, and routing to the Bifrost rmcp host.
- [ ] Add workspace lifecycle data, Bifrost launch arguments, prompt guidance, and reranker forwarding to Anvil.
- [ ] Add named workspace command-line input and ACP metadata to Mjolnir.
- [ ] Move the CodeScaleBench harness from a synthetic repository to real named repositories.
- [ ] Run focused and repository-level validation.
- [ ] Run one containerized CodeScaleBench proof task.
- [ ] Commit each repository separately and record the results here.

## Surprises & Discoveries

- Observation: Anvil and Mjolnir contain evaluation-only changes that are not on current upstream master.
  Evidence: the active Anvil evaluation branch contains semantic reranking, and the Mjolnir branch contains provider routing.

- Observation: Bifrost already keeps analyzer, watcher, semantic, and generation state inside `SearchToolsService`.
  Evidence: `crates/bifrost-mcp/src/searchtools_service.rs` owns these values, so one service per repository preserves isolation.

- Observation: A router can reuse the existing shared analyzer admission pool without changing `SearchToolsService`.
  Evidence: featureless `cargo check` passed, and five focused CLI and rmcp schema tests passed.

## Decision Log

- Decision: Implement multi-workspace support only in the `rmcp` host.
  Rationale: The user marked the hand-written host as legacy. Duplicating the router would add risk without product value.
  Date/Author: 2026-08-05 / Codex

- Decision: Use `workspace` as a required tool argument in named mode.
  Rationale: Explicit selection is safe for concurrent calls. A mutable active workspace is not safe.
  Date/Author: 2026-08-05 / Codex

- Decision: Send named workspaces through versioned ACP request metadata.
  Rationale: Standard `additionalDirectories` carries paths but no names. Request metadata keeps file authority separate from analysis identity.
  Date/Author: 2026-08-05 / Codex

- Decision: Keep the SQLite schema unchanged.
  Rationale: Each normal Bifrost service already resolves and shares its persisted cache safely. Routing does not change stored identities.
  Date/Author: 2026-08-05 / Codex

- Decision: Keep the first workspace warm and create later services on first use.
  Rationale: Starting many analyzer builds together can consume excessive CPU and memory. Lazy service creation keeps startup bounded.
  Date/Author: 2026-08-05 / Codex

## Outcomes & Retrospective

The Bifrost command and rmcp routing milestone is complete. Client and harness work remains.

## Context and Orientation

Bifrost is in `/mnt/optane/bifrost-nlp`. Its command-line entry is `src/bin/bifrost.rs`. Its current rmcp server is `crates/bifrost-mcp/src/rmcp_host.rs`. Tool descriptors come from the registry and `crates/bifrost-mcp/src/mcp_core.rs`. `SearchToolsService` in `crates/bifrost-mcp/src/searchtools_service.rs` represents one analyzer workspace.

Anvil is in `/mnt/optane/anvil-bifrost-multi-workspace`. It receives ACP lifecycle requests in `src/acp.rs`. It stores sessions in `src/session.rs`. It starts MCP servers in `src/mcp.rs`. It intercepts `semantic_search` in `src/semantic_rerank.rs`.

Mjolnir is in `/mnt/optane/mjolnir-bifrost-multi-workspace`. It parses commands in `src/main.rs`, normalizes roots in `src/paths.rs`, and builds ACP requests in `src/acp.rs`.

Brokkbench is in `/home/jonathan/Projects/brokkbench`. `codescalebench_agent_engine.py` prepares CodeScaleBench containers. `cimeval/remote/run_task.sh` writes Anvil setup and starts Mjolnir.

A named workspace has a stable model-facing name and an absolute repository path. File authority remains the ACP working directory plus additional directories. An analysis workspace must stay inside that authority.

## Plan of Work

First, add repeatable `--workspace NAME=PATH` parsing to Bifrost. Reject duplicate names, duplicate canonical paths, `--root` combinations, non-MCP use, and use without `BIFROST_MCP_RMCP=on`. Keep the single-root and rootless paths unchanged.

Add an rmcp-only router that owns ordered workspace entries. Each entry owns one `SearchToolsService`; the first starts with the server and later entries start on first use. Add registry metadata that states whether a tool needs workspace state. In named mode, add a required leading `workspace` schema property to those tools. Remove `activate_workspace` and `get_active_workspace`. Select the service, remove the routing argument, normalize paths against that service root, and execute through the existing shared analyzer pool. Scope cancellation by workspace identity and generation. A refresh in one repository must not cancel calls in another repository.

Second, add an Anvil `AnalysisWorkspace` value. Read `_meta["io.brokk/workspaces"]` with schema version 1 from ACP new, load, resume, and fork requests. Validate names, canonical paths, uniqueness, and containment within current file authority. Do not recover authority from a saved session file. When metadata is absent, derive workspace names from the working directory and additional directories. Use stable numeric suffixes for equal folder names.

Change the managed Bifrost argument template to contain `{bifrost_workspace_args}`. Expand one unnamed fallback workspace to `--root PATH`. Expand named or multiple workspaces to repeated `--workspace NAME=PATH` arguments. Start managed Bifrost with `BIFROST_MCP_RMCP=on`. Put the workspace map and concise selection guidance in the Anvil system prompt. Preserve `workspace` through semantic search reranking and all raw Bifrost follow-up calls.

Third, add repeatable `--workspace NAME=PATH` input to Mjolnir. Canonicalize each path, reject duplicates, and add paths outside the main working directory to ACP `additionalDirectories`. Attach the versioned metadata to new, load, resume, and fork requests. Preserve the flags in generated resume commands. Send no metadata when no explicit names exist, so older and simple sessions retain automatic behavior.

Fourth, change Brokkbench. Derive CodeScaleBench workspace names and paths from prepared source mounts. Use the real repository root as a fallback for single-repository tasks. Pass the named list to Mjolnir. Use `{bifrost_workspace_args}` in setup. Set `BIFROST_MCP_RMCP=on` for all arms. Prewarm each real repository in sequence against the shared Bifrost cache. Remove the synthetic aggregate Git repository and its tests. Store the workspace map and repository heads in run metadata.

## Concrete Steps

Work in these directories:

    /mnt/optane/bifrost-nlp
    /mnt/optane/anvil-bifrost-multi-workspace
    /mnt/optane/mjolnir-bifrost-multi-workspace
    /home/jonathan/Projects/brokkbench

Use focused tests after each subsystem. Check available disk space before any Bifrost NLP build. Do not put build targets in `/tmp`. Use the Bifrost isolated-target helper when isolation is necessary.

At each stable milestone, update this plan. Make a multiline checkpoint commit in the repository that changed. Stage only named files.

## Validation and Acceptance

Create two small Git repositories that contain declarations with the same name. Start Bifrost with two `--workspace` values. `tools/list` must show one tool copy, a required `workspace` property, and both names in its enum. It must not show `activate_workspace` or `get_active_workspace`. Calls against each name must return only that repository's declaration.

Run concurrent calls against both names. Refresh one workspace during a call against the other. The unrelated call must continue.

For Bifrost, run focused rmcp and command-line tests. Then run `cargo fmt`, the required Python 3.12 NLP test command, and `cargo clippy --workspace --all-targets --all-features -- -D warnings` when disk space permits.

For Anvil, run focused ACP, MCP, prompt, and reranker tests. Then run `cargo test` outside the restricted sandbox and `cargo clippy --all-targets -- -D warnings`.

For Mjolnir, run focused command, path, and ACP tests. Then run `cargo test` and `cargo clippy --all-targets -- -D warnings`.

For Brokkbench, run:

    PYTHONPATH=. uv run pytest tests/test_codescalebench_agent_engine.py cimeval/test_manifest.py
    uv run ruff check --config pyproject.toml codescalebench_agent_engine.py tests/test_codescalebench_agent_engine.py

Run one CodeScaleBench task with the real workspace list. Confirm that `/workspace` does not become a Git repository. Confirm that traces include a valid workspace on each Bifrost workspace call. Confirm that the semantic arm reuses the prewarmed database.

## Idempotence and Recovery

Workspace parsing and cache prewarming are safe to repeat. Existing SQLite reconciliation remains responsible for current tree state. A failed lazy analyzer build stays local to its workspace and must return an error that names that workspace.

Do not remove or stage unrelated Brokkbench files. If a test changes generated artifacts, remove only artifacts that the test created and identify them by exact path.

## Artifacts and Notes

The Bifrost worktree had one prior untracked task-selection file. It was committed separately as `5fd52670` before this plan started.

The Anvil worktree starts at `cacb07b`. The Mjolnir worktree starts at `26a3084`.

## Interfaces and Dependencies

Bifrost adds this command-line interface:

    bifrost --workspace NAME=PATH [--workspace NAME=PATH ...] --mcp TOOLSETS

Named mode changes only the advertised MCP schema. Each workspace-dependent tool receives:

    "workspace": "NAME"

Mjolnir adds the same repeatable command form. It sends:

    {
      "io.brokk/workspaces": {
        "version": 1,
        "items": [
          {"name": "NAME", "path": "/absolute/path"}
        ]
      }
    }

Anvil adds `{bifrost_workspace_args}` as a variable-length MCP argument template. No new third-party dependency is necessary.

Revision note: 2026-08-05. Created the first complete plan after the user fixed repository ownership and worktree rules.
