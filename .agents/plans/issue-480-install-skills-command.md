# Add `bifrost --install-skills`

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Zed and Antigravity-style hosts load Agent Skills from ordinary filesystem directories such as `~/.agents/skills` and `<worktree>/.agents/skills`. Bifrost already maintains useful skills under `plugins/bifrost-agent/skills`, but users currently have to copy or link those folders by hand for hosts that do not consume the full Bifrost plugin package. After this change, a user can run `bifrost --install-skills`, choose a numbered destination, and get the default Bifrost code-intelligence skills installed safely and idempotently.

## Progress

- [x] (2026-07-09T09:35Z) Created this ExecPlan before implementation.
- [x] (2026-07-09T09:50Z) Added `src/skill_install.rs` with embedded skill contents, project/global/custom target resolution, interactive menu selection, copy/symlink/auto modes, managed markers, dry-run output, and conflict handling.
- [x] (2026-07-09T09:55Z) Wired `--install-skills`, `--target`, `--skills-root`, `--mode`, `--skill-set`, `--force`, and `--dry-run` into `src/bin/bifrost.rs`.
- [x] (2026-07-09T10:00Z) Added end-to-end CLI tests for copy, idempotency, dry-run, unmanaged conflicts, force replacement, custom roots, interactive selection, help text, all-skill installs, and Unix symlinks.
- [x] (2026-07-09T10:05Z) Updated `plugins/bifrost-agent/README.md` to document the new command and clarify that skill installation is separate from MCP setup.
- [x] (2026-07-09T10:18Z) Ran focused validation and manifest checks; clippy passed after forcing Cargo to use the rustup clippy binaries instead of Homebrew clippy.
- [x] (2026-07-09T10:35Z) Cleared Bifrost-related entries from the local Antigravity/Gemini and generic Zed skill roots, then verified fresh installs and idempotent reruns against both roots.
- [x] (2026-07-09T11:55Z) Added existing-page docs coverage on the CLI, MCP overview, Zed MCP, and Antigravity pages, then validated the docs package.

## Surprises & Discoveries

- Observation: The `cargo clippy-no-cuda` alias itself is correct, but this shell had `cargo`/`rustc` from `/Users/dave/.local/bin` and `cargo-clippy`/`clippy-driver` from `/opt/homebrew/bin`, which made clippy report `E0514` incompatible compiler artifacts even in a fresh target directory.
  Evidence: `which cargo rustc clippy-driver cargo-clippy` showed mixed rustup/Homebrew paths. The same alias passed with `PATH="$(dirname "$(rustup which cargo-clippy)"):$PATH" CARGO_TARGET_DIR=/private/tmp/bifrost-clippy-rustup-target cargo clippy-no-cuda`.

- Observation: The workflow skill directories are named without the `brokk-` prefix even though their YAML `name` fields include it.
  Evidence: `plugins/bifrost-agent/skills/guided-review/SKILL.md` has `name: brokk-guided-review`, while its canonical source directory is `plugins/bifrost-agent/skills/guided-review`.

## Decision Log

- Decision: Install the three canonical Bifrost code-intelligence skills by default, not the generated Codex bundle or Amp single-skill bundle.
  Rationale: Issue #480 targets generic `.agents/skills` hosts. The source-of-truth skills already live under `plugins/bifrost-agent/skills`, while Codex and Amp have host-specific packaging flows.
  Date/Author: 2026-07-09 / Codex

- Decision: Limit v1 destinations to project `.agents/skills`, global `$HOME/.agents/skills`, and an explicit custom root.
  Rationale: Host-private roots such as Antigravity's app state can drift, while the generic roots are the documented cross-host contract.
  Date/Author: 2026-07-09 / Codex

## Outcomes & Retrospective

Implementation outcome 2026-07-09: `bifrost --install-skills` now installs generic Agent Skills into project, global, or explicit `.agents/skills` roots. The default skill set installs the three Bifrost code-intelligence skills, while `--skill-set all` installs every canonical skill directory. Copy installs write a `.bifrost-install.json` marker and protect unmanaged user skills; symlink installs point at checkout source directories when available. The CLI help and plugin README now document the command and state that MCP setup remains separate.

Manual host-root verification 2026-07-09: after clearing the old Bifrost entries, `./target/debug/bifrost --install-skills --target global --mode copy` populated `/Users/dave/.agents/skills` with `bifrost-code-navigation`, `bifrost-code-reading`, and `bifrost-codebase-search` while leaving the unrelated `use-railway` skill untouched. `./target/debug/bifrost --install-skills --skills-root /Users/dave/.gemini/antigravity/skills --mode copy` populated the explicit Antigravity/Gemini root with the same three skills. Rerunning both commands reported all three skills as `Up to date`.

Docs outcome 2026-07-09: the feature is documented on existing docs pages, not a new page. `docs/src/content/docs/cli.md` has the full option summary, `docs/src/content/docs/mcp.md` clarifies that skills are separate from MCP setup, and the Zed/Antigravity setup pages now point users at `bifrost --install-skills` instead of manual copying. `npm run check` and `npm run build` passed in `docs/` after installing the locked docs dependencies with `npm ci`.

## Context and Orientation

The top-level CLI entrypoint is `src/bin/bifrost.rs`. It currently hand-parses flags for MCP server mode, LSP mode, the `search_ast` REPL, and one-shot `--tool` calls. The canonical Bifrost skills are plain folders under `plugins/bifrost-agent/skills`; each direct child contains a `SKILL.md`. Zed-compatible skill roots also expect each skill to be a direct child folder with `SKILL.md` inside.

The implementation should add a small library module, `src/skill_install.rs`, that owns embedded skill contents, target resolution, safe copy/symlink installation, conflict detection, and human-readable status messages. The binary should only parse flags and call that module.

## Plan of Work

Add an embedded asset table for every canonical `SKILL.md` file using `include_str!`. The default `code` skill set should include only `bifrost-code-navigation`, `bifrost-code-reading`, and `bifrost-codebase-search`; the opt-in `all` skill set should include every direct canonical skill directory currently packaged.

Implement install destination resolution. `--target project` writes to `<root>/.agents/skills`; `--target global` writes to `$HOME/.agents/skills`; `--skills-root DIR` writes to that explicit root. If no destination is supplied, print a numbered menu with project and global choices, read one line from stdin, and install to the selected root.

Implement safe installation. Copy mode creates `<skill>/SKILL.md` and `<skill>/.bifrost-install.json`. Symlink mode creates `<skill>` as a symlink to the checkout source directory, but only when the source directory exists in this checkout. Auto mode uses symlinks for project-local installs when checkout sources are available and copy otherwise. Existing matching installs report as up to date. Existing Bifrost-managed copies with drift require `--force`. Existing unmanaged files or directories always fail clearly.

Update `src/bin/bifrost.rs` help text and argument validation, and update `plugins/bifrost-agent/README.md` to explain that skills are separate instructions and do not configure the MCP server.

## Concrete Steps

Work from the repository root:

    cd /Users/dave/.codex/worktrees/e7e5/bifrost

Implement the source edits, then run:

    cargo fmt
    cargo test --test bifrost_skill_install_cli
    cargo test --test bifrost_tool_cli
    cargo test --test bifrost_mcp_server
    PATH="$(dirname "$(rustup which cargo-clippy)"):$PATH" CARGO_TARGET_DIR=/private/tmp/bifrost-clippy-rustup-target cargo clippy-no-cuda
    node scripts/check-codex-plugin-manifest.mjs
    npm run check
    npm run build

The plain `cargo clippy-no-cuda` command should be preferred when `cargo-clippy`
and `clippy-driver` come from the same toolchain as `cargo` and `rustc`. In this
session, the explicit `PATH` prefix was necessary because Homebrew clippy was
earlier on `PATH`.

Run the docs commands from `docs/`. This worktree initially lacked
`docs/node_modules`, so `npm ci` was needed before `npm run check` and
`npm run build`.

## Validation and Acceptance

Acceptance is behavioral. `bifrost --install-skills --target project --mode copy --root <tmp-project>` must create `<tmp-project>/.agents/skills/bifrost-code-navigation/SKILL.md`, `bifrost-code-reading/SKILL.md`, and `bifrost-codebase-search/SKILL.md`. Running the same command again must report the skills are already up to date. Dry-run must not write files. Conflicts with unmanaged user skills must fail without modifying those skills. The interactive prompt must accept `1` and install project-local skills.

## Idempotence and Recovery

The install command must be safe to rerun. Managed copied installs are identified by `.bifrost-install.json`; unmanaged user files are never overwritten. If implementation stops midway, inspect `src/skill_install.rs` first because all CLI behavior should route through that module.

## Artifacts and Notes

No artifacts yet.

## Interfaces and Dependencies

`src/skill_install.rs` should expose:

    pub enum InstallMode { Auto, Symlink, Copy }
    pub enum SkillSet { Code, All }
    pub enum InstallTarget { Project, Global }
    pub struct InstallSkillsOptions { ... }
    pub fn install_skills(options: InstallSkillsOptions) -> Result<(), String>

The module should use only the standard library plus existing `serde` and `serde_json` dependencies.
