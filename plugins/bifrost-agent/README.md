# Bifrost Agent Plugin

This directory is the shared source for Bifrost integrations in Pi, Codex,
Claude Code, Cursor, and Amp. Every host reuses the same launcher and pinned
release metadata, but each distribution includes only the resources its host
supports. The npm package `@brokk/bifrost-agent` contains the Pi extension and
three generic code-intelligence skills. The Claude, Codex, and Cursor plugin
manifests expose their host-specific MCP configuration, broader workflow skills,
and specialist agents, while Amp uses its generated skill bundle.

None of these distributions bundles the Bifrost binary. The launcher resolves a
released Bifrost binary and makes a multi-language code-analysis subset of the
`bifrost` MCP tools discoverable through each host's plugin or skill system.

The Claude Code and Codex stable install name is `brokk`. Cursor uses the
Cursor-facing plugin name `bifrost` so the package is discoverable as Bifrost in
Cursor's Customize UI. The public marketplace namespace is `bifrost`, so
Claude/Codex marketplace installs read as `brokk@bifrost` where the host exposes
namespace-qualified install names.

The plugin starts `./bin/bifrost-launcher.mjs --mcp "symbol|extended"`.
The launcher uses `BIFROST_WORKSPACE_ROOT` when set, then a host-provided
`--root` or `--workspace-root`. Without either explicit override, Bifrost
starts unbound and requests the host's approved workspace through standard MCP
roots. On a rootless connection without advertised roots, it offers the
`codex/sandbox-state-meta` extension; current Codex uses that capability to
supply the active task. Bifrost never treats the installed plugin directory as
the analyzer workspace.
Claude Code and Codex read this server entry from `.mcp.json`; Cursor reads the
same entry from root `mcp.json`, using Cursor's documented `type: "stdio"`
field. Amp uses a different direct server-map shape for `mcp.json` and
`--mcp-config`, so the generated Amp bundle lives under
`plugins/bifrost-agent/amp-skills`.

Binary resolution order is:

1. `BIFROST_BINARY_PATH`, when set.
2. The launcher-managed cache for the pinned Bifrost release.
3. A compatible `bifrost` already on `PATH`, only when
   `BIFROST_LAUNCHER_ALLOW_PATH=1` is set.
4. A checksum-verified GitHub release download into the managed cache.

Set `BIFROST_LAUNCHER_AUTO_INSTALL=0` to disable downloads, or
`BIFROST_LAUNCHER_CACHE_DIR=/path/to/cache` to choose the managed cache
location. `BIFROST_BINARY_PATH` is the preferred local development override
because it bypasses ambient `PATH` lookup. Launcher diagnostics go to stderr so
stdio MCP traffic stays on stdin/stdout.

The launcher also has commands that do not require a workspace. `doctor`
checks the pinned version and configured binary candidates without modifying
the cache or downloading anything. Compatibility checks execute each selected
candidate with `--version`, so use `doctor` only with binary locations you
trust. `prepare` follows the normal resolution order and,
when automatic installation is enabled, downloads and verifies the pinned
release without starting MCP. Both accept `--json` for stable machine-readable
output:

```bash
plugins/bifrost-agent/bin/bifrost-launcher.mjs doctor
plugins/bifrost-agent/bin/bifrost-launcher.mjs prepare
```

After `prepare` succeeds, start a fresh host task so it negotiates the restored
Bifrost tool surface. `prepare` respects `BIFROST_LAUNCHER_AUTO_INSTALL=0`; unset
that variable before explicitly preparing a missing release.

For local development, build this checkout and point the launcher at the debug
binary:

```bash
cargo build --bin bifrost
BIFROST_BINARY_PATH="$(pwd)/target/debug/bifrost" node plugins/bifrost-agent/bin/bifrost-launcher.mjs --root . --mcp "symbol|extended"
```

## Pi Install

Pi loads a native extension from this package. The extension resolves the same
pinned, checksum-verified Bifrost binary as the other hosts, starts one stdio
MCP child for the session's workspace, and closes the child on session shutdown
or reload. Pi-visible tools use a `bifrost_` namespace, so Bifrost's canonical
MCP `query_code` tool appears as `bifrost_query_code`. The extension adds a
short system-prompt note that explains this host-specific rendering; the three
canonical `bifrost-code-navigation`, `bifrost-code-reading`, and
`bifrost-codebase-search` skills remain shared without Pi-specific copies.

Install a local checkout after installing its package dependencies:

```bash
cd plugins/bifrost-agent
npm install
pi install "$(pwd)"
```

For development against this checkout's Rust binary:

```bash
cargo build --bin bifrost
cd plugins/bifrost-agent
npm install
BIFROST_BINARY_PATH="$(cd ../.. && pwd)/target/debug/bifrost" pi -e "$(pwd)"
```

To install from GitHub before an npm release, clone the repository and install
the package directory as a local Pi package:

```bash
git clone https://github.com/BrokkAi/bifrost.git
cd bifrost/plugins/bifrost-agent
npm install
pi install "$(pwd)"
```

After `@brokk/bifrost-agent` is published to npm, install a pinned release with:

```bash
pi install npm:@brokk/bifrost-agent@0.8.8
```

Run `/bifrost` in Pi's interactive TUI to configure Bifrost for the current
workspace. The default enables symbol navigation, structural queries, and file
discovery/ranking. The settings list can also enable code-quality reports, Git
history, raw text search, or JSON/XML transforms. It never offers Bifrost
workspace-switching tools because Pi owns the session workspace.
Selections are stored in separate canonical-workspace files under
`<Pi agent directory>/bifrost/workspaces/` (normally
`~/.pi/agent/bifrost/workspaces/`), so they survive new sessions without
adding configuration to the repository or making concurrent workspaces rewrite
the same settings document. If a settings file is malformed, interactive Pi
reports the problem and starts with Bifrost disabled so `/bifrost` can repair
the selection. Pi modes without a UI context report the failure through the
extension error path and leave Bifrost unstarted instead of silently enabling
defaults; Pi itself can continue without Bifrost.

Changing a capability may restart the Bifrost child when it requires another
existing MCP server toolset. Tools discovered earlier remain registered with Pi
but are removed from Pi's active tool set when disabled or rejected by Pi's
command-line tool filters. The namespace note is omitted when Pi accepts no
Bifrost tools. A failed change before connection retirement leaves the prior
connection and saved selection active. If retiring that connection fails, the
saved selection remains but Bifrost tools are disabled because cleanup could
not be confirmed. In interactive Pi, startup, reconnect, and background
connection failures use Pi's error notifications; in modes without a UI
context, startup failures use Pi's extension error path. The extension does not
write directly into the TUI with `console.log` or `console.error`.

Tool calls time out after 300 seconds; startup times out after 60 seconds.
Cancellation stops the Pi request promptly, though the current Bifrost stdio
server may finish analyzer work before it reads the MCP cancellation
notification.

Bifrost results follow Pi's normal two-level output handling. The TUI shows a
five-visual-line preview and expands the bounded result with Pi's tool-output
shortcut (`Ctrl+O` by default). The model receives at most the first 2,000 lines
or 50 KB. When complete text exceeds that limit, the result includes the path
to a dedicated temporary overflow file containing the full output.

For a real-host smoke from the repository root, build Bifrost and ask Pi to
exercise navigation plus both supported structural-query inputs:

```bash
cargo build --bin bifrost
BIFROST_BINARY_PATH="$PWD/target/debug/bifrost" \
BIFROST_LAUNCHER_AUTO_INSTALL=0 \
pi --no-session -e "$PWD/plugins/bifrost-agent" -p \
  'Use the Bifrost tools directly. First call bifrost_get_summaries for src/mcp_common.rs. Then call bifrost_query_code with inline canonical JSON fields match.kind=declaration and limit=1. Then call bifrost_query_code with only query_file="docs/fixtures/ten-minute-evaluation/queries/find-audit.rql". Report whether all three calls succeeded and include one repository-relative path from each result.'
```

Expect all three calls to succeed. The saved query should return
`docs/fixtures/ten-minute-evaluation/src/app.py`; this also proves that
`query_file` is resolved from Pi's explicit session workspace rather than from
the installed package directory. Use Pi's JSON mode for protocol-level evidence
when needed; Bifrost diagnostics remain on stderr and must not appear as JSON
messages on stdout.

Package maintainers should keep `package.json`, `package-lock.json`,
`bifrost-release.json`, and the Rust crate version aligned. Validate the package before publication:

```bash
cd plugins/bifrost-agent
npm ci
npm run check
npm test
npm run test:packed
npm pack --dry-run
npm publish --dry-run
```

A real publication requires npm credentials and an unused matching version; the
repository does not imply that npm publishing is configured automatically.

## Codex Install

Add the Brokk marketplace from GitHub, then install Bifrost:

```bash
codex plugin marketplace add BrokkAi/bifrost --sparse .agents/plugins --sparse plugins
codex plugin add brokk@bifrost
```

For local development from a checkout, add the repository root instead:

```bash
codex plugin marketplace add "$(pwd)"
codex plugin add brokk@bifrost
```

For a local checkout build, start Codex with this repository's debug binary
selected explicitly:

```bash
BIFROST_BINARY_PATH="$(pwd)/target/debug/bifrost" codex
```

Start a fresh Codex session after installing the plugin. The plugin-provided
MCP server is registered automatically; do not add a second manual Bifrost MCP
entry. It starts a separate stdio Bifrost process with:

```bash
bifrost --mcp "symbol|extended"
```

For that rootless process, Bifrost prefers standard MCP roots. When the client
did not advertise roots, Bifrost offers the `codex/sandbox-state-meta`
capability. A compatible client may then attach its active task directory to
each analyzer tool call; current Codex does so. Bifrost binds that exact
directory and revokes it when the per-call scope disappears or changes.
`BIFROST_WORKSPACE_ROOT` remains an explicit compatibility override. Client-root
and sandbox-metadata sessions keep analyzer and semantic cache writes under the
exact approved root, including for linked worktrees.

The plugin gives Bifrost up to 180 seconds to download, verify, extract, and
start a missing pinned release, and up to 300 seconds for individual analyzer
tool calls. Large workspaces may need the tool-call budget because Bifrost can
build its persisted analyzer on the first real tool call.

The default plugin toolset intentionally omits Bifrost's `workspace` and `text`
MCP toolsets. That keeps local plugin installs focused on analyzer navigation
and avoids giving prompts a built-in way to switch the active workspace or read
arbitrary files through raw text tools. Users who explicitly want the full MCP
surface can still add a manual `codex mcp add` entry for `--mcp searchtools`.

Once the session starts, verify the tools by calling a lightweight analyzer
operation such as `get_summaries` or `search_symbols` against files in the
active workspace.

## Bundled Skills

The Bifrost plugin owns the skills that explain the analyzer-backed MCP tools
it installs, plus the broader Brokk/Bifrost workflow skills that build on those
tools:

- `bifrost-code-navigation`: definitions, references, call sites, and related
  files with `search_symbols`, `get_symbol_locations`, `scan_usages_by_location`, and
  `most_relevant_files`.
- `bifrost-code-reading`: source summaries and exact symbol bodies with
  `get_summaries` and `get_symbol_sources`.
- `bifrost-codebase-search`: symbol, usage, file, and related-file discovery
  with shell grep reserved for arbitrary text.
- `brokk-adversarial-test-sweep`: comprehensive test-suite hardening across
  edge cases, malformed inputs, concurrency, resource pressure, corrupted
  state, invalid assumptions, and weak or redundant coverage.
- `brokk-git-exploration`: git-history exploration and commit inspection.
- `brokk-guided-issue`: end-to-end GitHub issue resolution.
- `brokk-guided-review`: interactive review of local changes, branches, or
  remote PRs with specialist reviewer agents.
- `brokk-review-pr`: adversarial multi-agent PR review.
- `review`: concise code-review guidance for ordinary review requests.
- `brokk-today`: GitHub issue and PR work-queue triage with a Slack-ready
  summary.
- `brokk-write-issue`: issue drafting with source-code context.

The plugin also includes the specialist reviewer and issue-planning agents used
by those workflows. The default plugin MCP toolset still does not expose
Bifrost's `workspace` lifecycle tools, so the Brokk `workspace` skill is not
copied here. Workflow skills should rely on the host-provided workspace context
and the plugin's analyzer tools, or gracefully skip explicit workspace
activation when `activate_workspace` is unavailable.

Codex does not register plugin-provided `agents/*.md` files as named
`brokk:*` subagent types. The Codex manifest therefore loads generated skills
from `codex-skills/`; those files embed the specialist prompts and instruct
Codex to use generic subagents with the matching prompt. Do not edit
`codex-skills/` directly. Update `skills/` or `agents/`, then regenerate:

```bash
node scripts/generate-codex-skill-bundle.mjs
```

Hosts such as OpenCode, Zed, and Antigravity can also load generic Agent Skills
directly from filesystem roots such as `~/.agents/skills` and
`<worktree>/.agents/skills`. For those hosts, install Bifrost's generic skills
with the Bifrost CLI instead of copying directories by hand:

```bash
bifrost --root /absolute/path/to/workspace --install-skills --target project
```

The default command installs the three Bifrost code-intelligence skills. Use
`--target global` for `~/.agents/skills`, `--skills-root /path/to/skills` for an
explicit skills root, `--mode copy` for self-contained copies, or
`--skill-set all` to opt into the Brokk workflow/review skills as well. This
step installs only instructions for the agent. It does not register the Bifrost
MCP server; keep using the host-specific MCP setup below for analyzer tools.

## Claude Code Install

Add the Brokk marketplace from GitHub, then install Bifrost:

```bash
claude plugin marketplace add BrokkAi/bifrost --sparse .claude-plugin plugins
claude plugin install brokk@bifrost
```

Start a fresh Claude Code session after installing the plugin so the MCP server
configuration is loaded at startup.

## Claude Code Local Testing

From the repository root, start Claude Code with this package directory:

```bash
BIFROST_BINARY_PATH="$(pwd)/target/debug/bifrost" claude --plugin-dir plugins/bifrost-agent
```

Inspect `/plugin` to confirm the `bifrost` metadata loaded, then inspect `/mcp`
or ask Claude to call a lightweight analyzer operation such as `get_summaries`
or `search_symbols`.

To test the repository as a local Claude Code marketplace, run:

```bash
claude plugin marketplace add "$(pwd)"
claude plugin install brokk@bifrost --scope local
BIFROST_BINARY_PATH="$(pwd)/target/debug/bifrost" claude
```

Start a fresh Claude Code session after installing the plugin so the MCP server
configuration is loaded at startup.

## Cursor Local Testing

From the repository root, build Bifrost and open Cursor with the local binary
selected:

```bash
cargo build --bin bifrost
BIFROST_BINARY_PATH="$(pwd)/target/debug/bifrost" cursor .
```

In Cursor, open **Customize**, then use **Manage -> Add Marketplace -> Import
from Disk** and select the repository root. Cursor should read
`.cursor-plugin/marketplace.json`, find the `bifrost` plugin at
`plugins/bifrost-agent`, and offer it for installation. If testing the package
directory directly instead of the repository marketplace, select
`plugins/bifrost-agent`.

After installing, enable the Bifrost MCP server for the workspace from the
plugin's **MCPs** section in Customize. Cursor does not load installed MCP
servers into chat until they are enabled, and already-open agent chats may need
a fresh chat before newly enabled MCP tools appear. Then ask Cursor Agent to
call a lightweight analyzer operation such as `get_summaries` or
`search_symbols` against files in the active workspace. Use a source directory
or file, not `README.md`, so the smoke cannot pass through ordinary file
reading. For example:

```text
Use the Bifrost MCP get_summaries tool on src/analyzer/usages. Summarize the
package structure in five bullets and explicitly name the MCP tool result you
used.
```

The `cursor agent --plugin-dir` CLI path is useful for checking that Cursor can
load plugin skills, but it has not proven reliable for plugin-provided MCP
servers. Treat the desktop Customize/MCP path as the Cursor plugin MCP smoke.

To publish publicly, submit the repository URL at
<https://cursor.com/marketplace/publish>. The repository root contains
`.cursor-plugin/marketplace.json`, which points Cursor at this shared package.

## Antigravity Install and Local Testing

Antigravity 2.2.1 can load Bifrost through a manual MCP entry in
`~/.gemini/config/mcp_config.json`. The visible **Add MCP** flow is a curated
marketplace, but the local config file accepts the standard `mcpServers` shape:
see Antigravity's official [MCP](https://antigravity.google/docs/mcp)
documentation for the host-side convention.

```json
{
  "mcpServers": {
    "bifrost": {
      "command": "/absolute/path/to/bifrost/target/debug/bifrost",
      "args": [
        "--root",
        "/absolute/path/to/workspace",
        "--mcp",
        "symbol|extended"
      ]
    }
  }
}
```

Restart Antigravity or click **Refresh** in **Settings -> Customizations**. The
tested app showed `bifrost` with 21 enabled tools after reading this file.

Antigravity documents skills under workspace and global skill directories; see
the official [Skills](https://antigravity.google/docs/skills) documentation for
the host-side convention. In Antigravity 2.2.1 validation, workspace-local
skills loaded reliably and appeared in project-specific settings. If global
skills do not appear in your app session, install the Bifrost skills into each
target workspace:

```bash
bifrost --root /absolute/path/to/workspace --install-skills --target project --mode copy
```

Open the project-specific settings page in Antigravity. The project
**Customizations** section should list the installed Bifrost skills. Validate
with a prompt that requires a Bifrost MCP tool on source code:

```text
Use the bifrost-code-reading skill. Use the Bifrost MCP get_summaries tool on src/analyzer/usages for source context, and name the files summarized from the MCP result.
```

## Amp Install and Local Testing

Amp uses a generated skill collection at
`plugins/bifrost-agent/amp-skills`. Do not edit files under that directory
directly; update the canonical code-intelligence skills in
`plugins/bifrost-agent/skills`, then regenerate the Amp bundle:

```bash
node scripts/generate-amp-skill-bundle.mjs
```

The generated Amp skill is intentionally narrower than the Claude/Codex/Cursor
plugin package. It includes one `bifrost-code-intelligence` skill, a skill-local
`mcp.json`, the Bifrost launcher, and the release metadata needed by that
launcher. It does not include the Brokk workflow/review skills or specialist
agents.

From the repository root, build Bifrost:

```bash
cargo build --bin bifrost
```

Install the generated Amp skill collection into the current workspace. Use an
absolute source path; Amp treats relative local skill sources like Git sources
in some CLI paths:

```bash
mkdir -p .agents/skills
amp skill add "$(pwd)/plugins/bifrost-agent/amp-skills" --target "$(pwd)/.agents/skills" --overwrite
```

For a user-global install, use Amp's global skill target instead:

```bash
amp skill add "$(pwd)/plugins/bifrost-agent/amp-skills" --global --overwrite
```

After the Amp bundle has landed on the repository's default branch, install it
from GitHub with Amp's `owner/repo/path` source syntax:

```bash
amp skill add BrokkAi/bifrost/plugins/bifrost-agent/amp-skills --global --overwrite
```

Do not use a browser `https://github.com/.../tree/...` URL for Amp skill
sources. The tested Amp CLI did not accept branch-qualified GitHub skill
sources, so PR-branch validation should use a local checkout path and the
GitHub shorthand should be re-tested after merge.

The generated `mcp.json` uses Amp's direct server-map shape and a small shell
shim that locates `bifrost-code-intelligence/bin/bifrost-launcher.mjs` from the
workspace `.agents/skills` directory, the standard global Amp/agents skill
directories, or `BIFROST_AGENT_SKILL_DIR`. Start Amp from the workspace root, or
set `BIFROST_WORKSPACE_ROOT=/path/to/workspace`. For local checkout testing, set
`BIFROST_BINARY_PATH` so the launcher uses this build instead of downloading the
pinned release.

Amp does not expose the same configurable MCP startup budget as the shared
Claude/Codex and Cursor manifests. After updating the Amp bundle, run the
installed launcher's `doctor` command and, when needed, `prepare` before opening
a fresh Amp task. The commands are available through the bundled
`bifrost-code-intelligence/bin/bifrost-launcher.mjs` file.

Validate with a prompt that requires an analyzer MCP tool on source code, not a
README or docs file:

```bash
BIFROST_BINARY_PATH="$(pwd)/target/debug/bifrost" amp -x \
  'Load the bifrost-code-intelligence skill. Use the Bifrost MCP get_summaries tool on src/analyzer/usages/rust_graph/*.rs and name three symbols from the MCP result.'
```

Amp skill collection installs preserve skill-local support files only when the
collection parent is installed. Installing an individual skill directory copies
only `SKILL.md`. As of the tested Amp CLI, package-relative MCP commands such
as `./bin/bifrost-launcher.mjs` are resolved from the Amp process working
directory, not from the skill directory, so the generated `mcp.json` uses the
launcher search shim instead of a package-relative command.

## Difference From `codex mcp add`

`codex mcp add`, `claude mcp add`, a manual Cursor `mcp.json` entry, or
`amp mcp add` registers one MCP server directly in a user's host configuration.
This plugin packages a safer default server shape behind host plugin flows
where available, so users can install or remove Bifrost without hand-editing
MCP configuration. Amp uses the generated skill bundle documented above, with a
skill-local `mcp.json` rather than a host plugin manifest.

The MCP process created by this plugin is independent from the VS Code language
server process. They may point at the same `bifrost` binary, but each host
starts its own stdio process.
