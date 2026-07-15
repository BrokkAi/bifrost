# Make Bifrost documentation answer first-contact user questions

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan is maintained in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

Bifrost's reference documentation explains individual tools and query forms well, but a new reader cannot reliably tell which interface they need, whether their agent can execute a query, or how much confidence to place in a result. After this work, a researcher, an agent-platform engineer, an editor user, or a static-analysis builder can begin at a routing page, choose an interface and supported analysis, complete a reproducible evaluation, and interpret the result without confusing editor features, Model Context Protocol tools, command-line behavior, or instruction-only skills.

The first observable improvement is deliberately narrow and urgent: every agent-host setup will recommend the query-capable `symbol|extended` toolset, explain that `core` omits `query_code`, and show how to prove both inline JSON and saved `.rql` execution. Later milestones add suitability, evaluation, rule-building, safety, and trust guidance while preserving the existing reference pages as deeper material.

## Progress

- [x] (2026-07-15 09:47Z) Read the handed-off persona review, synchronized detached `HEAD` with `origin/master`, and verified the MCP/RQL contract against `src/mcp_extended.rs`, `src/searchtools_service.rs`, `plugins/bifrost-agent/mcp.json`, and the current docs.
- [x] (2026-07-15 09:53Z) Added the authoritative MCP/RQL availability matrix, changed query-capable host examples from `core` to `symbol|extended`, added host validation callouts, clarified the RQL and VS Code boundaries, and made the smoke queries executable documentation tests.
- [x] (2026-07-15 09:59Z) Added a first-contact "Choose Bifrost" route by analysis question, interface, and persona; added a source-backed language/capability/precision matrix; updated landing and Start navigation; and inspected desktop and mobile rendering.
- [x] (2026-07-15 10:02Z) Added a checked-in Python fixture and saved RQL query plus reproducible CLI, agent MCP, and VS Code journeys with one shared `src/app.py:5` expected result; added executable fixture/query drift checks and verified both CLI forms.
- [x] (2026-07-15 10:10Z) Added a production rule-building guide across RQL, JSON, CLI, MCP, Python, and Rust; documented all six terminal result variants, fixtures, CI, and reporting; added a result-safety decision rule to docs, every host page, and reusable agent guidance; verified desktop/mobile rendering.
- [x] (2026-07-15 12:14Z) Updated the Rust dependency example to 0.8.2, documented path-local call-cycle handling and alternate provenance, replaced generic `scan_usages` advice, completed the Python result-variant list, and added focused contract checks.
- [ ] Add evaluation methodology, workspace/data boundaries, citation, and reproducibility guidance; validate links, rendered pages, and the full site build.

## Surprises & Discoveries

- Observation: The worktree began at detached `HEAD`, and `origin/master` advanced from `3aee987b` to `d7285eea` during the required fetch.
  Evidence: `git rebase origin/master` completed successfully and `git log -1` now reports `d7285eea Add composable call traversal to query_code (#782)`.
- Observation: The Bifrost skills are installed, but their named MCP code-intelligence tools are not exposed in this task environment.
  Evidence: the available tool registry contained no `search_symbols`, `get_summaries`, `get_symbol_sources`, or related Bifrost tool. The skills explicitly permit shell `rg` and direct reads for arbitrary text and non-source files, so research continues through that fallback.
- Observation: The handoff's Rust version drift is already one release further behind than stated.
  Evidence: the current package version in `Cargo.toml` is `0.8.2`, while `docs/src/content/docs/rust-library.md` still needs to be checked and corrected during the drift milestone.
- Observation: The minimal cross-language declaration query is valid in both canonical JSON and RQL, so one smoke can be reused across all agent-host pages without assuming a particular language.
  Evidence: `cargo test --test code_query_docs documented_code_queries_parse` parsed `{"match":{"kind":"declaration"},"limit":1}` and `(limit 1 (declaration))` successfully.
- Observation: A Markdown table cell containing the literal toolset `symbol|extended` must escape the pipe even when the text is inside backticks.
  Evidence: the first rendered Choose Bifrost preview split the agent row into four cells; changing it to `symbol\|extended` restored the expected three-column row.
- Observation: The documentation tutorial harness can serve as a reproducibility contract for a published fixture, not only for language cookbooks.
  Evidence: `ten_minute_evaluation_tutorial` compares the checked-in source and RQL files with the rendered docs blocks, executes both RQL and canonical JSON, and asserts the complete `src/app.py:5` result.
- Observation: The public `CodeQueryResult` currently has six terminal variants across Rust and Python, while older prose describes only three.
  Evidence: `CodeQueryResultValue` and `_code_query_result_item` both enumerate `structural_match`, `declaration`, `file`, `reference_site`, `call_site`, and `expression_site`; the new rule guide teaches all six and the later drift milestone must update the older Python page.

## Decision Log

- Decision: Treat the MCP/RQL contract as an independent first milestone before adding new information-architecture pages.
  Rationale: It fixes an active correctness problem in existing installation instructions and provides stable terminology for all later journeys.
  Date/Author: 2026-07-15 / Codex
- Decision: Recommend `symbol|extended` for query-capable coding agents and retain `core` only in explicitly navigation-only or semantic-search-specific examples.
  Rationale: `query_code` is registered by `extended`; the shipped plugin already uses `symbol|extended`; and `core` expands to `symbol|nlp|workspace`, which does not advertise `query_code`.
  Date/Author: 2026-07-15 / Codex
- Decision: Keep editor/LSP, agent MCP, CLI, and skills as separate named surfaces throughout the docs.
  Rationale: They have materially different execution contracts. In particular, VS Code can execute unsaved RQL through LSP, MCP accepts saved `.rql` only through `query_file`, and skills alone expose no tools.
  Date/Author: 2026-07-15 / Codex
- Decision: Deliver the broader transformation as small, independently validated and committed milestones on the existing detached checkout without creating or switching branches.
  Rationale: The repository instructions require checkpoint commits during an ExecPlan and prohibit branch creation or switching unless explicitly requested.
  Date/Author: 2026-07-15 / Codex

## Outcomes & Retrospective

The MCP/RQL contract, persona routing, capability matrix, evaluator journeys, production rule workflow, agent safety decision rule, and known correctness-drift fixes are complete. `mcp.md` now answers availability at first contact, the packaged and manual agent-host setup paths agree on `symbol|extended`, every agent-facing page distinguishes MCP from skills and verifies both inline JSON and saved RQL, and the editor pages clearly identify unsaved RQL execution as an LSP feature. The landing page routes first to Choose Bifrost; that page selects analysis and interface before installation, and the adjacent capability matrix records language-specific precision and hard product boundaries. A checked-in Python fixture gives CLI, agent MCP, and VS Code readers the same executable result. Static-analysis builders now have an end-to-end workflow and exhaustive result-variant contract, while agents have explicit rules for diagnostics, truncation, proof, provenance, and claim wording. The Rust version, traversal semantics, public usage-tool names, and Python result variants now match the implementation and have focused drift checks. Astro check/build, whitespace validation, executable query parsing, cross-language tutorial coverage, evaluator fixture execution, direct CLI parity, and desktop/mobile rendered previews pass. Trust and reproducibility guidance remains next.

## Context and Orientation

The documentation site is an Astro Starlight project under `docs/`. Its navigation is declared in `docs/astro.config.mjs`; public pages live under `docs/src/content/docs/`; and `npm --prefix docs run check` plus `npm --prefix docs run build` validate content and production routing. The repository may not have `docs/node_modules` in a fresh worktree, so an existing compatible dependency directory may be copied from another local Bifrost checkout, or dependencies may be installed from `docs/package-lock.json`, before validation.

Model Context Protocol, abbreviated MCP, is the process protocol through which agent hosts call Bifrost tools. `src/mcp_extended.rs` declares the `query_code` MCP schema. Its `query_file` field accepts a workspace-relative `.rql` or `.json` path and is exclusive with inline JSON query fields. `src/searchtools_service.rs`, in `SearchToolsService::decode_query_code_input`, enforces that contract and lowers saved RQL to the canonical JSON-shaped `CodeQuery`. The `core` MCP composition omits `extended` and therefore omits `query_code`; `symbol|extended` and `searchtools` include it. The shipped plugin proves the intended agent default in `plugins/bifrost-agent/mcp.json`.

Rune Query Language, abbreviated RQL, is the human-friendly S-expression syntax that lowers to canonical JSON `CodeQuery`. The CLI can execute inline JSON with `--tool query_code`, interactive RQL in its read-evaluate-print loop, and saved RQL or JSON with `--query-file`. MCP does not accept inline RQL text; it accepts inline canonical JSON or a saved workspace `.rql`/`.json` path through `query_file`. The VS Code Play action is a separate language-server path that accepts the current editor buffer, including unsaved text.

Agent skills are instruction files that teach a host when and how to use tools. Installing a skill does not itself start MCP or expose any Bifrost tool. Each host page must preserve this boundary and tell readers to start a new chat or session when the host loads MCP configuration only at session creation.

The main pages for the first milestone are `docs/src/content/docs/mcp.md`, `codex.md`, `claude-code.md`, `cursor.md`, `zed-mcp.md`, `amp.md`, `antigravity.md`, `agents.mdx`, `rune-query-language.md`, `rql-vscode.md`, and the MCP subsection of `vscode.md`. Later routing begins in a new page added to `docs/astro.config.mjs`, while capability evidence comes from the language adapters and existing language tutorials rather than marketing-level claims in `overview.md`.

## Plan of Work

First, make `docs/src/content/docs/mcp.md` the authority for interface availability. Lead with a query-capable `symbol|extended` command, retain a clearly labelled navigation-only `core` alternative, add the six-row availability matrix, and explain `query_file` exclusivity. Update every agent-host page so its setup and validation agree with that contract. Query-capable validation must prove that `query_code` is advertised, then execute both a minimal inline JSON query and a checked-in saved `.rql` query. Clarify on the RQL and VS Code pages that editor execution is LSP functionality and does not establish MCP availability. Update `resources/agent-guidance/bifrost-agents.md` only in the later result-safety milestone so generated skill bundles can be regenerated and validated together.

Second, create `docs/src/content/docs/choose-bifrost.md` and place it first in the Start navigation. Route questions about known symbols, structural shapes, concept search, literal text, editor navigation, agent tools, and library embedding to the correct surface. Add a capability page or a clearly bounded section linked from that route. For every supported language, describe structural matching, exact references, resolved calls and receivers, proof status, named arguments, imports, hierarchy, and external-dependency boundaries. State globally that control-flow graphs, points-to analysis, alias analysis, and general data-flow analysis are not provided. Verify every non-uniform cell against implementation or executable tests.

Third, create a reproducible evaluation fixture inside the repository or document an exact generated fixture with no unexplained `./code-query-toy` dependency. Add ten-minute CLI, MCP, and VS Code journeys that use the same source and query so readers can compare interfaces. Each journey must state prerequisites, exact commands or clicks, expected results, and what the exercise does and does not prove. The MCP journey must include an inline JSON call and a saved `.rql` `query_file` call.

Fourth, add a production-oriented static-analysis rule guide and a separate agent-result-safety guide. The rule guide begins in RQL, inspects canonical JSON, pins `schema_version`, executes through supported integration surfaces, consumes all current result variants, handles diagnostics and budgets, adds a fixture regression, and describes CI/reporting integration without claiming an unavailable stable API. The safety guide gives a concrete decision rule: never claim completeness until `truncated` is false, diagnostics have been inspected, proven and unproven edges have been distinguished, and `provenance_truncated` has been checked. Link it from host setup and agent guidance.

Fifth, correct documentation drift as source-backed edits: use the current crate version or a version-independent dependency command where appropriate; describe path-local cycle detection and alternate provenance accurately; replace nonexistent generic `scan_usages` recommendations with the public mode-specific tools. Add focused text or docs tests where they protect a user-visible contract without merely mirroring registry order.

Finally, add pages that explain evaluation methodology and current evidence, workspace and model data boundaries, how to cite Bifrost and preserve query/schema/version metadata, and how to reproduce an analysis. Avoid fabricating benchmark or accuracy results; where no published measurement exists, say exactly what the engine structurally guarantees and identify the evidence gap. Render the site, inspect the new first-contact route and representative desktop/mobile layouts, and fix navigation, table overflow, broken links, or ambiguous wording before closing the plan.

## Concrete Steps

Run all commands from `/Users/dave/.codex/worktrees/1a41/bifrost`.

Before edits, keep the checkout current and confirm its state:

    git fetch
    git rebase origin/master
    git status --short --branch

The expected current state for this execution is detached `HEAD` at `d7285eea` with no working-tree changes before the ExecPlan is added.

After each documentation milestone, validate exact terms and site structure:

    rg -n -- '--mcp core|"core"' docs/src/content/docs
    npm --prefix docs run check
    npm --prefix docs run build
    git diff --check

The first command may retain `core` only where nearby prose labels it navigation-only or the page specifically documents semantic search. Both npm commands must exit zero. The build should report generated pages under `/bifrost/` without broken-link warnings.

Inspect the rendered site after significant navigation or layout changes:

    npm --prefix docs run dev -- --host 127.0.0.1

Open the printed local URL, verify the Start route, tables, callouts, cross-links, and code blocks, then stop the server. Record the active port because stale Astro processes can otherwise make an old build appear current.

At each completed milestone, update this plan, stage only files changed for that milestone, and create a multiline checkpoint commit explaining why the user journey changed. Do not push or create a branch unless the user asks.

## Validation and Acceptance

The MCP contract milestone is accepted when a reader can answer all four questions from `mcp.md` without following a buried reference link: whether `query_code` is present, whether inline JSON is accepted, whether inline RQL is accepted, and whether saved `.rql` is accepted. Every query-capable host page must use or identify `symbol|extended`, distinguish skills from MCP, and describe a smoke test that proves `query_code` rather than only `get_summaries`.

The routing and capability milestone is accepted when each of the four target personas can begin at "Choose Bifrost" and reach one recommended interface, one capability/limitation statement, and one executable next step in at most two links. Language-specific claims must be explicit enough that a reader can reject Bifrost for an unsupported CFG, points-to, alias, or data-flow requirement without reading implementation source.

The evaluator milestone is accepted when a clean reader can reproduce the fixture, run the same structural query through CLI and agent MCP, run it from VS Code, and compare expected file/range results. No command may depend on an unexplained local directory.

The builder and safety milestone is accepted when an integration guide handles every current result variant and when an agent following the safety checklist cannot honestly turn a truncated or diagnostic-bearing result into an unqualified "all" or "none" claim.

The full plan is accepted when `npm --prefix docs run check`, `npm --prefix docs run build`, and `git diff --check` pass; the rendered first-contact pages have been visually inspected; known drift is corrected; and trust/reproducibility claims distinguish published evidence from current gaps.

## Idempotence and Recovery

Documentation edits, searches, checks, and builds are safe to repeat. If dependencies are absent, use the lockfile-compatible local dependency tree or install from the lockfile; do not modify dependency versions merely to make the docs build. If Astro is already running, identify its actual port and process before trusting a browser preview. If a milestone check fails, leave the plan's progress item split into completed and remaining work, fix the root cause, and rerun that milestone's exact command before committing.

Because this checkout is detached, commits remain reachable from the worktree but are not pushed automatically. Record each commit hash in `Outcomes & Retrospective`. Do not create a branch, switch branches, or rebase after milestone commits unless the user explicitly expands authorization.

## Artifacts and Notes

The authoritative availability matrix to preserve is:

| Configuration or surface | `query_code` | Inline JSON | Inline RQL | Saved `.rql` |
| --- | --- | --- | --- | --- |
| MCP `core` | No | No | No | No |
| MCP `symbol|extended` | Yes | Yes | No | Yes, through `query_file` |
| MCP `searchtools` | Yes | Yes | No | Yes, through `query_file` |
| CLI | Yes | `--tool query_code` | REPL | `--query-file` |
| VS Code RQL Play action | Separate LSP path | No | Yes, including unsaved text | Yes |
| Skills without MCP | No tools exposed | No | No | No |

The source evidence is `src/mcp_extended.rs` for the MCP schema, `SearchToolsService::decode_query_code_input` in `src/searchtools_service.rs` for file decoding and exclusivity, and `plugins/bifrost-agent/mcp.json` for the shipped query-capable composition.

## Interfaces and Dependencies

This work changes public documentation and agent guidance, not Rust runtime interfaces. It must describe the existing `query_code` MCP input faithfully: either inline canonical JSON fields including `match`, or exactly one `query_file` string naming a workspace-relative `.rql` or `.json` file. No docs example may send raw inline RQL to MCP.

The site depends on the versions pinned by `docs/package-lock.json` and the scripts in `docs/package.json`. Use Starlight's supported Markdown/MDX syntax and existing site styles; add custom CSS only if a user-facing table or journey cannot remain usable with Starlight defaults.

Plan revision note (2026-07-15): Created the initial self-contained plan after verifying the handed-off review against current `master`. The milestones prioritize the incorrect MCP/RQL setup contract, then build persona routing, reproducible evaluation, safe integration, drift correction, and trust guidance on that foundation.

Plan revision note (2026-07-15 09:53Z): Marked the MCP/RQL milestone complete after aligning all agent-host pages and passing `npm --prefix docs run check`, `npm --prefix docs run build`, `git diff --check`, and the focused executable query-doc test. Recorded the reusable language-neutral smoke query and left persona routing as the next milestone.

Plan revision note (2026-07-15 09:59Z): Marked persona routing and the capability matrix complete after the site generated 42 pages, cross-language tutorial coverage passed, and desktop/mobile previews confirmed usable routes and scroll-contained wide tables. Recorded and corrected the rendered Markdown pipe issue found during preview.

Plan revision note (2026-07-15 10:02Z): Marked the evaluator milestone complete after adding the published fixture, asserting its source/query blocks against the docs, executing the documented RQL and JSON end to end, verifying saved and inline CLI output, and generating the 43-page site. Left production rule-building and agent result safety as the next milestone.

Plan revision note (2026-07-15 10:10Z): Marked the builder and safety milestone complete after executable rule examples parsed, all host pages linked the safety contract, the reusable agent template gained the same decision rule, the 45-page site built, and desktop/mobile previews confirmed the long guide and wide safety table remain usable. Recorded the older three-variant Python prose as correctness drift for the next milestone.

Plan revision note (2026-07-15 12:14Z): Marked correctness drift complete after checking the prose against the current call traversal and six-variant result models, replacing both generic usage-tool references, formatting the Rust test corpus, and passing the focused documentation contracts plus Astro validation. Left evidence, data-boundary, citation, and reproducibility guidance as the final milestone.
