# Add concise, color-aware policy output

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document is maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Routine policy runs should be readable at a glance. After this change, the default human output will show one compact entry per finding with its severity, clickable source location, useful terminal symbol when the canonical finding retains one, and policy message, followed by the run summary. Users who need the complete audit record can request `--verbose`. Terminal stdout can use severity colors and Unicode status symbols, while pipes and files remain deterministic plain ASCII unless `--color always` is explicitly requested. Canonical JSON and SARIF output remain unchanged and exhaustive.

## Progress

- [x] (2026-07-21 18:08Z) Verified issue #1040, the clean matching feature branch, and synchronization with `origin/master`.
- [x] (2026-07-21 18:08Z) Diagnosed the renderer, CLI option flow, output sinks, documentation examples, and relevant tests.
- [x] (2026-07-21 18:20Z) Defined explicit human detail and resolved color options, then split concise and audit rendering without weakening diagnostics, escaping, or byte limits.
- [x] (2026-07-21 18:20Z) Added `--verbose` and `--color auto|always|never`, resolving terminal and `NO_COLOR` behavior only in the CLI.
- [x] (2026-07-21 18:20Z) Updated renderer, CLI, and documentation tests for concise, verbose, colored, redirected, file, incomplete, escaped, and bounded output; 25 focused tests pass.
- [x] (2026-07-21 18:31Z) Completed security, duplication, intent, operations, and architecture reviews and addressed every finding; post-review focused tests pass.
- [x] (2026-07-21 18:39Z) Ran formatting, focused post-review tests, and all-target/all-feature clippy; reviewed the final diff and recorded outcomes.

## Surprises & Discoveries

- Observation: The installed Bifrost code-navigation skill is present, but its MCP tools are not exposed to this task, so the documented shell fallback is required.
  Evidence: Tool discovery returned no `search_symbols`, `get_symbol_sources`, or related Bifrost tools.
- Observation: The CLI already contains a small terminal-color precedent in `src/bin/bifrost/code_query_repl.rs`, using `std::io::IsTerminal` and `NO_COLOR`, so no new color dependency is necessary.
  Evidence: `should_colorize_repl()` returns `stdout().is_terminal() && var_os("NO_COLOR").is_none()`.
- Observation: A feature-enabled isolated build compiles the Rust sources but cannot link the local Python extension symbols on this host.
  Evidence: `cargo test --features nlp,python --test policy_rendering --no-run` reached the final dynamic-library link and failed with unresolved `_Py*` symbols; the helper then removed its isolated target.
- Observation: `origin/master` advanced by one unrelated commit during implementation, and repository instructions prohibit rebasing without an explicit request.
  Evidence: `git rev-list --left-right --count HEAD...origin/master` reports `1 1`; the new master commit is `a283aabd` for CodeQuery scheduling.

## Decision Log

- Decision: Keep terminal detection and environment inspection out of the library renderer.
  Rationale: Passing resolved options makes library output deterministic and lets tests cover every style without depending on a process terminal.
  Date/Author: 2026-07-21 / Codex
- Decision: Preserve the existing finding and rule rendering as the verbose implementation, and build the concise path from shared location, escaping, diagnostic, completion, and summary helpers.
  Rationale: This retains the audit contract with the smallest compatibility risk and avoids duplicating safety-critical logic.
  Date/Author: 2026-07-21 / Codex
- Decision: Treat `--color` and `--verbose` as human-format options and reject their use with JSON or SARIF.
  Rationale: Machine formats must stay canonical and option combinations should not be silently ignored.
  Date/Author: 2026-07-21 / Codex
- Decision: Auto color is conservative on Windows, where terminal attachment alone does not prove virtual-terminal processing is enabled; `--color always` remains the explicit override.
  Rationale: Bifrost supports Windows, and plain output is safer than emitting visible escape sequences to legacy consoles.
  Date/Author: 2026-07-21 / Codex
- Decision: Address every specialist-review finding, including low-severity duplication and documentation observations.
  Rationale: Sharing terminal capability logic avoids drift, and updating internal tests prevents a full-suite regression hidden by integration-only validation.
  Date/Author: 2026-07-21 / Codex

## Outcomes & Retrospective

Issue #1040 is implemented and locally validated. Default human reports are compact and deterministic, `--verbose` preserves the complete audit record, and `--color auto|always|never` respects sinks, `NO_COLOR`, terminal capability, and explicit overrides. JSON and SARIF remain unchanged. Security, duplication, intent, operations, and architecture reviews completed; every finding was addressed. The focused renderer, CLI, docs, internal renderer, and color-decision tests pass, and `cargo clippy --all-targets --all-features -- -D warnings` passes in a clean isolated target. A feature-enabled test binary could not link because this host does not expose Python symbols to the Rust dynamic-library link, while featureless focused tests passed. The branch remains one commit behind the newly advanced `origin/master`; no rebase was performed because repository instructions require explicit authorization.

## Context and Orientation

`src/analyzer/policy/render/human.rs` turns a canonical `PolicyReportDocument` into bounded, terminal-safe text. `HumanRenderOptions` is currently an empty type, and `write_policy_human()` always invokes the detailed `write_finding()` and `write_rule_detail()` paths. The same module owns escaping, diagnostics, incomplete-run completion lines, and the final summary.

`src/bin/bifrost.rs` parses the one-shot policy CLI. `run_inner()` collects policy arguments, `run_policy_mode()` evaluates policies, `write_policy_stdout()` and `write_policy_output_file()` select the sink, and `render_policy_report()` dispatches among human, JSON, and SARIF. Only this layer knows whether stdout is a terminal or an output file was requested.

`tests/policy_rendering.rs` protects deterministic rendering, complete audit fields, escaping, explicit clean/non-clean completion, and serialized byte limits. `tests/bifrost_policy_cli.rs` protects argument parsing, exit statuses, stdout versus file behavior, and error handling. `tests/policy_docs.rs` executes the human examples embedded in `docs/src/content/docs/static-analysis-policies.md`, so the documented default example must change with the renderer. `docs/src/content/docs/cli.md` describes policy output options.

Here, “concise” means a scan-oriented human presentation and “verbose” means the existing exhaustive audit presentation. “Resolved color” means the renderer receives an explicit yes/no decision; it never reads terminal state or environment variables itself.

## Plan of Work

First, change `src/analyzer/policy/render/human.rs`. Replace the empty options type with public, non-exhaustive detail and color enums plus an options struct whose default is concise and plain. Route `write_policy_human()` through concise or verbose finding rendering. Leave report and run diagnostics prominent in both modes. In verbose mode, retain the current finding and rule output byte-for-byte except where shared formatting deliberately gains a selected style. In concise mode, render a compact two-line finding block: a severity marker and location with an optional safe terminal-symbol label on the first line, followed by the escaped policy message. Use only canonical `PolicyFinding` and `PolicyQueryResultRef` fields; do not inspect source text. Emit rule descriptors only in verbose mode, except that zero-finding output must still communicate failures through the existing diagnostic and completion paths. Apply ANSI sequences only to fixed renderer-owned markers, never around untrusted text in a way that could bypass escaping. Continue using `BoundedWriter` so escape and color bytes count toward the serialized limit.

Second, change `src/bin/bifrost.rs`. Add internal `PolicyColorMode` parsing for `auto`, `always`, and `never`, track `--verbose` and repeated-option errors, and include both options in policy-syntax and exclusivity handling. Resolve `auto` to colored only when stdout is a terminal, no output file is selected, and `NO_COLOR` is absent. Resolve `always` to colored even for redirected or file output, and `never` to plain. Pass explicit `HumanRenderOptions` through `run_policy_mode()`, the stdout/file helpers, and `render_policy_report()`. Reject human-only options with JSON or SARIF. Update help text.

Third, update tests and documentation. In `tests/policy_rendering.rs`, make the default assertion prove concise deterministic plain output and add an explicit verbose assertion containing the existing identities, evidence, proof, classification, schema, endpoint, and precedence details. Exercise ANSI styling explicitly and prove unsafe report text is still escaped and byte bounds still apply in both detail modes. In `tests/bifrost_policy_cli.rs`, cover default redirected stdout without ANSI, `--verbose`, `--color always`, `--color never`, `NO_COLOR` with auto, output-file defaults, invalid/repeated values, and rejection with machine formats. Preserve incomplete and failed-report assertions. Update `docs/src/content/docs/static-analysis-policies.md`, `docs/src/content/docs/cli.md`, and any affected doc-test expectations to describe and demonstrate the concise default and audit option.

Finally, format and validate. Inspect the exact diff for scope, run focused policy rendering and CLI tests with `--features nlp,python`, run documentation tests that cover the changed examples, then run the repository-required clippy command through `scripts/with-isolated-cargo-target.sh`. If practical, run the full feature test suite. Record commands and results below and update the retrospective.

## Concrete Steps

All commands run from `/Users/dave/.codex/worktrees/c169/bifrost`.

Edit the files named above using small patches. After renderer changes, run:

    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test policy_rendering

After CLI changes, run:

    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test bifrost_policy_cli

After documentation changes, run:

    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test policy_docs

Run final checks:

    cargo fmt
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python

The isolated-target helper must clean each temporary target automatically. If a focused command fails, fix the root cause and rerun that command before proceeding.

## Validation and Acceptance

A default policy CLI invocation whose stdout is captured must contain one compact finding entry and a completion summary, contain no `finding:` identity or `policy rule:` audit stanza, and contain no escape byte. The same invocation with `--verbose` must contain the complete existing audit fields. `--color always` must add severity ANSI styling; `--color never` must not. Auto color must be absent for captured stdout, output files, and when `NO_COLOR` is present. JSON and SARIF bytes and schemas must remain unaffected.

Incomplete, unsupported, and failed runs must still show their diagnostics and a non-clean completion line. Every untrusted string must continue to use terminal escaping. A byte limit one lower than each fully rendered human document must return `PolicyRenderError::SerializedReportLimit` and write no more than the configured limit.

The focused renderer, CLI, and documentation tests must pass with `--features nlp,python`. Formatting and clippy must pass without ignore annotations. The full feature suite should pass unless an unrelated environmental limitation is recorded here with concrete evidence.

## Idempotence and Recovery

All edits and test commands are repeatable. The CLI continues to buffer stdout and atomically replace output files, so rendering failure cannot leave partial machine output or clobber a destination. Do not retain isolated Cargo targets. If an implementation choice breaks verbose parity, restore only the affected helper structure with a focused patch; do not discard unrelated worktree changes.

## Artifacts and Notes

The worktree began clean on branch `1040-add-concise-color-aware-human-output-for-policy-runs`, with `HEAD`, `origin/master`, and the matching remote branch at `d49a4fe0` after fetching.

## Interfaces and Dependencies

`src/analyzer/policy/render/human.rs` must expose explicit public renderer configuration analogous to:

    pub enum HumanRenderDetail { Concise, Verbose }
    pub enum HumanRenderColor { Plain, Ansi }
    pub struct HumanRenderOptions { ... }

Exact field constructors may follow existing Rust API conventions, but callers must be able to select both dimensions without environment access. `HumanRenderOptions::default()` must remain deterministic, concise, and plain.

`src/bin/bifrost.rs` must keep the user-facing unresolved enum private:

    enum PolicyColorMode { Auto, Always, Never }

No external crate is required: use `std::io::IsTerminal`, `std::env::var_os`, fixed ANSI sequences, and the existing escaping and bounded-writing infrastructure.

Revision note (2026-07-21): Created the initial self-contained plan after issue diagnosis, before implementation, to establish renderer/CLI ownership and compatibility boundaries.

Revision note (2026-07-21 18:20Z): Recorded the completed implementation milestone, focused test evidence, and the host Python-linker limitation before review and final validation.

Revision note (2026-07-21 18:31Z): Recorded specialist-review fixes, conservative Windows behavior, current remote drift, and the successful post-review focused tests.

Revision note (2026-07-21 18:39Z): Marked the plan complete after clean all-feature clippy, summarized validation evidence, and documented the only host/remote limitations.
