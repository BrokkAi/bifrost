# Performance regression benchmarks for the code-quality (SlopCop) tools


## Purpose

Bifrost ships a family of code-quality MCP tools (the "SlopCop" toolset, registered in
`crates/bifrost-mcp/src/mcp_slopcop.rs`): comment density, exception-handling smells, test-assertion
smells, structural clone smells, long-method/god-object smells, dead-code smells, secret-like code,
and git hotspots. Today only one of them, `report_dead_code_and_unused_abstraction_smells`, is
covered by the performance benchmark harness. If any of the others regresses in wall-clock cost —
say a clone-detection change makes `report_structural_clone_smells` quadratic on a real repo — no
automated signal exists; we find out when a user reports a slow tool call.

After this change, every code-quality tool has a daily, per-language performance benchmark scenario
in the existing `bifrost_benchmark` harness, each backed by a correctness oracle that proves the tool
returned a real, expected finding (a "true signal") on a pinned real-world repository, not an empty
or error report that happens to be fast. A regression in any tool on any covered language shows up
in the scheduled benchmark workflow's compare step against the blessed baseline, and locally via
`bifrost_benchmark run` + `bifrost_benchmark compare --strict`.


## Background: how the existing harness works

Everything below is in this repository; no external context is needed.

The benchmark harness is the `bifrost_benchmark` binary (`src/bin/bifrost_benchmark.rs`) driven by a
checked-in TOML manifest, `benchmark/targets.toml`. The manifest pins eleven real open-source repos
(one per supported analyzer language: java, go, cpp, javascript, typescript, python, rust, php,
scala, csharp, kotlin), each at an exact commit SHA, and declares per-repo "scenarios" — named
operations the harness times through a real MCP server session. The harness clones each repo into
`benchmark/.cache/repos`, starts the `bifrost` MCP server against it, runs each scenario
`warmup_iterations` (2) untimed then `measured_iterations` (10) timed times, asserts a per-scenario
correctness oracle on the tool result, and writes a JSON report to `benchmark/benchmark-output`.
`bifrost_benchmark compare` diffs a candidate report against the blessed baseline
`benchmark/baselines/ubuntu-latest.json` and, with `--strict`, exits nonzero on regressions.
The scheduled GitHub workflow `.github/workflows/benchmark.yml` runs validate, run, compare daily.

The code that matters:

- `src/benchmark/manifest.rs` — `BenchmarkScenario` enum (serde-renamed snake_case names, `ALL`
  array, `label()`, `tool_name()` mapping scenario to MCP tool name), `BenchmarkRepoTarget` with
  per-scenario probe-input fields, and `validate()` which rejects a repo that enables a scenario
  without the inputs that scenario needs, and rejects a manifest whose union of languages/scenarios
  no longer covers `required_languages`/`required_scenarios`.
- `src/benchmark/runner.rs` — `scenario_arguments()` builds the MCP tool-call JSON payload from the
  probe inputs; `assert_scenario_result()` is the per-scenario correctness oracle (for
  `dead_code_smells` it asserts every `dead_code_expect_report_contains` substring appears in the
  returned markdown report and every `dead_code_expect_report_absent` substring does not).
- `src/benchmark/report.rs` — report and compare model. Scenarios missing from a candidate are
  counted as `missing_candidate`; scenarios present only in the candidate are additions and do not
  fail compare, so new scenarios can land before the baseline is re-blessed.
- `tests/suite_bench_policy/benchmark_manifest.rs` — tests that load the checked-in manifest and
  assert coverage invariants (language union, scenario union, per-scenario input presence).
- `benchmark/README.md` — operator documentation for all of the above.

The existing `dead_code_smells` scenario is the model for a "verifiable true signal": its probe
inputs name exact fully-qualified symbols in the pinned repo that are genuinely dead, and the oracle
asserts stable substrings of the markdown report (the finding lines), plus absence of failure text
such as unresolved-symbol skips. Because the repo commit is pinned, these expectations are stable
forever.


## The code-quality tools to cover

All are registered in `crates/bifrost-mcp/src/mcp_slopcop.rs`, implemented under
`crates/bifrost-analysis/src/code_quality/`, and take project-relative `file_paths` unless noted:

- `report_comment_density_for_files` (`code_quality/comment_density.rs`): per-file tables of
  header/inline/span comment counts per top-level declaration. Works for every parsed language
  since PR #1357.
- `report_comment_density_for_code_unit`: same data for one symbol, input is `fq_name`.
- `report_exception_handling_smells` (`exception_smells.rs`): weighted heuristics over catch/error
  handlers. Supports Java, Go, C++, JS/JSX, TS/TSX, Python, Rust, PHP, Scala, C#, Ruby, Kotlin.
- `report_test_assertion_smells` (`test_assertion_smells.rs`): weighted heuristics over test
  bodies (no-assertion tests, tautologies, constant truths, ...).
- `report_structural_clone_smells` (`structural_clone_smells.rs`): token-shingle plus AST
  refinement clone detection. Language support is per-language modules (see
  `tests/suite_smells/*_structural_clone_smells.rs`); Kotlin is not yet supported (issue #1371).
- `report_long_method_and_god_object_smells` (`maintainability_size.rs`): long-method and
  god-object size metrics.
- `report_dead_code_and_unused_abstraction_smells` (`dead_code_smells.rs`): already benchmarked;
  its probe fields get migrated into the new generic shape (Milestone 1).
- `report_secret_like_code` (`secret_like_code.rs`): entropy/shape heuristics for secret-looking
  literals. Mostly language-independent over parsed files.
- `analyze_git_hotspots` (`git_hotspots.rs`): git-churn-based hotspot ranking. Language-agnostic;
  needs the repo's `.git` history, which the pinned clones have.

`analyze_diff` is excluded: it is a semantic diff tool rather than a per-file quality report, its
cost profile is dominated by the git object walk, and giving it a meaningful perf scenario deserves
its own design (endpoint selection per pinned repo). Record a follow-up issue instead of wedging it
in here.

Do not trust a static language-support matrix written in this plan; support drifts. The corpus
population milestone verifies support empirically per repo: a tool that reports "unsupported" for a
language simply does not get a probe in that repo, and the coverage test asserts the matrix we
actually shipped, derived from the manifest itself.


## Design

One new `BenchmarkScenario` variant per tool, so each tool keeps its own timing series in reports,
baselines, and the compare step:

    comment_density_files      -> report_comment_density_for_files
    comment_density_code_unit  -> report_comment_density_for_code_unit
    exception_smells           -> report_exception_handling_smells
    test_assertion_smells      -> report_test_assertion_smells
    structural_clone_smells    -> report_structural_clone_smells
    long_method_smells         -> report_long_method_and_god_object_smells
    secret_like_code           -> report_secret_like_code
    git_hotspots               -> analyze_git_hotspots

(`dead_code_smells` already exists and stays.)

Probe inputs do NOT get eight copies of the dead-code four-field pattern. Instead
`BenchmarkRepoTarget` gains one generic list, `[[repos.code_quality_probes]]`:

    [[repos.code_quality_probes]]
    scenario = "structural_clone_smells"
    file_paths = ["src/a.go", "src/b.go"]      # omitted for git_hotspots
    fq_names = ["pkg.Type.method"]             # only comment_density_code_unit (single entry) and dead_code_smells
    arguments = { min_score = 60 }             # optional raw knob overrides merged into the MCP payload
    expect_report_contains = ["`pkg.Type.method`"]
    expect_report_absent = ["(comment density unavailable; skipped)"]

Each probe is a `CodeQualityProbe` struct (serde, denies unknown fields via the manifest's existing
strictness). `arguments` is a `toml::value::Table` translated to JSON and merged over the
scenario's default payload, so per-tool tuning knobs (min_score, shingle_size, ...) need no new
schema fields ever. Validation rules, enforced in `BenchmarkRepoTarget::validate()`:

- a repo that enables one of the new scenarios must define at least one probe for it, and every
  probe's scenario must be enabled by the repo;
- every probe must define at least one `expect_report_contains` entry — an empty oracle is exactly
  the "fast because it did nothing" failure mode this work exists to prevent (`expect_report_absent`
  alone is not sufficient);
- `file_paths` are required for every scenario except `git_hotspots` (whole-repo churn) and
  `comment_density_code_unit`; `fq_names` is required for `comment_density_code_unit` (exactly one)
  and optional for `dead_code_smells`;
- probe `file_paths` participate in the same explicit-path pinning that `dead_code_file_paths` uses
  today for `--max-files` subset runs (see `src/benchmark/subset_workspace.rs`).

The existing `dead_code_*` fields on `BenchmarkRepoTarget` are migrated into
`code_quality_probes` entries with `scenario = "dead_code_smells"`, and the old fields are deleted
from the schema, `targets.toml`, validation, runner, tests, and README in the same milestone.
Backwards compatibility is explicitly not a goal in this repo.

In the runner, `scenario_arguments()` builds each new scenario's payload from its probe(s):
`file_paths` plus defaults (mirroring the bounded knobs the dead-code payload already sets), with
`arguments` merged on top. When a repo defines several probes for one scenario, the scenario issues
one tool call per probe per iteration and the oracle checks each probe's expectations against its
own call's report; timing covers the sum, which is fine because the probe set is pinned.
`assert_scenario_result()` gains one shared oracle helper: extract the markdown report string from
`structuredContent` (every SlopCop tool returns a `report` field plus flags), assert every
`expect_report_contains` present and every `expect_report_absent` absent, with error messages that
quote the missing/offending substring and the repo name.

`required_scenarios` in `benchmark/targets.toml` grows the new scenario names so the
manifest-level union check enforces that the corpus keeps covering every tool.
`BenchmarkScenario::ALL` grows the new variants (it feeds validation and the manifest tests).

Baseline note: new scenarios appear candidate-only in the daily compare, which reports them as
additions without failing. The blessed baseline `benchmark/baselines/ubuntu-latest.json` gets
re-promoted through the normal scheduled-workflow promotion path described in
`benchmark/baselines/README.md` after the first green scheduled run; nothing in this plan hand-edits
the baseline.


## Milestone 1: schema, runner, and validation support

Scope: all Rust-side support for the new scenarios, with the dead-code migration, landing green
without touching probe content for any new tool yet (the manifest keeps validating because no repo
enables a new scenario until Milestone 2).

Work, in order:

1. `src/benchmark/manifest.rs`: add the eight `BenchmarkScenario` variants (serde renames as the
   design table above), extend `ALL`, `label()`, `tool_name()`. Add `CodeQualityProbe` and the
   `code_quality_probes` field on `BenchmarkRepoTarget`. Implement the validation rules from the
   design section. Delete the four `dead_code_*` fields and rewrite dead-code validation in terms
   of probes.
2. `src/benchmark/runner.rs`: generalize `scenario_arguments()` and `assert_scenario_result()` as
   described; add the shared report-oracle helper; route `dead_code_smells` through it. Make the
   per-probe multi-call loop reuse the existing single-call iteration machinery in
   `src/benchmark/mcp_iteration.rs` rather than duplicating timing code.
3. `src/benchmark/subset_workspace.rs`: pin probe `file_paths` in subset runs where
   `dead_code_file_paths` is pinned today.
4. `benchmark/targets.toml`: migrate the existing dead-code fields (currently on the Python,
   JavaScript, TypeScript, PHP, and Scala repos) into `[[repos.code_quality_probes]]` entries.
   Do not add `required_scenarios` entries yet — that lands with corpus coverage in Milestone 2.
5. Tests in `tests/suite_bench_policy/benchmark_manifest.rs` (and a new sibling file if it grows
   past a few hundred lines): probe validation accepts/rejects the shapes above (missing
   expectations, probe for a disabled scenario, fq_name arity), the checked-in manifest still
   validates, and the dead-code migration kept the same effective payloads.
6. `benchmark/README.md`: replace the `dead_code_*` probe documentation with the generic probe
   documentation.

Acceptance: `cargo test --test suite_bench_policy` passes;
`cargo run --bin bifrost_benchmark -- validate --manifest benchmark/targets.toml` succeeds;
`cargo run --bin bifrost_benchmark -- run --manifest benchmark/targets.toml --repo django-python
--max-files 150` still runs the migrated dead-code scenario with its oracle green (exact repo name
per `targets.toml`; any migrated repo works). `cargo fmt` and
`cargo clippy --all-targets --all-features -- -D warnings` are clean (use the expanded clippy
command, not the alias, inside nested worktrees).


## Milestone 2: corpus population with verified true signals

Scope: for each of the eleven pinned repos, add probes for every code-quality scenario the repo's
language supports, each verified to produce a real finding on the pinned commit. At the end,
`required_scenarios` includes all eight new scenarios and the manifest coverage test asserts the
achieved language-by-tool matrix.

Method, per repo (work one repo per commit so progress is checkpointed):

1. Clone at the pinned commit via the harness cache (running any scenario populates
   `benchmark/.cache/repos`), or `git clone` + `git checkout <sha>` manually into that cache
   layout.
2. Pick probe files. Good probe files are large, real, and stable: for clone smells pick files the
   repo's own community flags as repetitive (generated-ish code, parallel API surfaces); for
   exception smells search for empty/log-only catch bodies; for test-assertion smells pick big test
   files; for long-method smells pick the repo's notorious god objects; for comment density any
   heavily-commented core file; for secret-like code prefer test fixtures with keys/tokens-shaped
   literals (never real secrets). Aim for a payload that takes meaningful but bounded time —
   roughly 5 to 30 files for the file-list tools, matching the existing scenarios' scale.
3. Run the tool against the workspace once (via `bifrost_benchmark run --repo <name>` with only
   that scenario enabled, or by driving the MCP server directly) and read the markdown report.
   Choose `expect_report_contains` substrings that quote a specific finding line — a fq-name or
   backticked symbol plus the smell label — not generic header text like "## Findings" that an
   empty report also contains. Choose `expect_report_absent` entries that pin known failure text
   (for example the unsupported/skipped placeholders each tool emits).
4. If a tool genuinely has no true signal in that repo (for example, no test files in the pinned
   slice for test-assertion smells), leave the scenario off for that repo and note it in the
   README's coverage notes, as done today for Ruby dead-code.
5. `git_hotspots` and `secret_like_code` and both comment-density scenarios should reach all eleven
   repos; `structural_clone_smells` reaches everything but Kotlin (#1371); the rest follow the
   empirically verified support.

Also in this milestone: extend the manifest coverage test so the matrix is enforced — for each new
scenario, assert the exact set of repo languages that define a probe for it, so silently dropping a
language's coverage fails the suite the same way the existing language-union check does.

Acceptance: `bifrost_benchmark validate` green with the grown `required_scenarios`;
`bifrost_benchmark run --repo <name>` green for every repo (full runs, not `--max-files`, at least
once locally); each new scenario's oracle demonstrably fails when its `expect_report_contains`
entry is perturbed (spot-check one probe per tool by temporarily editing the manifest — this proves
the oracle actually bites).


## Milestone 3: workflow, docs, and baseline promotion

Scope: the scheduled workflow picks up the new scenarios with no changes (it runs whatever the
manifest declares), so this milestone is verification and documentation. Update
`benchmark/README.md`'s probe-input list and coverage notes to the final matrix; update
`benchmark/baselines/README.md` if the promotion notes reference scenario counts. Trigger a manual
`workflow_dispatch` benchmark run (or wait for the cron), confirm the report includes the new
scenarios and compare reports them as additions, then promote the new baseline through the
documented promotion path. After promotion, a deliberate local regression (for example an
artificial sleep in one tool, never committed) should fail
`bifrost_benchmark compare --strict` against the new baseline — verifying end-to-end that the
regression signal is live.

Acceptance: scheduled workflow green with all scenarios present in its report artifact; blessed
baseline contains the new scenarios; `compare --strict` demonstrably fails on an induced
regression.


## Validation summary

- Unit/manifest tests: `cargo test --test suite_bench_policy` (featureless is fine; this suite is
  not gated on `nlp`).
- Manifest: `cargo run --bin bifrost_benchmark -- validate --manifest benchmark/targets.toml`.
- Per-repo: `cargo build --bin bifrost --bin bifrost_benchmark` then
  `./target/debug/bifrost_benchmark run --manifest benchmark/targets.toml --repo <name>`.
- Lints: `cargo fmt` and `cargo clippy --all-targets --all-features -- -D warnings`.
- Do not create ad-hoc `/tmp/bifrost-*` target dirs; use `scripts/with-isolated-cargo-target.sh`
  when isolation is needed.


## Decision log

- 2026-07-31: Excluded `analyze_diff` from this pass (different cost profile and input shape;
  follow-up issue instead). Excluded the `interactive-latency.toml` gate as the vehicle: the
  daily corpus harness is the regression suite the user pointed at, and per-language pinned repos
  are where true signals live; interactive-latency budgets can be added later for tools that prove
  latency-sensitive.
- 2026-07-31: Chose one scenario per tool plus a single generic probe table over per-tool field
  families, to keep per-tool timing series while stopping the four-fields-per-tool schema growth;
  chose to migrate and delete the `dead_code_*` fields in the same change since backwards
  compatibility is not a goal here.
- 2026-07-31: Required at least one `expect_report_contains` per probe so every scenario proves a
  true positive; scenario-off is the only representation for "no signal available in this repo".


- 2026-07-31 (Milestone 1): `BenchmarkScenario::ALL` stays at the original 12 entries during
  Milestone 1 and grows only in Milestone 2. `ALL` doubles as the default `required_scenarios` and
  the checked-in-manifest coverage assertion, so growing it before the corpus defines probes would
  fail validation for every manifest built with defaults. The design section's statement that `ALL`
  grows is therefore a Milestone 2 action.
- 2026-07-31 (Milestone 1): `git_hotspots` probes must pin `since_iso`/`until_iso` through the
  probe's `arguments` table: the tool's default window is "last 7 days from now", which a pinned
  commit's history ages out of. Documented in `benchmark/README.md`.

- 2026-07-31 (Milestone 2, early findings): the probes are already surfacing real latency. On
  google-gson (debug build, local): comment_density_files p50 17.3 s, structural_clone_smells
  p50 5.7 s, dead_code_smells p50 5.6 s, secret_like_code p50 5.5 s; and a dead-code probe against
  the heavily-used `com.google.gson.Gson.fromJson` exceeded the MCP request-wide time budget
  outright (the probe now targets `newBuilder` so the scenario stays deterministic). After the
  corpus lands, cross-check these against open latency issues and file/annotate per the project's
  five-second rule, with release-build timings.

- 2026-07-31 (Milestone 2, gin/fmt/ky findings): comment_density_files stays the slowest tool
  everywhere (gin p50 20.7 s over five small Go files; fmt exceeds the request budget on
  base.h/format.h-sized headers, so its probe pins args.h/color.h). fmt's macro-heavy C++
  (format-inl.h, os.h, os.cc, std.h, format.cc) fails to parse in exception_smells and comment
  density, so exception_smells is off for fmt. structural_clone_smells compares probes against
  workspace-wide peers and cold calls exceed the request budget on the fmt corpus even with a
  two-small-header probe, so the scenario is off for fmt and C++ clone coverage is an explicit gap
  until that latency bug is fixed. gin and ky have no secret-like findings, so secret_like_code is
  off there. Go testify assert.* calls are counted as zero assertions by test_assertion_smells
  (rows say `no-assertions` with assert.Len/Contains present) -- deterministic, so pinned as-is,
  but worth a product look. All of these belong in the follow-up issue sweep after the corpus
  lands.

- 2026-07-31 (Milestone 2, click/serde/fastroute findings): more latency evidence -- serde-json-rs
  dead_code_smells p50 17.6 s for a single zero-usage symbol (the usage scan dominates), and
  comment density stays 8-20 s wherever the probed file is large (click core.py exceeds the request
  budget outright, so its probes pin types.py). fastroute-php has genuinely clean exception
  handling and test assertions (zero findings at min_score 1), so those scenarios are off there;
  same for secret_like_code on click/serde/fastroute. PHP parity note: a file containing only
  free functions (fastroute src/functions.php) reports "(comment density unavailable; skipped)"
  even though it parses -- density seems to require a top-level class-like declaration in PHP;
  worth a product look alongside the Go testify note.

## Progress

- [x] Milestone 1: scenario variants, generic probes, runner payloads and oracle, dead-code
      migration, subset pinning, manifest tests, README probe docs. Validated 2026-07-31:
      `cargo test --test suite_bench_policy` (201 passed, includes the two new probe-shape tests),
      `cargo test --test suite_mcp_cli bifrost_benchmark` (12 passed, end-to-end run through the
      per-probe runner path), `bifrost_benchmark validate` on the checked-in manifest, `cargo fmt`,
      and `cargo clippy --all-targets --all-features -- -D warnings`.
- [ ] Milestone 2: probes for all repos/languages with verified true signals; coverage matrix test;
      `required_scenarios` grown.
- [ ] Milestone 3: workflow run verified, README coverage notes final, baseline promoted,
      induced-regression check performed.
- [ ] Follow-up issue filed for `analyze_diff` performance scenario design.
- [ ] Follow-up: once #1371 lands Kotlin clone smells, add the Kotlin clone probe and tighten the
      coverage test.
