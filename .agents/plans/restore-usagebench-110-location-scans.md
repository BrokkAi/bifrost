# Restore all planned usagebench location scans to 110/110

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan is maintained in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

The curated usagebench suite should report all 110 planned analyzer cases passing when run against Bifrost `master`. The migration from symbolic usage queries to `scan_usages_by_location`, followed by usagebench flattening Bifrost's proven and unproven results into one location set, exposed incomplete fixes: four Scala declarations could not be selected, one expected Go call existed only as an unproven candidate, a Java unproven candidate was incorrectly scored as an actual false positive, and one real CommonJS export-value reference was absent from the benchmark expectation. After this work, the exact local benchmark command reports `110 passed, 0 failed` while preserving Bifrost's proof tiers.

## Progress

- [x] (2026-07-12 16:38Z) Fetched Bifrost `origin/master` and rebased the current detached worktree to `3833adefd6ae51bcc1581dfbaae17a17ba2f890c`.
- [x] (2026-07-12 16:38Z) Fetched usagebench `origin/main` and rebased the existing `dave/usagebench-unproven-usage-locations` branch to `89a5bd845bbfe6d4f6a773c94842a589390f73da`.
- [x] (2026-07-12 16:38Z) Downloaded Actions run `29200146355` and reproduced its exact `104 passed, 6 failed` result locally.
- [x] (2026-07-12 16:55Z) Audited the attempted fixes since the original 100/110 run and reproduced both pre- and post-usagebench-`#46` outcomes against Bifrost `3833adef`.
- [x] (2026-07-12 17:03Z) Added focused service coverage for Scala object-member display selectors and repaired all four Scala location misses by accepting the existing display symbol for every language.
- [x] (2026-07-12 17:03Z) Reworked usagebench parsing and scoring to preserve proven and unproven locations separately: either tier satisfies expected recall, but only proven unmatched locations count as false positives.
- [x] (2026-07-12 17:03Z) Added the CommonJS export RHS as an expected `buildTask` usage because Bifrost deliberately and structurally proves that reference.
- [x] (2026-07-12 17:06Z) Ran the combined working-tree benchmark and observed `110 passed, 0 failed`.
- [x] (2026-07-12 17:18Z) Ran formatting, all-target/all-feature clippy, all 145 feature-complete `searchtools_service` tests, all 50 usagebench tests, and fixture validation.
- [x] (2026-07-12 17:19Z) Reran all usagebench cases from the committed implementations and recorded `110 passed, 0 failed` in `/tmp/usagebench-110-final.json`.
- [x] (2026-07-12 17:19Z) Committed the implementation milestones as Bifrost `35294d3e` and usagebench `0433cf7`, reviewed both committed diffs, and recorded the clean post-milestone review in this checkpoint.

## Surprises & Discoveries

- Observation: Bifrost issue `#632`, the Go pointer-receiver miss, is not one of the current failures.
  Evidence: run `29200146355` reports 104/110 with only Java, JavaScript, and Scala failures; `go-pointer-receiver-method-call` passes.
- Observation: usagebench commit `89a5bd8` did not create new analyzer locations; it began scoring both `files` and `unproven_files` returned by Bifrost.
  Evidence: `collect_scan_usage_locations` now iterates over both response groups and deduplicates them.
- Observation: the four Scala failures all have successful usage-to-declaration resolution but location scans return `not_found`.
  Evidence: the Actions artifact resolves declarations such as `example.Service$.build`, while the location request uses the source-facing selector `example.Service.build` and returns no candidates.
- Observation: usagebench `#46` did not improve the total pass count when isolated against the same Bifrost commit; it exchanged the Go false negative for a Java false positive.
  Evidence: usagebench `b355e99` against Bifrost `3833adef` reports failures for Go, JavaScript, and four Scala cases; usagebench `89a5bd8` reports Java, JavaScript, and the same four Scala cases. Both are 104/110.
- Observation: Go interface dispatch is intentionally unproven for a concrete implementation target.
  Evidence: Bifrost commit `1361358e` and its tests explicitly prevent signature-compatible interface receivers from becoming proven concrete-method usages while retaining them in `unproven_files`.
- Observation: the CommonJS export RHS is a proven lexical reference, not an unproven false positive.
  Evidence: Bifrost commit `ccb8fc8c` deliberately traverses the structured export assignment RHS and tests direct and aliased export values as proven usages.
- Observation: the desktop shell exposed two independent toolchain traps during CI-equivalent validation.
  Evidence: `cargo` and `rustc` resolved from `~/.local/bin`, while `clippy-driver` initially resolved from Homebrew and produced incompatible compiler metadata; explicitly preferring `~/.cargo/bin` fixed clippy. The macOS Python feature also required CI's `-undefined dynamic_lookup` Rust flags before the feature-complete tests linked.

## Decision Log

- Decision: Preserve proof tiers in usagebench instead of flattening `files` and `unproven_files`.
  Rationale: the expected Go call in issue `#632` is intentionally unproven, while the Java `makeAnonymous().handle` site is a different conservative candidate. An expected location may be satisfied by either tier for recall, but an unmatched unproven candidate must not be scored as a proven false positive.
  Date/Author: 2026-07-12 / Codex
- Decision: Treat the current failures as one burn-down plan with language-focused milestones rather than six isolated patches.
  Rationale: several attempted fixes changed the shared location selector surface, but Scala and JS/Java use different graph implementations. Shared audit and final validation prevent a fix for one language from undoing the others.
  Date/Author: 2026-07-12 / Codex

## Outcomes & Retrospective

The goal is complete. Usagebench now preserves the distinction between proven and unproven Bifrost locations, so the expected Go interface-dispatch candidate satisfies recall without turning an unrelated Java uncertainty into a false positive. Bifrost accepts its existing public Scala display selectors at location targets, restoring all companion-object, object-value, renamed-import, and extension-method cases. The JavaScript parity fixture now records the structurally proven CommonJS export RHS reference.

The final committed-state benchmark reports all 110 planned cases passing, with the pre-existing eight not-planned and two unsupported cases remaining in their separate reporting buckets. No analyzer graph fallback, source-text mini-parser, dependency, or public Bifrost response change was introduced. Post-milestone review found no further correctness, performance, path portability, or test-quality issue in the changed code.

## Context and Orientation

`usagebench` is a sibling Rust repository at `/Users/dave/Workspace/BrokkAi/usagebench`. Its `src/bifrost_runner.rs` starts Bifrost, calls location-based usage and definition tools, and compares normalized file-and-line locations with YAML expectations under `benchmarks/cases/`. The workflow run `29200146355` used usagebench commit `89a5bd8` and Bifrost commit `3833adef`.

In Bifrost, `src/searchtools.rs` implements `scan_usages_by_location`. It first selects the declaration at the requested source location, preserves a source-facing selector when available, and delegates to the language usage graph. The shared candidate expansion lives under `src/analyzer/usages/candidates.rs`. Scala extraction and resolution live under `src/analyzer/usages/scala_graph/`; Java and JavaScript/TypeScript have their own usage graph modules under `src/analyzer/usages/`. A proven hit has structured receiver, import, lexical, or inheritance evidence. An unproven hit is a structured AST-derived name candidate that could not be proved precise; it is useful for recall but must still exclude candidates contradicted by available structure.

The exact post-`#46` origin failures are `java-parity-concrete-implementation-method-call` with unproven extra `Runner.java:20`, `js-parity-commonjs-destructured-function-call` with proven extra `library.js:21`, and four Scala misses: `scala-companion-function-call`, `scala-object-val-access`, `scala-parity-import-alias-companion-method`, and `scala-parity-extension-method-call`. The controlled pre-`#46` run replaces the Java failure with `go-pointer-receiver-method-call`, proving that scorer flattening caused the swap.

## Plan of Work

First, inspect every relevant commit between the original location migration and `3833adef`, especially `68d9eeff` for selector forwarding, `1f5f6fd1`, `f5b5c9cb`, `edb092e2`, and `d6a0acf7` for Scala resolution, plus the Go, Ruby, Python, TypeScript, and JavaScript fixes that changed candidate classification. Compare each patch with the failing fixture and current regression tests. Record which fixes are complete and which encode an implementation-shaped special case.

For Scala, add location-surface tests using the shared inline project harness. The tests start from real declaration locations and exercise companion methods, object values, aliased companion methods, and extension methods. Repair selector identity at the declaration-to-graph boundary by accepting `display_symbol_for_target`, the existing language-aware public symbol representation, rather than adding another Scala-specific normalization path.

In usagebench `src/bifrost_runner.rs`, parse `files` and `unproven_files` into distinct sets. Compute missing expected locations from their union, because an explicitly expected conservative candidate is still useful recall. Compute unexpected locations from proven `files` only, because Bifrost has explicitly declined to claim an unproven candidate as actual. Serialize unproven observations separately in the report. Keep the Java analyzer behavior unchanged because it correctly labels the uncertain interface-return call as unproven.

In usagebench `benchmarks/cases/javascript-lsp-parity.yaml`, add the RHS `buildTask` token in `exports.buildTask = buildTask` as an expected usage. This is a structured lexical reference deliberately proved by Bifrost, not an uncertainty-tier artifact.

After each language milestone, run its focused graph tests and the related search-tools location tests. Review the diff for selector hacks, source-text parsing, unbounded graph scans, and regressions to the already-passing Go, Ruby, Python, and TypeScript cases. Commit the implementation and post-milestone review separately enough that the history explains the reason for each change.

Finally, run formatting, clippy with all features, feature-complete tests relevant to all changed modules, and the entire usagebench suite in working-tree mode. The final benchmark must report exactly 110 planned cases passed and zero failed.

## Concrete Steps

All Bifrost commands run from `/Users/dave/.codex/worktrees/2b24/bifrost`. Use `git show <commit> -- <paths>` and targeted `rg` searches to audit history and current code. Run focused tests with commands determined from the existing test targets, for example:

    cargo test --features nlp,python --test usages_scala_graph_test
    cargo test --features nlp,python --test searchtools_service <focused_test_name>

Run repository-wide checks before the final benchmark:

    cargo fmt
    cargo clippy --all-targets --all-features -- -D warnings

Run the final benchmark from the synced usagebench worktree. In this sandbox the editable detached worktree was `/tmp/usagebench-110`, which shares commit content with the existing branch commit `0433cf7`:

    cd /tmp/usagebench-110
    target/debug/usagebench run-bifrost benchmarks/cases --bifrost-repo /Users/dave/.codex/worktrees/2b24/bifrost --bifrost-working-tree --work-dir /tmp/usagebench-110-final --output /tmp/usagebench-110-final.json

The expected summary is:

    ran 110 planned case(s): 110 passed, 0 improved, 0 failed

## Validation and Acceptance

Acceptance requires behavior-focused tests rather than tests that merely assert registry membership or selector lists. The Scala service test must fail before the Bifrost change with `not_found` and pass after with the expected hit counts. The usagebench scorer test must prove that an expected unproven location satisfies recall while an unrelated unproven location is not reported as unexpected. The JavaScript fixture validator and full benchmark must prove that the export RHS is retained as a real usage.

Run `cargo fmt --check` after formatting and run clippy with `--all-targets --all-features -D warnings`. Because the default Cargo feature set skips `nlp` integration suites, the search-tools gate explicitly uses `--features nlp,python`. On macOS, mirror `.github/workflows/ci.yml` by setting `RUSTFLAGS='-C link-arg=-undefined -C link-arg=dynamic_lookup'` for that Python-feature test. The ultimate acceptance signal is a fresh working-tree usagebench report with totals `cases: 110`, `passed: 110`, and `failed: 0`; the eight not-planned and two unsupported reporting buckets remain outside those 110 planned cases.

## Idempotence and Recovery

The benchmark work directories and reports live under `/tmp` and may be deleted or replaced between runs without affecting either repository. Focused test commands and formatting are safe to repeat. During execution the Bifrost worktree was externally switched to the existing `632-go-location-usage-scan-misses-a-pointer-receiver-call` branch; it was rebased onto `origin/master` as requested and no new branch was created. The usagebench implementation was committed in a sandbox-writable detached worktree and cherry-picked onto the existing `dave/usagebench-unproven-usage-locations` branch. Do not reset, discard, or overwrite unrelated changes; stage only files named by this plan.

## Artifacts and Notes

The downloaded Actions report is `/tmp/usagebench-29200146355/run-29200146355.json`. The exact local origin reproduction is `/tmp/usagebench-repro-29200146355.json`. Both report:

    110 planned case(s): 104 passed, 6 failed

The origin SHAs are usagebench `89a5bd845bbfe6d4f6a773c94842a589390f73da` and Bifrost `3833adefd6ae51bcc1581dfbaae17a17ba2f890c`.

The controlled pre-`#46` report is `/tmp/usagebench-b355-3833.json`. The first combined passing report is `/tmp/usagebench-110-combined.json`, with totals `110 passed, 0 failed`.

The final report is `/tmp/usagebench-110-final.json` and records:

    {"cases":110,"passed":110,"failed":0,"notPlanned":8,"unsupported":2,"errors":0}

Validation evidence:

    cargo test --locked                         # usagebench: 48 library + 2 binary tests passed
    usagebench validate benchmarks/cases       # 23 benchmark case files validated
    cargo clippy --all-targets --all-features -- -D warnings
    cargo test --features nlp,python --test searchtools_service
                                                # 144 passed, 1 expensive smoke test ignored

## Interfaces and Dependencies

No new third-party dependency is expected. Changes should stay within the existing `scan_usages_by_location` request flow, declaration metadata and range helpers, language usage graph extractors/resolvers, and shared usage-candidate types. Preserve the public MCP response contract: each request returns `files` for proven locations, `unproven_files` for structured best-effort locations, and a status such as `found` or `not_found`.

Revision note (2026-07-12 16:38Z): Created the plan after syncing both repositories and reproducing Actions run `29200146355`; the plan separates the four Scala misses from the two newly scored unproven false positives while preserving the successful Go `#632` behavior.

Revision note (2026-07-12 17:06Z): Reframed the scorer milestone after the controlled pre/post-`#46` comparison proved that flattening proof tiers swapped Go and Java failures. Recorded the Scala display-selector fix, the intentional CommonJS export reference, and preliminary 110/110 evidence.

Revision note (2026-07-12 17:19Z): Closed the plan after CI-equivalent validation, committed-state 110/110 evidence, and post-milestone review. Added the Rust/clippy path mismatch and macOS PyO3 linker setup so the validation is reproducible.
