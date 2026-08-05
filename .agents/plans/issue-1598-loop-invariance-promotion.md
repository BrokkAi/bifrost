# Promote the loop-invariance sort rule into the built-in pack (#1598)

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. It must be maintained in accordance with `.agents/PLANS.md` at the repository root.

## Purpose / Big Picture

The built-in `bifrost.code-smells` pack's `sort-in-loop` rule asks "is a sort call written inside a loop?". Measured against this repository (2026-08-04 triage, 284 findings), that question had a ~100% false-positive rate: in essentially every finding the sorted value was itself created inside the loop, so the work was inherent to the iteration. The question those rules want to ask is loop *invariance* of the operand — the same value, created once, re-sorted on every pass.

Issue #1474 (landed as PR #1604) made that question expressible: RQL schema 9 exposes lexical scopes, bindings with activation intervals, and a reaching-binding join, and RQLP gained `(assert-reaching :declared inside|outside :relative-to ...)`. It also shipped a working prototype of exactly this rule — `tests/fixtures/policies/loop-invariant-receiver.rqlp` with suite `tests/suite_bench_policy/policy_loop_invariance_prototype.rs` — proven for Rust against the true positive (the ready-set re-sort at `crates/bifrost-policy/src/composition/precedence.rs:135`) and the four dominant false-positive families from the corpus. It was deliberately kept out of the pack because the pack bar demands proven positive and near-miss fixtures for every claimed language.

After this change, the pack ships `bifrost.performance.loop-invariant-sort` (replacing the naive `sort-in-loop`), claiming exactly the languages whose fixtures prove it. Running the pack against this repository then reports zero sort-related false positives, the 143 sort-in-loop suppression records in `.bifrost/suppressions.json` are deleted rather than re-keyed, and the one real positive the rule was built around — the precedence.rs ready-set re-sort — is fixed at the root instead of suppressed, so the gate ends with no sort acceptances at all.

## Progress

- [x] (2026-08-05) Studied the prototype rule, its suite, the `assert-reaching` vocabulary (`:role receiver_position`, `:relative-to` capture), the occurrence-role registry, and the old `sort-in-loop` selectors.
- [x] (2026-08-05) Authored this plan.
- [ ] Milestone 1: promoted rule source in the pack with explicit schema pins; prototype suite re-pointed at the pack file; Rust fixtures passing unchanged.
- [ ] Milestone 2: per-language positive + near-miss fixtures for every claimed language; claim trimmed to what passes.
- [ ] Milestone 3: pack manifest (new entry, `sort-in-loop` removed, semantic hash, version 2.0.0), `builtin_policy_pack.rs` expectations updated, pack docs updated.
- [ ] Milestone 4: fix the precedence.rs ready-set re-sort at the root; drop all `sort-in-loop` suppressions; re-run the gate clean; validation sweep; PR.

## Surprises & Discoveries

- Observation: the old `sort-in-loop` selects Python/Java/TS by file glob (`where "*.py" ... (call :callee (name "sort"))`) rather than per-language filters, and does not claim JavaScript. The promoted rule uses explicit `language` filters throughout.
  Evidence: `crates/bifrost-policy/policy-packs/bifrost.code-smells/policies/sort-in-loop.rqlp` on master.

## Decision Log

- Decision: Replace `bifrost.performance.sort-in-loop` with a new id, `bifrost.performance.loop-invariant-sort`, rather than changing the analysis under the old id or shipping both.
  Rationale: The id should say what the rule proves; "sort-in-loop" names lexical containment, which is exactly the discredited question. Shipping both would double-report every true positive. Backward compatibility is explicitly not a requirement in this repository; the suppression file consequences are handled in Milestone 4.
  Date/Author: 2026-08-05, session with dbakereffendi.
- Decision: Receiver-form sorts only in this promotion (`x.sort*()` with `assert-reaching :role receiver_position`); argument-form sorts (`sorted(xs)` in Python, `Collections.sort(list)` in Java) are recorded as a future extension, not claimed.
  Rationale: The argument form needs a differently-rooted capture and role (`value_reference` on an argument), doubling the fixture matrix. The receiver form is what the prototype proved and what the 160-finding corpus consisted of. Claiming less and proving all of it beats claiming more.
  Date/Author: 2026-08-05, session with dbakereffendi.
- Decision: Initially claim Rust, Python, Java, and TypeScript; trim rather than force. JavaScript is attempted with the TypeScript fixtures' shapes and dropped from the claim if its adapter's reaching-binding evidence does not produce complete clean near-misses.
  Rationale: #1604's conformance suites prove the binding machinery for Java, Rust, Python, and TypeScript. The pack bar is per-language proof; a language without a passing near-miss set must not be claimed.
  Date/Author: 2026-08-05, session with dbakereffendi.
- Decision: Severity `warning` with the prototype's message, which states the deferred-body boundary in the message text.
  Rationale: Unlike the old review prompt (`note`), a violation here carries a proven claim: the receiver's reaching binding is outside the loop. The two boundaries from #1598 are carried verbatim: field projections abstain under both polarities (tested), and calls in deferred bodies are explicit lexical positives whose message says the match is lexical rather than proven per-iteration cost.
  Date/Author: 2026-08-05, session with dbakereffendi.
- Decision: Pack version 1.3.0 -> 2.0.0.
  Rationale: A rule id is removed; that is a breaking change to the pack surface under any reasonable semver reading.
  Date/Author: 2026-08-05, session with dbakereffendi.
- Decision: Fix `crates/bifrost-policy/src/composition/precedence.rs` (binary-search insertion into the ready set instead of re-sorting it each push) rather than suppressing the promoted rule's one true positive here.
  Rationale: The repository's own design philosophy prefers root-cause fixes; the insertion preserves the deterministic topological order that motivated the re-sort while removing the re-sort. The gate then ends with zero sort acceptances of any kind.
  Date/Author: 2026-08-05, session with dbakereffendi.
- Decision: The pack rule file *is* the tested file: `policy_loop_invariance_prototype.rs` re-points its `include_str!` at the pack path, keeps every existing test, and the standalone fixture `tests/fixtures/policies/loop-invariant-receiver.rqlp` is deleted.
  Rationale: The prototype suite's comment already states "the file that ships is the file that is tested"; after promotion the shipped file is the pack file, and a divergent copy would rot.
  Date/Author: 2026-08-05, session with dbakereffendi.

## Outcomes & Retrospective

Not yet started; to be written as milestones complete.

## Context and Orientation

Key artifacts, all at repository head (post-#1604 master):

- Prototype rule: `tests/fixtures/policies/loop-invariant-receiver.rqlp`. An `assertion`-type policy whose subject captures loops (`:capture "region"`) containing sort calls with a captured receiver (`:capture "target"`), and whose single assert is `(assert-reaching :id declared-inside :at "target" :role receiver_position :declared inside :relative-to "region")`. The *requirement* is declared-inside; the *violation* (finding) is a receiver declared outside — the invariant half.
- Prototype suite: `tests/suite_bench_policy/policy_loop_invariance_prototype.rs`. Rust-only: one true positive (modelled on precedence.rs:135), near-misses for loop-local declaration, iterator-adapter collect, and rebinding, a both-polarity abstention proof for field projections, and an explicit lexical positive for closure bodies. Every near-miss asserts `PolicyRunCompletion::Complete` before asserting zero findings.
- Old rule to be replaced: `crates/bifrost-policy/policy-packs/bifrost.code-smells/policies/sort-in-loop.rqlp` (naive containment match; glob-scoped `sort` for py/java/ts/tsx plus a Rust method-name regex).
- Pack manifest: `crates/bifrost-policy/policy-packs/bifrost.code-smells/manifest.json` (version 1.3.0). Each entry records path, stable id, semantic hash (verified at catalog load — a mismatch panics the pack tests and prints both hashes), category, supported languages, required capabilities, severity rationale, and remediation.
- Pack behavior tests: `tests/suite_bench_policy/builtin_policy_pack.rs` — per-language positive/near-miss source fixtures with expected (file, line) findings per rule id; `sort-in-loop` expectations exist for py/java/js/ts/rs sources.
- Suppression state: `.bifrost/suppressions.json` on master holds 184 records, 143 of them for `bifrost.performance.sort-in-loop`; `.bifrost/policy-scope.json` holds 3 directory entries. The finding-id re-key procedure (by policy, path, nearest line) from the 2026-08-04 session is not needed here: sort records are deleted, not migrated.
- The occurrence-role registry (`crates/bifrost-core/src/analyzer/structural/occurrences.rs`) defines `receiver_position`; per-adapter support is a total declared table, so an unsupported language yields `Inconclusive` (zero findings, incomplete) rather than silently clean — which is exactly what the claim-trimming in Milestone 2 watches for.

"Reaching binding" means: the binding (declaration) that is in effect for a name at a given source position, computed from scope rows and activation intervals rather than source order, so a rebinding inside a loop shadows an outer declaration of the same name.

## Plan of Work

Milestone 1 — move the rule into the pack. Create `crates/bifrost-policy/policy-packs/bifrost.code-smells/policies/loop-invariant-sort.rqlp` from the prototype with: the stable id `bifrost.performance.loop-invariant-sort`, explicit `:schema-version` pins on both the policy envelope and the `(rql ...)` selector (the prototype pins neither; the pack requires explicit versions — use the current policy schema and RQL schema 9), a `:description`, `:help-uri`, and `:tags` matching pack conventions, and the Rust method-name regex widened to the old rule's full family (`sort|sort_by|sort_by_key|sort_by_cached_key|sort_unstable|sort_unstable_by|sort_unstable_by_key`). Delete `tests/fixtures/policies/loop-invariant-receiver.rqlp` and re-point the prototype suite's `include_str!` at the pack path. The suite must pass unchanged.

Milestone 2 — per-language proof. Extend `policy_loop_invariance_prototype.rs` (renamed in place to `policy_loop_invariant_sort.rs`, with the harness generalized from `RustAnalyzer` to a per-language analyzer selection) with, for each of Python, Java, TypeScript, and JavaScript: a true positive (receiver declared before the loop, `.sort()` inside it), the loop-local near-miss, and the rebinding near-miss; field-projection abstention and deferred-body lexical positives where the language has a natural spelling (Python nested `def`, Java/TS/JS lambdas). Each near-miss asserts completion first. A language whose fixtures cannot reach `Complete` + clean is removed from the rule's `language` union and from the claim — record which and why in this plan.

Milestone 3 — pack integration. Update the manifest: remove the `sort-in-loop` entry, add `loop-invariant-sort` (category `performance`, supported languages from Milestone 2's outcome, required capabilities extended with the resolution/assertion capabilities the loader reports for it, severity rationale and remediation written for the invariance claim), bump the pack version to 2.0.0, and take the semantic hash from the pack test's mismatch report. In `builtin_policy_pack.rs`, delete the `sort-in-loop` expectations and its positive-fixture sort lines where they exist only to feed that rule (the near-miss files keep their sorts — they must now be clean for the *new* rule too, which the language suites already prove). Update `docs/src/content/docs/static-analysis-policies.md`'s built-in pack section: the pack no longer contains a naive sort prompt; describe the invariance rule, its boundaries, and the 2.0.0 version note.

Milestone 4 — close the loop on this repository. Rewrite the ready-set maintenance in `crates/bifrost-policy/src/composition/precedence.rs` to insert each newly-ready node at its sorted position (`binary_search` + `insert` on the descending-ordered vec) instead of pushing and re-sorting; its existing determinism tests must pass unchanged. Delete all 143 `bifrost.performance.sort-in-loop` records from `.bifrost/suppressions.json`. Build the CLI and run the pack over the workspace with `--evaluation-date` set to today: expect status clean with zero `loop-invariant-sort` findings and zero sort suppressions; any finding that does appear is triaged on its merits (a real invariant re-sort gets fixed or suppressed with a reason, an FP is a bug in the rule and blocks the PR). Run the full featureless validation (policy crate, `suite_bench_policy`, `suite_cross_language`, MCP crate, workspace clippy), then open the PR referencing #1598, noting that the parsing/file-read/serialization/regex rules deliberately stay naive pending their own argument-form extension.

## Concrete Steps

Work from the repository root on branch `dave/issue-1598-loop-invariance`.

    cargo test --test suite_bench_policy policy_loop_invariant
    cargo test --test suite_bench_policy builtin
    cargo test -p brokk-bifrost-policy
    cargo build --bin bifrost
    ./target/debug/bifrost --policy-pack bifrost.code-smells --evaluation-date <today> --fail-on warning --format json --output <scratch>/gate.json
    cargo fmt && cargo clippy --workspace --all-targets -- -D warnings

The semantic hash workflow: edit the rule, run the `builtin` pack tests, copy the "has semantic hash X but the manifest records Y" value into the manifest, re-run.

## Validation and Acceptance

Acceptance is behavioral. `bifrost --list-policies` shows `bifrost.performance.loop-invariant-sort` and no `sort-in-loop`. The promoted-rule suite proves, per claimed language, that the true positive fires with assertion evidence naming the binding and that each near-miss is complete and clean. The pack suite passes with the new manifest. On this repository the gate run exits 0 with no sort-related suppressions in `.bifrost/suppressions.json`, and the precedence.rs rewrite passes the existing composition tests. Reverting the precedence.rs fix makes the gate report exactly one `loop-invariant-sort` finding at that site — demonstrating the promoted rule catches the shape it was built from.

## Idempotence and Recovery

All steps are additive or mechanical and re-runnable. The manifest hash step is self-correcting (the test prints the expected value). If a claimed language cannot be proven, the recovery is to shrink the `language` union, the manifest claim, and this plan's Milestone 2 record — not to weaken a fixture. The suppression deletion is regenerable at any time from the gate report and the reasons recorded in git history.

## Artifacts and Notes

The FP corpus and its per-family breakdown are recorded on issue #1474 (comment of 2026-08-04) and in the commit "Suppress triaged pre-existing policy-gate findings" (`fdf1a132b`). The prototype's both-polarity abstention test is the template for how boundaries must be proven rather than assumed.

## Interfaces and Dependencies

No new Rust interfaces. The rule uses existing RQLP vocabulary only: `assertion` analysis, `assert-reaching` with `:at`, `:role receiver_position`, `:declared inside`, `:relative-to`, and RQL captures inside `(inside (loop ...) (call ...))`. The pack loader, manifest verification, suppression and scope machinery are unchanged.
