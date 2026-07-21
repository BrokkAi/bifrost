# MCP property fuzzer (oracle-free contract fuzzing of the searchtools surface)


## Purpose

Bifrost's existing automated-analysis campaigns (the reference-differential runner, FIRD) audit one plane: whether the forward definition-resolution path and the inverse usage path agree about reference sites. A 2026-07-21 audit of live agent traffic (1,981 real tool calls from an 11-language P2T rollout) found six defects, and four of them were structurally invisible to FIRD because they are not reference-graph disagreements at all: a Scala class whose extracted source range stopped at its `@Inject()` constructor annotation (issue #1016), a `get_summaries` response that rendered a directory's children while simultaneously reporting that same directory `not_found` (#1017's ancestor), a `file#symbol` selector spelling that failed where the bare symbol name succeeded (#1018), and failure responses that carried no actionable hint or asserted that in-workspace symbols were "external" (#1015, #1019).

This plan builds the complementary instrument: a fuzzer that drives the same MCP tool surface agents use, generates its queries from Bifrost's own index, and checks self-consistency properties that need no external ground truth. Because every violation is self-evident from the responses in hand — no LLM judging, no human labeling, no VM rollouts — an autonomous coding agent can run it in a loop, shrink and deduplicate findings, file issues, and keep going until a full corpus pass produces no new failure signatures. That is the operating model: hand this plan to an agent and say "keep going until you run out of bugs."

After this change, a contributor can run one command against any corpus repository and receive a JSONL ledger of contract violations, each with a minimal reproduction (tool name, exact arguments, the offending response excerpt, and the invariant it violates), and can rerun any single finding in isolation to confirm it.


## Definitions

"MCP surface" means the tool descriptors and handlers Bifrost serves over the Model Context Protocol stdio server (`bifrost` with no arguments runs `--mcp searchtools`). The descriptor set is built in `src/mcp_core.rs::symbol_tool_descriptors(render_line_numbers)`. Note the surface is mode-dependent: with `render_line_numbers` false (the mode the P2T production harness uses) the server offers `get_definitions_by_reference` and `scan_usages_by_reference`; with it true, the `_by_location` variants replace them. The fuzzer must exercise both modes.

"Oracle-free" means the expected answer is not computed by any external authority (no LSP, no human labels). Each property is an internal-consistency claim: two responses from Bifrost itself, or one response and the index Bifrost itself built, must not contradict each other.

"Invariant" means one such machine-checkable property, identified by a short code (I1..I5 below).

"Failure signature" means the dedup key for a violation: `(invariant code, language, tool name, syntactic shape of the offending construct)` — for example `(I1, scala, get_symbol_sources, class-with-annotated-primary-constructor)`. Signatures exist so a corpus with ten thousand annotated Scala classes yields one ledger entry, not ten thousand.

"Shrinking" means reducing a failing case to the smallest reproduction that still violates the invariant — dropping unrelated batch entries, trimming context strings — before it is recorded.

"Ledger" means the append-only JSONL file of shrunk, deduplicated findings that survives across resumed runs, in the spirit of the FIRD runbook (`.agents/docs/reference-differential-runbook.md`). The ledger lives inside this repository under `.agents/plans/mcp-property-fuzzer/` and is committed, so findings are visible to the whole team rather than stranded on one operator's scratch disk.


## Repository orientation

The pieces this plan touches or imitates:

- `src/bin/bifrost_reference_differential.rs` — the FIRD CLI driver. The fuzzer gets a sibling binary, `src/bin/bifrost_mcp_property_fuzzer.rs`, and copies its argument conventions (corpus roots, resume, per-repo selection) where they fit.
- `src/reference_differential/mod.rs` — FIRD's engine and report schema; the model for a new `src/mcp_property_fuzzer/mod.rs`.
- `src/mcp_core.rs`, `src/searchtools_service.rs`, `src/tool_arguments.rs`, `src/searchtools_render.rs` — the descriptor definitions, the service layer that executes tool calls, argument parsing, and response rendering. The fuzzer calls the service layer in-process (like FIRD calls the analyzer) rather than spawning stdio servers, but it must construct calls exactly as the MCP handler would parse them, so selector-string handling and response rendering are genuinely under test.
- Corpus layout (identical to FIRD; see the runbook): clones under `/home/jonathan/Projects/brokkbench/clones`, which is a symlink to `/mnt/minasmorgul/repo-clones` (recreated 2026-07-21 after the previous `/mnt/T9` mount disappeared). Membership per language comes from `/home/jonathan/Projects/brokkbench/sft-tools-commits/<language>/<slug>.jsonl`; per-language priority is by task count derived from `/home/jonathan/Projects/brokkbench/tasks.py`'s task data (see Decision Log), not by `repos.csv::code_loc`. Durable run output — the ledger and any campaign state files — lives in this repository under `.agents/plans/mcp-property-fuzzer/`.


## The invariants

Every invariant below is annotated with the live defect that motivates it. When implementing, treat the motivating issues as executable acceptance tests: until the underlying bug is fixed, running the fuzzer on the named repository must reproduce the finding; after the fix, the finding must disappear.

**I1 — Range integrity.** For every symbol the index exposes: (a) the source range of a container symbol must contain the ranges of all its indexed members; (b) the text at the symbol's own range must contain the symbol's terminal name token; (c) `get_symbol_sources` for the symbol must return text identical to the file content at the reported range. Motivation: #1016 — `org.thp.thehive.connector.cortex.controllers.v0.JobCtrl` (repo TheHive-Project/TheHive) returns `start_line: 25, end_line: 26`, text `@Singleton\nclass JobCtrl @Inject()`, while its own methods are indexed at lines far below — a bare (a)-check over the corpus finds this class of bug in one pass with no tool calls at all.

**I2 — Selector-form equivalence.** For every indexed symbol, the selector spellings an agent plausibly writes — terminal name, fully qualified name, `path#terminal`, `path#qualified` — must either resolve to the same declaration or return an ambiguity/not-found response that is consistent across spellings (a strictly more specific spelling must never fail where a less specific one succeeds). Motivation: #1018 — in vuejs/core, `packages/runtime-core/src/hydration.ts#createHydrationFunctions` returned `symbol_not_found` from `get_definitions_by_reference` while bare `createHydrationFunctions` resolved. This recurred after #642 was closed, which is exactly why it belongs in a permanent harness rather than a one-off campaign.

**I3 — Cross-tool round-trips.** Three sub-checks. (a) If `get_summaries` lists symbol S under file F, then `get_symbol_sources(S)` must resolve, and its reported path must be F. (b) If `scan_usages_by_reference` reports a symbol as resolved (any status other than not-found/ambiguous), `search_symbols` for its terminal name must include that declaration among its results. (c) Self-contradiction: no response may both render content for a target and report that same target in its `not_found` list. Motivation for (c): a `get_summaries` call on doctrine/orm's `src/Query/Expr` rendered all thirteen member files and then appended `Not found: src/Query/Expr`; in production this contradiction sent an agent into a 483-call retry loop. (That specific bug is fixed at HEAD; the invariant keeps it fixed.)

**I4 — Diagnostic honesty.** A failure message must not assert a claim the index refutes. Concretely: if the response text matches phrases of the family "not indexed", "outside the indexed workspace", "external crate/module", then a `search_symbols` query for the terminal name of the failed selector must not return an in-workspace declaration with that name. Motivation: #1015 — tokio symbols wrapped in `cfg_rt!`/`cfg_coop!` macro blocks produced `unresolvable_import_boundary: … not indexed in this workspace` for `pub(crate)` items that plainly are in the workspace. (The fuzzer cannot decide whether macro-wrapped items should resolve — that is a resolution-quality question for FIRD's plane — but it can always catch the lie in the message.)

**I5 — Hint presence.** Every response with a failure status (not-found, ambiguous, invalid-location, and kin) must carry actionable next-step content: a candidate list, a corrective note, or a concrete suggested query. An empty refusal is a violation. Motivation: #1019 — C `file::struct tag` selectors (five occurrences in one rollout), TypeScript block-scoped closures, and Rust struct-field targets all dead-ended with a bare "no symbol matched" while other malformed shapes get rich hints. The check is syntactic (presence and non-triviality of hint fields/text per response schema), so it stays oracle-free.


## Query generation

Inputs come from the index, not from randomness, so coverage is exhaustive rather than probabilistic. For each corpus repository at its pinned commit: enumerate all indexed symbols (the same enumeration `search_symbols` draws from), all files, and all directories. From each symbol derive the I2 spelling set mechanically. For `get_definitions_by_reference`, derive `(symbol, context, target)` probes by taking a real line from inside the symbol's I1-verified range and a real identifier token on that line — which makes I1 a prerequisite: a truncated range would poison the probe, so ranges are validated first and range-invalid symbols are recorded under I1 and excluded from downstream probes. Batch shapes matter (the current descriptor takes `{"references": [...]}`): probe both single-entry and multi-entry batches, since single-versus-batch asymmetries are exactly the kind of surface drift agents hit.

Also probe the negative shapes real agents produced in traces, as a small fixed set: `file::struct tag` keyword-prefixed selectors, redundant `.__init__` package suffixes, file paths passed where symbols are expected. These are I5 probes — the expectation is not resolution but a non-empty corrective hint.

Two knobs bound runtime: a per-repository symbol cap (default a few thousand, sampled deterministically by hashing FQNs so reruns are stable) and per-language repo priority by task count (see Repository orientation). A full pass over one mid-size repository should take minutes, not hours; I1(a) alone is a pure index walk and should run corpus-wide routinely.


## Ledger, shrinking, and the run-until-dry loop

Each raw violation is shrunk (smallest batch, shortest context still failing), keyed by its failure signature, and appended to the ledger only if the signature is new for that run series. A ledger row records: signature, invariant, repository and pinned commit, tool, exact shrunk arguments (verbatim JSON), the relevant response excerpt(s), and for I1 the file-side evidence (expected range versus reported). Every row must be re-runnable in isolation via a `--rerun <ledger-line>` mode, mirroring FIRD's single-site rerun.

The autonomous loop an operating agent follows: run a corpus pass; for each new signature, rerun to confirm, then decide product-defect versus expected-behavior using the same discipline as the FIRD runbook ("a raw classification is a triage input, not proof"); file confirmed defects as GitHub issues on `BrokkAi/bifrost` (one per signature, carrying the shrunk repro verbatim) and record the issue number back into the ledger; fix or hand off; rerun the affected signature after any fix lands. Issue workflow specifics: `gh` is authenticated as `jbellis`; an issue is assigned to `jbellis` when the agent starts actively working its fix; fixes land directly on `master` (per repository AGENTS.md, no branches) with a thorough commit message — the commit message is the source of truth for what problem is being solved, so it must explain the defect, root cause, and fix in detail — containing `Fixes #N` so pushing to `origin/master` closes the issue; each fix is committed and pushed individually as it lands. The campaign is dry when two consecutive full passes add no new signatures. Campaign state (which repos, which pass, issue links) lives in this file's Progress section, per PLANS.md.


## Milestones

**M1 — Skeleton and I1 on one language.** Create `src/mcp_property_fuzzer/mod.rs` and `src/bin/bifrost_mcp_property_fuzzer.rs` with corpus/repo selection flags copied from FIRD's driver, plus `--invariants I1 --repo <slug>`. Implement I1 as a pure index walk. Acceptance: running against the TheHive clone reports the `JobCtrl` range violation (issue #1016) with correct evidence, and running against a small healthy repo reports nothing. Unit tests use fixture trees with a deliberately annotated-constructor Scala class.

    cd /home/jonathan/Projects/bifrost
    cargo run --release --bin bifrost_mcp_property_fuzzer -- \
      --clones-root /home/jonathan/Projects/brokkbench/clones \
      --repo TheHive-Project__TheHive --invariants I1 \
      --out .agents/plans/mcp-property-fuzzer/m1.jsonl

**M2 — All invariants, single repository, both render modes.** Wire the service layer in-process for both `render_line_numbers` modes; implement I2–I5 and the probe generator. Acceptance: on vuejs/core the I2 check reproduces the `file#symbol` inconsistency if it still exists at HEAD (or a fixture regression test demonstrates the check fires on a synthetic case); I3(c) and I5 pass on current HEAD (their motivating bugs are fixed) but each has a fixture test proving the check can fire.

**M3 — Corpus runner, ledger, resume, dedupe, shrink, rerun.** Bounded concurrency across repositories (reuse the pattern from `.agents/plans/concurrent-reference-corpus.md`), deterministic sampling, `--resume`, `--rerun`. Acceptance: a two-language corpus run resumes cleanly after an interrupt, produces a deduplicated ledger, and every ledger line reruns to the same violation.

**M4 — Acceptance campaign and issue workflow, tiered by task count.** First complete M1–M3 with whatever smoke tests make sense. Then run the campaign language-at-a-time in widening tiers drawn from the per-language task-count ranking: first the top 1 repository per language across all languages, then top 5, then top 10. Triage per the discipline above at each tier, file issues for confirmed signatures per the issue workflow in the Ledger section, fix confirmed defects, and commit and push each fix individually as it lands. Acceptance: the committed ledger under `.agents/plans/mcp-property-fuzzer/` covers every repo in the current tier, every confirmed signature has an issue link recorded in the ledger, and a follow-up pass after at least one fix shows its signature gone. A tier is complete only when its pass adds no new signatures; widening from top-1 to top-5 to top-10 happens tier by tier, not all at once.


## Validation

Beyond per-milestone acceptance: `cargo test` must stay green; new tests live beside the module (`tests/mcp_property_fuzzer.rs` for the engine, CLI tests mirroring `tests/bifrost_reference_differential_cli.rs`). Every invariant must have at least one fixture that makes it fire and one that proves it stays silent on healthy input — a checker that never fires is indistinguishable from a checker that is broken, so fixture-triggered firing is a hard requirement, not a nicety. When the runbook-style operational knowledge grows past this plan, split a `.agents/docs/mcp-property-fuzzer-runbook.md` out of it, as FIRD did.


## Surprises & Discoveries

Nothing yet recorded. This section is maintained per `.agents/PLANS.md`; unexpected behaviors, bugs, and insights discovered during implementation go here with short evidence snippets.


## Decision log

- 2026-07-21: Plan authored from the P2T trace-audit findings (issues #1014–#1019). Chose the oracle-free contract plane over an identifier-census differential as the first build because triage is mechanical (both contradicting responses are in hand), which is what makes the run-until-dry loop autonomous. The census differential (an over-approximating absolute leg that would catch symmetric resolution blind spots like #1014/#1015) is explicitly out of scope here and should become its own ExecPlan.
- 2026-07-21: Queries generated from the index rather than random strings: coverage should be exhaustive over what Bifrost claims to know, and malformed-input robustness is probed only through the I2 spelling set and the small fixed set of negative shapes agents actually produced in traces.
- 2026-07-21: Corpus root corrected at execution start. The plan's original path (`/home/jonathan/Projects/brokkbench/clones` → `/mnt/T9/repo-clones`) was stale because `/mnt/T9` is no longer mounted; the 12,816-clone corpus now lives at `/mnt/minasmorgul/repo-clones` (confirmed to contain all four acceptance repos). The `clones` symlink was recreated pointing at the new location so commands in this plan work verbatim. `/mnt/optane` is likewise gone, so durable output moved into this repository.
- 2026-07-21: Ledger location changed from `/mnt/optane/tmp/mcp-property-fuzzer/` to `.agents/plans/mcp-property-fuzzer/` inside this repository, committed to git. Rationale: the operator (Jonathan) wants findings visible to the rest of the team, and a local scratch path on one machine is neither durable nor visible.
- 2026-07-21: Ticket workflow confirmed as GitHub issues on `BrokkAi/bifrost`, as originally written. An earlier same-day revision briefly considered a local `tickets.md` because `gh` authentication was broken; the operator repaired `gh`/`git` credentials (authenticated as `jbellis`) and reverted to issues, with these specifics: assign the issue to `jbellis` when the agent starts actively working it; fixes commit directly to `master` with thorough commit messages (the message is the source of truth for the problem being solved) containing `Fixes #N`; push each fix to `origin/master` as it lands.
- 2026-07-21: Per-language repository prioritization changed from `repos.csv::code_loc` size ranking to task count per repository as derived from `/home/jonathan/Projects/brokkbench/tasks.py`'s task data, per operator direction ("for each language i want to prioritize by task count"). Rationale: task count reflects where agent traffic actually concentrates, so fuzzing effort follows real usage rather than repository size. The exact derivation (which tasks.py data structure yields the per-repo counts) will be recorded here when pinned during M3 implementation.
- 2026-07-21: Campaign scale structured into tiers. M1–M3 complete first with smoke tests; M4 then proceeds language-at-a-time in widening per-language tiers — top 1 repository by task count across all languages, then top 5, then top 10 — committing and pushing each fix as it goes. Rationale: bounds triage load early (every new signature gets individual attention) while still reaching broad coverage, and gives the team a steady stream of reviewed fixes rather than one giant batch.


## Progress

- [x] (2026-07-21) Execution environment prepared: `~/Projects/brokkbench/clones` symlink recreated at `/mnt/minasmorgul/repo-clones`; `.agents/plans/mcp-property-fuzzer/` ledger directory created; `gh` authenticated as `jbellis` with push access to `BrokkAi/bifrost`.
- [ ] M1: skeleton binary, corpus selection flags, I1 index walk, Scala fixture, TheHive acceptance run
- [ ] M2: in-process service wiring (both render modes), I2–I5, probe generator, per-invariant fixtures
- [ ] M3: corpus concurrency, deterministic sampling, resume, dedupe, shrink, --rerun, task-count ranking pinned and recorded in Decision Log
- [ ] M4 tier 1: top-1 repo per language by task count, full pass, triage, issues filed, fixes pushed
- [ ] M4 tier 2: widen to top-5 repos per language after tier 1 adds no new signatures
- [ ] M4 tier 3: widen to top-10 repos per language after tier 2 adds no new signatures


## Outcomes & Retrospective

Nothing yet recorded. Filled in at major milestones and at completion, per `.agents/PLANS.md`.


---

Revision note (2026-07-21): Updated at execution start to capture operator decisions made in conversation: corrected corpus paths (`/mnt/minasmorgul/repo-clones`, `/mnt/optane` gone), moved the ledger into this repository under `.agents/plans/mcp-property-fuzzer/`, confirmed the GitHub-issue ticket workflow with assign-to-`jbellis` and `Fixes #N` commit conventions, switched per-language prioritization from code_loc to task count per `tasks.py`, and structured M4 into top-1/top-5/top-10 tiers. All changes are recorded in the Decision Log; no technical content of the invariants, milestones M1–M3, or query generation was altered.
