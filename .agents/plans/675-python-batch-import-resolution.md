# Avoid repeated Python import resolution in definition batches

This ExecPlan is a living document. Maintain it in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Python reference-differential batches currently resolve a typed receiver such as
`service.run()` by first collecting the cached local type facts and then calling the
general Python graph receiver resolver for `Service`. That general resolver asks the
import-analysis provider for all imported code units of the source file. On the
`googleapis__google-cloud-python` corpus, a live sample showed that path repeatedly
performing import binding and module-name filesystem work. After this change, direct
named imports use the definition batch's existing import binder before that fallback.
Repeated references keep their current definitions while avoiding that broad import
resolution work.

## Progress

- [x] (2026-07-14) Captured the post-PR #735 hotspot: batch scope facts are cached,
  but `python_receiver_type_unit -> resolve_receiver_type -> resolve_import_bindings`
  still dominates the Python corpus run.
- [x] (2026-07-14) Add a bounded per-file receiver-type cache and direct named-import lookup.
- [x] (2026-07-14) Add lifecycle, isolation, and cache-cap regression coverage.
- [x] (2026-07-14) Run `cargo fmt` and the focused default- and feature-enabled
  Python batch tests.
- [x] (2026-07-14) Rebase the checkpoint onto merged PR #750 and rerun the focused
  Python batch and integration tests.
- [ ] Run clippy and the complete `nlp,python` suite.
- [ ] Repeat the warmed Python differential smoke after addressing the remaining
  candidate-lookup hotspot identified by the latest runtime sample.
- [x] (2026-07-14) Reject a resolver-local content-qualifier cache after profiling:
  candidate rows span distinct Python files, so it did not reduce
  `python_module_name` work.
- [ ] Run the full 1,000-file / 10,000-site / 1,000-target acceptance record when
  disk preflight permits, then record the result and close #675 only if it completes.

## Surprises & Discoveries

- Observation: The prior full corpus run was stopped after 49 minutes without a JSONL
  record because free disk dropped from 140 GiB to 72 GiB.
  Evidence: `/private/tmp/bifrost-675-postfix.sample.txt` puts the sampled work under
  `resolve_import_bindings` and `python_module_name`, not `scope_facts`.

- Observation: Passing explicit Homebrew Python 3.14 framework flags and
  `MACOSX_DEPLOYMENT_TARGET=26.5` fixed the local PyO3 link mismatch; the focused
  feature-enabled tests passed. That fresh feature build reduced free disk to 24 GiB,
  so the subsequent unrelated filtered test-binary sweep was interrupted.
  Evidence: `MACOSX_DEPLOYMENT_TARGET=26.5 PYO3_PYTHON=/opt/homebrew/bin/python3.14`
  with `-lpython3.14` completed the three batch tests before the interrupt.

- Observation: After PR #750 added an ephemeral differential-cache mode, an
  ephemeral smoke spent its time rebuilding the whole corpus and produced no JSONL,
  so it is not suitable for the plan's required warmed measurement. The subsequent
  persisted smoke was stopped after a runtime sample found no
  `resolve_import_bindings`, but found `python_module_name` called from
  `QueryResolver::resolve_rows` / SQL definition-candidate lookup, with filesystem
  `stat` work still prominent.
  Evidence: `/private/tmp/bifrost-675-warmed-smoke.sample.txt`.

- Observation: `QueryResolver::resolve_rows` already batches liveness validation by
  unique file. A local `(content_qualifier, file)` hydration cache passed its focused
  unit test but did not move the 20-file smoke: `python_module_name` remained the
  dominant child of `resolve_rows` because short-name candidate queries returned
  mostly distinct Python files. The experiment was reverted.
  Evidence: `/private/tmp/bifrost-675-warmed-smoke-postfix.sample.txt`.

## Decision Log

- Decision: Cache receiver type results only in `PythonDefinitionContext`, keyed by
  source-file context, trimmed type text, and the indexed-self-file flag.
  Rationale: The analyzer generation is immutable during a definition batch, while
  per-file context removal after the final lookup prevents workspace-lifetime state.
  Date/Author: 2026-07-14 / Codex

- Decision: Prefer binder-derived named imports and same-file classes before the
  shared graph resolver; preserve the shared resolver as the fallback.
  Rationale: The binder carries exact structured import facts. It resolves ordinary
  `from module import Type as Alias` without widening import scope or replacing
  structured resolution with text matching.
  Date/Author: 2026-07-14 / Codex

- Decision: Limit each receiver-type cache to 512 entries and bypass inserts after
  the limit while continuing exact uncached resolution.
  Rationale: The bound is deterministic and keeps only compact type strings plus
  `CodeUnit` results. It stores neither source nor tree state and cannot alter lookup
  outcomes when a large request exceeds the bound.
  Date/Author: 2026-07-14 / Codex

- Decision: Do not retain a QueryResolver hydration cache.
  Rationale: Its key had low reuse in the target corpus and preserved the costly
  one-per-candidate Python module-path stat. The root cause is broad short-name
  candidate retrieval, which needs path-aware filtering before hydration.
  Date/Author: 2026-07-14 / Codex

## Outcomes & Retrospective

The implementation is complete and the new focused behavior is covered. A
`PythonDefinitionContext` now owns a 512-entry mutex-protected cache of `Option<CodeUnit>`
values keyed by trimmed type text and the existing self-file mode. It consults the
binder's exact named import map, then same-file classes, and only then takes the
unchanged shared graph-resolver fallback. The context remains removed after its last
request, so no cache survives the batch-file lifecycle.

The full validation and acceptance benchmark remain blocked. Disk was reclaimed to
244 GiB before the renewed smoke and held above 200 GiB, so capacity is no longer the
gate. Instead, the new sample proves that a distinct Python module-name / SQL
candidate-lookup path remains hot. A cache attempt confirmed that candidate rows are
mostly from distinct files. Do not close #675 or start the full limits until Python
definition candidates can be narrowed by path-derived FQN before row hydration.

## Context and Orientation

`src/analyzer/usages/get_definition/mod.rs` owns `DefinitionBatchContext`, which
groups multiple public definition lookup requests and removes a Python context after
the final request for its file. `src/analyzer/usages/get_definition/python.rs` owns
the Python-specific forward lookup. Its `PythonDefinitionContext` already stores
named-import facts from `PythonAnalyzer::import_binder_of` and same-file declarations.

The shared `python_graph::resolver::resolve_receiver_type` is used by usage analysis
as well as definition lookup. It may call the import-analysis provider, so it must
not gain a definition-batch-specific cache. The new cache belongs exclusively in the
definition context and must leave the shared resolver and public capability traits
unchanged.

## Plan of Work

Add a private receiver-type resolver to `PythonDefinitionContext`. Its key is the
trimmed requested type name and `target_self_file`. On a cache miss, first look up the
name in the context's named imports and resolve that fully qualified name through the
existing `python_class_for_fqn` helper. Then look in same-file declarations. Only if
both exact structured paths fail may it call the existing
`resolve_python_receiver_type` fallback. Store both `Some(CodeUnit)` and `None` while
the 512-entry limit has capacity; after the limit, compute without inserting.

Thread this context method through inferred typed receivers, class-name receivers,
callable resolution, and callable-return resolution. Add test-only counters for cache
misses and generic fallback calls. Preserve current per-file context removal.

## Concrete Steps

From the repository root:

1. Update `PythonDefinitionContext` and its callers, then add focused tests in
   `src/analyzer/usages/get_definition/mod.rs` and `tests/get_definition_test.rs`.
2. Run `cargo fmt`.
3. Run focused library and integration tests with a single matching Python toolchain.
   On this host, set `PYO3_PYTHON` to the Homebrew Python that supplies the linker
   flags rather than mixing `/usr/bin/python3` with Homebrew libraries.
4. Run `cargo clippy --all-targets --all-features -- -D warnings` and
   `cargo test --features nlp,python`.
5. Build `bifrost_reference_differential` in release mode and run a warmed smoke on
   `/Users/dave/Workspace/test-repos/googleapis__google-cloud-python` with smaller
   file, site, and target limits. Preserve the JSONL report in
   `.agents/docs/reference-differential/`.

## Validation and Acceptance

The focused batch test must resolve two references on the same typed imported receiver,
build scope facts once, miss the receiver-type cache once, avoid the generic fallback,
and leave `python_contexts` empty. A multi-file batch using the same local type name
for two different imported classes must resolve each member to its own module. A small
test-only cache limit must retain no more entries than its limit and return the same
outcomes after bypassing insertion.

The warmed smoke must write a completed JSONL record. Before the full corpus command,
require at least 120 GiB free disk and monitor it; stop at 60 GiB free. The full record
uses `--max-files 1000 --max-sites 10000 --max-targets 1000`. It is the evidence
required to close #675 only if a fresh sample no longer shows import binding and module
path work dominating typed receiver resolution.

## Idempotence and Recovery

The source changes and tests are repeatable. The cache is rebuilt from immutable
analyzer facts and is discarded after a batch file's final request. Differential runs
must write a new JSONL path for each attempt and must not alter corpus source files.
If disk falls below the threshold, interrupt the run and retain the sample/report for
follow-up rather than deleting user data or corpus files.

## Interfaces and Dependencies

No public API changes are permitted. The private context resolver receives
`&PythonAnalyzer`, `&DefinitionLookupIndex`, `&dyn IAnalyzer`, `&ProjectFile`, a raw
type string, and the existing `target_self_file` boolean, returning `Option<CodeUnit>`.
It uses only existing binder facts, same-file declarations, `python_class_for_fqn`, and
the existing structured shared-resolver fallback.

Revision note (2026-07-14): Created from the post-#735 corpus sample to target the
remaining import-resolution hotspot without introducing workspace-lifetime caching.
