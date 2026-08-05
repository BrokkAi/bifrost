# Classify Python deferred annotations as type operands

This ExecPlan is a living document. Maintain it according to `.agents/PLANS.md`.

## Purpose / Big Picture

Python permits a type annotation inside a string. For example, `widget: "Widget"` can refer to a class declared later or otherwise unavailable during immediate evaluation. Bifrost currently creates an occurrence for the direct form `widget: Widget`, but it creates no occurrence for the string form. After this change, both forms produce a `type_operand` occurrence in the type namespace. Both occurrences resolve to the same declaration. An ordinary string with the same contents produces no occurrence.

The change must preserve Bifrost's structural identity contract. Each occurrence belongs to one normalized fact in the file facts arena. A structural query capture and its occurrence can then use the same content-scoped AST identifier. The implementation must parse annotation contents with tree-sitter. It must not find identifiers with regular expressions, delimiter scans, or string splitting.

## Progress

- [x] (2026-08-05 08:04Z) Diagnosed the missing row and confirmed the issue branch matches `origin/master` at `d338f34f8`.
- [x] (2026-08-05 08:10Z) Proved that `parse_source_region` parses a compound annotation with exact original byte positions.
- [x] (2026-08-05 08:29Z) Added the owned embedded-leaf contract and merged ordered leaf facts into the normalized arena.
- [x] (2026-08-05 08:29Z) Incremented the structural facts snapshot version from 5 to 6.
- [x] (2026-08-05 08:29Z) Shared Python annotation-context detection between structural extraction and definition resolution.
- [x] (2026-08-05 08:29Z) Emitted deferred-annotation identifier facts from the Python adapter with cancellable region parsing.
- [x] (2026-08-05 08:29Z) Added extractor, adapter, resolver-path, and end-to-end behavior tests.
- [x] (2026-08-05 08:53Z) Ran formatting, dependency, featureless test, Clippy, diff, and policy validation.
- [x] (2026-08-05 08:53Z) Ran all five guided specialist reviews and corrected each confirmed issue.

## Surprises & Discoveries

- Observation: Python definition resolution already accepts a `string_content` node inside an annotation.
  Evidence: `annotation_reference_candidates` in `crates/bifrost-analysis/src/analyzer/usages/python_graph/resolver.rs` handles `identifier | string_content`.

- Observation: The generic facts extractor explicitly assumes that adapters never synthesize nodes.
  Evidence: `extract_file_facts_limited` bounds occurrence roles by the existing node arena, and `RoleSink::occurrence_role` requires a fact ID.

- Observation: The initial required `bifrost.code-smells` MCP run took 9.249 seconds and returned `finding`, exit status 1. The selected pack had pre-existing repository findings. No issue files had changed.
  Evidence: request `{"policy_packs":["bifrost.code-smells"],"evaluation_date":"2026-08-05","fail_on":"warning"}` at revision `d338f34f8`.

- Observation: An included-range Python parse of `Widget | list[Gadget]` returns three identifier nodes with original file offsets.
  Evidence: `deferred_annotation_region_parse_preserves_source_positions` passes and checks all three source slices.

- Observation: Python strings expose `string_start`, `string_content`, and `string_end` as named children.
  Evidence: The first adapter test failed until the hook accepted the structured boundary nodes and selected exactly one content node.

- Observation: The general definition resolver rejected `string_content` before the new occurrence could resolve.
  Evidence: The first end-to-end run produced the deferred row with `target_kind: unresolved`. Routing annotation-scoped `string_content` as an identifier made both operands resolve to `src.deferred.Widget`.

- Observation: The core library remains affected by the known temporary-database environment failure.
  Evidence: 158 tests passed. `cache_db::tests::streaming_reader_has_a_small_non_mmap_page_cache` failed while opening its temporary SQLite file. The same failure is recorded in the parent #1473 plan.

- Observation: The default Rust compiler and Homebrew Clippy have the same release hash but different LLVM builds.
  Evidence: The default compiler reports LLVM 22.1.2. Homebrew Clippy reports LLVM 22.1.6. The isolated Homebrew toolchain passed.

- Observation: Specialist review found that the first resolver change used the complete outer string for each compound operand.
  Evidence: The new `"Widget | Gadget"` end-to-end case failed by inspection before the focused-reference helper. It now resolves both inner ranges.

- Observation: The final policy run completed in 2.790 seconds with 295 existing findings.
  Evidence: The only warning in a changed file is the unchanged sort and dedup at `python_graph/resolver.rs`.

## Decision Log

- Decision: Add source-backed facts before occurrence-row derivation. Do not add ad hoc occurrence rows.
  Rationale: Occurrence rows use facts-arena IDs for AST identity, containment, persistence, and policy correlation.
  Date/Author: 2026-08-05 / Codex

- Decision: Use `crate::analyzer::common::parse_source_region` for annotation contents.
  Rationale: It uses tree-sitter included ranges and preserves original byte, line, and column positions.
  Date/Author: 2026-08-05 / Codex

- Decision: Parse only a string that the outer Python AST proves is an annotation.
  Rationale: This keeps ordinary strings outside the occurrence domain.
  Date/Author: 2026-08-05 / Codex

- Decision: Fail closed when decoded string contents do not map to one exact source region.
  Rationale: A guessed range would violate the source-backed fact contract.
  Date/Author: 2026-08-05 / Codex

- Decision: Share one deferred-annotation range parser between extraction and resolution.
  Rationale: Both layers must accept the same inner identifiers and exact source ranges.
  Date/Author: 2026-08-05 / Codex

- Decision: Reject implicitly concatenated and escaped annotation strings.
  Rationale: Their decoded contents do not map to one contiguous parser-provided source region.
  Date/Author: 2026-08-05 / Codex

- Decision: Do not add an incomplete-extraction result to `StructuralSpec` in this change.
  Rationale: The accepted design intentionally fails closed for malformed or unmappable strings. The occurrence result makes no claim about all valid Python annotation forms.
  Date/Author: 2026-08-05 / Codex

## Outcomes & Retrospective

The implementation and review are complete. Deferred bare and compound annotation operands now use source-backed facts. They resolve by their exact inner ranges. Ordinary, malformed, escaped, and implicitly concatenated strings remain absent.

The featureless analysis library passed 1,714 tests, with 7 ignored. The cross-language suite passed all 362 tests. Focused adapter, extractor, resolver, and conformance tests passed. Formatting, dependency boundaries, diff checks, and focused all-target Clippy passed.

The required policy pack returned `finding` because the repository has existing warnings. It returned no new warning in changed code. The guided security, duplication, senior, DevOps, and architecture reviews found four confirmed defects. This plan corrected all four. The architecture review also proposed a wider completeness API. This plan did not accept that proposal because it conflicts with the explicit fail-closed boundary.

## Context and Orientation

Tree-sitter is the parser library used by Bifrost. It returns a concrete syntax tree with byte and line positions. A normalized fact is a language-neutral record for one selected parser node. Facts live in a flat vector called the facts arena. Each fact has a numeric ID, a parent fact, and the exclusive end of its subtree.

`crates/bifrost-analysis/src/analyzer/structural/extract.rs` parses one file and creates the facts arena. The first pass walks the parser tree iteratively and creates facts in preorder. The second pass invokes a language `StructuralSpec` and records names, semantic roles, and occurrence roles.

`crates/bifrost-core/src/analyzer/structural/spec.rs` defines `StructuralSpec` and `RoleSink`. A Python-specific implementation lives in `crates/bifrost-analysis/src/analyzer/python/structural.rs`. Its kind table admits ordinary `identifier` nodes. Its `python_occurrence_role` function classifies identifiers inside a `type` wrapper as `TypeOperand`.

For `widget: "Widget"`, the primary parser creates a `string` and `string_content`. It does not create an identifier inside the contents. The occurrence producer in `crates/bifrost-analysis/src/analyzer/structural/occurrence_rows.rs` can only classify existing facts. It therefore has no row to resolve.

`parse_source_region` in `crates/bifrost-analysis/src/analyzer/common.rs` parses one source byte interval with tree-sitter included ranges. Nodes in the returned tree keep positions from the original file. This is the structured parser seam for the annotation contents.

The persisted facts cache uses `STRUCTURAL_FACTS_SNAPSHOT_VERSION` in `crates/bifrost-analysis/src/analyzer/structural/facts.rs`. A normalization change requires a version increment. Old rows then become ordinary cache misses.

## Plan of Work

Milestone 1 proves the parser seam. Add focused Python adapter tests that call `parse_source_region` on the parser-provided `string_content` range. Confirm that a bare name and a compound type expression produce identifier nodes at exact original positions. Confirm that parse errors or escaped contents fail closed. Do not add a permanent public contract until this proof passes.

Milestone 2 adds a small owned descriptor to `crates/bifrost-core/src/analyzer/structural/spec.rs`. A descriptor identifies its primary-tree anchor and contains one source-backed normalized kind, exact range, and occurrence role. Add a default empty `StructuralSpec` hook so other adapters do not change. The descriptor must not contain a secondary-tree `Node`, because its tree will not survive extraction.

Update `extract_file_facts_limited` in `crates/bifrost-analysis/src/analyzer/structural/extract.rs`. Collect embedded descriptors while visiting their primary anchor. Insert each embedded fact in deterministic preorder under that anchor. Count each fact against `max_fact_nodes`. Keep traversal iterative. Poll cancellation while parsing and visiting inner trees. Recompute parent and `subtree_end` values without range-based joins. Reject descriptors outside the anchor or source.

Increment `STRUCTURAL_FACTS_SNAPSHOT_VERSION` in `crates/bifrost-analysis/src/analyzer/structural/facts.rs`. Update its history comment. The serialized data shape can remain unchanged, but Python normalization semantics will change.

Milestone 3 adds one AST-only annotation-context predicate in `crates/bifrost-analysis/src/analyzer/python/syntax.rs`. It recognizes function return types, typed parameters, typed default parameters, and annotated assignment type fields. Replace the private equivalent in `crates/bifrost-analysis/src/analyzer/usages/python_graph/resolver.rs` so extraction and resolution cannot disagree.

Implement the embedded-fact hook in `crates/bifrost-analysis/src/analyzer/python/structural.rs`. Start from a `string` proven to be an annotation. Use its parser-provided `string_content` range with `parse_source_region`. Walk the inner tree with an explicit stack. Emit only identifiers that the parsed type-expression structure consumes as type operands. Do not process ordinary strings. Do not use source-text parsing.

Milestone 4 adds behavior tests. Extractor tests prove deterministic IDs, anchor parentage, subtree containment, limits, cancellation, and snapshot round trips. Python adapter tests cover direct, deferred, compound, malformed, escaped, and ordinary-string cases. Update `tests/suite_cross_language/code_query_occurrences.rs` through its existing `InlineTestProject` path. The deferred and direct rows must resolve to the same declaration. The deferred row range must exclude quote characters.

Milestone 5 validates and reviews the result. Run formatting, focused featureless tests, the workspace dependency check, and the required `bifrost.code-smells` policy pack. Do not enable `nlp`. Then run the five guided review specialists. Correct confirmed findings and repeat affected validation.

## Concrete Steps

Run all commands from `/Users/dave/.codex/worktrees/96ff/bifrost`.

For focused implementation validation, use:

    cargo test -p brokk-bifrost-analysis structural_spec_tests::
    cargo test -p brokk-bifrost-analysis structural::extract::tests::
    cargo test --test suite_cross_language code_query_occurrences

If definition resolution changes, run its owning integration suite with the new test filter.

For task completion, use:

    cargo fmt --all -- --check
    cargo test -p brokk-bifrost-analysis --lib
    cargo test --test suite_cross_language
    node scripts/check-workspace-dependencies.mjs
    git diff --check

Use the installed Bifrost policy tool in one request. Select `bifrost.code-smells`, evaluation date `2026-08-05`, and `fail_on: warning`. The repository names no separate executable policy root at task start.

## Validation and Acceptance

The new adapter test must fail before implementation because no inner fact exists. It must pass after implementation and report `Widget` without quote bytes at the exact source position.

The end-to-end test must return three `Widget` rows: one declaration name, one direct type operand, and one deferred type operand. Both type operands must use the type namespace and resolve to `src.deferred.Widget`. The ordinary assignment string must produce no row.

A compound deferred annotation must create separate source-backed type operands where the parser proves them. A malformed or unmappable annotation must not create guessed rows. Cancellation and fact limits must stop inner extraction through the existing result paths.

Old snapshot version keys must not reuse facts that omit the embedded identifiers. Snapshot round-trip tests must preserve the new facts and their occurrence roles.

## Idempotence and Recovery

All parsing and extraction steps are deterministic. Repeated extraction over the same bytes must produce the same fact IDs and occurrence IDs.

If the region parser does not preserve exact source positions, stop after the prototype. Record the evidence here and select another tree-sitter parsing method. Do not add a text parser.

If embedded facts cannot preserve preorder containment, do not append them after extraction. Change the pass-one work stack so each embedded child enters before the primary anchor exits.

Tests and formatting are safe to repeat. Do not create manually named Cargo target directories. Do not enable NLP for this task.

## Artifacts and Notes

The issue fixture is:

    class Widget:
        pass

    def direct(widget: Widget) -> int:
        return 1

    def deferred(widget: "Widget") -> int:
        return 2

    name = "Widget"

The accepted occurrence spelling is `Widget`. Its start and end bytes are inside the annotation string content. The quote characters are not part of the range.

## Interfaces and Dependencies

The implementation uses the existing `tree-sitter` and `tree-sitter-python` dependencies. It adds no crate dependency.

In `crates/bifrost-core/src/analyzer/structural/spec.rs`, add one owned embedded-fact descriptor and a default empty `StructuralSpec` method. The final names can change during the prototype, but the descriptor must contain an anchor identity, `NormalizedKind`, `Range`, and `OccurrenceRole`.

In `crates/bifrost-analysis/src/analyzer/structural/extract.rs`, merge descriptors during pass one. Do not expose an analysis-layer type through `brokk-bifrost-core`.

In `crates/bifrost-analysis/src/analyzer/python/syntax.rs`, expose one crate-visible annotation-context predicate for both structural extraction and the Python usage resolver.

Plan revision note (2026-08-05): Created the initial self-contained implementation plan after issue diagnosis and user approval.

Plan revision note (2026-08-05): Recorded the successful included-range parser prototype and exact source-position evidence.

Plan revision note (2026-08-05): Recorded the embedded-fact implementation, resolver seam, focused tests, known core environment failure, and corrected root-package integration commands.

Plan revision note (2026-08-05): Recorded broad validation, five-reviewer findings, compound-resolution corrections, fail-closed edge cases, and final outcomes.
