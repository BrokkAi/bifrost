# Multi-Language Structural Clone Smells Rollout

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

`bifrost` now has a Java-only vertical slice for structural clone smells: shared clone models and scoring, a Java analyzer implementation, the MCP/report wrapper, and Java parity-style tests. The next stage is to expand that capability across the remaining analyzers in a sequence that preserves momentum, produces reviewable checkpoints, and keeps `bifrost` aligned with `brokk` where `brokk` already defines the semantics.

The rollout should not treat all languages as equal. Today, `brokk` already has clone-smell semantics and tests for Python and JS/TS, so those are parity ports. By contrast, C#, C++, Scala, and PHP are not presently covered by Brokk clone-smell tests in the same way, so they are new analyzer features that should build on the shared Rust engine after the parity languages are stable. The plan therefore splits the work into milestone commits that first finish the known Brokk-backed languages, then extend the same engine to additional tree-sitter analyzers in smaller risk-managed slices.

The observable outcome is that `report_structural_clone_smells` works consistently across the supported analyzers, `MultiAnalyzer` correctly groups and routes mixed-language requests, and each newly supported language lands with focused parity or behavior tests before the next language begins.

## Progress

- [x] (2026-05-18) Confirmed the current baseline: Java structural clone smells are implemented in `bifrost` end to end, including analyzer support, MCP wiring, and Java-focused tests.
- [x] (2026-05-18) Read `.agent/PLANS.md` and local ExecPlan examples to match the repository’s required plan structure and level of detail.
- [x] (2026-05-18) Audited Brokk’s current clone-smell coverage. `brokk` has dedicated tests and analyzer hooks for Java, Python, and JS/TS plus shared tree-sitter similarity tests, but not equivalent clone-smell suites for C#, C++, Scala, or PHP.
- [x] (2026-05-18) Completed Milestone 1. Added Python structural clone detection in `src/analyzer/python_analyzer.rs`, added Brokk-style Python parity tests in `tests/python_structural_clone_smells.rs`, and proved mixed Java-plus-Python `MultiAnalyzer` routing.
- [x] (2026-05-18) Validated the Milestone 1 checkpoint with `cargo test --test python_structural_clone_smells -- --nocapture`, `cargo test --test searchtools_service python_boundary_returns_structural_clone_report_json -- --nocapture`, `cargo test --test bifrost_mcp_server bifrost_searchtools_server_speaks_mcp_stdio -- --nocapture`, `cargo fmt --check`, and `cargo clippy --all-targets --all-features -- -D warnings`.
- [x] (2026-05-18) Completed Milestone 2. Added structural clone detection for both `JavascriptAnalyzer` and `TypescriptAnalyzer`, plus parity-style JS/TS tests in `tests/js_ts_structural_clone_smells.rs` covering TypeScript parity cases, JavaScript smoke coverage, and mixed JS-plus-TS `MultiAnalyzer` routing.
- [x] (2026-05-18) Validated the Milestone 2 checkpoint with `cargo test --test js_ts_structural_clone_smells -- --nocapture`, `cargo test --test searchtools_service python_boundary_returns_structural_clone_report_json -- --nocapture`, `cargo test --test bifrost_mcp_server bifrost_searchtools_server_speaks_mcp_stdio -- --nocapture`, `cargo fmt --check`, and `cargo clippy --all-targets --all-features -- -D warnings`.
- [x] (2026-05-18) Completed Milestone 3. Extracted the shared pairwise clone-finding loop into `src/analyzer/clone_detection.rs`, rewired Java/Python/JavaScript/TypeScript analyzers to use it, and added direct shared similarity tests modeled on Brokk’s `TreeSitterCloneSimilarityTest`.
- [x] (2026-05-18) Validated the Milestone 3 checkpoint with `cargo test --lib clone_detection::tests -- --nocapture`, `cargo test --test java_structural_clone_smells -- --nocapture`, `cargo test --test python_structural_clone_smells -- --nocapture`, `cargo test --test js_ts_structural_clone_smells -- --nocapture`, `cargo test --test searchtools_service python_boundary_returns_structural_clone_report_json -- --nocapture`, `cargo test --test bifrost_mcp_server bifrost_searchtools_server_speaks_mcp_stdio -- --nocapture`, `cargo fmt --check`, and `cargo clippy --all-targets --all-features -- -D warnings`.
- [ ] Add this plan’s milestone tracker updates as each language slice lands.
- [ ] Keep the `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` sections current during implementation.

## Surprises & Discoveries

- Observation: the remaining rollout naturally splits into two categories rather than one uniform backlog.
  Evidence: `brokk-shared` already contains `JavaCloneDetectionSmellTest`, `PythonCloneDetectionSmellTest`, `JsTsCloneDetectionSmellTest`, `AbstractCloneDetectionSmellTest`, and shared `TreeSitterCloneSimilarityTest`, but no equivalent clone-smell suites were found for C#, C++, Scala, or PHP.

- Observation: JS and TS should be treated as one implementation milestone and two validation surfaces, not two separate engines.
  Evidence: Brokk’s reference test is `JsTsCloneDetectionSmellTest`, and the Java implementation lives behind a single `JsTsAnalyzer` override rather than distinct JS and TS clone engines.

- Observation: the highest-value early risk is semantic drift in AST-refinement behavior, not MCP formatting.
  Evidence: the Java slice already established the MCP/report surface. The remaining language work mostly depends on correctly porting analyzer-specific AST-signature normalization and clone-candidate extraction.

- Observation: Python fit the shared Rust clone engine without needing a broader shared-engine refactor.
  Evidence: the milestone only required a Python-specific candidate builder plus token and AST normalization helpers in `src/analyzer/python_analyzer.rs`; the MCP wrapper and shared similarity helpers passed unchanged.

- Observation: JS and TS shared enough clone semantics that a thin shared helper layer inside the existing Rust JS analyzer utilities was sufficient.
  Evidence: both analyzers now reuse the same token normalization, AST-signature construction, and refinement helpers while keeping their own analyzer-specific file filtering and parser-language selection.

- Observation: after Java, Python, JS, and TS were all live, the remaining duplicated logic was concentrated almost entirely in the pairwise candidate-comparison loop rather than in candidate construction.
  Evidence: Milestone 3 could remove the shared scan, ordering, and symmetric-pair suppression logic without disturbing the language-specific candidate builders and AST-refinement hooks.

## Decision Log

- Decision: sequence the rollout as Brokk parity languages first, then new-language support.
  Rationale: Python and JS/TS have a concrete source contract in `../brokk`, which makes them lower-risk and gives the shared Rust clone engine broader validation before using it for languages where `brokk` does not already define expected clone semantics.
  Date/Author: 2026-05-18 / Codex

- Decision: treat C#, C++, Scala, and PHP as separate feature milestones rather than a single “all remaining languages” patch.
  Rationale: each language has different function-like node shapes, AST-label normalization requirements, and likely edge cases around declarations, exception handling constructs, and wrappers. Small milestones keep review and debugging tractable.
  Date/Author: 2026-05-18 / Codex

- Decision: require a checkpoint commit after each completed milestone before beginning the next one.
  Rationale: the user explicitly wants the rollout broken into milestones committed between each one, and the clone-smell engine is cross-cutting enough that clean checkpoints reduce integration risk.
  Date/Author: 2026-05-18 / Codex

## Outcomes & Retrospective

This section is intentionally incomplete until the rollout is executed.

The expected end state is that `bifrost` supports structural clone smells across the Brokk parity languages plus the additional tree-sitter languages targeted here, with tests proving each language’s semantics at the analyzer level and with mixed-language `MultiAnalyzer` coverage. The final retrospective should record which languages achieved near-parity with Brokk, which required Bifrost-specific semantics, and whether any shared clone-engine refactors became necessary along the way.

Milestone 1 outcome: Python is now in the same category as Java for this feature. `bifrost` has Brokk-style Python clone-smell semantics for the currently covered cases, and the shared engine plus MCP/report path needed no schema or routing changes beyond the Python analyzer implementation itself.

Milestone 2 outcome: JS/TS now joins Java and Python as a Brokk-backed parity slice. The Rust implementation needed only a small shared JS/TS clone-helper layer rather than a broader analyzer rewrite, which is a good sign for the upcoming shared-engine consolidation milestone.

Milestone 3 outcome: the shared clone engine is materially cleaner. The common detection loop now lives in one place, and direct unit tests cover the hashed shingle similarity and prefilter behavior independently of any one language analyzer. That reduces the risk of semantic drift as the first non-Brokk-backed languages are added next.

## Context and Orientation

The current structural clone implementation spans:

- `src/analyzer/model.rs` for `CloneSmell` and `CloneSmellWeights`.
- `src/analyzer/i_analyzer.rs` and `src/analyzer/multi_analyzer.rs` for the public contract and cross-language routing.
- `src/analyzer/clone_detection.rs` for the shared token/shingle similarity logic already ported from Brokk.
- `src/analyzer/java_analyzer.rs` for the current language-specific implementation.
- `src/code_quality/structural_clone_smells.rs`, `src/searchtools_service.rs`, and `src/mcp_server.rs` for the MCP/report path.
- `tests/java_structural_clone_smells.rs` for the current Java semantics suite.

The Brokk reference implementation lives in `/Users/dave/Workspace/BrokkAi/brokk`. The most relevant source files are:

- `brokk-shared/src/main/java/ai/brokk/analyzer/TreeSitterAnalyzer.java`
- `brokk-shared/src/main/java/ai/brokk/analyzer/JavaAnalyzer.java`
- `brokk-shared/src/main/java/ai/brokk/analyzer/PythonAnalyzer.java`
- `brokk-shared/src/main/java/ai/brokk/analyzer/JsTsAnalyzer.java`
- `brokk-shared/src/test/java/ai/brokk/analyzer/TreeSitterCloneSimilarityTest.java`
- `brokk-shared/src/test/java/ai/brokk/analyzer/code_quality/AbstractCloneDetectionSmellTest.java`
- `brokk-shared/src/test/java/ai/brokk/analyzer/code_quality/JavaCloneDetectionSmellTest.java`
- `brokk-shared/src/test/java/ai/brokk/analyzer/code_quality/PythonCloneDetectionSmellTest.java`
- `brokk-shared/src/test/java/ai/brokk/analyzer/code_quality/JsTsCloneDetectionSmellTest.java`

The new-language milestones for C#, C++, Scala, and PHP should use those same shared-engine references where possible, but the acceptance contract will be defined in `bifrost` tests because Brokk does not currently provide the same language-specific clone suites for them.

## Plan of Work

Start by broadening confidence in the shared Rust clone engine with the remaining Brokk-backed parity languages. Python is the next best target because it has a dedicated analyzer override and a compact clone test suite in Brokk. After Python lands, port JS/TS as one analyzer milestone, preserving Brokk’s shared `JsTsAnalyzer` behavior and making sure both `.js` and `.ts` style inputs are exercised in `bifrost`.

Once Java, Python, and JS/TS are all implemented and passing, tighten the shared layer before branching into entirely new languages. That cleanup milestone should only include the shared work that is justified by the first three languages, such as normalizing clone-candidate helper APIs, moving any Java-shaped assumptions out of `clone_detection.rs`, and expanding `MultiAnalyzer` tests for mixed Java, Python, and JS/TS requests.

Then add the new languages one milestone at a time, ordered by implementation leverage rather than by popularity. PHP and Scala are good first candidates because their analyzers and function-like declarations are usually easier to reason about than C++’s richer declaration space, while still exercising different AST shapes than the current languages. C# should follow once the shared hooks have handled a more statement-heavy OO language beyond Java. C++ should be last because template-heavy declarations, free functions, methods, constructors, and preprocessor-adjacent syntax are likely to surface the most clone-candidate and AST-normalization complexity.

Each milestone ends only when the language implementation, analyzer-level tests, and any necessary mixed-language routing tests pass, and the branch has a checkpoint commit describing what changed and why. The next milestone should begin from that committed state instead of accumulating multiple languages in one unbroken patch.

## Milestones

### Milestone 1: Python parity port

Implement structural clone smell support in `src/analyzer/python_analyzer.rs` using Brokk’s `PythonAnalyzer` override and `PythonCloneDetectionSmellTest` as the primary contract. Port the missing AST-refinement behavior, clone-candidate extraction rules, and test helpers so `tests/python_structural_clone_smells.rs` mirrors the Brokk scenarios.

This milestone should also add `MultiAnalyzer` coverage for Java-plus-Python grouped requests, proving that mixed file lists route per language and return the union of findings without duplicate delegation.

Checkpoint commit expectation: Python analyzer support, Python parity tests, and any minimal shared-engine fixes required to make the Python semantics pass.

### Milestone 2: JS/TS parity port

Implement clone-smell support in the shared JS/TS analyzer path, following Brokk’s `JsTsAnalyzer` and `JsTsCloneDetectionSmellTest`. Keep the implementation unified under the existing JS/TS analyzer architecture rather than splitting JS and TS into separate clone engines.

The test suite should prove both the Brokk semantics and the language-surface breadth. At minimum, cover TS fixtures matching Brokk and add a small JS-specific smoke case if the current analyzer path distinguishes them through parser or file classification behavior.

This milestone should also extend `MultiAnalyzer` tests to mixed Java, Python, JS, and TS inputs, because the JS/TS analyzer is the first one that intentionally spans more than one extension family behind one delegate.

Checkpoint commit expectation: JS/TS analyzer support, parity-style tests, and any shared-engine refactors discovered while supporting both Python and JS/TS.

### Milestone 3: Shared clone-engine consolidation

Pause language expansion and consolidate only the shared work that the first three languages exposed as necessary. Likely candidates include extracting common AST-signature helper entry points, removing Java-specific naming assumptions from shared clone-candidate metadata, tightening stable ordering guarantees across analyzers, and adding direct unit tests for shared scoring helpers analogous to Brokk’s `TreeSitterCloneSimilarityTest`.

This milestone should not add a new language. Its purpose is to reduce duplication and make the next languages cheaper and safer to add.

Checkpoint commit expectation: shared-engine cleanup, broader shared scoring tests, and stronger mixed-language routing coverage with no user-visible schema changes.

### Milestone 4: PHP support

Add structural clone smell support for PHP in its analyzer by defining clone-candidate extraction over function and method declarations, a PHP-specific AST-refinement/signature strategy, and focused inline-project tests that prove positive detection, threshold filtering, structurally different lookalikes, and stable ordering.

Because Brokk does not currently provide a PHP clone-smell suite, the acceptance contract here is the Bifrost test file plus consistency with the established Java/Python/JS/TS engine semantics.

Checkpoint commit expectation: PHP analyzer implementation, PHP behavior tests, and any minimal shared hook needed for PHP AST handling.

### Milestone 5: Scala support

Add Scala clone-smell support next. The emphasis should be on correctly modeling method-like declarations and AST normalization for expression-oriented method bodies so token-similar but structurally different blocks are still distinguished where appropriate.

Scala is intentionally separate from PHP because it exercises different syntax and declaration forms. Combining them would make failures harder to triage.

Checkpoint commit expectation: Scala analyzer implementation, Scala behavior tests, and any Scala-specific helper additions.

### Milestone 6: C# support

Add C# support after PHP and Scala have validated the shared hooks beyond Java. This milestone should pay special attention to constructors, properties versus methods, local functions if supported by the analyzer, and exception-handling wrappers that might affect AST-signature similarity.

The tests should follow the same structure as the prior languages: positive pair detection, strict-threshold rejection, wrapper tolerance where intended, and stable ordering for multi-file requests.

Checkpoint commit expectation: C# analyzer support, C# behavior tests, and any routing or candidate-shape fixes needed for an OO language with Java-adjacent but not identical structure.

### Milestone 7: C++ support

Add C++ last. The milestone should explicitly define what counts as a clone candidate in the first pass: free functions, methods, constructors, and any exclusions such as macros or declarations without bodies. C++ is the most likely language here to require careful scoping to avoid false positives caused by templates, overloads, or preprocessor-heavy code.

The first-pass test suite should therefore be modest but explicit. It is better to support a clearly bounded subset of C++ code units correctly than to claim broad support with noisy findings.

Checkpoint commit expectation: scoped C++ support, bounded C++ tests, and any final shared-engine adjustments justified by C++ syntax.

### Milestone 8: Cross-language hardening and MCP acceptance sweep

After all targeted languages land, run a final hardening pass across the whole feature. Expand MCP/service coverage where needed, confirm mixed-language requests behave predictably, and add any missing report-level tests for empty findings, ordering, truncation, and cross-language grouping.

This is also the point to document any intentional language limitations in code comments or developer guidance so future parity work has a clear starting point.

Checkpoint commit expectation: no new language support, only hardening, tests, and documentation updates.

## Concrete Steps

For each milestone, the workflow should be:

1. Read the relevant `../brokk` analyzer override and its tests if the language is a parity port.
2. Implement or refine the language-specific clone-candidate and AST-refinement logic in `bifrost`.
3. Add or expand a dedicated Rust integration test file using `tests/common/inline_project.rs`.
4. Run focused tests for that language and the shared MCP path.
5. Run Rust quality gates once the milestone is stable.
6. Create a checkpoint commit before starting the next milestone.

The command shape for each milestone should stay close to:

    cargo test --test <language_structural_clone_smells> -- --nocapture
    cargo test --test searchtools_service python_boundary_returns_structural_clone_report_json -- --nocapture
    cargo test --test bifrost_mcp_server bifrost_searchtools_server_speaks_mcp_stdio -- --nocapture
    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings

When shared clone-scoring logic changes, also run the direct shared tests that cover similarity calculations.

## Validation and Acceptance

Acceptance is milestone-based.

For Milestones 1 and 2, acceptance means the new Python and JS/TS tests in `bifrost` semantically mirror Brokk’s corresponding clone-smell suites and pass locally, along with the shared MCP and `MultiAnalyzer` checks.

For Milestones 4 through 7, acceptance means each new language has a focused dedicated test suite proving at least:

- a clear positive clone pair is reported;
- stricter thresholds can suppress that pair;
- structurally different but token-similar candidates are rejected when the language-specific AST refinement should distinguish them;
- duplicate symmetric findings are suppressed for multi-file requests;
- result ordering is deterministic.

For the final hardening milestone, acceptance means all supported-language clone tests pass together, the MCP/report tests still pass, and `cargo fmt --check` plus `cargo clippy --all-targets --all-features -- -D warnings` succeed from the milestone’s committed state.

## Idempotence and Recovery

The rollout consists of ordinary source edits and tests. Re-running the milestone test commands is safe. If a milestone exposes a shared-engine regression, the recovery path is to fix the shared engine within that milestone before committing, rather than partially landing a broken language slice.

If a language turns out to require a larger shared refactor than expected, stop adding new language-specific code and fold that work into the nearest shared-consolidation milestone so the commit history stays understandable.

Because each milestone ends with a checkpoint commit, abandoning or deferring a later language should still leave the branch in a valid, reviewable state with the earlier languages fully functional.

## Artifacts and Notes

The expected implementation artifacts are:

- one dedicated Rust clone-smell test file per newly supported language where that materially improves readability;
- updates to the shared clone-scoring and analyzer contract files only when justified by more than one language;
- incremental checkpoint commits after every milestone;
- this ExecPlan updated in place as milestones complete or change shape.

The primary reference corpus is `/Users/dave/Workspace/BrokkAi/brokk`, especially the clone-smell analyzers and tests listed above. For the new-language milestones where Brokk is not yet authoritative, use the Bifrost Java/Python/JS/TS structure as the design template and record any scope limitations directly in this document as they are discovered.

## Interfaces and Dependencies

This rollout should not change the public MCP tool schema unless a real cross-language gap is discovered. The existing `report_structural_clone_smells` parameters remain the contract surface.

The key internal interfaces expected to evolve are:

- the language-specific analyzer hook that turns a code unit into clone-candidate data;
- the language-specific AST-refinement hook that converts token similarity into final clone similarity;
- `MultiAnalyzer` routing for grouped file lists spanning multiple delegates;
- the shared clone-scoring helpers and their direct tests.

No new external dependencies are expected. The work should continue to rely on the existing tree-sitter analyzers and the Rust test harnesses already present in `bifrost`.
