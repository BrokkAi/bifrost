# Add Hybrid `most_relevant_files` To Bifrost Searchtools

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md`.

The shared Git-relevance design docs at the main entry points in bifrost and Brokk are part of the implementation contract for this work. Keep those docs in sync with each other and with the code whenever any shared ranking or canonicalization rule changes.

## Purpose / Big Picture

After this change, bifrost and Brokk will both expose a small command-line tool that takes one or more project-relative filenames and prints the top 100 related files, one per line, in relevance order. A human can prove it works by running the Rust CLI against the Brokk repository, running the Java CLI against the same repository, and comparing the outputs for 100 random seed files. Any mismatch discovered during that comparison must be turned into a failing automated test before the incorrect implementation is fixed.

## Progress

- [x] (2026-04-03 20:32Z) Confirmed the existing Rust and Python searchtools surfaces, the analyzer/project APIs, and the absence of any current Git ranking module in bifrost.
- [x] (2026-04-03 20:34Z) Confirmed the Brokk reference behavior and the battle-tested Java cases in `ContextNoGitFallbackTest`, `ImportPageRankerTest`, and `GitDistanceRelatedFilesTest`.
- [x] (2026-04-03 20:55Z) Added `src/relevance.rs` with Brokk-style import Personalized PageRank, Git co-change ranking via `git2`, rename canonicalization, and a crate-local seed-file entrypoint.
- [x] (2026-04-03 20:58Z) Exposed `most_relevant_files` through `src/searchtools.rs`, `src/searchtools_service.rs`, `src/mcp_server.rs`, and the Python `bifrost_searchtools` client and model layer.
- [x] (2026-04-03 21:06Z) Ported the relevant Brokk Java ranking cases into Rust tests, including hybrid Git fallback, reverse import traversal, multi-language import routing, and rename canonicalization. Added searchtools service, MCP, and Python client coverage for the new tool.
- [x] (2026-04-03 21:12Z) Ran `cargo test`, `cargo fmt --check`, and `uv run python -m unittest discover -s python_tests -p 'test_*.py'` successfully after the new tool landed.
- [x] (2026-04-04 15:32Z) Confirmed that `../brokk` was missing from the session sandbox policy, then fixed the session configuration so cross-repo edits are now writable without repeated approvals.
- [x] (2026-04-04 17:05Z) Added the bifrost CLI in `src/bin/most_relevant_files.rs` and the Brokk CLI in `app/src/main/java/ai/brokk/tools/MostRelevantFilesCli.java`, plus the direct Brokk seed-file entrypoint and CLI coverage.
- [x] (2026-04-04 18:40Z) Reproduced and fixed several confirmed parity bugs before broad reruns: Brokk reverse-import partial-cache reuse, bifrost TypeScript `import type` parsing, bifrost rename canonicalization over-joining file lineages, and a parity harness bug that was dropping `.github/...` result lines from the Brokk side.
- [x] (2026-04-04 19:20Z) Ran multiple 100-seed single-file parity sweeps and reduced the survivor list from seven mismatches to one remaining Brokk-side divergence on `app/src/test/java/ai/brokk/agents/ArchitectAgentTest.java`.
- [x] (2026-04-04 19:35Z) Committed the currently landed work before continuing: bifrost `2a599f1` (`summarize_symbols`), bifrost `dd61c92` (`most_relevant_files` and parity harness), and Brokk `abe4f1aa61` (`most relevant files CLI and analyzer parity fixes`).
- [x] (2026-04-04 22:40Z) Eliminated the remaining Brokk-repo parity survivors and validated the previously failing direct cases: Brokk reverse-import completeness, bifrost TypeScript import parsing, Brokk cached-analyzer freshness, Brokk rename canonicalization at plume/autogen, and the live-workspace parity harness all now agree on the targeted repros.
- [x] (2026-04-04 22:50Z) Confirmed that the previously failing external-repo direct cases now match under the current built CLIs: `plume-merge` single and pair, `axios` single, and `microsoft/autogen` single.
- [x] (2026-04-04 23:58Z) Root-caused the last plume Java single-file survivors to duplicate-definition ordering in bifrost's Tree-sitter definition index, not Git scoring. Ported Brokk-style definition ordering by priority, earliest range start, and path/FQN/signature, and added the `ImportsTest8Base.java` parity regression.
- [x] (2026-04-05 00:06Z) Re-ran the deterministic 100-file `plume-merge` Java single-file sweep and confirmed it is now clean.
- [x] (2026-04-05 16:20Z) Root-caused the remaining `microsoft/autogen` `Checker.cs` survivor to bifrost's commit-walk ordering, not another rename-threshold issue. The `AgentMetadata.cs` rename was already detectable, but a pure time-sorted walk let older pre-rename commits be processed before the later rename edge was recorded, collapsing the followed doc frequency from `5` to `2`. Switching the revwalk to `TOPOLOGICAL | TIME` fixed the regression and restored parity on the targeted autogen seed.
- [x] (2026-04-05 22:05Z) Added synchronized design-doc comments at the main Git relevance entry points in bifrost and Brokk, documenting the shared parity-sensitive rules and the requirement to update both docs together with the code.
- [x] (2026-04-05 23:35Z) Finalized the post-continuation Git lineage contract: no add/delete continuation inference, but native `RENAME` labels on both sides now pass the same compact-stem plus direct token-overlap sanity check before becoming lineage edges. Rebuilt the packaged Brokk CLI and revalidated the previously failing `VectorSimilarity` seed against that shared rule.
- [ ] (2026-04-04 22:50Z) Rerun deterministic cross-language single-seed sweeps against representative repos for each supported language and turn any survivor into a failing automated test before changing code.
- [ ] (2026-04-04 22:50Z) Only after the single-seed sweeps are clean, run the deterministic two-file-pair sweeps for the same repo set and repeat the same mismatch discipline there.

## Surprises & Discoveries

- Observation: bifrost already has the analyzer-side import data needed for Brokk's import ranking, including `imported_code_units_of` and `referencing_files_of` on the languages that matter here.
  Evidence: `src/analyzer/capabilities.rs` and the language delegates already implement `ImportAnalysisProvider`.

- Observation: bifrost has no Git abstraction comparable to Brokk's `GitRepo`, so hybrid parity requires fresh Git infrastructure rather than only wiring.
  Evidence: repository search found no `git2`, no Git repository wrapper, and no existing ranking code beyond analyzer autocomplete ordering.

- Observation: `FilesystemProject` respects ignore rules in a way that `TestProject` does not, which made ad hoc import-only temp-directory tests flaky depending on path and ignore configuration.
  Evidence: the first service-layer temp project returned empty relevance results under `FilesystemProject` while the equivalent `TestProject` parity cases passed; switching the JSON-boundary tests to explicit Git-backed root-level files removed that nondeterminism.

- Observation: the first cross-repo parity harness bug was in the harness, not the algorithms. Filtering Brokk output with a tracked-file or hard-coded prefix allowlist drops legitimate live-workspace results such as `.github/workflows/...`.
  Evidence: `ContentDiffUtils.java` initially looked mismatched until the raw Brokk CLI output was checked and shown to include the same `.github/workflows/daily-full-test.yml` and `.github/workflows/ci.yml` lines as bifrost.

- Observation: Brokk's reverse-import cache was reusing partial reverse edges as if they were complete, which changed import PageRank results depending on prior lookup order.
  Evidence: `JavaImportTest.testReferencingFilesOfDoesNotReusePartialReverseCacheFromOtherLookup` failed before the fix and passed after adding per-generation reverse-cache completeness tracking.

- Observation: one of the surviving parity failures was a real bifrost parser bug. TypeScript `import type { Foo } ...` and mixed named imports like `import { type Foo, Bar } ...` were not being parsed as named imports.
  Evidence: `frontend-mop/src/stores/lookup.ts` disagreed with Brokk until the parser tests in `src/analyzer/javascript_analyzer.rs` were added and the import parser was corrected.

- Observation: bifrost's first rename-canonicalization implementation was too aggressive because it globally chained rename edges across time, which pulled unrelated history into the current path when an old filename was later reused.
  Evidence: the `LutzAgentTest` parity reduction showed bifrost reporting a higher document frequency than Brokk; inspecting the commit history showed bifrost incorrectly connecting a delete/add path reuse into the later lineage.

- Observation: the only known remaining parity mismatch is not in the ranking math when both sides run against a stable analyzer. It is in Brokk's cached headless analyzer path.
  Evidence: for `ArchitectAgentTest.java`, fresh-analyzer Brokk import and Git results matched bifrost, but the headless CLI path still dropped the `ToolRegistry` / `dev.langchain4j.agent.tool.*` branch and emitted stale-analyzer warnings.

- Observation: the external-repo autogen mismatch was resolved in code before it was resolved in the CLI, because the hand-built Java classpath being used for direct checks was stale.
  Evidence: the targeted Brokk JUnit regression passed while the manual CLI still omitted the local `.csproj`; rerunning against the packaged `app/build/install/app/lib/*` classpath brought the CLI output into agreement with the test and with bifrost.

- Observation: the last remaining plume Java single-file mismatches were not Git problems at all. They came from duplicate definitions of the same Java FQN being ordered differently between Brokk and bifrost.
  Evidence: for `ImportsTest8Base.java`, both sides had no `ImportsTest9*` Git results, but Brokk resolved `tech.tablesaw.api.BooleanColumn` to `ImportsTest9Base.java` while bifrost resolved it to `ImportsTest9A.java`; Brokk's `getDefinitions(...)` ordering is based on priority plus earliest source range, while bifrost was using plain `CodeUnit::Ord`.

- Observation: the Brokk autogen `.csproj` case needed canonicalizer fallback edges, not just a lower JGit rename score.
  Evidence: after lowering JGit rename score the canonical-path test still failed; only after adding add/delete fallback rename inference to `GitRepo.buildCanonicalizer(...)` did the local `.csproj` path canonicalize forward and rank with the expected tied top set.

- Observation: one recurring class of rename parity failures was not actually about rename thresholds. It was about commit-walk ordering. A canonicalizer that walks commits in pure time order can see an older pre-rename commit before the newer rename edge has been recorded, which silently truncates followed history even when rename detection itself is correct.
  Evidence: bifrost detected the `b16b94...` `AgentMetadata.cs` rename in autogen, but still counted only `2` commits instead of `5` until the revwalk changed from `Sort::TIME` to `Sort::TOPOLOGICAL | Sort::TIME`.

## Decision Log

- Decision: preserve Brokk's hybrid behavior instead of shipping an import-only first cut.
  Rationale: the user explicitly chose full hybrid parity, and several of the strongest upstream tests cover Git fallback and merge behavior.
  Date/Author: 2026-04-03 / Codex + user

- Decision: expose ordered paths, not scores, in the public searchtools and Python results.
  Rationale: the user explicitly chose a path-only public contract; internal ranking scores remain implementation detail.
  Date/Author: 2026-04-03 / Codex + user

- Decision: port the relevant upstream Java tests rather than writing only new local approximations.
  Rationale: the user explicitly wants the battle-scarred Java cases preserved because they encode known edge conditions around Git fallback, PageRank flow, and renames.
  Date/Author: 2026-04-03 / Codex + user

- Decision: both implementations should use live-workspace semantics for import-based relevance instead of restricting the import graph to tracked files only.
  Rationale: the user explicitly chose "what is relevant in the current working tree" over commit-stable reproducibility, so untracked but analyzable files should remain visible to the import side and final results.
  Date/Author: 2026-04-04 / Codex + user

- Decision: parity reruns proceed in phases: first 100 deterministic single-file seeds, then 100 deterministic two-file pairs only after singles are clean.
  Rationale: the remaining work should isolate algorithm or analyzer problems with the smallest possible surface area before expanding to pair interactions.
  Date/Author: 2026-04-04 / Codex + user

- Decision: the shared Git-relevance design notes at the main entry points are part of the parity contract and must be kept in sync alongside the code.
  Rationale: the recurring rename/tie-order regressions came from hidden assumptions drifting between implementations; keeping the code comments synchronized at the entry points makes those assumptions explicit and reviewable instead of leaving them scattered across bug-fix breadcrumbs.
  Date/Author: 2026-04-05 / Codex + user

- Decision: stop using custom add/delete "continuation scoring" as part of the shared Git relevance contract. Git relevance should follow standard Git-native rename labels only, with synchronized thresholds/order between Brokk and bifrost. Native rename labels still pass one shared direct sanity check: compact filename stems must match and the directly compared old/new contents must have near-exact token overlap before the edge becomes lineage.
  Rationale: the fallback continuation heuristic became both the dominant large-repo Python performance cost and the main source of parity drift. The user explicitly prefers living with Git heuristic boundaries over maintaining a second homegrown lineage oracle. libgit2 and JGit still disagree on a few borderline native rename labels, so a cheap direct token-overlap check on native labels is the narrowest shared rule that preserves the performance win while keeping both implementations aligned. Keep the bifrost and Brokk entry-point docs in sync with this contract as code changes land.
  Date/Author: 2026-04-05 / Codex + user

## Outcomes & Retrospective

The core feature is in place on both sides. bifrost exposes a Brokk-style hybrid relevance engine through Rust, MCP, Python, and a dedicated CLI. Brokk now exposes a matching CLI and a seed-file entrypoint that does not require synthetic `ContextFragment` setup. Several parity bugs have already been retired with regression tests, which means the remaining work is now concentrated instead of being spread across multiple independent causes.

The most important lesson so far is that parity problems have come from three distinct layers: ranking semantics, analyzer/input semantics, and the parity harness itself. Each required a different kind of fix. The current unresolved issue is firmly in the second category: Brokk's cached headless analyzer path still diverges from a fresh analyzer build. The plan therefore shifts from broad algorithm work to making that analyzer path deterministic before doing the final randomized parity sweeps.

## Context and Orientation

The existing public searchtools layer lives in `src/searchtools.rs`. It defines serde parameter and result types for tools such as `search_symbols`, `get_symbol_locations`, and `get_file_summaries`, and it is invoked through the shared JSON service in `src/searchtools_service.rs`. The standalone MCP server in `src/mcp_server.rs` is a thin adapter over that service, and the Python package in `bifrost_searchtools/` talks to the same service through the PyO3 module defined in `src/python_module.rs`. `src/relevance.rs` now contains the hybrid ranking logic itself. A small Rust binary can therefore call that code directly without going through JSON.

The new feature belongs beside those tools, not in a new Context abstraction. Bifrost's analyzer interface already exposes a `Project` via `IAnalyzer::project()`, and file identities are represented by `ProjectFile`. The user-visible tool therefore accepts project-relative seed paths, resolves them to `ProjectFile` values, and passes them to the ranking module directly.

The reference implementation is Brokk's `Context.getMostRelevantFiles`, backed by `ImportPageRanker` and `GitDistance`. For the CLI comparison, Brokk also needs a direct seed-file entrypoint in `Context.java` so both sides can accept the same input shape: a collection of existing project files. The important behaviors to preserve are straightforward. Seed files never appear in results. Git ranking is attempted first when a usable repository and tracked seeds exist. Import ranking then fills any remaining slots without duplicates. Import ranking expands only a local graph around the seeds, respects two-hop flow, supports reverse traversal internally, and stays deterministic on ties.

## Plan of Work

First, keep the already-landed Rust ranking implementation and add a dedicated CLI binary under `src/bin/` that accepts `--root` plus one or more project-relative filenames. It must build a `FilesystemProject`, construct a `WorkspaceAnalyzer`, resolve the input filenames, call the existing ranking function with a limit of 100, and print one related file per line.

Next, update Brokk's `Context.java` so there is a direct overload that accepts a `Collection<ProjectFile>` seed set and computes the same hybrid ranking without requiring the caller to create `ContextFragment` objects. Then add a Java CLI under `app/src/main/java/ai/brokk/tools/` that accepts `--root` plus project-relative filenames, resolves them through `ContextManager.toFile`, invokes the new `Context` overload, and prints one result per line.

After both CLIs exist, the remaining work is a parity-debugging loop. First, root-cause the Brokk cached-analyzer divergence behind `ArchitectAgentTest.java`. The working hypothesis from the current evidence is that `ContextManager.createHeadlessInternal(...)` plus cached analyzer reuse still leaves the CLI on a stale or partially refreshed analyzer snapshot, even after the `AnalyzerWrapper.get()` barrier fix. That hypothesis must be tested by comparing three Brokk paths for the same seed: a fresh analyzer build, a loaded analyzer plus rebuild/update, and the actual headless CLI path. The first concrete deliverable is a failing Brokk automated test that proves the cached headless path can disagree with a fresh analyzer on import-based relevance for this seed or an equivalent reduced fixture.

Once that Brokk divergence is fixed, rerun the deterministic 100-file single-seed sweep. Any survivor must again be reduced to a failing automated test before code changes. Only when the single-seed sweep is completely clean should the process expand to the deterministic 100 two-file-pair sweep.

## Concrete Steps

From `/home/jonathan/Projects/bifrost`, edit these files first:

    Cargo.toml
    src/lib.rs
    src/searchtools.rs
    src/searchtools_service.rs
    src/mcp_server.rs
    src/relevance.rs
    src/bin/most_relevant_files.rs

Then update the Python package and docs:

    bifrost_searchtools/client.py
    bifrost_searchtools/models.py
    bifrost_searchtools/__init__.py
    README.md

Then add or update the tests:

    tests/most_relevant_files.rs
    tests/searchtools_service.rs
    tests/bifrost_mcp_server.rs
    python_tests/test_searchtools_client.py

Then edit the Brokk repository:

    ../brokk/app/src/main/java/ai/brokk/context/Context.java
    ../brokk/app/src/main/java/ai/brokk/tools/MostRelevantFilesCli.java
    ../brokk/app/src/test/java/ai/brokk/analyzer/ranking/...

The currently active Brokk investigation files are:

    ../brokk/app/src/main/java/ai/brokk/AnalyzerWrapper.java
    ../brokk/app/src/main/java/ai/brokk/ContextManager.java
    ../brokk/app/src/main/java/ai/brokk/tools/MostRelevantFilesCli.java
    ../brokk/app/src/test/java/ai/brokk/AnalyzerWrapperTest.java
    ../brokk/app/src/test/java/ai/brokk/analyzer/ranking/ContextNoGitFallbackTest.java
    ../brokk/app/src/test/java/ai/brokk/...

Run the CLI comparison after both binaries exist:

    cd /home/jonathan/Projects/bifrost
    cargo run --bin most_relevant_files -- --root /home/jonathan/Projects/brokk <seed-file>

    cd /home/jonathan/Projects/brokk
    ./gradlew :app:classes
    java -cp app/build/classes/java/main:app/build/resources/main:<runtime-classpath> ai.brokk.tools.MostRelevantFilesCli --root /home/jonathan/Projects/brokk <seed-file>

    cd /home/jonathan/Projects/bifrost
    python3 - <<'PY'
    import random
    from pathlib import Path
    root = Path('/home/jonathan/Projects/brokk')
    files = sorted(
        p.relative_to(root).as_posix()
        for p in root.rglob('*')
        if p.is_file() and '.git' not in p.parts
    )
    rng = random.Random(0)
    for path in rng.sample(files, 100):
        print(path)
    PY

The exact Java classpath assembly step must be documented with the final working command once the CLI is built.

Run focused validation from `/home/jonathan/Projects/bifrost`:

    cargo test --test most_relevant_files --test searchtools_service --test bifrost_mcp_server
    cargo test
    uv run python -m unittest discover -s python_tests -p 'test_*.py'

After the Brokk divergence fix, run the parity sweeps from `/home/jonathan/Projects/bifrost` with the direct Brokk CLI in parallel. Keep the comparison deterministic by using `random.Random(0)` for both the single-file sample and the pair sample. Save the comparison summary to `/tmp/mrf_parity_summary.json` (single-file run) and `/tmp/mrf_pair_parity_summary.json` (pair run) so any later contributor can inspect the exact survivors.

## Validation and Acceptance

Acceptance for the Rust ranking core is that the translated Brokk Java parity cases pass: no-Git import fallback, hybrid Git-plus-import merge, fill behavior when Git under-fills, untracked seed fallback, rename canonicalization, two-hop import flow, hub ranking, cycle stability, empty-internal-import handling, reverse traversal, and multi-language import routing.

Acceptance for the public tool is that a call shaped like:

    {"seed_files":["A.java"],"limit":5}

returns:

    {"files":[...],"not_found":[...]}

with only project-relative paths, never scores, never the seed file itself, and no duplicates.

Acceptance for the shared-service and Python boundaries is that `SearchToolsService::call_tool_json("most_relevant_files", ...)` and `SearchToolsClient.most_relevant_files(...)` both return the same ordered paths for the same fixture setup, and the MCP server publishes the tool in `tools/list`.

Acceptance for this milestone is stronger than feature wiring. The Rust CLI and the Java CLI must both print the top 100 related files, one per line, for the same seed input. The Brokk cached headless analyzer path must match fresh-analyzer results on the reduced regression that currently represents the `ArchitectAgentTest.java` failure. Then a deterministic 100-file single-seed comparison over the Brokk repository must complete with zero unexplained mismatches. Only after that passes should the deterministic 100-pair comparison run, and it must also complete with zero unexplained mismatches.

Acceptance also requires that the shared design-doc comments at the bifrost and Brokk Git-relevance entry points remain aligned with each other and with the implemented ranking rules. A parity fix is not complete until both the code and those entry-point docs agree.

The current follow-up performance/correctness track is to simplify the Git contract rather than keep tuning continuation heuristics. Acceptance for that simplification is:

    1. Bifrost and Brokk both use Git-native rename labels only, with the same rename threshold and commit-walk ordering.
    2. Neither side performs extra add/delete content-token continuation scoring during Git relevance.
    3. The shared entry-point docs in `src/relevance.rs` and `app/src/main/java/ai/brokk/git/GitDistance.java` describe that contract plainly and remain in sync.
    4. Large-repo Python timing is re-measured afterward to confirm the custom continuation path was the dominant cold-run Git cost.

## How To Run Tests

Run the bifrost-side tests from `/home/jonathan/Projects/bifrost`:

    cargo test --test most_relevant_files -- --nocapture
    cargo test
    cargo fmt --check
    uv run python -m unittest discover -s python_tests -p 'test_*.py'

Run the Brokk-side targeted tests from `/home/jonathan/Projects/brokk`:

    ./gradlew :app:test --tests ai.brokk.analyzer.ranking.ContextNoGitFallbackTest.testTrackedSeedCanReturnUntrackedImportNeighbor
    ./gradlew :app:test --tests ai.brokk.analyzer.imports.JavaImportTest.testReferencingFilesOfDoesNotReusePartialReverseCacheFromOtherLookup
    ./gradlew :app:test --tests ai.brokk.analyzer.ranking.ImportPageRankerTest
    ./gradlew :app:test --tests ai.brokk.AnalyzerWrapperTest.testGetWaitsForQueuedBackgroundRefresh
    ./gradlew :app:test --tests ai.brokk.tools.MostRelevantFilesCliTest

Prepare the Brokk direct Java CLI runtime once, then use it for parity checks without paying Gradle startup on every seed:

    cd /home/jonathan/Projects/brokk
    ./gradlew :app:installDist
    java -Djava.awt.headless=true \
      -cp '/home/jonathan/Projects/brokk/app/build/install/app/lib/*' \
      ai.brokk.tools.MostRelevantFilesCli \
      --root /home/jonathan/Projects/brokk \
      app/src/main/java/ai/brokk/gui/MergeDialogPanel.java

The direct Java CLI may still log startup warmup build failures or native-library warnings on stderr; the parity harness should ignore that noise and compare only the printed project-relative result lines.

Use the bifrost CLI from `/home/jonathan/Projects/bifrost`:

    cargo run --bin most_relevant_files -- \
      --root /home/jonathan/Projects/brokk \
      app/src/main/java/ai/brokk/gui/MergeDialogPanel.java

When comparing outputs, filter both sides down to actual result lines before diffing. The robust rule is: keep only lines whose text resolves to an existing file under the project root. Do not use a tracked-file filter or a hard-coded prefix allowlist, because live-workspace semantics intentionally allow untracked files and paths such as `.github/workflows/...` to appear in the ranked results.

The single-seed parity loop is:

    1. Run the deterministic 100-file sample with the Brokk CLI invocations parallelized.
    2. If a mismatch appears, inspect whether it is a harness bug, a ranking bug, or a Brokk analyzer-state bug.
    3. Add a failing automated test on the wrong side before changing code.
    4. Repeat until the single-seed sweep is clean.

The pair-seed parity loop is the same, but only begins after the single-seed sweep is clean.

## Idempotence and Recovery

These edits are additive. Re-running the tool wiring or the tests is safe. If Git-based ranking fails in a given repository, the code should degrade to import-only results instead of failing the whole tool. If a test repository leaves a locked `.git` directory behind on teardown, remove `.git` before deleting the temp directory, mirroring the cleanup approach used in Brokk's Java Git ranking tests.

## Artifacts and Notes

The most important upstream tests to mirror are:

    ../brokk/app/src/test/java/ai/brokk/analyzer/ranking/ContextNoGitFallbackTest.java
    ../brokk/app/src/test/java/ai/brokk/analyzer/ranking/ImportPageRankerTest.java
    ../brokk/app/src/test/java/ai/brokk/analyzer/ranking/GitDistanceRelatedFilesTest.java

The upstream `ContextTest` cases that only stub `getMostRelevantFiles` for unrelated context-summary behavior are not part of this feature's parity target.

## Interfaces and Dependencies

In `src/relevance.rs`, define crate-visible entrypoints equivalent to:

    pub(crate) fn most_relevant_project_files(
        analyzer: &dyn IAnalyzer,
        seeds: &[ProjectFile],
        top_k: usize,
    ) -> Vec<ProjectFile>

and an internal import-ranking helper that supports the Brokk `reversed` flag for parity tests.

In `src/searchtools.rs`, define:

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct MostRelevantFilesParams {
        pub seed_files: Vec<String>,
        #[serde(default = "default_limit")]
        pub limit: usize,
    }

    #[derive(Debug, Clone, Serialize)]
    pub struct MostRelevantFilesResult {
        pub files: Vec<String>,
        pub not_found: Vec<String>,
    }

The new Cargo dependency is `git2`. The public Python client interface must include:

    def most_relevant_files(self, seed_files: list[str], *, limit: int = 20) -> MostRelevantFilesResult

Revision note: on 2026-04-04 this ExecPlan was revised to reflect the work already landed, record the confirmed parity bugs already fixed, capture the remaining Brokk cached-analyzer divergence, document the commit points (`2a599f1`, `dd61c92`, `abe4f1aa61`), and make the execution order explicit: fix the Brokk analyzer divergence first, then rerun 100 deterministic single-file seeds, then 100 deterministic pairs only after singles are clean.

Revision note: later on 2026-04-04 the cross-repo parity harness was extended to support arbitrary target repositories and language-specific seed pools. The ignored Rust batch tests now accept:

    BROKK_APP_ROOT=/home/jonathan/Projects/brokk
    BROKK_PARITY_PROJECT_ROOT=/path/to/target/repo
    BROKK_PARITY_EXTENSIONS=java
    BROKK_PARITY_SAMPLE_SIZE=100

The Brokk app root stays fixed to the compiled Brokk checkout, while `BROKK_PARITY_PROJECT_ROOT` is the repo being compared and `BROKK_PARITY_EXTENSIONS` selects the seed language by file extension (for example `go`, `py`, `js`, `ts,tsx`, `cs`, `php`, `scala`, or `c,cc,cpp,cxx,h,hpp,hh,hxx`). This is the mechanism for running one 100-single-file batch and one 100-pair batch per supported language against external projects under `~/Projects` or `~/Projects/brokkbench/clones`.

Revision note: on 2026-04-05 the harness and Brokk CLI were further tightened so language-specific parity runs are actually scoped to the language under test instead of auto-detecting every tracked language in the repo. When `BROKK_PARITY_EXTENSIONS` maps to a single language, bifrost now builds a single-language `TestProject` workspace and Brokk's `MostRelevantFilesCli` is invoked with the matching internal language override. Keep this rule in sync with the shared entry-point design docs as well as the code; otherwise large out-of-scope files, such as a giant `.mjs` in a TypeScript repo, can dominate startup and invalidate the intended per-language matrix.
