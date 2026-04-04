# Add Hybrid `most_relevant_files` To Bifrost Searchtools

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

After this change, bifrost and Brokk will both expose a small command-line tool that takes one or more project-relative filenames and prints the top 100 related files, one per line, in relevance order. A human can prove it works by running the Rust CLI against the Brokk repository, running the Java CLI against the same repository, and comparing the outputs for 100 random seed files. Any mismatch discovered during that comparison must be turned into a failing automated test before the incorrect implementation is fixed.

## Progress

- [x] (2026-04-03 20:32Z) Confirmed the existing Rust and Python searchtools surfaces, the analyzer/project APIs, and the absence of any current Git ranking module in bifrost.
- [x] (2026-04-03 20:34Z) Confirmed the Brokk reference behavior and the battle-tested Java cases in `ContextNoGitFallbackTest`, `ImportPageRankerTest`, and `GitDistanceRelatedFilesTest`.
- [x] (2026-04-03 20:55Z) Added `src/relevance.rs` with Brokk-style import Personalized PageRank, Git co-change ranking via `git2`, rename canonicalization, and a crate-local seed-file entrypoint.
- [x] (2026-04-03 20:58Z) Exposed `most_relevant_files` through `src/searchtools.rs`, `src/searchtools_service.rs`, `src/mcp_server.rs`, and the Python `bifrost_searchtools` client and model layer.
- [x] (2026-04-03 21:06Z) Ported the relevant Brokk Java ranking cases into Rust tests, including hybrid Git fallback, reverse import traversal, multi-language import routing, and rename canonicalization. Added searchtools service, MCP, and Python client coverage for the new tool.
- [x] (2026-04-03 21:12Z) Ran `cargo test`, `cargo fmt --check`, and `uv run python -m unittest discover -s python_tests -p 'test_*.py'` successfully after the new tool landed.
- [x] (2026-04-04 15:32Z) Confirmed that `../brokk` is readable but still appears non-writable from the sandbox, so cross-repo edits may need to go through the escalated execution path even though the user launched Codex with `--add-dir`.
- [ ] (2026-04-04 15:32Z) Add a CLI binary in bifrost that accepts project-relative filenames, prints the top 100 related files on stdout, and can be pointed at the Brokk repository root.
- [ ] (2026-04-04 15:32Z) Add the matching Brokk CLI and a direct `Context` entrypoint that accepts `Collection<ProjectFile>` so the Java side can rank the same seed set without constructing synthetic context fragments.
- [ ] (2026-04-04 15:32Z) Run both CLIs on 100 random files from the Brokk repository, capture mismatches, convert each confirmed algorithm bug into a failing automated test, and then fix the wrong side.

## Surprises & Discoveries

- Observation: bifrost already has the analyzer-side import data needed for Brokk's import ranking, including `imported_code_units_of` and `referencing_files_of` on the languages that matter here.
  Evidence: `src/analyzer/capabilities.rs` and the language delegates already implement `ImportAnalysisProvider`.

- Observation: bifrost has no Git abstraction comparable to Brokk's `GitRepo`, so hybrid parity requires fresh Git infrastructure rather than only wiring.
  Evidence: repository search found no `git2`, no Git repository wrapper, and no existing ranking code beyond analyzer autocomplete ordering.

- Observation: `FilesystemProject` respects ignore rules in a way that `TestProject` does not, which made ad hoc import-only temp-directory tests flaky depending on path and ignore configuration.
  Evidence: the first service-layer temp project returned empty relevance results under `FilesystemProject` while the equivalent `TestProject` parity cases passed; switching the JSON-boundary tests to explicit Git-backed root-level files removed that nondeterminism.

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

## Outcomes & Retrospective

The repository now has a Brokk-style hybrid file-relevance stack instead of only symbol and summary searchtools. Rust callers can rank related files from a seed set of `ProjectFile`s, MCP clients can call `most_relevant_files`, and the Python `bifrost_searchtools` package exposes the same capability through a typed result model.

The parity coverage is deliberately split by concern. The new unit tests in `src/relevance.rs` preserve the upstream import-ranking edge cases that do not have to be public API, such as reverse traversal and multi-language delegate routing. The integration tests in `tests/most_relevant_files.rs` preserve the upstream hybrid behaviors that matter to the public tool, including no-Git fallback, under-filled Git results, untracked seeds, and rename canonicalization. The service, MCP, and Python boundary tests prove that the tool is actually reachable through the supported front doors.

The next milestone is no longer just feature exposure. It is operational parity. The repository needs a tiny CLI surface that makes the ranking observable from a shell, plus evidence from a 100-file comparison against the Brokk implementation. That comparison is the acceptance driver for any further algorithm changes.

## Context and Orientation

The existing public searchtools layer lives in `src/searchtools.rs`. It defines serde parameter and result types for tools such as `search_symbols`, `get_symbol_locations`, and `get_file_summaries`, and it is invoked through the shared JSON service in `src/searchtools_service.rs`. The standalone MCP server in `src/mcp_server.rs` is a thin adapter over that service, and the Python package in `bifrost_searchtools/` talks to the same service through the PyO3 module defined in `src/python_module.rs`. `src/relevance.rs` now contains the hybrid ranking logic itself. A small Rust binary can therefore call that code directly without going through JSON.

The new feature belongs beside those tools, not in a new Context abstraction. Bifrost's analyzer interface already exposes a `Project` via `IAnalyzer::project()`, and file identities are represented by `ProjectFile`. The user-visible tool therefore accepts project-relative seed paths, resolves them to `ProjectFile` values, and passes them to the ranking module directly.

The reference implementation is Brokk's `Context.getMostRelevantFiles`, backed by `ImportPageRanker` and `GitDistance`. For the CLI comparison, Brokk also needs a direct seed-file entrypoint in `Context.java` so both sides can accept the same input shape: a collection of existing project files. The important behaviors to preserve are straightforward. Seed files never appear in results. Git ranking is attempted first when a usable repository and tracked seeds exist. Import ranking then fills any remaining slots without duplicates. Import ranking expands only a local graph around the seeds, respects two-hop flow, supports reverse traversal internally, and stays deterministic on ties.

## Plan of Work

First, keep the already-landed Rust ranking implementation and add a dedicated CLI binary under `src/bin/` that accepts `--root` plus one or more project-relative filenames. It must build a `FilesystemProject`, construct a `WorkspaceAnalyzer`, resolve the input filenames, call the existing ranking function with a limit of 100, and print one related file per line.

Next, update Brokk's `Context.java` so there is a direct overload that accepts a `Collection<ProjectFile>` seed set and computes the same hybrid ranking without requiring the caller to create `ContextFragment` objects. Then add a Java CLI under `app/src/main/java/ai/brokk/tools/` that accepts `--root` plus project-relative filenames, resolves them through `ContextManager.toFile`, invokes the new `Context` overload, and prints one result per line.

After both CLIs exist, run them against the same 100 random filenames from the Brokk repository. Record any mismatches, reduce each mismatch to the smallest deterministic fixture that reproduces it, and add a failing automated test on the side that is wrong. Only after the test fails should the implementation be corrected.

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

Run the CLI comparison after both binaries exist:

    cd /home/jonathan/Projects/bifrost
    cargo run --bin most_relevant_files -- --root /home/jonathan/Projects/brokk <seed-file>

    cd /home/jonathan/Projects/brokk
    ./gradlew :app:classes
    java -cp app/build/classes/java/main:app/build/resources/main:<runtime-classpath> ai.brokk.tools.MostRelevantFilesCli --root /home/jonathan/Projects/brokk <seed-file>

    cd /home/jonathan/Projects/bifrost
    shuf -n 100 <(find /home/jonathan/Projects/brokk/app/src/main/java -name '*.java' -printf '%P\n')

The exact Java classpath assembly step must be documented with the final working command once the CLI is built.

Run focused validation from `/home/jonathan/Projects/bifrost`:

    cargo test --test most_relevant_files --test searchtools_service --test bifrost_mcp_server
    cargo test
    uv run python -m unittest discover -s python_tests -p 'test_*.py'

## Validation and Acceptance

Acceptance for the Rust ranking core is that the translated Brokk Java parity cases pass: no-Git import fallback, hybrid Git-plus-import merge, fill behavior when Git under-fills, untracked seed fallback, rename canonicalization, two-hop import flow, hub ranking, cycle stability, empty-internal-import handling, reverse traversal, and multi-language import routing.

Acceptance for the public tool is that a call shaped like:

    {"seed_files":["A.java"],"limit":5}

returns:

    {"files":[...],"not_found":[...]}

with only project-relative paths, never scores, never the seed file itself, and no duplicates.

Acceptance for the shared-service and Python boundaries is that `SearchToolsService::call_tool_json("most_relevant_files", ...)` and `SearchToolsClient.most_relevant_files(...)` both return the same ordered paths for the same fixture setup, and the MCP server publishes the tool in `tools/list`.

Acceptance for this milestone is stronger than feature wiring. The Rust CLI and the Java CLI must both print the top 100 related files, one per line, for the same seed input. A 100-file random comparison over the Brokk repository must complete, and every observed mismatch must have an explanation backed by a failing test and a fix on the wrong side.

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

Revision note: on 2026-04-04 this ExecPlan was revised to add the cross-repo CLI requirement, the 100-file random comparison against the Brokk repository, and the rule that any observed mismatch must first be captured in a failing automated test before the implementation is changed.
