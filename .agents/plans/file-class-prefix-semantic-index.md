# Replace blended semantic vectors with canonical file/class-prefixed documents

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document is maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost semantic search currently embeds each function body and a generated class-or-file summary separately, then averages the two vectors. Experiments in `~/Projects/brokkbench/localizer` found that a single SweRank-shaped document performs at least as well: a workspace-relative file/function path followed by source, with the enclosing class name added for methods. After this change Bifrost directly embeds that canonical document, returns the same signatures as before, and keeps BM25 based on raw source. Users can observe the change through recording-embedder tests that assert the exact embedded text and through a smaller semantic cache with no summary or component-vector tables.

## Progress

- [x] (2026-08-04) Inspected the localizer renderer, Bifrost extraction/materialization pipeline, active index, cache schema, and garbage collection.
- [x] (2026-08-04) Chose exact SweRank rendering with a literal `class` marker and raw-source-only BM25.
- [x] (2026-08-04) Implemented function-only extraction and direct document embedding.
- [x] (2026-08-04) Added path-aware semantic cache migration 14 and updated active indexing and garbage collection.
- [x] (2026-08-04) Updated diagnostics and behavior-focused tests, including exact rendering, raw-source BM25, identical blobs at different paths, cache sharing, and migration preservation.
- [x] (2026-08-04) Ran focused NLP tests and all-feature Clippy. One unrelated wall-clock-sensitive C# usage test timed out only under its 1,476-test parallel binary and passed alone in 0.85 seconds; the user approved skipping further reruns.
- [x] (2026-08-04) Rewarmed all 20 CodeScaleBench source revisions sequentially with DW10 into the shared schema-14 cache and wrote a 20-entry run manifest.
- [x] (2026-08-04) Profiled pathological generated Java and C++ repositories encountered by the rewarm, fixed quadratic comment-line indexing, bounded malformed C++ callable recovery, and removed redundant per-function global definition queries from streaming extraction.

## Surprises & Discoveries

- Observation: Existing file-summary chunks consume embeddings but cannot become returned results because active-index resolution discards rows without a function symbol.
  Evidence: `ActiveIndex::resolve` filters occurrences whose `fqfn` is absent.

- Observation: The exact localizer renderer recognizes many container kinds but always emits the literal text `class Name:`.
  Evidence: `localize_sft_core.py::swerank_document_text` returns `class {class_name}:{source_text}` for every recognized method parent.

- Observation: Adding the path to an embedding makes the current blob-OID-only cache identity incorrect for renames and for identical blobs at multiple paths.
  Evidence: `materialize_missing` currently chooses one representative `ProjectFile` per OID, while `ActiveIndex` attaches the resulting vector to every active path carrying that OID.

- Observation: Rust's default test concurrency can starve a pre-existing C# usage test with a wall-clock budget on this shared workstation.
  Evidence: `csharp_scan_usages_truncated_scan_does_not_report_verified_absent` returned `time_budget` in the full 1,476-test binary but passed alone in 0.85 seconds. The semantic-index change does not touch the C# usage analyzer.

- Observation: Function source rendering defeated the streaming file-state cache by querying the global definition index once per function.
  Evidence: A ten-second live ArangoDB profile attributed most useful samples to SQLite B-tree execution, row comparison, page-cache operations, and mutexes, including `candidate_row_from_row`. `get_sources` called `definitions(fq_name)` even though the active streaming scope already held the complete same-file declaration and range maps. Reusing those maps increased live materialization throughput from roughly 7-8 files/second to at least 17.5 files/second, with later samples exceeding 40 files/second as the pipeline filled.

- Observation: Source-comment expansion recomputed a full-file line-start index for every function in generated monoliths.
  Evidence: The OpenJDK/Kubernetes profile concentrated samples in `compute_line_starts` and `CharIndices`; replacing it with a bounded backward line walk reduced the remaining Kubernetes extraction to 47.4 seconds while preserving mixed-line-ending and adjacent-comment behavior.

## Decision Log

- Decision: Render free functions as `path/function\nsource` and methods as `path/Class/function\nclass Class:source`, with no newline after the colon.
  Rationale: This is byte-for-byte the measured localizer/SweRank representation.
  Date/Author: 2026-08-04 / Codex and user.

- Decision: Always emit the literal word `class`, not a language-native container keyword.
  Rationale: Native kinds are collapsed in `CodeUnitType`, recovering them cleanly would require a broad analyzer contract change, and it would diverge from the evaluated representation.
  Date/Author: 2026-08-04 / Codex and user.

- Decision: Keep BM25 tokens derived from raw function source only.
  Rationale: The user explicitly wants the new prefix to affect embeddings without changing the lexical retrieval leg or persisting duplicate text.
  Date/Author: 2026-08-04 / Codex and user.

- Decision: Key materialized semantic files by both blob OID and normalized relative path.
  Rationale: The path is part of the embedded document, so OID alone no longer determines the vector. The pair still shares work safely across branches and worktrees.
  Date/Author: 2026-08-04 / Codex.

- Decision: Retain the existing tokenizer dependency only for explicit sequence-length diagnostics, not live indexing.
  Rationale: The Python sidecar already applies the model's truncation contract. Removing production Rust token counting avoids duplicate per-file tokenization while keeping the diagnostic probe useful.
  Date/Author: 2026-08-04 / Codex.

- Decision: During `AnalyzerStreamingFileScope`, build one lazy same-file FQName-to-ranges index and use it for function source rendering.
  Rationale: It preserves the ordinary definition lookup and overloaded-function grouping contracts while eliminating one global SQLite lookup per function and avoiding a new quadratic in-memory scan.
  Date/Author: 2026-08-04 / Codex.

## Outcomes & Retrospective

The implementation is complete. Bifrost now embeds one ephemeral canonical document per function, stores only its direct quantized vector and raw-source BM25 terms, and uses `(blob_oid, rel_path)` as the materialization identity. Migration 14 automatically discards incompatible semantic rows while retaining analyzer and semantic-pack data. The schema and implementation remove summary rows, component vectors, composed vectors, parent alpha, and live Rust-side token counting.

Focused validation passed 49 NLP unit tests and 49 cache migration tests. The comprehensive `nlp,python` run passed the root, analyzer, persistence, semantic, and other suites until the unrelated C# usage wall-clock test described above stopped `suite_usages`; that test passed immediately in isolation. `cargo fmt --check` and all-target/all-feature Clippy with warnings denied passed. The optional real-model smoke remains ignored by design. The `bifrost-policy-checking` skill and its MCP tools were not installed in this session, so the repository policy pack could not be run.

The sequential DW10 CodeScaleBench rewarm completed all 20 requested source revisions. The shared cache at `/mnt/T9/repo-clones/.codescale-cache-dw10/bifrost_cache.db` is schema version 14 and contains 235,879 semantic files, 3,746,455 function chunks, and 2,244,371 distinct vectors in an 11 GiB database. The run manifest is `/mnt/containers/code_isnt_memory/codescale-flink42-file-class-rewarm-20260804-r1/prewarm-manifest.json`. The final large revisions completed as follows: ArangoDB in 923.4 seconds with 636,856 active chunks, Elasticsearch in 484.3 seconds with 444,413 chunks, and PostgreSQL in 123.1 seconds with 35,521 chunks. The post-fix Elasticsearch stage split was 40.0 seconds extraction, 254.2 seconds embedding, and 250.1 seconds SQLite, confirming extraction was no longer the bottleneck. The NLP crate now has 50 passing tests, and the all-target/all-feature Clippy gate still passes after the runtime-discovered fixes.

## Context and Orientation

`crates/bifrost-nlp/src/chunker.rs` walks analyzer `CodeUnit`s and emits function chunks with their nearest structured enclosing class. `materialize.rs` renders and directly embeds canonical documents. `store.rs` persists direct vector hashes and raw-source BM25 terms in the unified SQLite cache created by `crates/bifrost-core/src/cache_db.rs`. `active_index.rs` joins exact persisted `(blob_oid, rel_path)` rows to the active worktree and creates the in-memory vector/BM25 lookup used by `query.rs`. `crates/bifrost-core/src/cache_gc.rs` performs shared reachability collection for semantic and analyzer data.

The canonical embedding document is temporary. Bifrost persists only its hash and quantized vector, plus function metadata and the pre-tokenized raw-source BM25 text. The embedding sidecar continues to add the selected model's passage prefix and enforce its tokenizer sequence limit.

## Plan of Work

First simplify `chunker.rs` to return function occurrences containing raw source, the fully qualified result symbol, the simple function name, optional nearest enclosing-class name, and source lines. Add one renderer that consumes a normalized relative path and such a function occurrence to produce the exact two document forms. Delete summary construction, token-budget logic, file-summary kinds, and source-text deduplication.

Next simplify `materialize.rs`, `keys.rs`, and `engine.rs`. Compute raw-source BM25 tokens, render and hash the embedding document, embed every missing document hash directly, quantize it once, and persist the vector and function metadata. Remove parent alpha, component-vector reads and writes, vector composition, and production token counting. Keep batching by document count and bytes. Remove the Rust tokenizer from live sidecar workers; diagnostics that need token counts may load it directly.

Append `crates/bifrost-core/migrations/cache/0014-semantic-file-documents.sql`. It must delete the incompatible semantic data and replace the old semantic blob/chunk/summary/component tables with path-and-OID-keyed semantic file rows, function-only chunk rows, and one vector table keyed by `vector_hash`. It must preserve analyzer and semantic-pack tables. Add the migration to `cache_db.rs`, set the SQLite user version to 14, and extend migration tests.

Then update `store.rs`, `indexer.rs`, `active_index.rs`, and `query.rs` so missing-materialization checks, persistence, active construction, incremental watcher updates, vector scans, and resolution use `(blob_oid, rel_path)` and `vector_hash`. Update both semantic-store GC and shared core GC to select distinct semantic OIDs, delete every path variant of an unreachable OID, and delete vectors no longer referenced by a chunk. Rename component/composed terminology. Update semantic-index status to count only function occurrences.

Finally replace implementation-shaped tests with behavior checks for exact document rendering, structured nearest-class selection, raw-only BM25, direct embedding/cache reuse, path-sensitive identity, watcher updates, migration preservation, and GC. Update affected diagnostic binaries and documentation comments.

## Concrete Steps

Work from `/mnt/optane/bifrost-nlp`. Make edits with `apply_patch`, keep this plan current at each stopping point, and commit only changed files on the current branch.

Run focused validation while implementing:

    cargo fmt
    uv run --python 3.12 -- cargo test -p brokk-bifrost-nlp
    BIFROST_SEMANTIC_INDEX=off uv run --python 3.12 -- cargo test --test suite_semantic --features nlp,python
    BIFROST_SEMANTIC_INDEX=off uv run --python 3.12 -- cargo test --test suite_persistence --features nlp,python

Run the comprehensive gate before completion:

    BIFROST_SEMANTIC_INDEX=off uv run --python 3.12 -- cargo test --features nlp,python
    uv run --python 3.12 -- cargo clippy --all-targets --all-features -- -D warnings

Do not redirect Cargo builds into `/tmp`; if shared caches are blocked by the sandbox, rerun the command with filesystem escalation.

## Validation and Acceptance

The renderer tests must prove the exact newline and colon-adjacency contract for a free function and a method. Analyzer-backed tests must prove the nearest structured class is selected without regex parsing and that no file-summary occurrence remains. A recording fake must observe the headered document while BM25 tests prove path-only tokens do not enter lexical search. Two files with identical bytes at different paths must produce path-specific vector hashes and results; rebuilding an unchanged `(path, OID)` pair must issue no passage embedding. A version-13 fixture must migrate to version 14 with old semantic rows removed and analyzer plus semantic-pack rows intact. Full build, watcher update, vector scan, cache compatibility, and GC tests must pass.

All formatting, task-focused tests, and all-feature Clippy must finish without warnings or failures. The full `nlp,python` suite should be run; a failure demonstrably isolated to an unrelated load-sensitive test may be recorded when the test passes alone and the user agrees not to repeat it. If the `bifrost-policy-checking` skill and its MCP tools are installed, run `bifrost.code-smells` together with every repository policy root before completion; otherwise record that the required tool was unavailable.

## Idempotence and Recovery

The cache migration is transactional and semantic data is rebuildable. Reopening a migrated cache is a no-op. If migration or indexing is interrupted, SQLite rolls back the transaction and a later open retries it. Model/document fingerprint changes may safely clear only semantic materializations and vectors; analyzer and semantic-pack state must never be deleted. Tests use temporary cache databases and do not start production embedding sidecars.

## Artifacts and Notes

The reference renderer inspected in `~/Projects/brokkbench/localizer/localize_sft_core.py` is:

    free:   f"{path}/{function_name}\\n{source_text}"
    method: f"{path}/{class_name}/{function_name}\\nclass {class_name}:{source_text}"

Localizer measurements recorded in `GRANITE_R2_V4_FINAL_RECIPE.md` report headered documents outperforming parent-composed documents for both the Granite v4-final and Voyage nano v4-final evaluations.

## Interfaces and Dependencies

`ModelProfile` no longer exposes `parent_alpha`. `Embedder` no longer exposes `count_tokens`. The canonical document renderer is the sole function that constructs embedding input from file path, function name, optional class name, and source. The SQLite semantic schema exposes one `vector_hash` per persisted function chunk and one vector table; it exposes no summary IDs, component hashes, composed hashes, or stored document text. The external `semantic_search` request and response contracts do not change.

Revision note (2026-08-04): Marked implementation and the 20-revision DW10 rewarm complete, recorded the final direct-document and diagnostic-tokenizer decisions, added validation and cache evidence, documented the runtime-discovered generated-source and streaming-definition bottlenecks, and noted that policy tooling was unavailable. These updates make the plan sufficient to understand and reproduce the completed change without relying on session history.
