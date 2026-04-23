# Use Fast Hash Collections Internally

This ExecPlan is a living document. It follows `.agent/PLANS.md` and must be kept current as implementation proceeds.

## Purpose / Big Picture

The analyzer builds large internal maps and sets keyed by repository paths, files, and code units. Rust's standard `HashMap` and `HashSet` use a SipHash-based hasher intended to resist malicious hash-collision attacks, but this project analyzes trusted local repositories rather than accepting adversarial network keys. After this change, internal hash collections use a faster compiler-style hasher so analyzer builds spend less time in hashing while preserving deterministic output through existing sorted boundaries.

## Progress

- [x] (2026-04-23T14:20:14Z) Audited `src` for `HashMap` and `HashSet` usage and found internal analyzer/relevance/cache usage with deterministic behavior owned by `BTree*` collections or explicit sorting.
- [x] (2026-04-23T14:20:14Z) Decided to add crate-local `HashMap` and `HashSet` aliases backed by `rustc_hash`.
- [x] (2026-04-23T14:26:44Z) Converted internal source modules from direct `std::collections::HashMap` and `std::collections::HashSet` use to crate-local aliases.
- [x] (2026-04-23T14:26:44Z) Ran formatting, compile checks, focused analyzer tests, and a broad integration-test compile.
- [x] (2026-04-23T14:26:44Z) Recorded final validation and post-change Ghidra timing.
- [ ] Commit the change.

## Surprises & Discoveries

- Observation: The existing code already separates deterministic output from hash iteration in most hot paths. Child vectors are canonicalized in immutable analyzer state, and result boundaries use explicit sorting or `BTree*`.
  Evidence: The prior Ghidra profile showed hashing hot spots in `CodeUnit::hash` and `PathBuf::hash`, while `canonicalize_children` was no longer the dominant issue.

- Observation: `rustc_hash::FxHashMap` and `FxHashSet` are aliases to standard collections with a custom hasher, so `HashMap::new()` and `HashSet::with_capacity()` are not available on those aliased types.
  Evidence: `cargo check` reported constructor errors for the custom-hasher map/set types.

- Observation: One integration test constructed a standard `HashSet` for comparison with a public watcher delta set.
  Evidence: `cargo test --tests --no-run` failed in `tests/project_change_watcher_test.rs` until the test used `brokk_analyzer::hash::HashSet`.

## Decision Log

- Decision: Use standard `HashMap` and `HashSet` tables with `rustc_hash::FxBuildHasher` through crate-local aliases instead of introducing `xxhash` wrappers or hashbrown tables.
  Rationale: `rustc_hash` is idiomatic for compiler/analyzer workloads and preserves the standard collection API surface expected by Rayon and public trait signatures. Construction sites use `Default::default()` or explicit `with_capacity_and_hasher` where a custom hasher prevents `new()`/`with_capacity()`.
  Date/Author: 2026-04-23 / Codex.

- Decision: Treat hash collection iteration order as unspecified and fix any ordering-dependent tests or render paths by sorting at the boundary.
  Rationale: The user's stated contract is that this repository is not antagonistic, but deterministic output remains important. Fast hash maps should not become an accidental ordering source.
  Date/Author: 2026-04-23 / Codex.

## Outcomes & Retrospective

Implemented crate-local fast hash aliases and converted internal analyzer, watcher, and relevance code to use them. Deterministic output remains owned by ordered collections or explicit sorting; no rendering or JSON/MCP path was left depending on hash iteration order.

Validation completed:

    cargo check
    cargo fmt --check
    cargo test --lib
    cargo test --test java_modules_and_constructors --test java_update_parity --test java_update_regressions --test python_module_analyzer_test
    cargo test --tests --no-run
    cargo build --release --bin most_relevant_files

Post-change Ghidra timing for `target/release/most_relevant_files --root /home/jonathan/Projects/brokkbench/clones/NationalSecurityAgency__ghidra __missing_seed__.java` with `BIFROST_TIMING=1`:

    workspace_build total: 1,929.5 ms
      enumerate Java files: 176.6 ms
      analyze_files[15490]: 496.0 ms
      index_state: 1,230.3 ms

The command exits nonzero because the seed is intentionally missing; the analyzer build timing completes before that expected error.

## Context and Orientation

The main analyzer indexing code lives in `src/analyzer/tree_sitter_analyzer.rs`. Language-specific analyzers such as `src/analyzer/java_analyzer.rs`, `src/analyzer/python_analyzer.rs`, and others store import caches, relevance inputs, and hierarchy sets in hash collections. `src/relevance.rs` uses temporary hash maps and sets while ranking related files. These collections do not define public output order; deterministic output is handled by `BTreeMap`, `BTreeSet`, or explicit sorting before rendering or JSON/MCP responses.

`HashMap` means a key-value table. `HashSet` means a unique-value table. The standard library default hasher favors attack resistance over speed. The crate aliases keep standard collection tables but replace the default hasher with `rustc_hash::FxBuildHasher`, a faster non-cryptographic hasher suitable for local compiler-style analysis.

## Plan of Work

Add `rustc-hash` to `Cargo.toml`. Add a new public module, `src/hash.rs`, exporting `pub type HashMap<K, V> = std::collections::HashMap<K, V, rustc_hash::FxBuildHasher>` and `pub type HashSet<T> = std::collections::HashSet<T, rustc_hash::FxBuildHasher>`, with a comment documenting the design decision and warning that output order must be explicit. The module is public because some public APIs expose hash sets.

Update internal source modules under `src` to import `crate::hash::{HashMap, HashSet}` where they need hash collections. Keep `BTreeMap` and `BTreeSet` imports from `std::collections` because those are the ordered collections. Replace fully qualified `std::collections::HashMap` and `std::collections::HashSet` references in source with the crate aliases unless a compile error proves a third-party API needs the standard types.

If a test fails because it depended on hash iteration order, fix the test or rendering path to sort explicitly instead of reverting that collection to standard hashing.

## Concrete Steps

From `/home/jonathan/Projects/bifrost`, edit the files described above. Then run:

    cargo fmt --check
    cargo check
    cargo test --lib

Run focused analyzer tests if compile or behavior changes touch language-specific APIs:

    cargo test --test java_modules_and_constructors --test java_update_parity --test java_update_regressions --test python_module_analyzer_test

## Validation and Acceptance

The change is accepted when the project compiles, tests pass, and `rg "std::collections::Hash(Map|Set)|std::collections::\\{[^}]*Hash" src` shows no production use of standard hash collections except intentionally documented exceptions. Deterministic rendering and JSON/MCP behavior must remain owned by sorting or ordered collections, not by hash map iteration order.

## Idempotence and Recovery

The edits are mechanical and can be repeated safely. If `cargo check` reports a type mismatch with an external crate API, first adapt the local boundary by converting or collecting into the required type. Only leave a default-hasher standard hash collection in source if the external API strictly requires it and document the exception in this plan.

## Artifacts and Notes

Initial profile context from the Ghidra Java analyzer build:

    workspace_build total: 2,628 ms
      enumerate Java files: 178 ms
      analyze_files[15490]: 655 ms
      index_state: 1,757 ms
    perf children included 7.7% CodeUnit::hash and 4.2% PathBuf::hash.

## Interfaces and Dependencies

`Cargo.toml` must include:

    rustc-hash = "2"

`src/hash.rs` must expose:

    pub type HashMap<K, V> = std::collections::HashMap<K, V, rustc_hash::FxBuildHasher>;
    pub type HashSet<T> = std::collections::HashSet<T, rustc_hash::FxBuildHasher>;

`src/lib.rs` must declare:

    pub mod hash;
