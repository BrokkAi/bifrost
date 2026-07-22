# Rust task-ranked reference differential at `ca218491`

## Selection and provenance

This is the authoritative Rust leg of the task-ranked campaign. Repository membership came from `tasks.task_repos(tasks.SFT_PREDICATES, langs=["rust"])`, followed by a stable descending `task_count` sort. `SFT_PREDICATES` applies the required `large-repos.csv` exclusion. The five repositories were passed to the runner explicitly:

| Repository | Eligible tasks | Pinned head | First clean missing | Final missing |
| --- | ---: | --- | ---: | ---: |
| `tokio-rs__tokio` | 142 | `c4c6265a0746a79d4a2f3852f726aa0101f29fd3` | 363 | 19 |
| `kivikakk__comrak` | 59 | `45c1995fe922b6d5782b971a377721f088025fc8` | 97 | 40 |
| `ordian__toml_edit` | 44 | `cf87ca6c214253a34f9d2ce77f13a6155437f340` | 112 | 9 |
| `tokio-rs__tracing` | 40 | `d9d4c542de10f5d3a711b7a45ffe450fd0666437` | 298 | 50 |
| `foobarto__stado` | 37 | `3f1f85b30a3c6f9f7c8d83fa2fc4e7d643d5b8d1` | 0 | 0 |

The first clean pushed-head corpus contained 870 raw missing rows. Successive structured repairs reduced that to 321 in the first full dirty rerun, 248 in the final dirty smoke, 140 at clean `b58b8932`, 120 at clean `c7b8fa62`, and 118 at the final pushed source head `ca21849189c7dba334b435a63350f0ea35cd4321`.

## Defects and fixes

The campaign closed 24 issues, each solely assigned to `jbellis` before its implementation began:

- routing, imports, re-exports, and visibility: #987, #992, #1013, and #1045;
- receiver and member proof: #990, #1006, #1007, #1011, #1012, and #1049;
- declaration identity and Rust namespaces: #991, #993, #994, and #998;
- macro syntax and generated ownership: #995, #1046, #1050, and #1053;
- Cargo physical target and dependency identity: #1042 and #1052;
- value constructors and struct labels: #1047 and #1048;
- final clean-corpus regressions: #1060 and #1061.

The fixes are structured throughout. They preserve exact AST roles, declaration ranges, namespaces, lexical and import scopes, Cargo target/dependency routes, and physical CodeUnit identity. Macro support uses tree-sitter token-tree structure and proven emitted ownership. No regex or text-search resolver fallback was added.

The final two repairs keep exact same-file lexical `Self` definitions authoritative before considering cross-file Cargo replicas, and resolve lowercase `self` to the nearest enclosing inline `mod_item` by exact tree-sitter declaration range. Their implementation is `443bf72b`; the accepted integrated source head is `ca218491`.

## Residual disposition

The final corpus contains 118 raw `missing` classifications: Tokio 19, tracing 50, Comrak 40, toml_edit 9, and Stado 0. They are not remaining product defects. All were exhaustively reviewed in the preceding clean audit as nonacceptance artifacts, primarily qualifier/declaration-focus sites where the differential asks inverse lookup to reproduce a token that is intentionally outside the public inverse contract.

The canonical sorted final ledger is `/mnt/optane/tmp/reference-differential/rust-task-top5-ca218491-missing-ledger.jsonl`, SHA-256 `107fc2d9b684ad0e75e0425be59f5bc110d501ff4dc05b6a9d5c62d290f7fa97`. Its multiset comparison against the 120-row `c7b8fa62` ledger proves:

- 118 normalized rows are byte-identical;
- the only removals are Tokio `Self::Future` at `tokio/src/net/addr.rs:1614..1620` and tracing-appender lowercase `self` at `tracing-appender/src/non_blocking.rs:14642..14646`;
- there are zero added rows.

## Acceptance evidence

The release runner was rebuilt from the clean pushed source head. Its SHA-256 is `1faaaf9c634c1d9ed065a69b8488e70458b3d44ca88022b4f0d51567ad8e45b1`.

The final five-repository artifact is `/mnt/optane/tmp/reference-differential/rust-task-top5-ca218491-final.jsonl`, SHA-256 `e7be755863fac43a9a3a01bc032cac26697f248522c02cf2503dd65b3c7d871c`; its log SHA-256 is `704de8874c684d68518043963eddde20e98baedd80e66ae8796d8afadc9a189f`. All five records are clean and completed at `ca218491`, share fingerprint `25efbc1239033c9f3cea1fd9a59af850771c931e11a6de349dc95ff219b489a6`, pin the repository heads above, and report zero file errors, candidate-limit events, skipped targets, or target truncation.

Across the four repositories with eligible Rust files, the run sampled 40,000 sites: 6,990 consistent, 648 editor-only, 32,244 inconclusive, 118 reviewed missing, and zero unproven. Exact ephemeral post-fix witnesses both became consistent with one exact forward target and an exact inverse byte hit:

- Tokio `Self::Future`: `rust-ca218491-tokio-self-future-exact.jsonl`, SHA-256 `2d75afe773f5cfa02b620d988b2b10ced70aa50af9fdbcb95f80c07c69d8797c`;
- tracing-appender lowercase `self`: `rust-ca218491-tracing-self-qualifier-exact.jsonl`, SHA-256 `88a608465bf9542448c1392f4b2e61727e2383e0ecd311a5ba72f7de48477961`.

Validation passed the 610-test definition suite, 196-test Rust inverse suite, 17-test Rust residual suite, 8-test differential suite, the persisted candidate-bounded guard, formatting, diff hygiene, isolated all-target/all-feature Clippy with warnings denied, and the complete `cargo test --features nlp,python` matrix. Three process-spawning benchmark tests cannot run inside the restricted process sandbox; all five tests in that group and the complete feature-enabled matrix passed outside it. All 24 task-ranked Rust issues are closed with final evidence; unrelated historical Rust issues were not swept into this closure.
