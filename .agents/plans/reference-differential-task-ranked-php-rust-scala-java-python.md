# Complete the task-ranked PHP, Rust, Scala, Java, and Python reference differential

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current while work proceeds. Maintain it in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost's public MCP `symbols` toolset and associated Rust and Python APIs support both forward definition lookup and inverse reference lookup. When a source reference resolves forward to a workspace declaration group, a complete inverse query for that declaration should recover the same source range. This campaign tests that contract on the five repositories with the most eligible tasks in PHP, Rust, Scala, Java, and Python.

The repository membership is selected only through `/home/jonathan/Projects/brokkbench/tasks.py`: call `task_repos(SFT_PREDICATES, langs=[LANG])`, order the returned repositories by descending `task_count` while preserving the selector's order for equal counts, and retain five. `SFT_PREDICATES` excludes `large-repos.csv` entries and applies the build, testsome, skip, binding, generated-prompt, and non-fragile-test gates. The differential runner must receive the resulting slugs as explicit repeated `--repo` arguments; its `--repos-per-language` option ranks by code size and is not valid for this objective.

The observable result is twenty-five clean completed repository records, five per language, with every raw `missing` row exhaustively dispositioned. Each legitimate defect must have a GitHub issue assigned to `jbellis` before implementation unless an existing issue is assigned to somebody else, in which case the campaign records and skips it. Owned fixes receive structured behavior tests, exact production proof, local formatting, all-feature Clippy, the complete `cargo test --features nlp,python` gate, direct publication to `origin/master`, and issue closure. LSP shares the implementation and comes through the local gate, but editor-protocol behavior is not the focus.

## Progress

- [x] (2026-07-20 09:15-05:00) Read the repository instructions, `.agents/PLANS.md`, and `/home/jonathan/Projects/bifrost/.agents/docs/reference-differential-runbook.md`; created the persistent goal and established root ownership of planning, GitHub state, review, gates, commits, and publication.
- [x] (2026-07-20 09:25-05:00) Delegated read-only campaign reconciliation to the requested Oldskool research role. The review proved that every earlier PHP/Rust/Scala/Java/Python top-five artifact used code-LOC membership rather than the requested `tasks.py` task-count membership. Those artifacts and their closed fixes remain regression evidence but do not complete this objective.
- [x] (2026-07-20 09:28-05:00) Recomputed all five language sets through `task_repos(SFT_PREDICATES, langs=[LANG])`, sorted by descending task count with stable selector ordering for ties, and independently confirmed all twenty-five clones exist with clean tracked state.
- [x] (2026-07-20 09:20-05:00) Transplanted the previously reviewed PHP #904/#905 structured fix and its behavior tests into this current branch as `fdb7ae8d`; 49 targeted PHP usage tests, 16 whole-workspace graph tests, formatting, diff hygiene, and isolated all-target/all-feature Clippy pass. This remains regression/fix evidence until the task-ranked PHP corpus and clean publication proof are complete.
- [x] (2026-07-20 09:45-05:00) Ran the complete isolated `cargo test --features nlp,python` gate. The sandboxed attempt reached 1,459 passing library tests but denied three benchmark process-I/O tests with `Operation not permitted`; the required unsandboxed rerun then passed the complete unit, integration, and doc-test matrix with zero failures.
- [x] (2026-07-20 09:50-05:00) Committed the corrected task-ranked plan as `c0e01ba9`, forced a release-runner relink so its compile-time manifest path names this worktree, and recorded runner SHA-256 `c98f6b8a649eb0f838942de2de3818f20dcb103bdce7520f29144b53ca2f5682`.
- [x] (2026-07-20 10:00-05:00) Ran the authoritative PHP baseline over the five explicit task-ranked repositories. All five records completed cleanly at `c0e01ba9`; the JSONL SHA-256 is `0e1fb71713e0fe0d9e6b4ab77da36730f58e15f0e801a5f3b288df8c41652ebd`. Raw missing counts were Snipe-IT 0, Laravel 33, CakePHP 46, CodeIgniter4 31, and PhpSpreadsheet 188.
- [x] (2026-07-20 10:18-05:00) Delegated the four nonzero PHP repositories as three disjoint Oldskool triage partitions and independently reviewed the result. All 298 rows are legitimate and exhaustively reduce to 96 owner-relative class references, 200 call-return receiver chains, and four nullsafe calls, with two rows requiring both chain and nullsafe support.
- [x] (2026-07-20 10:22-05:00) Reproduced clean minimal production witnesses and created assigned issues #960, #961, and #962 before implementation. Exact baseline SHA-256 values are `1305e84e...` for Laravel `self`, `4669d644...` for the CakePHP call chain, and `fa77f406...` for the CakePHP nullsafe call.
- [x] (2026-07-20 10:50-05:00) Integrated and reviewed Oldskool's #960 implementation, then implemented #961/#962 with one shared stack-safe structured receiver evaluator, nearest declaring-owner lookup, and targeted/inverted behavior coverage. All 51 targeted PHP tests, all 18 PHP usage-graph tests, formatting, diff hygiene, and isolated all-target/all-feature Clippy pass.
- [x] (2026-07-20 13:05-05:00) Completed the PHP publication boundary. Commit `14aa44cb` was integrated with current `origin/master`, the resulting head was published at `64de341e`, and the exact release runner SHA-256 was `c2ab9b150125c6467ae5809511be4fdbc59381f60b1d6ed92786105703dbc7fc`. All three exact witnesses and all five authoritative task-ranked repositories completed with zero missing, inconclusive, diagnostics, or file errors. The final corpus SHA-256 is `12e80e0c30b982e54440c2ecf1e43b9e3bc05d632199067b6e57539337cd1e68`; assigned issues #960, #961, and #962 are closed with evidence. See `.agents/docs/reference-differential/php-task-ranked-64de341e-summary.md`.
- [x] (2026-07-21 08:30-05:00) Integrated and independently reviewed the Rust structured-resolution repairs through `13dda48d`, covering re-exported/private associated calls, exact scoped types, module routing, receiver identity, and candidate authority. Follow-up `22c3a6b9` replaced a per-reference workspace declaration scan with an exact hash lookup. The two focused Rust usage suites pass 21 and 157 tests; publication and the authoritative final Rust corpus remain pending.
- [x] (2026-07-21 10:15-05:00) Merged the detached structured Scala lineage as `5e57b0e2`, applied its preserved exact hierarchy/callable tail as `6c934486`, and committed review corrections in `6ec3736f`. Full definition lookup (566), Scala hierarchy (21), precedence (43), parameterized enum (7), forward usage graph (55), inverse usage graph (139), cache DB (25), and analyzer store (47) selections pass.
- [x] (2026-07-21 11:02-05:00) Created and assigned #1034 before completing the newly confirmed Scala-to-Java constructor root. Commit `c579f681` now classifies exact Java constructors from one prepared syntax snapshot, preserves class and record constructor shapes, and indexes compact record constructors with canonical signatures and cache invalidation. Repeated independent review found no remaining correctness or performance issue; the expanded public definition regression and the 643-test definition/Java/cache/store selection pass.
- [x] (2026-07-21 13:40-05:00) Created and assigned #1036 and #1037 before completing the bounded Scala forward-lookup repairs in `45e2dd4f` and `3bfcd3cf`; `5769b716` restored exact scoped Rust enum-constructor definitions, and `2abf0707` restored flat-layout Rust external-module ownership under already-assigned #987. Formatting, focused definition/LSP suites, both Rust usage suites, and isolated all-target/all-feature Clippy pass. The complete feature-enabled gate subsequently exposed two further #987 partial-project usage regressions in the Rust dead-code integration suite, which remain under active repair before publication.
- [x] (2026-07-21 17:05-05:00) Published the integrated Rust/Scala implementation through `ac0e9050`, rebuilt the release runner (SHA-256 `d9d9a20544be42d41f5c5af439803a9484bdc8c06cf5752294cb00491824373d`), passed the full `cargo test --features nlp,python` gate, and completed the authoritative five-repository Rust corpus. The clean untruncated artifact is `/mnt/optane/tmp/reference-differential/rust-task-top5-ac0e9050-publication.jsonl` (SHA-256 `3f51db329b494d9ed25625e13c4fd8f2550915a5a7d4741f0ed058f839bdee3f`), with raw missing counts Stado 0, Tokio 363, tracing 298, Comrak 97, and toml_edit 112.
- [x] (2026-07-21 17:25-05:00) Exhaustively triaged the first clean pushed-head Rust corpus. Ephemeral exact probes reproduced nested-Cargo import loss, same-file enum variant loss, formerly consistent dependency-module qualifier loss, and formerly `editor_only` import loss, ruling out persisted-cache drift. Existing assigned issues #987 and #994 cover the inverse roots. Created and assigned #1042 before implementation for 62 distinct wrong-forward rows that conflated independent Cargo examples, benches, and explicit fuzz/bin targets.
- [x] (2026-07-21 21:10-05:00) Completed the first dirty full-corpus rerun after #1042/#1045 repairs over all five Rust repositories: Stado 0, Tokio 79, tracing 161, Comrak 52, and toml_edit 29 raw misses (321 total, down from 870). Three delegated exhaustive audits accounted for every row exactly. They confirmed no remaining sampled #1042 cross-target witness in Tokio/Comrak/toml_edit, isolated 95 lowercase `self`/`super` rows plus 11 nonterminal import/re-export rows as non-actionable, mapped established families to assigned #987/#992/#994/#995/#998/#1011/#1013/#1045, and proved five distinct new roots. Created and assigned #1046 (bare macro invocations), #1047 (struct-expression field labels), #1048 (tuple/unit constructor value namespace), #1049 (associated owners resolved with member seeds), and #1050 (bare nominal macro-token references) before implementation. The dirty run is `/tmp/rust-task-top5-dirty-cargo1042-1045.jsonl`, SHA-256 `c43e9d6911933c098ea551f3c617621f19ecec21a8bdfcf51600b98878f1f08d`.
- [x] (2026-07-21 22:25-05:00) Integrated focused implementations for #987/#998/#1045-#1050 and independently reviewed the accumulated Rust routing changes. Exact Tokio/tracing witnesses are green for ordinary re-exports and grouped/direct module qualifiers. The Cargo review found two additional distinct roots before publication: dependency classes leaking across target kinds and passthrough-macro ownership claiming modules not emitted. Created and assigned #1052 and #1053 before implementation; #1042 remains the owner for path-base, target-discovery, and cross-package membership corrections found in the same review.
- [x] (2026-07-22 00:09-05:00) Completed and independently reviewed the integrated Rust repair set for assigned #987/#990-#995/#998/#1006-#1007/#1011-#1013/#1042/#1045-#1050/#1052-#1053. The final dirty-head five-repository smoke corpus fell to 248 raw rows (Stado 0, Tokio 56, tracing 127, Comrak 46, toml_edit 19), all remaining rows pending clean-head disposition rather than implementation authority. Review caught and repaired one valid `crate::Name` root-reexport regression before publication. The affected 820-test integration selection, all-target/all-feature Clippy, formatting, diff hygiene, and the complete `cargo test --features nlp,python` matrix pass on the final source. Publication and the authoritative clean-head audit remain active.
- [x] (2026-07-22 02:05-05:00) Published the first Rust residual-repair checkpoint through `b58b8932` and reran all five explicit task-ranked repositories. The clean artifact `/mnt/optane/tmp/reference-differential/rust-task-top5-b58b8932-final.jsonl` (SHA-256 `f14c8775338b524340c273ff89f54583d47b4d2752b9b22e18eb4021a33f094c`) contains 140 raw rows: Stado 0, Tokio 19, tracing 62, Comrak 40, and toml_edit 19.
- [x] (2026-07-22 03:00-05:00) Exhaustively dispositioned those 140 rows. Tokio's 19 and Comrak's 40 are nonacceptance artifacts. The 21 legitimate rows are three Criterion bare nominal references (#1050), nine tracing and five toml_edit independent Cargo-target identity errors (#1042), three serde_spanned bare module constants shadowed by associated constants (#991), and one child-module extern-prelude root captured by a parent sibling module (#992). Existing issues were open and assigned to `jbellis`; evidence comments were posted before implementation.
- [x] (2026-07-22 04:10-05:00) Completed final implementation review and local acceptance for the Rust residual repair. Structured fixes preserve physical Cargo-target identity in both directions, restore module-value and extern-prelude precedence, and keep same-FQN expansion within the declaration namespace. Formatting, diff hygiene, the 605-test definition suite, 196-test inverse suite, 17-test residual suite, 8-test differential suite, candidate-bounded guard, isolated all-target/all-feature Clippy with warnings denied, and the complete isolated `cargo test --features nlp,python` matrix all pass. Publication and the clean pushed-head five-repository proof remain.
- [x] (2026-07-22 04:20-05:00) Published the residual repair at integrated head `c7b8fa62` and completed a clean five-repository audit. The artifact `/mnt/optane/tmp/reference-differential/rust-task-top5-c7b8fa62-final.jsonl` (SHA-256 `93e4791ec38b076255366202fc7690ffd0fb7bcee87bde3e091c771438164677`) has 120 raw rows: Stado 0, Tokio 20, tracing 51, Comrak 40, and toml_edit 9. Exact old/new projection comparison proved that all 21 planned legitimate rows plus one additional corrected `ser::value` module identity disappeared and all 118 common residuals were byte-identical.
- [x] (2026-07-22 04:30-05:00) The same audit found two added legitimate rows. Created and assigned #1060 before repairing same-FQN expansion that broadened Tokio's exact `Self::Future` impl identity, and created and assigned #1061 before repairing nested inline-module `self` identity in tracing-appender. Both implementations are structured: exact same-file lexical-Self definitions remain authoritative while other-file Cargo replicas remain eligible, and lowercase `self` uses tree-sitter ancestry plus the exact inline-module declaration range. The 610-test definition suite, 196-test inverse suite, 17-test residual suite, 8-test differential suite, candidate-bounded guard, formatting, and diff hygiene pass; publication gates remain.
- [x] (2026-07-22 05:00-05:00) Published the final Rust source head `ca218491`, rebuilt the release runner (SHA-256 `1faaaf9c634c1d9ed065a69b8488e70458b3d44ca88022b4f0d51567ad8e45b1`), and completed the five-repository corpus with 118 raw rows: Stado 0, Tokio 19, tracing 50, Comrak 40, and toml_edit 9. Canonical multiset comparison found exactly the two #1060/#1061 removals, zero additions, and 118 byte-identical reviewed nonacceptance rows. Exact probes are consistent, all local gates pass, and all 24 solely assigned task-ranked Rust issues are closed. See `.agents/docs/reference-differential/rust-task-ranked-ca218491-summary.md`.
- [x] Complete, publish, close owned issues for, and summarize the Rust task-ranked leg.
- [x] (2026-07-22 09:25-05:00) Repaired the three newly reproduced #661 inverse roots from the clean Scala task-ranked audit. Parameter and class-parameter defaults now admit only their parser-owned `default_value` term; one shared nearest-first structural-owner walk covers plain, infix, applied, and receiver-root fields while preserving local, nearest-field, callable, and ambiguous-tier authority; renamed imports record both original and alias identifiers against exact object/type/member identity. Three new targeted/file-major behavior tests pass, as does the complete 147-test Scala inverse graph suite; root review and integrated campaign gates remain root-owned.
- [x] (2026-07-22 09:44-05:00) Repaired the three #664 wrong-forward roots from the final Scala corpus. Named constructor arguments now retain the exact physical lexical callee owner through member lookup, nonterminal import segments select the first declaration-or-package precedence tier without binding an unrelated lower package object, and anonymous refinement aliases map to the exact constructed base member while nearer unindexed bindings remain authoritative barriers. Three focused precedence tests pass with physical-owner, ambiguity, package/declaration collision, qualified-miss, and local-template controls; root owns integration and publication.
- [x] (2026-07-22 10:35-05:00) Created and assigned #1073 before repairing the remaining parser-owned wrong-forward site. A minimally vendored `tree-sitter-scala` 0.25.1 derivative makes `extension` a contextual soft identifier while retaining Scala 3 extension definitions. Independent regeneration reproduced the generated parser byte-for-byte, and raw-parser plus public forward/inverse tests pass 6/6.
- [x] (2026-07-22 11:15-05:00) Integrated #661, #664, and #1073. Review caught and repaired one callable-precedence regression by excluding synthetic constructors from ordinary lexical-callable authority. Formatting and diff hygiene pass, as do the complete 147-test Scala inverse graph, 51-test Scala definition-precedence, and 6-test parser/public round-trip targets. Exact corpus-witness replay, broad gates, publication, and final pushed-head evidence remain.
- [x] (2026-07-22 09:58-05:00) Rebuilt the dirty integrated release runner and exactly replayed all 12 Jonathan-owned baseline sites against their frozen repository heads. Nine are now `consistent`, the renamed-import token is correctly `editor_only`, and both FS2 nonterminal package segments fail closed as `unresolvable_import_boundary`; all 12 have zero actionable missing rows.
- [x] (2026-07-22 10:55-05:00) Merged current `origin/master`, then repaired two integration-contract regressions found only by the broad gate: imported singleton terms again precede unrelated type constructors while exact physical types still precede generic FQN fallback, and the new same-FQN MCP regression uses #1057's path-qualified exact selectors rather than expecting a bare ambiguous symbol to conflate replicas. Post-merge formatting, diff hygiene, all-feature Clippy, and the complete out-of-sandbox `cargo test --features nlp,python` suite pass.
- [x] (2026-07-22 11:45-05:00) The first clean persisted-cache publication attempt exposed a #1073 cache-invalidity defect: Metals retained the pre-fix flat `isWorksheet` owner because the contextual-keyword grammar patch changed parser tables without changing the node/field vocabulary hashed by the automatic analyzer epoch. The invalid two-record artifact was stopped and preserved under an explicit `stale-cache-invalid` name. The Scala epoch now carries a narrow parser-semantics salt, and a store regression seeds the exact prior epoch and proves the old parsed blob becomes a cache miss after the generation cutover.
- [x] (2026-07-22 12:20-05:00) Exhaustive review of the interrupted ZIO record found one new legitimate exact-identity defect. Created and solely assigned #1086 before implementation. A two-source-set reduction proves that path-qualified Scala 2 `Tracer.Type` loses six anonymous-refinement references only when a Scala 3 same-FQN replica is present. The structured repair retains the source-local constructed base, makes exact direct type members authoritative before export/ancestor ambiguity, and keeps a third-file ambiguous consumer fail-closed; focused Rust and MCP behavior coverage passes.
- [x] (2026-07-22 12:55-05:00) Published the integrated Scala fixes at `4589dd98`, proved #1073 and #1086 with clean persisted exact witnesses, and completed the corrected five-repository corpus. Its 47 raw missing rows were independently matched one-for-one to source bytes and targets: 26 import qualifiers, 8 nested qualifiers, 9 #128 cross-language skips, and 4 #419/#499 trait/default skips, with zero Jonathan-actionable rows. Closed #661, #663, #664, #1073, and #1086 with final evidence and recorded the language summary.
- [x] Complete, publish, close owned issues for, and summarize the Scala task-ranked leg.
- [x] (2026-07-22 16:30-05:00) Recovered the campaign after a machine crash at clean pushed head `9620eb8f`. The live `tasks.py` selector still returns Fastjson2, Hutool, LanguageTool, Halo, and Dubbo in that task-count order; all five clones remain at their pinned heads with no tracked changes, and no stale differential process survives. The operator reports a completed Fastjson2 leg and an interrupted LanguageTool inverse phase. Filesystem reconciliation found a durable five-envelope zero-missing Java artifact only at historical head `d675ad92`, but no current-head envelope for either repository. Because shared and Java analyzer changes landed after that historical head, all five repositories rerun at `9620eb8f`; the unchanged persisted caches accelerate recovery but do not substitute for new envelopes. All new temporary artifacts use `/mnt/optane/tmp/bifrost-fird/` as explicitly requested.
- [x] (2026-07-22 18:05-05:00) Integrated current `origin/master`, published clean campaign head `0b4f1d6f`, and built release runner SHA-256 `e6c0c49fb4447a3e5b74e68988d2fb26b4a3a5ad09321a324a7a7ea7a3e698df`. The recovered five-repository Java run completed with zero missing rows everywhere. Its clone dirty flags were sampled before the operational cache exclusions were installed, so those envelopes are diagnostic only; a second full run began after all five clone worktrees and Bifrost were verified clean. The runner snapshots all provenance before starting repository work and then executes the immutable release binary, allowing Python implementation to proceed during the long LanguageTool phase without changing Java's code or recorded state.
- [x] (2026-07-22 18:10-05:00) Completed the pinned Python baseline at `0b4f1d6f`. All five envelopes are clean, share fingerprint `292be91e9bf4dec85d7726e7814046bcee21b7a2451a0c2d70ea2f102538a572`, and have no file errors, truncation, skipped targets, or limit failures. Powsybl, Odysseus, and Deer Flow have zero missing; Cirq has four and Kornia has three. Seven clean ephemeral exact probes reproduced every row. Exhaustive source/forward/inverse review reduced them to four intermediate imported-module qualifier omissions (#795), one attribute-callee return-type omission (#1096), one comment-bearing grouped-import binding omission caused by the raw text mini-parser (#1097), and one distinct wrong-forward dotted-module alias collapse (#1098). #795 was reopened and #1096-#1098 were created, all solely assigned to `jbellis`, before product edits.
- [x] (2026-07-22 19:15-05:00) Completed the authoritative clean Java replay at pushed source head `0b4f1d6f`. All five explicit task-ranked repositories completed with zero missing rows, clean Bifrost and clone provenance, one fingerprint, and no file errors or candidate-limit events. The JSONL SHA-256 is `d95fa95d7bdd6678aace61ac2f1b8d273a870d2ab9800382b48eca7bbef4c740`; no new issue was found. See `.agents/docs/reference-differential/java-task-ranked-0b4f1d6f-summary.md`.
- [x] Complete, publish, close owned issues for, and summarize the Java task-ranked leg.
- [x] (2026-07-22 19:35-05:00) The complete Python publication gate exposed a newly integrated #1015 Rust symbol regression: unknown item-position macro reparsing also admitted compiler-builtin `stringify!`, whose contract consumes arbitrary tokens and emits a string rather than replaying items. Reopened the existing solely `jbellis`-assigned issue before editing, added the compiler-semantic rejection, and proved both the legacy inert-macro regression and the nine-test public MCP macro-index suite. Broad gates are rerunning with the repair included.
- [x] (2026-07-22 19:55-05:00) Completed root review and local acceptance of the integrated Python/#1015 source. The 100-test Python inverse suite, 32 analyzer/import tests, four exact MCP definition tests, two Rust macro-index suites, formatting, diff hygiene, isolated all-target/all-feature Clippy with warnings denied, and the complete out-of-sandbox `cargo test --features nlp,python` matrix all pass. Publication and clean production replay remain.
- [ ] Complete, publish, close owned issues for, and summarize the Python task-ranked leg.
- [ ] Verify the twenty-five-record matrix, compact manifests, issue states, clean worktree, and equality of local HEAD, local `origin/master`, and remote `refs/heads/master`.

## Surprises & Discoveries

- Observation: The earlier campaigns' repository sets are materially different from the requested task-ranked sets.
  Evidence: The old PHP campaign selected Moodle, Magento, Psalm, EduSoho, and Symfony by `repos.csv::code_loc`; the requested selector returns Laravel, CakePHP, PhpSpreadsheet, Snipe-IT, and CodeIgniter4 by filtered task count. Java, Python, Rust, and Scala have the same mismatch.

- Observation: `task_repos` applies the required `large-repos.csv` exclusion through `SFT_PREDICATES`, but its native ranking is a coarse count band plus build time rather than exact task-count order.
  Evidence: `tasks.py::_select` returns `RepoRef.task_count` and sorts first by `-int(log2(task_count))`; this plan explicitly stable-sorts those returned records by descending `task_count` before taking five. Scala's fifth place is tied at 62 tasks; stable selector order chooses `typelevel__fs2` ahead of `zio__zio-http`.

- Observation: The advanced historical Scala stack is large and touches shared analyzer, persistence, definition, and import infrastructure.
  Evidence: The detached `4e984fd9` lineage differs from this branch in 59 files and more than 32,000 inserted lines. It cannot be treated as accepted current-head evidence or integrated without deliberate conflict review and the full local gate.

- Observation: The restricted sandbox cannot execute three benchmark stderr-drain process tests, but the code is healthy outside that process sandbox.
  Evidence: The sandboxed full suite failed only `benchmark::mcp_session::{stderr_boundary_waits_for_delayed_marker_consumption,stderr_drain_bounds_an_unterminated_stream,stderr_drain_continuously_consumes_and_keeps_bounded_tail}` with OS error 1. The identical isolated feature-enabled command outside the sandbox passed the complete repository suite.

- Observation: An unrelated concurrent JS/TS campaign began modifying five tracked JS/TS files in this same worktree while the PHP full gate was running.
  Evidence: The PHP gate passed every library and integration target through the final usage-graph group, including all PHP tests, then failed `usage_graph_ts_test::qualified_type_references_create_exact_workspace_edges`; an isolated rerun reproduced it and exposed warnings in concurrently dirty `js_ts_graph/inverted.rs`. Those files are not part of the PHP change and will not be staged into its checkpoint.

- Observation: The shared branch advanced twice during the PHP publication gate, first with the completed TypeScript parity change and then with its lint-only follow-up, while `origin/master` also gained an LSP cache-isolation commit.
  Evidence: The final integrated PHP acceptance head is `64de341e`, containing `14aa44cb`, `de27750d`, `c5e4e3d2`, and `64de341e`. A clean detached build embedded that exact Bifrost head and source path. The unrestricted full gate passed every library test; 186 of 187 LSP tests passed in the suite, and the sole resource-contention SIGKILL (`lsp_server_drop_cleanup_exits_cleanly_after_initialize`) passed immediately when rerun alone.

- Observation: Exact Rust local-module visibility was semantically correct after the scoped-routing repair but initially performed a workspace declaration scan for every qualifying reference.
  Evidence: Review replaced `declaration_identities.values().find(...)` with an exact `declaration_domains` lookup keyed by file, module, name, and module namespace. Both Rust usage suites remained green while the hot path became constant-time with respect to workspace declarations.

- Observation: Scala hierarchy and Java-constructor correctness both depend on parser context surviving persistence and forward-query boundaries.
  Evidence: Scala supertype facts now persist lexical scopes and bump the Scala epoch; Java constructor classification reads declaration ranges, owner children, and syntax from one prepared `FileState`. Compact record constructors required a Java epoch bump because they newly enter the persisted declaration surface.

- Observation: The live Python task ranking changed after the initial campaign selection because the underlying eligible task inventory changed.
  Evidence: Re-running `task_repos(SFT_PREDICATES, langs=['py'])` on 2026-07-21 selects `pewdiepie-archdaemon__odysseus` (137) and `powsybl__powsybl-core` (97) in place of Glom and Caikit. All five live records are `RepoRef(lang='py')` and pass `not_overlarge`; powsybl-core is a legitimate selector result even though its checkout currently exposes only `docs/conf.py` to the Python analyzer.

- Observation: The first clean pushed-head Rust closure corpus exposed regressions introduced by the exact-routing fixes themselves rather than merely confirming the targeted witnesses.
  Evidence: Compared with `d91f902c`, 72 Comrak/toml_edit sites that were previously `consistent` or `editor_only` are now `missing` with byte-for-byte identical forward targets. Ephemeral exact runs at `ac0e9050` reproduce Comrak `NodeValue::Item`, toml_edit `toml_parser::parser`, and `crate::de` import-focus omissions, so persisted caches are not causal. Tokio `asyncify` reproduces the same way.

- Observation: Path-derived Rust package names collapse independent Cargo auto-targets before either forward or inverse resolution can preserve target identity.
  Evidence: The final corpus contains 62 wrong-forward rows across tracing examples/benches, Comrak explicit fuzz bins, and toml_edit benches. For example, `tower-load.rs` resolves `Svc` to `tower-server.rs`, and `2-array.rs` groups `NUM_ENTRIES` with `1-map.rs`. Issue #1042 was created and assigned before implementation.

- Observation: The `b58b8932` residual corpus contains 21 legitimate rows, not twelve.
  Evidence: The exhaustive ledger groups 3 rows under #1050, 14 under #1042, 3 under #991, and 1 under #992; `3 + 14 + 3 + 1 = 21`, leaving 119 nonacceptance rows from the 140-row raw corpus.

- Observation: Rust 2015 extern-prelude handling must distinguish the source binding from the Cargo route.
  Evidence: `extern crate toml_edit as edit; edit::de::from_str()` binds `edit` lexically but Cargo metadata is keyed by `toml_edit`. Final review caught the mismatch before publication; the structured ancestor-scope lookup now returns the underlying crate name and examines only direct items in visible scopes.

- Observation: A clean pushed-head differential can expose a new defect even when every planned baseline defect disappeared.
  Evidence: The `c7b8fa62` artifact removed all 21 legitimate `b58b8932` rows, but added Tokio's `Self::Future` same-FQN ambiguity and tracing-appender's nested `self` parent-module identity. Exact reruns and old/new projection comparison separated these two defects from 118 byte-identical nonacceptance rows; issues #1060 and #1061 own the repairs.

- Observation: Three residual Scala #661 families cross different syntax surfaces but share failures to preserve exact structured identity in the inverse scan.
  Evidence: tree-sitter places `EmptyCancelToken` directly in a `parameter` or `class_parameter` `default_value` field that the bare-term predicate currently rejects; nested `identifiers`, `testUtil`, and `EndToEndTest` references require walking exact structural owners beyond the nearest template; and renamed imports preserve the original path in `ImportInfo.path` while `record_import_name` currently accepts only the local alias token.

- Observation: Preseeded outer fields cannot be accepted before examining the nearest lexical owner, and fields cannot be considered independently of parameterless callables at the same tier.
  Evidence: the first outer-field ambiguity regression incorrectly selected `Container.ambiguous` before checking two conflicting inherited fields in `Container.Ambiguous`; after correcting that order, the full Scala graph suite exposed `Live.nextDouble` being hidden by an outer object field. The final helper checks each exact owner tier for fields and callable-name authority before advancing outward. The rerun passed all 147 tests.

- Observation: The three final Scala wrong-forward families were precedence and physical-identity losses, not missing name spellings.
  Evidence: Metals' named `isWordMatch` broadened an exact nested `TextSearchQuery` to a package namesake; FS2's nonterminal `fs2.compression` import segment bound `fs2.io.compression$`; and ZIO's anonymous `List` refinement leaked to `FastList$.List` instead of the constructed `ListModule.List`. A local class inside the anonymous refinement has no indexed class identity and correctly blocks outer lookup rather than inventing `Inner.List`.

- Observation: The remaining Metals `isWorksheet` wrong-forward row originated below the analyzer, in a valid Scala 2 identifier that the published parser treated as an unconditional Scala 3 keyword.
  Evidence: every official release through 0.26.0 and upstream master emits an `ERROR` for `extension == "json"`; adding `extension` to `_soft_identifier` with the corresponding GLR conflict yields an error-free Scala 2 tree, retains an `extension_definition` for Scala 3, and restores the nested implicit-class symbol round trip.

## Decision Log

- Decision: Treat all previous LOC-ranked language records as regression evidence only and rerun all five requested languages.
  Rationale: Repository membership is part of the requested acceptance contract. Exact fixes found in other repositories remain legitimate product work, but they cannot substitute for the selected twenty-five-repository matrix.
  Date/Author: 2026-07-20 / Codex

- Decision: Use `task_repos(SFT_PREDICATES, langs=[LANG])`, then a stable descending `task_count` sort, and pass explicit repository slugs to the differential runner.
  Rationale: This preserves every `tasks.py` eligibility filter, including `large-repos.csv`, while implementing the user's exact "most tasks" ordering. Explicit `--repo` arguments prevent the runner's unrelated LOC ranking from changing membership.
  Date/Author: 2026-07-20 / Codex

- Decision: Process PHP, Rust, Scala, Java, then Python, with a publication and summary boundary after each language.
  Rationale: This follows the requested order, limits cross-language dirty state, and makes issue closure and final-corpus evidence attributable to one integrated head at a time.
  Date/Author: 2026-07-20 / Codex

- Decision: Retain the already-reviewed #904/#905 PHP implementation on the branch but require task-ranked corpus proof before declaring the PHP language complete.
  Rationale: The fixes are structured and independently tested, yet the prior source witnesses came from an invalid membership set for this goal. The new corpus may expose additional roots and must be audited independently.
  Date/Author: 2026-07-20 / Codex

- Decision: Partition the 298 PHP residuals into three issues with explicit overlap rather than force them into disjoint symptom buckets.
  Rationale: Nullsafe node dispatch (#962) and call-return receiver inference (#961) are independent structured requirements; two PhpSpreadsheet sites need both. Owner-relative type identity (#960) is separate. The issue ledgers record 96, 200, and 4 affected rows respectively and identify the two-row overlap.
  Date/Author: 2026-07-20 / Codex

- Decision: Integrate the advanced Scala lineage, then preserve and review the current worktree tail as separate checkpoints before corpus publication.
  Rationale: The lineage contains the structured resolver and persistence foundation required by the task-ranked Scala witnesses, while the tail contains exact enum, constructor, hierarchy, and import-context fixes. Separate checkpoints made conflict resolution and independent review auditable.
  Date/Author: 2026-07-21 / Codex

- Decision: Treat Scala-to-Java construction as a language-bounded Java declaration problem rather than forcing Java units through Scala callable metadata.
  Rationale: Constructor kind, ordinary default suppression, record canonical shape, varargs, and compact declarations are Java semantics. Reading them from one prepared Java AST snapshot prevents same-FQN methods and stale parent/range facts from producing false definitions.
  Date/Author: 2026-07-21 / Codex

- Decision: Re-evaluate each not-yet-started language through the live `tasks.py` selector immediately before its corpus begins.
  Rationale: The user's acceptance set is defined by the selector rather than by a frozen hand-copied list, and the Python task inventory changed during this long-running campaign. The live result therefore supersedes the initial Python list while preserving the same stable descending-count rule and `large-repos.csv` filter.
  Date/Author: 2026-07-21 / Codex

- Decision: Do not close #987/#994/#1013 or start the Scala publication corpus from `ac0e9050` after the Rust run completed.
  Rationale: The full Rust corpus is the publication authority and found systemic exact inverse regressions plus a distinct Cargo target-identity defect. Scala evidence built from the same head would become stale as soon as those shared Rust fixes are committed; repair, gate, publish, and rerun Rust first.
  Date/Author: 2026-07-21 / Codex

- Decision: Preserve physical declaration identity before applying Cargo scope, but expand only within the same Rust declaration namespace.
  Rationale: Same-FQN declarations in independent auto-targets must remain available for physical routing, while legal type/value collisions such as a struct and constructor-shaped function must not become ambiguous. Namespace filtering and a direct collision regression make both constraints explicit.
  Date/Author: 2026-07-22 / Codex

- Decision: Treat structured lexical identity as authoritative within its physical source file before broadening candidates for Cargo routing.
  Rationale: Associated declarations from multiple impls can legally share the analyzer FQN in one file, whereas replicas in other files are required to disambiguate independent Cargo roots. Preserving the exact same-file `Self` result and admitting only other-file replicas satisfies both constraints. Lowercase `self` likewise resolves first to the nearest inline `mod_item` by exact declaration range, falling through to external-module routing only when no inline module encloses the site.
  Date/Author: 2026-07-22 / Codex

- Decision: Fix the three #661 inverse families at their shared structured boundaries rather than special-casing the observed repositories.
  Rationale: A parameter default is identified by the parser's `default_value` field, lexical outer-field lookup can walk exact owner units nearest-first with local shadows and ambiguous tiers authoritative, and a renamed import's original terminal is recoverable from its normalized import path. These rules cover ordinary, infix, receiver, Scala 2, and Scala 3 forms without source-text parsing or name-only fallback.
  Date/Author: 2026-07-22 / Codex

- Decision: Preserve exact Scala declaration identity until the final callable/member projection, and treat each structured lexical/import tier as authoritative before considering a lower tier.
  Rationale: Re-expanding a proven owner by rendered FQN reintroduces same-name physical replicas; package evidence below a lexical declaration reverses Scala import precedence; and unindexed local/refinement bindings must fail closed unless the parser proves an exact indexed base member. The implementation uses AST segment positions, structural parents, and exact `CodeUnit` identities throughout.
  Date/Author: 2026-07-22 / Codex

- Decision: Repair #1073 in the grammar rather than teaching the analyzer to recover declarations from malformed parser output.
  Rationale: `extension` is legal as a Scala 2 identifier and contextual in Scala 3. The grammar already uses soft identifiers and GLR conflicts for this class of ambiguity, so a narrow source-controlled grammar patch fixes ownership at its source without source-text parsing or analyzer recovery.
  Date/Author: 2026-07-22 / Codex

- Decision: Invalidate persisted Scala analysis explicitly for #1073 and preserve physical source-set identity through #1086's anonymous-refinement boundary.
  Rationale: Tree-sitter parse-table behavior can change while ABI/node/field vocabulary remains identical, so the established per-language epoch salt is the correct cache cutover. When parallel Scala source sets render the same FQN, a same-file declaration is exact evidence; direct members at that physical hierarchy tier precede exported or inherited ambiguity, while a consumer with no source-local winner remains unresolved.
  Date/Author: 2026-07-22 / Codex

- Decision: Replace Python import-text reconstruction with one tree-sitter-derived binding representation and invalidate persisted Python analysis at the cutover.
  Rationale: Comment-bearing grouped imports prove that comma and delimiter splitting cannot recover parser semantics. Every binder, re-export, wildcard, and import-resolution consumer should use the normalized `ImportInfo.path` and AST-derived identifier/alias facts. Old cached declarations lack those facts, so an explicit analyzer-epoch salt is safer than retaining the forbidden raw-text fallback.
  Date/Author: 2026-07-22 / Codex

- Decision: Repair Python module qualifiers, attribute-callee return inference, and dotted module aliases at separate structured boundaries.
  Rationale: Intermediate child-module qualifiers belong in the inverse attribute walk, factory-return members require the same scoped callable/receiver evidence used by forward lookup, and a dotted module alias already carries exact namespace identity before exported-symbol projection. Combining these symptoms into name matching would hide three distinct authority and precedence rules.
  Date/Author: 2026-07-22 / Codex

## Outcomes & Retrospective

PHP is complete. Its task-ranked baseline contained 298 legitimate misses: 96 owner-relative type references, 200 call-return receiver chains, and four nullsafe calls, with two chain/nullsafe overlaps. Structured fixes for #960, #961, and #962 reduced all five final repositories to zero actionable and zero inconclusive rows at pushed head `64de341e`; the three issues are closed. Historical #904/#905 remain integrated regression fixes. The focused PHP suites, formatting, diff hygiene, isolated all-feature Clippy, full feature-enabled Cargo gate, exact witnesses, and production corpus all passed. The final artifact and hashes are recorded in `.agents/docs/reference-differential/php-task-ranked-64de341e-summary.md`.

Rust is complete. The first clean task-ranked corpus contained 870 raw missing rows. Structured routing, receiver, namespace, macro, Cargo-identity, constructor, and label fixes reduced the final corpus to 118 exhaustively reviewed nonacceptance artifacts at pushed source head `ca218491`. Canonical old/new comparison proves all 118 are byte-identical to the prior reviewed set after removing only the two final legitimate #1060/#1061 rows. Exact witnesses, focused suites, Clippy, formatting, the complete feature-enabled Cargo gate, and the clean five-repository corpus all pass; all 24 solely assigned task-ranked Rust issues are closed. The final evidence is recorded in `.agents/docs/reference-differential/rust-task-ranked-ca218491-summary.md`.

Scala is complete. The final clean pushed-head corpus contains 47 exhaustively reviewed residuals and zero actionable defects. All twelve baseline Jonathan-owned #661/#664/#1073 rows, the new #1086 ZIO witness, and the #663 callable family are absent. The remaining rows are 26 import qualifiers, 8 nested qualifiers, 9 #128 cross-language skips, and 4 #419/#499 trait/default skips; those three David-owned issues were not modified. Clean persisted witnesses prove the parser-epoch cutover and same-FQN source-set repair. Issues #661, #663, #664, #1073, and #1086 are closed. Final paths, hashes, gates, and per-repository counts are recorded in `.agents/docs/reference-differential/scala-task-ranked-4589dd98-summary.md`.

Java is complete. Its authoritative replay used the immutable release runner built from already-pushed clean head `0b4f1d6f` while subsequent Python edits proceeded only in the source worktree. All five task-ranked repositories completed with zero missing rows and no new issue. The final provenance, bounds, hashes, and aggregate classifications are recorded in `.agents/docs/reference-differential/java-task-ranked-0b4f1d6f-summary.md`.

Python remains. Its seven baseline rows are reproduced and assigned to four structured repair roots; publication, clean exact proofs, the final task-ranked replay, issue closure, and the language summary remain.

## Context and Orientation

Work in `/mnt/optane/bifrost-fird` on the existing `bifrost-fird` branch. Do not create or switch branches, rebase, or open a pull request. Commit only files changed for this campaign. Before publication, fetch `origin/master`, merge it into the current branch without rebasing if necessary, repeat proportionate local gates, and push the integrated `HEAD` directly to `origin/master`.

The differential CLI is `src/bin/bifrost_reference_differential.rs`; the engine and JSONL schema are in `src/reference_differential/mod.rs`. Forward definition resolution lives under `src/analyzer/usages/get_definition/`; inverse reference logic lives in `src/analyzer/usages/` and its language modules. `tests/common/inline_project.rs::InlineTestProject` is the preferred harness for small behavior reductions.

Canonical clones are below `/home/jonathan/Projects/brokkbench/clones`, which resolves to `/mnt/T9/repo-clones`. Task selection and all corpus eligibility reads go through `/home/jonathan/Projects/brokkbench/tasks.py`; do not manually read or reimplement filters over its task stores. For this resumed campaign, durable differential artifacts and logs belong under `/mnt/optane/tmp/bifrost-fird/`; compact manifests and narrative summaries belong under `.agents/docs/reference-differential/`.

The authoritative task-ranked selections are:

- PHP: `laravel__framework` (126), `cakephp__cakephp` (95), `PHPOffice__PhpSpreadsheet` (84), `grokability__snipe-it` (82), `codeigniter4__CodeIgniter4` (74).
- Rust: `tokio-rs__tokio` (142), `kivikakk__comrak` (59), `ordian__toml_edit` (44), `tokio-rs__tracing` (40), `foobarto__stado` (37).
- Scala: `scala-steward-org__scala-steward` (147), `zio__zio` (106), `linkerd__linkerd` (72), `scalameta__metals` (71), `typelevel__fs2` (62). `zio__zio-http` also has 62; stable `tasks.py` order selects `typelevel__fs2`.
- Java: `alibaba__fastjson2` (328), `chinabugotech__hutool` (208), `languagetool-org__languagetool` (192), `halo-dev__halo` (163), `apache__dubbo` (126).
- Python (live selector, refreshed 2026-07-21): `bytedance__deer-flow` (208), `pewdiepie-archdaemon__odysseus` (137), `kornia__kornia` (112), `quantumlib__Cirq` (105), `powsybl__powsybl-core` (97). Powsybl-core is retained because `tasks.py` classifies it as `py` and filters it as eligible, despite its checkout currently containing only one Python file.

All twenty-five clone paths exist and their tracked worktrees were clean at selection time. Generated `.brokk/` cache state is operational, not source corpus content; exclude it in each clone's local `.git/info/exclude` if it would otherwise appear as untracked dirtiness.

## Plan of Work

Freeze a clean plan checkpoint and rebuild the release runner from that exact head. Record the Bifrost head, binary SHA-256, selector output, selected clone heads, and cleanliness. Run one language at a time with the five explicit task-ranked slugs, one repository job, eight inner workers, persisted cache mode, strict classification, and the runbook's established bounds.

For each completed language baseline, verify five completed repository envelopes, exact Bifrost and repository heads, clean flags, one semantic fingerprint, JSON integrity, configured limits, and file errors. Extract every raw `missing` site to a checksummed row ledger. Delegate disjoint source/row research where useful; root verifies source bytes, focused token and tree-sitter role, forward declaration group, inverse completeness, and exact-site reproducibility.

For each legitimate defect, search open and closed GitHub issues outside the restricted sandbox. If a matching issue is assigned to somebody other than `jbellis`, record it and skip implementation. Otherwise assign an existing issue to `jbellis` or create it already assigned before changing product code. Build a faithful `InlineTestProject` reduction with appropriate negative controls, delegate substantial structured diagnosis/implementation, independently review the diff, and run focused tests. Do not add regex, substring, delimiter-splitting, or source-text mini-parser fallbacks.

When all legitimate roots for a language are resolved or correctly skipped, run formatting, isolated all-target/all-feature Clippy, and the isolated complete `cargo test --features nlp,python` gate. Commit the relevant files with a multiline why-oriented message. Fetch and merge current `origin/master` if needed, repeat proportionate gates, and push directly to `origin/master` without waiting for CI.

Rebuild the release runner from the exact clean pushed head. Rerun every fixed exact witness and the full task-ranked five-repository language corpus into new head-scoped artifacts. Exhaustively audit all residuals. Only then comment on and close the owned issues, commit compact evidence, verify local/remote head agreement, give the user the language summary, and proceed immediately to the next language.

## Concrete Steps

Regenerate the selection without manually reading task stores:

    cd /mnt/optane/tmp/bifrost-burndown-3
    PYTHONDONTWRITEBYTECODE=1 python3 -c 'import sys; sys.path.insert(0,"/home/jonathan/Projects/brokkbench"); import tasks; print(sorted(tasks.task_repos(tasks.SFT_PREDICATES, langs=["php"]), key=lambda r: -r.task_count)[:5])'

Build and fingerprint the runner from a clean checkpoint:

    cargo build --release --bin bifrost_reference_differential
    git rev-parse HEAD
    sha256sum target/release/bifrost_reference_differential

The PHP command shape is:

    set -o pipefail
    /usr/bin/time -v target/release/bifrost_reference_differential run-corpus \
      --clones-root /home/jonathan/Projects/brokkbench/clones \
      --commits-root /home/jonathan/Projects/brokkbench/sft-tools-commits \
      --language php \
      --repo laravel__framework --repo cakephp__cakephp \
      --repo PHPOffice__PhpSpreadsheet --repo grokability__snipe-it \
      --repo codeigniter4__CodeIgniter4 \
      --repo-jobs 1 --jobs 8 --cache-mode persisted --strict \
      --max-files 1000 --max-sites 10000 \
      --max-candidates-per-file 50000 --max-source-bytes 4194304 \
      --max-targets 1000 --max-usage-files 1000 --max-usages 100000 \
      --seed 0 \
      --output /mnt/optane/tmp/reference-differential/php-task-top5-HEAD8.jsonl \
      2>&1 | tee -a /mnt/optane/tmp/reference-differential/php-task-top5-HEAD8.log

Repeat with the exact Rust, Scala, Java, and Python slug lists above and matching `--language` (`rust`, `scala`, `java`, `py`). Do not use `--repos-per-language`, `--include-tests`, or routine `--force`. Resume interrupted runs by confirming the old process is gone and repeating the identical command/output path.

Before each code publication, run:

    cargo fmt --all -- --check
    git diff --check
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    UV_CACHE_DIR=/tmp/bifrost-uv-cache BIFROST_SEMANTIC_INDEX=off \
      scripts/with-isolated-cargo-target.sh cargo test --features nlp,python

## Validation and Acceptance

A language is complete only when exactly its five selected repositories have completed records on one clean pushed Bifrost head, every repository head is pinned and clean, the configuration is uniform, every error and limit is accounted for, and every raw missing row has a reviewed disposition. Each owned legitimate defect must have an assigned issue, structured regression, fixing commit on `origin/master`, clean exact witness, clean final corpus proof, and closed issue. An issue assigned to another user is an explicit documented skip and is not modified.

The campaign is complete only when all five language boundaries pass, the compact evidence is committed, every accepted fixing head is an ancestor of final `origin/master`, the complete local gate passes after the final integration, and local HEAD, local `origin/master`, and remote master agree. GitHub CI is not a blocking gate.

## Idempotence and Recovery

`run-corpus` appends one completed repository envelope and skips an identical completion key on resume. Preserve JSONL, logs, and caches after interruption; repeat the exact command without `--force`. If Bifrost source changes, rebuild the runner and use a new head-scoped artifact. Do not mutate selected clone sources or delete caches to hide migration failures. Use `scripts/with-isolated-cargo-target.sh` for isolated Cargo targets and `scripts/cleanup-bifrost-tmp.sh` for reviewed cleanup.

## Artifacts and Notes

Keep resumed raw JSONL, logs, exact records, row ledgers, and checksums under `/mnt/optane/tmp/bifrost-fird/`. Check in only compact manifests and narrative summaries under `.agents/docs/reference-differential/`. Historical LOC-ranked artifacts and their issue fixes remain valuable regression inputs, but every final manifest must label them non-authoritative for this task-ranked objective.

## Interfaces and Dependencies

Reuse `reference_differential::run_reference_differential`, `WorkspaceAnalyzer`, `UsageFinder`, language-specific structured forward resolvers and inverse graphs, `AnalyzerStore`, and `InlineTestProject`. Preserve explicit target/file/usage limits and honest `unproven` or `inconclusive` outcomes. Add public SearchTools or Python binding coverage only when the exposed surface changes. Avoid new dependencies unless a reduced root cause requires them and this plan records why.

Revision note (2026-07-20): Created this task-ranked plan after an independent audit proved the prior campaigns used LOC-ranked repository membership. It pins the exact `tasks.py`/`SFT_PREDICATES` selection, invalidates old artifacts only as objective completion evidence, preserves their regression value, and records the issue, delegation, test, publication, and per-language summary boundaries.

Revision note (2026-07-20): Completed the PHP language boundary at pushed head `64de341e`, recorded its zero-residual production evidence, and closed assigned issues #960-#962.

Revision note (2026-07-22): Added the active #661 implementation boundary after exact Scala task-ranked triage reduced the remaining inverse defects to parameter default terms, nearest-first lexical outer fields, and original terminals of renamed imports. The plan now records their AST-backed implementation and negative-control requirements before code changes.

Revision note (2026-07-22): Recorded local completion of the three #661 inverse roots, including the full-suite-discovered parameterless-callable precedence correction and the green 147-test Scala inverse graph gate. Root review, integrated gates, and production proof remain explicit campaign work.

Revision note (2026-07-22): Recorded the invalid persisted-cache publication attempt, #1073 analyzer-epoch cutover, and newly assigned #1086 physical source-set identity repair before the corrected Scala publication boundary.

Revision note (2026-07-22): Recorded the completed Scala publication at `4589dd98`, the exhaustive zero-actionable 47-row ledger, clean persisted #1073/#1086 witnesses, five issue closures, and the transition to Java.

Revision note (2026-07-22): Recovered the campaign after the machine crash, revalidated the live task-ranked Java selection and pinned clones, recorded the interrupted LanguageTool boundary, moved resumed temporary output to the operator-requested `/mnt/optane/tmp/bifrost-fird/`, and corrected the current worktree path.

Revision note (2026-07-22): Recorded the published Java campaign head and clean rerun, the pinned clean Python baseline and seven exact probes, the exhaustive four-root Python disposition, assigned issues #795/#1096-#1098, and the structured implementation boundaries including the Python cache epoch cutover.

Revision note (2026-07-22): Accepted the completed clean Java replay at `0b4f1d6f`, recorded its zero-missing five-repository evidence and hashes, and closed the Java language boundary before Python publication.

Revision note (2026-07-22): Recorded the broad-gate #1015 regression, its assigned pre-edit issue state, structured compiler-builtin repair, independent clean-snapshot diagnosis, and complete local acceptance of the integrated Python source.
