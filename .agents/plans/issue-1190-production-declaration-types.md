# Close the remaining production declaration-type inverse gaps for issue 1190

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agents/PLANS.md` and must be maintained in accordance with that file.

## Purpose / Big Picture

After this change, the C++ symbols APIs will return the same declaration, cast, template, and functional-cast type references that forward definition lookup already resolves in the task-ranked production corpus. The observable proof is that the dedicated behavior test passes and all eleven exact Qpid, libzmq, and log4cxx byte-range replays stop classifying as `missing` under `bifrost_reference_differential --strict`.

## Progress

- [x] (2026-07-28 04:00Z) Verified issue 1190 is open and assigned only to `jbellis`.
- [x] (2026-07-28 04:00Z) Replayed eleven pre-triaged production ranges and confirmed all eleven are still exact forward-resolved `missing` sites.
- [x] (2026-07-28 04:00Z) Grouped the misses into structured declaration, cast, template, and functional-cast type wrappers; separated nearby target-declaration self references that must remain excluded.
- [x] (2026-07-28 05:20Z) Added production-shaped behavior coverage for bare, qualified, template, cast, nested-alias, macro-decorated, and functional-cast type references with unrelated same-name controls.
- [x] (2026-07-28 05:20Z) Generalized target-guided declaration-type recovery across structured wrapper nodes and declaration/cast contexts, including parser-lost macro namespace prefixes.
- [x] (2026-07-28 05:20Z) Reused the structurally resolved call-target identity for functional casts, retaining free-function and physical-visibility gates.
- [x] (2026-07-28 05:20Z) Replayed all eleven exact Qpid, libzmq, and log4cxx production sites; all now report `actionable=0` under `--strict`.
- [x] (2026-07-28 05:50Z) Replayed all eleven exact sites to zero actionable rows and passed 168 targeted C++ usage tests, 28 workspace-graph tests, formatting, and all-target/all-feature Clippy.
- [x] (2026-07-28 06:05Z) Prepared the reviewed, fully verified change for direct publication to `origin/master` and issue 1190 closure.

## Surprises & Discoveries

- Observation: Issue 1190 had already been fixed twice, but the previous fallback runs only after a lexical `Missing` result and accepts only a leaf `type_identifier` in field or parameter declarations.
  Evidence: `target_guided_missing_declaration_type_leaf` in `src/analyzer/usages/cpp_graph/extractor.rs` excludes qualified, template, local-declaration, and cast wrappers; the current `Resolved`-mismatch and `Ambiguous` branches do not consult it.

- Observation: The eleven remaining sites are real references, while nearby `Exception`, `WideMessageBuffer`, `wlogstream`, and `ulogstream` rows are intentionally excluded self references inside their own target declarations.
  Evidence: exact JSONL replays under `/mnt/optane/tmp/bifrost-fird/issue-1190-*.jsonl` and the target-declaration range filter in `src/analyzer/usages/cpp_graph/hits.rs`.

- Observation: Qpid's `pn_ssl_verify_mode_t(mode)` forward result contains two same-FQN typedef enum declarations, but only the header included by the C++ file is physically visible.
  Evidence: the exact replay lists `c/include/proton/ssl.h` and `python/cproton.h`; inverse recovery must retain visibility rather than matching terminal text.

- Observation: libzmq macro-decorated class declarations can preserve only a class name, or no lexical scope at all, while log4cxx can preserve a trailing namespace plus owner but lose the leading macro namespace.
  Evidence: targeted traces reported scopes `[]` for `dist_t`, `["yqueue_t"]` for `atomic_ptr_t`, and `["helpers", "Object"]` for `LOG4CXX_NS::helpers.Class`; the fallback now requires a unique visible target and either a short lost scope or a structured suffix match against the target package.

- Observation: Qpid's functional cast was already classified structurally as a type call, but the scanner discarded that exact `CodeUnit` and reran a duplicate-sensitive lexical lookup.
  Evidence: the traced `BareCallTargetResolution::Type` returned the physically visible `pn_ssl_verify_mode_t`; consuming that result directly made the exact replay consistent while invisible duplicate declarations remained excluded.

## Decision Log

- Decision: Extend the existing target-guided structured recovery instead of adding text scanning or repository-specific cases.
  Rationale: Tree-sitter nodes, analyzer lexical scope, target identity, and visibility already contain the required evidence and comply with the repository's structured-analysis design.
  Date/Author: 2026-07-28 / Codex

- Decision: Preserve the existing public range contract: qualified declaration types use their structured range, template declaration types retain the outer template range, and local declaration/call types use the existing terminal-node narrowing.
  Rationale: The differential accepts covering inverse evidence, and preserving established public ranges avoids an unrelated API change while still preventing nested-node double counting.
  Date/Author: 2026-07-28 / Codex

- Decision: Admit a fallback only when the target is physically visible and the structured name plus indexed lexical scope identifies the exact target, with the existing unique-visible exception limited to parser-lost parameter namespaces.
  Rationale: Wrong-owner and duplicate-name types must continue to fail closed.
  Date/Author: 2026-07-28 / Codex

## Outcomes & Retrospective

The implementation closes all eleven starting `missing` rows: one Qpid functional cast, two libzmq field types, and eight log4cxx parameter, local declaration, cast, field, and return types. The final design consumes already-proven call-target identity for functional casts and recovers declaration-context type wrappers only when target identity, source order, preprocessor guards, global qualification, physical visibility, and structured lexical scope remain compatible.

The broad regression suite initially exposed over-broad recovery across resolved/ambiguous paths and missing source-order/global-qualification gates. Those experiments were narrowed before publication. The final code retains the existing fallback only on lexical `Missing`, preserves range contracts, and passes all 196 relevant C++ tests plus Clippy. Two independent Oldskool reviews found no implementation blockers and prompted callable-shadow and wrong-owner alias controls.

## Context and Orientation

The targeted inverse scanner is `src/analyzer/usages/cpp_graph/extractor.rs`. Its `maybe_record_type_hit` function receives every tree-sitter node for one requested type target and records exact hits after lexical resolution. `target_guided_missing_declaration_type_leaf` is a conservative fallback added by the earlier issue-1190 fix; it uses the analyzer's enclosing declaration, C++ lexical scope, visible type candidates, and the requested `CodeUnit` target.

The whole-workspace inverted builder is `src/analyzer/usages/cpp_graph/inverted.rs`. It records resolved graph edges without a requested target. Shared node-role and exact-range helpers live in `src/analyzer/usages/cpp_graph/resolver.rs`. Regression coverage belongs in `tests/usages_cpp_graph_test.rs` and should use `InlineTestProject`.

A “structured wrapper” is a tree-sitter node such as `qualified_identifier`, `template_type`, or `type_descriptor` that contains the actual type-name leaf. A “target-guided” recovery uses the exact requested declaration identity to disambiguate structured evidence; it does not search source text.

## Plan of Work

First add one production-shaped test containing a namespace-qualified alias parameter, bare and template field types, a local pointer declaration plus C-style cast, nested class aliases in field and return positions, and a C-style functional cast to a typedef enum. Include unrelated same-name types, a same-named free function where legal, and target declaration names as negative controls. Assert both authoritative targeted results and the public whole-workspace surface.

Next refactor `target_guided_missing_declaration_type_leaf` so it derives structured name components and the exact hit node from bare, qualified, scoped, and template type nodes. Allow only recognized type-bearing ancestors: `field_declaration`, `parameter_declaration`, ordinary `declaration` type fields, and `type_descriptor` cast fields. Consult this recovery after lexical `Resolved` mismatch and `Ambiguous` as well as `Missing`, because production macro and alias environments can produce a non-target candidate rather than no candidate.

Then repair the functional-cast path in `maybe_record_direct_temporary_type_hit`. It must use the same requested-target visibility and lexical identity checks when ordinary call resolution sees an ambiguous duplicate typedef or loses the type wrapper. It must not reinterpret a proven free-function call as a type reference.

Finally rebuild the differential runner, replay all eleven exact sites, and iterate only on representatives that remain `missing`. Run focused and complete C++ graph suites, formatting, and all-target/all-feature Clippy. Commit only the issue-1190 files, push to `origin/master`, and close the assigned ticket with exact evidence.

## Concrete Steps

Run commands from `/mnt/optane/bifrost-fird`. Cargo and Bifrost commands use normal repository storage outside the sandbox at niceness 10.

    nice -n 10 cargo test -j8 --test usages_cpp_graph_test issue_1190

Expect the new production-shaped test to fail before implementation and pass afterward.

    nice -n 10 cargo build -j8 --bin bifrost_reference_differential
    nice -n 10 target/debug/bifrost_reference_differential run-repo --root /mnt/T9/repo-clones/zeromq__libzmq --language cpp --output /mnt/optane/tmp/bifrost-fird/issue-1190-libzmq-dist-final.jsonl --jobs 24 --cache-mode ephemeral --force --strict --path src/dish.hpp --start-byte 1262 --end-byte 1268

Expect strict replay exit code zero and `classifications.missing` equal to zero. Repeat the exact command shape for the recorded Qpid and log4cxx byte ranges.

    nice -n 10 cargo test -j8 --test usages_cpp_graph_test --test usage_graph_cpp_test
    nice -n 10 cargo fmt
    nice -n 10 cargo clippy -j8 --all-targets --all-features -- -D warnings

Expect every command to exit zero.

## Validation and Acceptance

Acceptance requires the new behavior test to prove exact targeted and whole-workspace hits for every supported context while preserving all negative controls. All eleven production JSONL files must contain zero `missing` classifications and non-null exact or covering inverse evidence. `usages_cpp_graph_test`, `usage_graph_cpp_test`, formatting, and Clippy must pass.

## Idempotence and Recovery

Tests and `--cache-mode ephemeral --force` replays are safe to repeat. All replay output stays under `/mnt/optane/tmp/bifrost-fird/`. Do not set `CARGO_TARGET_DIR`; normal Cargo storage is required. If a replay remains missing, inspect only that exact site's AST and resolver result rather than rerunning the full top-ten corpus. Temporary trace code must be removed before commit.

## Artifacts and Notes

Initial exact artifacts include:

    issue-1190-qpid-ssl-verify-mode.jsonl
    issue-1190-libzmq-dist.jsonl
    issue-1190-libzmq-atomic-ptr.jsonl
    issue-1190-log4cxx-*.jsonl

Each currently reports one forward-resolved `missing` site.

## Interfaces and Dependencies

No public API changes or new dependencies are required. The implementation should reuse `LexicalTypeResolution`, `resolve_type_node_lexically_for_target`, `indexed_enclosing_lexical_scope`, `lexical_component_tiers`, `same_visible_symbol`, `type_reference_hit_node`, and `VisibilityIndex` in `src/analyzer/usages/cpp_graph`.

Plan revision note (2026-07-28): Created after exact production replay and two independent read-only analyses established a single structured wrapper gap across the remaining issue-1190 sites.

Plan revision note (2026-07-28): Completed after two Oldskool review passes, adversarial negative-control additions, all relevant C++ tests and Clippy, and a final eleven-site strict replay with zero actionable rows.
