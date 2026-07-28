# Fix Python annotation inverse production parity for issue 1225

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows [.agents/PLANS.md](/mnt/optane/bifrost-fird/.agents/PLANS.md) and must be maintained in accordance with that file.

## Purpose / Big Picture

After this change, Python inverse-usage analysis should recognize two real production annotation forms that the current focused tests still miss: a class-owned alias referenced from an `@abc.abstractmethod` return annotation, and an outer typed receiver captured inside a nested closure return annotation such as `method.signature.return_type`. The change is observable by running the dedicated `issue_1225_python_annotation_inverse` test and by replaying the two exact Caikit byte ranges with `bifrost_reference_differential run-repo --strict`; both witnesses should stop classifying as `missing`.

## Progress

- [x] (2026-07-28 00:00Z) Read `.agents/PLANS.md` and the current Python inverse/resolver implementation.
- [x] (2026-07-28 00:00Z) Re-ran the focused `issue_1225_python_annotation_inverse` test; it passed before this parity pass.
- [x] (2026-07-28 00:00Z) Re-ran both exact Caikit witnesses and confirmed both still classified as `missing`.
- [x] (2026-07-28 02:00Z) Traced the decorated-method owner lookup and added structured class-scope recovery for declaration annotations and defaults.
- [x] (2026-07-28 02:00Z) Preserved outer typed-receiver facts for nested declaration annotations while keeping the nested body on its own local facts.
- [x] (2026-07-28 02:00Z) Reworked inverted scope-fact threading to use a per-walk snapshot arena keyed by small integer IDs.
- [x] (2026-07-28 02:00Z) Resolved the transient C++ compile blocker in the parallel C++ issue lane.
- [x] (2026-07-28 02:00Z) Added production-shaped fixtures and replayed both exact Caikit witnesses to `consistent` with `0 missing`.

## Surprises & Discoveries

- Observation: The current focused test passes while both production witnesses still fail.
  Evidence: `cargo test -j8 --test issue_1225_python_annotation_inverse` passed, but the exact replay JSONL files still reported `classification: "missing"` for both Caikit offsets.

- Observation: The inverted builder currently threads scope facts into nested functions with `.or(facts)`, which prefers newly resolved inner facts and drops outer captured bindings instead of preserving them.
  Evidence: `src/analyzer/usages/python_graph/inverted.rs` around the `function_definition` walker arm.

- Observation: `LocalBindingsSnapshot::merged_with_visible` gives precedence to the second argument, so a naive `local.merged_with_visible(inherited)` would let outer bindings overwrite inner ones and would also reintroduce names that the inner scope deliberately shadows.
  Evidence: `src/analyzer/usages/local_inference.rs` inserts `other.bindings` last and unions both `declared` sets.

- Observation: Python evaluates a nested function's defaults and annotations while defining it in the enclosing scope; its parameters and locals govern only the function body.
  Evidence: The production `method.signature.return_type` witness requires the outer typed `method` binding even when the nested function itself declares a same-named parameter.

## Decision Log

- Decision: Keep this pass constrained to the two production shapes named in issue 1225 instead of broadening annotation heuristics generally.
  Rationale: The focused test already demonstrates that the previous fix changed behavior, but the remaining failures are production-shape mismatches. The fastest correct path is to mirror and fix those exact shapes.
  Date/Author: 2026-07-28 / Codex

- Decision: Gate all class-owner recovery for annotation identifiers on `annotation_expression_is_class_scoped(node)`, including any tree-sitter fallback to an enclosing `class_definition`.
  Rationale: Nested functions defined inside a method body must not see bare class members as annotation bindings. Structural recovery is only valid for declaration-time expressions such as method return annotations, decorators, and defaults.
  Date/Author: 2026-07-28 / Codex

- Decision: Replace the temporary `Arc`-threaded scope-fact chain with a per-walk snapshot arena keyed by `usize`, and merge outer facts only after filtering out names shadowed by the inner snapshot.
  Rationale: This traversal is hot and file-wide. Integer IDs avoid refcount churn on every AST node, and filtering inherited bindings before `filtered_outer.merged_with_visible(&local)` preserves the correct visibility rule: inner bindings win, and inner shadows suppress outer names completely.
  Date/Author: 2026-07-28 / Codex

- Decision: Change `annotation_expression_is_class_scoped` from an eager nearest-function check to an enclosing-walk check that returns false if the site lies inside the body of any enclosing function or lambda before reaching the class.
  Rationale: A nested function return annotation is outside the inner function body but still inside the outer method body, so the old predicate incorrectly treated it as class-scoped.
  Date/Author: 2026-07-28 / Codex

- Decision: Evaluate nested-function defaults and annotations with enclosing scope facts, then switch to the nested function's local facts for its body.
  Rationale: This matches Python declaration-time name lookup and avoids treating a nested parameter as if it shadowed the expression that defines that parameter's own function.
  Date/Author: 2026-07-28 / Codex

## Outcomes & Retrospective

The focused issue test passes all seven cases. Exact Caikit replays for `ModelFutureBase` at bytes `2693..2708` and `method.signature.return_type` at bytes `5776..5785` both classify as `consistent` with exact inverse ranges. The implementation remains structural: tree-sitter owner/scope nodes, analyzer declarations, and typed binding snapshots provide all recovery and shadowing evidence.

## Context and Orientation

The Python forward usage scan lives in `src/analyzer/usages/python_graph/extractor.rs`. Shared Python annotation resolution helpers live in `src/analyzer/usages/python_graph/resolver.rs`. The whole-workspace inverted builder lives in `src/analyzer/usages/python_graph/inverted.rs`. The focused regression coverage for this issue lives in `tests/issue_1225_python_annotation_inverse.rs`.

The first failing production witness is in the Caikit clone at `caikit/core/model_management/model_trainer_base.py`, where `ModelTrainerBase` defines `ModelFutureBase = ModelTrainerFutureBase` and uses `-> ModelFutureBase` on `@abc.abstractmethod` methods. The second failing production witness is in `caikit/runtime/client/remote_module_base.py`, where nested `infer_func` uses `-> method.signature.return_type` and the typed receiver `method: RemoteRPCDescriptor` is declared on the enclosing outer function.

“Scope facts” in this repository means the structured local binding facts built by `collect_scope_facts_from_parsed_source`, stored as `HashMap<CodeUnit, LocalBindingsSnapshot<String>>`, and used to map local names such as function parameters to precise receiver types. “Owner recovery” here means finding the enclosing class `CodeUnit` for an annotation site using tree-sitter structure plus analyzer parent relationships, not text scanning.

## Plan of Work

First, instrument the current behavior narrowly enough to inspect the exact production sites. For the decorated-method witness, inspect `annotation_scope_owner_class` and `exact_owner_annotation_members` on the Caikit `ModelFutureBase` token and record the enclosing `CodeUnit`, its parent, and the candidate list. If `enclosing_code_unit` resolves the method but not the class owner at that annotation site, derive the enclosing `class_definition` structurally from the tree-sitter parent chain and map it back to exactly one analyzer class declaration in the same file.

Second, fix nested closure receiver facts in the inverted builder. When the walker enters a nested `function_definition` or `lambda`, it must preserve the chain of precise visible bindings from outer functions instead of dropping them with `.or(facts)`. The merge must remain structured: inner facts stay authoritative for names they bind, inner shadows must suppress same-named outer bindings completely, and surviving outer facts must remain available for unresolved captured names. To keep the traversal cheap, merged snapshots will be interned once per walk in a small arena and stack frames will carry only an optional arena index.

Third, update `tests/issue_1225_python_annotation_inverse.rs` to use production-shaped fixtures: an `@abc.abstractmethod` class-owned alias case with at least two methods, a nested closure `method.signature.return_type` case with a wrong-owner negative, a same-named nested parameter proving declaration-time enclosing-scope lookup, and a nested-function-inside-method negative proving that non-class-scoped inner annotations do not bind same-named class members. Then rerun the focused test and both exact replays, writing JSONL outputs under `/mnt/optane/tmp/bifrost-fird/`.

## Concrete Steps

From `/mnt/optane/bifrost-fird`:

    nice -n 10 cargo test -j8 --test issue_1225_python_annotation_inverse

Expect the dedicated test binary to compile and report all issue-1225 tests passing.

    nice -n 10 target/release/bifrost_reference_differential run-repo --root /home/jonathan/Projects/brokkbench/clones/caikit__caikit --language python --output /mnt/optane/tmp/bifrost-fird/issue-1225-caikit-modelfuturebase.jsonl --jobs 8 --cache-mode ephemeral --strict --path caikit/core/model_management/model_trainer_base.py --start-byte 2693 --end-byte 2708

    nice -n 10 target/release/bifrost_reference_differential run-repo --root /home/jonathan/Projects/brokkbench/clones/caikit__caikit --language python --output /mnt/optane/tmp/bifrost-fird/issue-1225-caikit-signature.jsonl --jobs 8 --cache-mode ephemeral --strict --path caikit/runtime/client/remote_module_base.py --start-byte 5776 --end-byte 5785

Expect each replay JSONL `sites[0].classification` to become `consistent` or otherwise stop being `missing`, with a non-null `inverse_hit`.

## Validation and Acceptance

Acceptance requires three behaviors:

1. `cargo test -j8 --test issue_1225_python_annotation_inverse` passes with fixtures that mirror the decorated abstract-method alias case and the nested closure captured-receiver case.
2. The exact Caikit `ModelFutureBase` witness no longer reports that the forward-resolved site is absent from the inverse result.
3. The exact Caikit `method.signature.return_type` witness no longer reports that the forward-resolved site is absent from the inverse result.

## Idempotence and Recovery

The test and replay commands are safe to rerun. Replay outputs should be overwritten in `/mnt/optane/tmp/bifrost-fird/` rather than `/tmp`. Temporary instrumentation must be removed before concluding the task so the working tree only contains the intended code and test changes.

## Artifacts and Notes

Before this pass, the exact replays produced:

    ModelFutureBase witness: classification "missing" for target caikit.core.model_management.model_trainer_base.ModelTrainerBase.ModelFutureBase
    method.signature.return_type witness: classification "missing" for target caikit.runtime.client.remote_config.RemoteRPCDescriptor.signature

## Interfaces and Dependencies

The resolver changes should stay within:

    src/analyzer/usages/python_graph/resolver.rs

The inverted scope-fact changes should stay within:

    src/analyzer/usages/python_graph/inverted.rs

Focused regression coverage should stay within:

    tests/issue_1225_python_annotation_inverse.rs

Revision note: Updated the plan after review to require whole-enclosing-chain class-scope detection, to replace the temporary `Arc`-based scope threading with an arena of merged snapshots keyed by IDs, and to record the unrelated C++ compile blocker that currently prevents validation.
