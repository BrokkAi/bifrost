# Disambiguate same-arity C++ function overloads in usage scans and definition lookups (issue #427)

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document must be maintained in accordance with `.agent/PLANS.md` at the repository root.

## Purpose

Bifrost's C++ support currently conflates same-arity function overloads. Given

    // include/parity.h
    namespace parity {
    std::string format(const std::string& value);
    std::string format(int value);
    }

    // src/main.cpp
    auto formatted = parity::format(first);   // first is a std::string
    auto number    = parity::format(7);

asking for the usages of `format(const std::string&)` (the `scan_usages` MCP tool, backed by `src/analyzer/usages/cpp_graph/`) wrongly includes the `parity::format(7)` call, and asking for the definition of the reference `parity::format(first)` (the `get_definition_by_location` MCP tool, backed by `src/analyzer/usages/get_definition/cpp.rs`) returns all four `format` code units (two header declarations plus two out-of-line definitions) instead of narrowing to the `std::string` overload. This is tracked as GitHub issue BrokkAi/bifrost#427 and is exercised by the `cpp-parity-overload-string-function-call` case in the BrokkAi/usagebench benchmark (fixture `fixtures/cpp/lsp-parity`, currently marked `expectedFailure`).

After this change:

- Declaration-to-usage: scanning usages of the `format(const std::string&)` declaration returns exactly the out-of-line definition site and the `parity::format(first)` call — not `parity::format(7)`. Scanning the `format(int)` overload returns only `parity::format(7)`-style call sites.
- Usage-to-declaration: `get_definition` on the `format` token of `parity::format(first)` returns only the `std::string` overload's declaration and out-of-line definition; on `parity::format(7)` it returns only the `int` overload's units.

Both behaviors are demonstrated by new tests named in the milestones below.

## Orientation: the three code paths and the terms used in this plan

A `CodeUnit` (`src/analyzer/model.rs`) is bifrost's record of one declared symbol: it carries a dotted fully-qualified name (`fq_name()`, e.g. `parity.format` — note: no signature, so *both overloads share the same fq_name*), the source `ProjectFile`, a `kind` (Function / Class / Field / ...), and an optional display `signature()` string, e.g. `std::string format(const std::string& value)`. The C++ analyzer indexes each overload declaration and each out-of-line definition as its own `CodeUnit`; they differ by `signature()` and/or `source()` but share `fq_name()`.

Three independent code paths interpret C++ references, and each has (or lacks) its own overload logic:

1. **The forward usage scan** — `src/analyzer/usages/cpp_graph/extractor.rs`, driven by `CppQueryResolver::find_usages` in `src/analyzer/usages/cpp_graph/shared.rs`. Given a target `CodeUnit` it re-parses candidate files with tree-sitter and records `UsageHit`s. The target is described by a `TargetSpec` (`src/analyzer/usages/cpp_graph/resolver.rs`) holding the member name, an optional owner, and `method_arity` (parameter count parsed from the target's signature). For a free-function call the scan currently accepts a hit if the callee *name* matches, the *arity* matches, and the name is visible as the target (`VisibilityIndex::contains_named_symbol`). Same-arity overloads are therefore indistinguishable — this produces the false `format(7)` hit. Note the `function_definition` arm (`maybe_record_free_function_definition_hit`) already compares full parameter-type lists via `function_definition_signature_matches_target`, so *definition* sites are already overload-precise; only *call* sites are not.

2. **The definition lookup** — `src/analyzer/usages/get_definition/cpp.rs`. `resolve_cpp_call` collects candidate `CodeUnit`s by name (`cpp_visible_name_candidates`, which also expands each visible unit through the workspace-wide `DefinitionLookupIndex::fqn`, which is how the two out-of-line definitions from `src/parity.cpp` join the candidate set even though that file is not in `main.cpp`'s include closure), then filters with `cpp_filter_candidates_by_call_lazy`: first by arity, then — only if *every* argument's type was inferred — by parameter compatibility (`cpp_candidate_params_match_args`), falling back to the arity-filtered set when the filtered set would be empty. The machinery is right, but it is powerless on this fixture for two reasons spelled out below (see "Why the existing filter fails").

3. **The inverted whole-workspace edge builder** — `src/analyzer/usages/cpp_graph/inverted.rs`, backing the `usage_graph` tool. It records `caller fqn -> callee fqn` edges keyed by *bare fq_name strings* (`NodeKey for String` in `src/analyzer/usages/inverted_edges.rs` is `unit.fq_name()`). Because both overloads share `fq_name() == "parity.format"`, they are **the same graph node by construction**; no per-call-site overload filtering can change the resulting edge set. Issue #427's suggested step 3 (filter overload candidates in `inverted.rs`) is therefore a functional no-op and is deliberately **not implemented** — see the Decision Log.

Two different "visibility index" types exist and must not be confused: `src/analyzer/usages/cpp_graph/resolver.rs` defines `VisibilityIndex` (used by paths 1 and 3), and `get_definition` uses its own `CppVisibilityIndex` (in `src/analyzer/usages/get_definition/cpp_visibility.rs` — check the actual filename with `grep -rn "struct CppVisibilityIndex" src/`). Both expose `resolve_type(file, text) -> Option<CodeUnit>` over the file's include closure. Shared helpers must therefore be *pure* (signature parsing, literal typing, name normalization, filter combinator over caller-supplied callbacks) rather than depending on either index type.

## Why the existing get_definition filter fails on the fixture

The benchmark fixture (reproduced in full under "Test fixture" below) does two things that defeat the current `CppType`-based matcher:

- `std::string` is **not an indexed workspace class** (it comes from the system `<string>` header, which is outside the workspace). The current `CppType` struct (`src/analyzer/usages/get_definition/cpp.rs`, near line 1112) *requires* a resolved `unit: CodeUnit`; `cpp_candidate_params_match_args` also requires `visibility.resolve_type(file, param_type)` to succeed for the *parameter* type. Neither holds for `std::string` or `int`, so type matching never fires and the code falls back to the arity-filtered set (all four candidates).
- The argument `first` is declared `auto first = base.handle("Ada");` where `base` is a `parity::BaseHandler&` (an indexed class). Typing `first` requires **method-call return-type inference**: type the receiver `base` via local bindings, look up member `handle` on `BaseHandler`, and read the return type `std::string` out of the member's signature text. `cpp_infer_type_from_value`'s `call_expression` arm currently only handles `qualified_identifier` (`X::m(...)`) and bare `identifier` callees — not `field_expression` (`recv.m(...)`) — and `cpp_function_return_type` also insists the return type resolve to an indexed unit.
- The literal argument `7` has no type at all today: `cpp_expression_type` has no arm for literal nodes.

So the fix must let a C++ type be *named but unindexed*: carry the normalized type text (e.g. `std::string`, `int`) always, and a resolved `CodeUnit` only when the workspace indexes it. Matching compares resolved units through the existing pointer-depth + base-class assignability logic and falls back to normalized-name equality when either side is name-only. This is the structured best-effort explicitly permitted by the repo design philosophy in `CLAUDE.md` (AST-derived names and `CodeUnit` signatures — not regex scans of source text).

## Matching semantics (normative)

These rules are shared by all milestones. "Type name" always means the output of the existing normalizers (`normalize_cpp_type_text` in get_definition / `normalize_type_text` + parameter-type normalization in cpp_graph): whitespace collapsed, leading `const`/tag prefixes stripped, trailing `&` stripped, parameter names and default values stripped. Pointer depth (`*` count at the top level) is tracked *separately* from the name via the existing `cpp_type_text_pointer_depth`; references (`&`) contribute depth 0 because a reference parameter binds a value argument.

An inferred **argument type** is `(name, optional unit, pointer depth)`. Inference sources:

- Integer literals (`number_literal` without `.`/`e`/`E` and without a floating suffix) → name `int`, depth 0. Floating literals → name `double`. `true`/`false` → `bool`. `char_literal` → `char`. **String literals deliberately infer nothing** (return unknown): a `"..."` argument can bind `const char*`, `std::string`, `std::string_view`, or any type with a converting constructor, so treating it as typed would create false proofs of non-match. Record this as a decision, not an oversight.
- A local variable → its binding's type. Bindings must now retain the *declared type text* even when it does not resolve to an indexed class (today such locals are shadowed with no type). `auto` locals are typed from their initializer where the initializer's type is inferable (constructor calls, `new`, and — after this plan — method/function call return types).
- A call expression argument → the (unique) return type of the resolved callee, by name when unindexed.
- Anything else (address-of/deref chains beyond the existing pointer_expression handling, arithmetic, ternaries, ...) → unknown.

A **candidate parameter list** comes from `CodeUnit::signature()` via the existing signature parameter-type extraction (`cpp_signature_param_types` in get_definition, `signature_parameter_types` in the extractor — Milestone 1 merges these).

**Per-argument compatibility** of parameter type `P` (text) against argument type `A`:

1. If the top-level pointer depths differ → incompatible.
2. If both `P` and `A` resolve to indexed units → compatible iff `A`'s unit is assignable to `P`'s unit (same unit or reachable through the declared base classes — the existing `cpp_type_assignable_to` walk).
3. Otherwise → compatible iff the normalized names are equal (`std::string` vs `std::string`; `int` vs `int`). Name inequality counts as incompatible; the set-level fallback below is what keeps this safe in the presence of implicit conversions.

**Set-level filter** (this is the existing `cpp_filter_candidates_by_call_lazy` contract, now shared): given same-name candidates and a call site — filter by arity first (if none survive, keep the unfiltered set); if ≤ 1 candidate remains, stop; if *any* argument's type is unknown, stop (keep the arity-filtered set); otherwise keep candidates whose every parameter is compatible with the corresponding argument; **if that set is empty, keep the arity-filtered set** (an implicit conversion we cannot model is more likely than a call that matches nothing).

**Forward-scan hit rule** (Milestone 3): at a call site whose callee name and arity match the target, resolve the *visible same-name candidate set* (the same iteration `contains_named_symbol` performs today, collecting matches instead of testing membership), apply the set-level filter with the call's inferred argument types, and record a hit only if the filtered set contains the target (`same_visible_symbol`). When the filter was inconclusive (unknown argument, or the empty-set fallback fired) the behavior is exactly today's: the name+arity match stands. When the filter conclusively excludes the target, the site is a *proven non-match*: record neither a hit nor `saw_unproven_match` (the same treatment `resolve_known_non_target` already gets on the qualified-name path).

## Test fixture (canonical, mirrors BrokkAi/usagebench `fixtures/cpp/lsp-parity`)

Use this three-file project in the new tests (via `InlineTestProject` from `tests/common/inline_project.rs`; see the existing C++ tests in `tests/usages_cpp_graph_test.rs` and `tests/get_definition_test.rs` for the harness idioms — get_definition tests take a `LOOKUP_LOCK` guard, copy the pattern of a neighboring test exactly):

    include/parity.h:
        #pragma once
        #include <string>
        namespace parity {
        struct AuditSink {
            std::string last;
            void record(const std::string& value);
        };
        class BaseHandler {
        public:
            virtual ~BaseHandler() = default;
            virtual std::string handle(const std::string& name) = 0;
        };
        class ConsoleHandler : public BaseHandler {
        public:
            explicit ConsoleHandler(AuditSink& sink);
            std::string handle(const std::string& name) override;
        private:
            AuditSink& sink_;
        };
        std::string format(const std::string& value);
        std::string format(int value);
        } // namespace parity

    src/parity.cpp:
        #include "parity.h"
        namespace parity {
        void AuditSink::record(const std::string& value) { last = value; }
        ConsoleHandler::ConsoleHandler(AuditSink& sink) : sink_(sink) {}
        std::string ConsoleHandler::handle(const std::string& name) {
            sink_.record(name);
            return name;
        }
        std::string format(const std::string& value) { return "s:" + value; }
        std::string format(int value) { return "i:" + std::to_string(value); }
        } // namespace parity

    src/main.cpp:
        #include "parity.h"
        namespace app {
        std::string run() {
            parity::AuditSink sink;
            parity::ConsoleHandler handler(sink);
            parity::BaseHandler& base = handler;
            auto first = base.handle("Ada");
            auto formatted = parity::format(first);
            auto number = parity::format(7);
            return formatted + number;
        }
        } // namespace app

(The real fixture routes `handler` through a `using HandlerAlias = ConsoleHandler;` alias and calls a template `choose<...>`; those aspects are covered by other benchmark cases and may be omitted here, but keep `auto first = base.handle("Ada")` — the virtual-call return-type inference is the point.)

Select the overload under test from `analyzer.get_all_declarations()` by `fq_name() == "parity.format"` plus `signature().contains("std::string&")` (or `contains("int")`), narrowed to the header file for declarations.

## Milestone 1 — shared call-compatibility helpers

Create `src/analyzer/usages/cpp_call_match.rs` (registered in `src/analyzer/usages/mod.rs`, visibility `pub(in crate::analyzer::usages)`) containing the pure pieces both sides use:

- Parameter-type extraction from a signature string. Today this exists twice with slightly different normalization: `cpp_signature_param_types`/`cpp_parameter_type_text` in `src/analyzer/usages/get_definition/cpp.rs` (~line 997) and `signature_parameter_types`/`normalize_parameter_type`/`strip_parameter_name` in `src/analyzer/usages/cpp_graph/extractor.rs` (~line 711). Consolidate into one implementation here and make both call sites use it. **Behavioral guardrail**: `function_definition_signature_matches_target` in the extractor compares its output for equality against the target's signature params — run `BIFROST_SEMANTIC_INDEX=off cargo test --test usages_cpp_graph_test --test get_definition_test` after the swap to prove no regression before moving on. Note the extractor variant uses a balanced-paren scan for the parameter span (correct for function *definitions* whose bodies follow) while the get_definition variant takes the first `(`..`)` — keep the balanced scan as the shared behavior.
- `cpp_literal_type_name(node: Node, source: &str) -> Option<&'static str>` implementing the literal rules from "Matching semantics".
- The per-argument compatibility check and the set-level filter, parameterized over caller-supplied callbacks for `resolve_type` and unit-to-unit assignability so the function does not depend on either visibility-index type. A reasonable shape:

        pub(in crate::analyzer::usages) struct CppArgType {
            pub name: String,        // normalized, never empty
            pub unit: Option<CodeUnit>,
            pub indirection: i32,
        }

        pub(in crate::analyzer::usages) fn cpp_filter_candidates_by_args<'a>(
            candidates: Vec<CodeUnit>,
            arg_types: &[Option<CppArgType>],
            resolve_type: &dyn Fn(&str) -> Option<CodeUnit>,
            assignable: &dyn Fn(&CodeUnit, &CodeUnit) -> bool,
        ) -> Vec<CodeUnit>

  implementing exactly the set-level rules above (the arity pre-filter can stay at the call sites, which already have it). Unit tests for this module belong inline (`#[cfg(test)] mod tests`) and should cover: name-equality match, unit assignability match, pointer-depth mismatch, unknown-argument bailout, empty-filter fallback.

Nothing user-visible changes in this milestone; acceptance is the two existing test suites passing unchanged.

## Milestone 2 — get_definition narrows overloads on the fixture

All in `src/analyzer/usages/get_definition/cpp.rs`:

1. Restructure `CppType` from `{ unit: CodeUnit, indirection, alias_unit }` to carry `name: String` (normalized type text, always present) and `unit: Option<CodeUnit>`. Every existing constructor site sets `name` from the text it already has (declared type text, `new T` text, return-type text, field declaration text); sites that only have a unit use `cpp_name_for(&unit)`. Consumers that need a receiver unit (`cpp_receiver_unit_for_access`, receiver typing) filter on `unit` being present — a name-only type simply cannot be a receiver owner, which is today's behavior anyway (those locals are currently shadowed with no type at all).
2. `cpp_seed_binding` (~line 2146): when the declared type text does not resolve to a unit, seed a name-only `CppType` (normalized text, declarator pointer depth) instead of `declare_shadow`. Keep `declare_shadow` for the no-type-no-value case. Preserve the "shadowed" semantics tests rely on: a local named `format` of unresolvable type must still shadow the free function for `bindings.is_shadowed` purposes — check how `is_shadowed` is computed in `src/analyzer/usages/local_inference.rs` (a seeded symbol is not "unknown", so `is_shadowed(name)` behavior may change for these locals; verify `resolve_cpp_call`'s `bindings.is_shadowed(name)` guard still rejects calls through local variables, and if seeding breaks that, consult `first_precise` usage and adjust the guard to "has any local binding" instead).
3. `cpp_expression_type` (~line 1182): add literal arms per the shared `cpp_literal_type_name`.
4. `cpp_infer_type_from_value` (~line 2474) / `cpp_call_return_type` (~line 2512): add a `field_expression` callee arm — type the receiver with the existing `cpp_field_receiver_type_units`, collect member candidates with `cpp_direct_member_candidates` + the inherited walk (`cpp_member_candidates` already packages this), arity-filter, and read the return type. Make `cpp_function_return_type` (~line 2551) fall back to a name-only `CppType` when `resolve_type` fails, instead of returning `None`. Guard against ambiguity: if multiple same-arity member candidates disagree on the return type name, return `None` (mirror `resolve_call_return_type` in `src/analyzer/usages/cpp_graph/resolver.rs`, which already implements this "unanimous or nothing" rule).
5. `cpp_candidate_params_match_args` (~line 962): replace its body with the shared per-argument check (resolve callbacks close over `analyzer`/`visibility`/`file`; assignability wraps the existing `cpp_type_assignable_to`).

Acceptance (add to `tests/get_definition_test.rs`, following an existing C++ test's exact harness pattern): on the canonical fixture, a definition lookup on the `format` token of `parity::format(first)` in `src/main.cpp` returns status `resolved` with definitions exactly the two `std::string`-overload units (header declaration + `src/parity.cpp` definition), and a lookup on `parity::format(7)` returns exactly the two `int`-overload units. Before this milestone the first lookup returns all four (verify by writing the test first and watching it fail).

## Milestone 3 — forward scan filters call sites by argument types

In `src/analyzer/usages/cpp_graph/resolver.rs` and `extractor.rs`:

1. `TargetSpec` gains `param_types: Option<Vec<String>>`, populated in `from_target` for function targets from `signature_parameter_types(target.signature())` (the Milestone 1 shared helper). `None` when the signature is missing.
2. Extend the scan's local bindings to retain declared type text. The engine is `LocalInferenceEngine<CodeUnit>` in `ScanCtx`; change its value type to a small `CppScanBinding { unit: Option<CodeUnit>, type_name: Option<String>, indirection: i32 }` (hashable; `unit` present implies `type_name` = `cpp_name_for(unit)` unless the declared spelling was more specific). Update `seed_binding_from_type_or_value`, `infer_type_from_value`, `receiver_matches_target`, `receiver_has_known_non_target` (both look through `.as_precise()` — they now match on the `unit` field), and `constructor_style_local_declaration` in `resolver.rs` (it only calls `resolve_symbol(...).is_unknown()`, so it can take the engine generically or accept the new type). `inverted.rs` has its own engine instance and seeding functions; it does not need argument typing — leave its `LocalInferenceEngine<CodeUnit>` alone unless the type change to shared helpers forces the same small mechanical update there (acceptable either way; keep the diff minimal).
3. Add a call-site argument typer in `extractor.rs`: for each argument node — literal → shared literal name; `identifier` → binding lookup (unit and/or type_name; unresolved *and* untyped → unknown); everything else → unknown. Depth handling: a plain identifier argument uses the binding's recorded indirection; wrap `pointer_expression` with the same +1/−1 the get_definition side uses if cheap, otherwise treat as unknown.
4. In `maybe_record_free_function_hit` and `maybe_record_method_hit` (call-expression arms, including the explicit-operator branch only if trivial — operators rarely overload by arity alone; fine to leave operators on the old path, documented): after the existing name and arity checks pass and *before* the visibility test, apply the forward-scan hit rule from "Matching semantics". Building the candidate set: iterate `ctx.visibility.visible_by_file` units the way `contains_named_symbol` does (`matches_kind_for_lookup` + `reference_matches_unit`), collect instead of short-circuiting, arity-filter with the existing `signature_arity`. If the filtered set excludes the target, `return` without setting `saw_unproven_match`. Otherwise fall through to today's logic untouched.
5. Wire the `resolve_type` / assignability callbacks for the shared filter from the cpp_graph side: `resolve_type` is `VisibilityIndex::resolve_type(file, text)`; for assignability, same-unit equality (`same_visible_symbol`) is enough for this milestone — base-class walking on the scan side can reuse `cpp_direct_base_types`' approach only if it is trivially liftable into the shared module; otherwise same-unit equality plus name equality is the documented conservative floor (the empty-set fallback keeps derived-to-base calls from being dropped: a derived-typed argument matches *no* candidate textually, so the filter falls back to arity behavior rather than excluding the target).

Acceptance (add to `tests/usages_cpp_graph_test.rs` on the canonical fixture, driving `crate` API the way that suite's existing tests do — most call `find_usages(analyzer, &[unit])` from `src/analyzer/usages/mod.rs`):

- Usages of the `format(const std::string&)` header declaration include the `src/parity.cpp` out-of-line definition and the `parity::format(first)` line, and **do not** include the `parity::format(7)` line.
- Usages of the `format(int)` header declaration include `parity::format(7)` and its out-of-line definition, and **do not** include `parity::format(first)`. Note this direction requires typing `first` in the *extractor*: `auto first = base.handle("Ada")` types through `infer_type_from_value`'s call arm, which currently delegates to `infer_cpp_initializer_type` (resolver.rs) and cannot type a `field_expression` receiver call. Extend `infer_cpp_initializer_type`'s `call_expression` arm to handle `field_expression` callees: receiver typed via the current bindings (the extractor already passes them around — check `infer_type_from_value`'s signature; `inverted.rs` calls the same helper without bindings, so give the helper an `Option`al bindings parameter or a receiver-resolver callback), member return type read via `cpp_function_return_type_text` with unanimous-or-nothing across same-arity members, name-only results allowed. If this proves disproportionately invasive, the *fallback* is to declare `first` with an explicit `std::string first = ...` in this second test and record the `auto` case as a known recall gap in the Decision Log — but attempt the structured fix first; it is the same inference Milestone 2 adds on the get_definition side.
- A conservative regression guard: a call `parity::format(sink.last)` (member field of unindexed type `std::string`... actually indexed as a field with signature text) or any argument the typer cannot resolve must still be reported as a usage of *both* overloads (unknown argument → today's behavior). Add one such call in a variant fixture or assert on `format(handler.handle("x"))`-style nested call if simpler.

Also re-run `tests/usage_graph_cpp_test.rs` (the fqn-keyed edge surface): behavior must be unchanged.

## Milestone 4 — end-to-end proof against the real tool surface

Add one test (place alongside existing `scan_usages`-level C++ coverage — `grep -rn "scan_usages" tests/ --include "*.rs"` to find the suite; if none exists at the tool layer for C++, the `find_usages` + `resolve_definition_batch` layers from Milestones 2–3 are the accepted stand-in and this milestone collapses into a checklist item verifying both new tests express the benchmark's exact expectations: header-decl → {definition site, `format(first)` line} and `format(first)` → header string declaration among a resolved, single-overload definition set).

Validation commands for the whole change, run from the worktree root:

    cargo fmt
    cargo clippy --all-targets --features nlp,python -- -D warnings
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_cpp_graph_test --test get_definition_test --test usage_graph_cpp_test --test cpp_analyzer_test

(The `clippy-no-cuda` alias must be spelled out long-form here: nested worktrees under `.claude/worktrees/` see both the repo's and the worktree's `.cargo/config.toml` and cargo rejects the duplicated alias. Never `--all-features`; it enables CUDA.) All three commands must be clean. The repo denies warnings in CI.

Optionally (not gating): clone BrokkAi/usagebench and run the benchmark case against this worktree to watch the case flip from `expectedFailure` to passing:

    git clone https://github.com/BrokkAi/usagebench /tmp/usagebench && cd /tmp/usagebench
    cargo run -- run-bifrost benchmarks/cases/cpp-lsp-parity.yaml \
      --bifrost-repo <worktree-path> --bifrost-commit HEAD \
      --output target/usagebench/lsp-parity-cpp.json

Note on the benchmark's selector semantics (context, no code change): the harness selects `include/parity.h#parity.format`, which matches both overload declarations; `CppQueryResolver::find_usages` scans `overloads.first()`, and `CodeUnit`'s `Ord` tiebreaks on signature so the `const std::string&` overload sorts before `int` — the scan target is deterministically the string overload, which is exactly the case's expectation. Do not "fix" the `.first()` by unioning per-overload scans; that would re-introduce the `format(7)` hit at the tool layer and fail the benchmark.

## Progress

- [x] Investigation: reproduced the failure mechanics by reading all three paths; confirmed fq_name conflation, `.first()` ordering, and the two get_definition blockers (this document).
- [ ] Milestone 1: shared `cpp_call_match.rs` helpers + dedup of signature param parsing, with inline unit tests (name/unit/pointer-depth/unknown-arg/empty-fallback).
- [ ] Milestone 2: get_definition narrows the fixture lookups (new tests in tests/get_definition_test.rs, written to fail first).
- [ ] Milestone 3: forward scan excludes proven non-target overload call sites (new tests in tests/usages_cpp_graph_test.rs, including the auto-from-virtual-call direction and the unknown-argument conservative guard).
- [ ] Milestone 4: fmt + clippy (long-form command) clean; the four named test suites green; optional usagebench run recorded here.

## Surprises & Discoveries

(From the investigation; implementers append here as they find more.)

- The usagebench fixture types `first` through a *virtual call on a base-class reference* (`auto first = base.handle("Ada")`), so the issue's "collect the call argument types using the same local binding/value inference already used" understates the work: method-call return-type inference does not exist on either path today, and `std::string` cannot resolve to a unit at all. This drives the named-but-unindexed `CppType` redesign.
- `usage_graph`'s C++ nodes are keyed by bare `fq_name()` strings; overloads are one node by construction, so the issue's step 3 (inverted.rs filtering) cannot change any observable output.
- The extractor's *definition*-site matching is already overload-precise (`function_definition_signature_matches_target` compares parameter-type lists); only call sites lack filtering.
- `scan_usages`'s rendering layer has an overload-aware post-filter on one path: `retain_hits_resolving_to_overloads` (src/searchtools.rs, `FuzzyResult::Ambiguous` + location-selected branch) re-runs definition lookups on hits. The benchmark's symbol-selector path takes the `Success` branch, which does *not* post-filter — the scan itself must be precise. Be aware of this interplay when validating end to end.
- Watch for tree-sitter-cpp wrapping negative literals (`format(-3)`) in a `unary_expression` around the `number_literal`; decide in Milestone 1 whether to type through the sign wrapper or return unknown, and record the choice here.

## Decision Log

- **Drop issue step 3 (inverted.rs overload filtering).** `NodeKey for String` is `unit.fq_name()`; both overloads are `parity.format`. Filtering candidates per call site cannot alter the edge set, and inventing a signature-qualified node key would change the `usage_graph` surface for every consumer — far beyond this issue. Alignment between `usage_graph` and `scan_usages` is preserved trivially (the graph is overload-agnostic by key design).
- **String literals infer no type.** `"abc"` can bind `const char*`, `std::string`, or any converting constructor; typing it as `char*` would let the filter *prove* false non-matches. Unknown keeps the conservative arity behavior.
- **Name inequality is a mismatch, safety lives in the set-level fallback.** Implicit conversions (e.g. `int` → `double`, converting constructors) mean textual inequality does not always mean the call cannot bind that overload. Instead of modeling conversions, the filter keeps the arity-filtered set whenever *no* candidate matches, so a conversion-only call degrades to today's behavior instead of losing hits.
- **Keep `CppQueryResolver`'s `overloads.first()` semantics.** The scan target for an ambiguous selector remains the first overload by `CodeUnit` order; scanning all overloads and unioning would regress the benchmark and change the tool contract. Out of scope.
- **Constructor overloads are out of scope.** `maybe_record_constructor_hit` has the same arity-only weakness for same-arity constructor overloads; noted for a follow-up issue rather than widening this change.
- **Extractor bindings carry `CppScanBinding { unit, type_name, indirection }`** (recommended shape) rather than a parallel second engine; `receiver_matches_target`/`receiver_has_known_non_target` match through the `unit` field. `inverted.rs` keeps `LocalInferenceEngine<CodeUnit>` untouched unless the shared helpers force a mechanical update; the implementer may substitute an equivalent design and must record it here.
- **`infer_cpp_initializer_type` gains an optional bindings-backed receiver resolver callback** (`None` from `inverted.rs`, bindings closure from the extractor) rather than duplicating the method-return inference in extractor.rs — one implementation of "type `recv.m(...)`'s return". If a cleaner seam emerges during implementation, take it and record the substitution here.

## Outcomes & Retrospective

(To be written at completion. Expected shape: both directions of the benchmark case pass; declaration-to-usage for `format(const std::string&)` returns exactly the out-of-line definition and the `format(first)` call; `get_definition` on `parity::format(first)` resolves to only the string overload's declaration+definition. Known gaps that will remain by design: constructor overloads still conflate by arity; string-literal arguments never disambiguate; operator overloads stay on the old scan path; `usage_graph` remains overload-agnostic by node-key design; `CppQueryResolver` still scans only `overloads.first()` for an ambiguous selector.)
