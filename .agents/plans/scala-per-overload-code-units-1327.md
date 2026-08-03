# Scala per-overload CodeUnits (#1327)

## Problem

Issue #1327: Scala find-usages on a specific `apply` overload returns the union of every
same-named overload's call sites. Diagnosis in this plan's implementation session found the
root cause is deeper than attribution: Scala function `CodeUnit`s are constructed without a
signature key (`CodeUnit::new_fq`), and `CodeUnit` identity (`PartialEq`/`Hash`) includes the
`signature` field. All same-named Scala overloads therefore collapse into ONE CodeUnit value
whose side maps (`ranges`, `signatures`) hold one entry per overload. "Per-overload
find-usages" was inexpressible: the query API takes `CodeUnit`s, and a single merged unit IS
the union. The three "exactly" tests in `tests/suite_usages/usages_scala_graph_test.rs`
selected units by declaration range, but `ranges(unit)` returns every overload's range for
the merged unit, so the selection was illusory.

## Decision (the issue's fork)

Take option (a), implemented at the root: give Scala function CodeUnits a compact
overload-discriminating signature key, exactly the C# model (`csharp_method_signature_key`
embeds a parameter-type key in the unit; C++ does the same). After the split, the existing
per-unit shape machinery (`callable_alternatives_for`, `record_callable`'s shape filter,
`TargetSpec::arity`, catalog arity gates) starts discriminating naturally, because each unit
now carries only its own signature.

Option (b) (rename tests, accept name-level attribution) is rejected: sibling languages
already discriminate, and the merged identity also blocks correct per-overload
`get_symbol_sources`/range queries.

False absences are worse than unions (issue's hazard list: default arguments, varargs,
currying, generated-vs-explicit apply). Every new discrimination point must fail open:
unknown/unresolvable argument or parameter shapes keep the hit.

## Implemented so far

1. `scala_method_signature_key` in `crates/bifrost-analysis/src/analyzer/scala/declarations.rs`:
   `extension (T)` prefix + `[N]` generic arity + `(TypeA, TypeB)(TypeC)` clause list from
   tree-sitter parameter nodes. Attached at both Scala `CodeUnitType::Function` construction
   sites (ordinary/secondary-constructor defs, synthetic primary constructor).
2. Scala display-signature parsers that treated `unit.signature()` as a rendered signature
   (previously always `None` for Scala, i.e. dead branches) now prefer the side-map
   signature: `visible_extension_methods`, `scala_function_return_type` in
   `usages/get_definition/scala.rs`.
3. `scala_exact_owner_typed_overload_resolution` now understands literal arguments:
   `ScalaExactArgument::{Constructed, Builtin}` with literal suffix awareness (`1L`, `1.0f`)
   and a conservative numeric relation (exact name match = Match, numeric/numeric otherwise =
   Unknown, never a wrong Mismatch). Needed because same-file overloads now surface as
   multiple candidate units to typed-overload resolution paths that previously saw one.
4. The three issue tests carry their decoy negative assertions;
   `..._nested_case_class_companion_apply_with_overloads_exactly` retargeted per the issue
   (positive = the explicit 1-arg site, negative = the generated 3-arg site).

State: `suite_analyzers` scala tests green (133/133). `suite_usages` scala tests 256/272;
16 failures under triage.

## Remaining work

1. Stale-contract tests (union asserted from a single unit, or `definitions.len() == 1`
   assertions such as `scala_usage_finder_handles_generic_only_calls_and_semantic_argument_arity`):
   update to pass the full `get_definitions(fqn)` overload set where union is the intent —
   this mirrors the MCP layer, where `distinct_definitions` deliberately keeps one symbol's
   overloads scanning together (`searchtools/selectors.rs`), so scan_usages union-by-name is
   unchanged.
2. Missing-hit failures (`assert_hit_contains` at usages_scala_graph_test.rs:9379): paths
   that gate on physical uniqueness (`PhysicalCallableTargets::Unique`,
   `target_is_physically_unique`, companion-apply unambiguity checks) now see several units
   per fq_name. Each must treat a same-file overload family as a shape-filterable set, not an
   ambiguity. Fail open when shapes cannot discriminate.
3. Same-arity overload discrimination (`scala_graph_resolves_explicit_apply_member_exactly`:
   `apply(String)` vs `apply(Int)`, both arity 1): extend `ScalaCallArgumentList` (or the
   shape builder in `scala_graph/syntax.rs`) with optional per-argument literal builtin
   types, and let `callable_alternative_matches` reject an alternative only when a known
   literal type contradicts a declared `Builtin`/`Declaration` parameter type at an
   unambiguous position (no named arguments, no varargs, exact positional mapping).
4. Companion-apply catalog routes (`accepts_companion_apply_syntax`, synthetic constructor
   event registration in `scala_graph/shared.rs`): ensure events for the case-class
   generated apply do not attribute to an explicit apply overload target whose shape cannot
   accept them, and vice versa.
5. Rerun full validation: featureless workspace tests, fmt, `cargo clippy --workspace
   --all-targets --all-features -- -D warnings` (expanded form; nested worktree breaks the
   alias).

## Risks / notes

- `CodeUnit::signature()` for Scala is now a compact key, not a display signature. Display
  surfaces already prefer `IAnalyzer::signatures` (side map); the C# precedent means
  downstream consumers tolerate key-style signatures. Any Scala-specific parser of
  `unit.signature()` text must read the side map instead.
- Storage/caches persist unit signatures already (C# relies on it); no schema work needed.
- Kotlin/Java cross-language JVM matching compares by name/fqn, not unit equality, so the
  identity change does not affect it.
