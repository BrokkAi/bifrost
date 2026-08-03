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

## Implemented in follow-up checkpoints (all landed)

5. Family-aware uniqueness: `same_overload_family`/`single_overload_family` in
   `scala_graph/inverted.rs`. Units identical on every identity field except the signature
   key were ONE unit before the split, so "physically unique declaration" gates mean
   "unique modulo signature". Applied to `VisibleNameBindings::resolve`,
   `importable_members_by_normalized_fqn` (imports bind the whole family),
   `exact_method_value_declaration_for_owner`, `target_is_physically_unique`, the
   companion-apply unambiguity checks, and `exact_import_targets_for_candidate`.
6. Family-wide "unique callable" leniency: `TargetSpec.family_callable_alternatives` for
   candidate counting in the query sink; `visible_extensions` counts the family closure of
   receiver-matching extension methods (receiver-incompatible siblings included), so
   unapplied method values over overloaded extensions stay ambiguous. Extension-method
   dedup keys switched from fqn to declaration unit.
7. Generated-vs-explicit apply: the catalog no longer routes case-class synthetic
   constructor events onto explicit `apply` overload targets; generated-apply call sites
   belong to the class/constructor targets. (The `callable_alternatives_for` graft of
   constructor shapes onto apply units remains for scanner resolution and inference.)
8. Same-arity literal discrimination: `ScalaCallSiteShape.leading_literal_argument_types`
   (kind-derived; `None` under named arguments) plus
   `callable_alternative_contradicts_literal_arguments`, applied only in the query sink's
   match step. Numeric/numeric differences are inconclusive by construction
   (`scala_numeric_builtins`), so literal suffixes (`1L`) cannot cause false absences.
9. Stale merged-identity tests updated: union-intent queries pass the full family via
   `overload_definitions()` (mirroring `distinct_definitions` in the MCP layer, which keeps
   one symbol's overloads scanning together); `definitions.len()` assertions updated; the
   Timeout merge test became `..._separates_...` asserting per-overload attribution with the
   generated site owned by the class target; the bounded-receiver ambiguity test now expects
   both overload declarations as candidate evidence.

State: suite_analyzers scala 133/133, suite_usages scala 272/272, including the three
issue tests with their decoy negatives. Full workspace validation per the checkpoints.

## Risks / notes

- `CodeUnit::signature()` for Scala is now a compact key, not a display signature. Display
  surfaces already prefer `IAnalyzer::signatures` (side map); the C# precedent means
  downstream consumers tolerate key-style signatures. Any Scala-specific parser of
  `unit.signature()` text must read the side map instead.
- Storage/caches persist unit signatures already (C# relies on it); no schema work needed.
- Kotlin/Java cross-language JVM matching compares by name/fqn, not unit equality, so the
  identity change does not affect it.
