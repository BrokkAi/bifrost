# FIRD scala wave, bucket A: `ambiguous_scala_typed_overload`

Diagnosis of the 783 tier-1 census sites in
`/mnt/optane/tmp/bifrost-fird/scala-diagnosis/A-typed-overload.json`.
All 783 have `forward_status = no_definition`, zero targets, and the diagnostic
`` `X` overloads cannot be selected from exact argument type identity ``.

Runner: `/mnt/optane/bifrost-fird/target/release/bifrost_reference_differential`,
bifrost head `90d65613`, clean. Fixtures and a driver script are in
`/mnt/optane/tmp/bifrost-fird/scala-fixtures/A/`.

## Headline

The diagnostic name is wrong for about 78 percent of the bucket. The dominant
mechanism has nothing to do with overloads, argument types, or the number of
candidates. One unresolvable or ambiguous **supertype** anywhere in the enclosing
class's ancestor closure makes every bare one-argument-list call in that class
answer `no_definition` with zero targets, even when exactly one candidate exists
and even when the candidate is a method declared five lines above the call.

## The mechanism

`crates/bifrost-analysis/src/analyzer/usages/get_definition/scala.rs`

`resolve_scala_call`, identifier branch, line 6644, calls
`scala_exact_owner_typed_overload_resolution` before the ordinary
enclosing-member fallback chain. Inside that function, lines 7797 to 7823:

```rust
    let mut levels = Vec::new();
    let mut level = vec![owner.clone()];
    while !level.is_empty() {
        for current in level {
            candidates.extend(scala_filter_callable_units(...));      // 7806
            match ctx.direct_ancestors_for_owner(&current) {
                ScalaDirectAncestorResolution::Resolved(ancestors) => next.extend(ancestors),
                ScalaDirectAncestorResolution::Ambiguous => {
                    return ScalaTypedOverloadResolution::Ambiguous;   // 7819
                }
            }
        }
        ...
    }
    let callable_count = levels.iter().map(Vec::len).sum::<usize>();
    if callable_count < 2 {
        return ScalaTypedOverloadResolution::NotNeeded;               // 7827
    }
```

Line 7819 returns before line 7827 is ever reached, and it discards the
candidates already collected at line 7806. The caller turns that into
`no_definition("ambiguous_scala_typed_overload", ...)` at scala.rs:6664-6671,
which also pre-empts the entire downstream fallback chain (exact-owner member
resolution at 6673, the lexical-owner walk at 6699 onward) that answers these
sites correctly when the leak does not fire.

`ScalaDirectAncestorResolution::Ambiguous` is produced by
`scala_forward_direct_ancestor_resolution` (scala.rs:9150-9209) in three ways:

- scala.rs:9199 `ScalaNameResolution::Unresolved => Ambiguous` -- the supertype
  is not indexed in the workspace. This is the normal state for `extends Actor`,
  `extends JsonDeserializer[...]`, `extends Serializable`, `extends AnyVal`.
- scala.rs:9165 and 9195 `ScalaNameResolution::Ambiguous => Ambiguous` -- the
  supertype name has more than one physical declaration in the workspace. This is
  the normal state for cross-build source sets (zio `core/js`, `core/jvm-native`,
  `core/shared`) and for `Fallback`/`Combine`-style repeated names.
- scala.rs:9189 -- more than one same-source nested candidate.

The correct precedence discipline already exists 500 lines later in the same
file. `scala_exact_owner_member_candidate_units` (scala.rs:8351-8365) answers
from the owner's **direct** members first and only consults the ancestor closure
when the owner has none; its inner loop records `next_is_ambiguous` as a deferred
flag (scala.rs:8392) instead of bailing. `scala_exact_owner_typed_overload_resolution`
does not follow that discipline.

The second, genuine trigger is `scala_exact_constructed_call_arguments`
(scala.rs:7808-7811):

```rust
    let Some(arguments) = scala_exact_constructed_call_arguments(ctx, resolver, call) else {
        return ScalaTypedOverloadResolution::Ambiguous;
    };
```

`scala_exact_constructed_argument` (scala.rs:7876-7906) accepts only a literal or
a `new T(...)` expression. Every other argument shape -- a parameter, a local
val, a method result, a lambda, an interpolated string -- yields `None`, so the
whole list yields `None`, so any call to a genuinely overloaded method with a
non-literal argument answers `no_definition` with zero targets. This is the case
the diagnostic message actually describes, but the answer shape is still wrong:
`candidates_outcome` (get_definition/mod.rs:1446-1467) already returns
`DefinitionLookupStatus::Ambiguous` **with** the candidate list for more than one
candidate, and that is what this path should return.

## Perturbation matrix (all reproducible via `scala-fixtures/A/RUN.sh`)

| # | fixture | shape | result |
|---|---|---|---|
| -- | external-ancestor-leak-probe | `Left("x")` in class `extends UnknownExternalTrait` | `ambiguous_scala_typed_overload` |
| -- | external-ancestor-leak-probe | `Left("x")` in class `extends LocalTrait` | `no_indexed_definition` |
| -- | external-ancestor-leak-probe | `Left("x")` in class with no `extends` | `no_indexed_definition` |
| M1 | perturbation-core | **one** same-class `def foo()`, unindexed supertype | `ambiguous_scala_typed_overload` |
| M2 | perturbation-core | one same-class `def foo()`, local supertype | **resolved**, 1 target |
| M3 | perturbation-core | one same-class `def foo()`, no supertype | **resolved**, 1 target |
| M4 | perturbation-core | two overloads, unindexed supertype, literal argument | `ambiguous_scala_typed_overload` |
| M5 | perturbation-core | two overloads, no supertype, literal argument | **resolved**, 1 target |
| M6 | perturbation-core | two overloads, no supertype, parameter argument | `ambiguous_scala_typed_overload` |
| M7 | perturbation-core | one overload, no supertype, parameter argument | **resolved**, 1 target |
| M8 | perturbation-core | `array(i) = null` update sugar, no supertype | **resolved**, 1 target |
| M9 | perturbation-core | `Left("x")`, `extends AnyVal` | `ambiguous_scala_typed_overload` |
| N1 | perturbation-call-shape | curried `cur(1)(2)`, unindexed supertype | **resolved** |
| N2 | perturbation-call-shape | no argument list at all, unindexed supertype | **resolved** |
| N3 | perturbation-call-shape | `this.foo()`, unindexed supertype | **resolved** |
| N4 | perturbation-call-shape | `foo()` empty list, unindexed supertype | `ambiguous_scala_typed_overload` |
| N5 | perturbation-call-shape | `foo()`, unindexed supertype **two levels up** | `ambiguous_scala_typed_overload` |
| N6 | perturbation-call-shape | `Comp(1)` apply sugar on a local object, local supertype | **resolved** |
| N7 | perturbation-call-shape | `Comp(1)` apply sugar on a local object, unindexed supertype | `ambiguous_scala_typed_overload` |
| N8 | perturbation-call-shape | `Comp.apply(1)` explicit, unindexed supertype | **resolved** |
| N9 | perturbation-call-shape | `new Made(1)` constructor, unindexed supertype | `no_indexed_definition` (different path) |
| P1 | perturbation-ancestor-kind | `foo()`, supertype declared **twice** in the repo | `ambiguous_scala_typed_overload` |
| P2 | perturbation-ancestor-kind | `array(i) = null`, unindexed supertype | `ambiguous_scala_typed_overload` |
| P3 | perturbation-ancestor-kind | `array(i) = null`, duplicated supertype | `ambiguous_scala_typed_overload` |

Necessary and sufficient conditions for the leak, read off the matrix:

1. the reference is a **bare identifier** call -- N3 and N8 show any receiver
   avoids the path entirely;
2. the call has **exactly one ordinary argument list** -- N1 (curried) and N2
   (none) escape via the `NotNeeded` guard at scala.rs:7791-7796; an empty list
   still counts (N4);
3. the innermost enclosing class's transitive ancestor closure contains an
   unindexed (M1, N4, N5) or multiply-declared (P1) supertype.

Candidate count is irrelevant: M1 fires with exactly one candidate, N7 with zero.
The declaration kind is irrelevant: M8 versus P2 shows update sugar is only
affected through the same leak.

## Sub-clusters

Estimated by `A-subcluster-classifier.py` (saved next to this report; output
`A-subclusters.json`). It finds each site's innermost enclosing class-like
declaration, takes the transitive closure of its `extends`/`with` names against a
repo-wide declaration index, and counts same-name `def` declarations in the owner
and in-repo ancestor bodies. It is a regex heuristic, so the split between A1/A2
and A4 is approximate; the A1+A2 versus A3 split is well separated because A3 is
dominated by a small number of heavily overloaded files.

| family | mechanism | est. sites | share |
|---|---|---|---|
| **A1** | ancestor leak, supertype **not indexed** (external library, JDK, cross-module) | 509 | 65% |
| **A2** | ancestor leak, supertype **multiply declared** in the workspace | 102 | 13% |
| **A3** | genuine >= 2 candidates, clean ancestors, argument not a literal or `new T` | 123 | 16% |
| **A4** | residual: clean-ancestor verdict with 0-1 candidates, plus 13 sites where the heuristic found no enclosing class | 49 | 6% |

A4 is almost certainly A1/A2 that the regex missed. Two verified examples:
`midonet HaproxyHealthMonitor.scala:209 writeConf` sits in
`class HaproxyHealthMonitor(...) extends Actor with ActorLogWithoutPath with Stash`
(Akka, unindexed) with exactly one candidate at line 344; and the `apalache
SymbStateRewriterImpl.scala` `key` sites are the same shape. Treat A1+A2+A4 as
one defect family of roughly 660 sites.

Per repository (A1+A2 / A3 / A4):

| repo | A1+A2 ancestor leak | A3 genuine overload | A4 residual |
|---|---|---|---|
| zio-http | 144 | 4 | 0 |
| airframe | 113 | 9 | 1 |
| chisel | 27 | 31 | 12 |
| zio | 42 | 2 | 6 |
| deequ | 23 | 11 | 2 |
| linkerd | 28 | 7 | 0 |
| midonet | 25 | 4 | 4 |
| stream-reactor | 29 | 2 | 2 |
| fs2 | 29 | 2 | 0 |
| http4s | 22 | 5 | 1 |
| apalache | 22 | 5 | 1 |
| twitter/util | 20 | 5 | 2 |
| metals | 9 | 8 | 8 |
| sangria | 8 | 15 | 2 |
| scalachess | 10 | 9 | 6 |
| grid | 22 | 1 | 1 |
| TheHive | 21 | 2 | 1 |
| SwayDB | 15 | 0 | 0 |
| scala-steward | 2 | 1 | 0 |
| **total** | **611** | **123** | **49** |

Witnesses per family:

- **A1**: `awslabs__deequ AnalysisResultSerde.scala:521 getOptionalWhereParam` --
  a lone `private[this] def` at line 715 inside
  `object AnalyzerDeserializer extends JsonDeserializer[...]` (Gson, unindexed).
  `zio__zio BoundedHubPow2.scala:151 array(index) = null` -- the brief's witness;
  the class is `BoundedHubPow2[A] extends Hub[A]`, and `zio/internal/Hub.scala:28`
  is `abstract class Hub[A] extends Serializable`, so the closure hits the JDK.
- **A2**: `zio__zio` cross-build duplicates; `typelevel__fs2` (23 of 31 sites).
- **A3**: `chipsalliance__chisel Serializer.scala` -- `private[chisel3] object Serializer`
  with no `extends` and roughly 20 `def serialize` overloads, called with
  identifiers; `awslabs__deequ Constraint.scala fromAnalyzer`;
  `sangria Context.scala arg`; `http4s Message.scala copy`.

Overlay, not a separate family: 131 of the 783 sites are stdlib companion
apply-sugar (`Left` 98, `Right` 29, `Some` 4). **All 131 fall inside A1/A2.**

## Falsified premises

1. **"`Left`/`Right` fail because the target is an unindexed external type."**
   False as a causal claim. The external target produces `no_indexed_definition`,
   not this diagnostic -- see the external-ancestor-leak-probe rows: the same
   `Left("x")` call resolves to `no_indexed_definition` in a class with a local
   supertype or no supertype, and to `ambiguous_scala_typed_overload` only when
   the *enclosing* class has an unindexed supertype. The external-ness that
   matters is the enclosing class's parent, not the callee. N7 makes this
   explicit: apply-sugar on a **local** object breaks the same way.

2. **"The selector collects apply/update overloads and then fails on argument
   type identity."** False for A1/A2, which is most of the bucket. M1 and N4 fire
   with exactly one candidate and N7 with zero; the function never reaches the
   argument stage. The premise is true only for A3 (about 123 sites), where M5
   versus M6 isolates it cleanly.

3. **"`array(index) = null` is an update-sugar defect."** False. M8 shows update
   sugar resolves correctly on its own. P2 and P3 show it breaks only through the
   ancestor leak, exactly like an ordinary call.

4. **"This might be new breakage from the tree-sitter-scala 0.26.2 swap."**
   False. Comparing `scala-census-09071ef6.jsonl` (pre-swap) with
   `scala-census-90d65613.jsonl` (post-swap) by
   `(repo, path, start_byte)`: 1757 `ambiguous_scala_typed_overload` sites are
   shared, 33 dropped, 8 added. Long-standing behaviour.

5. **Census-side finding, not in the brief:** the tier-1 grading of the 127
   `Left`/`Right` sites is an artifact. `bare_call_reaches_same_file_declaration`
   (`src/reference_differential/mod.rs:1406-1446`) returns unconditional `true`
   for Scala, so any bare call whose *name* matches any declaration anywhere in
   the file is graded tier 1. In `zio-http HttpCodec.scala` the matching
   declarations are `type Left = A1` (line 2392) and `type Left = A` (line 2403),
   abstract type members of `Combine` and `Fallback` that have nothing to do with
   `scala.Left`. Fixing the ancestor leak will move these sites from
   `ambiguous_scala_typed_overload` to `no_indexed_definition`; they will remain
   graded tier-1 missing unless either (a) the Scala arm of the bindability
   policy gains an owner/reachability test in the spirit of #1783, or (b) bare
   auto-imported stdlib companions get a boundary answer. Note that
   `scala_compiler_intrinsic_type_reference` (scala.rs:6479-6491) already provides
   the boundary machinery, but its name list covers only the lattice types
   `Any | AnyRef | Nothing | Null | Singleton | Matchable` -- not `Left`, `Right`,
   `Some`, `None`, `List`, `Option`.

## Blast radius beyond this bucket

`ambiguous_scala_typed_overload` occurs 1765 times across the 194,190 census
sites, so the tier-1 bucket is 44 percent of the affected sites. The correct
counterpart `no_applicable_scala_typed_overload` occurs **zero** times in the
whole census: the typed-overload selector never completes on real Scala code, it
only short-circuits.

`ScalaDirectAncestorResolution::Ambiguous` also gates
`scala_exact_owner_member_candidate_units` (scala.rs:8362) and
`scala_typed_candidate_is_subtype` (scala.rs:8050). The 8362 site respects
direct-member precedence and is defensible; it will still fail closed for a
genuinely inherited member, which is a plausible contributor to the census's
1728 `ambiguous_scala_enclosing_member` sites but was not investigated here.

## Recommendations

**A1 + A2 + A4 (about 660 sites): straightforward generalized fix.** Not a
narrow special case -- the change is to make one function obey the precedence
rule the rest of the file already obeys.

Contract to implement in `scala_exact_owner_typed_overload_resolution`
(scala.rs:7783):

- an unresolvable ancestor makes the hierarchy **incomplete**, not ambiguous;
  record it as a flag and keep walking the resolvable levels, the way
  scala.rs:8386-8392 already does with `next_is_ambiguous`;
- compute `callable_count` over the levels actually resolved, so the existing
  `callable_count < 2 => NotNeeded` guard at scala.rs:7826 does its job and the
  ordinary fallback chain answers the site (this is exactly what makes M3, M7 and
  N6 resolve today);
- when the walk was incomplete and produced no candidate, the honest answer is
  the existing `boundary_unchecked` shape ("a supertype of `Owner` is not indexed
  in this workspace"), not `no_definition`; the real target may live in the
  unindexed parent;
- rename the diagnostic. `ambiguous_scala_typed_overload` should be emitted only
  where overload selection actually ran. A distinct kind such as
  `scala_unindexed_supertype` for the incomplete-hierarchy case is what a caller
  needs.

Suggested regression names, mirroring the fixtures: `M1` (one candidate,
unindexed supertype, must resolve), `N5` (transitive), `P1` (duplicated
supertype), `N7` (apply sugar on a local object), `N1`/`N2`/`N3` (shapes that
must stay on the fast path).

**A3 (about 123 sites): straightforward answer-shape fix, plus a scoped
follow-up.** The immediate change is #1812-shaped: when the selector genuinely
cannot discriminate, return `candidates_outcome(candidates)` -- the collected
overloads, status `Ambiguous` -- instead of `no_definition` with zero targets.
`candidates_outcome` (get_definition/mod.rs:1446) already produces that shape and
already encodes the #1811 rule that zero candidates is never an ambiguity. This
turns 123 silent misses into usable multi-target answers with no new typing work.

Widening `scala_exact_constructed_argument` beyond literals and `new T(...)` --
so that a parameter with a declared type, or a val with an inferred local
constructor type, can discriminate -- is real typing work and should be a
separate, scoped item. It is not required to remove the Missing answers.

**Escalation:** none of this bucket needs it. Both fixes are local to
`get_definition/scala.rs`, both have an in-file precedent for the correct shape,
and both are covered by fixtures that already discriminate the intended behaviour
from the current behaviour.
