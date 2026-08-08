# FIRD scala wave -- bucket B diagnosis

Bucket: 229 census sites where forward resolution returns targets, but the site is
absent from the complete inverse `scan_usages` result.

Input: `/mnt/optane/tmp/bifrost-fird/scala-diagnosis/B-inverse-miss.json`
Binary: `/mnt/optane/bifrost-fird/target/release/bifrost_reference_differential`
Bifrost head: `90d656137b701f96bf97a6a8f9112e83ea8a6c84`
Fixtures: `/mnt/optane/tmp/bifrost-fird/scala-fixtures/B/f1..f11`
Annotated site list: `/mnt/optane/tmp/bifrost-fird/scala-diagnosis/B-annot.json`

## 0. Headline

Two families hold 116 of the 229 sites (51 %).

1. **B -- enclosing-def-name shadow (70 sites).** A bare `name(...)` reference inside
   `def name(...)` never resolves in the inverse scan. The Scala scan declares the
   method's own name as a local shadow inside the method's own scope, and the bare-call
   arm returns early on a shadowed name.
2. **A -- Scala site to Java declaration (39 sites).** The Scala-side scanner for Java
   targets covers only type references and *static* member access. Constructors,
   instance members, annotations, paren-less static calls, and pattern positions are
   never scanned.

One more family is large and is **not** an inverse defect:

3. **C -- wildcard companion import plus for-comprehension binder (46 sites, all
   `s3_website`).** Forward invents a reference to a case-class field. The inverse is
   correct to omit it.

About 60 of the 229 sites (families C, G, part of H, part of I, part of L) are
**forward false positives**. The bucket name "inverse miss" is wrong for them.

## 1. Falsified premises from the brief

| Premise | Verdict | Evidence |
| --- | --- | --- |
| "#1638 fixed recursion drops ... including Scala push-time classification" | **Falsified for Scala bare calls.** The `recursive` / `SelfReceiver` path in `crates/bifrost-jvm/src/scala/graph/query.rs:692-714` is unreachable for a bare self or sibling call, because the reference is discarded earlier in `inverted.rs:8370-8376`. Only a *qualified* self call (`Obj.m(...)`, `this.m(...)`) reaches it. | fixture `f5-overload`, `f6-selfname`, `f11-shadow` |
| "apply sugar sites -- inverse may not attribute `Foo(x)` to `Foo.apply`" | **Falsified.** `Nested.Queue(1, 2)` resolves to `app.Nested$.Queue$.apply` and is `consistent`. `Conf(a, b)` resolves to the case-class constructor and is `consistent`. | `f10-shapes2` line 15, `f4-scalashapes` lines 32-37 |
| "companion object vs class target identity (`Foo` object vs `Foo` class)" | **Not an inverse defect in this bucket.** The companion/class collapse does appear, but on the **forward** side: `scala_normalized_fq_name` (`crates/bifrost-jvm/src/scala/graph/resolver.rs:700-702`) strips `$`, so `import Conf._` exposes the *class* fields of `Conf`. That produces family C. | `f8-wildcard`, `f9-wildcardmatrix` |
| "trait mix-in member attribution" | **Mostly falsified.** A bare reference to an inherited trait member is `consistent` in a clean fixture. Only 4 sites remain (midonet `VppController.log`), and those have three mixed-in traits plus an abstract declaration. | `f10-shapes2` lines 5, 10 |
| "implicit/extension call sites" | **Not a measurable family.** At most 2 sites (scalachess `Bitboard` opaque-type extensions). | family K |
| "9691ab7e -- answer Scala bare-name knownness from indexes" | **Not implicated.** That change grades forward-*unresolvable* census sites into tiers. Every bucket-B record has `"tier": null` and `forward_status: resolved`. | `B-inverse-miss.json` |
| "#1779 `overloads.first()` collapse checked for Scala -- already correct" | **Confirmed.** `ScalaUsageGraphStrategy::find_graph_usages` uses `overloads[0]` only for a language check (`crates/bifrost-analysis/src/analyzer/usages/scala_graph.rs:178-185`); the resolver receives the full slice. | code read |
| "229 sites where FORWARD resolves but the site is absent from the INVERSE" | **True by construction, misleading in substance.** ~26 % are forward over-resolution. | families C, G, H, I, L |

Also note: the record field `text` is the *resolver's* reference text, not the census
byte range. `start_byte`/`end_byte` always cover one identifier leaf
(`src/reference_differential/mod.rs:846-853`). I checked for a range-shape artifact
in `covering_hit` (`src/reference_differential/mod.rs:1302-1311`); it is not a source
of misses here, because the census range is never wider than an inverse hit.

## 2. Family table

| Family | Sites | Side at fault | Repos |
| --- | ---: | --- | --- |
| B enclosing-def-name shadow | 70 | inverse | scalachess 11, TheHive 10, zio 9, midonet 6, metals 5, util 5, +9 more |
| C wildcard companion import + for-binder | 46 | **forward** | s3_website 46 |
| A1 Java constructor | 12 | inverse | midonet 12 |
| A3 Java instance member | 11 | inverse | midonet 11 |
| A2 Java nested-type qualifier / pattern | 10 | inverse | midonet 7, metals 2, airframe 1 |
| A4 Java annotation | 5 | inverse | midonet 4, util 1 |
| A5 Java paren-less static call | 1 | inverse | midonet 1 |
| J long qualified path | 16 | inverse (mixed) | chisel 6, sangria 4, airframe 2, +4 |
| L residual bare reference | 14 | mixed | midonet 5, airframe 4, sangria 2, apalache 2, scalachess 1 |
| K qualified member (receiver shape) | 15 | inverse (mixed) | zio 2, metals 2, chisel 2, TheHive 2, +7 |
| E extractor pattern | 7 | inverse | TheHive 5, chisel 1, util 1 |
| I named argument label | 6 | mixed | SwayDB 5, midonet 1 |
| D `new C(...) with T` | 7 | inverse | scalachess 5, http4s 1, sangria 1 |
| H type-param decl / `private[X]` | 4 | forward (2) + policy (2) | TheHive 2, airframe 1, util 1 |
| F import selector with duplicate declarations | 3 | inverse | chisel 2, grid 1 |
| G `super.member` | 2 | **forward** | util 2 |
| **Total** | **229** | | |

## 3. Family B -- enclosing-def-name shadow (70 sites)

### Reproduction

Real site, rerun at head 90d65613:

```
run-repo --root /mnt/T9/repo-clones/http4s__http4s --language scala \
  --probe-seed census --tiers 1 --cache-mode ephemeral \
  --path core/shared/src/main/scala/org/http4s/Status.scala --start-byte 5731 --end-byte 5737
-> 155 'lookup' resolved missing ['org.http4s.Status$.Registry$.lookup']
```

Source: `def lookup(code: Int, reason: String) = { val lookupResult = lookup(code) ... }`.

### Single-factor matrix (`f5-overload`, `f6-selfname`, `f11-shadow`)

| Fixture line | Shape | Result |
| --- | --- | --- |
| `def build(a,b) = build(a) + b` | bare call, enclosing def has the same name | **missing** |
| `def outside(a,b) = build(a) + b` | same call, different enclosing name | editor_only (found) |
| `def buildQ(a,b) = Maker.build(a) + b` | qualified call, enclosing name matches | editor_only (found) |
| `def render(x) = render(x, 0)` (trait) | inherited sibling overload | **missing** |
| `def zeta(x,y) = zeta(x) + y` with `import app.Src.zeta` | target is an imported free function in another owner | **missing** |
| `def zetaTwo(x) = zeta(x)` with the same import | different enclosing name | consistent |

The only factor that flips the result is the **name of the enclosing `def`**. The
target's owner, overload family, and file do not matter.

### Mechanism

1. `crates/bifrost-jvm/src/scala/graph/inverted.rs:7613-7629` -- `walk_enter` calls
   `bindings.enter_scope()` for a `function_definition` **before** `seed_declaration`.
2. `crates/bifrost-jvm/src/scala/graph/inverted.rs:10885-10893` -- `seed_declaration`
   then runs `bindings.declare_shadow(<own name>)`. The method's own name therefore
   becomes an opaque local binding **inside its own body**.
3. `crates/bifrost-jvm/src/scala/graph/inverted.rs:8370-8376` -- the bare-call arm:

   ```rust
   if !lexical_callable_bound
       && (!bindings.resolve_symbol(name).is_unknown()
           || bindings.is_shadowed(name))
   {
       return;
   }
   ```

   The reference is discarded before any owner, import, or overload lookup.

4. Consequence: `query.rs:692-714` (the #1638 `SelfReceiver` recursion record) can never
   fire for a bare call. FIRD hides the pure-recursion case, because
   `src/reference_differential/mod.rs:907-912` removes a site whose enclosing code unit
   equals its target. The *sibling overload* case is not hidden, so it surfaces here.

`seed_parent_scope_declaration` (`inverted.rs:7627-7652`) already handles the correct
case: a **nested** local `def` is declared in the *parent* scope. The unconditional
self-shadow at `:10885` is the defect.

### Fix

Straightforward and generalized. Remove the self-shadow from `seed_declaration`'s
`function_definition` arm, and let the bare name fall through to the existing
owner-member and import resolution. `record_lexically_visible_call` and
`callee_owned_by_enclosing_template` (`inverted.rs:7031-7046`) already classify a
same-owner bare call as `SelfReceiver`, which is what #1638 intended.

Risk: a bare use of a *method value* of the same name inside the body may then resolve
where it previously stayed opaque. That is the wanted behavior. Guard the change with
the `f5`/`f6`/`f11` matrix, plus a pure-recursion case asserted as `SelfReceiver`.

Do not replace the shadow with a name-equality skip. The correct rule is Scala's:
the bare name binds to the enclosing template's member family, and the call shape then
selects the overload.

## 4. Family A -- Scala site, Java declaration (39 sites)

### Reproduction

Real sites, rerun at head:

```
midonet MeterRegistry.scala:65  'FlowStats'   -> missing ['org.midonet.odp.flows.FlowStats.FlowStats']
midonet VppOvs.scala:204        'fmask.clear' -> missing ['org.midonet.odp.FlowMask.clear']
```

### Perturbation matrix (`f3-javamatrix`, one Java class, one Scala user)

| Scala source | Forward target | Result |
| --- | --- | --- |
| `new Stats()` | `lib.Stats.Stats` | **missing** |
| `Stats.origin()` | `lib.Stats.origin` | consistent |
| `Stats.origin` (no parens) | `lib.Stats.origin` | **missing** |
| `Stats.origin(3)` | `lib.Stats.origin` | consistent |
| `lib.Stats.origin()` | `lib.Stats.origin` | consistent |
| `Stats.LIMIT` (static field) | `lib.Stats.LIMIT` | consistent |
| `delta.bytes` (instance field) | `lib.Stats.bytes` | **missing** |
| `delta.inst()` (instance method) | `lib.Stats.inst` | **missing** |
| `def e1(t: Stats.Type)` -- qualifier | `lib.Stats` | **missing** |
| `def e1(t: Stats.Type)` -- leaf | `lib.Stats.Type` | consistent |
| `case Stats.Type.NEWADDR =>` | `lib.Stats` and `lib.Stats.Type` | **missing** (both) |
| `Stats.Type.NEWADDR` in an expression | both | consistent |
| `@JMark` (Java annotation) | `app.JMark` | **missing** (`f1-javatarget`) |

### Mechanism -- `crates/bifrost-jvm/src/java/graph/jvm_scala.rs`

The whole cross-language surface is this one file. Its dispatch is at `:178-185`:

```rust
if is_identifier_node(node) {
    match ctx.spec.kind {
        TargetKind::Type => maybe_record_java_type_hit(node, ctx),
        TargetKind::Method => maybe_record_java_static_method_hit(node, ctx),
        TargetKind::Field => maybe_record_java_static_field_hit(node, ctx),
        TargetKind::Constructor => {}
    }
}
```

- **A1 constructor (12).** `:30` returns immediately for `TargetKind::Constructor`, and
  `:183` is an empty arm. No Scala file is ever scanned for a Java constructor.
- **A3 instance member (11).** `scala_static_receiver_matches_target_owner` (`:337-357`)
  accepts a receiver only when its text equals the owner FQ name or a *visible type
  name*. An instance receiver (`fmask`, `delta`, `reply`) never matches. The function
  names say "static"; there is no instance path at all.
- **A5 paren-less static call (1).** `maybe_record_java_static_method_hit` requires
  `call_shape.lists.len() == 1` (`:309-311`). Scala `MAC.random` has no argument list.
- **A2 nested-type qualifier and pattern position (10).**
  `is_explicit_static_receiver_simple_name` (`:280-290`) requires
  `parent.kind() == "field_expression"`. In a type position the parent is a
  `stable_type_identifier`; in a `case` pattern it is a pattern node. Both fail.
- **A4 annotation (5).** `is_type_like_reference` does not accept the Scala annotation
  node, so `maybe_record_java_type_hit` (`:200-238`) rejects `@JMark`.

Note the Kotlin analogue exists (`crates/bifrost-jvm/src/kotlin/...`) but there is no
`scan_kotlin_files_for_java_target` equivalent audit here; only Scala is in scope.

### Fix

Escalate. This is a rewrite of `jvm_scala.rs`, not a patch:

- Reuse the Scala scan (`scala/graph/inverted.rs` `walk` + `record_reference`) with a
  sink that matches Java `CodeUnit` targets, instead of the parallel hand-written
  scanner. The Scala scan already resolves instance receivers, paren-less calls,
  patterns, annotations, and constructors correctly for Scala targets.
- If a rewrite is too large for one change, the minimum viable steps in priority order:
  1. constructor support (12 sites, one early return plus one empty match arm),
  2. instance-receiver support (11 sites), which needs the Scala receiver-type
     inference the Java-side scanner does not have,
  3. drop the `lists.len() == 1` gate for a zero-list Scala call (1 site),
  4. accept `stable_type_identifier` and pattern parents in the qualifier check (10),
  5. accept the Scala annotation position (5).

Steps 2 and 4 are the reason to escalate: they duplicate logic that already exists on
the Scala side.

## 5. Family C -- wildcard companion import plus for-comprehension binder (46 sites)

### Reproduction

Real sites (both reproduce at head):

```
s3_website Site.scala:36 's3_id' resolved missing ['s3.website.model.Config.s3_id']   # the for-binder itself
s3_website Site.scala:69 's3_id' resolved missing ['s3.website.model.Config.s3_id']   # a use of that local
```

`Site.scala:9` has `import s3.website.model.Config._`. `Config` is a case class with a
companion object. `s3_id` is a constructor parameter of the **class**.

### Minimal fixture (`f8-wildcard`)

```scala
// Conf.scala
case class Conf(alpha: String, beta: Int)
object Conf { def parse(s: String): Conf = Conf(s, 0) }

// Load.scala
import app.Conf._
object Load {
  def viaFor: Either[String, Conf] =
    for { alpha <- loadStr("a"); beta <- loadInt("b") } yield Conf(alpha, beta)
}
```

`alpha` and `beta` at the generator lines resolve to `app.Conf.alpha` / `app.Conf.beta`
and are reported `missing`.

### Control matrix (`f7-forcomp`, `f9-wildcardmatrix`)

| Variant | Result |
| --- | --- |
| for-comprehension binder, **no** wildcard import | not resolved (correct) |
| for-comprehension binder, **with** `import Conf._` | resolves to the case-class field (**wrong**) |
| `val alpha = x`, with `import Conf._` | not resolved (correct -- `val` is a shadow) |
| `import Obj._` then bare `gamma` where `Obj` is an object with `val gamma` | consistent (correct) |

### Mechanism

Two forward defects compose.

1. `scala_normalized_fq_name` (`crates/bifrost-jvm/src/scala/graph/resolver.rs:700-702`)
   strips `$`, so the companion object `app.Conf$` and the class `app.Conf` share one
   normalized key. A wildcard import of the object therefore exposes the *class's*
   constructor-parameter fields as bare names.
2. A `for` generator binder (`x <- ...`) is not seeded as a local binding.
   `seed_declaration` (`inverted.rs:10874-10906`) handles `val_definition` and
   `var_definition`, not the `for` enumerator. Nothing shadows the imported name.

The inverse is correct in both cases. There is no inverse work here.

### Fix

Straightforward, two independent changes:

- Seed `for` generator binders as local shadows, next to the `val_definition` case in
  `seed_declaration`. This alone removes all 46 sites.
- Separately, make wildcard-import member lookup respect the companion boundary: a
  wildcard import of `X` where `X` is an object must expose only `X$` members. This is
  the general correction and should be scoped with care, because `scala_normalized_fq_name`
  is used in many places.

Do the binder fix first; it is small, local, and testable.

## 6. Smaller families

### D -- `new C(...) with T` (7 sites)

`new Glyph(1)` resolves forward to the constructor `app.Glyph.Glyph` and is
`consistent`. `new Glyph(2) with Assess` resolves forward to the **class** `app.Glyph`
and is `missing`. I proved the inverse is at fault by putting a plain type reference in
the *same* target group: `def probe(g: Glyph)` is `consistent` for `app.Glyph` while
the mixin `new` position in the same group is `missing` (`f4-scalashapes` lines 26/29).

So the Scala scan emits no `Type`-role hit for the first parent of an anonymous mixin
template. Fix: in `record_reference`'s `type_identifier` arm, treat the first parent of
a `new C(...) with T` template like the `is_constructor_like_reference` case, and record
both the constructor and the class. Straightforward.

Two more sites are the same shape with `with` on the **next** line, so my classifier put
them in family L. Verified by reading the source:

- `http4s MultipartReceiver.scala:140` -- `new ReceiverAt(name, receiver)\n  with MultipartReceiver[...]`
- `sangria Schema.scala:564` -- `new UnionType[Ctx](...)\n  with MappedAbstractType[T] { ... }`

True family D size is therefore **7**, and family L is **14**.

### E -- extractor pattern (7 sites)

`case Extract(a, b)` where the target is `Extract$.unapply`, or a case class reached
through a renamed import (`case MispTag(...)` -> `org.thp.misp.dto.Tag.Tag`).
Reproduced in `f4-scalashapes` line 29 (`missing`). `record_reference` has an extractor
branch (`inverted.rs:8085-8129`) that records `CompanionExtractor` callables, so the
gap is in reaching it, not in the concept. Needs a focused trace; **medium** effort.

### F -- import selector with duplicate declarations (3 sites)

`import chisel3.probe.{Probe, RWProbe}` (chisel) and
`import lib.elasticsearch.{AggregateSearchParams, ElasticSearch}` (grid). In both
repositories the imported name is declared **twice** in the workspace:

- `core/src/main/scala-2/chisel3/probe/Probe.scala` and `.../scala-3/.../Probe.scala`
- `thrall/app/lib/elasticsearch/ElasticSearch.scala` and
  `media-api/app/lib/elasticsearch/ElasticSearch.scala`

Forward returns both replicas (the record's `targets` list holds the same identity
twice). The inverse import path requires a physically unique declaration:
`target_is_physically_unique` (`query.rs:538-554`) and the replica rule at
`inverted.rs:3756-3759` ("replicas across files stay out"). The reference is dropped.

This is the Scala analogue the brief expected from the c/cpp waves. It is deliberate
fail-closed behavior. Escalate a policy question rather than patch: when forward
returns *all* replicas as one group, the inverse should be allowed to record the
reference against the group. 3 sites here, but the rule is workspace-wide, so the true
blast radius in cross-build (`scala-2`/`scala-3`) repositories is larger than this
sample shows.

### G -- `super.member` (2 sites, twitter/util) -- forward defect

`super.publish(record)` inside `class ThrottledHandler` resolves forward to
`com.twitter.logging.ThrottledHandler.publish`, that is, the *same* class. `super`
must resolve to the supertype's member. In `f10-shapes2` the same shape resolves to
the enclosing class's own override and FIRD then filters it as "enclosed by its own
target declaration". Fix the forward `super` receiver; the inverse is right to omit.

### H -- type-parameter declaration and `private[X]` qualifier (4 sites)

Two separate things:

- **Forward false positive (2).** `def withResource[Resource <: AutoCloseable, U]` binds
  a type parameter named `Resource`; forward resolves it to the unrelated object
  `wvlet.log.io.Resource$`. Same for `[F <: JsonFactory]` -> `com.twitter.util.jackson.F`.
  A type-parameter binder is a declaration, not a reference.
- **Policy disagreement (2).** `private[ActionOperationSrv] lazy val logger` inside
  `class ActionOperationSrv`. The inverse drops it as "the declaration itself"
  (`query.rs:699-708`, `inside_own_declaration && !is_function`). FIRD does not filter
  it, because `enclosing_code_unit` returns the innermost unit (`logger`), not the class
  (`src/reference_differential/mod.rs:907-912`). Harmless; align the two rules or accept.

### I -- named argument label (6 sites, mostly SwayDB)

`updateCount = segment.updateCount` inside `PersistentSegmentOne.apply`. The label
belongs to the callee's parameter list. Forward resolves it to a same-named `def` on the
class. A named argument to a case class *does* work (`f4-scalashapes` line 37,
`Conf(alpha = "a")` is `consistent`), so the failure is the choice between the callee's
parameter and an unrelated same-named member. Mixed forward/inverse; **medium** effort,
low value (6 sites).

### J -- long qualified path (16 sites)

Shapes: `_root_.logger.LogLevel.None`, `svsim.verilator.Backend.CompilationSettings`,
`am.MessagePack.newBufferPacker` (renamed-import prefix), `util.string.extractWords`
and `facade.os.EOL` (package-object prefix), `macro chisel3....ProbeTransform.sourceApply`.
Simple two-segment and three-segment paths work in fixtures (`f10-shapes2`), so the gap
is in the *prefix* forms: `_root_`, renamed import aliases, package objects, and macro
bodies. Needs a per-shape trace; **medium** effort, spread across 6 repositories.

### K -- qualified member with an unusual receiver or call shape (15 sites)

Sub-shapes seen: receiver is a call result (`userConfiguration().verboseCompilation`,
`userConfig().worksheetCancelTimeout`, `Counter(...)` result `deq_ptr.value`); member
passed as a method value (`output.createJob`, `SecondaryRateLimitExceeded.fromThrowable`);
type-arguments-only call (`RxRouter.of[MyRPC]`); multi-line select
(`Annotations\n  .findAnnotation[...](...)`); paren-less call with an implicit-only
parameter list (`Gen.byte`); extension method on an opaque type
(`occupied.contains(s)` -> `chess.Bitboard$.contains`); type member through a companion
(`Zippable.Out`). The plain forms of each of these are `consistent` in `f10-shapes2`,
so each sub-shape needs its own reduction. **Medium** effort; treat as a follow-up
sweep, not one fix.

### L -- residual bare references (14 sites)

- 4 midonet `VppController.log`: bare reference to an abstract member of a mixed-in
  trait, in a class that mixes three traits.
- 4 airframe `extractCode { ... }`: bare call whose only argument is a brace block, to a
  varargs method; `call_site_shape_for_reference` most likely reports no argument list.
- 2 sangria: `val Scalar, Object, ... = Value` (Enumeration `Value`, forward FP),
  `ValidationRule#AstValidatingVisitor` (type projection).
- 2 apalache: `.map { FixedElemPtr }` (constructor as a function value);
  `new SourceLocation(...)` at `SourceLocation.scala:12`, inside `object SourceLocation`
  in package `...imp.src`, where the class comes from
  `import at.forsyte.apalache.tla.lir.src._` -- a wildcard-imported class whose simple
  name collides with the enclosing object.
- midonet `new SimChain(...)`: constructor through a **renamed** import
  (`ChainMapper.scala:35`, `import ...simulation.{Chain => SimChain, ...}`).
- scalachess `occupied & notMask`: operator method on an opaque type.

Each needs its own reduction. **Low** priority individually.

## 7. Recommended order of work

| Rank | Family | Sites | Effort | Kind |
| --- | --- | ---: | --- | --- |
| 1 | B -- remove the self-shadow in `seed_declaration` | 70 | small, generalized | inverse fix |
| 2 | C -- seed `for` generator binders as shadows | 46 | small, generalized | forward fix |
| 3 | A1 -- Java constructor scan for Scala files | 12 | small | inverse fix |
| 4 | A3 -- Java instance receivers from Scala | 11 | large | **escalate** |
| 5 | A2 + A4 + A5 -- Java qualifier, pattern, annotation, paren-less | 16 | medium | inverse fix |
| 6 | D -- `new C(...) with T` first parent | 7 | small | inverse fix |
| 7 | F -- replica declarations and import references | 3 | policy | **escalate** |
| 8 | G, H -- forward `super` receiver, type-parameter binder | 4 | small | forward fix |
| 9 | E, I, J, K, L | 58 | mixed | follow-up sweep |

Ranks 1-3 and 6 together close 135 of 229 sites (59 %) with small, general changes.

The A family is the only place where I recommend escalation on *design*: the Scala-side
scanner for Java targets (`jvm_scala.rs`) is a second, weaker implementation of a scan
that already exists in `scala/graph/inverted.rs`. Extending it shape by shape will keep
producing this class of gap.

## 8. Artifacts

- Annotated sites with family labels: `/mnt/optane/tmp/bifrost-fird/scala-diagnosis/B-annot.json`
  (fields `_leaf`, `_pre`, `_post`, `_encl`, `_fam`, `_final`).
- Per-family example lists: `/mnt/optane/tmp/bifrost-fird/scala-diagnosis/final-examples.txt`.
- Fixtures (each is a git repository, run with `--cache-mode ephemeral`):
  - `f1-javatarget` -- Java constructor and Java annotation from Scala.
  - `f2-javamember` -- Java instance field and method from Scala.
  - `f3-javamatrix` -- full Java target perturbation matrix.
  - `f4-scalashapes` -- overload sibling, `new ... with`, extractor, import selector.
  - `f5-overload`, `f6-selfname`, `f11-shadow` -- family B single-factor matrix.
  - `f7-forcomp`, `f8-wildcard`, `f9-wildcardmatrix` -- family C matrix.
  - `f10-shapes2` -- controls that pass (apply sugar, method value, paren-less,
    type-args-only, inherited member, receiver-is-call).
- Real-site reruns: `/mnt/optane/tmp/bifrost-fird/scala-fixtures/B/real-*.jsonl`.
