# Bifrost FIRD - scala wave - bucket C (tail) diagnosis

- Bucket: `/mnt/optane/tmp/bifrost-fird/scala-diagnosis/C-tail.json`, 132 sites, all tier 1, all
  `forward_status == "no_definition"`, all `classification == "missing"`.
- Runner: `/mnt/optane/bifrost-fird/target/release/bifrost_reference_differential`
  (bifrost head `90d65613`, sha256 `bb1bb5319efa10d8f4b3c0445e2ec68a64f1fda0ec8d884d2d20ca0012e4742d`).
- Clones: `/mnt/T9/repo-clones/<slug>` (read only).
- Fixtures: `/mnt/optane/tmp/bifrost-fird/scala-fixtures/C/<family>/`.
- Single-site rerun output: `/mnt/optane/tmp/bifrost-fird/scala-diagnosis/runs/*.jsonl`.

## 0. Prior checks (all four priors were partly wrong)

**Prior 1 - "tree-sitter-scala 0.26.2 introduced new shapes."** FALSE for this bucket.
Diffed the pre-swap census `scala-census-09071ef6.jsonl` against `C-tail.json` by
`(repo, path, start_byte)`: **0 of 132 sites are new since the swap, and 0 changed diagnostic
kind.** The full-census delta (1145 -> 1144) is 13 new / 14 removed sites, all with empty
diagnostics or `ambiguous_scala_typed_overload`, i.e. entirely in buckets A/B.

**Prior 2 - "`local_variable_reference` is the cpp D-report shape: two unrelated defects and zero
actual local variables."** HALF FALSE. 32 of 35 are genuine local binders (11 `case`-pattern
binders, 21 local `def`s) where `local_variable_reference` is the correct forward verdict. The
census, not the resolver, is wrong there. The other 3 are a real resolver defect
(anonymous-class members mislabelled as locals).

**Prior 3 - "`no_applicable_scala_callable` is the Scala twin of C# #1797 / C #1811."** MOSTLY
TRUE but the discriminator is not arity-of-one-list; it is **number of application lists**
(Scala curried / function-valued members). 31 of 39 are that defect; 8 are genuinely external
targets that deserve a boundary answer.

**Prior 4 - "`ambiguous_scala_wildcard_import`: two wildcard imports genuinely make the name
ambiguous?"** FALSE in all 13. Every site has exactly ONE distinct wildcard import target; the
resolver counts the same `import X._` statement once per lexical occurrence in the file.

## 1. Family summary

| # | Family | Sites | Recommendation |
|---|--------|-------|----------------|
| F1 | Duplicate wildcard-import statements counted as multiple exporters | 13 | **Fix** (small, local) |
| F2 | Unresolvable ancestor poisons the exact lexical type namespace | 20 | **Fix** |
| F3a | Call-shape relation rejects extra application lists (function-valued member) | 24 | **Fix** |
| F3b | Call-shape relation rejects partial application / eta-expansion | 7 | **Fix** (same site) |
| F3c | Genuinely external / cross-file inherited callable | 8 | **Escalate to boundary answer** |
| F4a | Self-type (`this: A with B =>`) members not resolvable | 16 | **Escalate** (new capability) |
| F4b | Anonymous-class (`new T { ... }`) members have no CodeUnit | 6 | **Escalate** (new capability) |
| F4c | Scala 3 top-level `def` in a script file not indexed | 1 | Escalate |
| F4d | Package-object member not resolvable from a sibling file | 1 | Escalate |
| F5 | Census seeds proven-local forward verdicts as tier-1 gaps | 32 | **Grading** (engine side) |
| F6 | Same-arity `apply` overloads incl. varargs / enclosing-owner ambiguity | 3 | Escalate (bucket A adjacent) |
| F7 | External library member via wildcard import answered as a gap | 1 | Escalate to boundary |

Total 132.

## 2. F1 - duplicate wildcard imports counted as multiple exporters (13)

**Root cause, code-level.** `scala_wildcard_imported_member_outcome`
(`crates/bifrost-analysis/src/analyzer/usages/get_definition/scala.rs:8957-9024`) iterates over
`ctx.scala.import_info_of(ctx.file)` - every wildcard import in the **file**, with no lexical
scoping - and increments `contributing_imports` once per import statement that yields any
candidate:

```
scala.rs:9005   if !import_candidates.is_empty() {
scala.rs:9006       contributing_imports += 1;
scala.rs:9007       candidates.extend(import_candidates);
scala.rs:9008   }
scala.rs:9009   if contributing_imports > 1 {
scala.rs:9010       return Some(no_definition("ambiguous_scala_wildcard_import", ...));
```

The bail at 9009 fires **before** the `sort_units` / `dedup` at 9019-9021 that would have
collapsed the identical CodeUnits to one. So two occurrences of the *same* `import Encoding.*`
in two sibling templates are reported as an ambiguity. Two independent bugs: (a) wildcard
imports are collected file-wide rather than per lexical scope; (b) ambiguity is counted over
*import statements* instead of *distinct candidate units*.

**Fixture proof** (`scala-fixtures/C/wildcard_dup`, `wildcard_single`) - the only difference is
whether the second sibling object repeats `import Encoding.*`:

| fixture | forward | diagnostic |
|---|---|---|
| `wildcard_single` (one `import Encoding.*`) | `resolved` -> `fx.Outer$.Encoding$.table` | - |
| `wildcard_dup` (same import repeated in a sibling object), site A | `no_definition` | `ambiguous_scala_wildcard_import` |
| `wildcard_dup`, site B | `no_definition` | `ambiguous_scala_wildcard_import` |

**Production evidence.** Every one of the 13 sites is a file with a repeated identical wildcard
import and no second distinct exporter:

| repo / file | repeated import | occurrences | sites |
|---|---|---|---|
| scalachess `format/pgn/Binary.scala` | `import Encoding.*` | lines 33, 118 | 4 (`checkStrs` x2, `checkInts` x2) |
| scalachess `format/UciCharPair.scala` | `import UciCharPair.implementation.*` / `import implementation.*` | lines 11, 23 | 2 (`toChar`) |
| scalachess `format/BinaryFen.scala` | (same shape) | - | 1 (`writeLong`) |
| chisel `properties/Property.scala` | `import PropertyExpressionHelpers._` | lines 556, 604, 622, 641, 700 | 2 (`binOp`, `cmpOp`) |
| midonet `SessionInventory.scala` | `import ...SessionInventory._` | lines 237, 379 | 2 (`errorBuilder`, `ackBuilder`) |
| twitter/util `BufConcatBenchmark.scala` | `import BufConcatBenchmark._` | lines 62, 82 | 1 (`concatN`) |
| zio `stm/ZSTM.scala` | `import internal._` | lines 759, 876 | 1 (`tryCommitSync`) |

Exact rerun confirmed for `scalachess Binary.scala:74 checkStrs` (`runs/real-Binary-checkStrs.jsonl`).

**Recommendation: fix.** De-duplicate by candidate unit (the `dedup` already present two lines
below), and scope wildcard imports to the enclosing template. This closes all 13 with no
behaviour change for a genuinely ambiguous two-target case (add that as the negative control).

## 3. F2 - unresolvable ancestor poisons the exact lexical type namespace (20)

**Root cause, code-level.** `resolve_exact_lexical_type_namespace`
(`crates/bifrost-jvm/src/scala/graph/namespace.rs:91-151`) returns `Ambiguous` for the whole
name lookup whenever the enclosing owner's supertype list cannot be resolved:

```
namespace.rs:117   let mut level = match direct_ancestors(&owner) {
namespace.rs:118       ScalaDirectAncestorResolution::Resolved(ancestors) => ancestors,
namespace.rs:119       ScalaDirectAncestorResolution::Ambiguous => {
namespace.rs:120           return ScalaTypeNamespaceResolution::Ambiguous;
namespace.rs:121       }
...
namespace.rs:144       [] if next_is_ambiguous => return ScalaTypeNamespaceResolution::Ambiguous,
```

Line 144 propagates the same verdict transitively, so one unindexed link anywhere in the
supertype chain poisons every unqualified type lookup made from inside that owner. The caller
`scala.rs:6363-6368` then reports `ambiguous_scala_type` with the message "`X` resolves to
multiple exact Scala type declarations" - which is **actively false**: there is exactly one
candidate for `X`, and the ambiguity is in an unrelated ancestor.

**Fixture proof** (`scala-fixtures/C/anc_*`). Identical file, only the companion object's
`extends` clause changes; the reference is `ServerAddress("", -1)` inside the companion:

| fixture | companion clause | forward | diagnostic |
|---|---|---|---|
| `anc_none` | (none) | `resolved` | - |
| `anc_enum` | `extends Enumeration` | `no_definition` | `ambiguous_scala_type` |
| `anc_undefined` | `extends Foo` (nowhere defined) | `no_definition` | `ambiguous_scala_type` |
| `anc_generic` | `extends Function2[String, Int, ServerAddress]` | `no_definition` | `ambiguous_scala_type` |
| `anc_qualified` | `extends a.b.Foo` | `no_definition` | `ambiguous_scala_type` |
| `anc_transitive` | `extends LogSupport`, where an indexed `LogSupport extends LoggingMethods with LazyLogger` (both unindexed) | `no_definition` | `ambiguous_scala_type` |

`anc_transitive` is the airframe production shape exactly (`wvlet.log.LogSupport extends
LoggingMethods with LazyLogger`, `airframe-log/.../LogSupport.scala:21`). Negative controls that
do NOT trigger it, so the trigger is not the companion pair itself: `companion_pair`,
`companion_classbody`, `companion_default_param`, `companion_apply_overload`,
`companion_extends` (in-file supertype), `companion_extends_indexed`, `opaque_companion`,
`ancestor_ambiguity`/`ancestor_ambiguity2` (two same-named LogSupport traits + explicit import) -
all `resolved`. Copying the whole real `ServerAddress.scala` into a one-file workspace
(`airframe_repro`) also resolves, which is what first proved the trigger is workspace-wide
ancestor state, not file text.

**Production evidence** (exact rerun: `runs/real-ServerAddress-ServerAddress.jsonl`):

- companion class + object, companion has an externally-rooted supertype (8):
  zio `Schedule.Interval` (`extends Function2[...]`), midonet `TaskType` and
  `NeutronResourceType` x2 (`extends Enumeration`), airframe `ServerAddress`,
  `ParquetObjectWriter`, `Button` (`extends LogSupport`), linkerd `BaseDtab`
  (`extends Stack.Param[BaseDtab]`).
- Scala 3 `opaque type X` + `object X extends OpaqueInt/OpaqueFloat/OpaqueString[X]` (4, all
  scalachess, base trait from the external `scalalib` library): `SimpleFen`, `HalfMoveClock`,
  `KFactor`, `TiebreakPoint`.
- zio-http `Header.scala` `Some` x5 and `Bearer` x1 - enclosing chain
  `object SourcePolicyType` -> `object ContentSecurityPolicy extends HeaderType` -> unresolvable.
  Note the *correct* answer for `Some(...)` here is `scala.Some` (external), never one of the
  three sibling `final case class Some` declarations.
- zio `stm/TRandom.scala` `shuffleWith` (1) - enclosing `case class TRandomLive extends TRandom`
  under `object TRandom extends Serializable`.

**Recommendation: fix.** An ancestor whose declaration is not indexed cannot introduce a member,
so it must not upgrade a single exact candidate to `Ambiguous`. At minimum, prefer a unique
direct/own candidate over an unresolved-ancestor verdict, and if the verdict must stay negative,
report it as unproven-because-of-an-unindexed-supertype, not as "multiple exact declarations".
This single change is the largest single-family win in bucket C.

## 4. F3 - the call-shape relation fails closed on application-list count (39)

**Root cause, code-level.** `scala_call_shape_relation`
(`crates/bifrost-jvm/src/scala/graph/syntax.rs:2044-2125`) walks the actual argument lists
against the declared parameter lists and gives up when the site supplies more lists than the
declaration has:

```
syntax.rs:2081   let Some(declared_list) = declared.get(declared_index) else {
syntax.rs:2082       return ScalaCallShapeRelation::Incompatible;
syntax.rs:2083   };
```

In Scala an extra application list is legal whenever the member's *result* is a function value.
Conversely, `Partial { .. }` (fewer lists than declared) is only accepted when
`unique_callable` (`syntax.rs:2143`) or when the site's `method_value_arity` is known
(`syntax.rs:2184-2187`), so an eta-expanded/partially applied member passed as an argument is
rejected. `scala_filter_callable_units` (`scala.rs:8591-8649`) then admits nothing and the
caller reports `no_applicable_scala_callable`.

**Fixture proof:**

| fixture | shape | result |
|---|---|---|
| `fnvalue_extra_apply` | `def transform(flag: Boolean): Int => Int` called `transform(true)(x)` | `no_applicable_scala_callable` |
| `fnvalue_zero_list` | `def transform: Int => Int` called `transform(x)` | `no_applicable_scala_callable` |
| `partial_application` | `def render(base: String)(x: Int)` used as `xs.map(render("p"))` | `no_applicable_scala_callable` |

Exact production rerun confirmed: apalache `ExpansionMarker.scala:38 transform`
(`runs/real-ExpansionMarker-transform.jsonl`).

### F3a - extra application list on a function-valued member (24) - fix

`def f(a): SomeFunctionType` applied twice, or a zero-parameter-list `def f: A => B` applied
once, or an explicit `given`/implicit list supplied at the call site.

apalache dominates (14): `ExpansionMarker.transform` x3, `SkolemizationMarker.transform`,
`Normalizer.transform`, `TypeSubstitutor.transform`, `MkSeqRule.computeCapacity`,
`TermToVMTWriter.tr`, `TlaExUtil.findLabels`, `Cacher.replaceApplicationsWithNullary` x2,
`ConstSimplifierBase.simplifyShallow` x2, `SetMembershipSimplifier.isTypeDefining`.
Plus linkerd `SvcAddr.nodesToAddresses`, linkerd `Router.configured`,
http4s `User-Agent.parsePartiallyApplied`, http4s `DefaultHead.apply`,
sangria `ResolverBasedAstSchemaBuilder.createDynamicArgs`, sangria `Schema.fieldsFn`,
TheHive `AuditRenderer.caseToJson`, scalachess `Tiebreak.opponentsOf` x2 and `Tiebreak.scoreOf`.

### F3b - partial application / eta-expansion (7) - fix

Call supplies fewer lists than declared and the result is used as a function value:
zio-http `BodyCodec.validateZIO`, zio-http `CodeGen.render`, linkerd
`EndpointsNamer.fromEndpoints`, linkerd `ThriftClientPrep.prepareService`, apalache
`IncrementalRenaming.nameCounterMapFromEx`, deequ `GroupingAnalyzers.filterOptional`,
scalachess `Parser.showExpectations`.

### F3c - genuinely external or cross-file inherited callable (8) - escalate to a boundary

The same-file same-name candidate is correctly excluded on shape, but the real target lives
outside the file/workspace and the resolver answers `no_definition` instead of continuing to the
inheritance chain or declaring a boundary (the #1811 fail-closed shape):

- fs2 `AsyncByteArrayInputStream.scala:72` `read(buf)` -> `java.io.InputStream.read(byte[])` (JDK).
- midonet `ScalableStateTableManager.scala:1113` `get()` -> inherited zero-arg member of
  `SubscriptionList`, not the same-file `def get(key: K)` at line 520.
- chisel `Module.scala:370` `Module(...)` -> `apply` inherited from `ModuleObjIntf`.
- scalachess `eval.scala` `Cp` x2, `Mate`, and `Tiebreak.scala` `TournamentScore` x2 ->
  `apply` inherited from the external `scalalib` `OpaqueInt` / `OpaqueFloat` base traits.

## 5. F4 - Scala structures with no CodeUnit identity (24 across two diagnostics)

### F4a - self-type members (16) - escalate

`trait Tokens { protected def ws(c: Char) ... }` and
`trait TypeSystemDefinitions { this: Parser with Tokens with ... => ... ws(':') ... }`.
Bifrost does not model the self-type annotation, so the member is not reachable.

Fixture `scala-fixtures/C/selftype_member` reproduces exactly:
`ws` -> `no_definition` / `no_indexed_definition`.

All 16 are sangria `modules/parser/src/main/scala/sangria/parser/QueryParser.scala`
(`ws` x4, `wsNoComment` x7, `wsCapture` x5); the definitions are at lines 145/147/150 in
`trait Tokens` (ends line 152) and the use sites are in six sibling traits whose self-types name
`Tokens` (lines 10, 155, 195, 559, 640, 684, 762, 777). Exact rerun:
`runs/real-QueryParser-ws.jsonl`.

### F4b - anonymous-class (`new T { ... }`) members (6) - escalate

Members declared inside a `new T { ... }` template body produce **no CodeUnit**, so neither the
sibling reference nor the inherited-member reference resolves. Proved by
`scala-fixtures/C/anon_p2_no_overload`: the sibling `helper` is not even in
`analyzer.declarations(&file)` (the site graded tier 3, meaning the census's same-file name set
did not contain it).

Three sites surface as `no_indexed_definition`:
- zio `stacktracer/.../Tracer.scala:18` `parseOrNull` (sibling member of `new Tracer { }`),
- http4s `EntityDecoder.scala:197` `matchesMediaType` (member **inherited** by the anonymous
  `new EntityDecoder[F,T] { }` from the trait it instantiates; fixture
  `scala-fixtures/C/anon_inherited_member` reproduces),
- zio-http `Handler.scala:254` `self` (the `self =>` self-alias of the enclosing trait,
  referenced from inside a nested anonymous class).

Three more surface as `local_variable_reference` and are a **separate, real mislabel** (see
below): zio `ConfigProvider.scala:652` `load`, zio `Console.scala:99` `printLine`,
linkerd `Stream.scala:164` `reset`.

**The mislabel.** `scala_is_local_function_definition`
(`crates/bifrost-analysis/src/analyzer/usages/get_definition/scala.rs:11526-11543`) walks up from
a `function_definition` and returns `true` on the first `block`/`indented_block`/`case_clause`/
`lambda_expression`/`function_definition` ancestor, `false` on the first
`class_definition`/`object_definition`/`trait_definition`/`enum_definition`. **`template_body`
under `instance_expression` is in neither list**, so the walk sails past the anonymous class body
and hits the `indented_block` that tree-sitter-scala wraps a continuation-line
`val x =\n  new T { ... }` in. Verified AST (tree-sitter-scala 0.26.2) for the reduced fixture:

```
identifier[184,193] < call_expression < call_expression < indented_block
  < function_definition[134,220] < template_body[126,324] < instance_expression[112,324]
  < indented_block[112,325] < val_definition[84,325] < template_body < object_definition
```

Fixture matrix (`scala-fixtures/C/anon_*`), same overload pair each time:

| fixture | shape | diagnostic |
|---|---|---|
| `anon_class_member` | `val u: T =\n  new T { def m(x)=m(s)(x); private def m(s)(x)=... }` | `local_variable_reference` |
| `anon_p3_sameline` | same, but `new T {` on the `=` line (no wrapping `indented_block`) | `no_indexed_definition` |
| `anon_p1_named_object` | same overload pair in a named `object` | **resolved** |
| `anon_p4_named_class_selfname` | same overload pair in a named `class` | **resolved** |
| `anon_p5_indentedblock_named_object` | `indented_block` present, named object | **resolved** |

So the mislabel needs anonymous-class + continuation-line layout; the underlying miss
(anonymous-class members are not indexed) is present either way.

### F4c - Scala 3 top-level `def` in a script file (1) - escalate

metals `bin/merged_prs.scala:89` `template` -> top-level `def template` at line 110 of the same
scala-cli script (no enclosing object). Fixture `scala-fixtures/C/toplevel_def` reproduces.

### F4d - package-object member from a sibling file (1) - escalate

zio-http `Route.scala:351` `handler` -> `def handler[H](...)` in
`zio-http/shared/src/main/scala/zio/http/package.scala:30` (`package object http`).
Fixture `scala-fixtures/C/package_object` reproduces
(`no_definition` / `no_indexed_definition`).

## 6. F5 - census grading: proven-local forward verdicts seeded as tier-1 gaps (32)

**This is an engine-side grading question, not a resolver defect.** For 32 of the 35
`local_variable_reference` sites the forward verdict is *correct*: a lexical binder in scope
shadows the name, and Scala locals are deliberately not CodeUnits.

I reimplemented `scala_active_path_declares_name_before_mode`
(`scala.rs:9611-9673`) against tree-sitter-scala 0.26.2 and recovered the exact binder the
resolver found for all 35 sites:

| binder kind | sites | verdict |
|---|---|---|
| `case` clause pattern binder (`case Cons(fa, more) => ... more()`) | 11 | correct |
| local `def` (nested method in a `block`/`lambda`/`if`/`case` body) | 21 | correct |
| anonymous-class member misread as local (F4b) | 3 | **defect** |

Pattern-binder sites: twitter/util `AsyncStream.scala` `more` x5, zio `NewEncodingBenchmark`
`rescuer` + `andThen`, zio `ZManaged` `release`, zio-http `AsyncBodyReader` `callback`,
fs2 `StreamDecoder` `decoder` + `y`.
Local-`def` sites: zio `ZIO.interrupt`, zio `ZSink.fold`, metals `connect`/`search`/
`isPackageObjectLike`/`isStop`/`loop` x2, zio-http `Middleware.allowedHeaders`,
SwayDB `Logs.find`, chisel `Lookupable.impl`, airframe `CompileTimeSurfaceFactory.resolveType`,
apalache `Arena.create`, sangria `SchemaValidationRule.validate` x3,
grid `ImageResponse.writes` x3, fs2 `Stream.pull`, fs2 `text.decodeC`.

**Why the census seeds them.** `classify_census_gaps`
(`src/reference_differential/mod.rs:1469-1544`) excludes only two forward statuses from grading:

```
mod.rs:1482   if record.forward_status != "resolved"
mod.rs:1483       && record.forward_status != "unresolvable_import_boundary"
```

Its tier-1 evidence is "some declaration named N exists in this file" plus
`bare_call_reaches_same_file_declaration`, whose Scala arm (`mod.rs:1430-1435`) returns
**`true` unconditionally** - exactly the #1783 false-evidence shape that was fixed for JS/TS
only. Concrete false evidence: twitter/util `AsyncStream.scala` `more` binds to
`case Cons(fa, more)`, but the file's declaration set contains `more` from
`private final class Oneshot[A](var more: () => AsyncStream[A])` at line 721 - an unrelated
class in the same file. sangria `validate` binds to the local `def validate(fn: ...)` at line
734, but the file also declares `def validate` members at lines 25/46/62/198/208.

**Recommendation: grading.** `local_variable_reference` is an adjudicated forward answer (the
resolver *proved* a lexical binder shadows the name), semantically the same class of answer as
`unresolvable_import_boundary`. Exclude proven-local verdicts from census gap grading, either by
consulting the diagnostic kind or by giving the resolver a distinct forward status. Sizing from
the full census: `local_variable_reference` occurs 14,416 times overall but only 35 sites are
tier 1, so the change removes 32 false gaps (3 remain, correctly, once F4b relabels them) and
touches nothing else. Precedents: #1783/#1784 (`reference_candidates.rs:125, 415, 497`), #1834
(`mod.rs:685`).

## 7. F6/F7 - remainder (4)

- linkerd `ThriftNamerInterface.scala:313, 316` `TPath(...)` (2) - `ambiguous_scala_callable`,
  "multiple same-arity lexical singleton `apply` overloads". `object TPath` declares
  `apply(elems: String*)` (varargs) and `apply(path: Path)`. Scala ranks a fixed-arity match
  above a varargs alternative, so an applicability rule for varargs would decide this. Adjacent
  to bucket A's typed-overload family; recommend folding it there rather than fixing separately.
- zio-http `Route.scala:466` `handler` (1) - `ambiguous_scala_enclosing_member`, "multiple
  physical enclosing-owner definitions". Same target as F4d (the `package object http` `handler`),
  with several same-named parameters/vals in `Route.scala` competing. Resolving F4d should
  subsume it; re-audit after.
- deequ `Analyzer.scala:566` `count("*")` (1) - target is
  `org.apache.spark.sql.functions.count`, brought in by
  `import org.apache.spark.sql.functions._` (line 32). External. The honest answer is
  `unresolvable_import_boundary`, not `no_indexed_definition`; today the wildcard-import
  boundary check does not fire for this shape.

## 8. Fix / escalate / grading tally

- **Fix now (bounded, reduced, with fixtures):** F1 (13), F2 (20), F3a+F3b (31) = **64 sites**.
- **Escalate (new analyzer capability or boundary contract):** F3c (8), F4a (16), F4b (6),
  F4c (1), F4d (1), F6 (3), F7 (1) = **36 sites**.
- **Engine-side grading (census should not seed):** F5 = **32 sites**.

F2 alone is worth doing first: it is a one-function change in
`crates/bifrost-jvm/src/scala/graph/namespace.rs` with a false diagnostic message attached, and
the same `Ambiguous`-on-unresolved-ancestor rule is very likely inflating the 5,566 tier-3
`ambiguous_scala_type` sites in the wider census.

## 9. Reproduction index

Real-site reruns (all reproduced the census diagnostic exactly):

| tag | site | diagnostic |
|---|---|---|
| `real-ServerAddress-ServerAddress` | airframe `ServerAddress.scala` @1564 | `ambiguous_scala_type` |
| `real-Binary-checkStrs` | scalachess `Binary.scala` @2838 | `ambiguous_scala_wildcard_import` |
| `real-ExpansionMarker-transform` | apalache `ExpansionMarker.scala` @1831 | `no_applicable_scala_callable` |
| `real-QueryParser-ws` | sangria `QueryParser.scala` @15018 | `no_indexed_definition` |
| `real-more1` | twitter/util `AsyncStream.scala` | `local_variable_reference` |
| `real-printLine` | zio `Console.scala` | `local_variable_reference` |
| `real-tpath` | linkerd `ThriftNamerInterface.scala` | `ambiguous_scala_callable` |
| `real-routehandler` | zio-http `Route.scala` | `no_indexed_definition` |
| `real-matchesmt` | http4s `EntityDecoder.scala` | `no_indexed_definition` |

Command form used throughout:

```
target/release/bifrost_reference_differential run-repo \
  --root <clone-or-fixture> --language scala --probe-seed census --tiers 1 \
  --cache-mode ephemeral --path <FILE> --start-byte N --end-byte M --output <out.jsonl>
```

34 fixtures under `/mnt/optane/tmp/bifrost-fird/scala-fixtures/C/`; each is a one- or two-file
git repository so `run-repo` accepts it.
