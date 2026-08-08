# cpp verification-phase diagnosis: the log4cxx survivors and the 11 new sites

Bifrost head `b2084178` (clean). Runner
`/mnt/optane/bifrost-fird/target/release/bifrost_reference_differential` (0.8.24).
Probe binary `/mnt/optane/bifrost-fird/target/release/bifrost` rebuilt at the same head
(the checked-in `target/release/bifrost` was stale at 0.8.23 / Aug 6 and was replaced).

Corpus clone `apache__logging-log4cxx` at `a345ec7de5971990f13c0943b4505a928df4c8b1`,
clean. All `bifrost --tool` probing ran against a byte-identical copy at
`/mnt/optane/tmp/bifrost-fird/cpp-fixtures/verify-lx/REAL-log4cxx` so the clone stayed
read-only.

Fixtures: `/mnt/optane/tmp/bifrost-fird/cpp-fixtures/verify-lx/`.
Raw runs: `/mnt/optane/tmp/bifrost-fird/cpp-diagnosis/lx/`.

---

## 1. Verdict in one paragraph

#1829 works. The angle-aware include visibility it added is live on the real repo and
is *not* what holds these sites back. The 60 surviving forward-resolved-but-inverse-missing
log4cxx sites are **four unrelated defects**, none of them the angle-include theory in
`C-report.md` family A, and none of them the `LOG4CXX_NS` macro token that the FQN
display suggested:

| n | family | side at fault | mechanism |
|---|--------|---------------|-----------|
| 21 | `LevelPtr` | **forward** | definition resolution answers an out-of-include-closure same-FQN twin as the *only* target; the inverse on the correct twin covers 21/21 sites |
| 16 | `logchar` | **inverse** | `unique_type_candidate_preserving_target` fails closed when a name has several same-FQN type declarations with different alias targets (the `#if` family in `logstring.h`) |
| 6 | `helpers::Pool` | **extraction (#1803 face)** | `object.h:98` mints `helpers.Pool` -- the `LOG4CXX_NS` namespace segment is dropped -- while its 10 siblings mint `LOG4CXX_NS::helpers.Pool`; forward answers the split unit |
| 4 | `.format` | **regression from this wave** | the `using Base::name;` overload merge (10f26deb / e1308630) makes a call on a derived object answer the base declaration |
| ~13 | singletons | mixed | not individually adjudicated (see 6) |

Only the `.format` four are new damage. The other 56 are pre-existing and were already
in the pre-wave census under the same classification.

---

## 2. Question 1: did #1829's angle-aware visibility take effect?

**Yes. Confirmed on the real repo, not only in fixtures.**

`src/main/cpp/logger.cpp` reaches `src/main/include/log4cxx/level.h` only through
`#include <log4cxx/level.h>`. Neither direct rule can resolve that: source-relative is
`src/main/cpp/log4cxx/level.h` and project-relative is `log4cxx/level.h`; both are absent.
Only the angle-admitting `resolve_include_targets_with_index` unique-suffix step lands it.

```
bifrost --tool scan_usages_by_location \
  --args '{"targets":[{"path":"src/main/include/log4cxx/level.h","line":38,"column":32}],
           "paths":["src/main/cpp/logger.cpp"]}'
-> status "found", hits at logger.cpp 56, 182, 190, 263, 277, 282, 290, ... (45 in logger.h too)
```

The inverse attributes references in an angle-including consumer across a separate include
root. Pre-#1829 this returned nothing at all (`quoted_include_paths` filtered every
`#include <...>` out of `imported_code_units_of`).

Fixture confirmation, same shape, one variable:

| fixture | include spelling | result |
|---|---|---|
| `F1-baseline` | `<log4cxx/logstring.h>`, separate include root | missing |
| `F4-quoted` | `"logstring.h"`, same directory | missing |
| `F5-direct-site` | `<log4cxx/logstring.h>`, separate include root | **consistent** |

`F1` vs `F4` shows the include spelling makes no difference any more; `F5` shows the
angle + separate-root layout resolves end to end. Include spelling is falsified as a
factor.

---

## 3. Question 2: what actually blocks each family

### 3.1 `logchar` (16 sites) -- same-FQN alias family fails closed in the inverse

**Both suspects in the brief are wrong, and the real factor is a third thing.**

Perturbation ladder (each row differs from `F1-baseline` in exactly one respect;
all run through `bifrost_reference_differential run-repo --path/--start-byte/--end-byte`):

| fixture | perturbation | classification |
|---|---|---|
| `F1-baseline` | log4cxx shape: angle include, separate root, `namespace LOG4CXX_NS`, typedef in `#if`, alias site | missing |
| `F2-no-preproc` | typedef not in `#if` | missing |
| `F4-quoted` | quoted same-dir include | missing |
| `F3-real-ns` | `namespace log4cxx` instead of `LOG4CXX_NS` | **consistent** |
| `F5-direct-site` | site spells `UniChar`, not the alias | **consistent** |
| `F8-macrotok-nodefine` | `namespace LOG4CXX_NS`, but no `#define LOG4CXX_NS` in the workspace | **consistent** |
| `F16-define-unrelated` | `#define OTHER_TOK log4cxx` present, namespace token undefined | **consistent** |

`F8` falsifies suspect (a): a macro-*looking* namespace token in the FQN is harmless.
The real clone has no visible `#define LOG4CXX_NS` at all -- the only definition lives in
`src/main/include/log4cxx/log4cxx.h.in:105`, a CMake template that is not an analyzed C++
source. So the `LOG4CXX_NS` token in `LOG4CXX_NS.UniChar` is *not* the blocker.

Faithful ladder, built from the real `logstring.h` namespace block:

| fixture | header shape | classification |
|---|---|---|
| `G1-real-nsblock` | verbatim real block (3 `logchar` typedefs across `#if` branches + `UniChar`) | missing |
| `G2-unichar-only-if` | one `logchar` typedef, still inside `#if` | **consistent** |
| `G3-unichar-only-noif` | one `logchar` typedef, no `#if` | **consistent** |
| `G4-two-branch` | two `logchar` typedefs (`char`, `UniChar`) in disjoint `#if` | missing |
| `G5-order-flipped` | same two, source order swapped | missing |
| `G6-same-target` | two `logchar` typedefs, **both** aliasing `UniChar` | **consistent** |
| `G7-two-noif` | two competing `logchar` typedefs, no `#if` at all | missing |
| `G9-distinct-names` | two typedefs with *different* names | **consistent** |

The single flipping factor is **two or more type declarations sharing one FQN whose alias
targets differ**. Preprocessor wrapping is not it (`G3` vs `G7`), order is not it (`G5`),
alias transitivity itself is not it (`G6` works).

**Code:** `crates/bifrost-cpp/src/graph/resolver.rs:3993`
`VisibilityIndex::unique_type_candidate_preserving_target`.

```rust
if self.alternate_same_fqn_type_declarations(analyzer, candidates, target) {
    return Some(target.clone());
}
let mut resolved_candidates = Vec::new();
for candidate in candidates {
    let resolved =
        self.type_candidate_preserving_target(analyzer, visible_from, candidate, target)?;
    ...
    resolved_candidates.push(resolved);
    if resolved_candidates.len() > 1 {
        return None;                      // <- Ambiguous, site is never attributed
    }
}
```

For the site `logchar` the candidate set is the whole same-FQN family. Each candidate is
canonicalised independently by `type_candidate_preserving_target`
(`resolver.rs:4260`): `typedef char logchar;` stops at
`StructuredAliasTarget::Builtin` and returns *itself* (alias units are `is_class()`),
while `typedef UniChar logchar;` returns the target. Two distinct resolutions -> `None`
-> `TypeCandidateFailure::Ambiguous` -> `LexicalTypeResolution::Ambiguous` -> no hit.

The escape hatch that exists for exactly this "one logical type, mutually exclusive
physical declarations" case is `alternate_same_fqn_type_declarations`
(`resolver.rs:4031`), but it cannot fire here. Two of its preconditions exclude the shape:

```rust
&& candidates.iter().any(|candidate| same_symbol(candidate, target))     // target must BE a candidate
&& candidates.iter().any(|candidate| !same_logical_symbol(candidate, target))
```

- When the forward target is `LOG4CXX_NS.UniChar` (6 of the 16 sites) the target is not
  among the `logchar` candidates at all, so the guard-aware merge is skipped.
- When the forward target is one of the `logchar` declarations (the other 10 sites) all
  three candidates *are* `same_logical_symbol` with the target, so
  `any(|c| !same_logical_symbol(c, target))` is false and `same_api` is false.

Product-API confirmation on the real repo: `scan_usages_by_location` on **each** of the
three `logchar` declarations (`logstring.h:42`, `:47`, `:56`) returns
`verified_absent` -- zero usages workspace-wide for a typedef with 16 sampled references
and many more real ones. That is the user-visible face of the defect.

**Fix sketch.** Two options, not mutually exclusive.

1. Widen `alternate_same_fqn_type_declarations` to admit a same-FQN, same-file family
   whose members are all type aliases under provably disjoint preprocessor guards, even
   when the requested target is *reached through* the family rather than being a member
   of it. The guard-disjointness machinery
   (`declaration_guard_requirements` / `merge_preprocessor_guards`) is already there and
   already returns `None` for `#if A` vs `#if B` in `logstring.h`; only the
   `same_symbol(candidate, target)` and `!same_logical_symbol(candidate, target)`
   preconditions block reuse.
2. In `unique_type_candidate_preserving_target`, when the several resolutions disagree
   but exactly one of them is `same_visible_symbol` with the requested target, prefer
   that one instead of failing closed. Preserving the *requested* target is the whole
   contract of the `PreserveTarget` mode; disagreement among the other branches is not
   evidence against it.

Either way, add the `G4`/`G6`/`G9` triple as the regression: two same-FQN aliases with
different targets must still attribute the reference, two with the same target must stay
attributed, and two with different names must be unaffected.

### 3.2 `LevelPtr` (21 sites) -- forward answers an invisible twin

`LOG4CXX_NS.LevelPtr` is declared twice, identically:

```
src/main/include/log4cxx/level.h:38                 typedef std::shared_ptr<Level> LevelPtr;
src/main/include/log4cxx/helpers/optionconverter.h:28  typedef std::shared_ptr<Level> LevelPtr;
```

`src/main/cpp/logger.cpp` includes `<log4cxx/level.h>` and does **not** reach
`optionconverter.h` in any include closure (12 includes, none of them
`optionconverter.h`, and no transitive path through `logger.h`, `level.h`, `hierarchy.h`,
`logmanager.h`).

```
get_definitions_by_location  logger.cpp:182:29  ->  ONE definition:
    LOG4CXX_NS.LevelPtr @ src/main/include/log4cxx/helpers/optionconverter.h:28
scan_usages_by_location      optionconverter.h:28  -> verified_absent, covers 0/21
scan_usages_by_location      level.h:38            -> found, covers 21/21
```

The inverse is right. The forward is wrong twice over: it selects the declaration the
reference cannot see, and it returns it as a *singleton* group rather than the group of
same-logical declarations, so nothing downstream can recover.

This is not a same-FQN-across-files problem in general: fixtures `H1-alias-two-files`,
`H3-fwd-many-files`, `H5-alias-twin-invisible` all reproduce the duplicate-declaration
layout and all classify **consistent**, with both/all declarations present in the target
group. The real repo's group collapsing to the invisible member is not reproduced by the
obvious minimisation; the mechanism that drops the visible twin from the group is not yet
isolated. What is proven is the observable: forward answers an out-of-closure declaration
and omits the in-closure one.

**Fix sketch.** Definition resolution for a type reference must (a) prefer a declaration
that is include-visible from the reference file, and (b) return the full
same-logical-symbol group when several declarations are equally good, the way the C++
inverse target group already expects. `VisibilityIndex::is_physically_visible` /
`external_type_candidate_visible_at` already answer (a) and are used by the inverse; the
forward path in `crates/bifrost-analysis/src/analyzer/usages/get_definition/cpp.rs` is
where the preference is missing.

### 3.3 `helpers::Pool` (6 sites) -- an extraction identity split, i.e. an #1803 face

Eleven `class Pool` declarations exist. Ten mint `LOG4CXX_NS::helpers.Pool`. One does not:

```
LOG4CXX_NS::helpers.Pool   src/main/include/log4cxx/helpers/pool.h:32       class LOG4CXX_EXPORT Pool
LOG4CXX_NS::helpers.Pool   src/main/include/log4cxx/file.h:34               class Pool
LOG4CXX_NS::helpers.Pool   ... 8 more ...
helpers.Pool               src/main/include/log4cxx/helpers/object.h:98     class Pool     <-- LOG4CXX_NS dropped
```

`object.h:98` sits in the same textual shape as `file.h:34`
(`namespace LOG4CXX_NS { ... namespace helpers { class Pool; ... } }`), yet the outer
namespace segment is lost from the minted FQN. Deterministic across repeated cold runs
(3/3 with `.bifrost` removed each time).

Consequence: the forward answers the split unit
(`helpers.Pool` @ `object.h`) as the sole target for `file.cpp`'s
`helpers::Pool` references. `scan_usages_by_location` on that unit reports
`verified_absent`; on the correct `pool.h:32` unit it reports `found` and covers 5 of the
6 survivor sites.

Minimisation (all probes with the file alone in a scratch workspace, checking the minted
FQN with `search_symbols`):

| content | minted FQN |
|---|---|
| verbatim `object.h` | `helpers.Pool` |
| body with the license header, `#ifndef` guard and `#include`s stripped | `LOG4CXX_NS::helpers.Pool` |
| guard restored, body unchanged | `helpers.Pool` |
| `#include`s restored without the guard | `LOG4CXX_NS::helpers.Pool` |
| guard + namespace region `[89..140)` (verbatim) | `helpers.Pool` |
| guard + same region minus the trailing `template<...> cast(...)` function | `LOG4CXX_NS::helpers.Pool` |
| guard + same region minus the `class Object { ... }` body | `LOG4CXX_NS::helpers.Pool` |

So the split needs three ingredients together: the `#ifndef/#define` include guard, the
`class Object` body (which contains the bare, semicolon-less macro invocation
`DECLARE_LOG4CXX_CLAZZ_OBJECT(Object)`), and the trailing namespace-scope
`template<...> std::shared_ptr<Ret> cast(...)` function. Reconstructing those three
ingredients synthetically did **not** reproduce (`U-*` fixtures all mint the correct
FQN), so the trigger is a parse-recovery interaction that still needs an exact
minimisation. The *fact* -- a deterministic, single-file, workspace-independent FQN split
-- is fully established and is the reportable defect.

Attribution: this is an #1803 face (extraction minting a unit under a degraded namespace),
not an inverse gap. The inverse behaves correctly for both FQNs.

### 3.4 What the brief's suspects turned out to be

- **(a) "the `LOG4CXX_NS` macro-token namespace in the target FQN blocks inverse
  matching."** Falsified. `F8`/`F16` show an undefined all-caps namespace token resolves
  end to end, and the real clone has no analyzed `#define LOG4CXX_NS`.
- **(b) "alias transitivity does not cover macro-namespaced units."** Half right. Alias
  transitivity *is* the axis that matters for `logchar` (`F5` direct-site works,
  alias-site does not), but the blocker is competing same-FQN declarations, not the
  namespace spelling: `G6` (two aliases, same target, macro-token namespace) is
  consistent.
- **(c) something else.** Yes -- three different "something else"es, one per family.

### 3.5 Side observation, corpus-unconfirmed

In fixtures only, a second independent trigger appeared: when the enclosing namespace
token is *also* an object-like macro whose replacement differs from the token
(`#define LOG4CXX_NS log4cxx` + `namespace LOG4CXX_NS`), an alias-spelled site stops
being attributed even with a single alias declaration
(`F1`, `F2`, `F13-define-otherident`, `F14-define-number` all missing;
`F15-define-self`, `F16-define-unrelated`, `F8-macrotok-nodefine` all consistent). The
suspected seam is `macro_expanded_cpp_name_components`
(`crates/bifrost-cpp/src/graph/extractor.rs:8448`) expanding one side of the
`using namespace` tier comparison but not the other. This does **not** occur in log4cxx
(no analyzed `#define LOG4CXX_NS`), so it is a lead for repos that really do define a
namespace-token macro, not a finding against this corpus. Not chased further.

---

## 4. Question 3: adjudication of the 11 new missing sites

Key = `(repo, path, start_byte)`. Pre-wave truth read from the site records in
`cpp-census-bba1c5da.jsonl` (all 11 found), current truth from
`cpp-missing-verify-b2084178.json` plus exact single-site reruns where noted.

| # | repo | site | text | pre-wave (`bba1c5da`) | now (`b2084178`) | verdict |
|---|------|------|------|------------------------|-------------------|---------|
| 1 | log4cxx | `src/fuzzers/cpp/PatternConverterFuzzer.cpp` @3472 | `Pool` | `inconclusive` -- "inverse unproven samples were truncated before this site could be disproven" | `missing`, target group of 12 `LOG4CXX_NS::helpers.Pool` | **churn** -- newly adjudicated, never previously decided |
| 2 | log4cxx | same file @4353 | `.format` | **`consistent`**, target `LOG4CXX_NS::pattern.FullLocationPatternConverter.format` | `missing`, target `LOG4CXX_NS::pattern.LoggingEventPatternConverter.format` | **REGRESSION** |
| 3 | log4cxx | same file @4932 | `.format` | **`consistent`**, target `...ThreadPatternConverter.format` | `missing`, target `...LoggingEventPatternConverter.format` | **REGRESSION** |
| 4 | log4cxx | same file @5021 | `.format` | **`consistent`**, target `...ThreadUsernamePatternConverter.format` | `missing`, target `...LoggingEventPatternConverter.format` | **REGRESSION** |
| 5 | log4cxx | same file @5211 | `.format` | **`consistent`**, target `...ThrowableInformationPatternConverter.format` | `missing`, target `...LoggingEventPatternConverter.format` | **REGRESSION** |
| 6 | BehaviorTree.CPP | `include/behaviortree_cpp/decorators/consume_queue.h` @1954 | `executeTick` | `inconclusive` -- forward `no_definition`, diag `unsupported_cpp_receiver` | `missing`, forward now `resolved` to `BT.TreeNode.executeTick`, diag `unproven_cpp_link_unit` | **churn** -- new surface exposed by fixed forward resolution |
| 7 | BehaviorTree.CPP | `include/behaviortree_cpp/decorators/loop_node.h` @4807 | `executeTick` | same as #6 | same as #6 | **churn** -- same |
| 8 | abseil | `absl/container/internal/raw_hash_set.h` @90133 | `Hash` | `inconclusive` -- unproven-sample truncation | `missing`, target `absl::hash_internal.Hash` | **churn** -- newly adjudicated |
| 9 | abseil | `absl/container/internal/raw_hash_set.h` @139128 | `PolicyTraits::template` | `inconclusive` -- unproven-sample truncation | `missing`, target `absl::container_internal.hash_policy_traits` | **churn** -- newly adjudicated |
| 10 | abseil | `absl/container/linked_hash_map.h` @2598 | `Alloc` | `inconclusive` -- unproven-sample truncation | `missing`, target `absl::container_internal.GetFromListOr` | **churn** -- newly adjudicated |
| 11 | abseil | `absl/container/linked_hash_set.h` @15455 | `Alloc` | `inconclusive` -- unproven-sample truncation | `missing`, target `absl::container_internal.GetFromListOr` | **churn** -- newly adjudicated |

**Summary: 4 regressions, 7 churn, 0 nondeterminism.** None of the 11 is a #1836
nondeterminism artifact -- every pre-wave record exists and every pre-wave classification
is a decided one, and the four regressions reproduce on exact single-site rerun.

Note on #10 and #11: the forward target `absl::container_internal.GetFromListOr` for a
reference whose text is `Alloc` is itself suspect and probably a separate forward defect,
but it is unchanged from the pre-wave census, so it is not this wave's damage.

### 4.1 The `.format` regression, characterised

Reproduced at head:

```
bifrost_reference_differential run-repo --root <log4cxx> --language cpp \
  --cache-mode ephemeral --path src/fuzzers/cpp/PatternConverterFuzzer.cpp \
  --start-byte 4353 --end-byte 4359
-> .format resolved missing
   target LOG4CXX_NS::pattern.LoggingEventPatternConverter.format
          @ loggingeventpatternconverter.h
          "(const spi::LoggingEventPtr &, LogString &, helpers::Pool &) const"
```

Source shape (`src/main/include/log4cxx/pattern/fulllocationpatternconverter.h:55-57`):

```cpp
class LOG4CXX_EXPORT FullLocationPatternConverter
    : public LoggingEventPatternConverter
{
    public:
        using LoggingEventPatternConverter::format;
        void format( LOG4CXX_FORMAT_EVENT_FORMAL_PARAMETERS ) const override;
};
```

with `LOG4CXX_FORMAT_EVENT_FORMAL_PARAMETERS` expanding (in the API-version branch) to
exactly the base's three-parameter list. So the derived member *overrides* the base
virtual; the call `FullLocationPatternConverter().format(event, logger, p)` targets the
derived override, which is what the pre-wave census recorded.

Minimal reproduction at head, `Y-*` fixtures
(`/mnt/optane/tmp/bifrost-fird/cpp-fixtures/verify-lx/Y-a` .. `Y-d`),
`get_definitions_by_location` on `Derived().format(e, o, p)`:

| derived class body | forward answer |
|---|---|
| `using Base::format;` + `void format(FMT_PARAMS) const override;` | **`ambiguous`**: `pat.Base.format` *and* `pat.Derived.format` |
| `using Base::format;` + `void format(const Event&, LogString&, Pool&) const override;` | **`ambiguous`**: both |
| no `using` + `void format(FMT_PARAMS) const override;` | `resolved`: `pat.Derived.format` |
| no `using` + explicit parameter list | `resolved`: `pat.Derived.format` |

The `using` declaration alone flips a correct singleton answer into an ambiguity that
includes an overload the derived class *overrides*. C++ [namespace.udecl]/14 is explicit
that a derived member with the same parameter-type-list hides the base member the
using-declaration would otherwise introduce; the merge is not applying that exclusion.

Wave commits in `bba1c5da..b2084178` that own this behaviour:
`10f26deb` "Merge C++ `using Base::name;` overloads into the derived overload set" and
`e1308630` "Gate the using-declaration merge on the parse, not the ancestor read".
`ff63e25f` "Let unproven C++ call arity preserve an ambiguity, not manufacture one" is a
plausible co-factor for why the real (macro-parameter-list) case degrades all the way to
"base only" instead of "ambiguous".

**Fix sketch.** When merging a `using Base::name;` overload set into the derived class,
drop every base overload whose parameter-type-list is matched by a derived declaration of
the same name. Where the derived parameter list is a macro token whose replacement is
known in the file's macro environment (`object_macro_replacement_at`), expand it before
comparing; where it is not known, treat the derived declaration as covering the base
overload rather than as an unknown that lets the base win -- an `override` specifier is
direct evidence that some base virtual is being replaced. Regression: the `Y-a` fixture
must answer `pat.Derived.format` alone.

---

## 5. Falsified premises, collected

1. **"#1829 did not take effect on the real repo."** False. Proven live by
   `scan_usages_by_location` attributing `logger.cpp` references to `level.h` across an
   angle include and a separate include root, and by fixture `F5`.
2. **"The log4cxx family is one family."** False. It is at least four distinct defects
   with three different responsible layers (forward resolution, inverse type-candidate
   selection, extraction), plus one regression introduced by this wave.
3. **"The `LOG4CXX_NS` macro token in the target FQN is the blocker (#1803 face)."**
   False for `logchar` and `LevelPtr`. There is a real #1803 face in the family, but it
   is a different one: the *dropped* `LOG4CXX_NS` segment on `object.h`'s `Pool`, not the
   *present* `LOG4CXX_NS` segment elsewhere.
4. **"The forward target being the underlying typedef (`UniChar`) rather than the alias
   (`logchar`) is the blocker."** Incidental. 10 of the 16 `logchar` sites resolve
   forward to `LOG4CXX_NS.logchar` itself and are still missing; the `#if` family is the
   blocker in both cases.
5. **"The `#if` preprocessor wrapping is the blocker."** False. `G3-unichar-only-noif`
   (no `#if`, one alias) is consistent and `G7-two-noif` (no `#if`, two competing
   aliases) is missing.
6. **"Same-FQN declarations across multiple files break the inverse."** False in
   general: `H1`, `H3`, `H5` all reproduce that layout and classify consistent. The
   `LevelPtr` failure is specifically that the forward returns the *invisible* member as
   a singleton group.
7. **"The 11 new sites may be #1836 nondeterminism."** False. All 11 have decided
   pre-wave records; 7 are genuine churn (previously undecided or previously
   forward-unresolved) and 4 are a reproducible regression.

---

## 6. Not adjudicated

The ~13 log4cxx singleton survivors (`Ch` x2, `spi::ConfigurationStatus`,
`ThreadSpecificData::NamePairPtr`, `DefaultConfigurator::configure`,
`MessageBuffer::operator`, `UniChar`, `ODBCAppender::SQLHDBC`, `SQLSMALLINT`,
`PropertyMap`, `WriterAppender::WriterAppenderPriv`, `Logger`, `Pool`) were not
individually diagnosed. Two of them (`MessageBuffer::operator`, `PropertyMap`) already
answer `ambiguous` from `get_definitions_by_location`, which is the same
`TypeCandidateFailure::Ambiguous` shape as 3.1 and is worth checking against the same
fix.

The exact parse-recovery trigger for the `object.h` FQN split (3.3) is isolated to three
co-occurring ingredients but not yet reduced to a synthetic minimal case.

## 7. Artifacts

- Fixtures: `/mnt/optane/tmp/bifrost-fird/cpp-fixtures/verify-lx/` -- `F*` (single-axis
  perturbations), `G*` (faithful `logstring.h` ladder), `H*` (multi-file same-FQN
  controls), `U*`/`V*`/`S*`/`T*` (`object.h` split minimisation), `Y*` (`using Base::name;`
  regression), `REAL-log4cxx` (byte-identical probing copy).
- Differential runs: `/mnt/optane/tmp/bifrost-fird/cpp-diagnosis/lx/*.jsonl`.
- The 11 new sites and their pre-wave records:
  `/mnt/optane/tmp/bifrost-fird/cpp-diagnosis/lx/new-11.json`,
  `/mnt/optane/tmp/bifrost-fird/cpp-diagnosis/lx/new-11-pre.json`.
- Batched forward answers for all 60 survivors:
  `/mnt/optane/tmp/bifrost-fird/cpp-diagnosis/lx/lx60-forward.json`.
