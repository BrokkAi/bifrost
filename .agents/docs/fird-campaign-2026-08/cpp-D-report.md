# FIRD cpp wave — bucket D diagnosis

Bucket: 38 census "missing" sites across `unsupported_cpp_receiver` (29),
`no_applicable_overload` (7), `local_variable_reference` (2).

Input list: `/mnt/optane/tmp/bifrost-fird/cpp-diagnosis/D-receiver-overload-local.json`
Binary: `/mnt/optane/bifrost-fird/target/release/bifrost_reference_differential`
Bifrost head: `458a5c065069133b16aaf5ae5d98a9d6d20eb51f` (clean worktree)
Clone heads: BehaviorTree.CPP `4630e066`, ccache `ddd9437c`, abseil `e65a8cbf`,
log4cxx `a345ec7d`, brpc `0f820848`, esphome `9327d011`.

Single-site FIRD reruns: `/mnt/optane/tmp/bifrost-fird/cpp-diagnosis/D-reruns/*.jsonl`
Fixtures: `/mnt/optane/tmp/bifrost-fird/cpp-fixtures/D/{R1..R10,O1..O6}` (each is a
git repo so `run-repo --root .` works; `bifrost --root . --tool
get_definitions_by_location` was the fast probe).

---

## 1. Family table

| Family | Mechanism | Count | Witness site | Fixture |
|---|---|---|---|---|
| **R-T** | Inherited-member lookup returns nothing when the **owner class is a class template**. Own members and explicit `Base::m()` still resolve. | 19 | `ccache/src/third_party/tl-expected/tl/expected.hpp:1638` `this->construct(*rhs)` | `D/R10/{w,x,y,z}.h`, `D/R9/t.h` |
| **R-P** | Parse damage in the **declaring header**: the class node is lost, or the class body is truncated, or the enclosing `namespace` node is demoted so header FQNs lose their namespace while the `.cpp` definitions keep it. | 10 | `esphome/components/dsmr/dsmr.cpp:107` `this->uart_read_chunk_()`; `abseil/absl/synchronization/mutex.cc:1541` `this->LockSlow(...)` | `D/R8`, `D/R7`, `D/R9` (T7), `D/R5` (real-file bisect) |
| **O-U** | A member **`using Base::name;` declaration is not merged into the derived overload set**, so C++ name hiding is applied where the source explicitly disabled it. | 2 | `log4cxx/src/main/cpp/fmtlayout.cpp:66` `activateOptions();` | `D/O5` |
| **O-M** | A **macro qualifier before a constructor** makes the extractor mint a spurious callable `Owner.<last-mem-init-name>` with the constructor's arity; it then shadows the real data member. | 1 | `ccache/src/third_party/fmt/fmt/base.h:1829` `grow_(*this, new_capacity)` | `D/O6` |
| **O-D** | **Constructor / destructor declarator seeded as a reference.** Not a reference site at all; the engine's declaration guard also misses it, so the kind is wrong too. | 4 | `brpc/src/butil/third_party/rapidjson/filewritestream.h:74` `FileWriteStream(const FileWriteStream&);` | `D/O1` (negative control) |
| **O-S** | Unqualified `swap` whose true target is `std::swap`, brought in by a function-body `using std::swap;` that is ignored; the walk binds the enclosing member `swap(expected&)` and rejects it on arity. | 1 | `BehaviorTree.CPP/include/behaviortree_cpp/contrib/expected.hpp:2140` | — (read-only analysis) |
| **L-B** | A **bare macro invocation at namespace scope** (`ABSL_NAMESPACE_BEGIN`, no trailing `;`) breaks bare-call resolution inside the nested namespace: a bodyless callee is reported as a *local value*, a callee with a body as *no indexed definition*. | 1 | `abseil/absl/container/internal/raw_hash_set.h:907` `EmptyGeneration()` | `D/O4/{v1,v2,v3,v4}.h` |

19 + 10 = 29 (`unsupported_cpp_receiver`); 2 + 1 + 3 + 1 = 7 (`no_applicable_overload`);
1 + 1 = 2 (`local_variable_reference`). Total 38.

Per-diagnostic split of `no_applicable_overload`: O-U 2, O-M 1, O-D 3
(properties.h `~Properties()`, filewritestream.h, bit_gen_ref.h), O-S 1.
Per-diagnostic split of `local_variable_reference`: O-D 1 (smtpappender.h ctor
declaration), L-B 1 (abseil `EmptyGeneration`).

**All 38 reproduce.** Eight representative sites were rerun through
`run-repo --path/--start-byte/--end-byte --cache-mode ephemeral`; every one
returns the same `forward_status=no_definition` and the same diagnostic kind.
Under the default `index` probe seed they classify as **`inconclusive`**, not
`missing` — the `missing` label is produced only by the `census` probe seed.

---

## 2. Family R-T — inherited member lookup dies on class-template owners (19 sites)

### Members

| Repo | Path | Line | Token | Enclosing owner |
|---|---|---|---|---|
| ccache | `src/third_party/tl-expected/tl/expected.hpp` | 979, 1096, 1638, 1653, 1667, 1669, 1681 | `construct_with`, `assign`, `construct` x4, `construct_error` | `expected_copy_base<T,E,false,true>`, `expected_move_assign_base<T,E,false>`, `template<class T,class E> class TL_EXPECTED_NODISCARD expected` |
| ccache | `src/third_party/fmt/fmt/base.h` | 1903, 1959, 2036 | `clear`, `set`, `size` | `template<...> class iterator_buffer : public Traits, public buffer<T>`, `counting_buffer` |
| BehaviorTree.CPP | `include/behaviortree_cpp/contrib/expected.hpp` | 927, 934, 961, 979, 980, 1023(x2), 1024 | `construct_value`, `construct_error`, `has_value` | `class storage_t<T,E,true,true> : public storage_t_impl<T,E>` and siblings (partial specializations) |
| esphome | `esphome/components/sensor/filter.h` | 365 | `value_matches_any_` | `template<size_t N> class FilterOutValueFilter : public ValueListFilter<N>` |

### Perturbation matrix (`D/R10`)

`x.h`, `y.h`, `z.h`, `w.h`. Base `struct XB { void xm() {} };` in every row.

| # | Derived | Base | Reference | Verdict |
|---|---|---|---|---|
| 1 | `struct XD1` | `XB` | `this->xm()` | **resolved** |
| 2 | `struct D6` | `B2<int>` | `this->construct()` | **resolved** |
| 3 | `template<class T> struct XD2` | `XB` (non-template base!) | `this->xm()` | `unsupported_cpp_receiver` |
| 4 | `template<class T> struct D9` | `B2<int>` (concrete) | `this->construct()` | `unsupported_cpp_receiver` |
| 5 | `template<class T> struct D2` | `B2<T>` (dependent) | `this->construct()` | `unsupported_cpp_receiver` |
| 6 | `template<class T> struct D11` | `public B2<T>` | `this->construct()` | `unsupported_cpp_receiver` |
| 7 | `template<class T> struct D12` | `B2<T>` | `B2<T>::construct()` (qualified) | **resolved** |
| 8 | `template<class T> struct S1..S5` | none | `this->own()` (own member) | **resolved** |
| 9 | `template<class T> struct WD2 : WB` | `WB` | bare `wconstruct()` (no `this->`) | `no_indexed_definition` |
| 10 | `struct ZD2 : ZB` via `ZD2& r` | `ZB` | `r.zbm()` | **resolved** |
| 11 | `template<class T> struct ZD : ZB` via `ZD<int>& r` | `ZB` | `r.zown()` (own) | **resolved** |
| 12 | same | `ZB` | `r.zbm()` (inherited) | `unsupported_cpp_receiver` |

Causal factor is exactly **"the resolved owner CodeUnit is a class template"**.
Non-causal: whether the base is a template, whether the base arguments are
dependent, whether the receiver is `this` or a typed variable, `public`/`private`
inheritance, `class` vs `struct`, `typename` vs `class` vs `int` template
parameters, partial specialization.

Rows 8/11 prove the owner *is* resolved (own members are found through the same
owner); row 12 isolates the base walk. Row 9 shows the bare-call path fails the
same way, so this is not receiver-specific.

### Code trace

* `cpp_member_lookup` — `crates/bifrost-analysis/src/analyzer/usages/get_definition/cpp.rs:5099-5118`
  (direct members first, then `cpp_inherited_member_candidates`).
* `cpp_inherited_member_candidates` — `cpp.rs:5311-5354`; the only base source is
  `cpp_direct_base_types` at line 5328.
* `cpp_direct_base_types` — `cpp.rs:5544-5580`. It recovers bases by **string
  splitting the class's rendered signature**:

  ```rust
  let signature = unit.signature().map(str::to_string)
      .or_else(|| analyzer.get_source(unit, false));
  let Some((_, bases)) = signature.split_once(':') else { return Vec::new(); };
  let bases = bases.split('{').next().unwrap_or(bases);
  ```

  For a class template the rendered head carries the `template <...>` prefix
  (`render_cpp_type_signature`, `crates/bifrost-cpp/src/declarations.rs:4522-4539`,
  which prepends `template {template_signature} `).
* The graph's supertype edges are **correct** for template classes:
  `bifrost --tool get_symbol_ancestors --args '{"symbols":["ns.D10","ns.D2"]}'`
  in `D/R10` returns `ns.B1` / `ns.B2` for both the template and non-template
  derived classes. `extract_cpp_supertypes` (`declarations.rs:3572-3593`) reads
  the `base_class_clause` from the AST. So the structured fact exists and only
  this signature re-parse loses it.

  I did **not** finish localising which of "signature string has no usable `:`"
  vs "the owner unit chosen for a template class is a second unit whose rendered
  signature lacks the base clause" is the actual failure; both are consistent
  with the observed behaviour and both live behind `cpp_direct_base_types`.
  Confirming this needs a unit test at that function (the harness cannot print
  `unit.signature()`).

* Diagnostic mislabel: `resolve_cpp_field` — `cpp.rs:4408-4421` — emits
  `unsupported_cpp_receiver` whenever `candidates.is_empty()`, *including* when
  the receiver resolved perfectly and only the member walk came up empty. Every
  R-T site is such a case. The same conflation exists in the bounded provider at
  `cpp.rs:744-757`.

### Recommendation

**Straightforward generalized fix.** Replace the signature-string base recovery
in `cpp_direct_base_types` with the analyzer's structured supertype edges (the
ones `get_symbol_ancestors` already serves), falling back to the signature parse
only where no edge exists. That removes a string mini-parser the project
explicitly prohibits *and* fixes 19 of the 38 sites in one change. Split the
`unsupported_cpp_receiver` diagnostic into "receiver type unresolved" versus
"member not found on <owner>" at the same time; the current message actively
misdirected this bucket's triage.

---

## 3. Family R-P — parse damage in the declaring header (10 sites)

Two downstream symptoms, one root class of cause:

* **(a) the member declaration is never indexed** → `this->m()` has no candidate;
* **(b) the header class keeps its name but loses its namespace** (`Dsmr` instead
  of `esphome::dsmr.Dsmr`) while the `.cpp` out-of-line definitions are indexed
  as `esphome::dsmr.Dsmr.<member>` → the FQN-keyed member lookup
  `format!("{}.{}", owner.fq_name(), member)` (`cpp.rs:5288`) can never match.

### Isolated triggers

| Trigger | Real witness | Fixture | Effect |
|---|---|---|---|
| **P1** attribute-like macro invocation preceding a member *declaration* (no body) | `esphome/components/dsmr/dsmr.h:100` `ESPDEPRECATED("...", "2026.2.0")` before `void set_decryption_key(...)` | `D/R8/v.h` `VB` | class body truncated from that point; enclosing namespace demoted |
| **P2** attribute macros between `class` and the class name | `abseil/absl/synchronization/mutex.h:163` `class ABSL_LOCKABLE ABSL_ATTRIBUTE_WARN_UNUSED Mutex {` | `D/R9/t.h` `class ATTR_A ATTR_B D7` | **no class unit at all** (`get_summaries` on mutex.h lists `absl.MutexLock`, `absl.Condition`, … but no `absl.Mutex`) |
| **P3** qualified or variadic-`friend` declaration in a class body | (fixture-only) `friend void ::ns::free_fn(int);`, `template<typename... Ts> friend class Other;` | `D/R7/v.h` `VB`, `VC` | namespace demoted from that class onward |
| **P4** preprocessor conditional inside the base-class clause | `esphome/components/remote_transmitter/remote_transmitter.h:34-40` (`#if defined(USE_ESP32) …` between base specifiers) | — | class lost; header extraction stops at line 31 of 105 |
| **P5** (not isolated) | `esphome/components/wifi/wifi_component.h:423` `class WiFiComponent final : public Component` | — | class node lost, members flattened: `wifi_mode_` is indexed as `esphome::wifi.wifi_mode_` at :730, not `esphome::wifi.WiFiComponent.wifi_mode_` |
| **P6** (not isolated) | `esphome/core/scheduler.h:24` `class Scheduler` | — | no `esphome.Scheduler` class unit; members flattened (`esphome.set_timeout`, …); extraction stops at line 170 of 753 |

### Perturbation results

**P1, real file** (`D/R5`, header-only copy of `esphome/components/dsmr/dsmr.h`,
line-deletion sweep over lines 85-100, `bis4.py`):

```
del  99: '  // Remove before 2026.8.0'                 -> ns=False cls=['Dsmr']            urc=False last=85
del 100: '  ESPDEPRECATED("Use \'decryption_key\'...'  -> ns=True  cls=['esphome::dsmr.Dsmr'] urc=True  last=151
```

Deleting exactly one line — the `ESPDEPRECATED(...)` macro invocation — restores
the namespace prefix on every symbol in the file, restores the class FQN, indexes
`uart_read_chunk_`, and extends extraction from line 85 to line 151. No other
single-line deletion in that window does so.

**P1, reduced** (`D/R8/v.h` + `v.cpp`, three classes, only the member after the
macro differs):

| Class | Shape | Header FQN | `this->helper_()` in `.cpp` |
|---|---|---|---|
| `VA` | `DEPRECATED("x","1.0")` then `void old_api() { return; }` (**definition**) | `ns.VA` | **resolved** |
| `VB` | `DEPRECATED("x","1.0")` then `void old_api();` (**declaration**) | `VB` (namespace lost) | `no_definition` |
| `VC` | no macro | `VC` (already downstream of VB's damage) | `no_definition` |

The macro is harmless before a member *definition* and fatal before a member
*declaration*. Damage is **positional**: it demotes the enclosing
`namespace_definition`, so every class *after* the offending one in the same file
also loses its namespace (VC is collateral).

**P2/P3** (`D/R9`, `D/R7`): `class ATTR_A ATTR_B D7 { ... }` produces no class
unit; `friend void ::ns::free_fn(int);` inside `VB` demotes the namespace for
`VB`, `VC`, `VD`, `VE`. An anonymous `union` member inside a nested struct does
**not** trigger it — verified in isolation in `D/R11`, where `ns.VD` and its
namespace survive and `this->helper_()` resolves. (`D/R11` does expose an
unrelated minor gap: the anonymous union's own members `a` and `b` are not
indexed, only the sibling field `c`.)

### Recommendation

**Escalate — extractor-side, not resolver-side.** The resolver behaves correctly
given a damaged index. The work belongs in `crates/bifrost-cpp/src/declarations.rs`
recovery: it already has macro-recovery paths
(`recover_exported_class_function_definition`, `cpp_sentinel_reparsed_class`,
`declarations.rs:5649` documents the `ERROR(class, type_identifier,
base_class_clause?, "{", members...)` shape), so the shapes above should be added
to that recovery set rather than treated as new machinery:

1. `MACRO(args)` immediately preceding a member declarator (P1);
2. attribute macros between the `class`/`struct` keyword and the name (P2) — this
   one alone recovers `absl::Mutex`, the largest single class in abseil;
3. qualified / variadic `friend` declarations (P3);
4. a `#if`/`#endif` region inside a `base_class_clause` (P4).

A cheap, high-value invariant to add while doing this: **a class body whose
extraction stops before its closing brace, or a `namespace_definition` that is
demoted, should be reported** (a file-level parse-recovery counter in the
differential's `file_errors`), because today the damage is completely silent —
`esphome/core/scheduler.h` loses 583 of 753 lines with no signal at all.

---

## 4. Family O-U — `using Base::member;` ignored (2 sites)

`log4cxx` declares the 0-argument overload in the base and re-exposes it in every
derived class:

* `src/main/include/log4cxx/spi/optionhandler.h:55/64` — `void activateOptions();`
  and `virtual void activateOptions(helpers::Pool&) = 0;`
* `src/main/include/log4cxx/layout.h:132` — `using spi::OptionHandler::activateOptions;`
* `src/main/include/log4cxx/fmtlayout.h:254` — `using Layout::activateOptions;`
  then `void activateOptions( LOG4CXX_ACTIVATE_OPTIONS_FORMAL_PARAMETERS ) override;`
* call site `src/main/cpp/fmtlayout.cpp:66` — `activateOptions();` (arity 0)

`cpp_inherited_member_candidates` (`cpp.rs:5324-5352`) implements C++ name hiding
correctly — it stops at the first derivation level that declares the name — but
nothing re-adds the overloads a `using`-declaration un-hides. The level that
answers declares only the 1-argument override, the arity filter empties it,
`had_member_callable` is true, and `cpp.rs:4034-4040` reports
`no_applicable_overload`.

### Perturbation (`D/O5`)

| Case | Shape | Verdict |
|---|---|---|
| `Sub : Layout`, `Layout` has `using OptionHandler::act;` + `void act(ACT_PARAMS) override;` | bare `act()` | `no_applicable_overload` — **defect** |
| `Sub : Layout`, same but with a real `Pool& p` parameter instead of the macro | bare `plain()` | `no_applicable_overload` — **defect** (so the macro-parameterised arity is *not* the cause) |
| `Sub2 : NoUsing`, no `using`-declaration | bare `act()` | `no_applicable_overload` — **correct**; C++ really does hide the base overloads here |
| `l->act()` through a `Layout*` receiver | typed receiver, arity 0 | resolved |

The negative control matters: the fix must key on the `using`-declaration, not
loosen the arity filter.

### Recommendation

**Straightforward generalized fix.** During the base walk, when a level declares
the name, also collect any `using <Base>::<name>;` declarations on that level and
continue into the named base for that name only, merging both sets before the
arity filter. Sketch: index member `using`-declarations as a per-class
`(name -> qualified base scope)` map in `crates/bifrost-cpp/src/declarations.rs`,
and consult it in `cpp_inherited_member_candidates` before returning `direct`.

Independently: the same walk should distinguish *"a nearer level declared this
name and hid the base"* from *"nothing declares it"* in the diagnostic message —
`no_applicable_overload` is currently emitted for both.

---

## 5. Family O-M — spurious callable minted from a constructor member-initializer (1 site)

`ccache/src/third_party/fmt/fmt/base.h`:

```
1769:  using grow_fun = void (*)(buffer& buf, size_t capacity);
1770:  grow_fun grow_;                       // data member
1775:  FMT_MSC_WARNING(suppress : 26495)
1776:  FMT_CONSTEXPR buffer(grow_fun grow, size_t sz) noexcept
1776:      : size_(sz), capacity_(sz), grow_(grow) {}
1829:  if (new_capacity > capacity_) grow_(*this, new_capacity);   <-- site
```

The index contains **three** entries for `grow_`:

```
classes  1769  buffer$grow_fun | using grow_fun = void (*)(buffer& buf, size_t capacity);
functions 1776 buffer.grow_    | template <typename T> FMT_MSC_WARNING(suppress : 26495) FMT_CONSTEXPR buffer(grow_fun grow, size_t sz) noexcept : size_(sz), capacity_(sz), grow_(grow) {};
fields    1770 buffer.grow_    | grow_fun grow_;
```

The constructor was indexed under the name of its **last member-initializer**,
with the constructor's own arity (1). The call has arity 2, the arity filter
empties the callable set, `had_member_callable` is true → `no_applicable_overload`.

### Perturbation (`D/O6/c.h`)

| Class | Constructor preamble | Indexed units | `grow_(*this, n)` |
|---|---|---|---|
| `BufA` | `MSC_WARNING(suppress : 26495)` + `CONSTEXPR` | field `BufA.suppress` (bogus) + function `BufA.grow_` (bogus); **no** `BufA.BufA` | `no_applicable_overload` |
| `BufB` | `CONSTEXPR` only | function `BufB.BufB` **and** bogus function `BufB.grow_` | `no_applicable_overload` |
| `BufC` | no macro | function `BufC.BufC` only | `no_indexed_definition` |

Any unrecognised macro qualifier in front of the constructor is sufficient; the
attribute macro additionally destroys the constructor's identity. `BufC` shows
the residual, much smaller gap: **calling a function-pointer data member is not
resolved to the field**.

### Recommendation

**Straightforward fix, extractor-side.** A `field_(args)` entry in a
`field_initializer_list` must never mint a callable CodeUnit; the recovery path
that handles a macro-qualified constructor should take the *declarator* name, not
the last initializer. Add the `BufC` shape as a separate, smaller follow-up:
a bare call whose name resolves to a member field of function-pointer type should
answer with the field, not `no_indexed_definition`.

---

## 6. Family O-D — constructor/destructor declarators seeded as references (4 sites)

| Repo | Site | Source |
|---|---|---|
| log4cxx | `src/main/include/log4cxx/helpers/properties.h:55` | `~Properties();` |
| log4cxx | `src/main/include/log4cxx/net/smtpappender.h:98` | `SMTPAppender(LOG4CXX_NS::helpers::Pool& p);` |
| brpc | `src/butil/third_party/rapidjson/filewritestream.h:74` | `FileWriteStream(const FileWriteStream&);` |
| abseil | `absl/random/bit_gen_ref.h:80` | `BitGenRef(const BitGenRef&) = default;` |

These are **declaration sites, not reference sites**. Per the runbook's triage
step 2 ("verify the focused token is the referenced terminal, not a … declaration")
they should never have been seeded. This is a **census-grading fix**, not a
resolver defect.

Two secondary observations:

* The engine's declaration guard `cpp_is_non_reference_declaration_name` is
  applied only in the `Identifier` branch (`cpp.rs:272-278` and `cpp.rs:330`),
  never for a node that tree-sitter recovered as a call. In a clean fixture
  (`D/O1/o.h`) the same declarations `F();`, `F(const F&);`, `~F();` are correctly
  answered `declaration_or_import_site`; in the real files they are not, and the
  emitted kinds are `no_applicable_overload` / `local_variable_reference`.
* In `filewritestream.h` the declaration at :74 is **absent** from the file's
  indexed elements while `operator=` at :75 is present, i.e. tree-sitter did not
  parse :74 as a declaration in that context. Same for `bit_gen_ref.h:80`, whose
  class body is full of `detector<Trait, std::void_t<...>, Args...>` template
  machinery.

### Recommendation

**Census-grading fix (primary).** Reject a focused token that is a constructor or
destructor declarator name in a class body before it becomes a tier-1 gap. The
existing `declaration_or_import_site` predicate is the right notion; the census
seeder should apply the same test the `Identifier` branch does, and it must not
depend on the parse recovering the node as a declaration.

**Small engine fix (secondary).** Run `cpp_is_non_reference_declaration_name` (or
an equivalent structural check for "this identifier is the declarator name of a
constructor/destructor in a class body") on the `Call` branch too, so the kind
reported is `declaration_or_import_site` rather than a misleading overload or
locality claim.

---

## 7. Family O-S — `swap` through a function-body `using std::swap;` (1 site)

`BehaviorTree.CPP/include/behaviortree_cpp/contrib/expected.hpp:2140`:

```
2137:        using std::swap;
2140:        else if ( ! bool(*this) && ! bool(other) ) { swap( contained.error(), other.contained.error() ); }
```

The enclosing member is itself `swap( expected & other )` (arity 1). The intended
target is `std::swap` (2 arguments, external, not indexed in this workspace). The
walk binds the enclosing class's member `swap`, arity-rejects it, and reports
`no_applicable_overload`.

The census seeded this because a same-file free function
`swap( expected<T,E>&, expected<T,E>& )` exists at :3413 — arity 2, but the wrong
parameter types (the arguments here are `error_type&`).

### Recommendation

**Census-grading fix plus a small engine fix.** The engine cannot resolve
`std::swap` (no indexed declaration), so the honest verdict is an
unresolved-boundary / `unproven` answer, not `no_applicable_overload`. Two
changes: (1) honour function-body `using <ns>::<name>;` declarations when routing
a bare call, and when the named scope is not indexed answer
`boundary_unchecked` — `cpp_unresolved_include_boundary` at `cpp.rs:3955-3962`
already has this shape for the field path; (2) the census should not treat an
arity-only same-file name match as a tier-1 gap when a lexically nearer
`using`-declaration names a different scope.

---

## 8. Family L-B — bare macro at namespace scope poisons bare-call resolution (1 site)

`abseil/absl/container/internal/raw_hash_set.h`:

```
 261: using GenerationType = uint8_t;
 363: GenerationType* EmptyGeneration();          // declaration, no body
 907:   const GenerationType* generation_ptr_ = EmptyGeneration();   <-- site
```

`EmptyGeneration` is indexed correctly — declaration at `raw_hash_set.h:363` and
definition at `raw_hash_set.cc:149`. The engine nevertheless answers
`local_variable_reference: "EmptyGeneration is a local C++ value"`, which comes
from `bindings.is_shadowed(name)` at `cpp.rs:3986-3991`.

**Necessary condition, real file** (`D/O3/bis3.py`, whole file preserved, single
lines blanked, site kept at 907):

```
orig                 -> local_variable_reference
blank line 363       -> no_indexed_definition      (the declaration is what is being mis-bound)
blank lines 340-370  -> no_indexed_definition
blank line 265       -> local_variable_reference   (unrelated)
blank lines 149-160  -> local_variable_reference   (unrelated)
```

**Minimal reduction** (`D/O4`, 2x2 matrix; all four index identically —
`ns::internal.PtrDecl` is present in every case, so this is purely a resolve-time
binding decision):

| bare macro at outer namespace scope | callee has a body | verdict |
|---|---|---|
| no | yes | **resolved** (correct) |
| no | no | `no_definition` ("candidates contain no implementation body") |
| yes | yes | **`no_indexed_definition`** — wrong |
| yes | no | **`local_variable_reference`** — wrong |

`v2.h`/`v3.h` differ from `v1.h`/`v4.h` by exactly one line: `BARE_MACRO` (an
identifier on its own line with no trailing semicolon, the shape of
`ABSL_NAMESPACE_BEGIN`) at the enclosing namespace scope, with the declarations
inside a nested `namespace internal { }`.

### Recommendation

**Straightforward generalized fix.** A bare macro invocation at namespace scope
is a very common C++ shape (`ABSL_NAMESPACE_BEGIN`, `LOG4CXX_NS_BEGIN`,
`RAPIDJSON_NAMESPACE_BEGIN`, `BEGIN_NAMESPACE_X`). Two defects fall out of it and
both should be fixed: (a) a namespace-scope function declaration must never be
recorded as a value binding by the local-binding collector — a binding used by
`is_shadowed` should require an actual local/parameter/field declarator; (b) the
same macro must not prevent an indexed nested-namespace callable from being found
by a bare call (`v3` row).

This is one site in this bucket but the shape is workspace-wide in abseil, so it
is very likely to be over-represented in other census buckets.

---

## 9. Falsified premises in the brief

1. **"Repo clones: `/mnt/T9/repo-clones/cpp/<slug>`."** False. The clone root is
   flat: `/mnt/T9/repo-clones/<slug>` (e.g. `/mnt/T9/repo-clones/ccache__ccache`).
   There is no `cpp/` level.
2. **"`unsupported_cpp_receiver` (29) … names like construct/construct_error/
   construct_value and esphome trailing-underscore methods."** The naming is not
   the cluster. The 29 sites are **two disjoint root causes** with no shared
   resolver seam: 19 are class-template inherited lookup (including one esphome
   trailing-underscore site, `filter.h:365 value_matches_any_`) and 10 are header
   parse damage (including two non-underscore abseil sites, `LockSlow` /
   `UnlockSlow`). Grouping by diagnostic kind or by identifier spelling would have
   produced the wrong fix.
3. **"`local_variable_reference` (2): determine whether the census should even
   seed these (a local variable is not a cross-file reference…)."** Neither site
   references a local variable. One (`smtpappender.h:98`) is a constructor
   declaration — the census should indeed not seed it, but the local-variable
   framing is wrong; the other (`raw_hash_set.h:907`) is a real reference to a
   real, correctly indexed free function that the resolver mislabels. So this is
   *not* a #1783/#1784-style seeding/grading bug on both counts.
4. **"`no_applicable_overload` with 7 sites: determine whether the overload filter
   is wrongly rejecting a viable overload (defect) or the call genuinely has no
   matching indexed overload (correct answer)."** The dichotomy is incomplete.
   Actual split: 3 are not calls at all (declarators), 1 rejects an overload the
   extractor invented out of a member-initializer, 2 are the `using`-declaration
   gap (the overload *is* viable and *is* indexed, just not merged), 1 targets an
   unindexed `std::swap`. Only the last would fit "genuinely no matching indexed
   overload", and even there the correct verdict is an import boundary, not
   `no_applicable_overload`.
5. **Implicit: these are `missing` sites.** Under the runner's default `index`
   probe seed all eight rerun witnesses classify as **`inconclusive`**
   (`forward_status=no_definition`), not `missing`. The `missing` classification
   in the census file comes from the `census` probe seed's tier-1 rule
   ("same-file declaration exists but forward lookup returned no_definition").
   That matters for grading: 5 of the 38 (family O-D, plus O-S) are sites where
   the tier-1 rule fired on a same-file *declarator* or a same-name-wrong-type
   free function.

Not falsified: the bucket counts (29/7/2 and ccache 10 / esphome 9 /
BehaviorTree.CPP 8 / abseil 2) are exact, and every site reproduces at the pinned
heads with the current binary.

---

## 10. Recommended disposition summary

| Family | Sites | Disposition |
|---|---|---|
| R-T | 19 | **Fix (generalized, one seam).** Read structured supertype edges in `cpp_direct_base_types` instead of re-parsing the rendered class signature. Also split the `unsupported_cpp_receiver` diagnostic. |
| R-P | 10 | **Escalate to the C++ extractor.** Four isolated macro/preproc recovery shapes (P1-P4) plus two un-isolated esphome headers (P5, P6). Add a parse-damage signal so silent class truncation is detectable. |
| O-U | 2 | **Fix (generalized).** Merge member `using Base::name;` into the derived overload set during the base walk. Negative control (`NoUsing`) must stay `no_applicable_overload`. |
| O-M | 1 | **Fix (extractor).** Never mint a callable from a `field_initializer_list` entry; take the declarator name for a macro-qualified constructor. Follow-up: resolve a call through a function-pointer data member. |
| O-D | 4 | **Census-grading fix.** Do not seed constructor/destructor declarators. Secondary: apply the declaration guard on the `Call` branch too. |
| O-S | 1 | **Census-grading fix + small engine fix.** Honour function-body `using ns::name;`; answer an unindexed target as a boundary, not `no_applicable_overload`. |
| L-B | 1 | **Fix (generalized).** A namespace-scope function declaration must not become a shadowing value binding; a bare namespace-scope macro must not hide a nested-namespace callable from a bare call. |

Net: **23 of 38** sites (R-T + O-U + O-M + L-B) are fixed by four bounded,
generalized resolver/extractor changes. **10** need extractor parse recovery
(R-P). **5** are census over-claims (O-D + O-S) that should be graded out rather
than fixed in the resolver.
