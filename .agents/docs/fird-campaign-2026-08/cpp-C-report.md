# FIRD cpp wave — bucket C diagnosis

**Bucket:** 178 sites, `classification=missing`, note
`forward-resolved site is absent from the complete inverse result`.

**Evidence base**

| item | value |
| --- | --- |
| Bifrost head | `458a5c065069133b16aaf5ae5d98a9d6d20eb51f` (clean; equals the census head) |
| runner | `/mnt/optane/bifrost-fird/target/release/bifrost_reference_differential` |
| census | `/mnt/optane/tmp/bifrost-fird/cpp-census-bba1c5da.jsonl` |
| site list | `/mnt/optane/tmp/bifrost-fird/cpp-diagnosis/C-inverse-miss-resolved.json` |
| family assignment | `/mnt/optane/tmp/bifrost-fird/cpp-diagnosis/C-families.json` |
| exact reruns | `/mnt/optane/tmp/bifrost-fird/cpp-diagnosis/C-probes/p01..p10.jsonl` |
| fixtures | `/mnt/optane/tmp/bifrost-fird/cpp-fixtures/C/<family>/` |
| clones | `/mnt/T9/repo-clones/<slug>` (not `/mnt/T9/repo-clones/cpp/<slug>` — the brief's path is wrong; all clones are clean at their pinned heads) |

Census scope checks for the six dominant repositories: `candidate_limit_exceeded_files=0`,
`file_errors=0` everywhere. `skipped_targets`/`target_truncated_sites` are non-zero for
qpid-proton, brpc and libzmq, but the runner classifies those sites separately
(`site omitted by per-target usage file limit`), so no site in this bucket is a
truncation artifact.

---

## 1. Falsified premises

The brief's central hypothesis is **falsified**.

1. **"The C++ inverse only handles callables"** / **"the inverse usage scan for an alias
   declaration never emits type-reference usage sites"** — FALSE.
   Fixture `cpp-fixtures/C/typedef-struct/` (`struct Impl_s`, `typedef struct Impl_s Impl_t`,
   `typedef int Plain_t`, `using Alias_t = Impl_s`): `scan_usages_by_location` on **every**
   one of the four declarations returns its type-reference sites, all proven
   (`unproven_hits=0`). The underlying struct's result is additionally alias-transitive:
   `Impl_s` reports the `Impl_t*` and `Alias_t*` parameter sites as its own.

2. **"Forward resolves a type reference to its typedef and the inverse for that alias emits
   nothing"** — FALSE as a mechanism. In fixtures the alias target's inverse is complete.
   Where the real repositories fail, the *same alias* is found on some lines and missed on
   others in the same file, so the alias-ness is not the discriminator.

3. **"The striking name pattern (XXH3_state_t, LevelPtr, logchar) means this is a type-alias
   bug"** — FALSE. The name distribution is an artifact of two unrelated per-repository
   mechanisms:
   * log4cxx's alias names are missed because **no declaration in any header is visible from
     `src/main/cpp/*.cpp` at all**. The plain class `helpers::Pool` (6 sites) and the plain
     classes `Writer`, `WriterAppender`, `DatagramPacket`, `JSONLayout` are missed by exactly
     the same rule; they are not aliases.
   * The xxhash names are missed because of a macro-induced parse recovery. Within the same
     header, `XXH3_freeState(XXH3_state_t* statePtr)` is present in the inverse result
     (classified `unproven`), while
     `XXH3_64bits_reset(XXH_NOESCAPE XXH3_state_t* statePtr)` is absent. The discriminator is
     the `XXH_NOESCAPE` token, not the typedef. 44 of 44 c-blosc2 sites have an all-caps
     macro token immediately before the missing token; 0 of 44 lack one.

4. **"The operator& sample suggests a family: address-of-member in `.def()` bindings"** —
   half true. The family is real but pybind is irrelevant: a plain
   `static BinOp p = &Bitmap::operator&;` in a two-file fixture reproduces it, while
   `&Bitmap::plainMethod` on the adjacent line is found. The discriminator is the
   `operator@` name, not the `.def()` context.

5. **"5 `unproven_cpp_link_unit` sites — same mechanism or a separate link-unit-proof gap?"**
   Those diagnostics sit on the **forward** result, not the inverse. All 5 land in the
   residual bucket (BehaviorTree 4, libzmq `get_ctx` 1) and in all 5 the forward target group
   contains both a `.cpp` definition and a synthetic `.h` declaration. They are neither of the
   large families; see §4.

6. Minor: the brief's repo spread lists log4cxx 59 / c-blosc2 44 / ccache 22 / qpid 15 /
   libzmq 14 / brpc 13 — those counts are correct.

---

## 2. Family table

| # | family | count | mechanism | witness (exact rerun) | fixture |
| --- | --- | --: | --- | --- | --- |
| A | `A_no_quoted_include_visibility` | **60** | Include visibility for C++ ignores angle-bracket `#include <...>`. A `.cpp` that includes its own project headers with `<>` sees **no** header declaration, so the inverse never attributes any of its sites to a header target. Forward still resolves, because the forward/resolver side uses the angle-aware `include_paths`. | log4cxx `src/main/cpp/logger.cpp` 4505-4513 → `p03-log4cxx-levelptr.jsonl` | `cpp-fixtures/C/angle-include/`, `cpp-fixtures/C/inc-matrix/` |
| B | `B_macro_decorated_param_type` | **44** | `f(MACRO T* p)`: tree-sitter-cpp recovers by inserting a zero-width `::`, so the real type `T` becomes the `scope` (`namespace_identifier`) of a `qualified_identifier` whose `name` is the declarator. The existing recovery hook declines inside `parameter_declaration`, so the inverse emits no candidate. | c-blosc2 `plugins/codecs/ndlz/xxhash.h` 42646-42658 → `p01-xxh3-macro.jsonl` (control: 42340-42352 → `p02-xxh3-plain.jsonl`, `unproven`, hit present) | `cpp-fixtures/C/xxh-shape/`, `cpp-fixtures/C/macro-prefixed-type/` |
| C | `C_phantom_macro_member_decl` | **10** | `PN_CPP_EXTERN std::string user() const;` makes the declaration extractor mint a **phantom field named `std`** in the enclosing class. The forward navigates the `std` qualifier token to that phantom; the phantom has no usages, so the site is "missing". Forward target is semantically wrong. | qpid `cpp/include/proton/message.hpp` 2503-2506 → `p06-qpid-std.jsonl` | reproduced directly on the clone (`search_symbols` shows `proton.message.std` kind `field`, signature `PN_CPP_EXTERN std;`, and `proton.message.friend`) |
| D | `D_qualified_outofline_dtor_name` | **10** | `ns::Class::~Class ()`: `out_of_line_destructor_type_reference` requires the `name` child of the outer `qualified_identifier` to be a `destructor_name`. With three components the `name` child is another `qualified_identifier`, so the destructor-name token is never recorded. Two-component `Class::~Class` inside a `namespace ns { }` block works. | libzmq `src/pair.cpp` 340-346 → `p04-zmq-dtor.jsonl` | `cpp-fixtures/C/dtor-matrix/` |
| E | `E_operator_member_pointer` | **4** | `&Class::operator@` as a member-pointer value is not recorded; `&Class::plainMethod` on the next line is. | LMCache `csrc/storage_manager/pybind.cpp` 3044-3053 → `p07-lmcache-opand.jsonl` | `cpp-fixtures/C/misc-matrix/` |
| G | `G_inherited_scope_nested_type` | **4** | Inside `class D : public Base::Inner`, a reference `Inner::Nested` reaches `Inner` through the base class. The inverse records the **qualifier** `Inner` but not the terminal nested type `Nested`; the fully qualified `Base::Inner::Nested` on an adjacent line is recorded. | ccache `src/ccache/storage/remote/httpstorage.cpp` 1483-1492 → `p09-ccache-attr.jsonl` | `cpp-fixtures/C/inherit-nested/` |
| F | `F_qualified_function_value` | **3** | A qualified function name used as a *value* without `&` (`std::bind(Conf::configure, r)`, `p = InputMessenger::OnNewMessages;`, `f(alloc::call_dec_ref, ...)`) is not recorded; the same reference written `&Conf::other` is. | log4cxx `src/main/cpp/logmanager.cpp` 3001-3010 (not rerun individually) | `cpp-fixtures/C/fnaddr/` |
| Z | residual | **43** | see §4 | — | — |

Per-repo distribution:

```
A  log4cxx 58, qpid 1, ccache 1
B  c-blosc2 44
C  qpid 10
D  libzmq 10
E  LMCache 2, qpid 2
G  ccache 4
F  log4cxx 1, brpc 1, libzmq 1
Z  ccache 17, brpc 12, libzmq 4, BehaviorTree 5, esphome 3, qpid 2
```

135 of 178 (76%) are reduced to six mechanisms; four of the six are single-token
perturbations.

---

## 3. Perturbation matrices

### A — angle vs quoted include (`cpp-fixtures/C/angle-include/`)

Layout deliberately mirrors log4cxx: headers under `src/main/include/log4cxx/`, sources
under `src/main/cpp/`. The two `.cpp` files differ **only** in `<...>` vs `"..."`.

| site | forward | inverse contains it |
| --- | --- | --- |
| `src/main/cpp/logger_angle.cpp:4` `const LevelPtr&` (alias) | resolved → `l4.LevelPtr@level.h:6` | **no** |
| `src/main/cpp/logger_angle.cpp:5` `Pool&` (plain class) | resolved → `l4.Pool@level.h:7` | **no** |
| `src/main/cpp/logger_quoted.cpp:4` `const LevelPtr&`, `Pool&` | resolved | yes |
| `src/main/include/log4cxx/logger.h:7,8` (sibling of `level.h`) | — | yes |

Second matrix (`cpp-fixtures/C/inc-matrix/`), one header `inc/pkg/level.h`, five consumers:

| consumer | include spelling | same dir as target | inverse hit |
| --- | --- | --- | --- |
| `q_quote_rel.cpp` | `"inc/pkg/level.h"` | no | yes |
| `q_quote_pkg.cpp` | `"pkg/level.h"` | no | yes |
| `q_angle_pkg.cpp` | `<pkg/level.h>` | no | **no** |
| `q_bare_angle.cpp` | `<level.h>` | no | **no** |
| `inc/pkg/sibling_angle.h` | `<pkg/level.h>` | **yes** | yes |
| `inc/pkg/sibling_bare_angle.h` | `<level.h>` | **yes** | yes |

Transitive quoted includes are fine (`cpp-fixtures/C/transitive/`: `a.h` → `b.h` → `c.cpp`
all recorded), so the defect is specific to the `<>` spelling, not to include depth.

Live confirmation on the clone: `scan_usages_by_location` for `LOG4CXX_NS.LevelPtr` declared
at `src/main/include/log4cxx/level.h:38` returns 124 hits in exactly six files —
`logger.h`, `level.h`, `stream.h`, `appenderskeleton.h`, `hierarchy.h`, `levelchange.h`
(plus two test `.cpp`) — every one a **same-directory sibling** of `level.h`. Not one of the
401 audited `src/main/cpp/*.cpp` files appears, although `logger.cpp` alone contains 35
`LevelPtr` occurrences and does `#include <log4cxx/level.h>` on line 22.

A second-order consequence, visible in the target column of the log4cxx rows: with no header
visible, the forward falls back to a workspace-wide name lookup and picks
`optionconverter.h:28`'s duplicate `typedef std::shared_ptr<Level> LevelPtr;` rather than
`level.h:38`. `scan_usages` for the optionconverter copy returns 2 hits, both inside
optionconverter.h. Similarly `logchar` (three `#if`-guarded typedefs in `logstring.h`)
resolves to line 42 from one file and to `LOG4CXX_NS.UniChar` (line 38, a different name)
from another. Fixing A will not by itself make the forward pick a stable representative for
duplicated/conditional declarations.

### B — macro-decorated declarator (`cpp-fixtures/C/xxh-shape/`)

| line | source | forward | inverse contains it |
| --- | --- | --- | --- |
| 15 | `XXH_PUBLIC_API XXH_errorcode XXH3_freeState(XXH3_state_t* statePtr);` | resolved → `XXH3_state_s` | yes |
| 16 | `XXH_PUBLIC_API void XXH3_copyState(XXH_NOESCAPE XXH3_state_t* dst_state, XXH_NOESCAPE const XXH3_state_t* src_state);` | resolved → `XXH3_state_s` | **no** (both occurrences) |
| 17 | `XXH_PUBLIC_API XXH_errorcode XXH3_64bits_reset(XXH_NOESCAPE XXH3_state_t* statePtr);` | resolved → `XXH3_state_s` | **no** |

The parse (field-annotated dump of the exact xxhash prototypes) is:

```
declaration
  type: type_identifier "XXH_PUBLIC_API"           <- the macro takes the type field
  declarator: function_declarator
    declarator: qualified_identifier               <- return-type case, handled today
      scope: namespace_identifier "XXH_errorcode"
      :: MISSING
      name: identifier "XXH3_freeState"
    parameters: parameter_list
      parameter_declaration
        type: type_identifier "XXH_NOESCAPE"       <- the macro takes the type field
        declarator: qualified_identifier           <- parameter case, NOT handled
          scope: namespace_identifier "XXH3_state_t"   <- the real type reference
          :: MISSING
          name: pointer_type_declarator "* dst_state"
```

Perturbations in `cpp-fixtures/C/macro-prefixed-type/`: with the macro alone on a
prototype (`void macro_alias(NOESC S_t* p);`) the **forward** also fails
(`no_indexed_definition`) — that shape does not occur in the corpus. The corpus shape needs
the extra leading `XXH_PUBLIC_API`/return-type token, which is what puts the parameter's real
type into a recovered `scope` while leaving the forward path able to resolve it.

### D — destructor spelling (`cpp-fixtures/C/dtor-matrix/`)

| definition form | qualifier recorded | destructor name recorded |
| --- | --- | --- |
| `zmq::pair_t::~pair_t ()` (file scope, 3 components) | yes (`8:6`) | **no** |
| `solo_t::~solo_t ()` inside `namespace zmq { }` (2 components) | yes (`4:1`) | yes (`4:10`) |
| `zmq::pair_t::pair_t (int)` (constructor, 3 components) | yes (`3:6`) | n/a (constructor names are not owner references) |

All 10 corpus witnesses are the 3-component form; libzmq writes every out-of-line member at
file scope with a `zmq::` qualifier.

### E / F — reference-as-value (`cpp-fixtures/C/misc-matrix/`, `cpp-fixtures/C/fnaddr/`)

| expression | inverse |
| --- | --- |
| `&Bitmap::plainMethod` | found |
| `&Bitmap::operator&` | **absent** (`verified_absent`, 0 hits) |
| `&Conf::other` | found |
| `Conf::configure` (no `&`, passed to a function) | **absent** (`verified_absent`, 0 hits) |

### G — inherited-scope qualifier (`cpp-fixtures/C/inherit-nested/`)

`class HttpBackend : public RemoteStorage::Backend` in one file:

| expression | `…$Backend` hit | `…$Backend$Attribute` hit |
| --- | --- | --- |
| `std::vector<RemoteStorage::Backend::Attribute>` | yes | yes |
| `std::vector<Backend::Attribute>` (qualifier via base class) | yes | **no** |
| `std::vector<Plain::Attr2>` (control, no inheritance) | — | yes |

---

## 4. Residual (43)

These reproduce as `missing` on the clone but did not reduce to a minimal fixture within this
pass. Sub-clusters, in decreasing confidence about the *shape*:

* **ccache third-party template code, 17** — `src/third_party/fmt/**` (12) and
  `src/third_party/tl-expected/tl/expected.hpp` (5). All are same-file, template-dependent
  references (`using ret_t = expected<Ret, err_t<Exp>>;`,
  `parse_context<Char>::do_check_arg_id`, `locking<T>::value`,
  `const cache_entry_type& cache`). The reduced shapes all pass:
  `cpp-fixtures/C/tmpl/` finds `expected<...>` in a namespace-scope `using`, in a function-local
  `using`, and as a member. Something about the real files' scale or SFINAE shape is required.
  Note a related macro artifact in the same file:
  `template <class T, class E> class TL_EXPECTED_NODISCARD expected;` (line 142) is indexed as a
  class named **`tl.TL_EXPECTED_NODISCARD`**, i.e. the attribute macro between `class` and the
  name displaces the class name — the same root as families B and C, on the declaration side.
  Three of these rows also have a semantically wrong forward target
  (`cache_entry_type` → `uint128_fallback`, `carrier_uint` → `dragonbox.float_info`), so they
  are not clean inverse-miss witnesses.
* **brpc member/dependent typedefs, 12** — `mutex_type`, `pointer`, `Ch`, `string16`,
  `execute_func_t`, `up_detail::rv`, `_back_ref`. Half have a suspicious forward target that
  followed the alias to an unrelated underlying class (`mutex_type` → `butil.Mutex`,
  `mutex_type` → `std.unique_lock$mutex_type` from a *different* class). Isolated member
  typedefs work in fixture (`ns.holder$mutex_type` is found), so the discriminator is the
  template-dependent context, not the member-ness.
* **BehaviorTree, 5** — all carry the forward diagnostic `unproven_cpp_link_unit` and a
  two-element target group (`.cpp` definition + synthetic `.h` declaration): `tinyxml2.cpp`
  implicit-`this` calls (`DeleteChildren();`, `InsertEndChild(node)`) and
  `child_node_->executeTick()`. Note that a plain implicit-`this` self call **is** produced
  by the analyzer as a `self_receiver` hit (verified in `cpp-fixtures/C/misc-matrix/` and
  `dtor-matrix/`), which the runner would classify `editor_only`, not `missing` — so the
  link-unit split, not the self-receiver-ness, is the discriminator here. This is the
  C++ analogue of #1819's "the inverse cannot prove MACRO targets" shape: a target group
  whose two members are not proven to be one link unit.
* **libzmq forward-declaration targets, 4** — `session_base.hpp:150`
  `class hello_msg_session_t ZMQ_FINAL : public session_base_t` resolves to
  `class session_base_t;` in `plain_server.hpp` although the definition is at line 21 of the
  *same file*; `msg_t::command` resolves to `class msg_t;` in `req.hpp`, not `msg.hpp:33`.
  The inverse for a forward-declaration-only unit has a much narrower visible set.
  `cpp-fixtures/C/fwddecl/` does **not** reproduce it (the forward correctly prefers the
  definition there), so the trigger is something else in libzmq — the `ZMQ_FINAL` macro in
  the base-clause line is the obvious suspect and is untested.
* **esphome, 3** — same shape: two-element target groups where one member is a forward
  declaration in a different header (`class BLEClientBase;` in `ble_service.h`).
* **qpid, 2** — `jobs::iterator` (member typedef used as a qualifier) and `static encoder* e;`
  inside an SFINAE probe struct.

---

## 5. Code citations

**Family A.** The `ImportAnalysisProvider` half of C++ include analysis is quoted-include-only
in every one of its four resolution points:

* `crates/bifrost-analysis/src/analyzer/cpp/imports.rs:26` —
  `imported_code_units_of` iterates `quoted_include_paths(&imports)`.
* `crates/bifrost-analysis/src/analyzer/cpp/imports.rs:69` —
  `imported_files_from_infos` filters with `parse_quoted_include`.
* `crates/bifrost-analysis/src/analyzer/cpp/imports.rs:104` —
  `could_import_file` filters with `parse_quoted_include`.
* `crates/bifrost-analysis/src/analyzer/cpp/imports.rs:136` —
  `include_targets_for_file`, which builds the reverse include index behind
  `referencing_files_of`, iterates `quoted_include_paths(&imports)`.

`quoted_include_paths` (`crates/bifrost-cpp/src/imports.rs:231`) keeps only lines that
`parse_quoted_include` accepts, i.e. lines containing `"`. The angle-aware sibling
`include_paths` (`crates/bifrost-cpp/src/imports.rs:238`, via `parse_include_path` at
`:145`) exists and is what the **forward/resolver** side uses:

* `crates/bifrost-cpp/src/graph/resolver.rs:12` — `include_paths as cpp_include_paths`
* `crates/bifrost-cpp/src/graph/resolver.rs:1053`, `:5623`, `:5759`, `:5810`, `:5887`,
  `:5966`, `:9737`
* `crates/bifrost-cpp/src/hierarchy.rs:45`, `crates/bifrost-cpp/src/identity.rs:248`

That asymmetry is the defect: the resolver follows `<...>`, the visibility/candidate index
does not.

Secondary: `imported_code_units_of` calls `resolve_direct_include_targets_with_index`
(`crates/bifrost-cpp/src/imports.rs:203`), which is direct-only, while
`include_targets_for_file` calls `IncludeTargetIndex::resolve_indexed`
(`crates/bifrost-cpp/src/imports.rs:49`), which additionally matches by file-name suffix.
Two include-resolution strengths inside one provider.

**Family B.** The recovery hook exists but excludes parameter position:

* `crates/bifrost-cpp/src/graph/resolver.rs:7687` `recovered_macro_decorated_type_node` —
  requires a `namespace_identifier` in the `scope` of a `qualified_identifier` with a
  `MISSING ::`, then calls `recovered_declarator_container`.
* `crates/bifrost-cpp/src/graph/resolver.rs:7717` `recovered_declarator_container` — walks up
  and returns only for `init_declarator`/`declaration`/`function_definition`; the accepted
  intermediate kinds at `:7738-7746` are `array_declarator | function_declarator |
  parenthesized_declarator | pointer_declarator | pointer_type_declarator |
  reference_declarator`. **`parameter_declaration` is not in either list**, so the walk
  returns `None` for `f(MACRO T* p)`.
* Consumers that therefore never fire for a parameter:
  `crates/bifrost-cpp/src/graph/inverted.rs:271-275` (the `"namespace_identifier"` match arm
  is guarded by `recovered_macro_decorated_type_node`) and
  `crates/bifrost-cpp/src/graph/extractor.rs:767`.
* With that arm skipped, `inverted.rs:280` only matches
  `type_identifier | qualified_identifier | scoped_type_identifier | template_type`; a bare
  `namespace_identifier` falls through and no candidate is emitted.

**Family D.**

* `crates/bifrost-cpp/src/graph/resolver.rs:8226` `out_of_line_destructor_type_reference` —
  `node.child_by_field_name("name")?` must have kind `destructor_name`. For
  `ns::Class::~Class` the outer `qualified_identifier`'s `name` is a nested
  `qualified_identifier`, so it returns `None`.
* Callers: `crates/bifrost-cpp/src/graph/inverted.rs:289` and
  `crates/bifrost-cpp/src/graph/extractor.rs:835`. Both are additionally reached only when
  `out_of_line_member_definition_owner` (`resolver.rs:8239`) succeeds, which requires
  `is_function_declarator_name_root(node)` — true only for the outer node.

**Family C.** No single line; the phantom is observable through the public index:
`bifrost --root /mnt/T9/repo-clones/apache__qpid-proton --sources cpp/include/proton/message.hpp
--tool search_symbols --args '{"patterns":["std"]}'` returns
`{"symbol":"proton.message.std","line":96,"signature":"PN_CPP_EXTERN std;"}` (kind `field`)
and `{"symbol":"proton.message.friend", ...}`. Line 96 is
`PN_CPP_EXTERN std::string user() const;`. The C++ member-declaration extractor in
`crates/bifrost-cpp/src/declarations.rs` mints a field from the recovered
`type: PN_CPP_EXTERN` / `declarator: std::…` shape.

---

## 6. Recommendations

### A — straightforward generalized fix (60 sites; highest value in the whole bucket)

Make C++ include visibility angle-aware. Replace `quoted_include_paths` with
`include_paths` at the four call sites in
`crates/bifrost-analysis/src/analyzer/cpp/imports.rs` (`:26`, `:69`, `:104`, `:136`) and use
one resolution strength — `resolve_include_targets_with_index` (direct, then the
unique-suffix fallback) — everywhere in that provider rather than the direct-only variant at
`:28`/`:69`. The unique-suffix fallback in
`IncludeTargetIndex::resolve_unique_fallback` (`crates/bifrost-cpp/src/imports.rs:111`)
already refuses ambiguous matches, which is the property that makes it safe to admit `<...>`
without a compiler include path; `CppCompileContexts::project_include_roots`
(`crates/bifrost-cpp/src/compile_context.rs:20`) is the precise source when
`compile_commands.json` is present and should be preferred when it is.

Risk: this *widens* visibility, so it can convert some current `missing` rows into `ambiguous`
and can change forward target identity (the log4cxx `LevelPtr` duplicate-typedef pick). Per
the runbook, the whole corpus must be rerun, not diffed.

Negative controls the regression needs: a system header name that collides with a project
header (`<memory>` vs a project `memory.h`), two project headers with the same basename in
different directories (must stay unresolved, not pick one), and a quoted include that
currently resolves (must not change).

### B — straightforward generalized fix (44 sites)

Extend `recovered_declarator_container`
(`crates/bifrost-cpp/src/graph/resolver.rs:7717`) to terminate on
`parameter_declaration` / `optional_parameter_declaration` the same way it terminates on
`declaration`, returning a third `RecoveredDeclaratorTypeContext::Parameter`. The existing
two-candidate disambiguation in `extractor.rs:767-808` (resolve both the recovered scope and
the displaced `type` node against the target, accept a unique match, refuse two) transfers
unchanged and is exactly the right guard, because in the parameter shape the *scope* is the
real type and the `type` field is the macro — the opposite of the return-type shape the code
was written for.

Regression fixtures: the `xxh-shape` matrix above (macro-prefixed parameter present, plain
parameter present, both proven), plus a negative control where the leading token is a real
type (`Foo Bar* p` must not invent a `Foo` reference).

### D — straightforward generalized fix (10 sites)

Make `out_of_line_destructor_type_reference`
(`crates/bifrost-cpp/src/graph/resolver.rs:8226`) descend the `name` chain: while the `name`
child is itself a `qualified_identifier`, recurse; accept when it is a `destructor_name`.
`qualified_owner_components` (`:8203`) already handles arbitrary component counts, so the
owner resolution feeding `innermost` is already correct — only the terminal lookup is
two-component-limited. Regression: the `dtor-matrix` fixture, with the 2-component form as
the negative control that must keep working.

### C — escalate (10 sites)

This is a declaration-extraction defect, not an inverse defect: Bifrost indexes a field named
`std` (and one named `friend`) inside `proton::message`. The correct fix is in the C++ member
declarator extraction in `crates/bifrost-cpp/src/declarations.rs`: when a member declaration's
`type` field is an all-caps identifier and its declarator is a macro-recovered
`qualified_identifier` with a `MISSING ::`, the declaration must not be minted at all (the
same recovery evidence families B and D use). Escalate because it changes indexed declaration
identity workspace-wide and will move census rows in and out of several buckets at once; it
also overlaps the `TL_EXPECTED_NODISCARD` phantom class in ccache, so the fix should be
scoped as "unexpanded macro in declarator position never produces a declaration" rather than
per-shape.

### E, F, G — small, independent, straightforward (11 sites)

* **E**: the member-pointer path records `&C::m` but not `&C::operator@`. The terminal-node
  helpers around `crates/bifrost-cpp/src/graph/inverted.rs:280-310` treat
  `operator_name` differently from `field_identifier`/`identifier`; add `operator_name` to the
  terminal kinds used for a qualified member reference.
* **F**: same code region — a `qualified_identifier` naming a function that is **not** the
  child of a `call_expression` and **not** under a `pointer_expression` is currently dropped.
  Admit it as an ordinary reference hit.
* **G**: `out_of_line_member_definition_owner`-style base-class scope resolution already
  resolves the qualifier `Backend` through inheritance (the qualifier is recorded); the
  terminal nested type is not looked up in the resolved qualifier's scope. Fix where the
  nested-type terminal is resolved (`is_nested_type_node` early return at
  `inverted.rs:300-303`), by resolving the terminal against the qualifier's resolved unit
  including its base classes.

Each of E/F/G is a one-arm change with a two-line fixture and an adjacent positive control
that already passes; they do not need to be sequenced behind A/B/D.

### Residual — escalate as one investigation

The 43 residual rows are dominated by template-dependent contexts in vendored third-party
headers (ccache `fmt`/`tl-expected` 17, brpc 12). They should be re-triaged **after** A, B
and C land, because C's phantom-declaration fix will change several of their forward targets
(`cache_entry_type` → `uint128_fallback`, `tl.TL_EXPECTED_NODISCARD`) and because a wrong
forward target is not a legitimate inverse miss.

### Sequencing

`A` first (largest, and it changes forward target identity for others), then `C`
(declaration identity), then `B`, `D`, and the E/F/G trio in any order, then re-census and
re-triage the residual. Do not subtract this bucket from the baseline; rerun the full corpus
per the runbook.
