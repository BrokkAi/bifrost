# FIRD cpp wave — bucket A diagnosis

`forward_status = no_definition`, diagnostic `no_indexed_definition`
("`X` did not resolve to an indexed C++ callable"), **523 sites**.

Source list: `/mnt/optane/tmp/bifrost-fird/cpp-diagnosis/A-no-indexed-definition.json`
Binary: `/mnt/optane/bifrost-fird/target/release/bifrost_reference_differential` (HEAD `458a5c06`, includes the C-wave fixes #1811-#1815).
All probes used `--cache-mode ephemeral`. All fixtures are `git init`-ed single-purpose repos under
`/mnt/optane/tmp/bifrost-fird/cpp-fixtures/A/`. Probe helper: `/mnt/optane/tmp/bifrost-fird/cpp-fixtures/probe.sh`.

## 0. Falsified premises

Every one of these was in the brief or was my own first hypothesis. All were disproved by
perturbation, not by reading.

| Premise | Verdict | Evidence |
|---|---|---|
| The 67+ `XXH_readLE64` / `XXH_readLE32` sites are the "macro-token declaration" family (`XXH_FORCE_INLINE`) | **FALSE** | `macro-prefix/v2-macro` (`#define FORCE_INLINE static`, `FORCE_INLINE u64 readLE64(...)`) **resolves**. `v3-macro-undefined` (macro never defined) also **resolves**. The macro prefix is irrelevant; the `#if/#else` around the declaration is the whole cause (`v4-plain-guarded`, plain `static`, no macro at all, **fails**). |
| The 144 log4cxx sites are a namespace/`LOG4CXX_NS` macro problem | **FALSE** | `ns-macro/x2-macro-ns` (`namespace NS_MACRO { ... }` + `using namespace NS_MACRO;`) **resolves** with FQN `NS_MACRO.Logger.forcedLog`. `x4-both` (macro namespace *and* `class MY_EXPORT`) also **resolves**. |
| The 134 abseil sites are "templates/namespaces" | **FALSE** | Templates resolve fine (`template-callable/t1-template-member`, `t3-template-free` both **resolve**). Plain nested namespaces resolve (`ns-macro-token/f1-plain`). The cause is the bare `ABSL_NAMESPACE_BEGIN` token *immediately before* a `namespace` keyword. |
| Class-body macro noise (`DECLARE_ABSTRACT_LOG4CXX_OBJECT(...)`, `BEGIN_LOG4CXX_CAST_MAP()`) breaks log4cxx | **FALSE** | `ns-macro/y3-macro-body` **resolves**. |
| Private access filtering drops the qpid `insert` candidate | **FALSE** | `private-member/p1-private` **resolves**. |
| The qpid/ccache/libzmq "implicit-this member call" sites are the plain out-of-line-member shape | **FALSE** | `implicit-this/w1-outofline` (header + `.cpp`, `void C::g() const { f(1); }`) **resolves**. |
| `#if !defined(A) || defined(B)` (an undecidable guard expression) blocks a same-guard reference | **FALSE** | `guard-complex/g2-same-complex` **resolves**; so do `g3`, `g4`. Same-guard co-activation from #1813 works for arbitrary expressions. |
| A single site record ≈ a single defect instance | **FALSE (sampling artifact)** | The census samples. All four `ParseOneCharToken` call sites I probed in `demangle.cc` (bytes 27884, 28108, 30924, 31058) fail, but only 30 of that file's many sites are in the list. Family counts below are **lower bounds on real impact**. |

## 1. Family table

| Family | Mechanism | Sites | Witness (`path#byte`) | Fixture root |
|---|---|---:|---|---|
| **A1** | Callable declared inside a preprocessor conditional; reference outside it or in a sibling branch. Declaration is never activated. | **123** | `Blosc__c-blosc2 plugins/codecs/ndlz/xxhash.h#109291` (line 3077, `XXH_readLE64`) | `A/macro-prefix/` |
| **A2** | A bare ALL_CAPS macro token immediately before `namespace` (or before a class head) makes tree-sitter build a synthetic `function_definition` whose `compound_statement` holds the real declarations. Extraction recovers the FQNs; the *callable activation walk* rejects anything under a `compound_statement`. | **120** (+**12** A2b where only the declaration is wrapped) | `abseil__abseil-cpp absl/debugging/internal/demangle.cc#27884` (line 796, `ParseOneCharToken`) | `A/ns-macro-token/` |
| **A3** | The only reachable same-file declaration is an *owner-qualified out-of-line definition* (`Owner::name`). The owning class is not indexed / not reachable, so an unqualified member or constructor call has no candidate. | **186** | `apache__logging-log4cxx src/main/cpp/logger.cpp#7857` (line 279, `forcedLog`) | `A/implicit-this/`, `A/orphan-owner/`, `A/export-class/` |
| ↳ A3a | Root cause: export-macro class head defeats the existing recovery. Two proven sub-shapes. | ≥74 | `logger.h:50` `class LOG4CXX_EXPORT Logger : public virtual spi::AppenderAttachable`; `ndc.h:78` `class LOG4CXX_EXPORT NDC` | `A/export-class/e2`, `e12` |
| ↳ A3b | Root cause: no `#include` edge to the header that declares the owner (generated/concatenated fragments). | 21 | `google__wuffs internal/cgen/auxiliary/image.cc#…` (`DecodeImageResult`) | `A/orphan-owner/h2`, `h4` |
| ↳ A3c | Owner class *is* extracted *and* included; resolution still fails (see A6). | ~16 | `apache__qpid-proton cpp/src/encoder.cpp#4197` (line 127, `insert`) | `cpp-fixtures/bisect/qpid` |
| **A5** | Heterogeneous residual (see §6). Largest sub-patterns: data member used as a callable; call preceding the only indexed declaration; overload sets on one owner. | **82** | `GoogleCloudPlatform__esp-v2 .../http_call.cc` line 106 `on_done_(OkStatus(), body)` | — |
| **A6** | (cross-cuts A3c/A5) Foreign-declaration visibility is sensitive to *byte-level, semantically irrelevant* edits in the donor header. Deterministic per content, flips on adding a comment line. | ≥16 | `apache__qpid-proton cpp/src/encoder.cpp#4197` | `cpp-fixtures/bisect/qpid` + `/tmp/bis2.sh` |

Coverage: A1+A2+A2b+A3 = **441 / 523 (84 %)** with a proven mechanism and a reproducing fixture.

Per-family repo/file tables: `/mnt/optane/tmp/bifrost-fird/cpp-diagnosis/family_tables.txt`.
Machine-readable per-site classification: `families2.json` (keys `repo|path|byte`), with the
underlying tree-sitter ancestor chains and declaration guard sets in `chains4.json`.

## 2. A1 — callable under a preprocessor conditional (123 sites)

### Perturbation matrix (`A/macro-prefix/`, probe on the call site)

| Fixture | Declaration shape | Reference | Result |
|---|---|---|---|
| `v1-plain` | `static u64 readLE64(...)` | outside, no guards | **resolved** |
| `v2-macro` | `FORCE_INLINE u64 readLE64(...)`, `#define FORCE_INLINE static` | outside | **resolved** |
| `v3-macro-undefined` | `FORCE_INLINE …`, macro never defined | outside | **resolved** |
| `v8-dup-unguarded` | two identical definitions, no `#if` | outside | **resolved** |
| `v11-if1` | inside `#if 1` | outside | **resolved** |
| `v10-same-guard` | inside `#ifdef FORCE_MEM` | **inside the same `#ifdef`** | **resolved** |
| `v6-single-guarded` | inside `#ifdef FORCE_MEM` | outside | **no_definition** |
| `v12-ifndef` | inside `#ifndef FORCE_MEM` | outside | **no_definition** |
| `v13-guarded-nonstatic` | inside `#ifdef`, non-static | outside | **no_definition** |
| `v4-plain-guarded` | two plain definitions, `#if X==3` / `#else` | outside | **no_definition** |
| `v5-macro-guarded` | as `v4` but with the macro prefix (the exact xxhash shape) | outside | **no_definition** |
| `v9-ifdef-else` | `#ifdef` / `#else` pair | outside | **no_definition** |
| `v14-guarded-class-method` | member function inside `#ifdef` in a class body | sibling member | **resolved** |

The factor flips exactly with "is the declaration under a non-trivial preprocessor conditional that
the reference is not also under". Nothing else moves it.

### Code

`crates/bifrost-cpp/src/graph/resolver.rs:6325` `callable_preprocessor_context_is_visible_for_reference`:

```rust
guard => {
    if !reference
        .guards()
        .is_some_and(|active| active.contains(&guard))
    {
        return false;                       // resolver.rs:6356-6360
    }
}
```

Called from `callable_declaration_activation_in_file` (`resolver.rs:6302-6306`), whose `None` result
makes `physical_declaration_visible_at` (`resolver.rs:2336-2343`) return `false`, so the candidate
never reaches the arity/overload stage and the site answers `Missing` → `no_definition`.

This is #1813's B2 seam. #1813 accepts a guard only when the *reference* already requires it. That is
right for a lone conditional branch, but it has no notion of a **completed `#if`/`#else` family**: in
xxhash the two `XXH_readLE64` definitions cover all paths, so the name is declared in every
configuration and the reference cannot fail to see one of them. The equivalent reasoning already
exists on the *type* side — `external_type_candidate_visible_in_context` computes
`complementary_visible` from `complementary_same_fqn_type_declarations` /
`is_exhaustive_same_fqn_type_declaration_family` (`resolver.rs:2489-2519`, helper
`preprocessor_guard_terms_cover_all_paths` at `resolver.rs:3970`). The callable path has no such
branch.

Sub-split of the 123: **90** sites have exactly 2 same-name declarations whose guards form an
`#if`/`#else` pair (the exhaustive case, incl. all 84 xxhash sites); **26** have a single
conditional declaration; the rest have 3-8.

### Verdict: **FIX**, straightforward and general

Reuse the existing exhaustive-family machinery on the callable path.

- Add a callable analogue of `complementary_visible` in `physical_declaration_visible_at`
  (`resolver.rs:2316`): when the candidate's same-FQN declaration set in one file forms an
  exhaustive `#if`/`#else` family (`preprocessor_guard_terms_cover_all_paths`), treat the guard
  requirement as satisfied and fall back to the ordinary activation-byte test.
  Contract: *a name declared on every branch of a completed conditional family is declared
  unconditionally.* Fixes ≥90 sites, including all 84 xxhash ones, with no recall risk.
- Optional second step for the remaining ~26 single-branch cases: return a structured best-effort
  answer instead of `Missing`. This is a policy call, not a correctness one — I would keep those as
  `unproven`, not `missing`, rather than resolve them.

## 3. A2 — namespace-opening macro token (120 + 12 sites)

`ABSL_NAMESPACE_BEGIN` (abseil, 112 sites), `FMT_BEGIN_NAMESPACE` (fmt vendored in ccache, 4+),
and equivalents.

### Tree-sitter shape (verified with `tree-sitter parse`, grammar `tree-sitter-cpp 0.23.4`)

```
ABSL_NAMESPACE_BEGIN
namespace debugging_internal { … }
```
parses as

```
(function_definition
  type: (type_identifier "ABSL_NAMESPACE_BEGIN")
  (ERROR (identifier "namespace"))
  declarator: (identifier "debugging_internal")
  body: (compound_statement   <-- every real declaration lives in here
     (function_definition …)  …))
```

### Perturbation matrix (`A/ns-macro-token/`)

| Fixture | Shape | Result |
|---|---|---|
| `f1-plain` | `namespace absl { namespace debugging_internal { … } }` | **resolved** (`absl::debugging_internal.ParseOneCharToken`) |
| `f3-anon-ns` | plain + an anonymous `namespace { }` block | **resolved** |
| `f8-macro-semicolon` | `ABSL_NAMESPACE_BEGIN;` then `namespace …` | **resolved** |
| `f9-macro-after-ns` | macro token *inside* the namespace body | **resolved** |
| `f7-macro-then-func` | macro token then a plain function (no `namespace`) | **resolved** |
| `f2-macro-token` | `ABSL_NAMESPACE_BEGIN` + `namespace …` (+ `ABSL_NAMESPACE_END`) | **no_definition** |
| `f4-begin-only` | `ABSL_NAMESPACE_BEGIN` + `namespace …` | **no_definition** |
| `f5-end-only` | only `ABSL_NAMESPACE_END` before the closing brace | **resolved** |
| `f6-begin-toplevel` | macro token + `namespace` at translation-unit scope | **no_definition** |
| `f10-type-in-wrapper` | **type** reference (`struct State`) inside the wrapper | **resolved** |
| `f12-prototype-outside` | same as `f6` plus an *unwrapped* prototype | **resolved**, and it binds to the unwrapped prototype (`ParseOneCharToken`, not the namespaced FQN) |

Two decisive controls: `f10` proves extraction and the *type* visibility path are unaffected — only
the callable path fails; `f12` proves that the declaration nested in the wrapper is exactly what is
being discarded.

Independent confirmation that extraction is fine:
`bifrost --sources absl/debugging/internal/demangle.cc --tool search_symbols` returns
`absl::debugging_internal.ParseOneCharToken` at line 345, with the correct package.

### Code

`crates/bifrost-cpp/src/graph/resolver.rs:6205` `callable_declaration_activation_in_file`, ancestor
walk at **`resolver.rs:6222-6257`**:

```rust
if node.kind() == "function_definition"
    && crate::declarations::is_recovered_exported_class_container(node, prepared.source())
{ ancestor = node.parent(); continue; }            // resolver.rs:6228-6238
if node.kind() == "compound_statement"
    && node.parent().is_some_and(|parent| is_recovered_exported_class_container(parent, …))
{ ancestor = …; continue; }                        // resolver.rs:6239-6251
if matches!(node.kind(), "compound_statement" | "function_definition" | "lambda_expression") {
    return None;                                   // resolver.rs:6252-6257  <-- the drop
}
```

The escape hatch exists, but only for the *exported-class* recovery. The namespace-opening-macro
recovery shape is not recognised, so the declaration's activation is `None` and
`physical_declaration_visible_at` returns `false`.

### Verdict: **FIX**, straightforward and general

- Add `declarations::is_recovered_macro_namespace_container(node, source) -> bool`, the namespace
  twin of `is_recovered_exported_class_container` (`declarations.rs:1188`): a `function_definition`
  whose `type` is a bare ALL_CAPS identifier (`cpp_export_macro_token`), whose only non-declarator
  child is an `ERROR` containing the `namespace` token, and whose `declarator` is a bare identifier.
  The extractor already reconstructs the namespace owner for this shape (FQNs are correct), so the
  predicate can be derived from the same evidence rather than re-invented.
- Add the two matching `continue` arms to the walk at `resolver.rs:6222-6251`.
- Contract: *a declaration whose only function-like ancestors are macro-recovery artifacts is at
  namespace scope, and activates at its declarator like any other.*

This is ~132 sites and, given the sampling caveat, most of abseil's real reference graph.

## 4. A3 — orphan owner (186 sites)

Symptom in all 186: the reference is an unqualified member call (`forcedLog(...)`,
`callAppenders(event)`) or an unqualified constructor call (`return DecodeImageResult(msg)`), and
the only same-file indexed declaration of that name is an owner-qualified out-of-line definition
(`void Logger::forcedLog(...)`, `DecodeImageResult::DecodeImageResult(...)`).

### Perturbation matrix

| Fixture | Owner class | Result |
|---|---|---|
| `implicit-this/w1-outofline` | declared in an included header | **resolved** (`C.f`) |
| `implicit-this/w2-thisqual` | ditto, `this->f(1)` | **resolved** |
| `implicit-this/w3-inclass` | in-class definition | **resolved** |
| `implicit-this/w4-samefile` | class declared in the same `.cpp` | **resolved** |
| `ns-macro/y2-angle-include` | header reached by `<pkg/a.h>` across an include dir | **resolved** |
| `ns-macro/y1-no-class` | **no class declaration anywhere** | **no_definition** |
| `orphan-owner/h1-struct-visible` | `struct Res` in the same file | **resolved** |
| `orphan-owner/h3-header-included` | `struct Res` in an included header | **resolved** (targets `ns.Res`) |
| `orphan-owner/h2-struct-orphan` | out-of-line ctor only, no `struct Res` | **no_definition** |
| `orphan-owner/h4-header-not-included` | header exists but is not `#include`d | **no_definition** |

So the proximate condition is "the owner type is not an indexed, reachable declaration". Three root
causes produce it.

### A3a — export-macro class head defeats extraction (≥74 sites)

Two independent proven sub-shapes, both in `A/export-class/` (measured with
`bifrost --sources a.h --tool search_symbols`, i.e. directly on extraction):

| Fixture | Class head | Extracted |
|---|---|---|
| `e1-export-plainbase` | `class MY_EXPORT Logger`⏎`: public Base` | `ns.Logger` + 2 members |
| `e3-plain-virtualbase` | `class Logger`⏎`: public virtual spi::X` | `ns.Logger` + 2 members |
| `e5-export-virtual-unqual` | `class MY_EXPORT Logger`⏎`: public virtual Base` | `ns.Logger` + 2 members |
| `e6-export-qualbase` | `class MY_EXPORT Logger`⏎`: public spi::X` | `ns.Logger` + 2 members |
| **`e2-export-virtualbase`** | `class MY_EXPORT Logger`⏎`: public virtual spi::AppenderAttachable` | **nothing** (only the base class) |
| **`e8-export-virtual-nonamespace`** | `class MY_EXPORT Logger`⏎`: virtual public Base` | **`ns.MY_EXPORT`** — the macro is taken as the class name |
| **`e12-allcaps-classname`** | `class MY_EXPORT NDC { … }` | **nothing** |
| `e13-mixedcase-classname` | `class MY_EXPORT Ndc { … }` | `ns.Ndc` + 1 member |
| `e14-allcaps-noexport` | `class NDC { … }` | `ns.NDC` + 1 member |

`e12` vs `e13` vs `e14` isolates a clean, general defect: **`cpp_export_macro_token`
(`crates/bifrost-cpp/src/declarations.rs:253`) calls any ALL_CAPS token an export macro**, and
`exported_class_name_from_node` (`declarations.rs:1285-1315`, and the sibling filters at
`declarations.rs:205`, `216`, `238`, `677`, `834`, `975`, `983`) discards a recovered name that
satisfies that predicate. When the *real class name* is also ALL_CAPS the recovery cannot tell the
macro from the name and drops both.

`e2`/`e8` are a second gap in the same recovery: `recover_exported_class_declaration`
(`declarations.rs:298-333`) bails when the direct `declarator` is not `identifier | type_identifier`
(`declarations.rs:312-320`); the `public virtual ns::Base` recovery produces a `qualified_identifier`
declarator (verified in the `tree-sitter parse` dump), and the `virtual public Base` recovery loses
the class name entirely.

Production witnesses:
- `apache__logging-log4cxx src/main/include/log4cxx/logger.h:50` `class LOG4CXX_EXPORT Logger : public virtual spi::AppenderAttachable` — `search_symbols --sources logger.h` returns only the forward declarations at lines 34/36/40; the class body and all members are missing. This is the root cause of the 52 `logger.cpp` sites.
- `apache__logging-log4cxx src/main/include/log4cxx/ndc.h:78` `class LOG4CXX_EXPORT NDC` — 0 classes, 0 functions extracted (the ALL_CAPS shape).
- `zeromq__libzmq src/udp_engine.hpp:17` `class udp_engine_t ZMQ_FINAL : public io_object_t, public i_engine` — class missing; the member `error` is extracted as the *free* function `zmq.error`, owner lost.
- `cppcheck-opensource__cppcheck lib/importproject.h:62` `class CPPCHECKLIB WARN_UNUSED ImportProject {` — 0 classes extracted.

Negative controls in the same corpus (export macro present, extraction fine):
`log4cxx transcoder.h:33 class LOG4CXX_EXPORT Transcoder`, `level.h:48`, `helpers/exception.h:39`.

This is the #1803 family applied to *class heads* rather than function declarators. There is already
substantial dedicated recovery machinery
(`recover_exported_class_declaration`, `recover_malformed_exported_multiple_base_class`,
`recover_exported_class_function_definition`, `FragmentedExportBody`, issues #938/#941), so it is a
coverage gap, not a missing capability.

**Verdict: FIX**, in two independent pieces.
1. *ALL_CAPS class name* (`declarations.rs:253` + the name filters). Contract: when a class head has
   two adjacent bare identifiers, the **last** one is the class name and the earlier ones are
   attribute macros — decide by position, not by casing. `cpp_export_macro_token` should only be
   used to decide whether a *leading extra* token exists, never to veto the trailing name.
2. *Base-clause recovery shapes* (`recover_exported_class_declaration`, `declarations.rs:298`).
   Accept a `qualified_identifier` displaced declarator, and recognise the `virtual public Base`
   ordering. Add `e2`, `e8`, `e12` as fixtures.

Attribution: report against **#1803** with this evidence, do not file new. Note explicitly that the
current #1803 statement ("visibility-macro declarations like `CJSON_PUBLIC(...)`") is about
*function* declarators; the class-head half is what dominates the C++ corpus.

### A3b — no include edge (21 sites, all `google__wuffs internal/cgen/auxiliary/image.cc`)

`image.cc` is a code fragment that the wuffs build concatenates; it never `#include`s `image.hh`.
`image.hh:15 struct DecodeImageResult` extracts correctly, but there is no include edge, so the
struct is not reachable and `return DecodeImageResult(std::move(error_message));` has no candidate.
The out-of-line constructors in `image.cc` *are* indexed
(`wuffs_aux.DecodeImageResult.DecodeImageResult`, lines 19 and 26).

Fixture: `orphan-owner/h4-header-not-included` reproduces exactly; `h1`, `h3` are the controls.

**Verdict: FIX, narrow and defensible.** An out-of-line definition `Owner::member` in file F is
itself structured proof that `Owner` is a class-like entity in F's scope. Contract: *when a file
contains owner-qualified out-of-line definitions, treat the owner as an implicitly declared
class-scope binding in that file for unqualified member and constructor lookup within its sibling
definitions.* This is a structured best-effort answer from real AST evidence (a
`qualified_identifier` declarator), not a text fallback. It also independently rescues every A3a
site even before the extraction fix lands, and it is the same shape as the `y1-no-class` /
`h2-struct-orphan` fixtures.

Risk to weigh: it can bind an unqualified call to a member of a class the reference is not actually
inside. Gate it on the reference being lexically inside another out-of-line definition of the same
owner (which is true for every A3 witness I inspected).

### A3c — residual (~16 sites, qpid-proton) → see A6.

## 5. A6 — foreign-declaration visibility is byte-position sensitive (≥16 sites)

This is the one finding I could **not** reduce to a mechanism, and it is the most alarming.

Witness: `apache__qpid-proton cpp/src/encoder.cpp#4197` (line 127,
`encoder& encoder::operator<<(bool x) { return insert(x, pn_data_put_bool); }`).
`proton::codec.encoder` and `proton::codec.encoder.insert` are both correctly extracted from
`cpp/include/proton/codec/encoder.hpp`; the header is `#include`d; the include path is unique.

Reduction harness: `/mnt/optane/tmp/bifrost-fird/cpp-fixtures/bisect/qpid` (a copy of the clone's
`cpp/` subtree, git-initialised — **the real clone was never modified**), driver `/tmp/bis2.sh`
(fresh output file per run; note that reusing one `--output` silently *skips* completed records, which
invalidated an earlier bisection pass of mine).

Findings:
- Replacing the header with a 12-line minimal equivalent → **resolved**. Replacing `encoder.cpp`
  with a 14-line minimal equivalent while keeping the real header → still **no_definition**. The
  breakage is on the donor-header side.
- Bisecting the header preamble: `lines[:26] + minimal class` **resolves**; `lines[:27] + minimal
  class` (one more `#include`) **no_definition**.
- But: the same three includes *without* the license comment block **resolve**; adding a single
  `// a comment line` (17 bytes) to the resolving variant makes it **fail**; adding `// c` (4 bytes)
  does not; adding 20 short comment lines does; creating an unrelated empty header elsewhere in the
  tree also flipped a case.
- Padding sweep (`guard + N bytes + class`, N = 0…400) is **monotonically resolved**, so it is not a
  simple byte threshold. Results are perfectly deterministic per content (5/5 identical across runs,
  and identical at `--jobs 1` and `--jobs 8`), so it is not a data race.

Deterministic-per-content but flipping on semantically empty edits points at a content-derived key:
a hash-bucket iteration order, a content-hashed memo (`cache_unconditional_include_reachability`,
`macro_event_cell`), or a candidate-set cap. I did not isolate it.

**Verdict: ESCALATE.** It needs an instrumented/debug build to log the candidate set and the
`physical_declaration_visible_at` decision for the failing content, which is outside this diagnosis
pass. Flag as a correctness-of-determinism issue, not just a recall issue: forward resolution should
not depend on comment bytes in an unrelated part of a header.

## 6. A5 — residual (82 sites)

Not a single mechanism. Sub-patterns I identified by inspection (counts approximate):

1. **Data member used as a callable** (~15): `on_done_(OkStatus(), body)` (esp-v2, 6),
   `callback_()`, `function_(...)` (brpc `callback.h`), `putFunc_(*os_, c)` (rapidjson),
   `size_(sz)` in a member-initializer (fmt `base.h`). The declaration is a `field_declaration`,
   so "did not resolve to an indexed C++ **callable**" is literally true. Bifrost should resolve
   these to the field. **Fixable**, but it is a forward-classification question (callable vs field
   reference), and some are census artifacts (member-initializer names are declarations of an
   initialization target, not call sites).
2. **Overload set on one owner** (~15): `has_value()` in `tl::expected` (11 sites),
   `match(child)` in cppcheck `vf_analyzers.cpp`. Many same-named members across sibling classes;
   the resolver answers `Missing` rather than `Ambiguous`. Overlaps with bucket B.
3. **Call precedes the only indexed declaration** (~8): cppcheck `forwardanalyzer.cpp` line 665 calls
   `getStepTokFromEnd`, defined at line 946; libzmq `zmq.cpp` line 391 calls `zmq_msg_init_buffer`,
   defined at line 605. Worth re-checking against #1811/#1813 — a file-scope prototype exists in
   some of these but is not indexed as its own symbol.
4. **Census artifacts** (~5): `OnlyOnceErrorHandler();` at `onlyonceerrorhandler.h:61` and
   `~DefaultRepositorySelector();` at `defaultrepositoryselector.h:45` are *declarations*, not
   references; `_fqMulLeg(c,a,a)` at `circl ecc/fourq/fq_amd64.h:217` is inside a `#define` body
   (#1819 territory).

**Verdict: defer.** Re-triage A5 after A1/A2/A3 land; several of these will change classification
once candidates start being produced.

## 7. Recommended order

1. **A2** — smallest, most mechanical change (`resolver.rs:6222-6251` + one predicate in
   `declarations.rs`), 132 sites, zero interaction with other families.
2. **A1** — reuse `preprocessor_guard_terms_cover_all_paths` on the callable path, ≥90 sites.
3. **A3a** — the `cpp_export_macro_token` positional fix is small and high-yield; the base-clause
   recovery shapes are more invasive. Attribute to #1803.
4. **A3b** — the implicit-owner-binding rule; also acts as a safety net for A3a.
5. **A6** — escalate with the `bisect/qpid` harness attached.
6. **A5** — re-triage last.

## 8. Artifacts

```
/mnt/optane/tmp/bifrost-fird/cpp-diagnosis/
  A-report.md                 this file
  families2.json              per-site family, keyed "repo|path|byte"
  chains4.json                per-site tree-sitter ancestor chain, guard sets,
                              and every same-file declaration with its own chain/guards
  family_tables.txt           per-family repo/file breakdown
  filesyms_index.json         per-file extracted symbol inventory (142 files)
  classify2/3/4.py            the classifiers
/mnt/optane/tmp/bifrost-fird/cpp-fixtures/
  probe.sh                    fixture probe driver
  A/macro-prefix/             A1, 14 variants
  A/ns-macro-token/           A2, 12 variants
  A/implicit-this/            A3 controls, 5 variants
  A/orphan-owner/             A3b, 4 variants
  A/export-class/             A3a, 14 variants
  A/ns-macro/                 falsification of the macro-namespace hypothesis
  A/guard-complex/            falsification of the complex-guard hypothesis
  A/template-callable/        falsification of the template hypothesis
  A/private-member/           falsification of the access-control hypothesis
  A/include-layout/           include-resolution controls
  bisect/qpid/                A6 reduction harness (copy of the clone's cpp/ subtree)
```

No product code was changed. The read-only clones under `/mnt/T9/repo-clones` were not modified.
