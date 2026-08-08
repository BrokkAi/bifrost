# FIRD cpp wave - bucket B (`forward_status = ambiguous`) diagnosis

Binary: `/mnt/optane/bifrost-fird/target/release/bifrost_reference_differential` (branch `bifrost-fird`, head `c31801ac`).
Input: `/mnt/optane/tmp/bifrost-fird/cpp-diagnosis/B-ambiguous.json` (211 sites).
Fixtures: `/mnt/optane/tmp/bifrost-fird/cpp-fixtures/B/<name>/` (each is a git repo; each has a sibling `<name>.jsonl` with the run output).
Derived data: `/mnt/optane/tmp/bifrost-fird/cpp-diagnosis/B-subfamilies.json`.

All fixture runs use:

    bifrost_reference_differential run-repo --root <fixture> --language cpp \
      --output <fixture>.jsonl --jobs 4 --cache-mode ephemeral \
      --path <file> --start-byte N --end-byte M

No source file was modified. No issue was created.

---

## 0. Executive summary

211 sites split into two unrelated defects:

| Family | Count | One-line cause |
|---|---:|---|
| **B1-B4** arity-unknown (`ambiguous_definition` + "argument count ... unknown after macro expansion") | 196 | The **bare member-call branch** of `resolve_cpp_call` returns `Ambiguous` whenever call arity is unproven, **without the #1811 lone-candidate rule and without `dedupe_callable_candidates`**. 113 of the 196 have a target set that is literally one entity; 40 of those have exactly **one** target. |
| **B5** `ambiguous_definition` ("bare call ... has ambiguous lookup candidates", 0 targets) | 15 | Not overload ambiguity at all. `canonical_type_unit` returns `None` when a `using`/`typedef` alias points at a **type that is not indexed** (a std type, an fmt type, or a template parameter); `resolve_imported_type_candidate` maps that `None` onto `LexicalTypeResolution::Ambiguous`. |

**The brief's headline hypothesis is falsified.** Decl/def double-counting is real (73/196 sites) but it is not the mechanism: fixture `p3_single_member_poisoned` has a single inline member function, exactly one candidate, no header/impl pair at all, and is still `ambiguous`. 40 production sites likewise report exactly one target.

---

## 1. Static measurement of the decl/def-pair hypothesis (all 211 records)

Collapse key = `same_logical_symbol` = `(kind, fq_name, signature)` (`crates/bifrost-cpp/src/graph/resolver.rs:10016-10020`).

| shape | sites |
|---|---:|
| arity-unknown, **1 target** (nothing to be ambiguous between) | **40** |
| arity-unknown, 2 targets, identical `(fq_name, signature)` -> collapse to 1 | **73** |
| arity-unknown, >=2 distinct signatures | 83 |
| `ambiguous lookup candidates`, **0 targets** | 15 |

Of the 73 identical pairs, **73/73** are `(synthetic:false, synthetic:true)` and 72/73 are `(.cpp|.cc, .h|.hpp)` - i.e. an out-of-line definition plus its header declaration. So the pair pattern the brief spotted is real and pervasive; it is simply not load-bearing, because the single-target cohort fails identically.

Progressive collapse ladder over the 196 arity-unknown sites (how many have a target set that reduces to **one logical entity**):

| relaxation | collapses to 1 entity |
|---|---:|
| L0 `same_logical_symbol` as-is | **113 / 196** |
| L1 + tolerate a differing trailing cv/ref/noexcept qualifier | 118 |
| L2 + treat top-level `const` on a parameter as not part of the type | 122 |
| L3 + qualification-insensitive parameter types | **138 / 196** |
| residual genuine overload sets | **58** |

Caveat on L1: a blanket "ignore the trailing qualifier" rule is **wrong**. Two of the five L1 gains are genuine C++ overloads that must stay ambiguous - `absl/container/internal/btree.h:667/670` (`slot(size_type)` vs `slot(size_type) const`) and `absl/status/status_builder.h:213/214` (`Log(absl::LogSeverity) &` vs `&&`). The correct fix is to stop *dropping* the qualifier during extraction (section 4), which unifies the true pairs and keeps those overloads distinct.

---

## 2. Family table

| Family | Sites | Witness | Fixture | Verdict |
|---|---:|---|---|---|
| **B1a** bare member call, arity unproven, **exactly one candidate** | 40 | `esp-v2 src/envoy/http/service_control/http_call.cc:@4063 attemptRetry`; `cppcheck lib/valueflow.cpp:@196905 traverseCondition` | `p3_single_member_poisoned` | wrong `Ambiguous`; straightforward fix |
| **B1b** bare member call, arity unproven, decl+def of one entity | 73 | `cppcheck gui/mainwindow.cpp:@25866 getCppcheckSettings` | `p1_pair_poisoned` (vs `p2_pair_clean`, `p11_literal_args_poisoned`) | wrong `Ambiguous`; straightforward fix |
| **B2** decl+def separated by a **dropped trailing cv/ref/noexcept qualifier** on the out-of-line definition | 3 confirmed (+1 needs B3 too) | `log4cxx src/main/cpp/jsonlayout.cpp:155/330 appendQuotedEscapedString`; `brpc src/brpc/ts.cpp:725 encode_33bits_dts_pts`; `libzmq src/tcp_listener.cpp:156 get_socket_name` | `p16_constqual_multiline` vs `p17_constqual_singleline` vs `p18_constqual_doublespace` vs `p19_noexcept_multiline` | extraction bug; straightforward fix |
| **B3** decl+def separated by **parameter-type spelling** (FQ vs unqualified, or top-level `const`) | 20 (4 top-level const + 16 qualification) | `libzmq src/dist.cpp:124 send_to_matching` (`(msg_t *)` vs `(zmq::msg_t *)`); `esp-v2 client_cache.cc:260 collectCallStatus` (`StatusCode` vs `absl::StatusCode`); `cppcheck gui/mainwindow.cpp:1362 analyzeProject` (`bool` vs `const bool`) | `p8_qualified_poisoned`, `p7_topconst_poisoned` | signature-identity defect; fix with care |
| **B4** genuine overload sets under unproven arity | 58 | `abseil absl/time/civil_time.cc:182 ParseLenientCivilTime` (6 overloads x 2 spellings); `esphome fastled_light.h:51 add_leds` (11 template overloads) | `p6_member_overload_poisoned` | `Ambiguous` is the **correct** answer given the arity evidence; only fixable by making arity provable (section 5) |
| **B5a** bare call on a `using`/`typedef` alias whose **target type is not indexed** | 10 | `abseil absl/container/linked_hash_map.h:179 hasher`; `ccache src/ccache/util/time.hpp:74 TimePoint`; `wuffs example/jsonfindptrs/jsonfindptrs.cc:353 JsonVector`; `brpc src/butil/strings/string_piece.h:277 const_reverse_iterator`; `log4cxx asyncbuffer.h:216 WideFmtArgStore` | `q6_alias_std_template` (fails) vs `q4_plain_class`, `q5_alias_local_class`, `q7_typedef_local_class`, `q8_alias_builtin` (all resolve); `q1_member_alias_twice`, `q3_member_alias_once` | wrong `Ambiguous`; straightforward fix |
| **B5b** free function declared in two namespaces under mutually exclusive `#if` branches | 5 | `BehaviorTree.CPP include/behaviortree_cpp/contrib/expected.hpp:2522 make_unexpected` (decls at `nonstd::make_unexpected` line 247 and `nonstd::expected_lite::make_unexpected` line 1565) | not reduced | escalate with reduction work |

Repo distribution of the 196 arity-unknown sites (level x poisoning source):

| repo | L0-collapsible | L3-collapsible | genuine overloads | poisoning source |
|---|---:|---:|---:|---|
| zeromq/libzmq | 35 | 9 | 3 | generated `platform.hpp` (7 copies under `builds/*`, none in `src/`) |
| abseil | 23 | 2 | 17 | **`.inc` textual includes (resolver defect)** |
| brpc | 21 | 2 | 18 | `*.pb.h`, `gflags/gflags.h`, `butil/config.h` (absent) |
| esp-v2 | 16 | 9 | 10 | envoy/protobuf headers (absent, bazel-external) |
| esphome | 7 | 0 | 6 | Arduino `WString.h` (absent) |
| cppcheck | 5 | 1 | 0 | Qt-generated `ui_mainwindow.h` (absent) |
| BehaviorTree.CPP | 3 | 0 | 3 | none / macro-argument binding |
| LMCache | 3 | 0 | 0 | absent |
| log4cxx | 0 | 2 | 1 | none - conditionally defined `LOG4CXX_STR` argument macro |

---

## 3. Mechanism trace - arity-unknown -> `Ambiguous` (families B1-B4)

### 3.1 The odd branch

`crates/bifrost-analysis/src/analyzer/usages/get_definition/cpp.rs:4001-4034`:

```rust
let (member_candidates, had_member_callable) = if call_arity.is_none() {
    cpp_member_candidates_lazy_with_presence(ctx, vec![owner], name, None, || None)
} else { ... };
if !member_candidates.is_empty() {
    if call_arity.is_none() {
        return ambiguous_candidates_outcome(member_candidates, /* "argument count ... unknown" */);
    }
    return cpp_callable_candidates_outcome(member_candidates);
}
```

There is no candidate-count test and no `dedupe_callable_candidates` call. Any non-empty member set plus unproven arity is `Ambiguous`.

Contrast the three sibling branches in the same function, all of which tolerate unproven arity:

- **free-function bare call**, `cpp.rs:4058-4098`, delegates to `resolve_callable_candidates` (`crates/bifrost-cpp/src/graph/extractor.rs:2026-2064`), which calls `dedupe_callable_candidates` (`extractor.rs:2013-2024`, keyed on `same_logical_symbol`) and then, at `extractor.rs:2039-2050`, returns `FreeFunctions` for a **lone** candidate. Its `debug_assert!(units.len() >= 2, ...)` at `cpp.rs:4086-4089` documents exactly the invariant the member branch lacks.
- **qualified call** `Scope::name(...)`, `cpp.rs:3908` -> `qualified_call_has_applicable_arity` (`cpp.rs:5399-5410`) returns `true` for `arity == None`.
- **receiver call** `recv->name(...)`, `cpp.rs:3822-3833` -> `resolve_cpp_field`, which simply skips arity filtering.

Consequence: **the same call written two ways gets two different verdicts.** Fixture `p14_this_receiver_poisoned` (`this->prepare(a, b)`) resolves; `p1_pair_poisoned` (`prepare(a, b)`), identical in every other respect, is ambiguous.

### 3.2 Why arity is unproven

`CppVisibilityIndex::call_arity_evidence` (`crates/bifrost-cpp/src/graph/resolver.rs:1168-1205`):

1. If no argument has an arity-changing shape (`argument_shape_may_change_arity`, `resolver.rs:7394-7429` - any bare `identifier`, or a `call_expression` whose function is an identifier), return `Exact(n)`. Fixture `p11_literal_args_poisoned` (`prepare(1, 2)`) resolves even under a poisoned include, proving this early exit.
2. Otherwise consult the macro environment. `argument_arity_evidence` (`resolver.rs:1207-1274`) at lines 1230-1236: an identifier argument with **no** macro binding yields `Unknown` iff `environment.unknown_names`.

`unknown_names` has exactly two roots (`resolver.rs:1485`, `1604`, `1642`, `1687`):

- an included file with no prepared C++ syntax, and
- `MacroEvent::Include { targets: [] }` - an **unresolvable quoted** include. Angle-bracket includes are deliberately exempt (`resolver.rs:1775-1781`), confirmed by `p9_angle_include` (resolves).

Note that the `conditional` flag is checked *after* the empty-targets test (`resolver.rs:1603-1606`), so an unresolvable include under a provably inactive `#ifdef` poisons unconditionally - fixture `p12_conditional_poisoned` (libzmq's `#if defined _WIN32_WCE / #include "..\builds\msvc\errno.hpp"`) is ambiguous.

A third, independent trigger exists that the brief did not mention: `argument_arity_evidence`'s final arm `_ => CallArityEvidence::Unknown` (`resolver.rs:1272`) fires when an argument identifier *does* have a binding but the binding is `Unsupported`/ambiguous, and `macro_expansion_shape_is_safe` (`resolver.rs:7472-7505`) rejects any argument subtree containing an identifier for which `environment.may_bind` is true. This is what poisons log4cxx (3 sites, zero unresolvable includes): the calls pass `LOG4CXX_STR("thread")`, and `LOG4CXX_STR` is `#define`d four times under conditionals in `src/main/include/log4cxx/logstring.h:43,49,51,57`.

### 3.3 Legitimacy of the include failures

| class | arity sites | example | fixable? |
|---|---:|---|---|
| target exists on disk but its **extension is not indexed** | **40** (all abseil) | `absl/numeric/int128.h:1214 #include "absl/numeric/int128_have_intrinsic.inc"` - the `.inc` file exists | **yes, resolver defect** |
| several same-basename candidates, none project-local | 44 (all libzmq) | `#include "platform.hpp"` with 7 copies under `builds/*` and none generated into `src/` | defensible fail-closed |
| genuinely absent (generated / external / OS-specific) | 98 | `ui_mainwindow.h` (Qt uic), `*.pb.h` (protoc), `source/common/**` (envoy), `WString.h` (Arduino), `stddef.h` spelled with quotes | no |
| no include poisoning; macro-argument binding | 5 | log4cxx `LOG4CXX_STR`, BT.CPP `nsel_*` | correct fail-closed |

`Language::Cpp` extensions are `["c","cc","cpp","cxx","h","hpp","hh","hxx"]` at `crates/bifrost-core/src/analyzer/model.rs:112`. `.inc`/`.inl`/`.ipp`/`.tcc`/`.def` are missing, so `IncludeTargetIndex::resolve_direct` (`crates/bifrost-cpp/src/imports.rs:72-94`) cannot see them. Fixture `p20_inc_extension` proves it: `#include "helper.inc"` where `helper.inc` **exists in the fixture** still yields `ambiguous`.

---

## 4. Mechanism trace - signature identity (families B2, B3)

### B2: trailing qualifier silently dropped

`crates/bifrost-cpp/src/declarations.rs:3749-3757`:

```rust
let full_text = normalize_cpp_whitespace(node_text(declarator, source));
let suffix = full_text
    .split_once(node_text(parameters_node, source))     // RAW needle in a NORMALIZED haystack
    .map(|(_, tail)| normalize_cpp_qualifier_suffix(tail))
    .unwrap_or_default();                                //  <- silently empty on mismatch
```

The haystack is whitespace-normalized; the needle is raw source text. Whenever the parameter list contains any whitespace that normalization rewrites, `split_once` misses and the trailing `const`, `noexcept`, `&`/`&&`, `override`, and trailing-return-type are dropped.

Perturbation matrix (identical header decl `bool prepare(int, int) const;` in every case):

| fixture | definition spelling | extracted def signature | verdict |
|---|---|---|---|
| `p17_constqual_singleline` | `prepare(int settings, int supprs) const` on one line | `(int, int) const` | matches decl |
| `p16_constqual_multiline` | parameter list split across two lines | `(int, int)` | **const lost** |
| `p18_constqual_doublespace` | one line, **two spaces** between params | `(int, int)` | **const lost** |
| `p19_noexcept_multiline` | multi-line, `noexcept` | `(int, int)` | **noexcept lost** |

So the trigger is whitespace normalization, not line breaks. This also violates the repository rule against replacing parser support with source-text splitting: the cv-qualifier, ref-qualifier and `noexcept` specifier are structured siblings of `parameters` inside the `function_declarator`.

Production confirmations: `log4cxx src/main/cpp/jsonlayout.cpp:207-208` and `brpc src/brpc/ts.cpp:758-759` both carry `const` in the source and lose it in the index; `libzmq src/tcp_listener.cpp:70-71` loses `const` *and* spells its parameters `zmq::fd_t`.

### B3: signature is a source spelling, not a type identity

`cpp_parameter_type` (`declarations.rs:6213-6242`) renders each parameter from the raw type node text. A header declaring `bool prepare(ns::Msg *m, int)` and a definition written inside `namespace ns { ... prepare(Msg *m, int) ... }` therefore produce different signature strings for one entity - fixture `p8_qualified_poisoned` yields `('ns.Widget.prepare','(Msg *, int)')` and `('ns.Widget.prepare','(ns::Msg *, int)')`. Same for `const int` vs `int` at top level (`p7_topconst_poisoned`), which C++ says is not part of the function type at all ([dcl.fct]/5).

---

## 5. Mechanism trace - family B5a (the 15 zero-target sites)

`crates/bifrost-cpp/src/graph/resolver.rs:3183-3186`:

```rust
let Some(unit) = self.resolve_type_candidates(analyzer, file, &candidates, resolution) else {
    return LexicalTypeResolution::Ambiguous;
};
```

`resolve_type_candidates` -> `unique_canonical_type_candidate` (`resolver.rs:3863-3884`) returns `None` in **two different situations**: more than one canonical candidate (real ambiguity), and `canonical_type_unit` failing (`resolver.rs:3871`, `?`). `canonical_type_unit` (`resolver.rs:3549-3569`) fails at line 3567 when `resolve_structured_alias_target` cannot find the alias' target unit - i.e. the alias points at something outside the index. Both are reported as `Ambiguous`. That verdict then reaches `get_definition/cpp.rs:4115-4121` (`ambiguous_without_candidates`), producing `ambiguous` with an empty target list.

Isolation matrix (all one-file fixtures, `return X();`):

| fixture | declaration | verdict |
|---|---|---|
| `q4_plain_class` | `struct Foo {};` | resolved -> `Foo` |
| `q5_alias_local_class` | `using Alias = Foo;` (Foo indexed) | resolved -> `Foo` |
| `q7_typedef_local_class` | `typedef Foo Alias;` | resolved -> `Foo` |
| `q8_alias_builtin` | `using Alias = int;` | resolved -> the **alias unit itself** (`StructuredAliasTarget::Builtin` arm, `resolver.rs:3561-3563`) |
| `q6_alias_std_template` | `using Alias = std::vector<int>;` | **ambiguous, 0 targets** |
| `q3_member_alias_once` | `using hasher = KeyHash;` (template parameter), unique in the workspace | **ambiguous, 0 targets** |
| `q1_member_alias_twice` | same name in two classes | ambiguous, 0 targets |

`q3` is decisive: a *unique* alias is reported as ambiguous. The number of same-named declarations is irrelevant; what matters is whether the alias' right-hand side is indexed. `q8` shows the desired behaviour already exists for builtins - answer the alias declaration itself.

All 10 B5a production witnesses match: `absl` `using hasher = KeyHash` / `key_equal` / `allocator_type` (template parameters), `brpc` `typedef std::reverse_iterator<const_iterator> const_reverse_iterator`, `ccache` `using TimePoint = std::chrono::time_point<...>`, `wuffs` `using JsonVector = std::vector<JsonValue>`, `log4cxx` `using WideFmtArgStore = fmt::dynamic_format_arg_store<...>`.

---

## 6. Premises I falsified

1. **"decl+def counted as two candidates turns a uniquely-named function into ambiguous" - FALSE as a mechanism.** `p3_single_member_poisoned` has one candidate and is still ambiguous; 40/196 production sites report one target. The pair pattern is a *correlate* (73/196), not the cause. The cause is the unconditional `ambiguous_candidates_outcome` at `get_definition/cpp.rs:4023-4031`.
2. **"the C exemption `bare_name_binds_only_target`" - no such symbol exists** anywhere in the tree. The #1811 exemption is the `candidates.len() == 1` arm of `resolve_callable_candidates` (`extractor.rs:2039-2050`).
3. **"C++ has real overloading, so the exemption may deliberately not fire when multiple candidates exist" - FALSE.** The exemption fires normally for C++ free functions: `p4_free_single_poisoned` and `p5_free_pair_poisoned` both resolve under the identical poisoned include. The member branch simply never reaches that code.
4. **"an unresolvable quoted `#include` ... poisons `unknown_names`; any identifier argument then makes call arity unprovable" - TRUE but incomplete.** It is confirmed (`p1` ambiguous vs `p2` resolved vs `p11` resolved), but 5 sites (log4cxx, BT.CPP) have zero unresolvable includes and are poisoned instead by a conditionally-defined function-like macro *argument*.
5. **"whether the include-resolution failure is legitimate or a resolver defect" - both, and the split is measurable:** 40 resolver defect (`.inc`), 44 defensible fail-closed (duplicate basenames), 98 genuinely absent, 5 not include-related.
6. **Bucket B is not one bucket.** The 15 `ambiguous lookup candidates` sites share nothing with the 196 arity sites - no macros, no overloads, no arity. They are alias resolution.

Findings the brief did not anticipate: the receiver/qualified/bare inconsistency (section 3.1), the trailing-qualifier extraction bug (section 4/B2), and the alias `None`-means-`Ambiguous` conflation (section 5).

---

## 7. Fix vs escalate

### F1 - straightforward. Give the bare member-call branch the same contract as the free-function branch. (covers B1a+B1b = 113 sites)

`get_definition/cpp.rs:4001-4034`. Before deciding, collapse the candidate set with the existing `same_logical_symbol` predicate, then apply the lone-candidate rule:

```rust
if !member_candidates.is_empty() {
    if call_arity.is_none() {
        let mut logical = member_candidates.clone();
        dedupe_callable_candidates(&mut logical);        // extractor.rs:2013, needs re-export
        if logical.len() == 1 {
            // Unproven arity cannot create ambiguity where member lookup found
            // exactly one logical declaration; a declaration and its out-of-line
            // body are one entity, not an overload set (#1811 for members).
            return cpp_callable_candidates_outcome(member_candidates);
        }
        return ambiguous_candidates_outcome(member_candidates, ...);
    }
    return cpp_callable_candidates_outcome(member_candidates);
}
```

Contract: *unproven call arity never converts a single logical member declaration into `Ambiguous`; it only preserves an existing overload ambiguity.* Genuine overloads are untouched - `p6_member_overload_poisoned` keeps 2 logical candidates and stays ambiguous. Negative controls a regression test must include: `p6` (two real member overloads), `absl btree.h slot` (const/non-const pair), `absl status_builder.h Log` (ref-qualified pair), `esphome add_leds` (template overload set).

Same-shaped review question worth answering while in there: whether the surviving `Ambiguous` answers should also carry the deduped set rather than the raw set, since the differential currently sees decl+def as separate `targets` entries.

### F2 - straightforward. Stop dropping the trailing qualifier. (covers B2, and repairs `same_logical_symbol` fidelity workspace-wide)

`declarations.rs:3749-3757`. Replace the `full_text.split_once(raw parameter text)` string search with the structured siblings of `parameters` inside the `function_declarator` (`type_qualifier`, `ref_qualifier`, `noexcept`, `trailing_return_type`, virtual specifiers), rendered through `normalize_cpp_qualifier_suffix`. This removes a source-text mini-parser that the repository rules already prohibit. Regression cases: `p16`/`p17`/`p18`/`p19`, plus the genuine const/non-const overload pair from `absl btree.h` to prove the qualifier is still *distinguishing*.

### F3 - straightforward. Top-level `const` on a parameter is not part of the function type. (covers 4 sites)

`cpp_parameter_type` (`declarations.rs:6213-6242`) should drop a top-level `type_qualifier` that is not behind a pointer/reference declarator, per [dcl.fct]/5. `const T&` and `const T*` are unaffected. Cases: `cppcheck mainwindow analyzeProject`, `libzmq do_setsockopt_int_as_bool_relaxed/strict`. Fixture `p7_topconst_poisoned`.

### F4 - fix, but design first. Signature identity must not be a source spelling. (covers 16 sites)

The right shape is a resolved-type identity for signature comparison (there is already `StructuredTypeIdentity` in the C# resolver and `cpp_resolve_type_unit` here), used by `same_logical_symbol` while `signature()` keeps its human-readable spelling. A cheap textual normalization would be a regression against the repository's "no source-text mini-parser" rule and would also wrongly merge `ns_a::T` with `ns_b::T`. Recommend: **file as its own issue** with `p8_qualified_poisoned` as the reduction, and land F1-F3 first.

### F5 - straightforward, but confirm scope. Index textual-include extensions. (unblocks arity for 40 abseil sites, 17 of which are genuine overload sets that would then resolve)

`crates/bifrost-core/src/analyzer/model.rs:112` omits `inc`, `inl`, `ipp`, `tcc`, `def`. Adding them to the C++ extension set makes `IncludeTargetIndex` resolve `absl/numeric/int128_have_intrinsic.inc` and removes the `unknown_names` poison for the whole abseil workspace. Risk to weigh before doing it: those files are not standalone translation units, so they will also start being *declared into* the index and sampled by the census; a narrower alternative is to index them for the include graph only. Fixture `p20_inc_extension`. Recommend confirming the narrower option with the owner.

### F6 - straightforward. Distinguish "alias target not indexed" from "ambiguous". (covers B5a = 10 sites)

`resolve_imported_type_candidate` (`resolver.rs:3183-3186`) turns every `None` from `resolve_type_candidates` into `Ambiguous`. `unique_canonical_type_candidate` (`resolver.rs:3863-3884`) has two distinct failure modes. Make them distinguishable (e.g. `LexicalTypeResolution::Unresolvable` alongside `Ambiguous`, or have `canonical_type_unit` fall back to the alias declaration itself exactly as its `StructuredAliasTarget::Builtin` arm already does at `resolver.rs:3561-3563`).

Contract: *a `using`/`typedef` alias whose target is outside the workspace resolves to the alias declaration, not to `Ambiguous`.* This is the same answer `q8_alias_builtin` already gives. Negative control: `q1_member_alias_twice` must keep failing closed only if the two aliases are genuinely both visible from the reference; note the correct C++ answer there is the enclosing class's member alias, so a follow-up check on member-alias scoping is warranted.

### F7 - escalate. B5b, `make_unexpected` (5 sites)

Two declarations in different namespaces (`nonstd` at `expected.hpp:247`, `nonstd::expected_lite` at `expected.hpp:1565`) under mutually exclusive `#if nsel_P0323R` branches; the call at 2522 is inside `nonstd::expected_lite`, so unqualified lookup should pick the inner one. I did not reduce this shape. Recommend a dedicated reduction: same-named free function template in an outer and an inner namespace, each in one arm of an `#if`, called from the inner namespace - then decide whether the defect is in `enclosing_lexical_scope_components` (`extractor.rs:2116-2119` returns `Ambiguous` for an ambiguous lexical scope) or in `lexical_component_tiers` inner-first ordering.

### Not a defect

The 58 B4 sites (genuine overload sets under unproven arity, minus the 17 abseil ones F5 would rescue) are a **correct** `Ambiguous`. They should be reclassified in the census ledger as `unproven`, not `missing`, unless the arity evidence itself can be improved.

---

## 8. Fixture and evidence index

`/mnt/optane/tmp/bifrost-fird/cpp-fixtures/B/`

| fixture | what it isolates | result |
|---|---|---|
| `p1_pair_poisoned` | member call, decl+def, unresolvable quoted include | ambiguous, 2 identical targets |
| `p2_pair_clean` | same, include removed | resolved |
| `p3_single_member_poisoned` | inline member, **one** candidate | **ambiguous, 1 target** |
| `p4_free_single_poisoned` | free function, one candidate | resolved (#1811) |
| `p5_free_pair_poisoned` | free function, decl+def | resolved (dedupe + #1811) |
| `p6_member_overload_poisoned` | two real member overloads | ambiguous (correct) |
| `p7_topconst_poisoned` | decl `const int` vs def `int` | ambiguous |
| `p8_qualified_poisoned` | decl `ns::Msg*` vs def `Msg*` | ambiguous |
| `p9_angle_include` | unresolved `<string>` | resolved (angle exempt) |
| `p10_quoted_resolved` | resolvable quoted include | resolved |
| `p11_literal_args_poisoned` | literal arguments under poison | resolved (arity provable) |
| `p12_conditional_poisoned` | unresolvable include under inactive `#if` | ambiguous |
| `p13_quoted_stdheader` | `#include "stddef.h"` | ambiguous |
| `p14_this_receiver_poisoned` | `this->prepare(...)` | **resolved** (inconsistency) |
| `p15_static_member_poisoned` | `static` member | ambiguous |
| `p16_constqual_multiline` | out-of-line `const` def, multi-line params | const dropped |
| `p17_constqual_singleline` | same, single line | const kept |
| `p18_constqual_doublespace` | same, one line + double space | const dropped |
| `p19_noexcept_multiline` | `noexcept`, multi-line | noexcept dropped |
| `p20_inc_extension` | `#include "helper.inc"` (file exists) | ambiguous |
| `q1_member_alias_twice` | member alias in two classes | ambiguous, 0 targets |
| `q2_single_alias` | file-scope alias to `std::chrono::time_point` | ambiguous, 0 targets |
| `q3_member_alias_once` | member alias, unique | **ambiguous, 0 targets** |
| `q4_plain_class` | plain class construction | resolved |
| `q5_alias_local_class` | alias to indexed class | resolved |
| `q6_alias_std_template` | alias to `std::vector<int>` | **ambiguous, 0 targets** |
| `q7_typedef_local_class` | `typedef` to indexed class | resolved |
| `q8_alias_builtin` | `using Alias = int` | resolved to the alias |

Production rerun: `/mnt/optane/tmp/bifrost-fird/cpp-diagnosis/rerun-abseil-assertvalid2.jsonl` reproduces `absl/strings/internal/cord_rep_btree.cc@31984 AssertValid` as `ambiguous` with 4 targets (2 overloads x decl+def) and the arity-unknown diagnostic, on the current binary.

Helper scripts used for the include-closure census live in the session scratchpad (`incl.py`, `incl2.py`, `incl3.py`); they reimplement `IncludeTargetIndex::resolve_direct` + `resolve_unique_fallback` semantics over the clones and are approximations, not authoritative.
