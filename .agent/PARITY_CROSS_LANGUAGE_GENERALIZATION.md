Cross-language generalization of the Java/Python IntelliJ-parity work


This records what the 2026-06-30 IntelliJ go-to-definition / find-usages parity
work on Java and Python implies for the other 9 analyzer languages (Go, C++,
JavaScript, TypeScript, Rust, PHP, Scala, C#, Ruby), so the same bugs are not
rediscovered one language at a time.


## Already language-agnostic (fixed once, applies to all 11)

- Cursor-resolution fix (single-method-class `block` == method range) lives in
  `src/lsp/handlers/broad_symbol.rs` (`node_for_exact_range` returns the deepest
  exact-span node). It is language-independent, so every language's
  `textDocument/references` / `definition` already benefits.
- The `UsageHitKind { Reference, Import }` classification and its filtering
  (`FuzzyResult::all_hits` / `into_either` exclude `Import`; `all_hits_including_imports`
  for the IDE find-references path; searchtools / dead-code / rename skip `Import`)
  are all language-agnostic (`src/analyzer/usages/model.rs` + consumers). Only the
  *emission* of `Import` hits is per-language — currently just the Python scan.
- The LSP-driven caret->references/definition test harness
  (`tests/common/lsp_client.rs::LspServer` + the `tests/intellij_*` suites) is
  language-agnostic. Building an `intellij_<lang>_definition` / `_find_usages`
  suite for another language is just fixtures + triage.


## Should generalize — evidence of shared gaps

Ranked by likely yield.

### 1. Call-receiver type inference (highest value)

We added, in Java and Python `get_definition`, resolution of a *call* receiver:
`Foo().bar` (construction), `getABC().i` / `make().go()` (return type), and chains
`A().make().go()`. The pattern is: type the call receiver by the callee (class ->
construction; function/method -> its declared or inferred return type), then look
up the member.

Evidence this is missing elsewhere (grep of `get_definition/<lang>.rs` for
return-type / call-receiver handling):

- `csharp.rs` and `php.rs`: ZERO return-type / call-receiver-node hits — the
  `getABC().i`-style gap almost certainly exists there.
- `ruby.rs`: thin (2 hits).
- `go.rs`, `js_ts.rs`, `rust.rs`, `cpp.rs`, `scala.rs`: some handling exists but
  may be incomplete (unannotated inference, chaining). Worth a targeted port to
  confirm.

Note: static languages (Java, Go, C#, C++, Scala, Rust, TS) can *read* a declared
return type; dynamic ones (Python, JS, Ruby, PHP) must *infer* it (annotation, or
`return X()` in the body). Both plug into the same "type the receiver, resolve
the member" machinery — the receiver-typing seam is uniform.

### 2. `self` / `this` receiver typed as the enclosing class (find-usages)

Python Bug 2a: `self.member` was not counted as a usage because `self` had no
type. Each language has its own usage-graph strategy
(`src/analyzer/usages/<lang>_graph/`); the concept (an implicit `self`/`this`/
receiver is the lexically enclosing class, directly or via inheritance) is
universal to the OO languages and should be audited in each strategy.

### 3. `Import`-kind hit emission per language

The infrastructure is ready; each language's usage scan should emit an
`Import`-kind hit for a binding that brings the target into a file, so LSP
find-references is complete while the call-graph surfaces stay import-free. Only
Python emits these today.

### 4. Attribute/subscript-target over-declaration (declaration extraction)

Python declared spurious module fields from `foo.bar = 1` / `foo[i] = 1` targets
(fixed by skipping `attribute`/`subscript` subtrees in `collect_assigned_names`).
The analogous mistake — declaring a name from `obj.x = …`, `$obj->x = …`,
`obj[i] = …` — is plausible in the JS/TS, Ruby, PHP, and Go declaration
extractors and should be audited.


## Language-specific — do NOT generalize

These were Java/Python idioms with no cross-language analog:

- Constructor -> `__init__` mapping, decorator member references, the `$`
  nested-class index separator (Python-specific indexing), class-body bare-name
  member references — Python only.
- Qualified nested-class in `extends` (`B.Foo`) and bare unqualified field
  resolution as implemented are tied to Java's grammar/scoping (other languages
  need their own equivalents, but not this code).


## Recommended order of attack

1. Stand up `intellij_<lang>_definition` suites for C#, PHP, Ruby first (thinnest
   receiver handling) using the existing harness — cheap, and most likely to
   surface the call-receiver gap.
2. Port the call-receiver type-inference pattern into whichever languages fail.
3. Audit `self`/`this` receiver typing in each `<lang>_graph` find-usages strategy.
4. Emit `Import`-kind hits per language; audit attribute-target over-declaration.

The methodology is the real generalization: the caret->LSP harness turns "does
language X have bug Y" into a handful of fixtures, so cross-language coverage is a
porting exercise, not a research one.


## Outcomes (generalization pass)

Each pattern has a cross-language suite that both proves the fix and pins the
remaining gaps.

- **1. Call/construction-receiver type inference — DONE (all languages).**
  `tests/cross_language_receiver_definition.rs`. Added construction-receiver
  member resolution to C#, PHP, Scala, C++, and JS/TS `get_definition` (Java and
  Python already had it). All seven green.

- **2. `self`/`this` receiver in find-usages — surfaced.**
  `tests/cross_language_self_usages.rs`. C#, PHP, Scala, Go, Ruby already count a
  `this`/`self` same-class call as a usage. C++, Rust, JS, TS do not; those four
  are `#[ignore]`d (the fix lives in each `<lang>_graph` receiver-typing, a
  heavier change than the `get_definition` work).

- **3. `Import`-kind hit emission — DONE for JS/TS (was Python-only).**
  `tests/cross_language_import_hits.rs`. The JS/TS graph now emits an `Import`
  hit for the specifier that binds the target (ESM named + aliased + default), so
  LSP find-references reports the import line while call-graph surfaces still
  filter it (`js_ts_graph::extractor::handle_import_statement`). CommonJS
  `require` destructuring and the remaining languages are the follow-up.

- **4. Attribute/subscript-target over-declaration — audited.**
  `tests/cross_language_attribute_target_declarations.rs`. Ruby, PHP, Go are
  already correct (regression-guarded). JS/TS over-declare `obj.x` from a
  plain-local `obj.x = 1`; unlike Python this is not a blanket skip (the same
  `js_member_assignment_name` path carries legitimate `Foo.prototype.m` /
  namespace declarations), so it needs scope-aware narrowing and is `#[ignore]`d.
