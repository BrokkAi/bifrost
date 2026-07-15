# usagebench run 29408065738 assertion hand-off

Date: 2026-07-15

## Scope

This document separates incorrect or incomplete benchmark assertions from genuine
Bifrost gaps in [usagebench run 29408065738](https://github.com/BrokkAi/usagebench/actions/runs/29408065738).
It is intended as a hand-off for editing the precision cases added by
[usagebench PR #48](https://github.com/BrokkAi/usagebench/pull/48).

The comparison run is
[29325156779](https://github.com/BrokkAi/usagebench/actions/runs/29325156779).
The earlier 110 planned cases all still pass. PR #48 added 27 planned cases:
13 pass and 14 fail. Thus, none of the pre-existing cases regressed.

Run revisions:

- usagebench: `5059785c5ccd763bcd391d6c81a56e8076390774`
- Bifrost: `a2b7f7fdde2b060a7d79589c8caf40942e47d0e2`
- result: 123 passed, 14 failed, 137 planned

## Assertion policy to settle first

`benchmarks/README.md` defines the corpus contract as follows:

- `expectedUsages` contains true semantic usages.
- `allowedExtraUsages` is for an intentionally broader analyzer interpretation.
- Import and re-export binding sites are **not** usages and must not be placed in
  either list. An analyzer that returns them should fail the case.
- A runtime expression that exports a value still reads that value. For example,
  `module.exports = { Client }` and `exports.Client = Client` contain a real
  `Client` usage on the right-hand side; this is distinct from an ES/TS
  re-export specifier such as `export { Client } from "./client"`.
- `expectedFailure` is the right way to retain a planned analyzer gap without
  weakening the intended assertion.

The recommendations below follow that contract. This matters for JavaScript and
TypeScript because Bifrost currently returns barrel/export binding sites and some
of its own tests treat them as references. If the desired usagebench contract is
instead “whatever Bifrost currently calls a reference,” the export locations can
be added to `expectedUsages`; that would be a deliberate contract change from the
current usagebench README.

Do not move a precise expected usage to `expectedUnprovenUsages` merely to make a
case green. If the purpose is to require proof, retain `expectedUsages` and mark
the case `expectedFailure` until Bifrost proves it.

## Recommended assertion edits

All ranges below use the fixture's zero-based UTF-16 coordinates.

### 1. C++ out-of-line member definition

Case: `cpp-out-of-line-member-call`

Add the out-of-line definition to `expectedUsages`:

```yaml
- location: { uri: benchmark://source/src/worker.cpp, range: { start: { line: 4, character: 13 }, end: { line: 4, character: 20 } } }
  kind: method
  displayName: execute
```

`Worker::execute` in a definition is a semantic reference to the header
declaration. This also agrees with the existing C++ LSP-parity case. The consumer
call remains expected. This case should pass after the assertion edit.

### 2. C++ overload definition

Case: `cpp-overload-string-call-is-narrow`

Add the matching `const char *` overload definition:

```yaml
- location: { uri: benchmark://source/src/worker.cpp, range: { start: { line: 7, character: 4 }, end: { line: 7, character: 10 } } }
  kind: function
  displayName: select
```

Bifrost did not merge the `int` overload. The extra is the definition of the
selected declaration, so the precision behavior is correct. This case should
pass after the assertion edit.

### 3. PHP interface implementation

Case: `php-interface-typed-receiver-call`

Add the implementing method declaration:

```yaml
- location: { uri: benchmark://source/src/Consumer.php, range: { start: { line: 7, character: 20 }, end: { line: 7, character: 24 } } }
  kind: method
  displayName: send
```

The implementation is a semantic usage of the interface member and is already
part of usagebench's PHP parity expectations. Keep the interface-typed call on
line 12. This case should pass after the assertion edit.

### 4. Python inheritance reference

Case: `python-barrel-class-construction`

Add the subclass base expression:

```yaml
- location: { uri: benchmark://source/precision/services.py, range: { start: { line: 9, character: 17 }, end: { line: 9, character: 22 } } }
  kind: class
  displayName: Child
```

`class Grandchild(Child)` is a real reference to `Child`, independently of the
barrel. Keep the consumer construction. This case should pass after the assertion
edit.

### 5. JavaScript construction inside the factory

Case: `js-commonjs-barrel-class-construction`

Add the factory's construction:

```yaml
- location: { uri: benchmark://source/src/lib.js, range: { start: { line: 5, character: 13 }, end: { line: 5, character: 19 } } }
  kind: class
  displayName: Client
```

Also add the runtime CommonJS export read:

```yaml
- location: { uri: benchmark://source/src/lib.js, range: { start: { line: 8, character: 19 }, end: { line: 8, character: 25 } } }
  kind: class
  displayName: Client
```

Unlike a pure ES/TS re-export specifier, the object-literal shorthand evaluates
`Client` at runtime. With Bifrost classifying pure re-exports as editor-only,
this case should pass and does not need `expectedFailure`.

### 6. TypeScript return type

Case: `ts-type-annotation-through-barrel`

Add the function return type:

```yaml
- location: { uri: benchmark://source/src/api.ts, range: { start: { line: 4, character: 32 }, end: { line: 4, character: 38 } } }
  kind: interface
  displayName: Widget
```

The `Widget` return annotation is a real type usage. Do **not** add the `Widget`
token in `src/barrel.ts:1`; it is a re-export binding. With Bifrost retaining
that site only for editor references, this case should pass and does not need
`expectedFailure`.

### 7. Rust trait implementation

Case: `rust-barrel-trait-static-qualifier`

Add the trait in the implementation header:

```yaml
- location: { uri: benchmark://source/src/service.rs, range: { start: { line: 6, character: 5 }, end: { line: 6, character: 11 } } }
  kind: interface
  displayName: Worker
```

`impl Worker for Local` is a real reference to the trait, not a re-export
binding. Retain both expected `Worker` qualifier references in `src/lib.rs`.
Bifrost still misses those two references, so the case remains an
`expectedFailure`.

## Cases whose assertions should remain strict

These locations describe the intended semantic result. The current failures
should be represented with `expectedFailure`, not by weakening or deleting the
assertions.

| Case | Current mismatch | Recommendation |
| --- | --- | --- |
| `csharp-generic-extension-call` | The expected call on `Precision.cs:19` is returned only as unproven. | Keep it in `expectedUsages`; mark expected failure. |
| `go-dot-import-concrete-receiver-call` | Concrete calls on lines 7 and 9 are proven; the interface-typed call on line 11 is a legitimate conservative candidate. | Keep lines 7 and 9 in `expectedUsages`; put line 11 in `expectedUnprovenUsages`. |
| `go-interface-receiver-method-call` | Line 11 is proven, while concrete calls on lines 7 and 9 are incorrectly emitted as unproven. | Keep line 11 only; do not allowlist lines 7 and 9; mark expected failure. |
| `js-commonjs-barrel-member-call` | Direct construction resolves, but the factory-returned receiver call on line 4 is only unproven. | Keep both calls in `expectedUsages`; mark expected failure. |
| `ruby-factory-return-member-call` | The explicit factory call resolves; the call through a factory using bare `new` is unproven. | Keep both calls in `expectedUsages`; mark expected failure. |
| `rust-ufcs-trait-method-through-barrel` | Both UFCS calls through the chained trait re-export are missing. | Keep both calls in `expectedUsages`; mark expected failure. |
| `ts-chained-barrel-function-call` | The consumer call resolves and the barrel is useful to IDE find-references but noisy for external usage queries. | Keep only the consumer call; Bifrost should classify the barrel as editor-only. |

The Rust static-qualifier case from the previous section should also be marked
`expectedFailure` after its genuine missing expected site is added.

Recommended expected-failure set after the assertion and re-export-contract
changes (6 cases):

```text
csharp-generic-extension-call
go-interface-receiver-method-call
js-commonjs-barrel-member-call
ruby-factory-return-member-call
rust-ufcs-trait-method-through-barrel
rust-barrel-trait-static-qualifier
```

Example marker:

```yaml
expectedFailure:
  reason: "Bifrost does not yet resolve the expected semantic usage precisely."
```

Use a specific reason per case where practical. usagebench will continue running
the case and report it as improved if the case starts passing.

## Bifrost root-cause hand-off

The remaining six expected failures reduce to five implementation seams:

1. **C# object-created receivers** — `receiver_type_fq_names` in
   `src/analyzer/usages/csharp_graph/resolver.rs` handles identifiers, member
   access, invocations, casts, and `this`, but not
   `object_creation_expression`. Therefore `new Registered().Echo()` loses the
   receiver type and becomes unproven.
2. **Go typed-local facts** — `seed_var_spec` in
   `src/analyzer/usages/go_graph/extractor.rs` can fall through from an explicit
   interface type to RHS alias inference. While scanning `Worker`, this aliases
   `var recorder Recorder = worker` to `Worker`; while scanning `Recorder`, the
   `Worker` constructor is not recognized as known-unrelated. The resolver needs
   richer typed-local facts rather than an allowlist.
3. **JavaScript CommonJS function summaries** —
   `src/analyzer/usages/js_ts_graph/receiver_analysis.rs` summarizes imported
   functions for named/default imports but not `CommonJsRequire`, so
   `require("./barrel").create().request()` cannot retain the factory return
   type. Export specifiers are now retained as editor references but filtered
   from the external usage surface.
4. **Ruby bare `new` in factories** — factory outcome inference in
   `src/analyzer/usages/ruby_graph/extractor.rs` recognizes an explicit
   receiver such as `Service.new`, but not the AST shape of bare `new` inside a
   class method. Existing tests cover only the explicit form.
5. **Rust chained re-export canonicalization** —
   `resolve_scoped_associated_item` in
   `src/analyzer/usages/rust_graph/resolver.rs` does not canonicalize the
   `facade::Worker` re-export through the earlier `service::Worker` re-export.
   This loses both the trait qualifier and associated method identity. Trait
   implementation references should remain included.

No matching open Bifrost issues were found for these five seams during the
investigation. Closed issue #739 is adjacent to the C# generic behavior but did
not cover the object-creation receiver shape.

## Suggested edit-and-check sequence in usagebench

1. Apply the assertion additions above.
2. Add `expectedFailure` to the six-case set.
3. Leave re-export binding locations out of all expectation and allowance lists
   unless the README contract is intentionally changed first.
4. Run the focused precision documents, then the complete scheduled command.
5. With the Bifrost re-export classification change, expect the JavaScript class
   and both TypeScript barrel cases to pass instead of remaining expected
   failures.
