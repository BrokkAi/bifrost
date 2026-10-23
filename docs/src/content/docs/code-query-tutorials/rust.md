---
title: Rust
description: Query Rust async/await, calls, assignments, imports, closures, and method receivers with query_code.
---

> Last verified end to end: 2026-10-07 (`query_code` schema version 1).

For exact inbound and outbound symbol edges, proof tiers, and adapter-specific caveats, see [Reference Traversal](/code-query-tutorials/reference-traversal/).

Rust maps turbofish calls, method receivers, grouped `use` declarations, closures, signed literals, and compound assignments into the normalized `query_code` model. The fixture includes both production code and a closure so containment and exclusion remain observable.

## Fixture

<!-- code-query-fixture:rust/lib.rs -->
```rust
use std::{fmt, io};

const LIMIT: i32 = -3;
struct Service { count: i32 }

impl Service {
    fn run(&self, code: &str) -> String {
        code.parse::<String>()
    }
}

fn audit(code: &str) -> String {
    let callback = |value: i32| { return value; };
    let mut service = Service { count: 0 };
    service.count += 1;
    service.run(code)
}

async fn async_value() -> u32 {
    1
}

async fn wait_for_value() -> u32 {
    async_value().await
}
```

## Receiver calls, turbofish, and closures

The same terminal method name can occur as a generic call or a method call. A receiver constraint selects the structured method form, while `not_inside` excludes calls inside the closure fixture when refining a broader call query.

<!-- code-query-case:method-call:rql -->
```lisp
(language rust
  (call :callee (name "parse") :receiver (name "code")))
```

<!-- code-query-case:method-call:json -->
```json
{"languages":["rust"],"match":{"kind":"call","callee":{"name":"parse"},"receiver":{"name":"code"}}}
```

<!-- code-query-case:method-call:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "rust.Service.run",
      "end_line": 8,
      "kind": "call",
      "language": "rust",
      "result_type": "structural_match",
      "path": "rust/lib.rs",
      "start_line": 8,
      "text": "code.parse::<String>()"
    }
  ],
  "truncated": false
}
```

Calls written inside macro arguments are included in the query results.

<!-- code-query-case:generic-call-type-arguments:rql -->
```lisp
(language rust
  (call :callee (name "parse") :type-arguments [(name "String")]))
```

<!-- code-query-case:generic-call-type-arguments:json -->
```json
{"languages":["rust"],"match":{"kind":"call","callee":{"name":"parse"},"type-arguments":[{"name":"String"}]}}
```

<!-- code-query-case:generic-call-type-arguments:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "rust/lib.rs",
      "language": "rust",
      "kind": "call",
      "start_line": 8,
      "end_line": 8,
      "text": "code.parse::<String>()",
      "enclosing_symbol": "rust.Service.run"
    },
    {
      "result_type": "structural_match",
      "path": "rust/modules.rs",
      "language": "rust",
      "kind": "call",
      "start_line": 2,
      "end_line": 2,
      "text": "raw.parse::<String>()",
      "enclosing_symbol": "rust.load"
    },
    {
      "result_type": "structural_match",
      "path": "rust/modules.rs",
      "language": "rust",
      "kind": "call",
      "start_line": 7,
      "end_line": 7,
      "text": "\"1\".parse::<String>()",
      "enclosing_symbol": "rust.tests.covers_load"
    }
  ],
  "truncated": false
}
```

## Callee provenance and unsafe calls

`call-shape` exposes four Rust callee columns independently of dispatch resolution:

| Column | Meaning |
| --- | --- |
| `callee_provenance` | `caller_supplied`, `local_closure`, `declared`, or `unknown`; `unsupported` for languages that do not publish provenance. |
| `callee_supplier` | `parameter N`, `closure_parameter N`, or `receiver`; null when no supplier is identified. Parameter ordinals start at zero and exclude `self`. |
| `callee_type_shape` | `fn_bound_generic`, `trait_bound_generic`, `dyn_trait`, `impl_trait`, `fn_pointer`, `nominal`, or `unknown`. |
| `callee_bounds` | An array of written trait paths, such as `["FnMut"]` or `["Runner"]`. |

Classification uses the nearest lexical binding, including shadowing. Function
parameters with inline or `where` bounds containing `Fn`, `FnMut`, or `FnOnce`
are `caller_supplied` with `fn_bound_generic`; other generic trait bounds use
`trait_bound_generic`. `dyn Trait`, `impl Trait`, and function-pointer parameters
use `dyn_trait`, `impl_trait`, and `fn_pointer` respectively. Reference layers
are ignored. Closure parameters are caller-supplied, with `unknown` shape when
untyped. Trait `self` and generic receivers are also caller-supplied. A nominal
parameter has provenance `declared` and shape `nominal`.

`T: Trait` is caller-supplied because the caller chooses the concrete `T` and
therefore the method implementation. This remains true when dispatch can list
workspace implementations: provenance describes who supplies the code, while
dispatch describes possible targets.

A local initialized directly with a closure is `local_closure`. A named function
or path is `declared`. Other local initializers and callable fields remain
`unknown`: following their values requires value-flow analysis. In particular,
this fixture's call is `local_closure`, despite its parameter's bound:

```rust
fn shadowed<F: Fn()>(f: F) {
    let f = || {};
    f();
}
```

Rust call patterns also accept Boolean `:unsafe-context` (`unsafe_context` in
JSON). True selects calls inside an `unsafe` block or an `unsafe fn`; false
selects calls outside either context. Other pattern kinds reject the property,
and other languages report the existing unsupported-property diagnostic.

This query selects caller-supplied calls in unsafe contexts, a starting point
for panic-safety checks involving uninitialized memory:

```lisp
(filter :where ((callee_provenance eq caller_supplied))
  (call-shape (language rust (call :unsafe-context true))))
```

A panic-safety policy must additionally establish the hazardous ordering. The
regression policy joins these calls through `call-results` to calls to `set_len`
or `assume_init` in the same procedure, then uses `control-relations` dominance
to require initialization-state publication before the callback. It reports the
callback after `set_len`, and excludes callbacks before `set_len`, local
closures, and named helpers. The query above alone does not prove a defect.

## Async functions and await points

The callable's AST-backed `:async true` property scopes the query to the async
function. `(await)` selects its await expression, and `program-point-of`
projects that source match to its unique suspension point.

<!-- code-query-case:await-expression:rql -->
```lisp
(language rust
  (inside (function :name "wait_for_value" :async true)
    (await)))
```

<!-- code-query-case:await-expression:json -->
```json
{"languages":["rust"],"match":{"kind":"await"},"inside":{"kind":"function","name":"wait_for_value","async":true}}
```

<!-- code-query-case:await-expression:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "rust.wait_for_value",
      "end_line": 24,
      "kind": "await",
      "language": "rust",
      "path": "rust/lib.rs",
      "result_type": "structural_match",
      "start_line": 24,
      "text": "async_value().await"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:await-suspend-point:rql -->
```lisp
(language rust
  (program-point-of
    (inside (function :name "wait_for_value" :async true)
      (await))))
```

<!-- code-query-case:await-suspend-point:json -->
```json
{"languages":["rust"],"match":{"kind":"await"},"inside":{"kind":"function","name":"wait_for_value","async":true},"steps":[{"op":"program_point_of"}]}
```

<!-- code-query-case:await-suspend-point:expected -->
```json
{
  "results": [
    {
      "event_count": 4,
      "evidence": {
        "completeness": "complete",
        "proof": "proven"
      },
      "id": "<public-id>",
      "language": "rust",
      "path": "rust/lib.rs",
      "procedure_id": "<public-id>",
      "provenance": [
        {
          "seed": {
            "end_line": 24,
            "kind": "await",
            "path": "rust/lib.rs",
            "result_type": "structural_match",
            "start_line": 24
          },
          "steps": [
            {
              "op": "program_point_of",
              "result": {
                "id": "<public-id>",
                "path": "rust/lib.rs",
                "procedure_id": "<public-id>",
                "range": {
                  "end_column": 24,
                  "end_line": 24,
                  "start_column": 5,
                  "start_line": 24
                },
                "result_type": "program_point"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 24,
        "end_line": 24,
        "start_column": 5,
        "start_line": 24
      },
      "result_type": "program_point"
    }
  ],
  "truncated": false
}
```

## Grouped imports and signed assignments

Rust exposes the imported path through `module`, and signed numeric expressions are still normalized as `numeric_literal` values. The exact output proves that the query is structural rather than a text search.

<!-- code-query-case:import:rql -->
```lisp
(language rust (import :module (name "fmt")))
```

<!-- code-query-case:import:json -->
```json
{"languages":["rust"],"match":{"kind":"import","module":{"name":"fmt"}}}
```

<!-- code-query-case:import:expected -->
```json
{
  "results": [
    {
      "end_line": 1,
      "kind": "import",
      "language": "rust",
      "result_type": "structural_match",
      "path": "rust/lib.rs",
      "start_line": 1,
      "text": "use std::{fmt, io};"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:negative-limit:rql -->
```lisp
(language rust
  (assignment :left (name "LIMIT")
    :right (numeric_literal :capture "value")))
```

<!-- code-query-case:negative-limit:json -->
```json
{"languages":["rust"],"match":{"kind":"assignment","left":{"name":"LIMIT"},"right":{"kind":"numeric_literal","capture":"value"}}}
```

<!-- code-query-case:negative-limit:expected -->
```json
{
  "results": [
    {
      "captures": [
        {"name": "value", "start_line": 3, "text": "-3"}
      ],
      "enclosing_symbol": "rust._module_.LIMIT",
      "end_line": 3,
      "kind": "assignment",
      "language": "rust",
      "result_type": "structural_match",
      "path": "rust/lib.rs",
      "start_line": 3,
      "text": "const LIMIT: i32 = -3;"
    }
  ],
  "truncated": false
}
```

## Excluding closures and unsupported roles

`has` can prove that a closure contains a return node. Rust does not model named keyword arguments, so asking for `kwargs` returns a capability diagnostic; the example records that limitation instead of pretending the role exists.

<!-- code-query-case:closure:rql -->
```lisp
(language rust (lambda :has (return)))
```

<!-- code-query-case:closure:json -->
```json
{"languages":["rust"],"match":{"kind":"lambda","has":{"kind":"return"}}}
```

<!-- code-query-case:closure:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "rust.audit",
      "end_line": 13,
      "kind": "lambda",
      "language": "rust",
      "result_type": "structural_match",
      "path": "rust/lib.rs",
      "start_line": 13,
      "text": "|value: i32| { return value; }"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:unsupported-kwargs:rql -->
```lisp
(language rust
  (call :kwargs [(shell (boolean_literal))]))
```

<!-- code-query-case:unsupported-kwargs:json -->
```json
{"languages":["rust"],"match":{"kind":"call","kwargs":{"shell":{"kind":"boolean_literal"}}}}
```

<!-- code-query-case:unsupported-kwargs:expected -->
```json
{
  "diagnostics": [
    {
      "code": "unsupported_structural_feature",
      "impact": "incomplete",
      "language": "rust",
      "message": "structural adapter for rust does not support role(s): kwargs"
    }
  ],
  "results": [],
  "truncated": false
}
```

Rust does not expose `kwargs` or a normalized null-literal syntax in this adapter. Queries for those shapes should retain the returned capability diagnostic and be refined to roles Rust can prove, such as `receiver`, `args`, `module`, `decorators`, `left`, and `right`.

## Modules And Test-Gated Code

A `mod` declaration is the normalized `module` kind, and it is the containment
parent of everything it encloses. That makes "production code only" a
structural constraint rather than a path convention: `not-inside` a
`(module :name "tests")` drops the calls written inside the test module and
keeps the rest.

<!-- code-query-fixture:rust/modules.rs -->
```rust
fn load(raw: &str) -> String {
    raw.parse::<String>().unwrap()
}

mod tests {
    fn covers_load() {
        assert_eq!("1".parse::<String>().unwrap(), load("1"));
    }
}
```

<!-- code-query-case:module:rql -->
```lisp
(language rust (module :name "tests"))
```

<!-- code-query-case:module:json -->
```json
{"languages":["rust"],"match":{"kind":"module","name":"tests"}}
```

<!-- code-query-case:module:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "rust.tests",
      "end_line": 9,
      "kind": "module",
      "language": "rust",
      "path": "rust/modules.rs",
      "result_type": "structural_match",
      "start_line": 5,
      "text": "mod tests {\u2026"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:outside-test-module:rql -->
```lisp
(not-inside
  (module :name "tests")
  (language rust (call :callee (name "unwrap"))))
```

<!-- code-query-case:outside-test-module:json -->
```json
{"languages":["rust"],"match":{"kind":"call","callee":{"name":"unwrap"}},"not_inside":{"kind":"module","name":"tests"}}
```

<!-- code-query-case:outside-test-module:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "rust.load",
      "end_line": 2,
      "kind": "call",
      "language": "rust",
      "path": "rust/modules.rs",
      "result_type": "structural_match",
      "start_line": 2,
      "text": "raw.parse::<String>().unwrap()"
    }
  ],
  "truncated": false
}
```

## Traverse Indexed Types And Members

<!-- code-query-fixture:rust/hierarchy.rs -->
```rust
trait QueryRoot {
    fn query_member(&self);
}

struct QueryLeaf {
    value: i32,
}

impl QueryRoot for QueryLeaf {
    fn query_member(&self) {}
}
```

<!-- code-query-case:hierarchy-supertypes:rql -->
```lisp
(supertypes :transitive true (enclosing-decl (language rust (class :name "QueryLeaf"))))
```

<!-- code-query-case:hierarchy-supertypes:json -->
```json
{"languages":["rust"],"match":{"kind":"class","name":"QueryLeaf"},"steps":[{"op":"enclosing_decl"},{"op":"supertypes","transitive":true}]}
```

<!-- code-query-case:hierarchy-supertypes:expected -->
```json
{
  "results": [
    {
      "end_line": 3,
      "fq_name": "rust.QueryRoot",
      "kind": "class",
      "language": "rust",
      "path": "rust/hierarchy.rs",
      "provenance": [
        {
          "seed": {
            "end_line": 7,
            "kind": "class",
            "path": "rust/hierarchy.rs",
            "result_type": "structural_match",
            "start_line": 5
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 7,
                "fq_name": "rust.QueryLeaf",
                "kind": "class",
                "path": "rust/hierarchy.rs",
                "result_type": "declaration",
                "start_line": 5
              }
            },
            {
              "op": "supertypes",
              "result": {
                "end_line": 3,
                "fq_name": "rust.QueryRoot",
                "kind": "class",
                "path": "rust/hierarchy.rs",
                "result_type": "declaration",
                "start_line": 1
              }
            }
          ]
        }
      ],
      "result_type": "declaration",
      "signature": "trait QueryRoot {",
      "start_line": 1
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:hierarchy-subtype-members-owner:rql -->
```lisp
(owner (members (subtypes (enclosing-decl (language rust (class :name "QueryRoot"))))))
```

<!-- code-query-case:hierarchy-subtype-members-owner:json -->
```json
{"languages":["rust"],"match":{"kind":"class","name":"QueryRoot"},"steps":[{"op":"enclosing_decl"},{"op":"subtypes"},{"op":"members"},{"op":"owner"}]}
```

<!-- code-query-case:hierarchy-subtype-members-owner:expected -->
```json
{
  "results": [
    {
      "end_line": 7,
      "fq_name": "rust.QueryLeaf",
      "kind": "class",
      "language": "rust",
      "path": "rust/hierarchy.rs",
      "provenance": [
        {
          "seed": {
            "end_line": 3,
            "kind": "class",
            "path": "rust/hierarchy.rs",
            "result_type": "structural_match",
            "start_line": 1
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 3,
                "fq_name": "rust.QueryRoot",
                "kind": "class",
                "path": "rust/hierarchy.rs",
                "result_type": "declaration",
                "start_line": 1
              }
            },
            {
              "op": "subtypes",
              "result": {
                "end_line": 7,
                "fq_name": "rust.QueryLeaf",
                "kind": "class",
                "path": "rust/hierarchy.rs",
                "result_type": "declaration",
                "start_line": 5
              }
            },
            {
              "op": "members",
              "result": {
                "end_line": 10,
                "fq_name": "rust.QueryLeaf.query_member",
                "kind": "function",
                "path": "rust/hierarchy.rs",
                "result_type": "declaration",
                "start_line": 10
              }
            },
            {
              "op": "owner",
              "result": {
                "end_line": 7,
                "fq_name": "rust.QueryLeaf",
                "kind": "class",
                "path": "rust/hierarchy.rs",
                "result_type": "declaration",
                "start_line": 5
              }
            }
          ]
        },
        {
          "seed": {
            "end_line": 3,
            "kind": "class",
            "path": "rust/hierarchy.rs",
            "result_type": "structural_match",
            "start_line": 1
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 3,
                "fq_name": "rust.QueryRoot",
                "kind": "class",
                "path": "rust/hierarchy.rs",
                "result_type": "declaration",
                "start_line": 1
              }
            },
            {
              "op": "subtypes",
              "result": {
                "end_line": 7,
                "fq_name": "rust.QueryLeaf",
                "kind": "class",
                "path": "rust/hierarchy.rs",
                "result_type": "declaration",
                "start_line": 5
              }
            },
            {
              "op": "members",
              "result": {
                "end_line": 6,
                "fq_name": "rust.QueryLeaf.value",
                "kind": "field",
                "path": "rust/hierarchy.rs",
                "result_type": "declaration",
                "start_line": 6
              }
            },
            {
              "op": "owner",
              "result": {
                "end_line": 7,
                "fq_name": "rust.QueryLeaf",
                "kind": "class",
                "path": "rust/hierarchy.rs",
                "result_type": "declaration",
                "start_line": 5
              }
            }
          ]
        }
      ],
      "result_type": "declaration",
      "signature": "struct QueryLeaf {",
      "start_line": 5
    }
  ],
  "truncated": false
}
```

## Unsafe Send and Sync impl bounds

`rust_marker_impls_of` (also spelled `rust-marker-impls-of`) enumerates
positive `Send` and `Sync` impls for selected Rust structs, enums, and unions.
These marker impls require `unsafe` in Rust. The relation publishes facts for
policies to inspect; it does not decide whether an impl is sound.

```lisp
(rust-marker-impls-of (language rust (class)))
```

Each `rust_marker_impl` row describes one impl type parameter, its positional
mapping to a declaration parameter, its inline and where-clause bounds, and
its uses in the declaration's fields. An impl without type parameters still
emits a row with `parameter = null`. `impl_range` anchors the impl header.
Every row has `impl_coverage = "same_file"`: the relation searches the
selected declaration's file, including nested modules and function bodies,
but does not enumerate impls in other files. A clean result therefore does
not prove the absence of unsafe impls elsewhere.

Marker identity uses definition lookup first. When standard-library
declarations are unavailable, the fallback reads structured paths and import
bindings. The `trait_proof` values distinguish these cases:

| Proof | Identity evidence |
| --- | --- |
| `resolved` | Definition lookup identifies `core::marker::Send` or `std::marker::Send`, or the corresponding `Sync` declaration. |
| `prelude_name` | An unshadowed `Send` or `Sync` path, or its exact `core::marker` / `std::marker` path, is recognized in the declaring file. |
| `import_alias` | A single-segment name has exactly one same-file import binding to the standard marker, such as `use std::marker::Send as S2`. Multiple bindings or other import targets do not qualify. |

The same identity rules apply to marker bounds and `PhantomData` field heads.
Resolvable workspace traits can imply markers through their declared
supertraits. This syntax traversal visits at most 16 traits per bound and
respects the query's work and source limits. Unresolved supertraits and
unsupported external traits leave `bounds_proof = "open"`; unknown facts
must not be treated as missing bounds.

`uses` records each field and the wrappers surrounding its type-parameter
use. `stored` is true when at least one use has neither a `phantom` wrapper
nor a function-type (`fn`) wrapper. Thus `PhantomData<T>` and a function
return type alone do not count as storing `T`, while `*const T` and
`*mut T` do. `shared_ref_only` is true when every stored use has a shared
reference (`ref`) as its outermost wrapper. `&T` qualifies; `&mut T` and
`Box<&T>` do not. Policies use this flag together with `stored`.

A policy should report only rows with `completeness = "complete"`, using
these conditions:

- For `trait = "send"`: `stored AND NOT has_send_bound AND NOT
  (shared_ref_only AND has_sync_bound)`.
- For `trait = "sync"`: `stored AND NOT has_sync_bound AND NOT
  has_send_bound AND shared_access != "none"`.

`shared_access` is `touches` when a shared-reference method accesses a field
storing the parameter or lets its receiver escape, including macro uses,
unknown method calls, and calls to shared helpers that touch. It is `none`
when every shared method is analyzed without access, and `unknown` when
method syntax or the query budget prevents that conclusion. Send rows use
`not_applicable`. Exclusive receivers are excluded; methods implemented for a
reference self type count as shared. Associated functions accepting a shared
reference to the type are analyzed in the same way.

The Sync condition accepts a Send bound alone because a lock-like type can
be Sync when its protected value only needs to be Send, as with
`std::sync::Mutex<T>`. Requiring Sync for every stored parameter would flag
these valid impls. This rule favors precision: it does not analyze whether
an arbitrary wrapper actually provides that protection, and can therefore
miss unsound Sync impls that already have a Send bound. Macros or syntax
errors in field types leave the uses open and the row incomplete; they do
not support a finding under this rule. This relation supplies the Send/Sync
slice of #3855; its other declaration-linkage obligations remain separate.
