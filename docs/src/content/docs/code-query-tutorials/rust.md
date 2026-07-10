---
title: Rust
description: Query Rust calls, assignments, imports, closures, and method receivers with query_code.
---

> Last verified end to end: 2026-07-10 (`query_code` schema version 1).

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
  "matches": [
    {
      "enclosing_symbol": "rust.Service.run",
      "end_line": 8,
      "kind": "call",
      "language": "rust",
      "path": "rust/lib.rs",
      "start_line": 8,
      "text": "code.parse::<String>()"
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
  "matches": [
    {
      "end_line": 1,
      "kind": "import",
      "language": "rust",
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
  "matches": [
    {
      "captures": [
        {"name": "value", "start_line": 3, "text": "-3"}
      ],
      "enclosing_symbol": "rust._module_.LIMIT",
      "end_line": 3,
      "kind": "assignment",
      "language": "rust",
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
  "matches": [
    {
      "enclosing_symbol": "rust.audit",
      "end_line": 13,
      "kind": "lambda",
      "language": "rust",
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
      "language": "rust",
      "message": "structural adapter for rust does not support role(s): kwargs"
    }
  ],
  "matches": [],
  "truncated": false
}
```

Rust does not expose `kwargs`, `decorators`, or a normalized null-literal syntax in this adapter. Queries for those shapes should retain the returned capability diagnostic and be refined to roles Rust can prove, such as `receiver`, `args`, `module`, `left`, and `right`.
