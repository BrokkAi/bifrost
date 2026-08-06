---
title: Kotlin
description: Query Kotlin named arguments, block calls, annotations, imports, and assignments with query_code.
---

> Last verified end to end: 2026-07-30 (`query_code` schema version 1).

For exact inbound and outbound symbol edges, proof tiers, and adapter-specific caveats, see [Reference Traversal](../reference-traversal/).

Kotlin's grammar is field-poor: callees, navigation members, and named-argument labels are recovered positionally rather than through dedicated tree-sitter fields. The normalized adapter keeps named arguments in `kwargs`, while real `val`/`var` declarations remain `assignment` facts even though a named argument's `code = "named"` shares assignment-like syntax.

## Fixture

<!-- code-query-fixture:kotlin/App.kt -->
```kotlin
package app

import kotlin.math.max

@Deprecated("use Service2")
class Service(var name: String) {
    fun run(code: String): String {
        audit(code)
        val password = "hunter2"
        val callback = { value: String ->
            value
        }
        listOf(1).forEach { value ->
            audit(value.toString())
        }
        auditNamed(code = "named")
        this.name = "updated"
        return code
    }
}

fun audit(code: String): String {
    return code
}

fun auditNamed(code: String): String {
    return code
}
```

## Named arguments and block calls

Use `kwargs` for Kotlin named arguments. A block argument can be queried with `has`, which selects the `forEach` call containing an `audit` descendant.

<!-- code-query-case:named-call:rql -->
```lisp
(language kotlin
  (call :callee (name "auditNamed")
    :kwargs [(code (string_literal :capture "value"))]))
```

<!-- code-query-case:named-call:json -->
```json
{"languages":["kotlin"],"match":{"kind":"call","callee":{"name":"auditNamed"},"kwargs":{"code":{"kind":"string_literal","capture":"value"}}}}
```

<!-- code-query-case:named-call:expected -->
```json
{
  "results": [
    {
      "captures": [
        {"name": "value", "start_line": 16, "text": "\"named\""}
      ],
      "enclosing_symbol": "app.Service.run",
      "end_line": 16,
      "kind": "call",
      "language": "kotlin",
      "result_type": "structural_match",
      "path": "kotlin/App.kt",
      "start_line": 16,
      "text": "auditNamed(code = \"named\")"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:block-call:rql -->
```lisp
(language kotlin
  (call :callee (name "forEach")
    :args [(has (call :callee (name "audit")))]))
```

<!-- code-query-case:block-call:json -->
```json
{"languages":["kotlin"],"match":{"kind":"call","callee":{"name":"forEach"},"args":[{"has":{"kind":"call","callee":{"name":"audit"}}}]}}
```

<!-- code-query-case:block-call:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "app.Service.run",
      "end_line": 15,
      "kind": "call",
      "language": "kotlin",
      "result_type": "structural_match",
      "path": "kotlin/App.kt",
      "start_line": 13,
      "text": "listOf(1).forEach { value ->…"
    }
  ],
  "truncated": false
}
```

## Assignment precision and annotations

The assignment query finds the real `val password` declaration. It must not mistake `auditNamed(code = "named")` for an assignment, even though Kotlin represents the named argument with assignment-shaped syntax. Annotations are normalized as decorators on the enclosing class.

<!-- code-query-case:assignment:rql -->
```lisp
(language kotlin
  (assignment :left (name "password")
    :right (string_literal :capture "value")))
```

<!-- code-query-case:assignment:json -->
```json
{"languages":["kotlin"],"match":{"kind":"assignment","left":{"name":"password"},"right":{"kind":"string_literal","capture":"value"}}}
```

<!-- code-query-case:assignment:expected -->
```json
{
  "results": [
    {
      "captures": [
        {"name": "value", "start_line": 9, "text": "\"hunter2\""}
      ],
      "enclosing_symbol": "app.Service.run",
      "end_line": 9,
      "kind": "assignment",
      "language": "kotlin",
      "result_type": "structural_match",
      "path": "kotlin/App.kt",
      "start_line": 9,
      "text": "val password = \"hunter2\""
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:annotation:rql -->
```lisp
(language kotlin (class :decorators [(name "Deprecated")]))
```

<!-- code-query-case:annotation:json -->
```json
{"languages":["kotlin"],"match":{"kind":"class","decorators":[{"name":"Deprecated"}]}}
```

<!-- code-query-case:annotation:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "app.Service",
      "end_line": 20,
      "kind": "class",
      "language": "kotlin",
      "result_type": "structural_match",
      "path": "kotlin/App.kt",
      "start_line": 5,
      "text": "@Deprecated(\"use Service2\")…"
    }
  ],
  "truncated": false
}
```

## Imports and receivers

An `import` node exposes its imported name through `module`. Receiver and field roles similarly keep `this.name = "updated"` structurally separate from its terminal name.

<!-- code-query-case:import:rql -->
```lisp
(language kotlin (import :module (name "max")))
```

<!-- code-query-case:import:json -->
```json
{"languages":["kotlin"],"match":{"kind":"import","module":{"name":"max"}}}
```

<!-- code-query-case:import:expected -->
```json
{
  "results": [
    {
      "end_line": 3,
      "kind": "import",
      "language": "kotlin",
      "result_type": "structural_match",
      "path": "kotlin/App.kt",
      "start_line": 3,
      "text": "import kotlin.math.max"
    }
  ],
  "truncated": false
}
```

## Traverse Indexed Types And Members

<!-- code-query-fixture:kotlin/QueryHierarchy.kt -->
```kotlin
open class QueryRoot {
    fun rootMember() {
    }
}

class QueryLeaf : QueryRoot() {
    fun leafMember() {
    }
}
```

<!-- code-query-case:hierarchy-supertypes:rql -->
```lisp
(supertypes :transitive true (enclosing-decl (language kotlin (class :name "QueryLeaf"))))
```

<!-- code-query-case:hierarchy-supertypes:json -->
```json
{"languages":["kotlin"],"match":{"kind":"class","name":"QueryLeaf"},"steps":[{"op":"enclosing_decl"},{"op":"supertypes","transitive":true}]}
```

<!-- code-query-case:hierarchy-supertypes:expected -->
```json
{
  "results": [
    {
      "end_line": 4,
      "fq_name": "QueryRoot",
      "kind": "class",
      "language": "kotlin",
      "path": "kotlin/QueryHierarchy.kt",
      "provenance": [
        {
          "seed": {
            "end_line": 9,
            "kind": "class",
            "path": "kotlin/QueryHierarchy.kt",
            "result_type": "structural_match",
            "start_line": 6
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 9,
                "fq_name": "QueryLeaf",
                "kind": "class",
                "path": "kotlin/QueryHierarchy.kt",
                "result_type": "declaration",
                "start_line": 6
              }
            },
            {
              "op": "supertypes",
              "result": {
                "end_line": 4,
                "fq_name": "QueryRoot",
                "kind": "class",
                "path": "kotlin/QueryHierarchy.kt",
                "result_type": "declaration",
                "start_line": 1
              }
            }
          ]
        }
      ],
      "result_type": "declaration",
      "signature": "open class QueryRoot {",
      "start_line": 1
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:hierarchy-subtype-members-owner:rql -->
```lisp
(owner (members (subtypes (enclosing-decl (language kotlin (class :name "QueryRoot"))))))
```

<!-- code-query-case:hierarchy-subtype-members-owner:json -->
```json
{"languages":["kotlin"],"match":{"kind":"class","name":"QueryRoot"},"steps":[{"op":"enclosing_decl"},{"op":"subtypes"},{"op":"members"},{"op":"owner"}]}
```

<!-- code-query-case:hierarchy-subtype-members-owner:expected -->
```json
{
  "results": [
    {
      "end_line": 9,
      "fq_name": "QueryLeaf",
      "kind": "class",
      "language": "kotlin",
      "path": "kotlin/QueryHierarchy.kt",
      "provenance": [
        {
          "seed": {
            "end_line": 4,
            "kind": "class",
            "path": "kotlin/QueryHierarchy.kt",
            "result_type": "structural_match",
            "start_line": 1
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 4,
                "fq_name": "QueryRoot",
                "kind": "class",
                "path": "kotlin/QueryHierarchy.kt",
                "result_type": "declaration",
                "start_line": 1
              }
            },
            {
              "op": "subtypes",
              "result": {
                "end_line": 9,
                "fq_name": "QueryLeaf",
                "kind": "class",
                "path": "kotlin/QueryHierarchy.kt",
                "result_type": "declaration",
                "start_line": 6
              }
            },
            {
              "op": "members",
              "result": {
                "end_line": 8,
                "fq_name": "QueryLeaf.leafMember",
                "kind": "function",
                "path": "kotlin/QueryHierarchy.kt",
                "result_type": "declaration",
                "start_line": 7
              }
            },
            {
              "op": "owner",
              "result": {
                "end_line": 9,
                "fq_name": "QueryLeaf",
                "kind": "class",
                "path": "kotlin/QueryHierarchy.kt",
                "result_type": "declaration",
                "start_line": 6
              }
            }
          ]
        }
      ],
      "result_type": "declaration",
      "signature": "class QueryLeaf : QueryRoot() {",
      "start_line": 6
    }
  ],
  "truncated": false
}
```
