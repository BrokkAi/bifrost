---
title: Scala
description: Query Scala named and block arguments, annotations, imports, and assignments with query_code.
---

> Last verified end to end: 2026-07-14 (`query_code` schema version 2).

Scala has several call shapes that look like assignments in source. The normalized adapter keeps named arguments in `kwargs`, while real `val`/`var` declarations remain `assignment` facts. It also exposes block arguments as structured descendants.

## Fixture

<!-- code-query-fixture:scala/App.scala -->
```scala
package app

import scala.util.Try
import scala.collection.mutable.{ListBuffer, Map as MutableMap}

@deprecated("use Service2", "1.0")
class Service(var name: String) {
  def run(code: String): String = {
    audit(code)
    val password = "hunter2"
    val callback = (value: String) => { return value }
    ListBuffer(1).foreach { value => audit(value.toString) }
    auditNamed(code = "named")
    this.name = "updated"
    code.toString
  }
}

def audit(code: String): String = code
def auditNamed(code: String): String = code
```

## Named arguments and block calls

Use `kwargs` for Scala named arguments. A block argument can be queried with `has`, which selects the `foreach` call containing an `audit` descendant.

<!-- code-query-case:named-call:rql -->
```lisp
(language scala
  (call :callee (name "auditNamed")
    :kwargs [(code (string_literal :capture "value"))]))
```

<!-- code-query-case:named-call:json -->
```json
{"languages":["scala"],"match":{"kind":"call","callee":{"name":"auditNamed"},"kwargs":{"code":{"kind":"string_literal","capture":"value"}}}}
```

<!-- code-query-case:named-call:expected -->
```json
{
  "results": [
    {
      "captures": [
        {"name": "value", "start_line": 13, "text": "\"named\""}
      ],
      "enclosing_symbol": "app.Service.run",
      "end_line": 13,
      "kind": "call",
      "language": "scala",
      "result_type": "structural_match",
      "path": "scala/App.scala",
      "start_line": 13,
      "text": "auditNamed(code = \"named\")"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:block-call:rql -->
```lisp
(language scala
  (call :callee (name "foreach")
    :args [(has (call :callee (name "audit")))]))
```

<!-- code-query-case:block-call:json -->
```json
{"languages":["scala"],"match":{"kind":"call","callee":{"name":"foreach"},"args":[{"has":{"kind":"call","callee":{"name":"audit"}}}]}}
```

<!-- code-query-case:block-call:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "app.Service.run",
      "end_line": 12,
      "kind": "call",
      "language": "scala",
      "result_type": "structural_match",
      "path": "scala/App.scala",
      "start_line": 12,
      "text": "ListBuffer(1).foreach { value => audit(value.toString) }"
    }
  ],
  "truncated": false
}
```

## Assignment precision and annotations

The assignment query finds the real `val password` declaration. It must not mistake `auditNamed(code = "named")` for an assignment, even though Scala represents the named argument with assignment-shaped syntax. Annotations are normalized as decorators on the enclosing class.

<!-- code-query-case:assignment:rql -->
```lisp
(language scala
  (assignment :left (name "password")
    :right (string_literal :capture "value")))
```

<!-- code-query-case:assignment:json -->
```json
{"languages":["scala"],"match":{"kind":"assignment","left":{"name":"password"},"right":{"kind":"string_literal","capture":"value"}}}
```

<!-- code-query-case:assignment:expected -->
```json
{
  "results": [
    {
      "captures": [
        {"name": "value", "start_line": 10, "text": "\"hunter2\""}
      ],
      "enclosing_symbol": "app.Service.run",
      "end_line": 10,
      "kind": "assignment",
      "language": "scala",
      "result_type": "structural_match",
      "path": "scala/App.scala",
      "start_line": 10,
      "text": "val password = \"hunter2\""
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:annotation:rql -->
```lisp
(language scala (class :decorators [(name "deprecated")]))
```

<!-- code-query-case:annotation:json -->
```json
{"languages":["scala"],"match":{"kind":"class","decorators":[{"name":"deprecated"}]}}
```

<!-- code-query-case:annotation:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "app.Service",
      "end_line": 17,
      "kind": "class",
      "language": "scala",
      "result_type": "structural_match",
      "path": "scala/App.scala",
      "start_line": 6,
      "text": "@deprecated(\"use Service2\", \"1.0\")…"
    }
  ],
  "truncated": false
}
```

## Imports and receivers

Grouped imports expose their imported selector or alias through `module`; path prefixes are not falsely reported as complete modules. Receiver and field roles similarly keep `service.run(...)` and `this.name` structurally separate from their terminal names.

<!-- code-query-case:import:rql -->
```lisp
(language scala (import :module (name "MutableMap")))
```

<!-- code-query-case:import:json -->
```json
{"languages":["scala"],"match":{"kind":"import","module":{"name":"MutableMap"}}}
```

<!-- code-query-case:import:expected -->
```json
{
  "results": [
    {
      "end_line": 4,
      "kind": "import",
      "language": "scala",
      "result_type": "structural_match",
      "path": "scala/App.scala",
      "start_line": 4,
      "text": "import scala.collection.mutable.{ListBuffer, Map as MutableMap}"
    }
  ],
  "truncated": false
}
```

## Traverse Indexed Types And Members

<!-- code-query-fixture:scala/QueryHierarchy.scala -->
```scala
class QueryRoot {
  def rootMember(): Unit = ()
}

class QueryLeaf extends QueryRoot {
  def leafMember(): Unit = ()
}
```

<!-- code-query-case:hierarchy-supertypes:rql -->
```lisp
(supertypes :transitive true (enclosing-decl (language scala (class :name "QueryLeaf"))))
```

<!-- code-query-case:hierarchy-supertypes:json -->
```json
{"languages":["scala"],"match":{"kind":"class","name":"QueryLeaf"},"steps":[{"op":"enclosing_decl"},{"op":"supertypes","transitive":true}]}
```

<!-- code-query-case:hierarchy-supertypes:expected -->
```json
{
  "results": [
    {
      "end_line": 3,
      "fq_name": "QueryRoot",
      "kind": "class",
      "language": "scala",
      "path": "scala/QueryHierarchy.scala",
      "provenance": [
        {
          "seed": {
            "end_line": 7,
            "kind": "class",
            "path": "scala/QueryHierarchy.scala",
            "result_type": "structural_match",
            "start_line": 5
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 7,
                "fq_name": "QueryLeaf",
                "kind": "class",
                "path": "scala/QueryHierarchy.scala",
                "result_type": "declaration",
                "start_line": 5
              }
            },
            {
              "op": "supertypes",
              "result": {
                "end_line": 3,
                "fq_name": "QueryRoot",
                "kind": "class",
                "path": "scala/QueryHierarchy.scala",
                "result_type": "declaration",
                "start_line": 1
              }
            }
          ]
        }
      ],
      "result_type": "declaration",
      "signature": "class QueryRoot {",
      "start_line": 1
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:hierarchy-subtype-members-owner:rql -->
```lisp
(owner (members (subtypes (enclosing-decl (language scala (class :name "QueryRoot"))))))
```

<!-- code-query-case:hierarchy-subtype-members-owner:json -->
```json
{"languages":["scala"],"match":{"kind":"class","name":"QueryRoot"},"steps":[{"op":"enclosing_decl"},{"op":"subtypes"},{"op":"members"},{"op":"owner"}]}
```

<!-- code-query-case:hierarchy-subtype-members-owner:expected -->
```json
{
  "results": [
    {
      "end_line": 7,
      "fq_name": "QueryLeaf",
      "kind": "class",
      "language": "scala",
      "path": "scala/QueryHierarchy.scala",
      "provenance": [
        {
          "seed": {
            "end_line": 3,
            "kind": "class",
            "path": "scala/QueryHierarchy.scala",
            "result_type": "structural_match",
            "start_line": 1
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 3,
                "fq_name": "QueryRoot",
                "kind": "class",
                "path": "scala/QueryHierarchy.scala",
                "result_type": "declaration",
                "start_line": 1
              }
            },
            {
              "op": "subtypes",
              "result": {
                "end_line": 7,
                "fq_name": "QueryLeaf",
                "kind": "class",
                "path": "scala/QueryHierarchy.scala",
                "result_type": "declaration",
                "start_line": 5
              }
            },
            {
              "op": "members",
              "result": {
                "end_line": 6,
                "fq_name": "QueryLeaf.leafMember",
                "kind": "function",
                "path": "scala/QueryHierarchy.scala",
                "result_type": "declaration",
                "start_line": 6
              }
            },
            {
              "op": "owner",
              "result": {
                "end_line": 7,
                "fq_name": "QueryLeaf",
                "kind": "class",
                "path": "scala/QueryHierarchy.scala",
                "result_type": "declaration",
                "start_line": 5
              }
            }
          ]
        }
      ],
      "result_type": "declaration",
      "signature": "class QueryLeaf {",
      "start_line": 5
    }
  ],
  "truncated": false
}
```
