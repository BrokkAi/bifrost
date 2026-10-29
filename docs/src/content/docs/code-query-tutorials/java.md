---
title: Java
description: Query Java member calls, constructors, annotations, exceptions, and control flow with query_code.
---

> Last verified end to end: 2026-10-27 (`query_code` schema version 1).

For exact inbound and outbound symbol edges, proof tiers, and adapter-specific caveats, see [Reference Traversal](/code-query-tutorials/reference-traversal/).

Java normalizes methods, constructors, annotations, object creation, member calls, imports, assignments, exceptions, and control flow. The fixture includes two `post` receivers so receiver filtering proves a real exclusion.

## Fixture

<!-- code-query-fixture:java/App.java -->
```java
package app;

import java.io.IOException;

@interface Route {}

class Response {}

class Client {
    Response post(String path) { return new Response(); }
}

class Api {
    @Route
    Api() {}

    @Route
    Response save(Client client, Client backup, String path) {
        backup.post(path);
        try {
            if (path.isEmpty()) {
                throw new IllegalArgumentException();
            }
            while (path.startsWith("/")) {
                return client.post(path);
            }
            return new Response();
        } catch (RuntimeException error) {
            throw error;
        }
    }
}

class Batch {
    void drain(java.util.List<String> paths) {
        for (String path : paths) {
            path.trim();
        }
    }
}
```

## Narrow A Member Call

`callee: "post"` alone finds both calls. `receiver: "client"`, the positional capture, and `inside` select only the return-path call in `Api.save`.

<!-- code-query-case:client-post:rql -->
```lisp
(inside
  (method :name "save")
  (language java
    (call :callee "post" :receiver "client" :args [(capture "path")])) )
```

<!-- code-query-case:client-post:json -->
```json
{
  "languages": ["java"],
  "match": {
    "kind": "call",
    "callee": {"name": "post"},
    "receiver": {"name": "client"},
    "args": [{"capture": "path"}]
  },
  "inside": {"kind": "method", "name": "save"}
}
```

<!-- code-query-case:client-post:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "java/App.java",
      "language": "java",
      "kind": "call",
      "start_line": 25,
      "end_line": 25,
      "text": "client.post(path)",
      "captures": [{"name": "path", "text": "path", "start_line": 25}],
      "enclosing_symbol": "app.Api.save"
    }
  ],
  "truncated": false
}
```

## Analyze A Java Receiver

Java receiver traversal uses shared semantic value and heap evidence together with bounded Java type and definition resolution. This query starts from the exact `client.post(path)` structural match and returns the typed `Client` receiver with an explicit analysis outcome.

<!-- code-query-case:receiver-target:rql -->
```lisp
(receiver-targets
  (inside
    (method :name "save")
    (language java
      (call :callee "post" :receiver "client"))))
```

<!-- code-query-case:receiver-target:json -->
```json
{
  "languages": ["java"],
  "match": {
    "kind": "call",
    "callee": {"name": "post"},
    "receiver": {"name": "client"}
  },
  "inside": {"kind": "method", "name": "save"},
  "steps": [{"op": "receiver_targets"}]
}
```

<!-- code-query-case:receiver-target:expected -->
```json
{
  "results": [
    {
      "analysis_kind": "receiver_targets",
      "input_kind": "identifier",
      "language": "java",
      "outcome": "precise",
      "path": "java/App.java",
      "provenance": [
        {
          "seed": {
            "end_line": 25,
            "kind": "call",
            "path": "java/App.java",
            "result_type": "structural_match",
            "start_line": 25
          },
          "steps": [
            {
              "op": "receiver_targets",
              "result": {
                "analysis_kind": "receiver_targets",
                "outcome": "precise",
                "path": "java/App.java",
                "range": {
                  "end_column": 30,
                  "end_line": 25,
                  "start_column": 24,
                  "start_line": 25
                },
                "result_type": "receiver_analysis"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 30,
        "end_line": 25,
        "start_column": 24,
        "start_line": 25
      },
      "result_type": "receiver_analysis",
      "site_ast_id": "<public-id>",
      "site_id": "<public-id>",
      "text": "client",
      "values": [
        {
          "declaration": {
            "end_line": 11,
            "fq_name": "app.Client",
            "kind": "class",
            "language": "java",
            "path": "java/App.java",
            "signature": "class Client {",
            "start_line": 9
          },
          "receiver_value_kind": "instance_type"
        }
      ]
    }
  ],
  "truncated": false
}
```

The companion `points_to` and `member_targets` steps use the same receiver-query path. Every analyzed input returns `precise`, `ambiguous`, `unknown`, `unsupported`, or `exceeded_budget`; a zero-result is not substituted for uncertainty.

## Find An Annotated Constructor

Java annotations use the normalized `decorators` role. A constructor remains distinct from an ordinary method.

<!-- code-query-case:annotated-constructor:rql -->
```lisp
(constructor :name "Api" :decorators [(decorator :name "Route" :capture "annotation")])
```

<!-- code-query-case:annotated-constructor:json -->
```json
{
  "match": {
    "kind": "constructor",
    "name": "Api",
    "decorators": [
      {"kind": "decorator", "name": "Route", "capture": "annotation"}
    ]
  }
}
```

<!-- code-query-case:annotated-constructor:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "java/App.java",
      "language": "java",
      "kind": "constructor",
      "start_line": 14,
      "end_line": 15,
      "text": "@Route…",
      "captures": [
        {"name": "annotation", "text": "@Route", "start_line": 14}
      ],
      "enclosing_symbol": "app.Api.Api"
    }
  ],
  "truncated": false
}
```

## Query Exception And Control-Flow Shapes

`has` searches descendants, so these queries select only the catch, conditional, and loop that contain the requested statement shape.

<!-- code-query-case:catch-throw:rql -->
```lisp
(catch (has (throw :capture "rethrown")))
```

<!-- code-query-case:catch-throw:json -->
```json
{"match":{"kind":"catch","has":{"kind":"throw","capture":"rethrown"}}}
```

<!-- code-query-case:catch-throw:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "java/App.java",
      "language": "java",
      "kind": "catch",
      "start_line": 28,
      "end_line": 30,
      "text": "catch (RuntimeException error) {…",
      "captures": [
        {"name": "rethrown", "text": "throw error;", "start_line": 29}
      ],
      "enclosing_symbol": "app.Api.save"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:if-throw:rql -->
```lisp
(if (has (throw :capture "failure")))
```

<!-- code-query-case:if-throw:json -->
```json
{"match":{"kind":"if","has":{"kind":"throw","capture":"failure"}}}
```

<!-- code-query-case:if-throw:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "java/App.java",
      "language": "java",
      "kind": "if",
      "start_line": 21,
      "end_line": 23,
      "text": "if (path.isEmpty()) {…",
      "captures": [
        {
          "name": "failure",
          "text": "throw new IllegalArgumentException();",
          "start_line": 22
        }
      ],
      "enclosing_symbol": "app.Api.save"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:loop-return:rql -->
```lisp
(loop (has (return :capture "exit")))
```

<!-- code-query-case:loop-return:json -->
```json
{"match":{"kind":"loop","has":{"kind":"return","capture":"exit"}}}
```

<!-- code-query-case:loop-return:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "java/App.java",
      "language": "java",
      "kind": "while_loop",
      "start_line": 24,
      "end_line": 26,
      "text": "while (path.startsWith(\"/\")) {…",
      "captures": [
        {
          "name": "exit",
          "text": "return client.post(path);",
          "start_line": 25
        }
      ],
      "enclosing_symbol": "app.Api.save"
    }
  ],
  "truncated": false
}
```

## Refined Loop Kinds

`loop` is subtype-aware: the result above reports its refined kind
`while_loop`. Query `while_loop` directly for condition-controlled loops, or
`for_loop` for the for-each family (Java's enhanced `for`; the classic
counting `for` stays plain `loop`).

<!-- code-query-case:while-loop-return:rql -->
```lisp
(while_loop (has (return :capture "exit")))
```

<!-- code-query-case:while-loop-return:json -->
```json
{"match":{"kind":"while_loop","has":{"kind":"return","capture":"exit"}}}
```

<!-- code-query-case:while-loop-return:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "java/App.java",
      "language": "java",
      "kind": "while_loop",
      "start_line": 24,
      "end_line": 26,
      "text": "while (path.startsWith(\"/\")) {…",
      "captures": [
        {
          "name": "exit",
          "text": "return client.post(path);",
          "start_line": 25
        }
      ],
      "enclosing_symbol": "app.Api.save"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:for-each-work:rql -->
```lisp
(for_loop (has (call :callee (name "trim") :capture "work")))
```

<!-- code-query-case:for-each-work:json -->
```json
{"match":{"kind":"for_loop","has":{"kind":"call","callee":{"name":"trim"},"capture":"work"}}}
```

<!-- code-query-case:for-each-work:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "java/App.java",
      "language": "java",
      "kind": "for_loop",
      "start_line": 36,
      "end_line": 38,
      "text": "for (String path : paths) {…",
      "captures": [
        {
          "name": "work",
          "text": "path.trim()",
          "start_line": 37
        }
      ],
      "enclosing_symbol": "app.Batch.drain"
    }
  ],
  "truncated": false
}
```

## Match A Resource Release

`resource_release` matches a construct that releases a resource at its own
exit. In Java that is a `try`-with-resources statement: the statement carries
the implicit `close` of every resource its clause declares, so the construct,
not a spelled `close` call, is the source fact a lifecycle rule names.

<!-- code-query-case:resource-release:rql -->
```lisp
(language java (resource_release))
```

<!-- code-query-case:resource-release:json -->
```json
{"languages":["java"],"match":{"kind":"resource_release"}}
```

<!-- code-query-case:resource-release:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "QueryResource.release",
      "end_line": 17,
      "kind": "resource_release",
      "language": "java",
      "path": "java/QueryHierarchy.java",
      "result_type": "structural_match",
      "start_line": 15,
      "text": "try (QueryHandle handle = new QueryHandle()) {…"
    }
  ],
  "truncated": false
}
```

## Match A Lexical Scope

`block` matches a statement list that opens a scope of its own: a method body,
a bare block, the body of a loop or conditional, and a `switch` body. Class
bodies are member lists, not statement lists, so they never match. Combine it
with `inside` to reach one specific scope.

<!-- code-query-case:loop-body-scope:rql -->
```lisp
(inside (for_loop) (language java (block (has (call :callee (name "trim") :capture "work")))))
```

<!-- code-query-case:loop-body-scope:json -->
```json
{
  "languages": ["java"],
  "match": {
    "kind": "block",
    "has": {"kind": "call", "callee": {"name": "trim"}, "capture": "work"}
  },
  "inside": {"kind": "for_loop"}
}
```

<!-- code-query-case:loop-body-scope:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "java/App.java",
      "language": "java",
      "kind": "block",
      "start_line": 36,
      "end_line": 38,
      "text": "{…",
      "captures": [
        {
          "name": "work",
          "text": "path.trim()",
          "start_line": 37
        }
      ],
      "enclosing_symbol": "app.Batch.drain"
    }
  ],
  "truncated": false
}
```

## Unsupported Keyword Arguments

Java has positional arguments but no keyword-argument syntax. Asking for `kwargs` produces a capability diagnostic and no pretend match.

<!-- code-query-case:unsupported-kwargs:rql -->
```lisp
(language java (call :callee "post" :kwargs [(path (name "path"))]))
```

<!-- code-query-case:unsupported-kwargs:json -->
```json
{
  "languages": ["java"],
  "match": {
    "kind": "call",
    "callee": {"name": "post"},
    "kwargs": {"path": {"name": "path"}}
  }
}
```

<!-- code-query-case:unsupported-kwargs:expected -->
```json
{
  "results": [],
  "truncated": false,
  "diagnostics": [
    {
      "code": "unsupported_structural_feature",
      "impact": "incomplete",
      "language": "java",
      "message": "structural adapter for java does not support role(s): kwargs"
    }
  ]
}
```

## Precision Boundary

Receiver names are syntactic. `receiver: "client"` does not prove that the variable has type `Client`; use symbol and usage tools when identity matters.

## Traverse Indexed Types And Members

<!-- code-query-fixture:java/QueryHierarchy.java -->
```java
class QueryRoot {
    void rootMember() {}
}

class QueryLeaf extends QueryRoot {
    void leafMember() {}
}

class QueryHandle implements AutoCloseable {
    public void close() {}
}

class QueryResource {
    void release() {
        try (QueryHandle handle = new QueryHandle()) {
            handle.hashCode();
        }
    }
}
```

<!-- code-query-case:hierarchy-supertypes:rql -->
```lisp
(supertypes (enclosing-decl (language java (class :name "QueryLeaf"))))
```

<!-- code-query-case:hierarchy-supertypes:json -->
```json
{"languages":["java"],"match":{"kind":"class","name":"QueryLeaf"},"steps":[{"op":"enclosing_decl"},{"op":"supertypes"}]}
```

<!-- code-query-case:hierarchy-supertypes:expected -->
```json
{
  "results": [
    {
      "end_line": 3,
      "fq_name": "QueryRoot",
      "kind": "class",
      "language": "java",
      "path": "java/QueryHierarchy.java",
      "provenance": [
        {
          "seed": {
            "end_line": 7,
            "kind": "class",
            "path": "java/QueryHierarchy.java",
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
                "path": "java/QueryHierarchy.java",
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
                "path": "java/QueryHierarchy.java",
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
(owner (members (subtypes :transitive true (enclosing-decl (language java (class :name "QueryRoot"))))))
```

<!-- code-query-case:hierarchy-subtype-members-owner:json -->
```json
{"languages":["java"],"match":{"kind":"class","name":"QueryRoot"},"steps":[{"op":"enclosing_decl"},{"op":"subtypes","transitive":true},{"op":"members"},{"op":"owner"}]}
```

<!-- code-query-case:hierarchy-subtype-members-owner:expected -->
```json
{
  "results": [
    {
      "end_line": 7,
      "fq_name": "QueryLeaf",
      "kind": "class",
      "language": "java",
      "path": "java/QueryHierarchy.java",
      "provenance": [
        {
          "seed": {
            "end_line": 3,
            "kind": "class",
            "path": "java/QueryHierarchy.java",
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
                "path": "java/QueryHierarchy.java",
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
                "path": "java/QueryHierarchy.java",
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
                "path": "java/QueryHierarchy.java",
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
                "path": "java/QueryHierarchy.java",
                "result_type": "declaration",
                "start_line": 5
              }
            }
          ]
        }
      ],
      "result_type": "declaration",
      "signature": "class QueryLeaf extends QueryRoot {",
      "start_line": 5
    }
  ],
  "truncated": false
}
```

## Query expression operands and branches

A cast exposes its target `type` and its input `value`. An `instance_of`
expression exposes its `operand`, tested `type`, and optional pattern
`binding`. The conditional expression uses `if` with `test`, `consequence`,
and `alternative` roles.

<!-- code-query-fixture:java/Shapes.java -->
```java
class Shapes {
    void inspect(Object value, int size, boolean flag) {
        String text = (String) value;
        if (value instanceof String match) {}
        int picked = flag ? size : 0;
        int[] values = new int[size];
        int negative = -size;
        outer: while (flag) {
            continue outer;
        }
    }
}
```

<!-- code-query-case:cast-type:rql -->
```lisp
(language java (cast :type (capture "target") :value (capture "input")))
```

<!-- code-query-case:cast-type:json -->
```json
{"languages":["java"],"match":{"kind":"cast","type":{"capture":"target"},"value":{"capture":"input"}}}
```

<!-- code-query-case:cast-type:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "java/Shapes.java",
      "language": "java",
      "kind": "cast",
      "start_line": 3,
      "end_line": 3,
      "text": "(String) value",
      "enclosing_symbol": "Shapes.inspect",
      "captures": [
        {
          "name": "input",
          "text": "value",
          "start_line": 3
        },
        {
          "name": "target",
          "text": "String",
          "start_line": 3
        }
      ]
    }
  ],
  "truncated": false
}
```


<!-- code-query-case:instance-binding:rql -->
```lisp
(language java (instance_of :operand (capture "input") :type (capture "target") :binding (capture "bound")))
```

<!-- code-query-case:instance-binding:json -->
```json
{"languages":["java"],"match":{"kind":"instance_of","operand":{"capture":"input"},"type":{"capture":"target"},"binding":{"capture":"bound"}}}
```

<!-- code-query-case:instance-binding:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "java/Shapes.java",
      "language": "java",
      "kind": "instance_of",
      "start_line": 4,
      "end_line": 4,
      "text": "value instanceof String match",
      "enclosing_symbol": "Shapes.inspect",
      "captures": [
        {
          "name": "target",
          "text": "String",
          "start_line": 4
        },
        {
          "name": "input",
          "text": "value",
          "start_line": 4
        },
        {
          "name": "bound",
          "text": "match",
          "start_line": 4
        }
      ]
    }
  ],
  "truncated": false
}
```


<!-- code-query-case:conditional-branches:rql -->
```lisp
(language java (if :test (capture "condition") :consequence (capture "yes") :alternative (capture "no")))
```

<!-- code-query-case:conditional-branches:json -->
```json
{"languages":["java"],"match":{"kind":"if","test":{"capture":"condition"},"consequence":{"capture":"yes"},"alternative":{"capture":"no"}}}
```

<!-- code-query-case:conditional-branches:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "java/Shapes.java",
      "language": "java",
      "kind": "if",
      "start_line": 5,
      "end_line": 5,
      "text": "flag ? size : 0",
      "enclosing_symbol": "Shapes.inspect",
      "captures": [
        {
          "name": "condition",
          "text": "flag",
          "start_line": 5
        },
        {
          "name": "yes",
          "text": "size",
          "start_line": 5
        },
        {
          "name": "no",
          "text": "0",
          "start_line": 5
        }
      ]
    }
  ],
  "truncated": false
}
```


Array creation separates the element `type` from its `dimensions`, whose
spans include the brackets. Unary
expressions expose their `operand`. A labeled jump exposes the destination
through `label`.

<!-- code-query-case:array-dimension:rql -->
```lisp
(language java (array_creation :type (capture "element") :dimensions [(capture "size")]))
```

<!-- code-query-case:array-dimension:json -->
```json
{"languages":["java"],"match":{"kind":"array_creation","type":{"capture":"element"},"dimensions":[{"capture":"size"}]}}
```

<!-- code-query-case:array-dimension:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "java/Shapes.java",
      "language": "java",
      "kind": "array_creation",
      "start_line": 6,
      "end_line": 6,
      "text": "new int[size]",
      "enclosing_symbol": "Shapes.inspect",
      "captures": [
        {
          "name": "element",
          "text": "int",
          "start_line": 6
        },
        {
          "name": "size",
          "text": "[size]",
          "start_line": 6
        }
      ]
    }
  ],
  "truncated": false
}
```


<!-- code-query-case:unary-operand:rql -->
```lisp
(language java (unary_expression :operand (capture "input")))
```

<!-- code-query-case:unary-operand:json -->
```json
{"languages":["java"],"match":{"kind":"unary_expression","operand":{"capture":"input"}}}
```

<!-- code-query-case:unary-operand:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "java/Shapes.java",
      "language": "java",
      "kind": "unary_expression",
      "start_line": 7,
      "end_line": 7,
      "text": "-size",
      "enclosing_symbol": "Shapes.inspect",
      "captures": [
        {
          "name": "input",
          "text": "size",
          "start_line": 7
        }
      ]
    }
  ],
  "truncated": false
}
```


<!-- code-query-case:continue-label:rql -->
```lisp
(language java (continue :label (capture "destination")))
```

<!-- code-query-case:continue-label:json -->
```json
{"languages":["java"],"match":{"kind":"continue","label":{"capture":"destination"}}}
```

<!-- code-query-case:continue-label:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "java/Shapes.java",
      "language": "java",
      "kind": "continue",
      "start_line": 9,
      "end_line": 9,
      "text": "continue outer;",
      "enclosing_symbol": "Shapes.inspect",
      "captures": [
        {
          "name": "destination",
          "text": "outer",
          "start_line": 9
        }
      ]
    }
  ],
  "truncated": false
}
```

## Select array indices

A Java array access is a `subscript`. Its `object` is the indexed array and
its `indices` are the index expressions.

<!-- code-query-fixture:java/Indexing.java -->
```java
class Indexing {
    int first(int[] values) {
        return values[0];
    }
}
```

<!-- code-query-case:subscript-index:rql -->
```lisp
(language java (subscript :object (name "values") :indices [(capture "index")]))
```

<!-- code-query-case:subscript-index:json -->
```json
{"languages":["java"],"match":{"kind":"subscript","object":{"name":"values"},"indices":[{"capture":"index"}]}}
```

<!-- code-query-case:subscript-index:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "java/Indexing.java",
      "language": "java",
      "kind": "subscript",
      "start_line": 3,
      "end_line": 3,
      "text": "values[0]",
      "enclosing_symbol": "Indexing.first",
      "captures": [
        {
          "name": "index",
          "text": "0",
          "start_line": 3
        }
      ]
    }
  ],
  "truncated": false
}
```
