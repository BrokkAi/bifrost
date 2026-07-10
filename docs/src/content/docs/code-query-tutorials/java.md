---
title: Java
description: Query Java member calls, constructors, annotations, exceptions, and control flow with query_code.
---

> Last verified end to end: 2026-07-10 (`query_code` schema version 1).

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
  "matches": [
    {
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
  "matches": [
    {
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
  "matches": [
    {
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
  "matches": [
    {
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
  "matches": [
    {
      "path": "java/App.java",
      "language": "java",
      "kind": "loop",
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
  "matches": [],
  "truncated": false,
  "diagnostics": [
    {
      "language": "java",
      "message": "structural adapter for java does not support role(s): kwargs"
    }
  ]
}
```

## Precision Boundary

Receiver names are syntactic. `receiver: "client"` does not prove that the variable has type `Client`; use symbol and usage tools when identity matters.
