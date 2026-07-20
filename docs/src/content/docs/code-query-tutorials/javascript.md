---
title: JavaScript
description: Query JavaScript member calls, arrows, class expressions, field access, and new expressions with query_code.
---

> Last verified end to end: 2026-07-18 (`query_code` schema version 2).

For exact inbound and outbound symbol edges, proof tiers, and adapter-specific caveats, see [Reference Traversal](../reference-traversal/).

JavaScript normalizes functions, methods, constructors, arrows, class declarations and expressions, calls and `new`, imports, assignments, and member access. It does not invent keyword arguments for a language that has none.

## Fixture

<!-- code-query-fixture:javascript/app.js -->
```javascript
import service from "./service.js";

function audit(value) {
  return value;
}

class Runner {
  constructor(client) {
    this.client = client;
  }

  run(payload) {
    backup.send(payload);
    service.send(payload);
    return audit(payload);
  }
}

const factory = () => new Runner(service);
const Inline = class {
  save(value) {
    return service.send(value);
  }
};
```

## Narrow A Common Member Name

The fixture contains three `send` calls. Receiver and enclosing-method filters select only `service.send(payload)` in `Runner.run`.

<!-- code-query-case:service-send:rql -->
```lisp
(inside
  (method :name "run")
  (language javascript
    (call :callee "send" :receiver "service" :args [(capture "payload")])))
```

<!-- code-query-case:service-send:json -->
```json
{
  "languages": ["javascript"],
  "match": {
    "kind": "call",
    "callee": {"name": "send"},
    "receiver": {"name": "service"},
    "args": [{"capture": "payload"}]
  },
  "inside": {"kind": "method", "name": "run"}
}
```

<!-- code-query-case:service-send:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "javascript/app.js",
      "language": "javascript",
      "kind": "call",
      "start_line": 14,
      "end_line": 14,
      "text": "service.send(payload)",
      "captures": [
        {"name": "payload", "text": "payload", "start_line": 14}
      ],
      "enclosing_symbol": "Runner.run"
    }
  ],
  "truncated": false
}
```

## Find An Arrow That Constructs A Class

`new Runner(...)` is a normalized `call`, so an arrow can be selected by a descendant call whose callee is `Runner`.

<!-- code-query-case:factory-lambda:rql -->
```lisp
(lambda :capture "factory" (has (call :callee "Runner")))
```

<!-- code-query-case:factory-lambda:json -->
```json
{
  "match": {
    "kind": "lambda",
    "capture": "factory",
    "has": {"kind": "call", "callee": {"name": "Runner"}}
  }
}
```

<!-- code-query-case:factory-lambda:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "javascript/app.js",
      "language": "javascript",
      "kind": "lambda",
      "start_line": 19,
      "end_line": 19,
      "text": "() => new Runner(service)",
      "captures": [
        {
          "name": "factory",
          "text": "() => new Runner(service)",
          "start_line": 19
        }
      ],
      "enclosing_symbol": "factory"
    }
  ],
  "truncated": false
}
```

## Query A Class Expression And Field Access

Anonymous class expressions are queryable as `class`, but the assignment binding is not their normalized class name. A `text` regex selects the anonymous `class {` shape, while the descendant field access is constrained through normalized `object` and `field` roles.

<!-- code-query-case:inline-class:rql -->
```lisp
(class
  (text/regex "^class \\{")
  (has (field_access :object "service" :field "send")))
```

<!-- code-query-case:inline-class:json -->
```json
{
  "match": {
    "kind": "class",
    "text": {"regex": "^class \\{"},
    "has": {
      "kind": "field_access",
      "object": {"name": "service"},
      "field": {"name": "send"}
    }
  }
}
```

<!-- code-query-case:inline-class:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "javascript/app.js",
      "language": "javascript",
      "kind": "class",
      "start_line": 20,
      "end_line": 24,
      "text": "class {…",
      "enclosing_symbol": "app.js.Inline"
    }
  ],
  "truncated": false
}
```

## Unsupported Keyword Arguments

<!-- code-query-case:unsupported-kwargs:rql -->
```lisp
(language javascript (call :callee "send" :kwargs [(value (capture "value"))]))
```

<!-- code-query-case:unsupported-kwargs:json -->
```json
{
  "languages": ["javascript"],
  "match": {
    "kind": "call",
    "callee": {"name": "send"},
    "kwargs": {"value": {"capture": "value"}}
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
      "language": "javascript",
      "message": "structural adapter for javascript does not support role(s): kwargs"
    }
  ]
}
```

## Precision Boundary

`service` is matched as source structure, not resolved to the imported binding. Follow a structural result with symbol/usage tools when identity matters.

## Traverse Indexed Types And Members

<!-- code-query-fixture:javascript/hierarchy.js -->
```javascript
class QueryRoot {
  rootMember() {}
}

class QueryLeaf extends QueryRoot {
  leafMember() {}
}
```

<!-- code-query-case:hierarchy-supertypes:rql -->
```lisp
(supertypes (enclosing-decl (language javascript (class :name "QueryLeaf"))))
```

<!-- code-query-case:hierarchy-supertypes:json -->
```json
{"languages":["javascript"],"match":{"kind":"class","name":"QueryLeaf"},"steps":[{"op":"enclosing_decl"},{"op":"supertypes"}]}
```

<!-- code-query-case:hierarchy-supertypes:expected -->
```json
{
  "results": [
    {
      "end_line": 3,
      "fq_name": "QueryRoot",
      "kind": "class",
      "language": "javascript",
      "path": "javascript/hierarchy.js",
      "provenance": [
        {
          "seed": {
            "end_line": 7,
            "kind": "class",
            "path": "javascript/hierarchy.js",
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
                "path": "javascript/hierarchy.js",
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
                "path": "javascript/hierarchy.js",
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
(owner (members (subtypes :depth 2 (enclosing-decl (language javascript (class :name "QueryRoot"))))))
```

<!-- code-query-case:hierarchy-subtype-members-owner:json -->
```json
{"languages":["javascript"],"match":{"kind":"class","name":"QueryRoot"},"steps":[{"op":"enclosing_decl"},{"op":"subtypes","depth":2},{"op":"members"},{"op":"owner"}]}
```

<!-- code-query-case:hierarchy-subtype-members-owner:expected -->
```json
{
  "results": [
    {
      "end_line": 7,
      "fq_name": "QueryLeaf",
      "kind": "class",
      "language": "javascript",
      "path": "javascript/hierarchy.js",
      "provenance": [
        {
          "seed": {
            "end_line": 3,
            "kind": "class",
            "path": "javascript/hierarchy.js",
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
                "path": "javascript/hierarchy.js",
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
                "path": "javascript/hierarchy.js",
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
                "path": "javascript/hierarchy.js",
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
                "path": "javascript/hierarchy.js",
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
