---
title: JavaScript
description: Query JavaScript member calls, arrows, class expressions, field access, and new expressions with query_code.
---

> Last verified end to end: 2026-07-10 (`query_code` schema version 1).

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
  "matches": [
    {
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
  "matches": [
    {
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
  "matches": [
    {
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
  "matches": [],
  "truncated": false,
  "diagnostics": [
    {
      "language": "javascript",
      "message": "structural adapter for javascript does not support role(s): kwargs"
    }
  ]
}
```

## Precision Boundary

`service` is matched as source structure, not resolved to the imported binding. Follow a structural result with symbol/usage tools when identity matters.
