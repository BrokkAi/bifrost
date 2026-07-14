---
title: Python
description: Query Python calls, decorators, assignments, keyword arguments, and callable containment with query_code.
---

> Last verified end to end: 2026-07-14 (`query_code` schema version 2).

For exact inbound and outbound symbol edges, proof tiers, and adapter-specific caveats, see [Reference Traversal](../reference-traversal/).

Python exposes calls, receiver/member access, positional and keyword arguments, imports, assignments, decorated declarations, callable refinements, literals, and control-flow nodes through the normalized model. These examples deliberately include two `client.post(...)` calls so the narrowing query has something real to exclude.

## Fixture

<!-- code-query-fixture:python/app.py -->
```python
from web import route

def audit(value):
    return value

class Api:
    @route("/save")
    def save(self, client, payload):
        result = client.post("/items", json=payload)
        audit(result)
        return result

def helper(client, payload):
    client.post("/items", json=payload)

save_lambda = lambda payload: audit(payload)
```

## Narrow A Member Call

The broad shape “call named `post`” finds both calls. Adding `receiver`, ordered `args`, `kwargs`, `inside`, `not_inside`, `languages`, and `where` selects only the production method and captures both values.

<!-- code-query-case:filtered-post:rql -->
```lisp
(not-inside
  (function :name "helper")
  (inside
    (method :name "save")
    (where "python/**/*.py"
      (language python
        (call
          :callee "post"
          :receiver "client"
          :args [(capture "path")]
          :kwargs [(json (capture "payload"))])))))
```

<!-- code-query-case:filtered-post:json -->
```json
{
  "where": ["python/**/*.py"],
  "languages": ["python"],
  "match": {
    "kind": "call",
    "callee": {"name": "post"},
    "receiver": {"name": "client"},
    "args": [{"capture": "path"}],
    "kwargs": {"json": {"capture": "payload"}}
  },
  "inside": {"kind": "method", "name": "save"},
  "not_inside": {"kind": "function", "name": "helper"}
}
```

<!-- code-query-case:filtered-post:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "python/app.py",
      "language": "python",
      "kind": "call",
      "start_line": 9,
      "end_line": 9,
      "text": "client.post(\"/items\", json=payload)",
      "captures": [
        {"name": "path", "text": "\"/items\"", "start_line": 9},
        {"name": "payload", "text": "payload", "start_line": 9}
      ],
      "enclosing_symbol": "python.app.Api.save"
    }
  ],
  "truncated": false
}
```

The exact result excludes the identical call in `helper`; this is structural candidate narrowing, not type or call-graph reasoning.

## Match A Decorated Method With An Assignment

This query requires a `route` decorator and an assignment whose left side is the identifier `result` and whose right side is a call to `post`. It exercises the `decorators`, `left`, and `right` roles without inspecting Python grammar node names.

<!-- code-query-case:decorated-assignment:rql -->
```lisp
(method
  :name "save"
  :decorators [(decorator :name "route" :capture "decorator")]
  (has
    (assignment
      :left (identifier :name "result")
      :right (call :callee "post"))))
```

<!-- code-query-case:decorated-assignment:json -->
```json
{
  "match": {
    "kind": "method",
    "name": "save",
    "decorators": [
      {"kind": "decorator", "name": "route", "capture": "decorator"}
    ],
    "has": {
      "kind": "assignment",
      "left": {"kind": "identifier", "name": "result"},
      "right": {"kind": "call", "callee": {"name": "post"}}
    }
  }
}
```

<!-- code-query-case:decorated-assignment:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "python/app.py",
      "language": "python",
      "kind": "method",
      "start_line": 8,
      "end_line": 11,
      "text": "def save(self, client, payload):…",
      "captures": [
        {
          "name": "decorator",
          "text": "@route(\"/save\")",
          "start_line": 7
        }
      ],
      "enclosing_symbol": "python.app.Api.save"
    }
  ],
  "truncated": false
}
```

## Exclude Anonymous Callables

`callable` is subtype-aware. `not_kind` removes lambdas, while `has` keeps only named callables that contain an `audit` call. The lambda at the bottom is therefore excluded even though it also calls `audit`.

<!-- code-query-case:named-callables:rql -->
```lisp
(callable
  (not-kind lambda)
  (name/regex "^(save|helper)$")
  (has (call :callee "audit")))
```

<!-- code-query-case:named-callables:json -->
```json
{
  "match": {
    "kind": "callable",
    "not_kind": "lambda",
    "name": {"regex": "^(save|helper)$"},
    "has": {"kind": "call", "callee": {"name": "audit"}}
  }
}
```

<!-- code-query-case:named-callables:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "python/app.py",
      "language": "python",
      "kind": "method",
      "start_line": 8,
      "end_line": 11,
      "text": "def save(self, client, payload):…",
      "enclosing_symbol": "python.app.Api.save"
    }
  ],
  "truncated": false
}
```

## Precision Boundary

These matches are syntactic. `receiver: "client"` checks the normalized receiver name; it does not prove the receiver's runtime type. Use `scan_usages` after `query_code` when symbol identity matters.

## Traverse Indexed Types And Members

<!-- code-query-fixture:python/hierarchy.py -->
```python
class QueryRoot:
    def root_member(self):
        pass

class QueryLeaf(QueryRoot):
    def leaf_member(self):
        pass
```

`supertypes` supports bounded closure; here depth two includes every indexed ancestor one or two edges away.

<!-- code-query-case:hierarchy-supertypes:rql -->
```lisp
(supertypes :depth 2 (enclosing-decl (language python (class :name "QueryLeaf"))))
```

<!-- code-query-case:hierarchy-supertypes:json -->
```json
{"languages":["python"],"match":{"kind":"class","name":"QueryLeaf"},"steps":[{"op":"enclosing_decl"},{"op":"supertypes","depth":2}]}
```

<!-- code-query-case:hierarchy-supertypes:expected -->
```json
{
  "results": [
    {
      "end_line": 3,
      "fq_name": "python.hierarchy.QueryRoot",
      "kind": "class",
      "language": "python",
      "path": "python/hierarchy.py",
      "provenance": [
        {
          "seed": {
            "end_line": 7,
            "kind": "class",
            "path": "python/hierarchy.py",
            "result_type": "structural_match",
            "start_line": 5
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 7,
                "fq_name": "python.hierarchy.QueryLeaf",
                "kind": "class",
                "path": "python/hierarchy.py",
                "result_type": "declaration",
                "start_line": 5
              }
            },
            {
              "op": "supertypes",
              "result": {
                "end_line": 3,
                "fq_name": "python.hierarchy.QueryRoot",
                "kind": "class",
                "path": "python/hierarchy.py",
                "result_type": "declaration",
                "start_line": 1
              }
            }
          ]
        }
      ],
      "result_type": "declaration",
      "signature": "class QueryRoot:",
      "start_line": 1
    }
  ],
  "truncated": false
}
```

This compact pipeline finds direct `subtypes`, lists their direct `members`, then uses `owner` to recover each exact declaring type.

<!-- code-query-case:hierarchy-subtype-members-owner:rql -->
```lisp
(owner (members (subtypes (enclosing-decl (language python (class :name "QueryRoot"))))))
```

<!-- code-query-case:hierarchy-subtype-members-owner:json -->
```json
{"languages":["python"],"match":{"kind":"class","name":"QueryRoot"},"steps":[{"op":"enclosing_decl"},{"op":"subtypes"},{"op":"members"},{"op":"owner"}]}
```

<!-- code-query-case:hierarchy-subtype-members-owner:expected -->
```json
{
  "results": [
    {
      "end_line": 7,
      "fq_name": "python.hierarchy.QueryLeaf",
      "kind": "class",
      "language": "python",
      "path": "python/hierarchy.py",
      "provenance": [
        {
          "seed": {
            "end_line": 3,
            "kind": "class",
            "path": "python/hierarchy.py",
            "result_type": "structural_match",
            "start_line": 1
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 3,
                "fq_name": "python.hierarchy.QueryRoot",
                "kind": "class",
                "path": "python/hierarchy.py",
                "result_type": "declaration",
                "start_line": 1
              }
            },
            {
              "op": "subtypes",
              "result": {
                "end_line": 7,
                "fq_name": "python.hierarchy.QueryLeaf",
                "kind": "class",
                "path": "python/hierarchy.py",
                "result_type": "declaration",
                "start_line": 5
              }
            },
            {
              "op": "members",
              "result": {
                "end_line": 7,
                "fq_name": "python.hierarchy.QueryLeaf.leaf_member",
                "kind": "function",
                "path": "python/hierarchy.py",
                "result_type": "declaration",
                "start_line": 6
              }
            },
            {
              "op": "owner",
              "result": {
                "end_line": 7,
                "fq_name": "python.hierarchy.QueryLeaf",
                "kind": "class",
                "path": "python/hierarchy.py",
                "result_type": "declaration",
                "start_line": 5
              }
            }
          ]
        }
      ],
      "result_type": "declaration",
      "signature": "class QueryLeaf(QueryRoot):",
      "start_line": 5
    }
  ],
  "truncated": false
}
```
