---
title: Go
description: Query Go selector calls, multi-value assignments, imports, methods, and capability diagnostics with query_code.
---

> Last verified end to end: 2026-07-14 (`query_code` schema version 2).

Go normalizes selector calls, functions and methods, type declarations and aliases, function literals, grouped imports, multi-value assignments, returns, conditionals, and loops. It does not model keyword arguments or decorators.

## Fixture

<!-- code-query-fixture:go/app.go -->
```go
package app

import (
    "context"
    log "fmt"
)

type Service struct{}
type ServiceAlias = Service

func load() ([]string, error) { return nil, nil }

func (s Service) Send(ctx context.Context, value string) string {
    return value
}

func run(primary Service, backup Service) string {
    values, err := load()
    if err != nil {
        return ""
    }
    go func() { backup.Send(context.Background(), "background") }()
    for _, value := range values {
        primary.Send(context.Background(), value)
    }
    log.Println(err)
    return values[0]
}
```

## Exclude A Call By Descendant Shape

Both services call `Send`. `not_has` removes the call containing the literal `"background"`; `inside` and path/language scoping keep the query local to `run`.

<!-- code-query-case:foreground-send:rql -->
```lisp
(inside
  (function :name "run")
  (where "go/**/*.go"
    (language go
      (call
        :callee "Send"
        :args [(capture "context") (capture "value")]
        (not-has (string_literal (text/regex "background")))))))
```

<!-- code-query-case:foreground-send:json -->
```json
{
  "where": ["go/**/*.go"],
  "languages": ["go"],
  "match": {
    "kind": "call",
    "callee": {"name": "Send"},
    "args": [{"capture": "context"}, {"capture": "value"}],
    "not_has": {"kind": "string_literal", "text": {"regex": "background"}}
  },
  "inside": {"kind": "function", "name": "run"}
}
```

<!-- code-query-case:foreground-send:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "go/app.go",
      "language": "go",
      "kind": "call",
      "start_line": 24,
      "end_line": 24,
      "text": "primary.Send(context.Background(), value)",
      "captures": [
        {"name":"context","text":"context.Background()","start_line":24},
        {"name":"value","text":"value","start_line":24}
      ],
      "enclosing_symbol": "go.run"
    }
  ],
  "truncated": false
}
```

## Match A Multi-Value Assignment

Go attaches repeated structured left and right targets. This query selects the assignment containing `values` and a `load` call without parsing comma-separated text.

<!-- code-query-case:load-assignment:rql -->
```lisp
(assignment
  :left (identifier :name "values" :capture "first-left")
  :right (call :callee "load" :capture "loader"))
```

<!-- code-query-case:load-assignment:json -->
```json
{
  "match": {
    "kind": "assignment",
    "left": {"kind": "identifier", "name": "values", "capture": "first-left"},
    "right": {"kind": "call", "callee": {"name": "load"}, "capture": "loader"}
  }
}
```

<!-- code-query-case:load-assignment:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "go/app.go",
      "language": "go",
      "kind": "assignment",
      "start_line": 18,
      "end_line": 18,
      "text": "values, err := load()",
      "captures": [
        {"name":"first-left","text":"values","start_line":18},
        {"name":"loader","text":"load()","start_line":18}
      ],
      "enclosing_symbol": "go.run"
    }
  ],
  "truncated": false
}
```

## Query A Grouped Import Path

The module role is the imported path, not the local alias used by later Go expressions.

<!-- code-query-case:import-path:rql -->
```lisp
(language go (import :module "fmt"))
```

<!-- code-query-case:import-path:json -->
```json
{"languages":["go"],"match":{"kind":"import","module":{"name":"fmt"}}}
```

<!-- code-query-case:import-path:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "go/app.go",
      "language": "go",
      "kind": "import",
      "start_line": 3,
      "end_line": 6,
      "text": "import (…"
    }
  ],
  "truncated": false
}
```

## Capability Diagnostics

<!-- code-query-case:unsupported-kwargs:rql -->
```lisp
(language go (call :callee "Send" :kwargs [(value (capture "value"))]))
```

<!-- code-query-case:unsupported-kwargs:json -->
```json
{"languages":["go"],"match":{"kind":"call","callee":{"name":"Send"},"kwargs":{"value":{"capture":"value"}}}}
```

<!-- code-query-case:unsupported-kwargs:expected -->
```json
{"results":[],"truncated":false,"diagnostics":[{"language":"go","message":"structural adapter for go does not support role(s): kwargs"}]}
```

<!-- code-query-case:unsupported-decorators:rql -->
```lisp
(language go (method :name "Send" :decorators [(name "Route")]))
```

<!-- code-query-case:unsupported-decorators:json -->
```json
{"languages":["go"],"match":{"kind":"method","name":"Send","decorators":[{"name":"Route"}]}}
```

<!-- code-query-case:unsupported-decorators:expected -->
```json
{"results":[],"truncated":false,"diagnostics":[{"language":"go","message":"structural adapter for go does not support role(s): decorators"}]}
```

## Precision Boundary

The `ServiceAlias` type alias is a normalized `declaration`; Go's `type Service struct{}` is class-like. Import queries expose `fmt`, not its local alias `log`. These normalized facts intentionally do not reproduce every Go declaration or binding distinction.

## Traverse Indexed Types And Members

<!-- code-query-fixture:go/hierarchy.go -->
```go
package hierarchy

type QueryRoot interface {
    QueryMember()
}

type QueryLeaf struct{}

func (QueryLeaf) QueryMember() {}
```

<!-- code-query-case:hierarchy-supertypes:rql -->
```lisp
(supertypes (enclosing-decl (language go (class :name "QueryLeaf"))))
```

<!-- code-query-case:hierarchy-supertypes:json -->
```json
{"languages":["go"],"match":{"kind":"class","name":"QueryLeaf"},"steps":[{"op":"enclosing_decl"},{"op":"supertypes"}]}
```

<!-- code-query-case:hierarchy-supertypes:expected -->
```json
{
  "results": [
    {
      "end_line": 5,
      "fq_name": "go.QueryRoot",
      "kind": "class",
      "language": "go",
      "path": "go/hierarchy.go",
      "provenance": [
        {
          "seed": {
            "end_line": 7,
            "kind": "class",
            "path": "go/hierarchy.go",
            "result_type": "structural_match",
            "start_line": 7
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 7,
                "fq_name": "go.QueryLeaf",
                "kind": "class",
                "path": "go/hierarchy.go",
                "result_type": "declaration",
                "start_line": 7
              }
            },
            {
              "op": "supertypes",
              "result": {
                "end_line": 5,
                "fq_name": "go.QueryRoot",
                "kind": "class",
                "path": "go/hierarchy.go",
                "result_type": "declaration",
                "start_line": 3
              }
            }
          ]
        }
      ],
      "result_type": "declaration",
      "signature": "QueryRoot interface {",
      "start_line": 3
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:hierarchy-subtype-members-owner:rql -->
```lisp
(owner (members (subtypes :transitive true (enclosing-decl (language go (class :name "QueryRoot"))))))
```

<!-- code-query-case:hierarchy-subtype-members-owner:json -->
```json
{"languages":["go"],"match":{"kind":"class","name":"QueryRoot"},"steps":[{"op":"enclosing_decl"},{"op":"subtypes","transitive":true},{"op":"members"},{"op":"owner"}]}
```

<!-- code-query-case:hierarchy-subtype-members-owner:expected -->
```json
{
  "results": [
    {
      "end_line": 7,
      "fq_name": "go.QueryLeaf",
      "kind": "class",
      "language": "go",
      "path": "go/hierarchy.go",
      "provenance": [
        {
          "seed": {
            "end_line": 5,
            "kind": "class",
            "path": "go/hierarchy.go",
            "result_type": "structural_match",
            "start_line": 3
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 5,
                "fq_name": "go.QueryRoot",
                "kind": "class",
                "path": "go/hierarchy.go",
                "result_type": "declaration",
                "start_line": 3
              }
            },
            {
              "op": "subtypes",
              "result": {
                "end_line": 7,
                "fq_name": "go.QueryLeaf",
                "kind": "class",
                "path": "go/hierarchy.go",
                "result_type": "declaration",
                "start_line": 7
              }
            },
            {
              "op": "members",
              "result": {
                "end_line": 9,
                "fq_name": "go.QueryLeaf.QueryMember",
                "kind": "function",
                "path": "go/hierarchy.go",
                "result_type": "declaration",
                "start_line": 9
              }
            },
            {
              "op": "owner",
              "result": {
                "end_line": 7,
                "fq_name": "go.QueryLeaf",
                "kind": "class",
                "path": "go/hierarchy.go",
                "result_type": "declaration",
                "start_line": 7
              }
            }
          ]
        }
      ],
      "result_type": "declaration",
      "signature": "QueryLeaf struct {",
      "start_line": 7
    }
  ],
  "truncated": false
}
```
