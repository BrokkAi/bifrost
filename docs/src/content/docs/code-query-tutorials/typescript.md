---
title: TypeScript
description: Query TypeScript declarations, callable refinements, decorators, and TSX with query_code.
---

> Last verified end to end: 2026-07-13 (`query_code` schema version 2).

TypeScript shares JavaScript's structural adapter and adds interface, enum, abstract-class, type-alias, type-identifier, decorator, and TSX grammar shapes.

## Fixtures

<!-- code-query-fixture:typescript/service.ts -->
```typescript
function Route(path: string) {
  return (_target: unknown, _key: string) => path;
}

interface User {
  id: UserId;
}

enum State {
  Ready,
}

abstract class BaseService {}
type UserId = string;

class Service extends BaseService {
  constructor() {
    super();
  }

  @Route("/save")
  save(value: string): string {
    return value;
  }
}

export const service = new Service();
```

<!-- code-query-fixture:typescript/view.tsx -->
```tsx
export const View = () => (
  <button onClick={() => service.save("tsx")}>Save</button>
);
```

## TypeScript-Only Declarations

A type alias is a normalized `declaration`; interfaces, enums, and abstract classes are normalized as `class`.

<!-- code-query-case:type-alias:rql -->
```lisp
(language typescript (declaration :name "UserId"))
```

<!-- code-query-case:type-alias:json -->
```json
{"languages":["typescript"],"match":{"kind":"declaration","name":"UserId"}}
```

<!-- code-query-case:type-alias:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "typescript/service.ts",
      "language": "typescript",
      "kind": "declaration",
      "start_line": 14,
      "end_line": 14,
      "text": "type UserId = string;",
      "enclosing_symbol": "service.ts.UserId"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:class-like:rql -->
```lisp
(language typescript (class (name/regex "^(User|State|BaseService)$")))
```

<!-- code-query-case:class-like:json -->
```json
{
  "languages": ["typescript"],
  "match": {
    "kind": "class",
    "name": {"regex": "^(User|State|BaseService)$"}
  }
}
```

<!-- code-query-case:class-like:expected -->
```json
{
  "results": [
    {"result_type":"structural_match","path":"typescript/service.ts","language":"typescript","kind":"class","start_line":5,"end_line":7,"text":"interface User {…","enclosing_symbol":"User"},
    {"result_type":"structural_match","path":"typescript/service.ts","language":"typescript","kind":"class","start_line":9,"end_line":11,"text":"enum State {…","enclosing_symbol":"State"},
    {"result_type":"structural_match","path":"typescript/service.ts","language":"typescript","kind":"class","start_line":13,"end_line":13,"text":"abstract class BaseService {}","enclosing_symbol":"BaseService"}
  ],
  "truncated": false
}
```

## Exclude Constructors And Lambdas

`callable` includes functions, methods, constructors, and lambdas. `not_kind` keeps only the named `save` method, and the decorator constraint proves its annotation mapping.

<!-- code-query-case:named-save:rql -->
```lisp
(callable
  :name "save"
  (not-kind [constructor lambda])
  :decorators [(decorator :name "Route" :capture "route")])
```

<!-- code-query-case:named-save:json -->
```json
{
  "match": {
    "kind": "callable",
    "name": "save",
    "not_kind": ["constructor", "lambda"],
    "decorators": [
      {"kind": "decorator", "name": "Route", "capture": "route"}
    ]
  }
}
```

<!-- code-query-case:named-save:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "typescript/service.ts",
      "language": "typescript",
      "kind": "method",
      "start_line": 22,
      "end_line": 24,
      "text": "save(value: string): string {…",
      "captures": [
        {"name":"route","text":"@Route(\"/save\")","start_line":21}
      ],
      "enclosing_symbol": "Service.save"
    }
  ],
  "truncated": false
}
```

## Scope A Query To TSX

The TypeScript language filter includes `.tsx`; `where` narrows this call to the TSX fixture and excludes the `new Service()` call in the `.ts` file.

<!-- code-query-case:tsx-call:rql -->
```lisp
(where "typescript/**/*.tsx"
  (language typescript
    (call :callee "save" :receiver "service" :args [(capture "value")])))
```

<!-- code-query-case:tsx-call:json -->
```json
{
  "where": ["typescript/**/*.tsx"],
  "languages": ["typescript"],
  "match": {
    "kind": "call",
    "callee": {"name": "save"},
    "receiver": {"name": "service"},
    "args": [{"capture": "value"}]
  }
}
```

<!-- code-query-case:tsx-call:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "typescript/view.tsx",
      "language": "typescript",
      "kind": "call",
      "start_line": 2,
      "end_line": 2,
      "text": "service.save(\"tsx\")",
      "captures": [{"name":"value","text":"\"tsx\"","start_line":2}],
      "enclosing_symbol": "View"
    }
  ],
  "truncated": false
}
```

## Precision Boundary

Interfaces, enums, and abstract classes intentionally share the normalized `class` kind. Use `name`, containment, or source/path scoping when their source syntax matters; version 2 has no separate public `interface` kind.
