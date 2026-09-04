---
title: TypeScript
description: Query TypeScript declarations, callable refinements, decorators, and TSX with query_code.
---

> Last verified end to end: 2026-08-26 (`query_code` schema version 1).

For exact inbound and outbound symbol edges, proof tiers, and adapter-specific caveats, see [Reference Traversal](../reference-traversal/). For bounded allocation/factory provenance, ambiguity, exact member targets, and call-input composition, see [Receiver Traversal](../receiver-traversal/).

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

function Input(_target: object, _key: string, _index: number) {}

class Controller {
  handle(@Input value: string): string {
    return value;
  }
}
```

<!-- code-query-fixture:typescript/view.tsx -->
```tsx
export const View = () => (
  <button onClick={() => service.save("tsx")}>Save</button>
);
```

<!-- code-query-fixture:typescript/jsx-structure.tsx -->
```tsx
const props = { title: "Save" };
const dynamicKey = "tone";
const html = "safe";
const config = { __html: html, [dynamicKey]: "warm", ...props };

export const StructuredView = () => (
  <div {...props} dangerouslySetInnerHTML={config}>
    <span>{html}</span>
  </div>
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
      "kind": "class",
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

## Select A Decorated Parameter

Parameters are file-backed declarations with their own exact source ranges. A `decorators` constraint selects the parameter through its structural decorator edge instead of matching decorator text.

<!-- code-query-case:decorated-parameter:rql -->
```lisp
(language typescript
  (parameter :name "value"
    :decorators [(decorator :name "Input")]))
```

<!-- code-query-case:decorated-parameter:json -->
```json
{
  "languages": ["typescript"],
  "match": {
    "kind": "parameter",
    "name": "value",
    "decorators": [{"kind": "decorator", "name": "Input"}]
  }
}
```

<!-- code-query-case:decorated-parameter:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "typescript/service.ts",
      "language": "typescript",
      "kind": "parameter",
      "start_line": 32,
      "end_line": 32,
      "text": "@Input value: string",
      "enclosing_symbol": "Controller.handle"
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

## Query JSX And Object Structure

JSX elements, named and spread attributes, and their exact value operands are
structural facts. Tag, attribute, child, and value roles compose without
parsing source text.

<!-- code-query-case:jsx-structure:rql -->
```lisp
(language typescript
  (jsx_element
    :tag "div"
    :attributes [
      (jsx_spread_attribute :value "props")
      (jsx_attribute :name "dangerouslySetInnerHTML" :value "config")
    ]
    :children [(jsx_element :tag "span")]))
```

<!-- code-query-case:jsx-structure:json -->
```json
{
  "languages": ["typescript"],
  "match": {
    "kind": "jsx_element",
    "tag": {"name": "div"},
    "attributes": [
      {"kind": "jsx_spread_attribute", "value": {"name": "props"}},
      {"kind": "jsx_attribute", "name": "dangerouslySetInnerHTML", "value": {"name": "config"}}
    ],
    "children": [{"kind": "jsx_element", "tag": {"name": "span"}}]
  }
}
```

<!-- code-query-case:jsx-structure:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "typescript/jsx-structure.tsx",
      "language": "typescript",
      "kind": "jsx_element",
      "start_line": 7,
      "end_line": 9,
      "text": "<div {...props} dangerouslySetInnerHTML={config}>…",
      "enclosing_symbol": "StructuredView"
    }
  ],
  "truncated": false
}
```

Object properties expose structured key and value roles. Computed properties
remain distinct from static keys, while spreads use the context-free
`spread_element` kind in object, array, and argument contexts.

<!-- code-query-case:object-property:rql -->
```lisp
(language typescript (object_property :key "__html" :value "html"))
```

<!-- code-query-case:object-property:json -->
```json
{
  "languages": ["typescript"],
  "match": {
    "kind": "object_property",
    "key": {"name": "__html"},
    "value": {"name": "html"}
  }
}
```

<!-- code-query-case:object-property:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "typescript/jsx-structure.tsx",
      "language": "typescript",
      "kind": "object_property",
      "start_line": 4,
      "end_line": 4,
      "text": "__html: html",
      "enclosing_symbol": "jsx-structure.tsx.config"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:computed-property:rql -->
```lisp
(language typescript (computed_property :value "dynamicKey"))
```

<!-- code-query-case:computed-property:json -->
```json
{"languages":["typescript"],"match":{"kind":"computed_property","value":{"name":"dynamicKey"}}}
```

<!-- code-query-case:computed-property:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "typescript/jsx-structure.tsx",
      "language": "typescript",
      "kind": "computed_property",
      "start_line": 4,
      "end_line": 4,
      "text": "[dynamicKey]",
      "enclosing_symbol": "jsx-structure.tsx.config"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:spread-elements:rql -->
```lisp
(language typescript (spread_element :value "props"))
```

<!-- code-query-case:spread-elements:json -->
```json
{"languages":["typescript"],"match":{"kind":"spread_element","value":{"name":"props"}}}
```

<!-- code-query-case:spread-elements:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "typescript/jsx-structure.tsx",
      "language": "typescript",
      "kind": "spread_element",
      "start_line": 4,
      "end_line": 4,
      "text": "...props",
      "enclosing_symbol": "jsx-structure.tsx.config"
    },
    {
      "result_type": "structural_match",
      "path": "typescript/jsx-structure.tsx",
      "language": "typescript",
      "kind": "spread_element",
      "start_line": 7,
      "end_line": 7,
      "text": "...props",
      "enclosing_symbol": "StructuredView"
    }
  ],
  "truncated": false
}
```

## Precision Boundary

Interfaces, enums, and abstract classes intentionally share the normalized `class` kind. Use `name`, containment, or source/path scoping when their source syntax matters; there is no separate public `interface` kind.

This example exposes bounded receiver values through the shared public `query_code` contract. The adapter preserves explicit `unknown`, `ambiguous`, `unsupported`, and budget outcomes; it does not provide whole-program points-to, general alias analysis, path-sensitive control flow, taint, or general data flow.

## Traverse Indexed Types And Members

<!-- code-query-fixture:typescript/hierarchy.ts -->
```typescript
class QueryRoot {
  rootMember(): void {}
}

class QueryLeaf extends QueryRoot {
  leafMember(): void {}
}
```

<!-- code-query-case:hierarchy-supertypes:rql -->
```lisp
(supertypes :transitive true (enclosing-decl (language typescript (class :name "QueryLeaf"))))
```

<!-- code-query-case:hierarchy-supertypes:json -->
```json
{"languages":["typescript"],"match":{"kind":"class","name":"QueryLeaf"},"steps":[{"op":"enclosing_decl"},{"op":"supertypes","transitive":true}]}
```

<!-- code-query-case:hierarchy-supertypes:expected -->
```json
{
  "results": [
    {
      "end_line": 3,
      "fq_name": "QueryRoot",
      "kind": "class",
      "language": "typescript",
      "path": "typescript/hierarchy.ts",
      "provenance": [
        {
          "seed": {
            "end_line": 7,
            "kind": "class",
            "path": "typescript/hierarchy.ts",
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
                "path": "typescript/hierarchy.ts",
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
                "path": "typescript/hierarchy.ts",
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
(owner (members (subtypes (enclosing-decl (language typescript (class :name "QueryRoot"))))))
```

<!-- code-query-case:hierarchy-subtype-members-owner:json -->
```json
{"languages":["typescript"],"match":{"kind":"class","name":"QueryRoot"},"steps":[{"op":"enclosing_decl"},{"op":"subtypes"},{"op":"members"},{"op":"owner"}]}
```

<!-- code-query-case:hierarchy-subtype-members-owner:expected -->
```json
{
  "results": [
    {
      "end_line": 7,
      "fq_name": "QueryLeaf",
      "kind": "class",
      "language": "typescript",
      "path": "typescript/hierarchy.ts",
      "provenance": [
        {
          "seed": {
            "end_line": 3,
            "kind": "class",
            "path": "typescript/hierarchy.ts",
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
                "path": "typescript/hierarchy.ts",
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
                "path": "typescript/hierarchy.ts",
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
                "path": "typescript/hierarchy.ts",
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
                "path": "typescript/hierarchy.ts",
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
