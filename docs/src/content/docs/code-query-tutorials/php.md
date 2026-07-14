---
title: PHP
description: Query PHP named arguments, attributes, imports, and nullsafe calls with query_code.
---

> Last verified end to end: 2026-07-14 (`query_code` schema version 2).

PHP exposes instance, static, nullsafe, and object-creation calls; named arguments through `kwargs`; attributes through `decorators`; and namespace imports separately from trait composition.

## Fixture

<!-- code-query-fixture:php/app.php -->
```php
<?php
namespace App;

use App\Support\Formatter;
use App\Support\{Logger, Writer as WriterAlias};

#[Route('/run')]
class Service {
    use Loggable;

    public const LIMIT = -3;

    public function run(string $code): string {
        audit_named(code: $code);
        $formatted = Formatter::format($code);
        return $formatted;
    }
}

function audit_named(string $code): string {
    return $code;
}

$service = new Service();
$service?->run("input");
```

## Named arguments and static receivers

The named-argument query uses `kwargs` to distinguish `audit_named(code: $code)` from ordinary positional calls. A receiver constraint separately identifies the static formatter call.

<!-- code-query-case:named-call:rql -->
```lisp
(language php
  (call :callee (name "audit_named")
    :kwargs [(code (identifier :name "code" :capture "value"))]))
```

<!-- code-query-case:named-call:json -->
```json
{"languages":["php"],"match":{"kind":"call","callee":{"name":"audit_named"},"kwargs":{"code":{"kind":"identifier","name":"code","capture":"value"}}}}
```

<!-- code-query-case:named-call:expected -->
```json
{
  "results": [
    {
      "captures": [
        {"name": "value", "start_line": 14, "text": "$code"}
      ],
      "enclosing_symbol": "App.Service.run",
      "end_line": 14,
      "kind": "call",
      "language": "php",
      "result_type": "structural_match",
      "path": "php/app.php",
      "start_line": 14,
      "text": "audit_named(code: $code)"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:static-call:rql -->
```lisp
(language php (call :callee (name "format") :receiver (name "Formatter")))
```

<!-- code-query-case:static-call:json -->
```json
{"languages":["php"],"match":{"kind":"call","callee":{"name":"format"},"receiver":{"name":"Formatter"}}}
```

<!-- code-query-case:static-call:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "App.Service.run",
      "end_line": 15,
      "kind": "call",
      "language": "php",
      "result_type": "structural_match",
      "path": "php/app.php",
      "start_line": 15,
      "text": "Formatter::format($code)"
    }
  ],
  "truncated": false
}
```

## Attributes, imports, and trait boundaries

PHP attributes are normalized as decorators. Namespace `use` declarations are imports, while `use Loggable` inside the class is trait composition and must not become an import match.

<!-- code-query-case:attribute:rql -->
```lisp
(language php (class :decorators [(name "Route")]))
```

<!-- code-query-case:attribute:json -->
```json
{"languages":["php"],"match":{"kind":"class","decorators":[{"name":"Route"}]}}
```

<!-- code-query-case:attribute:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "App.Service",
      "end_line": 18,
      "kind": "class",
      "language": "php",
      "result_type": "structural_match",
      "path": "php/app.php",
      "start_line": 7,
      "text": "#[Route('/run')]…"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:import:rql -->
```lisp
(language php (import :module (name "WriterAlias")))
```

<!-- code-query-case:import:json -->
```json
{"languages":["php"],"match":{"kind":"import","module":{"name":"WriterAlias"}}}
```

<!-- code-query-case:import:expected -->
```json
{
  "results": [
    {
      "end_line": 5,
      "kind": "import",
      "language": "php",
      "result_type": "structural_match",
      "path": "php/app.php",
      "start_line": 5,
      "text": "use App\\Support\\{Logger, Writer as WriterAlias};"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:trait-not-import:rql -->
```lisp
(language php (import :module (name "Loggable")))
```

<!-- code-query-case:trait-not-import:json -->
```json
{"languages":["php"],"match":{"kind":"import","module":{"name":"Loggable"}}}
```

<!-- code-query-case:trait-not-import:expected -->
```json
{
  "results": [],
  "truncated": false
}
```

The adapter also exposes nullsafe calls, constructors, assignments, field access, literals, and lambdas. It deliberately does not reinterpret class-body trait composition as an import, so a zero-match result here is a correctness proof rather than a missing fallback.

## Traverse Indexed Types And Members

<!-- code-query-fixture:php/hierarchy.php -->
```php
<?php
class QueryRoot {
    public function rootMember() {}
}

class QueryLeaf extends QueryRoot {
    public function leafMember() {}
}
```

<!-- code-query-case:hierarchy-supertypes:rql -->
```lisp
(supertypes (enclosing-decl (language php (class :name "QueryLeaf"))))
```

<!-- code-query-case:hierarchy-supertypes:json -->
```json
{"languages":["php"],"match":{"kind":"class","name":"QueryLeaf"},"steps":[{"op":"enclosing_decl"},{"op":"supertypes"}]}
```

<!-- code-query-case:hierarchy-supertypes:expected -->
```json
{
  "results": [
    {
      "end_line": 4,
      "fq_name": "QueryRoot",
      "kind": "class",
      "language": "php",
      "path": "php/hierarchy.php",
      "provenance": [
        {
          "seed": {
            "end_line": 8,
            "kind": "class",
            "path": "php/hierarchy.php",
            "result_type": "structural_match",
            "start_line": 6
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 8,
                "fq_name": "QueryLeaf",
                "kind": "class",
                "path": "php/hierarchy.php",
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
                "path": "php/hierarchy.php",
                "result_type": "declaration",
                "start_line": 2
              }
            }
          ]
        }
      ],
      "result_type": "declaration",
      "signature": "class QueryRoot {",
      "start_line": 2
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:hierarchy-subtype-members-owner:rql -->
```lisp
(owner (members (subtypes :depth 2 (enclosing-decl (language php (class :name "QueryRoot"))))))
```

<!-- code-query-case:hierarchy-subtype-members-owner:json -->
```json
{"languages":["php"],"match":{"kind":"class","name":"QueryRoot"},"steps":[{"op":"enclosing_decl"},{"op":"subtypes","depth":2},{"op":"members"},{"op":"owner"}]}
```

<!-- code-query-case:hierarchy-subtype-members-owner:expected -->
```json
{
  "results": [
    {
      "end_line": 8,
      "fq_name": "QueryLeaf",
      "kind": "class",
      "language": "php",
      "path": "php/hierarchy.php",
      "provenance": [
        {
          "seed": {
            "end_line": 4,
            "kind": "class",
            "path": "php/hierarchy.php",
            "result_type": "structural_match",
            "start_line": 2
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 4,
                "fq_name": "QueryRoot",
                "kind": "class",
                "path": "php/hierarchy.php",
                "result_type": "declaration",
                "start_line": 2
              }
            },
            {
              "op": "subtypes",
              "result": {
                "end_line": 8,
                "fq_name": "QueryLeaf",
                "kind": "class",
                "path": "php/hierarchy.php",
                "result_type": "declaration",
                "start_line": 6
              }
            },
            {
              "op": "members",
              "result": {
                "end_line": 7,
                "fq_name": "QueryLeaf.leafMember",
                "kind": "function",
                "path": "php/hierarchy.php",
                "result_type": "declaration",
                "start_line": 7
              }
            },
            {
              "op": "owner",
              "result": {
                "end_line": 8,
                "fq_name": "QueryLeaf",
                "kind": "class",
                "path": "php/hierarchy.php",
                "result_type": "declaration",
                "start_line": 6
              }
            }
          ]
        }
      ],
      "result_type": "declaration",
      "signature": "class QueryLeaf extends QueryRoot {",
      "start_line": 6
    }
  ],
  "truncated": false
}
```
