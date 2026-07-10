---
title: PHP
description: Query PHP named arguments, attributes, imports, and nullsafe calls with query_code.
---

> Last verified end to end: 2026-07-10 (`query_code` schema version 1).

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
  "matches": [
    {
      "captures": [
        {"name": "value", "start_line": 14, "text": "$code"}
      ],
      "enclosing_symbol": "App.Service.run",
      "end_line": 14,
      "kind": "call",
      "language": "php",
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
  "matches": [
    {
      "enclosing_symbol": "App.Service.run",
      "end_line": 15,
      "kind": "call",
      "language": "php",
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
  "matches": [
    {
      "enclosing_symbol": "App.Service",
      "end_line": 18,
      "kind": "class",
      "language": "php",
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
  "matches": [
    {
      "end_line": 5,
      "kind": "import",
      "language": "php",
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
  "matches": [],
  "truncated": false
}
```

The adapter also exposes nullsafe calls, constructors, assignments, field access, literals, and lambdas. It deliberately does not reinterpret class-body trait composition as an import, so a zero-match result here is a correctness proof rather than a missing fallback.
