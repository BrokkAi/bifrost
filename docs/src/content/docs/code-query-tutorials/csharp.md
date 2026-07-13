---
title: C#
description: Query C# null-conditional calls, named arguments, attributes, and using aliases with query_code.
---

> Last verified end to end: 2026-07-13 (`query_code` schema version 2).

C# exposes object creation, null-conditional access, named arguments, attributes, constructors, properties, and using aliases through normalized structural facts. Alias bindings are represented by their visible alias, not by the terminal name of the target type.

## Fixture

<!-- code-query-fixture:csharp/App.cs -->
```csharp
using System;
using App.Support;
using WriterAlias = App.Support.Writer;

namespace App;

[Route("/run")]
class Service {
    private string empty;
    public Service() {}

    public string Run(string code) {
        AuditNamed(code: code);
        return code;
    }

    public static string AuditNamed(string code) => code;
}

class AppEntry {
    void Main() {
        var service = new Service();
        service?.Run("optional");
    }
}
```

## Null-conditional and named calls

The receiver and argument predicates select the null-conditional call. Named arguments use `kwargs`, with the identifier capture proving which value was bound to `code`.

<!-- code-query-case:conditional-call:rql -->
```lisp
(language csharp
  (call :callee (name "Run") :receiver (name "service")
    :args [(string_literal (text/regex "^\\\"optional\\\"$"))]))
```

<!-- code-query-case:conditional-call:json -->
```json
{"languages":["csharp"],"match":{"kind":"call","callee":{"name":"Run"},"receiver":{"name":"service"},"args":[{"kind":"string_literal","text":{"regex":"^\\\"optional\\\"$"}}]}}
```

<!-- code-query-case:conditional-call:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "App.AppEntry.Main",
      "end_line": 23,
      "kind": "call",
      "language": "csharp",
      "result_type": "structural_match",
      "path": "csharp/App.cs",
      "start_line": 23,
      "text": "service?.Run(\"optional\")"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:named-call:rql -->
```lisp
(language csharp
  (call :callee (name "AuditNamed")
    :kwargs [(code (identifier :name "code" :capture "value"))]))
```

<!-- code-query-case:named-call:json -->
```json
{"languages":["csharp"],"match":{"kind":"call","callee":{"name":"AuditNamed"},"kwargs":{"code":{"kind":"identifier","name":"code","capture":"value"}}}}
```

<!-- code-query-case:named-call:expected -->
```json
{
  "results": [
    {
      "captures": [
        {"name": "value", "start_line": 13, "text": "code"}
      ],
      "enclosing_symbol": "App.Service.Run",
      "end_line": 13,
      "kind": "call",
      "language": "csharp",
      "result_type": "structural_match",
      "path": "csharp/App.cs",
      "start_line": 13,
      "text": "AuditNamed(code: code)"
    }
  ],
  "truncated": false
}
```

## Attributes and using aliases

Attributes are decorators on the class. An alias import matches `WriterAlias`, but querying the target terminal name `Writer` must remain empty so an alias does not overmatch.

<!-- code-query-case:attribute:rql -->
```lisp
(language csharp (class :decorators [(name "Route")]))
```

<!-- code-query-case:attribute:json -->
```json
{"languages":["csharp"],"match":{"kind":"class","decorators":[{"name":"Route"}]}}
```

<!-- code-query-case:attribute:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "App.Service",
      "end_line": 18,
      "kind": "class",
      "language": "csharp",
      "result_type": "structural_match",
      "path": "csharp/App.cs",
      "start_line": 7,
      "text": "[Route(\"/run\")]…"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:alias:rql -->
```lisp
(language csharp (import :module (name "WriterAlias")))
```

<!-- code-query-case:alias:json -->
```json
{"languages":["csharp"],"match":{"kind":"import","module":{"name":"WriterAlias"}}}
```

<!-- code-query-case:alias:expected -->
```json
{
  "results": [
    {
      "end_line": 3,
      "kind": "import",
      "language": "csharp",
      "result_type": "structural_match",
      "path": "csharp/App.cs",
      "start_line": 3,
      "text": "using WriterAlias = App.Support.Writer;"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:alias-target-excluded:rql -->
```lisp
(language csharp (import :module (name "Writer")))
```

<!-- code-query-case:alias-target-excluded:json -->
```json
{"languages":["csharp"],"match":{"kind":"import","module":{"name":"Writer"}}}
```

<!-- code-query-case:alias-target-excluded:expected -->
```json
{
  "results": [],
  "truncated": false
}
```

Uninitialized declarations such as `empty` are intentionally not assignments. Querying `assignment` with that left name is a useful exact-zero check when auditing initialization patterns.
