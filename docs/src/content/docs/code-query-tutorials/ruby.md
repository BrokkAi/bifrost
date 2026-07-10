---
title: Ruby
description: Query Ruby keyword calls, blocks, imports, qualified classes, and precision boundaries with query_code.
---

> Last verified end to end: 2026-07-10 (`query_code` schema version 1).

Ruby maps ordinary and receiver calls, keyword arguments, blocks/lambdas, methods, qualified classes, assignments, and static imports. Import refinement is deliberately conservative: receiver calls named `require` and interpolated strings do not become precise import modules.

## Fixture

<!-- code-query-fixture:ruby/app.rb -->
```ruby
require "app/support"
require "plugins/#{tenant}"

module App
  class Service
    def run(code)
      audit(code)
      audit_named(code: code)
      password = "hunter2"
      callback = ->(value) { return value }
      loader.require("plugin")
    end
  end
end

class App::External
end

def helper
  service = App::Service.new("primary")
  service.run("input")
end

missing = nil
```

## Keyword and receiver calls

The keyword query selects `audit_named(code: code)`. A receiver constraint keeps `loader.require(...)` as a normal call, even though bare `require "..."` is an import shape.

<!-- code-query-case:named-call:rql -->
```lisp
(language ruby
  (call :callee (name "audit_named")
    :kwargs [(code (identifier :name "code" :capture "value"))]))
```

<!-- code-query-case:named-call:json -->
```json
{"languages":["ruby"],"match":{"kind":"call","callee":{"name":"audit_named"},"kwargs":{"code":{"kind":"identifier","name":"code","capture":"value"}}}}
```

<!-- code-query-case:named-call:expected -->
```json
{
  "matches": [
    {
      "captures": [
        {"name": "value", "start_line": 8, "text": "code"}
      ],
      "enclosing_symbol": "App$Service.run",
      "end_line": 8,
      "kind": "call",
      "language": "ruby",
      "path": "ruby/app.rb",
      "start_line": 8,
      "text": "audit_named(code: code)"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:receiver-require:rql -->
```lisp
(language ruby
  (call :callee (name "require") :receiver (name "loader")))
```

<!-- code-query-case:receiver-require:json -->
```json
{"languages":["ruby"],"match":{"kind":"call","callee":{"name":"require"},"receiver":{"name":"loader"}}}
```

<!-- code-query-case:receiver-require:expected -->
```json
{
  "matches": [
    {
      "enclosing_symbol": "App$Service.run",
      "end_line": 11,
      "kind": "call",
      "language": "ruby",
      "path": "ruby/app.rb",
      "start_line": 11,
      "text": "loader.require(\"plugin\")"
    }
  ],
  "truncated": false
}
```

## Static and dynamic imports

Only fully static strings provide a `module` role. The interpolated `plugins/#{tenant}` require is intentionally absent, and the receiver call above is not classified as an import.

<!-- code-query-case:static-import:rql -->
```lisp
(language ruby (import :module (name "app/support")))
```

<!-- code-query-case:static-import:json -->
```json
{"languages":["ruby"],"match":{"kind":"import","module":{"name":"app/support"}}}
```

<!-- code-query-case:static-import:expected -->
```json
{
  "matches": [
    {
      "end_line": 1,
      "kind": "import",
      "language": "ruby",
      "path": "ruby/app.rb",
      "start_line": 1,
      "text": "require \"app/support\""
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:dynamic-import-excluded:rql -->
```lisp
(language ruby (import :module (name "plugins/")))
```

<!-- code-query-case:dynamic-import-excluded:json -->
```json
{"languages":["ruby"],"match":{"kind":"import","module":{"name":"plugins/"}}}
```

<!-- code-query-case:dynamic-import-excluded:expected -->
```json
{
  "matches": [],
  "truncated": false
}
```

## Blocks and unsupported decorators

`has` identifies the return inside the lambda. Ruby does not model decorators, so that role reports a capability diagnostic rather than a guessed match.

<!-- code-query-case:lambda:rql -->
```lisp
(language ruby (lambda :has (return)))
```

<!-- code-query-case:lambda:json -->
```json
{"languages":["ruby"],"match":{"kind":"lambda","has":{"kind":"return"}}}
```

<!-- code-query-case:lambda:expected -->
```json
{
  "matches": [
    {
      "enclosing_symbol": "App$Service.run",
      "end_line": 10,
      "kind": "lambda",
      "language": "ruby",
      "path": "ruby/app.rb",
      "start_line": 10,
      "text": "->(value) { return value }"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:unsupported-decorator:rql -->
```lisp
(language ruby (method :decorators [(name "memoized")]))
```

<!-- code-query-case:unsupported-decorator:json -->
```json
{"languages":["ruby"],"match":{"kind":"method","decorators":[{"name":"memoized"}]}}
```

<!-- code-query-case:unsupported-decorator:expected -->
```json
{
  "diagnostics": [
    {
      "language": "ruby",
      "message": "structural adapter for ruby does not support role(s): decorators"
    }
  ],
  "matches": [],
  "truncated": false
}
```

Qualified declarations such as `class App::External` are nameable through their terminal class name, and assignments/literals remain available for ordinary Ruby data-shape queries.

<!-- code-query-case:null-literal:rql -->
```lisp
(language ruby (null_literal (text/regex "^nil$")))
```

<!-- code-query-case:null-literal:json -->
```json
{"languages":["ruby"],"match":{"kind":"null_literal","text":{"regex":"^nil$"}}}
```

<!-- code-query-case:null-literal:expected -->
```json
{
  "matches": [
    {
      "end_line": 24,
      "kind": "null_literal",
      "language": "ruby",
      "path": "ruby/app.rb",
      "start_line": 24,
      "text": "nil"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:literal-supertype:rql -->
```lisp
(language ruby (literal (text/regex "^nil$")))
```

<!-- code-query-case:literal-supertype:json -->
```json
{"languages":["ruby"],"match":{"kind":"literal","text":{"regex":"^nil$"}}}
```

<!-- code-query-case:literal-supertype:expected -->
```json
{
  "matches": [
    {
      "end_line": 24,
      "kind": "null_literal",
      "language": "ruby",
      "path": "ruby/app.rb",
      "start_line": 24,
      "text": "nil"
    }
  ],
  "truncated": false
}
```
