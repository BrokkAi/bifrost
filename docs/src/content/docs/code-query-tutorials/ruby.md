---
title: Ruby
description: Query Ruby keyword calls, blocks, imports, qualified classes, and precision boundaries with query_code.
---

> Last verified end to end: 2026-07-13 (`query_code` schema version 2).

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

<!-- code-query-fixture:ruby/graph/a.rb -->
```ruby
require_relative "b"

def graph_seed
end
```

<!-- code-query-fixture:ruby/graph/b.rb -->
```ruby
require_relative "c"

def graph_middle
end
```

<!-- code-query-fixture:ruby/graph/c.rb -->
```ruby
def graph_target
end
```

<!-- code-query-fixture:ruby/graph/also_imports_c.rb -->
```ruby
require_relative "c"

def another_graph_entry
end
```

## Typed declaration and import pipelines

Pipeline wrappers transform syntax matches into declarations or files. `enclosing-decl` is inclusive and returns the smallest indexed declaration containing the match. `file-of` converts a syntax match or declaration to its exact project file.

<!-- code-query-case:enclosing-decl:rql -->
```lisp
(enclosing-decl
  (language ruby (call :callee (name "audit_named"))))
```

<!-- code-query-case:enclosing-decl:json -->
```json
{"languages":["ruby"],"match":{"kind":"call","callee":{"name":"audit_named"}},"steps":[{"op":"enclosing_decl"}]}
```

<!-- code-query-case:enclosing-decl:expected -->
```json
{
  "results": [
    {
      "end_line": 12,
      "fq_name": "App$Service.run",
      "kind": "function",
      "language": "ruby",
      "path": "ruby/app.rb",
      "provenance": [
        {
          "seed": {
            "end_line": 8,
            "kind": "call",
            "path": "ruby/app.rb",
            "result_type": "structural_match",
            "start_line": 8
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 12,
                "fq_name": "App$Service.run",
                "kind": "function",
                "path": "ruby/app.rb",
                "result_type": "declaration",
                "start_line": 6
              }
            }
          ]
        }
      ],
      "result_type": "declaration",
      "signature": "(code)",
      "start_line": 6
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:file-of:rql -->
```lisp
(file-of (language ruby (function :name "graph_target")))
```

<!-- code-query-case:file-of:json -->
```json
{"languages":["ruby"],"match":{"kind":"function","name":"graph_target"},"steps":[{"op":"file_of"}]}
```

<!-- code-query-case:file-of:expected -->
```json
{
  "results": [
    {
      "language": "ruby",
      "path": "ruby/graph/c.rb",
      "provenance": [
        {
          "seed": {
            "end_line": 2,
            "kind": "function",
            "path": "ruby/graph/c.rb",
            "result_type": "structural_match",
            "start_line": 1
          },
          "steps": [
            {
              "op": "file_of",
              "result": {
                "path": "ruby/graph/c.rb",
                "result_type": "file"
              }
            }
          ]
        }
      ],
      "result_type": "file"
    }
  ],
  "truncated": false
}
```

`imports-of` follows one direct project-local import edge. `importers-of` follows the reverse direct edge; nesting it twice performs two hops rather than silently computing a transitive closure.

<!-- code-query-case:imports-of:rql -->
```lisp
(imports-of
  (file-of (language ruby (function :name "graph_seed"))))
```

<!-- code-query-case:imports-of:json -->
```json
{"languages":["ruby"],"match":{"kind":"function","name":"graph_seed"},"steps":[{"op":"file_of"},{"op":"imports_of"}]}
```

<!-- code-query-case:imports-of:expected -->
```json
{
  "results": [
    {
      "language": "ruby",
      "path": "ruby/graph/b.rb",
      "provenance": [
        {
          "seed": {
            "end_line": 4,
            "kind": "function",
            "path": "ruby/graph/a.rb",
            "result_type": "structural_match",
            "start_line": 3
          },
          "steps": [
            {
              "op": "file_of",
              "result": {
                "path": "ruby/graph/a.rb",
                "result_type": "file"
              }
            },
            {
              "op": "imports_of",
              "result": {
                "path": "ruby/graph/b.rb",
                "result_type": "file"
              }
            }
          ]
        }
      ],
      "result_type": "file"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:importers-of:rql -->
```lisp
(importers-of
  (file-of (language ruby (function :name "graph_target"))))
```

<!-- code-query-case:importers-of:json -->
```json
{"languages":["ruby"],"match":{"kind":"function","name":"graph_target"},"steps":[{"op":"file_of"},{"op":"importers_of"}]}
```

<!-- code-query-case:importers-of:expected -->
```json
{
  "results": [
    {
      "language": "ruby",
      "path": "ruby/graph/also_imports_c.rb",
      "provenance": [
        {
          "seed": {
            "end_line": 2,
            "kind": "function",
            "path": "ruby/graph/c.rb",
            "result_type": "structural_match",
            "start_line": 1
          },
          "steps": [
            {
              "op": "file_of",
              "result": {
                "path": "ruby/graph/c.rb",
                "result_type": "file"
              }
            },
            {
              "op": "importers_of",
              "result": {
                "path": "ruby/graph/also_imports_c.rb",
                "result_type": "file"
              }
            }
          ]
        }
      ],
      "result_type": "file"
    },
    {
      "language": "ruby",
      "path": "ruby/graph/b.rb",
      "provenance": [
        {
          "seed": {
            "end_line": 2,
            "kind": "function",
            "path": "ruby/graph/c.rb",
            "result_type": "structural_match",
            "start_line": 1
          },
          "steps": [
            {
              "op": "file_of",
              "result": {
                "path": "ruby/graph/c.rb",
                "result_type": "file"
              }
            },
            {
              "op": "importers_of",
              "result": {
                "path": "ruby/graph/b.rb",
                "result_type": "file"
              }
            }
          ]
        }
      ],
      "result_type": "file"
    }
  ],
  "truncated": false
}
```

This is the direct answer to “which project files import the declaration `graph_target`?”: first convert the declaration match to `graph/c.rb`, then follow one reverse edge. It returns every project file with a resolved direct import of that file; it does **not** claim that each importer calls `graph_target`, nor does it turn an external package import into a synthetic declaration.

To inspect actual uses today, run a structural call query (or a resolved `scan_usages` query when the declaration is indexed) separately. A pipeline cannot yet feed its file results back into a second structural query as a correlated scope, so it cannot express “among these importers, find calls to this imported member” in one query.

<!-- code-query-case:importers-of-two-hops:rql -->
```lisp
(importers-of
  (importers-of
    (file-of (language ruby (function :name "graph_target")))))
```

<!-- code-query-case:importers-of-two-hops:json -->
```json
{"languages":["ruby"],"match":{"kind":"function","name":"graph_target"},"steps":[{"op":"file_of"},{"op":"importers_of"},{"op":"importers_of"}]}
```

<!-- code-query-case:importers-of-two-hops:expected -->
```json
{
  "results": [
    {
      "language": "ruby",
      "path": "ruby/graph/a.rb",
      "provenance": [
        {
          "seed": {
            "end_line": 2,
            "kind": "function",
            "path": "ruby/graph/c.rb",
            "result_type": "structural_match",
            "start_line": 1
          },
          "steps": [
            {
              "op": "file_of",
              "result": {
                "path": "ruby/graph/c.rb",
                "result_type": "file"
              }
            },
            {
              "op": "importers_of",
              "result": {
                "path": "ruby/graph/b.rb",
                "result_type": "file"
              }
            },
            {
              "op": "importers_of",
              "result": {
                "path": "ruby/graph/a.rb",
                "result_type": "file"
              }
            }
          ]
        }
      ],
      "result_type": "file"
    }
  ],
  "truncated": false
}
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
  "results": [
    {
      "captures": [
        {"name": "value", "start_line": 8, "text": "code"}
      ],
      "enclosing_symbol": "App$Service.run",
      "end_line": 8,
      "kind": "call",
      "language": "ruby",
      "result_type": "structural_match",
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
  "results": [
    {
      "enclosing_symbol": "App$Service.run",
      "end_line": 11,
      "kind": "call",
      "language": "ruby",
      "result_type": "structural_match",
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
  "results": [
    {
      "end_line": 1,
      "kind": "import",
      "language": "ruby",
      "result_type": "structural_match",
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
  "results": [],
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
  "results": [
    {
      "enclosing_symbol": "App$Service.run",
      "end_line": 10,
      "kind": "lambda",
      "language": "ruby",
      "result_type": "structural_match",
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
  "results": [],
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
  "results": [
    {
      "end_line": 24,
      "kind": "null_literal",
      "language": "ruby",
      "result_type": "structural_match",
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
  "results": [
    {
      "end_line": 24,
      "kind": "null_literal",
      "language": "ruby",
      "result_type": "structural_match",
      "path": "ruby/app.rb",
      "start_line": 24,
      "text": "nil"
    }
  ],
  "truncated": false
}
```
