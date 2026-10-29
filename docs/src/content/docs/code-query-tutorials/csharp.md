---
title: C#
description: Query C# null-conditional calls, named arguments, attributes, and using aliases with query_code.
---

> Last verified end to end: 2026-10-27 (`query_code` schema version 1).

For exact inbound and outbound symbol edges, proof tiers, and adapter-specific caveats, see [Reference Traversal](/code-query-tutorials/reference-traversal/).

C# exposes object creation, null-conditional access, named arguments, attributes, constructors, properties, and using aliases through normalized structural facts. Alias bindings are represented by their visible alias, not by the terminal name of the target type.

In each `#if`, `#elif`, `#else` chain, Bifrost indexes only the first branch whose condition is not the literal `false`. It does not model defined symbols, so declarations in the other branches are not indexed. See [language support](/reference/languages/) for details.

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

## C# parity facts and query fields

The following fixture keeps the newer C# structural and pipeline vocabulary
concrete: character literals, assignment operators, element-access objects,
language rules, statement facts, body ownership, failure-handler details, and
call-site argument identities all remain structured query data.

<!-- code-query-fixture:csharp/Parity.cs -->
```csharp
using System;

class Parity {
    public static readonly int[] Values = { 1 };

    public void BodyAndLoops(bool flag, int[] values) {
        if (flag) {}
        for (int i = 0; i < 10; i++) {
            for (int j = 0; j < 10; i++) {
            }
        }
    }

    public void CatchAndCall(int value) {
        try {
            Consume(value);
        } catch (Exception error) {
            throw error;
        } catch {
        }
    }

    public void Consume(int value) {}

    public void Access(int[] values) {
        values[0] += 1;
        char marker = 'x';
    }
}
```

The C# adapter keeps `'x'` as `character_literal`, publishes the assignment
operator, and exposes the object side of `values[0]` through `object`.

<!-- code-query-case:character-literal:rql -->
```lisp
(language csharp (character_literal))
```

<!-- code-query-case:character-literal:json -->
```json
{"languages":["csharp"],"match":{"kind":"character_literal"}}
```

<!-- code-query-case:character-literal:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "Parity.Access",
      "end_line": 27,
      "kind": "character_literal",
      "language": "csharp",
      "path": "csharp/Parity.cs",
      "result_type": "structural_match",
      "start_line": 27,
      "text": "'x'"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:assignment-operator:rql -->
```lisp
(language csharp
  (assignment :operator (text/regex "^\\+=$")))
```

<!-- code-query-case:assignment-operator:json -->
```json
{"languages":["csharp"],"match":{"kind":"assignment","operator":{"text":{"regex":"^\\+=$"}}}}
```

<!-- code-query-case:assignment-operator:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "Parity.Access",
      "end_line": 26,
      "kind": "assignment",
      "language": "csharp",
      "path": "csharp/Parity.cs",
      "result_type": "structural_match",
      "start_line": 26,
      "text": "values[0] += 1"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:element-access-object:rql -->
```lisp
(language csharp
  (field_access :object (name "values")))
```

<!-- code-query-case:element-access-object:json -->
```json
{"languages":["csharp"],"match":{"kind":"field_access","object":{"name":"values"}}}
```

<!-- code-query-case:element-access-object:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "Parity.Access",
      "end_line": 26,
      "kind": "field_access",
      "language": "csharp",
      "path": "csharp/Parity.cs",
      "result_type": "structural_match",
      "start_line": 26,
      "text": "values[0]"
    }
  ],
  "truncated": false
}
```

`language_rule` and `statement_facts` select the C# parity relations without
falling back to source-text searches. The body predicates select the empty
block owned by an `if` consequence.

<!-- code-query-case:language-rule:rql -->
```lisp
(language csharp (assignment :language-rule "cs/static-array"))
```

<!-- code-query-case:language-rule:json -->
```json
{"languages":["csharp"],"match":{"kind":"assignment","language_rule":"cs/static-array"}}
```

<!-- code-query-case:language-rule:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "Parity.Values",
      "end_line": 4,
      "kind": "assignment",
      "language": "csharp",
      "path": "csharp/Parity.cs",
      "result_type": "structural_match",
      "start_line": 4,
      "text": "Values = { 1 }"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:statement-facts:rql -->
```lisp
(language csharp
  (statement-facts :kind nested-loops-with-same-variable (loop)))
```

<!-- code-query-case:statement-facts:json -->
```json
{"languages":["csharp"],"match":{"kind":"loop"},"steps":[{"op":"statement_facts","statement_fact_kind":"nested-loops-with-same-variable"}]}
```

<!-- code-query-case:statement-facts:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "Parity.BodyAndLoops",
      "end_line": 10,
      "kind": "loop",
      "language": "csharp",
      "path": "csharp/Parity.cs",
      "provenance": [
        {
          "seed": {
            "end_line": 10,
            "kind": "loop",
            "path": "csharp/Parity.cs",
            "result_type": "structural_match",
            "start_line": 9
          },
          "steps": [
            {
              "op": "statement_facts",
              "result": {
                "end_line": 10,
                "kind": "loop",
                "path": "csharp/Parity.cs",
                "result_type": "structural_match",
                "start_line": 9
              }
            }
          ]
        }
      ],
      "result_type": "structural_match",
      "start_line": 9,
      "text": "for (int j = 0; j < 10; i++) {…"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:body-state-owner:rql -->
```lisp
(language csharp
  (block :body-state empty :body-owner if-consequence))
```

<!-- code-query-case:body-state-owner:json -->
```json
{"languages":["csharp"],"match":{"kind":"block","body_state":"empty","body_owner":"if-consequence"}}
```

<!-- code-query-case:body-state-owner:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "Parity.BodyAndLoops",
      "end_line": 7,
      "kind": "block",
      "language": "csharp",
      "path": "csharp/Parity.cs",
      "result_type": "structural_match",
      "start_line": 7,
      "text": "{}"
    }
  ],
  "truncated": false
}
```

Configuration facts are a separate seed domain, so their query omits a
programming-language scope. These predicates combine exact and
case-insensitive decoded values with numeric bounds on one XML attribute.

<!-- code-query-fixture:csharp/Web.config -->
```xml
<configuration>
  <system.web>
    <httpRuntime maxRequestLength="512" />
  </system.web>
</configuration>
```

<!-- code-query-case:configuration-values:rql -->
```lisp
(configuration-facts
  :format xml
  :role xml_attribute
  :key "maxRequestLength"
  :value "512"
  :value-ignore-case "512"
  :value-gt "500"
  :value-lt "1024")
```

<!-- code-query-case:configuration-values:json -->
```json
{"configuration_facts":{"formats":["xml"],"roles":["xml_attribute"],"keys":["maxRequestLength"],"values":["512"],"values_ignore_case":["512"],"value_gt":"500","value_lt":"1024"}}
```

<!-- code-query-case:configuration-values:expected -->
```json
{
  "results": [
    {
      "completeness": "complete",
      "end_byte": 64,
      "fact_id": "<public-id>",
      "fact_provenance": "authored",
      "format": "xml",
      "id": "<public-id>",
      "key": "maxRequestLength",
      "node_kind": "member",
      "occurrence": 1,
      "ordinal": 7,
      "parent_id": "<public-id>",
      "path": "csharp/Web.config",
      "range": {
        "end_column": 34,
        "end_line": 3,
        "start_column": 18,
        "start_line": 3
      },
      "result_type": "configuration_fact",
      "role": "xml-attribute",
      "route": "[\"configuration\",\"system.web\",\"httpRuntime\",\"maxRequestLength\"]",
      "scalar_kind": "string",
      "start_byte": 48,
      "value": "512",
      "value_id": "<public-id>"
    }
  ],
  "truncated": false
}
```

The failure-handler and call-site projections keep the C# details in their
typed result rows. In particular, a catch row carries `caught_type`, and a
call-site row carries its receiver and argument binding identities.

<!-- code-query-case:failure-handler-details:rql -->
```lisp
(failure-handler-state (language csharp (catch)))
```

<!-- code-query-case:failure-handler-details:json -->
```json
{"languages":["csharp"],"match":{"kind":"catch"},"steps":[{"op":"failure_handler_state"}]}
```

<!-- code-query-case:failure-handler-details:expected -->
```json
{
  "results": [
    {
      "body_range": {
        "end_column": 10,
        "end_line": 19,
        "start_column": 35,
        "start_line": 17
      },
      "catch_ast_id": "<public-id>",
      "caught_type": "System.Exception",
      "caught_type_relation": "system_exception",
      "coverage": "exhaustive",
      "has_filter": false,
      "id": "failure_handler_state:csharp/Parity.cs:<public-id>",
      "language": "csharp",
      "path": "csharp/Parity.cs",
      "proof": "exact",
      "provenance": [
        {
          "seed": {
            "end_line": 19,
            "kind": "catch",
            "path": "csharp/Parity.cs",
            "result_type": "structural_match",
            "start_line": 17
          },
          "steps": [
            {
              "op": "failure_handler_state",
              "result": {
                "catch_ast_id": "<public-id>",
                "id": "failure_handler_state:csharp/Parity.cs:<public-id>",
                "path": "csharp/Parity.cs",
                "range": {
                  "end_column": 10,
                  "end_line": 19,
                  "start_column": 11,
                  "start_line": 17
                },
                "result_type": "failure_handler_state",
                "verdict": "nonempty"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 10,
        "end_line": 19,
        "start_column": 11,
        "start_line": 17
      },
      "result_type": "failure_handler_state",
      "rethrow_kind": "caught_variable",
      "verdict": "nonempty"
    },
    {
      "body_range": {
        "end_column": 10,
        "end_line": 20,
        "start_column": 17,
        "start_line": 19
      },
      "catch_ast_id": "<public-id>",
      "caught_type": "System.Exception",
      "caught_type_relation": "system_exception",
      "coverage": "exhaustive",
      "has_filter": false,
      "id": "failure_handler_state:csharp/Parity.cs:<public-id>",
      "language": "csharp",
      "path": "csharp/Parity.cs",
      "proof": "exact",
      "provenance": [
        {
          "seed": {
            "end_line": 20,
            "kind": "catch",
            "path": "csharp/Parity.cs",
            "result_type": "structural_match",
            "start_line": 19
          },
          "steps": [
            {
              "op": "failure_handler_state",
              "result": {
                "catch_ast_id": "<public-id>",
                "id": "failure_handler_state:csharp/Parity.cs:<public-id>",
                "path": "csharp/Parity.cs",
                "range": {
                  "end_column": 10,
                  "end_line": 20,
                  "start_column": 11,
                  "start_line": 19
                },
                "result_type": "failure_handler_state",
                "verdict": "empty"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 10,
        "end_line": 20,
        "start_column": 11,
        "start_line": 19
      },
      "result_type": "failure_handler_state",
      "rethrow_kind": "none",
      "verdict": "empty"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:call-site-identities:rql -->
```lisp
(call-sites-to :proof proven
  (enclosing-decl (language csharp (method :name "Consume"))))
```

<!-- code-query-case:call-site-identities:json -->
```json
{"languages":["csharp"],"match":{"kind":"method","name":"Consume"},"steps":[{"op":"enclosing_decl"},{"op":"call_sites_to","proof":"proven"}]}
```

<!-- code-query-case:call-site-identities:expected -->
```json
{
  "results": [
    {
      "argument_identity": "<public-id>",
      "arguments": [
        {
          "caller_parameter_identity": "<public-id>",
          "formal_index": 0,
          "formal_name": "value",
          "identity": "<public-id>",
          "position": 0,
          "range": {
            "end_column": 26,
            "end_line": 16,
            "start_column": 21,
            "start_line": 16
          }
        }
      ],
      "call_kind": "function",
      "callee": {
        "end_line": 23,
        "fq_name": "Parity.Consume",
        "kind": "function",
        "language": "csharp",
        "path": "csharp/Parity.cs",
        "signature": "(int)",
        "start_line": 23
      },
      "callee_range": {
        "end_column": 20,
        "end_line": 16,
        "start_column": 13,
        "start_line": 16
      },
      "caller": {
        "end_line": 21,
        "fq_name": "Parity.CatchAndCall",
        "kind": "function",
        "language": "csharp",
        "path": "csharp/Parity.cs",
        "signature": "(int)",
        "start_line": 14
      },
      "caller_parameter_identity": "<public-id>",
      "language": "csharp",
      "path": "csharp/Parity.cs",
      "program_point_id": "<public-id>",
      "proof": "proven",
      "provenance": [
        {
          "seed": {
            "end_line": 23,
            "kind": "method",
            "path": "csharp/Parity.cs",
            "result_type": "structural_match",
            "start_line": 23
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 23,
                "fq_name": "Parity.Consume",
                "kind": "method",
                "path": "csharp/Parity.cs",
                "result_type": "declaration",
                "start_line": 23
              }
            },
            {
              "op": "call_sites_to",
              "result": {
                "callee_fq_name": "Parity.Consume",
                "caller_fq_name": "Parity.CatchAndCall",
                "path": "csharp/Parity.cs",
                "proof": "proven",
                "range": {
                  "end_column": 27,
                  "end_line": 16,
                  "start_column": 13,
                  "start_line": 16
                },
                "result_type": "call_site"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 27,
        "end_line": 16,
        "start_column": 13,
        "start_line": 16
      },
      "receiver_kind": "implicit",
      "result_type": "call_site",
      "site_id": "<public-id>"
    }
  ],
  "truncated": false
}
```

## Traverse Indexed Types And Members

<!-- code-query-fixture:csharp/QueryHierarchy.cs -->
```csharp
class QueryRoot {
    public void RootMember() {}
}

class QueryLeaf : QueryRoot {
    public void LeafMember() {}
}
```

<!-- code-query-case:hierarchy-supertypes:rql -->
```lisp
(supertypes :depth 2 (enclosing-decl (language csharp (class :name "QueryLeaf"))))
```

<!-- code-query-case:hierarchy-supertypes:json -->
```json
{"languages":["csharp"],"match":{"kind":"class","name":"QueryLeaf"},"steps":[{"op":"enclosing_decl"},{"op":"supertypes","depth":2}]}
```

<!-- code-query-case:hierarchy-supertypes:expected -->
```json
{
  "results": [
    {
      "end_line": 3,
      "fq_name": "QueryRoot",
      "kind": "class",
      "language": "csharp",
      "path": "csharp/QueryHierarchy.cs",
      "provenance": [
        {
          "seed": {
            "end_line": 7,
            "kind": "class",
            "path": "csharp/QueryHierarchy.cs",
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
                "path": "csharp/QueryHierarchy.cs",
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
                "path": "csharp/QueryHierarchy.cs",
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
(owner (members (subtypes :transitive true (enclosing-decl (language csharp (class :name "QueryRoot"))))))
```

<!-- code-query-case:hierarchy-subtype-members-owner:json -->
```json
{"languages":["csharp"],"match":{"kind":"class","name":"QueryRoot"},"steps":[{"op":"enclosing_decl"},{"op":"subtypes","transitive":true},{"op":"members"},{"op":"owner"}]}
```

<!-- code-query-case:hierarchy-subtype-members-owner:expected -->
```json
{
  "results": [
    {
      "end_line": 7,
      "fq_name": "QueryLeaf",
      "kind": "class",
      "language": "csharp",
      "path": "csharp/QueryHierarchy.cs",
      "provenance": [
        {
          "seed": {
            "end_line": 3,
            "kind": "class",
            "path": "csharp/QueryHierarchy.cs",
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
                "path": "csharp/QueryHierarchy.cs",
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
                "path": "csharp/QueryHierarchy.cs",
                "result_type": "declaration",
                "start_line": 5
              }
            },
            {
              "op": "members",
              "result": {
                "end_line": 6,
                "fq_name": "QueryLeaf.LeafMember",
                "kind": "function",
                "path": "csharp/QueryHierarchy.cs",
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
                "path": "csharp/QueryHierarchy.cs",
                "result_type": "declaration",
                "start_line": 5
              }
            }
          ]
        }
      ],
      "result_type": "declaration",
      "signature": "class QueryLeaf : QueryRoot {",
      "start_line": 5
    }
  ],
  "truncated": false
}
```

## Select locked bodies

A `lock` exposes the locked `value` and its `body` as separate roles.

<!-- code-query-fixture:csharp/Locking.cs -->
```csharp
class Locking {
    void Guard(object gate) {
        lock (gate) {
            Touch();
        }
    }
    void Touch() {}
}
```

<!-- code-query-case:lock-body:rql -->
```lisp
(language csharp (lock :value (capture "gate") :body (block)))
```

<!-- code-query-case:lock-body:json -->
```json
{"languages":["csharp"],"match":{"kind":"lock","value":{"capture":"gate"},"body":{"kind":"block"}}}
```

<!-- code-query-case:lock-body:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "csharp/Locking.cs",
      "language": "csharp",
      "kind": "lock",
      "start_line": 3,
      "end_line": 5,
      "text": "lock (gate) {\u2026",
      "enclosing_symbol": "Locking.Guard",
      "captures": [
        {
          "name": "gate",
          "text": "gate",
          "start_line": 3
        }
      ]
    }
  ],
  "truncated": false
}
```
