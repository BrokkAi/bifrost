---
title: Python
description: Query Python comparisons by operand binding identity alongside calls, decorators, assignments, and callable containment.
---

> Last verified end to end: 2026-10-09 (`query_code` schema version 1).

For exact inbound and outbound symbol edges, proof tiers, and adapter-specific caveats, see [Reference Traversal](/code-query-tutorials/reference-traversal/).

Python exposes calls, receiver/member access, positional and keyword arguments, imports, assignments, decorated declarations, callable refinements, literals, binary expressions, pairwise comparisons, comparison chains, and control-flow nodes through the normalized model. These examples deliberately include two `client.post(...)` calls so the narrowing query has something real to exclude.

## Local Initialization Paths

`binding-uses` supplies exact lexical read occurrences, and
`python-uninitialized-variable` joins each occurrence to the matching CFG read.
The rule reports only a local read with a modeled entry path that reaches it
without initialization. Module and class names, cross-module globals, builtins,
closures, and open flow identities keep the run incomplete:

```lisp
(filter :where (
    (relation eq undefined_placeholder_variable)
    (outcome eq may_be_uninitialized)
    (completeness eq complete))
  (language python
    (python-uninitialized-variable
      (union
        (binding-uses (bindings))
        (occurrences :class reference :role [value_reference receiver_position])))))
```

<!-- code-query-fixture:python/initialization.py -->
```python
def partial(flag):
    if flag:
        missing_placeholder = 1
    return missing_placeholder
```

<!-- code-query-case:uninitialized-local:rql -->
```lisp
(where "python/initialization.py"
  (filter :where (
      (relation eq undefined_placeholder_variable)
      (outcome eq may_be_uninitialized)
      (completeness eq complete))
    (language python
      (python-uninitialized-variable
        (union
          (binding-uses (bindings))
          (occurrences :class reference :role [value_reference receiver_position]))))))
```

<!-- code-query-case:uninitialized-local:json -->
```json
{
  "where": ["python/initialization.py"],
  "languages": ["python"],
  "union": [
    {"bindings": {}, "steps": [{"op": "binding_uses"}]},
    {"occurrences": {"class": ["reference"], "role": ["value_reference", "receiver_position"]}}
  ],
  "steps": [
    {"op": "python_uninitialized_variable"},
    {"op": "filter", "where": [
      {"field": "relation", "op": "eq", "value": {"enum": "undefined_placeholder_variable"}},
      {"field": "outcome", "op": "eq", "value": {"enum": "may_be_uninitialized"}},
      {"field": "completeness", "op": "eq", "value": {"enum": "complete"}}
    ]}
  ]
}
```

<!-- code-query-case:uninitialized-local:expected -->
```json
{
  "results": [
    {
      "completeness": "complete",
      "id": "b7777869101ff392df4f5a9374e07401b1af1333f23ac8b28b8dcf63590c1acb",
      "language": "python",
      "outcome": "may_be_uninitialized",
      "owner_id": "0bcce212a7e9c2fc382255a98a7baa732b3242591bfc7437f00408f3fc1f4f60",
      "path": "python/initialization.py",
      "proof": "proven",
      "range": {
        "end_column": 31,
        "end_line": 4,
        "start_column": 12,
        "start_line": 4
      },
      "relation": "undefined_placeholder_variable",
      "result_type": "python_rule_fact"
    }
  ],
  "truncated": false
}
```

## Missing Documentation

`python-documentation` reports decoded docstrings, public scope, CodeQL-style
code-line counts, and Python method exclusions as typed rule facts. This query
finds public functions that need documentation:

<!-- code-query-fixture:python/documentation.py -->
```python
def public_function(flag):
    if flag:
        return 1
    return 2

def documented_function():
    """Already documented."""
    return 1
```

<!-- code-query-case:missing-function-docstring:rql -->
```lisp
(filter :where ((relation eq documentation)
                (outcome eq issue)
                (completeness eq complete))
  (where "python/documentation.py"
    (python-documentation
      (enclosing-decl
        (language python
          (function))))))
```

<!-- code-query-case:missing-function-docstring:json -->
```json
{
  "where": ["python/documentation.py"],
  "languages": ["python"],
  "match": {"kind": "function"},
  "steps": [
    {"op": "enclosing_decl"},
    {"op": "python_documentation"},
    {"op": "filter", "where": [
      {"field": "relation", "op": "eq", "value": {"enum": "documentation"}},
      {"field": "outcome", "op": "eq", "value": {"enum": "issue"}},
      {"field": "completeness", "op": "eq", "value": {"enum": "complete"}}
    ]}
  ]
}
```

<!-- code-query-case:missing-function-docstring:expected -->
```json
{
  "results": [
    {
      "completeness": "complete",
      "decorator_count": 0,
      "docstring_present": false,
      "id": "ce1837ccf4968d124c74522090c31957484ddb169f7e92890643d5d6e60b8e7f",
      "is_override": false,
      "is_property_accessor": false,
      "language": "python",
      "lines_of_code": 4,
      "outcome": "issue",
      "owner_id": "decl:v1:7b0bfc78d8c8ce4d96b57ff9a3d3d785e210ad6729492503fe50fb2dc20a8da0",
      "path": "python/documentation.py",
      "proof": "proven",
      "provenance": [
        {
          "seed": {
            "end_line": 4,
            "kind": "function",
            "path": "python/documentation.py",
            "result_type": "structural_match",
            "start_line": 1
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 4,
                "fq_name": "python.documentation.public_function",
                "kind": "function",
                "path": "python/documentation.py",
                "result_type": "declaration",
                "start_line": 1
              }
            },
            {
              "op": "python_documentation",
              "result": {
                "id": "ce1837ccf4968d124c74522090c31957484ddb169f7e92890643d5d6e60b8e7f",
                "outcome": "issue",
                "path": "python/documentation.py",
                "range": {
                  "end_column": 13,
                  "end_line": 4,
                  "start_column": 1,
                  "start_line": 1
                },
                "relation": "documentation",
                "result_type": "python_rule_fact"
              }
            },
            {
              "op": "filter",
              "result": {
                "id": "ce1837ccf4968d124c74522090c31957484ddb169f7e92890643d5d6e60b8e7f",
                "outcome": "issue",
                "path": "python/documentation.py",
                "range": {
                  "end_column": 13,
                  "end_line": 4,
                  "start_column": 1,
                  "start_line": 1
                },
                "relation": "documentation",
                "result_type": "python_rule_fact"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 13,
        "end_line": 4,
        "start_column": 1,
        "start_line": 1
      },
      "relation": "documentation",
      "result_type": "python_rule_fact",
      "scope_is_public": true
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:useless-class:rql -->
```lisp
(filter :where ((relation eq useless_class)
                (outcome eq issue)
                (completeness eq complete))
  (where "python/useless_class.py"
    (python-useless-class
      (enclosing-decl
        (language python
          (class))))))
```

<!-- code-query-case:useless-class:json -->
```json
{
  "where": ["python/useless_class.py"],
  "languages": ["python"],
  "match": {"kind": "class"},
  "steps": [
    {"op": "enclosing_decl"},
    {"op": "python_useless_class"},
    {"op": "filter", "where": [
      {"field": "relation", "op": "eq", "value": {"enum": "useless_class"}},
      {"field": "outcome", "op": "eq", "value": {"enum": "issue"}},
      {"field": "completeness", "op": "eq", "value": {"enum": "complete"}}
    ]}
  ]
}
```

<!-- code-query-case:useless-class:expected -->
```json
{
  "results": [
    {
      "completeness": "complete",
      "has_inheritance": false,
      "has_special_method": false,
      "has_subclasses": false,
      "id": "745dc914bd8ae610a335f21d333c2f513637422081c65394631b393ad830b847",
      "is_decorated": false,
      "is_probable_mixin": false,
      "is_stateful": false,
      "is_top_level": true,
      "language": "python",
      "outcome": "issue",
      "owner_id": "decl:v1:e41944877afcf4d910a3d63aaa081147bec7d9f922db530f63df0481e609f02e",
      "path": "python/useless_class.py",
      "proof": "proven",
      "provenance": [
        {
          "seed": {
            "end_line": 2,
            "kind": "class",
            "path": "python/useless_class.py",
            "result_type": "structural_match",
            "start_line": 1
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 2,
                "fq_name": "python.useless_class.Empty",
                "kind": "class",
                "path": "python/useless_class.py",
                "result_type": "declaration",
                "start_line": 1
              }
            },
            {
              "op": "python_useless_class",
              "result": {
                "id": "745dc914bd8ae610a335f21d333c2f513637422081c65394631b393ad830b847",
                "outcome": "issue",
                "path": "python/useless_class.py",
                "range": {
                  "end_column": 9,
                  "end_line": 2,
                  "start_column": 1,
                  "start_line": 1
                },
                "relation": "useless_class",
                "result_type": "python_rule_fact"
              }
            },
            {
              "op": "filter",
              "result": {
                "id": "745dc914bd8ae610a335f21d333c2f513637422081c65394631b393ad830b847",
                "outcome": "issue",
                "path": "python/useless_class.py",
                "range": {
                  "end_column": 9,
                  "end_line": 2,
                  "start_column": 1,
                  "start_line": 1
                },
                "relation": "useless_class",
                "result_type": "python_rule_fact"
              }
            }
          ]
        }
      ],
      "public_method_count": 0,
      "range": {
        "end_column": 9,
        "end_line": 2,
        "start_column": 1,
        "start_line": 1
      },
      "relation": "useless_class",
      "result_type": "python_rule_fact",
      "scope_is_public": true
    },
    {
      "completeness": "complete",
      "has_inheritance": false,
      "has_special_method": false,
      "has_subclasses": false,
      "id": "165f967aada203d39c82647a62077152e80d4926e3fbbe3afa761c3eaa9941ed",
      "is_decorated": false,
      "is_probable_mixin": false,
      "is_stateful": false,
      "is_top_level": true,
      "language": "python",
      "outcome": "issue",
      "owner_id": "decl:v1:6a732974a444bca1c8bda1cef8945800c64f3646eee6c9b9be5d22fb5afc4cda",
      "path": "python/useless_class.py",
      "proof": "proven",
      "provenance": [
        {
          "seed": {
            "end_line": 6,
            "kind": "class",
            "path": "python/useless_class.py",
            "result_type": "structural_match",
            "start_line": 4
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 6,
                "fq_name": "python.useless_class.OneMethod",
                "kind": "class",
                "path": "python/useless_class.py",
                "result_type": "declaration",
                "start_line": 4
              }
            },
            {
              "op": "python_useless_class",
              "result": {
                "id": "165f967aada203d39c82647a62077152e80d4926e3fbbe3afa761c3eaa9941ed",
                "outcome": "issue",
                "path": "python/useless_class.py",
                "range": {
                  "end_column": 13,
                  "end_line": 6,
                  "start_column": 1,
                  "start_line": 4
                },
                "relation": "useless_class",
                "result_type": "python_rule_fact"
              }
            },
            {
              "op": "filter",
              "result": {
                "id": "165f967aada203d39c82647a62077152e80d4926e3fbbe3afa761c3eaa9941ed",
                "outcome": "issue",
                "path": "python/useless_class.py",
                "range": {
                  "end_column": 13,
                  "end_line": 6,
                  "start_column": 1,
                  "start_line": 4
                },
                "relation": "useless_class",
                "result_type": "python_rule_fact"
              }
            }
          ]
        }
      ],
      "public_method_count": 1,
      "range": {
        "end_column": 13,
        "end_line": 6,
        "start_column": 1,
        "start_line": 4
      },
      "relation": "useless_class",
      "result_type": "python_rule_fact",
      "scope_is_public": true
    }
  ],
  "truncated": false
}
```

<!-- code-query-fixture:python/useless_class.py -->
```python
class Empty:
    pass

class OneMethod:
    def run(self):
        pass

class TwoMethods:
    def first(self):
        pass

    def second(self):
        pass
```

## Attributes That Hide Descendant Methods

`python-attribute-shadows-method` joins direct descendant methods with
attribute writes from ancestor `__init__` methods. It follows complete C3
ancestry and local `self` aliases. Unknown bases, dynamic `setattr` names,
escaped `self` values, and unresolved local aliases remain incomplete.

<!-- code-query-fixture:python/attribute_shadow.py -->
```python
class Base:
    def __init__(self):
        self.value = 0

class ShadowedChild(Base):
    def value(self):
        return 1
```

<!-- code-query-case:attribute-shadows-method:rql -->
```lisp
(filter :where ((relation eq attribute_shadows_method)
                (outcome eq issue)
                (completeness eq complete))
  (where "python/attribute_shadow.py"
    (python-attribute-shadows-method
      (enclosing-decl
        (language python
          (class))))))
```

<!-- code-query-case:attribute-shadows-method:json -->
```json
{
  "where": ["python/attribute_shadow.py"],
  "languages": ["python"],
  "match": {"kind": "class"},
  "steps": [
    {"op": "enclosing_decl"},
    {"op": "python_attribute_shadows_method"},
    {"op": "filter", "where": [
      {"field": "relation", "op": "eq", "value": {"enum": "attribute_shadows_method"}},
      {"field": "outcome", "op": "eq", "value": {"enum": "issue"}},
      {"field": "completeness", "op": "eq", "value": {"enum": "complete"}}
    ]}
  ]
}
```

<!-- code-query-case:attribute-shadows-method:expected -->
```json
{
  "results": [
    {
      "completeness": "complete",
      "id": "25e76f04d3f8567aa315adc490dd5f5618ccfe4e22ef287e9cc793d099b05732",
      "language": "python",
      "outcome": "issue",
      "owner_id": "decl:v1:21498572a12d10a92bcd8f336b1ed7dbb611949d2503f8e2db9da49c7d919ae0",
      "path": "python/attribute_shadow.py",
      "proof": "proven",
      "provenance": [
        {
          "seed": {
            "end_line": 7,
            "kind": "class",
            "path": "python/attribute_shadow.py",
            "result_type": "structural_match",
            "start_line": 5
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 7,
                "fq_name": "python.attribute_shadow.ShadowedChild",
                "kind": "class",
                "path": "python/attribute_shadow.py",
                "result_type": "declaration",
                "start_line": 5
              }
            },
            {
              "op": "python_attribute_shadows_method",
              "result": {
                "id": "25e76f04d3f8567aa315adc490dd5f5618ccfe4e22ef287e9cc793d099b05732",
                "outcome": "issue",
                "path": "python/attribute_shadow.py",
                "range": {
                  "end_column": 14,
                  "end_line": 6,
                  "start_column": 9,
                  "start_line": 6
                },
                "relation": "attribute_shadows_method",
                "result_type": "python_rule_fact"
              }
            },
            {
              "op": "filter",
              "result": {
                "id": "25e76f04d3f8567aa315adc490dd5f5618ccfe4e22ef287e9cc793d099b05732",
                "outcome": "issue",
                "path": "python/attribute_shadow.py",
                "range": {
                  "end_column": 14,
                  "end_line": 6,
                  "start_column": 9,
                  "start_line": 6
                },
                "relation": "attribute_shadows_method",
                "result_type": "python_rule_fact"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 14,
        "end_line": 6,
        "start_column": 9,
        "start_line": 6
      },
      "reason": "initializer attribute write at python/attribute_shadow.py:3",
      "relation": "attribute_shadows_method",
      "result_type": "python_rule_fact",
      "target_id": "decl:v1:d2fc8b9481a9c5c6f205af9e2ca03c8c9063480ca0f0d60e335be49d86ae9d04"
    }
  ],
  "truncated": false
}
```

## Mutable Parameter Defaults

`python-modification-of-default-value` follows local aliases from mutable
list, dictionary, and set defaults to in-place method calls, subscript stores
and deletes, and augmented assignments. Straight line rebinding ends the
alias. A simple truthiness guard skips a mutation when it proves that the
default's known empty or nonempty state cannot reach that branch. Calls that
may let the object escape keep the result incomplete.

<!-- code-query-fixture:python/mutable_default.py -->
```python
def append_default(items=[]):
    items.append(1)

def safe_after_rebinding(items=[]):
    items = []
    items.append(2)
```

<!-- code-query-case:mutable-default:rql -->
```lisp
(filter :where ((relation eq modification_of_default_value)
                (outcome eq issue)
                (completeness eq complete))
  (where "python/mutable_default.py"
    (python-modification-of-default-value
      (enclosing-decl
        (language python
          (function))))))
```

<!-- code-query-case:mutable-default:json -->
```json
{
  "where": ["python/mutable_default.py"],
  "languages": ["python"],
  "match": {"kind": "function"},
  "steps": [
    {"op": "enclosing_decl"},
    {"op": "python_modification_of_default_value"},
    {"op": "filter", "where": [
      {"field": "relation", "op": "eq", "value": {"enum": "modification_of_default_value"}},
      {"field": "outcome", "op": "eq", "value": {"enum": "issue"}},
      {"field": "completeness", "op": "eq", "value": {"enum": "complete"}}
    ]}
  ]
}
```

<!-- code-query-case:mutable-default:expected -->
```json
{
  "results": [
    {
      "completeness": "complete",
      "id": "87830c19f3cbf89acbdafd541d4a29e31591c9f26ba07736aa12c8fd2fc4cc0e",
      "language": "python",
      "outcome": "issue",
      "owner_id": "decl:v1:f778cfb2b9704f4b6a532f6506166b2f9e56c3288b49d3b8286f32e7f2614faa",
      "path": "python/mutable_default.py",
      "proof": "proven",
      "provenance": [
        {
          "seed": {
            "end_line": 2,
            "kind": "function",
            "path": "python/mutable_default.py",
            "result_type": "structural_match",
            "start_line": 1
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 2,
                "fq_name": "python.mutable_default.append_default",
                "kind": "function",
                "path": "python/mutable_default.py",
                "result_type": "declaration",
                "start_line": 1
              }
            },
            {
              "op": "python_modification_of_default_value",
              "result": {
                "id": "87830c19f3cbf89acbdafd541d4a29e31591c9f26ba07736aa12c8fd2fc4cc0e",
                "outcome": "issue",
                "path": "python/mutable_default.py",
                "range": {
                  "end_column": 20,
                  "end_line": 2,
                  "start_column": 5,
                  "start_line": 2
                },
                "relation": "modification_of_default_value",
                "result_type": "python_rule_fact"
              }
            },
            {
              "op": "filter",
              "result": {
                "id": "87830c19f3cbf89acbdafd541d4a29e31591c9f26ba07736aa12c8fd2fc4cc0e",
                "outcome": "issue",
                "path": "python/mutable_default.py",
                "range": {
                  "end_column": 20,
                  "end_line": 2,
                  "start_column": 5,
                  "start_line": 2
                },
                "relation": "modification_of_default_value",
                "result_type": "python_rule_fact"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 20,
        "end_line": 2,
        "start_column": 5,
        "start_line": 2
      },
      "relation": "modification_of_default_value",
      "result_type": "python_rule_fact"
    }
  ],
  "truncated": false
}
```

## Destructor Complexity

`python-overly-complex-delete` reports the cyclomatic complexity of a
destructor from its reachable control-flow graph. The campaign example has
complexity four and crosses the `py/overly-complex-delete` threshold:

<!-- code-query-fixture:python/overly_complex_delete.py -->
```python
class Complex:
    def __del__(self):
        if self.ready:
            print(1)
        if self.closed:
            print(2)
        for value in range(2):
            print(value)

class Simple:
    def __del__(self):
        self.close()

    def close(self):
        pass
```

<!-- code-query-case:overly-complex-delete:rql -->
```lisp
(filter :where ((relation eq overly_complex_delete)
                (cyclomatic_complexity eq 4)
                (outcome eq issue)
                (completeness eq complete))
  (where "python/overly_complex_delete.py"
    (python-overly-complex-delete
      (enclosing-decl
        (language python
          (callable))))))
```

<!-- code-query-case:overly-complex-delete:json -->
```json
{
  "where": ["python/overly_complex_delete.py"],
  "languages": ["python"],
  "match": {"kind": "callable"},
  "steps": [
    {"op": "enclosing_decl"},
    {"op": "python_overly_complex_delete"},
    {"op": "filter", "where": [
      {"field": "relation", "op": "eq", "value": {"enum": "overly_complex_delete"}},
      {"field": "cyclomatic_complexity", "op": "eq", "value": {"integer": 4}},
      {"field": "outcome", "op": "eq", "value": {"enum": "issue"}},
      {"field": "completeness", "op": "eq", "value": {"enum": "complete"}}
    ]}
  ]
}
```

<!-- code-query-case:overly-complex-delete:expected -->
```json
{
  "results": [
    {
      "completeness": "complete",
      "cyclomatic_complexity": 4,
      "id": "95f98e8bb2d32ffbe7ad2f78a58df66f21fbe72b504e1f06d5f1020f5853c736",
      "language": "python",
      "outcome": "issue",
      "owner_id": "decl:v1:c68be755c5c1624a5a25ab4fd43a84f92ba4063a4444d7099a81ff933cbcb5a6",
      "path": "python/overly_complex_delete.py",
      "proof": "proven",
      "provenance": [
        {
          "seed": {
            "end_line": 8,
            "kind": "method",
            "path": "python/overly_complex_delete.py",
            "result_type": "structural_match",
            "start_line": 2
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 8,
                "fq_name": "python.overly_complex_delete.Complex.__del__",
                "kind": "method",
                "path": "python/overly_complex_delete.py",
                "result_type": "declaration",
                "start_line": 2
              }
            },
            {
              "op": "python_overly_complex_delete",
              "result": {
                "id": "95f98e8bb2d32ffbe7ad2f78a58df66f21fbe72b504e1f06d5f1020f5853c736",
                "outcome": "issue",
                "path": "python/overly_complex_delete.py",
                "range": {
                  "end_column": 25,
                  "end_line": 8,
                  "start_column": 5,
                  "start_line": 2
                },
                "relation": "overly_complex_delete",
                "result_type": "python_rule_fact"
              }
            },
            {
              "op": "filter",
              "result": {
                "id": "95f98e8bb2d32ffbe7ad2f78a58df66f21fbe72b504e1f06d5f1020f5853c736",
                "outcome": "issue",
                "path": "python/overly_complex_delete.py",
                "range": {
                  "end_column": 25,
                  "end_line": 8,
                  "start_column": 5,
                  "start_line": 2
                },
                "relation": "overly_complex_delete",
                "result_type": "python_rule_fact"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 25,
        "end_line": 8,
        "start_column": 5,
        "start_line": 2
      },
      "relation": "overly_complex_delete",
      "result_type": "python_rule_fact"
    }
  ],
  "truncated": false
}
```

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

def receive(value):
    return value

receive(object())
```

<!-- code-query-case:polynomial-regex-risk:rql -->
```lisp
(language python (regex_risk_polynomial))
```

<!-- code-query-case:polynomial-regex-risk:json -->
```json
{"languages":["python"],"match":{"kind":"regex_risk_polynomial"}}
```

<!-- code-query-case:polynomial-regex-risk:expected -->
```json
{"results":[{"enclosing_symbol":"python.regex.trim_input","end_line":4,"kind":"regex_risk_polynomial","language":"python","path":"python/regex.py","result_type":"structural_match","start_line":4,"text":"+"}],"truncated":false}
```

<!-- code-query-fixture:python/regex.py -->
```python
import re

def trim_input(value):
    return re.search(r"\s+$", value)
```

<!-- code-query-fixture:python/lifecycle.py -->
```python
class LifecycleBase:
    def __init__(self):
        pass

class LifecycleLeaf(LifecycleBase):
    def __init__(self):
        super().__init__()

class CleanupBase:
    def __del__(self):
        pass

class CleanupLeaf(CleanupBase):
    def __del__(self):
        super().__del__()
```

<!-- code-query-fixture:python/inference.py -->
```python
class KnownBase:
    pass

class UnresolvedBase(MissingBase):
    pass

class ResolvableChild(KnownBase):
    pass
```

The `inference_failure` fact identifies a particular written base the analyzer could not resolve. Its class, base ordinal, spelling, and reason form a definite row; the same query still reports open hierarchy coverage for checks that depend on the full MRO.

<!-- code-query-case:failed-inheritance-inference:rql -->
```lisp
(filter
  :where ((fact_kind eq inference_failure)
          (coverage eq complete))
  (class-hierarchy
    (enclosing-decl
      (language python
        (class :name "UnresolvedBase")))))
```

<!-- code-query-case:failed-inheritance-inference:json -->
```json
{"languages":["python"],"match":{"kind":"class","name":"UnresolvedBase"},"steps":[{"op":"enclosing_decl"},{"op":"class_hierarchy"},{"op":"filter","where":[{"field":"fact_kind","op":"eq","value":{"enum":"inference_failure"}},{"field":"coverage","op":"eq","value":{"enum":"complete"}}]}],"result_detail":"compact"}
```

<!-- code-query-case:failed-inheritance-inference:expected -->
```json
{"diagnostics":[{"code":"python_hierarchy_derivation_incomplete","impact":"incomplete","language":"python","message":"Python class hierarchy facts have open outcomes; unresolved or unsupported base information prevents a definite result"}],"results":[{"base_resolution":"unresolved","base_spelling":"MissingBase","coverage":"complete","fact_kind":"inference_failure","id":"3930540a51aab53fd4688a72eab684af480b05ce27a112a1c8b55d5c86d2e6f8","language":"python","ordinal":0,"outcome":"unresolved","path":"python/inference.py","provenance":[{"seed":{"end_line":5,"kind":"class","path":"python/inference.py","result_type":"structural_match","start_line":4},"steps":[{"op":"enclosing_decl","result":{"end_line":5,"fq_name":"python.inference.UnresolvedBase","kind":"class","path":"python/inference.py","result_type":"declaration","start_line":4}},{"op":"class_hierarchy","result":{"fact_kind":"inference_failure","id":"3930540a51aab53fd4688a72eab684af480b05ce27a112a1c8b55d5c86d2e6f8","outcome":"unresolved","path":"python/inference.py","range":{"end_column":9,"end_line":5,"start_column":1,"start_line":4},"result_type":"python_hierarchy_fact","root_id":"220141a010ff00e4c6dd435b78e619051f9eb32f51bbafef46aa77f58732b69a"}},{"op":"filter","result":{"fact_kind":"inference_failure","id":"3930540a51aab53fd4688a72eab684af480b05ce27a112a1c8b55d5c86d2e6f8","outcome":"unresolved","path":"python/inference.py","range":{"end_column":9,"end_line":5,"start_column":1,"start_line":4},"result_type":"python_hierarchy_fact","root_id":"220141a010ff00e4c6dd435b78e619051f9eb32f51bbafef46aa77f58732b69a"}}]}],"range":{"end_column":9,"end_line":5,"start_column":1,"start_line":4},"reason":"unresolved_base","result_type":"python_hierarchy_fact","root":{"end_line":5,"fq_name":"python.inference.UnresolvedBase","kind":"class","language":"python","path":"python/inference.py","signature":"class UnresolvedBase(MissingBase):","start_line":4},"root_declaration_id":"220141a010ff00e4c6dd435b78e619051f9eb32f51bbafef46aa77f58732b69a","root_id":"220141a010ff00e4c6dd435b78e619051f9eb32f51bbafef46aa77f58732b69a"}],"truncated":false}
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

<!-- code-query-case:python-lifecycle-call:rql -->
```lisp
(filter
  :where ((fact_kind eq call_lifecycle))
  (python-call-relations
    (enclosing-decl
      (language python
        (class :name "LifecycleLeaf")))))
```

<!-- code-query-case:python-lifecycle-call:json -->
```json
{"languages":["python"],"match":{"kind":"class","name":"LifecycleLeaf"},"steps":[{"op":"enclosing_decl"},{"op":"python_call_relations"},{"op":"filter","where":[{"field":"fact_kind","op":"eq","value":{"enum":"call_lifecycle"}}]}]}
```

<!-- code-query-case:python-lifecycle-call:expected -->
```json
{
  "results": [
    {
      "coverage": "complete",
      "declaration": {
        "end_line": 7,
        "fq_name": "python.lifecycle.LifecycleLeaf.__init__",
        "kind": "function",
        "language": "python",
        "path": "python/lifecycle.py",
        "signature": "(self)",
        "start_line": 6
      },
      "declaration_id": "92016e3b71f006511d8e4bc0439e6a369bfc091096fc88d65fde5a2d1b17618c",
      "fact_kind": "call_lifecycle",
      "id": "37bc527d1bb65f4a06ea578f1c2811c31b79e703f54f1b1d2f250b0b8c738828",
      "language": "python",
      "member_name": "__init__",
      "mro_rank": 1,
      "ordinal": 1,
      "outcome": "called",
      "owner": {
        "end_line": 7,
        "fq_name": "python.lifecycle.LifecycleLeaf",
        "kind": "class",
        "language": "python",
        "path": "python/lifecycle.py",
        "signature": "class LifecycleLeaf(LifecycleBase):",
        "start_line": 5
      },
      "owner_id": "535172ee3cb59edf22337efe7c69cfb82a59afa15efcca9bff54194c3395b559",
      "path": "python/lifecycle.py",
      "provenance": [
        {
          "seed": {
            "end_line": 7,
            "kind": "class",
            "path": "python/lifecycle.py",
            "result_type": "structural_match",
            "start_line": 5
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 7,
                "fq_name": "python.lifecycle.LifecycleLeaf",
                "kind": "class",
                "path": "python/lifecycle.py",
                "result_type": "declaration",
                "start_line": 5
              }
            },
            {
              "op": "python_call_relations",
              "result": {
                "fact_kind": "call_lifecycle",
                "id": "37bc527d1bb65f4a06ea578f1c2811c31b79e703f54f1b1d2f250b0b8c738828",
                "outcome": "called",
                "path": "python/lifecycle.py",
                "range": {
                  "end_column": 27,
                  "end_line": 7,
                  "start_column": 5,
                  "start_line": 6
                },
                "result_type": "python_hierarchy_fact",
                "root_id": "535172ee3cb59edf22337efe7c69cfb82a59afa15efcca9bff54194c3395b559"
              }
            },
            {
              "op": "filter",
              "result": {
                "fact_kind": "call_lifecycle",
                "id": "37bc527d1bb65f4a06ea578f1c2811c31b79e703f54f1b1d2f250b0b8c738828",
                "outcome": "called",
                "path": "python/lifecycle.py",
                "range": {
                  "end_column": 27,
                  "end_line": 7,
                  "start_column": 5,
                  "start_line": 6
                },
                "result_type": "python_hierarchy_fact",
                "root_id": "535172ee3cb59edf22337efe7c69cfb82a59afa15efcca9bff54194c3395b559"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 27,
        "end_line": 7,
        "start_column": 5,
        "start_line": 6
      },
      "result_type": "python_hierarchy_fact",
      "root": {
        "end_line": 7,
        "fq_name": "python.lifecycle.LifecycleLeaf",
        "kind": "class",
        "language": "python",
        "path": "python/lifecycle.py",
        "signature": "class LifecycleLeaf(LifecycleBase):",
        "start_line": 5
      },
      "root_declaration_id": "535172ee3cb59edf22337efe7c69cfb82a59afa15efcca9bff54194c3395b559",
      "root_id": "535172ee3cb59edf22337efe7c69cfb82a59afa15efcca9bff54194c3395b559",
      "target": {
        "end_line": 3,
        "fq_name": "python.lifecycle.LifecycleBase.__init__",
        "kind": "function",
        "language": "python",
        "path": "python/lifecycle.py",
        "signature": "(self)",
        "start_line": 2
      },
      "target_id": "a47ddb73c872d36934204ed32f1df7e3d636dc63d5f2cea02d71d4f3540adf91",
      "target_owner": {
        "end_line": 3,
        "fq_name": "python.lifecycle.LifecycleBase",
        "kind": "class",
        "language": "python",
        "path": "python/lifecycle.py",
        "signature": "class LifecycleBase:",
        "start_line": 1
      },
      "target_owner_id": "ced358501135bd4c21d6270966ae4c466e8eacad9b51c335761bc314c84dc1b3"
    },
    {
      "coverage": "complete",
      "declaration": {
        "end_line": 7,
        "fq_name": "python.lifecycle.LifecycleLeaf.__init__",
        "kind": "function",
        "language": "python",
        "path": "python/lifecycle.py",
        "signature": "(self)",
        "start_line": 6
      },
      "declaration_id": "92016e3b71f006511d8e4bc0439e6a369bfc091096fc88d65fde5a2d1b17618c",
      "fact_kind": "call_lifecycle",
      "id": "11d375fd57aa69f7392510a6b9d04c62527ed067f2930e96bd8cd59384f2ce07",
      "language": "python",
      "member_name": "__init__",
      "outcome": "no_issue",
      "owner": {
        "end_line": 7,
        "fq_name": "python.lifecycle.LifecycleLeaf",
        "kind": "class",
        "language": "python",
        "path": "python/lifecycle.py",
        "signature": "class LifecycleLeaf(LifecycleBase):",
        "start_line": 5
      },
      "owner_id": "535172ee3cb59edf22337efe7c69cfb82a59afa15efcca9bff54194c3395b559",
      "path": "python/lifecycle.py",
      "provenance": [
        {
          "seed": {
            "end_line": 7,
            "kind": "class",
            "path": "python/lifecycle.py",
            "result_type": "structural_match",
            "start_line": 5
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 7,
                "fq_name": "python.lifecycle.LifecycleLeaf",
                "kind": "class",
                "path": "python/lifecycle.py",
                "result_type": "declaration",
                "start_line": 5
              }
            },
            {
              "op": "python_call_relations",
              "result": {
                "fact_kind": "call_lifecycle",
                "id": "11d375fd57aa69f7392510a6b9d04c62527ed067f2930e96bd8cd59384f2ce07",
                "outcome": "no_issue",
                "path": "python/lifecycle.py",
                "range": {
                  "end_column": 27,
                  "end_line": 7,
                  "start_column": 5,
                  "start_line": 6
                },
                "result_type": "python_hierarchy_fact",
                "root_id": "535172ee3cb59edf22337efe7c69cfb82a59afa15efcca9bff54194c3395b559"
              }
            },
            {
              "op": "filter",
              "result": {
                "fact_kind": "call_lifecycle",
                "id": "11d375fd57aa69f7392510a6b9d04c62527ed067f2930e96bd8cd59384f2ce07",
                "outcome": "no_issue",
                "path": "python/lifecycle.py",
                "range": {
                  "end_column": 27,
                  "end_line": 7,
                  "start_column": 5,
                  "start_line": 6
                },
                "result_type": "python_hierarchy_fact",
                "root_id": "535172ee3cb59edf22337efe7c69cfb82a59afa15efcca9bff54194c3395b559"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 27,
        "end_line": 7,
        "start_column": 5,
        "start_line": 6
      },
      "result_type": "python_hierarchy_fact",
      "root": {
        "end_line": 7,
        "fq_name": "python.lifecycle.LifecycleLeaf",
        "kind": "class",
        "language": "python",
        "path": "python/lifecycle.py",
        "signature": "class LifecycleLeaf(LifecycleBase):",
        "start_line": 5
      },
      "root_declaration_id": "535172ee3cb59edf22337efe7c69cfb82a59afa15efcca9bff54194c3395b559",
      "root_id": "535172ee3cb59edf22337efe7c69cfb82a59afa15efcca9bff54194c3395b559"
    },
    {
      "coverage": "complete",
      "fact_kind": "call_lifecycle",
      "id": "416f0c056aac849d99efeeecdc34a6461bc51a1be00becae6cb3fba27aa47c90",
      "language": "python",
      "member_name": "__del__",
      "outcome": "no_issue",
      "owner": {
        "end_line": 7,
        "fq_name": "python.lifecycle.LifecycleLeaf",
        "kind": "class",
        "language": "python",
        "path": "python/lifecycle.py",
        "signature": "class LifecycleLeaf(LifecycleBase):",
        "start_line": 5
      },
      "owner_id": "535172ee3cb59edf22337efe7c69cfb82a59afa15efcca9bff54194c3395b559",
      "path": "python/lifecycle.py",
      "provenance": [
        {
          "seed": {
            "end_line": 7,
            "kind": "class",
            "path": "python/lifecycle.py",
            "result_type": "structural_match",
            "start_line": 5
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 7,
                "fq_name": "python.lifecycle.LifecycleLeaf",
                "kind": "class",
                "path": "python/lifecycle.py",
                "result_type": "declaration",
                "start_line": 5
              }
            },
            {
              "op": "python_call_relations",
              "result": {
                "fact_kind": "call_lifecycle",
                "id": "416f0c056aac849d99efeeecdc34a6461bc51a1be00becae6cb3fba27aa47c90",
                "outcome": "no_issue",
                "path": "python/lifecycle.py",
                "range": {
                  "end_column": 27,
                  "end_line": 7,
                  "start_column": 1,
                  "start_line": 5
                },
                "result_type": "python_hierarchy_fact",
                "root_id": "535172ee3cb59edf22337efe7c69cfb82a59afa15efcca9bff54194c3395b559"
              }
            },
            {
              "op": "filter",
              "result": {
                "fact_kind": "call_lifecycle",
                "id": "416f0c056aac849d99efeeecdc34a6461bc51a1be00becae6cb3fba27aa47c90",
                "outcome": "no_issue",
                "path": "python/lifecycle.py",
                "range": {
                  "end_column": 27,
                  "end_line": 7,
                  "start_column": 1,
                  "start_line": 5
                },
                "result_type": "python_hierarchy_fact",
                "root_id": "535172ee3cb59edf22337efe7c69cfb82a59afa15efcca9bff54194c3395b559"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 27,
        "end_line": 7,
        "start_column": 1,
        "start_line": 5
      },
      "result_type": "python_hierarchy_fact",
      "root": {
        "end_line": 7,
        "fq_name": "python.lifecycle.LifecycleLeaf",
        "kind": "class",
        "language": "python",
        "path": "python/lifecycle.py",
        "signature": "class LifecycleLeaf(LifecycleBase):",
        "start_line": 5
      },
      "root_declaration_id": "535172ee3cb59edf22337efe7c69cfb82a59afa15efcca9bff54194c3395b559",
      "root_id": "535172ee3cb59edf22337efe7c69cfb82a59afa15efcca9bff54194c3395b559"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:python-super-context:rql -->
```lisp
(filter
  :where ((fact_kind eq call_context))
  (python-call-relations
    (enclosing-decl
      (language python
        (class :name "CleanupLeaf")))))
```

<!-- code-query-case:python-super-context:json -->
```json
{"languages":["python"],"match":{"kind":"class","name":"CleanupLeaf"},"steps":[{"op":"enclosing_decl"},{"op":"python_call_relations"},{"op":"filter","where":[{"field":"fact_kind","op":"eq","value":{"enum":"call_context"}}]}]}
```

<!-- code-query-case:python-super-context:expected -->
```json
{
  "results": [
    {
      "coverage": "complete",
      "declaration": {
        "end_line": 15,
        "fq_name": "python.lifecycle.CleanupLeaf.__del__",
        "kind": "function",
        "language": "python",
        "path": "python/lifecycle.py",
        "signature": "(self)",
        "start_line": 14
      },
      "declaration_id": "d349f9e99aac4b6537853a349bd87d86a73cb2bbb2afcdc1e850690764c0c67a",
      "fact_kind": "call_context",
      "id": "b0c03dfdb913d62fcd742b5778b9a7da636e7491546c0023680ca401eb82034a",
      "language": "python",
      "member_name": "__del__",
      "mro_rank": 1,
      "outcome": "approved_cleanup",
      "owner": {
        "end_line": 15,
        "fq_name": "python.lifecycle.CleanupLeaf",
        "kind": "class",
        "language": "python",
        "path": "python/lifecycle.py",
        "signature": "class CleanupLeaf(CleanupBase):",
        "start_line": 13
      },
      "owner_id": "6e0307a75d6541490ba1b02e5007b421ce8b15ea0d1bf06f272daaa90d02da1e",
      "path": "python/lifecycle.py",
      "provenance": [
        {
          "seed": {
            "end_line": 15,
            "kind": "class",
            "path": "python/lifecycle.py",
            "result_type": "structural_match",
            "start_line": 13
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 15,
                "fq_name": "python.lifecycle.CleanupLeaf",
                "kind": "class",
                "path": "python/lifecycle.py",
                "result_type": "declaration",
                "start_line": 13
              }
            },
            {
              "op": "python_call_relations",
              "result": {
                "fact_kind": "call_context",
                "id": "b0c03dfdb913d62fcd742b5778b9a7da636e7491546c0023680ca401eb82034a",
                "outcome": "approved_cleanup",
                "path": "python/lifecycle.py",
                "range": {
                  "end_column": 26,
                  "end_line": 15,
                  "start_column": 9,
                  "start_line": 15
                },
                "result_type": "python_hierarchy_fact",
                "root_id": "6e0307a75d6541490ba1b02e5007b421ce8b15ea0d1bf06f272daaa90d02da1e"
              }
            },
            {
              "op": "filter",
              "result": {
                "fact_kind": "call_context",
                "id": "b0c03dfdb913d62fcd742b5778b9a7da636e7491546c0023680ca401eb82034a",
                "outcome": "approved_cleanup",
                "path": "python/lifecycle.py",
                "range": {
                  "end_column": 26,
                  "end_line": 15,
                  "start_column": 9,
                  "start_line": 15
                },
                "result_type": "python_hierarchy_fact",
                "root_id": "6e0307a75d6541490ba1b02e5007b421ce8b15ea0d1bf06f272daaa90d02da1e"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 26,
        "end_line": 15,
        "start_column": 9,
        "start_line": 15
      },
      "result_type": "python_hierarchy_fact",
      "root": {
        "end_line": 15,
        "fq_name": "python.lifecycle.CleanupLeaf",
        "kind": "class",
        "language": "python",
        "path": "python/lifecycle.py",
        "signature": "class CleanupLeaf(CleanupBase):",
        "start_line": 13
      },
      "root_declaration_id": "6e0307a75d6541490ba1b02e5007b421ce8b15ea0d1bf06f272daaa90d02da1e",
      "root_id": "6e0307a75d6541490ba1b02e5007b421ce8b15ea0d1bf06f272daaa90d02da1e",
      "target": {
        "end_line": 11,
        "fq_name": "python.lifecycle.CleanupBase.__del__",
        "kind": "function",
        "language": "python",
        "path": "python/lifecycle.py",
        "signature": "(self)",
        "start_line": 10
      },
      "target_id": "e3de44eda7ba07083c6a7d74f3ea7953801acb3ce815080c0f7404d2b0a4a5f8",
      "target_owner": {
        "end_line": 11,
        "fq_name": "python.lifecycle.CleanupBase",
        "kind": "class",
        "language": "python",
        "path": "python/lifecycle.py",
        "signature": "class CleanupBase:",
        "start_line": 9
      },
      "target_owner_id": "4041f54d24685e94db8894b61206f2c3c2e3f0a9fd64a1e7e9e1634d247b8707"
    }
  ],
  "truncated": false
}
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

## Resolve A Value Passed To A Call

`resolved_value` follows an actual expression to its exact declaration identity. This example keeps only the `object()` constructor passed to `receive` by proving Python's builtin identity, rather than comparing the source spelling.

<!-- code-query-case:resolved-value-argument:rql -->
```lisp
(resolved-value
  :resolves-to builtins.object
  :proof exact
  (call-argument :formal-name "value"
    (call-bindings
      (call-shape
        (language python
          (call :callee (name "receive")))))))
```

<!-- code-query-case:resolved-value-argument:json -->
```json
{
  "languages": ["python"],
  "match": {"kind": "call", "callee": {"name": "receive"}},
  "steps": [
    {"op": "call_shape"},
    {"op": "call_bindings"},
    {"op": "call_argument", "formal_name": "value"},
    {"op": "resolved_value", "resolves_to": {"stable": "builtins.object"}, "call_proof": "exact"}
  ]
}
```

<!-- code-query-case:resolved-value-argument:expected -->
```json
{
  "results": [
    {
      "actual_count": 1,
      "actual_index": 0,
      "argument_id": "362916b538b6ec5282d4e4681312bb4348ce9ef755a714ab84079e7e17e30b37",
      "binding_kind": "positional",
      "bound_count": 1,
      "conversion_reason": "unsupported_language",
      "conversion_status": "unknown",
      "coverage": "exhaustive",
      "declared_target_id": "decl:v1:e7fd53af94d0920970dc7b23fa4b48c59dba67e9c6935d38497a220e7f5a73d4",
      "dispatch_coverage": "open",
      "dispatch_outcome": "unknown",
      "dispatch_target_count": 0,
      "dispatch_targets_truncated": false,
      "formal_index": 0,
      "formal_layout_id": "19fbcec6f972b52bf6454519f96fd20ab36a71d75008384e289e698621273583",
      "formal_name": "value",
      "group_id": "11198aa6162f7ac33dd7d9f1f405ab95669f8e1abb17dc24dadfd67d19208827",
      "id": "0ff9e4bd5916fba9ba2b0a3362ccf3d31bb63ed4ad237a26e82cd9deb5bfad28",
      "language": "python",
      "mapping": "exact",
      "path": "python/app.py",
      "provenance": [
        {
          "seed": {
            "end_line": 21,
            "kind": "call",
            "path": "python/app.py",
            "result_type": "structural_match",
            "start_line": 21
          },
          "steps": [
            {
              "op": "call_shape",
              "result": {
                "call_kind": "function",
                "coverage": "exact",
                "id": "4b2cfd43b428339cd8711eb5b5e07533ff241cea5a4982662a32958f86c15ed7",
                "path": "python/app.py",
                "range": {
                  "end_column": 18,
                  "end_line": 21,
                  "start_column": 1,
                  "start_line": 21
                },
                "result_type": "call_shape",
                "site_id": "4b2cfd43b428339cd8711eb5b5e07533ff241cea5a4982662a32958f86c15ed7"
              }
            },
            {
              "op": "call_bindings",
              "result": {
                "binding_kind": "positional",
                "coverage": "exhaustive",
                "id": "0ff9e4bd5916fba9ba2b0a3362ccf3d31bb63ed4ad237a26e82cd9deb5bfad28",
                "mapping": "exact",
                "path": "python/app.py",
                "range": {
                  "end_column": 17,
                  "end_line": 21,
                  "start_column": 9,
                  "start_line": 21
                },
                "result_type": "call_binding",
                "site_id": "4b2cfd43b428339cd8711eb5b5e07533ff241cea5a4982662a32958f86c15ed7",
                "target_origin": "source"
              }
            },
            {
              "op": "call_argument",
              "result": {
                "binding_kind": "positional",
                "coverage": "exhaustive",
                "id": "0ff9e4bd5916fba9ba2b0a3362ccf3d31bb63ed4ad237a26e82cd9deb5bfad28",
                "mapping": "exact",
                "path": "python/app.py",
                "range": {
                  "end_column": 17,
                  "end_line": 21,
                  "start_column": 9,
                  "start_line": 21
                },
                "result_type": "call_binding",
                "site_id": "4b2cfd43b428339cd8711eb5b5e07533ff241cea5a4982662a32958f86c15ed7",
                "target_origin": "source"
              }
            },
            {
              "op": "resolved_value",
              "result": {
                "binding_kind": "positional",
                "coverage": "exhaustive",
                "id": "0ff9e4bd5916fba9ba2b0a3362ccf3d31bb63ed4ad237a26e82cd9deb5bfad28",
                "mapping": "exact",
                "path": "python/app.py",
                "range": {
                  "end_column": 17,
                  "end_line": 21,
                  "start_column": 9,
                  "start_line": 21
                },
                "result_type": "call_binding",
                "site_id": "4b2cfd43b428339cd8711eb5b5e07533ff241cea5a4982662a32958f86c15ed7",
                "target_origin": "source"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 17,
        "end_line": 21,
        "start_column": 9,
        "start_line": 21
      },
      "result_type": "call_binding",
      "selector_exact": true,
      "selector_proof": "derived",
      "signature_id": "19fbcec6f972b52bf6454519f96fd20ab36a71d75008384e289e698621273583",
      "site_ast_id": "51198bf617402caa98cd61bd6ae3a79c2f2392d82ece2c57a2588e9a6cfb827a",
      "site_id": "4b2cfd43b428339cd8711eb5b5e07533ff241cea5a4982662a32958f86c15ed7",
      "target": {
        "end_line": 19,
        "fq_name": "python.app.receive",
        "kind": "function",
        "language": "python",
        "path": "python/app.py",
        "signature": "(value)",
        "start_line": 18
      },
      "target_origin": "source",
      "terminal": false
    }
  ],
  "truncated": false
}
```

## Compare Overridden Method Signatures

`python_override_signatures` joins py01's C3-selected override with the persisted signature rows on each side. The witness keeps each signature ID and ordinal, coverage, and required, total, and repeated positional arity. Compare `source_required_arity` with `target_required_arity` in the returned row to find overrides that change the positional call contract.

<!-- code-query-fixture:python/overrides.py -->
```python
class Base:
    def process(self, value):
        return value

class Derived(Base):
    def process(self, value, label):
        return value, label
```

<!-- code-query-case:override-signature-mismatch:rql -->
```lisp
(python-override-signatures
  (enclosing-decl
    (language python
      (inside (class :name "Derived") (method :name "process")))))
```

<!-- code-query-case:override-signature-mismatch:json -->
```json
{
  "languages": ["python"],
  "match": {"kind": "method", "name": "process"},
  "inside": {"kind": "class", "name": "Derived"},
  "steps": [
    {"op": "enclosing_decl"},
    {"op": "python_override_signatures"}
  ]
}
```

<!-- code-query-case:override-signature-mismatch:expected -->
```json
{
  "results": [
    {
      "coverage": "complete",
      "declaration": {
        "end_line": 7,
        "fq_name": "python.overrides.Derived.process",
        "kind": "function",
        "language": "python",
        "path": "python/overrides.py",
        "signature": "(self, value, label)",
        "start_line": 6
      },
      "declaration_id": "1fd391239727cdc055fdc593653c4bcda644378fdf0df59ff97377c52e2b0b69",
      "fact_kind": "override_signature",
      "id": "fcf4ef6402338d9e0c0bc1ad911a7c803d8062132f310020125b64b0a55d5adb",
      "language": "python",
      "member_name": "process",
      "mro_rank": 1,
      "outcome": "overrides",
      "owner": {
        "end_line": 7,
        "fq_name": "python.overrides.Derived",
        "kind": "class",
        "language": "python",
        "path": "python/overrides.py",
        "signature": "class Derived(Base):",
        "start_line": 5
      },
      "owner_id": "123a88aaa1b39b062841595bbcf747435aa529cd920f7d35803d554ce6fe6eee",
      "path": "python/overrides.py",
      "provenance": [
        {
          "seed": {
            "end_line": 7,
            "kind": "method",
            "path": "python/overrides.py",
            "result_type": "structural_match",
            "start_line": 6
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 7,
                "fq_name": "python.overrides.Derived.process",
                "kind": "method",
                "path": "python/overrides.py",
                "result_type": "declaration",
                "start_line": 6
              }
            },
            {
              "op": "python_override_signatures",
              "result": {
                "fact_kind": "override_signature",
                "id": "fcf4ef6402338d9e0c0bc1ad911a7c803d8062132f310020125b64b0a55d5adb",
                "outcome": "overrides",
                "path": "python/overrides.py",
                "range": {
                  "end_column": 28,
                  "end_line": 7,
                  "start_column": 5,
                  "start_line": 6
                },
                "result_type": "python_hierarchy_fact",
                "root_id": "1fd391239727cdc055fdc593653c4bcda644378fdf0df59ff97377c52e2b0b69"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 28,
        "end_line": 7,
        "start_column": 5,
        "start_line": 6
      },
      "result_type": "python_hierarchy_fact",
      "root": {
        "end_line": 7,
        "fq_name": "python.overrides.Derived.process",
        "kind": "function",
        "language": "python",
        "path": "python/overrides.py",
        "signature": "(self, value, label)",
        "start_line": 6
      },
      "root_declaration_id": "1fd391239727cdc055fdc593653c4bcda644378fdf0df59ff97377c52e2b0b69",
      "root_id": "1fd391239727cdc055fdc593653c4bcda644378fdf0df59ff97377c52e2b0b69",
      "source_repeated_arity": false,
      "source_required_arity": 3,
      "source_signature_coverage": "exact",
      "source_signature_id": "e394fb4d8cd482c0cc7b19f6b95a0344615a2e67d2eb855fa181f8322ae2bbdb",
      "source_signature_ordinal": 0,
      "source_total_arity": 3,
      "target": {
        "end_line": 3,
        "fq_name": "python.overrides.Base.process",
        "kind": "function",
        "language": "python",
        "path": "python/overrides.py",
        "signature": "(self, value)",
        "start_line": 2
      },
      "target_id": "c0c1a5bc8aed93306859722983e3840a684fbd4d9fdddf04cfa7f9a3dda2e1bc",
      "target_owner": {
        "end_line": 3,
        "fq_name": "python.overrides.Base",
        "kind": "class",
        "language": "python",
        "path": "python/overrides.py",
        "signature": "class Base:",
        "start_line": 1
      },
      "target_owner_id": "95a64935d06ac908ead76844f68c6e02225de95c6dad1c30d54060b16976a68a",
      "target_repeated_arity": false,
      "target_required_arity": 2,
      "target_signature_coverage": "exact",
      "target_signature_id": "79f66533429d8bb02c5d4afd465ea0307f853664b9d630d6b26881c67e73368f",
      "target_signature_ordinal": 0,
      "target_total_arity": 2
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

These matches are syntactic. `receiver: "client"` checks the normalized receiver name; it does not prove the receiver's runtime type. When symbol identity matters, resolve the indexed declaration and use `scan_usages_by_reference`, or use `scan_usages_by_location` when you already know its declaration range.

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

## Select Parts Of A Parenthesized Implicit String

Python publishes the literal parts of an implicitly concatenated string in source order. The `parts` role and `parenthesized` property distinguish this expression from an ordinary string literal.

<!-- code-query-fixture:python/literals.py -->
```python
value = [("left" "right")]
```

<!-- code-query-case:parenthesized-parts:rql -->
```lisp
(language python
  (string_literal
    :parenthesized true
    :parts [(string_literal :capture "first") (string_literal :capture "second")]))
```

<!-- code-query-case:parenthesized-parts:json -->
```json
{
  "languages": ["python"],
  "match": {
    "kind": "string_literal",
    "parenthesized": true,
    "parts": [
      {"kind": "string_literal", "capture": "first"},
      {"kind": "string_literal", "capture": "second"}
    ]
  }
}
```

## Match A Decoded Value In A Python List

The Python adapter records ordinary string literal values after escape decoding. `list_literal` keeps list membership separate from dictionaries and sets, so this query selects the middleware string by its value and its direct `elements` role.

<!-- code-query-fixture:python/csrf.py -->
```python
MIDDLEWARE = ["\x64jango.middleware.csrf.CsrfViewMiddleware"]
```

<!-- code-query-case:decoded-list-value:rql -->
```lisp
(language python
  (list_literal
    :elements [(string_literal
      :string-value "django.middleware.csrf.CsrfViewMiddleware"
      :capture "middleware")]))
```

<!-- code-query-case:decoded-list-value:json -->
```json
{
  "languages": ["python"],
  "match": {
    "kind": "list_literal",
    "elements": [
      {
        "kind": "string_literal",
        "string_value": "django.middleware.csrf.CsrfViewMiddleware",
        "capture": "middleware"
      }
    ]
  }
}
```

<!-- code-query-case:decoded-list-value:expected -->
```json
{
  "results": [
    {
      "result_type": "structural_match",
      "path": "python/csrf.py",
      "language": "python",
      "kind": "list_literal",
      "start_line": 1,
      "end_line": 1,
      "text": "[\"\\x64jango.middleware.csrf.CsrfViewMiddleware\"]",
      "captures": [
        {
          "name": "middleware",
          "text": "\"\\x64jango.middleware.csrf.CsrfViewMiddleware\"",
          "start_line": 1
        }
      ],
      "enclosing_symbol": "python.csrf"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:parenthesized-parts:expected -->
```json
{
  "results": [
    {
      "captures": [
        {"name": "first", "start_line": 1, "text": "\"left\""},
        {"name": "second", "start_line": 1, "text": "\"right\""}
      ],
      "enclosing_symbol": "python.literals",
      "end_line": 1,
      "kind": "string_literal",
      "language": "python",
      "path": "python/literals.py",
      "result_type": "structural_match",
      "start_line": 1,
      "text": "\"left\" \"right\""
    },
    {
      "captures": [
        {"name": "first", "start_line": 76, "text": "\"parenthesized\""},
        {"name": "second", "start_line": 77, "text": "\"parts\""}
      ],
      "enclosing_symbol": "python.public-vocabulary.values",
      "end_line": 77,
      "kind": "string_literal",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 76,
      "text": "\"parenthesized\"…"
    }
  ],
  "truncated": false
}
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

## Compare Operand Identity

Python comparison steps can narrow comparison rows using the lexical binding identities already recorded by the analyzer. `identical-operands` selects a repeated bound name or a static attribute path with the same root binding. `python-missing-self` finds the same bare name compared in a method when the class also uses that name through `self`.

<!-- code-query-fixture:python/identity.py -->
```python
class Record:
    def same_value(self, value):
        return value == value

    def same_field(self):
        return self.value == self.value
```

<!-- code-query-fixture:python/missing-self.py -->
```python
class Record:
    def check(self):
        return value == value

    def read_value(self):
        return self.value
```

<!-- code-query-case:identical-operands:rql -->
```lisp
(where "python/identity.py"
  (identical-operands (language python (comparison))))
```

<!-- code-query-case:identical-operands:json -->
```json
{
  "where": ["python/identity.py"],
  "languages": ["python"],
  "match": {"kind": "comparison"},
  "steps": [{"op": "identical_operands"}]
}
```

<!-- code-query-case:identical-operands:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "python.identity.Record.same_value",
      "end_line": 3,
      "kind": "comparison",
      "language": "python",
      "path": "python/identity.py",
      "provenance": [
        {
          "seed": {
            "end_line": 3,
            "kind": "comparison",
            "path": "python/identity.py",
            "result_type": "structural_match",
            "start_line": 3
          },
          "steps": [
            {
              "op": "identical_operands",
              "result": {
                "end_line": 3,
                "kind": "comparison",
                "path": "python/identity.py",
                "result_type": "structural_match",
                "start_line": 3
              }
            }
          ]
        }
      ],
      "result_type": "structural_match",
      "start_line": 3,
      "text": "value == value"
    },
    {
      "enclosing_symbol": "python.identity.Record.same_field",
      "end_line": 6,
      "kind": "comparison",
      "language": "python",
      "path": "python/identity.py",
      "provenance": [
        {
          "seed": {
            "end_line": 6,
            "kind": "comparison",
            "path": "python/identity.py",
            "result_type": "structural_match",
            "start_line": 6
          },
          "steps": [
            {
              "op": "identical_operands",
              "result": {
                "end_line": 6,
                "kind": "comparison",
                "path": "python/identity.py",
                "result_type": "structural_match",
                "start_line": 6
              }
            }
          ]
        }
      ],
      "result_type": "structural_match",
      "start_line": 6,
      "text": "self.value == self.value"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:missing-self:rql -->
```lisp
(where "python/missing-self.py"
  (python-missing-self (language python (comparison))))
```

<!-- code-query-case:missing-self:json -->
```json
{
  "where": ["python/missing-self.py"],
  "languages": ["python"],
  "match": {"kind": "comparison"},
  "steps": [{"op": "python_missing_self"}]
}
```

<!-- code-query-case:missing-self:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "python.missing-self.Record.check",
      "end_line": 3,
      "kind": "comparison",
      "language": "python",
      "path": "python/missing-self.py",
      "provenance": [
        {
          "seed": {
            "end_line": 3,
            "kind": "comparison",
            "path": "python/missing-self.py",
            "result_type": "structural_match",
            "start_line": 3
          },
          "steps": [
            {
              "op": "python_missing_self",
              "result": {
                "end_line": 3,
                "kind": "comparison",
                "path": "python/missing-self.py",
                "result_type": "structural_match",
                "start_line": 3
              }
            }
          ]
        }
      ],
      "result_type": "structural_match",
      "start_line": 3,
      "text": "value == value"
    }
  ],
  "truncated": false
}
```

## Query Syntax, Python Facts, And Regular Expressions

This fixture gives the newly published Python syntax kinds and semantic relations positive examples. The syntax-error fixture is intentionally incomplete so parser recovery contributes a real `syntax_error` node.

<!-- code-query-fixture:python/public-vocabulary.py -->
```python
import re
import query_helper
from query_helper import chosen

# Keep comments available as queryable nodes.
def shapes(value):
    enabled = True
    pair = (value, 2)
    incremented = value + 1
    equal = value == 1
    chained = 0 < value < 3
    assert value, "value is required"
    return pair

def maybe(value):
    if value:
        return value
    return None

def tuple_return(flag):
    if flag:
        return (1, 2)
    return (1, 2, 3)

def target(value):
    return value

forward = lambda item: target(item)

def consume(value):
    result = target(value)
    return result

class Parent:
    def describe(self):
        return "parent"

class Child(Parent):
    def describe(self):
        return "child"

re.compile(r"^([A-Z]+|item).*?$")
re.compile("(www|beta).example.com/")
re.compile(r"[A-z]")
re.compile(r"<script.*?>.*?</script>")
re.compile(r"^_(__|.)+_$")
re.compile(r"[\b]")
re.compile(r"[aa]")
re.compile(r"(P<name>[A-Za-z]+)")
re.compile(r"a^b")
re.compile(r"a$b")
re.compile(pattern)

def yielded():
    yield "value"

import unittest

class TestContext(unittest.TestCase):
    def helper(self):
        assert "a constant in a test scope"

if ready:
    pass
elif other:
    pass
else:
    assert True

def assign_tuple(flag):
    first, second, third = tuple_return(flag)

values = [
    "first"
    "second",
    ("parenthesized"
     "parts"),
    "neighbor",
]
```

<!-- code-query-fixture:python/query_helper.py -->
```python
def chosen(value):
    return value
```

<!-- code-query-fixture:cycle_a.py -->
```python
import cycle_b
```

<!-- code-query-fixture:cycle_b.py -->
```python
import cycle_a
```

The kind queries below each return a concrete match. The operator and test roles constrain the exact syntax edge selected by the Python adapter.

<!-- code-query-case:public-boolean_literal:rql -->
```lisp
(where "python/public-vocabulary.py"
  (limit 1
    (language python (boolean_literal))))
```

<!-- code-query-case:public-boolean_literal:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"boolean_literal"},"limit":1}
```

<!-- code-query-case:public-boolean_literal:expected -->
```json
{
  "diagnostics": [
    {
      "code": "result_limit_reached",
      "impact": "incomplete",
      "language": "workspace",
      "message": "query_code reached the query limit of 1 and returned the first 1 results; results are ordered by project-relative path; refine the query with where, languages, exact names, or a narrower pattern"
    }
  ],
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary.shapes",
      "end_line": 7,
      "kind": "boolean_literal",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 7,
      "text": "True"
    }
  ],
  "truncated": true
}
```

<!-- code-query-case:public-yield:rql -->
```lisp
(where "python/public-vocabulary.py"
  (language python (yield)))
```

<!-- code-query-case:public-yield:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"yield"}}
```

<!-- code-query-case:public-yield:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary.yielded",
      "end_line": 55,
      "kind": "yield",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 55,
      "text": "yield \"value\""
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:public-tuple_literal:rql -->
```lisp
(where "python/public-vocabulary.py"
  (limit 1
    (language python (tuple_literal))))
```

<!-- code-query-case:public-tuple_literal:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"tuple_literal"},"limit":1}
```

<!-- code-query-case:public-tuple_literal:expected -->
```json
{
  "diagnostics": [
    {
      "code": "result_limit_reached",
      "impact": "incomplete",
      "language": "workspace",
      "message": "query_code reached the query limit of 1 and returned the first 1 results; results are ordered by project-relative path; refine the query with where, languages, exact names, or a narrower pattern"
    }
  ],
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary.shapes",
      "end_line": 8,
      "kind": "tuple_literal",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 8,
      "text": "(value, 2)"
    }
  ],
  "truncated": true
}
```

<!-- code-query-case:public-comment:rql -->
```lisp
(where "python/public-vocabulary.py"
  (limit 1
    (language python (comment))))
```

<!-- code-query-case:public-comment:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"comment"},"limit":1}
```

<!-- code-query-case:public-comment:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary",
      "end_line": 5,
      "kind": "comment",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 5,
      "text": "# Keep comments available as queryable nodes."
    }
  ],
  "truncated": false
}
```

To select commented-out code, wrap a Python `comment` match with
`python-commented-out-code`. It returns one `python_rule_fact` row per block;
the row range covers the block, and `comment_block_text` plus
`comment_block_lines` preserve its source. Example-heavy blocks and comments
that look like documentation, doctests, URLs, paths, filler, or trailing
comments are excluded.

```lisp
(python-commented-out-code (language python (comment)))
```

```json
{"languages":["python"],"match":{"kind":"comment"},"steps":[{"op":"python_commented_out_code"}]}
```

<!-- code-query-case:public-binary_expression:rql -->
```lisp
(where "python/public-vocabulary.py"
  (limit 1
    (language python (binary_expression))))
```

<!-- code-query-case:public-binary_expression:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"binary_expression"},"limit":1}
```

<!-- code-query-case:public-binary_expression:expected -->
```json
{
  "diagnostics": [
    {
      "code": "result_limit_reached",
      "impact": "incomplete",
      "language": "workspace",
      "message": "query_code reached the query limit of 1 and returned the first 1 results; results are ordered by project-relative path; refine the query with where, languages, exact names, or a narrower pattern"
    }
  ],
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary.shapes",
      "end_line": 9,
      "kind": "binary_expression",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 9,
      "text": "value + 1"
    }
  ],
  "truncated": true
}
```

<!-- code-query-case:public-comparison:rql -->
```lisp
(where "python/public-vocabulary.py"
  (limit 1
    (language python (comparison))))
```

<!-- code-query-case:public-comparison:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"comparison"},"limit":1}
```

<!-- code-query-case:public-comparison:expected -->
```json
{
  "diagnostics": [
    {
      "code": "result_limit_reached",
      "impact": "incomplete",
      "language": "workspace",
      "message": "query_code reached the query limit of 1 and returned the first 1 results; results are ordered by project-relative path; refine the query with where, languages, exact names, or a narrower pattern"
    }
  ],
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary.shapes",
      "end_line": 10,
      "kind": "comparison",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 10,
      "text": "value == 1"
    }
  ],
  "truncated": true
}
```

<!-- code-query-case:public-comparison_chain:rql -->
```lisp
(where "python/public-vocabulary.py"
  (limit 1
    (language python (comparison_chain))))
```

<!-- code-query-case:public-comparison_chain:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"comparison_chain"},"limit":1}
```

<!-- code-query-case:public-comparison_chain:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary.shapes",
      "end_line": 11,
      "kind": "comparison_chain",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 11,
      "text": "0 < value < 3"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:public-assertion:rql -->
```lisp
(where "python/public-vocabulary.py"
  (limit 1
    (language python (assertion))))
```

<!-- code-query-case:public-assertion:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"assertion"},"limit":1}
```

<!-- code-query-case:public-assertion:expected -->
```json
{
  "diagnostics": [
    {
      "code": "result_limit_reached",
      "impact": "incomplete",
      "language": "workspace",
      "message": "query_code reached the query limit of 1 and returned the first 1 results; results are ordered by project-relative path; refine the query with where, languages, exact names, or a narrower pattern"
    }
  ],
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary.shapes",
      "end_line": 12,
      "kind": "assertion",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 12,
      "text": "assert value, \"value is required\""
    }
  ],
  "truncated": true
}
```

<!-- code-query-case:public-regex_pattern:rql -->
```lisp
(where "python/public-vocabulary.py"
  (limit 1
    (language python (regex_pattern))))
```

<!-- code-query-case:public-regex_pattern:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"regex_pattern"},"limit":1}
```

<!-- code-query-case:public-regex_pattern:expected -->
```json
{
  "diagnostics": [
    {
      "code": "result_limit_reached",
      "impact": "incomplete",
      "language": "workspace",
      "message": "query_code reached the query limit of 1 and returned the first 1 results; results are ordered by project-relative path; refine the query with where, languages, exact names, or a narrower pattern"
    }
  ],
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary",
      "end_line": 42,
      "kind": "regex_pattern",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 42,
      "text": "^([A-Z]+|item).*?$"
    }
  ],
  "truncated": true
}
```

<!-- code-query-case:public-regex_sequence:rql -->
```lisp
(where "python/public-vocabulary.py"
  (limit 1
    (language python (regex_sequence))))
```

<!-- code-query-case:public-regex_sequence:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"regex_sequence"},"limit":1}
```

<!-- code-query-case:public-regex_sequence:expected -->
```json
{
  "diagnostics": [
    {
      "code": "result_limit_reached",
      "impact": "incomplete",
      "language": "workspace",
      "message": "query_code reached the query limit of 1 and returned the first 1 results; results are ordered by project-relative path; refine the query with where, languages, exact names, or a narrower pattern"
    }
  ],
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary",
      "end_line": 42,
      "kind": "regex_sequence",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 42,
      "text": "^([A-Z]+|item).*?$"
    }
  ],
  "truncated": true
}
```

<!-- code-query-case:public-regex_group:rql -->
```lisp
(where "python/public-vocabulary.py"
  (limit 1
    (language python (regex_group))))
```

<!-- code-query-case:public-regex_group:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"regex_group"},"limit":1}
```

<!-- code-query-case:public-regex_group:expected -->
```json
{
  "diagnostics": [
    {
      "code": "result_limit_reached",
      "impact": "incomplete",
      "language": "workspace",
      "message": "query_code reached the query limit of 1 and returned the first 1 results; results are ordered by project-relative path; refine the query with where, languages, exact names, or a narrower pattern"
    }
  ],
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary",
      "end_line": 42,
      "kind": "regex_group",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 42,
      "text": "([A-Z]+|item)"
    }
  ],
  "truncated": true
}
```

<!-- code-query-case:public-regex_alternation:rql -->
```lisp
(where "python/public-vocabulary.py"
  (limit 1
    (language python (regex_alternation))))
```

<!-- code-query-case:public-regex_alternation:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"regex_alternation"},"limit":1}
```

<!-- code-query-case:public-regex_alternation:expected -->
```json
{
  "diagnostics": [
    {
      "code": "result_limit_reached",
      "impact": "incomplete",
      "language": "workspace",
      "message": "query_code reached the query limit of 1 and returned the first 1 results; results are ordered by project-relative path; refine the query with where, languages, exact names, or a narrower pattern"
    }
  ],
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary",
      "end_line": 42,
      "kind": "regex_alternation",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 42,
      "text": "|"
    }
  ],
  "truncated": true
}
```

<!-- code-query-case:public-regex_character_class:rql -->
```lisp
(where "python/public-vocabulary.py"
  (limit 1
    (language python (regex_character_class))))
```

<!-- code-query-case:public-regex_character_class:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"regex_character_class"},"limit":1}
```

<!-- code-query-case:public-regex_character_class:expected -->
```json
{
  "diagnostics": [
    {
      "code": "result_limit_reached",
      "impact": "incomplete",
      "language": "workspace",
      "message": "query_code reached the query limit of 1 and returned the first 1 results; results are ordered by project-relative path; refine the query with where, languages, exact names, or a narrower pattern"
    }
  ],
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary",
      "end_line": 42,
      "kind": "regex_character_class",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 42,
      "text": "[A-Z]+"
    }
  ],
  "truncated": true
}
```

<!-- code-query-case:public-regex_character_range:rql -->
```lisp
(where "python/public-vocabulary.py"
  (limit 1
    (language python (regex_character_range))))
```

<!-- code-query-case:public-regex_character_range:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"regex_character_range"},"limit":1}
```

<!-- code-query-case:public-regex_character_range:expected -->
```json
{
  "diagnostics": [
    {
      "code": "result_limit_reached",
      "impact": "incomplete",
      "language": "workspace",
      "message": "query_code reached the query limit of 1 and returned the first 1 results; results are ordered by project-relative path; refine the query with where, languages, exact names, or a narrower pattern"
    }
  ],
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary",
      "end_line": 42,
      "kind": "regex_character_range",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 42,
      "text": "A-Z"
    }
  ],
  "truncated": true
}
```

<!-- code-query-case:public-regex_quantifier:rql -->
```lisp
(where "python/public-vocabulary.py"
  (limit 1
    (language python (regex_quantifier))))
```

<!-- code-query-case:public-regex_quantifier:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"regex_quantifier"},"limit":1}
```

<!-- code-query-case:public-regex_quantifier:expected -->
```json
{
  "diagnostics": [
    {
      "code": "result_limit_reached",
      "impact": "incomplete",
      "language": "workspace",
      "message": "query_code reached the query limit of 1 and returned the first 1 results; results are ordered by project-relative path; refine the query with where, languages, exact names, or a narrower pattern"
    }
  ],
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary",
      "end_line": 42,
      "kind": "regex_quantifier",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 42,
      "text": "+"
    }
  ],
  "truncated": true
}
```

<!-- code-query-case:public-regex_anchor:rql -->
```lisp
(where "python/public-vocabulary.py"
  (limit 1
    (language python (regex_anchor))))
```

<!-- code-query-case:public-regex_anchor:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"regex_anchor"},"limit":1}
```

<!-- code-query-case:public-regex_anchor:expected -->
```json
{
  "diagnostics": [
    {
      "code": "result_limit_reached",
      "impact": "incomplete",
      "language": "workspace",
      "message": "query_code reached the query limit of 1 and returned the first 1 results; results are ordered by project-relative path; refine the query with where, languages, exact names, or a narrower pattern"
    }
  ],
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary",
      "end_line": 42,
      "kind": "regex_anchor",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 42,
      "text": "^"
    }
  ],
  "truncated": true
}
```

<!-- code-query-case:public-regex_escape:rql -->
```lisp
(where "python/public-vocabulary.py"
  (limit 1
    (language python (regex_escape))))
```

<!-- code-query-case:public-regex_escape:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"regex_escape"},"limit":1}
```

<!-- code-query-case:public-regex_escape:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary",
      "end_line": 47,
      "kind": "regex_escape",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 47,
      "text": "\\b"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:public-regex_literal:rql -->
```lisp
(where "python/public-vocabulary.py"
  (limit 1
    (language python (regex_literal))))
```

<!-- code-query-case:public-regex_literal:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"regex_literal"},"limit":1}
```

<!-- code-query-case:public-regex_literal:expected -->
```json
{
  "diagnostics": [
    {
      "code": "result_limit_reached",
      "impact": "incomplete",
      "language": "workspace",
      "message": "query_code reached the query limit of 1 and returned the first 1 results; results are ordered by project-relative path; refine the query with where, languages, exact names, or a narrower pattern"
    }
  ],
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary",
      "end_line": 42,
      "kind": "regex_literal",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 42,
      "text": "i"
    }
  ],
  "truncated": true
}
```

<!-- code-query-case:public-regex_wildcard:rql -->
```lisp
(where "python/public-vocabulary.py"
  (limit 1
    (language python (regex_wildcard))))
```

<!-- code-query-case:public-regex_wildcard:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"regex_wildcard"},"limit":1}
```

<!-- code-query-case:public-regex_wildcard:expected -->
```json
{
  "diagnostics": [
    {
      "code": "result_limit_reached",
      "impact": "incomplete",
      "language": "workspace",
      "message": "query_code reached the query limit of 1 and returned the first 1 results; results are ordered by project-relative path; refine the query with where, languages, exact names, or a narrower pattern"
    }
  ],
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary",
      "end_line": 42,
      "kind": "regex_wildcard",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 42,
      "text": ".*?"
    }
  ],
  "truncated": true
}
```

<!-- code-query-case:public-regex_risk_hostname:rql -->
```lisp
(where "python/public-vocabulary.py"
  (limit 1
    (language python (regex_risk_hostname))))
```

<!-- code-query-case:public-regex_risk_hostname:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"regex_risk_hostname"},"limit":1}
```

<!-- code-query-case:public-regex_risk_hostname:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary",
      "end_line": 43,
      "kind": "regex_risk_hostname",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 43,
      "text": "."
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:public-regex_risk_range:rql -->
```lisp
(where "python/public-vocabulary.py"
  (limit 1
    (language python (regex_risk_range))))
```

<!-- code-query-case:public-regex_risk_range:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"regex_risk_range"},"limit":1}
```

<!-- code-query-case:public-regex_risk_range:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary",
      "end_line": 44,
      "kind": "regex_risk_range",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 44,
      "text": "A-z"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:public-regex_risk_bad_tag:rql -->
```lisp
(where "python/public-vocabulary.py"
  (limit 1
    (language python (regex_risk_bad_tag))))
```

<!-- code-query-case:public-regex_risk_bad_tag:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"regex_risk_bad_tag"},"limit":1}
```

<!-- code-query-case:public-regex_risk_bad_tag:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary",
      "end_line": 45,
      "kind": "regex_risk_bad_tag",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 45,
      "text": "<script.*?>.*?</script>"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:public-regex_risk_exponential:rql -->
```lisp
(where "python/public-vocabulary.py"
  (limit 1
    (language python (regex_risk_exponential))))
```

<!-- code-query-case:public-regex_risk_exponential:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"regex_risk_exponential"},"limit":1}
```

<!-- code-query-case:public-regex_risk_exponential:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary",
      "end_line": 46,
      "kind": "regex_risk_exponential",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 46,
      "text": "+"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:public-regex_incomplete:rql -->
```lisp
(where "python/public-vocabulary.py"
  (limit 1
    (language python (regex_incomplete))))
```

<!-- code-query-case:public-regex_incomplete:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"regex_incomplete"},"limit":1}
```

<!-- code-query-case:public-regex_incomplete:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary",
      "end_line": 52,
      "kind": "regex_incomplete",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 52,
      "text": "pattern"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:public-regex_risk_backspace_escape:rql -->
```lisp
(where "python/public-vocabulary.py"
  (limit 1
    (language python (regex_risk_backspace_escape))))
```

<!-- code-query-case:public-regex_risk_backspace_escape:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"regex_risk_backspace_escape"},"limit":1}
```

<!-- code-query-case:public-regex_risk_backspace_escape:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary",
      "end_line": 47,
      "kind": "regex_risk_backspace_escape",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 47,
      "text": "\\b"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:public-regex_risk_duplicate_class_character:rql -->
```lisp
(where "python/public-vocabulary.py"
  (limit 1
    (language python (regex_risk_duplicate_class_character))))
```

<!-- code-query-case:public-regex_risk_duplicate_class_character:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"regex_risk_duplicate_class_character"},"limit":1}
```

<!-- code-query-case:public-regex_risk_duplicate_class_character:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary",
      "end_line": 48,
      "kind": "regex_risk_duplicate_class_character",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 48,
      "text": "a"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:public-regex_risk_unmatchable_caret:rql -->
```lisp
(where "python/public-vocabulary.py"
  (limit 1
    (language python (regex_risk_unmatchable_caret))))
```

<!-- code-query-case:public-regex_risk_unmatchable_caret:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"regex_risk_unmatchable_caret"},"limit":1}
```

<!-- code-query-case:public-regex_risk_unmatchable_caret:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary",
      "end_line": 50,
      "kind": "regex_risk_unmatchable_caret",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 50,
      "text": "^"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:public-regex_risk_unmatchable_dollar:rql -->
```lisp
(where "python/public-vocabulary.py"
  (limit 1
    (language python (regex_risk_unmatchable_dollar))))
```

<!-- code-query-case:public-regex_risk_unmatchable_dollar:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"regex_risk_unmatchable_dollar"},"limit":1}
```

<!-- code-query-case:public-regex_risk_unmatchable_dollar:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary",
      "end_line": 51,
      "kind": "regex_risk_unmatchable_dollar",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 51,
      "text": "$"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:public-regex_risk_incomplete_special_group:rql -->
```lisp
(where "python/public-vocabulary.py"
  (limit 1
    (language python (regex_risk_incomplete_special_group))))
```

<!-- code-query-case:public-regex_risk_incomplete_special_group:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"regex_risk_incomplete_special_group"},"limit":1}
```

<!-- code-query-case:public-regex_risk_incomplete_special_group:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary",
      "end_line": 49,
      "kind": "regex_risk_incomplete_special_group",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 49,
      "text": "(P<name>"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:public-operator-role:rql -->
```lisp
(where "python/public-vocabulary.py"
  (language python (comparison :operator (text/regex "^==$"))))
```

<!-- code-query-case:public-operator-role:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"comparison","operator":{"text":{"regex":"^==$"}}}}
```

<!-- code-query-case:public-operator-role:expected -->
```json
{
  "diagnostics": [
    {
      "code": "unsupported_structural_feature",
      "impact": "incomplete",
      "language": "python",
      "message": "Python comparison chains do not expose singular left/right/operator roles required by this query in python/public-vocabulary.py at byte ranges [(234, 247)]"
    }
  ],
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary.shapes",
      "end_line": 10,
      "kind": "comparison",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 10,
      "text": "value == 1"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:public-test-role:rql -->
```lisp
(where "python/public-vocabulary.py"
  (language python (assertion :test (identifier :name "value"))))
```

<!-- code-query-case:public-test-role:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"assertion","test":{"kind":"identifier","name":"value"}}}
```

<!-- code-query-case:public-test-role:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary.shapes",
      "end_line": 12,
      "kind": "assertion",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 12,
      "text": "assert value, \"value is required\""
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:public-parameter:rql -->
```lisp
(where "python/public-vocabulary.py"
  (language python (parameter :name "value")))
```

<!-- code-query-case:public-parameter:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"parameter","name":"value"}}
```

<!-- code-query-case:public-parameter:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary.shapes",
      "end_line": 6,
      "kind": "parameter",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 6,
      "text": "value"
    },
    {
      "enclosing_symbol": "python.public-vocabulary.maybe",
      "end_line": 15,
      "kind": "parameter",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 15,
      "text": "value"
    },
    {
      "enclosing_symbol": "python.public-vocabulary.target",
      "end_line": 25,
      "kind": "parameter",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 25,
      "text": "value"
    },
    {
      "enclosing_symbol": "python.public-vocabulary.consume",
      "end_line": 30,
      "kind": "parameter",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "result_type": "structural_match",
      "start_line": 30,
      "text": "value"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:python-procedure-return-profile:rql -->
```lisp
(procedure-return-profile (procedure-of (language python (function :name "maybe"))))
```

<!-- code-query-case:python-procedure-return-profile:json -->
```json
{"languages":["python"],"match":{"kind":"function","name":"maybe"},"steps":[{"op":"procedure_of"},{"op":"procedure_return_profile"}]}
```

<!-- code-query-case:python-procedure-return-profile:expected -->
```json
{
  "results": [
    {
      "completeness": "complete",
      "explicit_return_statements": 2,
      "explicit_value_returns": 1,
      "fallthrough_none_returns": 0,
      "id": "4e03e82e5e265ea2932f1cc3e71dfe00767cde06adba8524c5c64c0254708488",
      "is_async": false,
      "is_generator": false,
      "language": "python",
      "mixed_returns": false,
      "none_returns": 1,
      "outcome": "uniform_returns",
      "owner_id": "f700b2164b22b0689c54b1d1a1f8a195b242c567262d84ec799ce081a6410072",
      "path": "python/public-vocabulary.py",
      "proof": "proven",
      "provenance": [
        {
          "seed": {
            "end_line": 18,
            "kind": "function",
            "path": "python/public-vocabulary.py",
            "result_type": "structural_match",
            "start_line": 15
          },
          "steps": [
            {
              "op": "procedure_of",
              "result": {
                "id": "f700b2164b22b0689c54b1d1a1f8a195b242c567262d84ec799ce081a6410072",
                "path": "python/public-vocabulary.py",
                "procedure_kind": "function",
                "range": {
                  "end_column": 16,
                  "end_line": 18,
                  "start_column": 1,
                  "start_line": 15
                },
                "result_type": "procedure"
              }
            },
            {
              "op": "procedure_return_profile",
              "result": {
                "id": "4e03e82e5e265ea2932f1cc3e71dfe00767cde06adba8524c5c64c0254708488",
                "outcome": "uniform_returns",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 16,
                  "end_line": 18,
                  "start_column": 1,
                  "start_line": 15
                },
                "relation": "procedure_return_profile",
                "result_type": "python_rule_fact"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 16,
        "end_line": 18,
        "start_column": 1,
        "start_line": 15
      },
      "relation": "procedure_return_profile",
      "result_type": "python_rule_fact",
      "return_contract": "may_return_value"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:python-call-result-use:rql -->
```lisp
(call-result-use (call-shape (language python (call :callee (name "target")))))
```

<!-- code-query-case:python-call-result-use:json -->
```json
{"languages":["python"],"match":{"kind":"call","callee":{"name":"target"}},"steps":[{"op":"call_shape"},{"op":"call_result_use"}]}
```

<!-- code-query-case:python-call-result-use:expected -->
```json
{
  "results": [
    {
      "completeness": "complete",
      "id": "1991e32bc4bd00c34510f79c2465c12b00421b4b6e19ff32713eae05860ddaef",
      "language": "python",
      "outcome": "consumed",
      "owner_id": null,
      "path": "python/public-vocabulary.py",
      "proof": "proven",
      "provenance": [
        {
          "seed": {
            "end_line": 28,
            "kind": "call",
            "path": "python/public-vocabulary.py",
            "result_type": "structural_match",
            "start_line": 28
          },
          "steps": [
            {
              "op": "call_shape",
              "result": {
                "call_kind": "function",
                "coverage": "exact",
                "id": "ac323aba1f00a398c63b8fc57b8426f849ad4f015179e2e97533ea2fd1010308",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 36,
                  "end_line": 28,
                  "start_column": 24,
                  "start_line": 28
                },
                "result_type": "call_shape",
                "site_id": "ac323aba1f00a398c63b8fc57b8426f849ad4f015179e2e97533ea2fd1010308"
              }
            },
            {
              "op": "call_result_use",
              "result": {
                "id": "1991e32bc4bd00c34510f79c2465c12b00421b4b6e19ff32713eae05860ddaef",
                "outcome": "consumed",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 36,
                  "end_line": 28,
                  "start_column": 24,
                  "start_line": 28
                },
                "relation": "call_result_use",
                "result_type": "python_rule_fact"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 36,
        "end_line": 28,
        "start_column": 24,
        "start_line": 28
      },
      "relation": "call_result_use",
      "result_type": "python_rule_fact",
      "result_use": "consumed",
      "return_contract": "may_return_value",
      "target_id": "ad62196126533ebe80c02c4238285b85da0a416c10a9b144d81207165915d0e9"
    },
    {
      "completeness": "complete",
      "id": "a5ff0a0977a3042502b60ae6d235555c923e578b47adf1dab86ab79c0aa19382",
      "language": "python",
      "outcome": "consumed",
      "owner_id": null,
      "path": "python/public-vocabulary.py",
      "proof": "proven",
      "provenance": [
        {
          "seed": {
            "end_line": 31,
            "kind": "call",
            "path": "python/public-vocabulary.py",
            "result_type": "structural_match",
            "start_line": 31
          },
          "steps": [
            {
              "op": "call_shape",
              "result": {
                "call_kind": "function",
                "coverage": "exact",
                "id": "413b1f28df2ce588a24a18d1b56a1e78382176920dcabbdacd9fa4d99fbd5a31",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 27,
                  "end_line": 31,
                  "start_column": 14,
                  "start_line": 31
                },
                "result_type": "call_shape",
                "site_id": "413b1f28df2ce588a24a18d1b56a1e78382176920dcabbdacd9fa4d99fbd5a31"
              }
            },
            {
              "op": "call_result_use",
              "result": {
                "id": "a5ff0a0977a3042502b60ae6d235555c923e578b47adf1dab86ab79c0aa19382",
                "outcome": "consumed",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 27,
                  "end_line": 31,
                  "start_column": 14,
                  "start_line": 31
                },
                "relation": "call_result_use",
                "result_type": "python_rule_fact"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 27,
        "end_line": 31,
        "start_column": 14,
        "start_line": 31
      },
      "relation": "call_result_use",
      "result_type": "python_rule_fact",
      "result_use": "consumed",
      "return_contract": "may_return_value",
      "target_id": "ad62196126533ebe80c02c4238285b85da0a416c10a9b144d81207165915d0e9"
    }
  ],
  "truncated": false
}
```

## Assertion Context

`python_assertion_context` attaches CodeQL-style tri-state test-scope and
terminal-elif metadata to the shared Python rule-fact row. It follows
unittest inheritance, pytest/nose imports, and the `test_*.py` filename rule;
unresolved unittest ancestry remains `unknown`.

<!-- code-query-case:python-assertion-context:rql -->
```lisp
(where "python/public-vocabulary.py"
  (python-assertion-context
    (language python (assertion))))
```

<!-- code-query-case:python-assertion-context:json -->
```json
{"where":["python/public-vocabulary.py"],"languages":["python"],"match":{"kind":"assertion"},"steps":[{"op":"python_assertion_context"}]}
```

<!-- code-query-case:python-assertion-context:expected -->
```json
{
  "results": [
    {
      "completeness": "complete",
      "id": "3f9c74dfb22c51dec89f497eefeeb1ec20d0614f2a36896933eeb4a65356c817",
      "language": "python",
      "outcome": "no_issue",
      "owner_id": null,
      "path": "python/public-vocabulary.py",
      "proof": "proven",
      "provenance": [
        {
          "seed": {
            "end_line": 12,
            "kind": "assertion",
            "path": "python/public-vocabulary.py",
            "result_type": "structural_match",
            "start_line": 12
          },
          "steps": [
            {
              "op": "python_assertion_context",
              "result": {
                "id": "3f9c74dfb22c51dec89f497eefeeb1ec20d0614f2a36896933eeb4a65356c817",
                "outcome": "no_issue",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 38,
                  "end_line": 12,
                  "start_column": 5,
                  "start_line": 12
                },
                "relation": "assertion_context",
                "result_type": "python_rule_fact"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 38,
        "end_line": 12,
        "start_column": 5,
        "start_line": 12
      },
      "relation": "assertion_context",
      "result_type": "python_rule_fact",
      "terminal_elif_else": "no",
      "test_scope": "no"
    },
    {
      "completeness": "complete",
      "id": "d6a994ba9c828710719bec8a7b43c75043788026e548124831758f0f4804e1da",
      "language": "python",
      "outcome": "no_issue",
      "owner_id": null,
      "path": "python/public-vocabulary.py",
      "proof": "proven",
      "provenance": [
        {
          "seed": {
            "end_line": 61,
            "kind": "assertion",
            "path": "python/public-vocabulary.py",
            "result_type": "structural_match",
            "start_line": 61
          },
          "steps": [
            {
              "op": "python_assertion_context",
              "result": {
                "id": "d6a994ba9c828710719bec8a7b43c75043788026e548124831758f0f4804e1da",
                "outcome": "no_issue",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 44,
                  "end_line": 61,
                  "start_column": 9,
                  "start_line": 61
                },
                "relation": "assertion_context",
                "result_type": "python_rule_fact"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 44,
        "end_line": 61,
        "start_column": 9,
        "start_line": 61
      },
      "relation": "assertion_context",
      "result_type": "python_rule_fact",
      "terminal_elif_else": "no",
      "test_scope": "yes"
    },
    {
      "completeness": "complete",
      "id": "7d7ced100183c6a00d89aec95b5ad987e2418c01a7615369f7a4a3d7c8a9bd99",
      "language": "python",
      "outcome": "no_issue",
      "owner_id": null,
      "path": "python/public-vocabulary.py",
      "proof": "proven",
      "provenance": [
        {
          "seed": {
            "end_line": 68,
            "kind": "assertion",
            "path": "python/public-vocabulary.py",
            "result_type": "structural_match",
            "start_line": 68
          },
          "steps": [
            {
              "op": "python_assertion_context",
              "result": {
                "id": "7d7ced100183c6a00d89aec95b5ad987e2418c01a7615369f7a4a3d7c8a9bd99",
                "outcome": "no_issue",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 16,
                  "end_line": 68,
                  "start_column": 5,
                  "start_line": 68
                },
                "relation": "assertion_context",
                "result_type": "python_rule_fact"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 16,
        "end_line": 68,
        "start_column": 5,
        "start_line": 68
      },
      "relation": "assertion_context",
      "result_type": "python_rule_fact",
      "terminal_elif_else": "yes",
      "test_scope": "no"
    }
  ],
  "truncated": false
}
```

## Tuple Assignment Arity

Tuple-return facts include a bounded, sorted array of distinct exact return
arities. `tuple_return_assignment` joins a directly resolved call to the
assignment's top-level target count and reports whether all proven tuple
returns match that count.

<!-- code-query-case:python-tuple-return-assignment:rql -->
```lisp
(filter :where ((assignment_target_count eq 3)
    (assignment_arity_match eq no)
    (tuple_return_arities eq [2 3])
    (proof eq proven) (completeness eq complete))
  (tuple-return-assignment
    (where "python/public-vocabulary.py"
      (language python (assignment)))))
```

<!-- code-query-case:python-tuple-return-assignment:json -->
```json
{
  "where": ["python/public-vocabulary.py"],
  "languages": ["python"],
  "match": {"kind": "assignment"},
  "steps": [
    {"op": "tuple_return_assignment"},
    {"op": "filter", "where": [
      {"field": "assignment_target_count", "op": "eq", "value": {"integer": 3}},
      {"field": "assignment_arity_match", "op": "eq", "value": {"enum": "no"}},
      {"field": "tuple_return_arities", "op": "eq", "value": {"integer_list": [2, 3]}},
      {"field": "proof", "op": "eq", "value": {"enum": "proven"}},
      {"field": "completeness", "op": "eq", "value": {"enum": "complete"}}
    ]}
  ]
}
```

<!-- code-query-case:python-tuple-return-assignment:expected -->
```json
{
  "results": [
    {
      "annotated": false,
      "assignment_arity_match": "no",
      "assignment_target_count": 3,
      "completeness": "complete",
      "distinct_tuple_arities": 2,
      "id": "66673978755ea6becfedc6c506d290133240d47bbfdb713c0b0c3fb22ef8ed2d",
      "is_async": false,
      "is_generator": false,
      "language": "python",
      "mixed_tuple_arities": true,
      "outcome": "mixed_tuple_arities",
      "owner_id": null,
      "path": "python/public-vocabulary.py",
      "proof": "proven",
      "provenance": [
        {
          "seed": {
            "end_line": 71,
            "kind": "assignment",
            "path": "python/public-vocabulary.py",
            "result_type": "structural_match",
            "start_line": 71
          },
          "steps": [
            {
              "op": "tuple_return_assignment",
              "result": {
                "id": "66673978755ea6becfedc6c506d290133240d47bbfdb713c0b0c3fb22ef8ed2d",
                "outcome": "mixed_tuple_arities",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 46,
                  "end_line": 71,
                  "start_column": 5,
                  "start_line": 71
                },
                "relation": "tuple_return_groups",
                "result_type": "python_rule_fact"
              }
            },
            {
              "op": "filter",
              "result": {
                "id": "66673978755ea6becfedc6c506d290133240d47bbfdb713c0b0c3fb22ef8ed2d",
                "outcome": "mixed_tuple_arities",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 46,
                  "end_line": 71,
                  "start_column": 5,
                  "start_line": 71
                },
                "relation": "tuple_return_groups",
                "result_type": "python_rule_fact"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 46,
        "end_line": 71,
        "start_column": 5,
        "start_line": 71
      },
      "relation": "tuple_return_groups",
      "result_type": "python_rule_fact",
      "target_id": "7fabcceb15862e49b6dcf299e906c0c44487e9f548cb159a1dbb2ebef607d91d",
      "tuple_return_arities": [
        2,
        3
      ],
      "tuple_return_count": 2
    }
  ],
  "truncated": false
}
```

## Implicit String Concatenation

`python_implicit_string_concatenation` expands an implicit string-concatenation
group into one finding row per literal part. Each row's range is the literal's
own range, so both missing-comma locations remain independently selectable.

<!-- code-query-case:python-implicit-string-concatenation:rql -->
```lisp
(filter :where ((relation eq implicit_string_concatenation)
    (proof eq proven) (completeness eq complete))
  (python-implicit-string-concatenation
    (where "python/public-vocabulary.py"
      (language python (string_literal)))))
```

<!-- code-query-case:python-implicit-string-concatenation:json -->
```json
{
  "where": ["python/public-vocabulary.py"],
  "languages": ["python"],
  "match": {"kind": "string_literal"},
  "steps": [
    {"op": "python_implicit_string_concatenation"},
    {"op": "filter", "where": [
      {"field": "relation", "op": "eq", "value": {"enum": "implicit_string_concatenation"}},
      {"field": "proof", "op": "eq", "value": {"enum": "proven"}},
      {"field": "completeness", "op": "eq", "value": {"enum": "complete"}}
    ]}
  ]
}
```

<!-- code-query-case:python-implicit-string-concatenation:expected -->
```json
{
  "results": [
    {
      "completeness": "complete",
      "id": "e241153176028e25d0b6c447e3be5410b27f2a0d8a0816bfc2a8af717a2ae558",
      "language": "python",
      "outcome": "issue",
      "owner_id": null,
      "path": "python/public-vocabulary.py",
      "proof": "proven",
      "provenance": [
        {
          "seed": {
            "end_line": 75,
            "kind": "string_literal",
            "path": "python/public-vocabulary.py",
            "result_type": "structural_match",
            "start_line": 74
          },
          "steps": [
            {
              "op": "python_implicit_string_concatenation",
              "result": {
                "id": "e241153176028e25d0b6c447e3be5410b27f2a0d8a0816bfc2a8af717a2ae558",
                "outcome": "issue",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 12,
                  "end_line": 74,
                  "start_column": 5,
                  "start_line": 74
                },
                "relation": "implicit_string_concatenation",
                "result_type": "python_rule_fact"
              }
            },
            {
              "op": "filter",
              "result": {
                "id": "e241153176028e25d0b6c447e3be5410b27f2a0d8a0816bfc2a8af717a2ae558",
                "outcome": "issue",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 12,
                  "end_line": 74,
                  "start_column": 5,
                  "start_line": 74
                },
                "relation": "implicit_string_concatenation",
                "result_type": "python_rule_fact"
              }
            }
          ]
        },
        {
          "seed": {
            "end_line": 74,
            "kind": "string_literal",
            "path": "python/public-vocabulary.py",
            "result_type": "structural_match",
            "start_line": 74
          },
          "steps": [
            {
              "op": "python_implicit_string_concatenation",
              "result": {
                "id": "e241153176028e25d0b6c447e3be5410b27f2a0d8a0816bfc2a8af717a2ae558",
                "outcome": "issue",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 12,
                  "end_line": 74,
                  "start_column": 5,
                  "start_line": 74
                },
                "relation": "implicit_string_concatenation",
                "result_type": "python_rule_fact"
              }
            },
            {
              "op": "filter",
              "result": {
                "id": "e241153176028e25d0b6c447e3be5410b27f2a0d8a0816bfc2a8af717a2ae558",
                "outcome": "issue",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 12,
                  "end_line": 74,
                  "start_column": 5,
                  "start_line": 74
                },
                "relation": "implicit_string_concatenation",
                "result_type": "python_rule_fact"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 12,
        "end_line": 74,
        "start_column": 5,
        "start_line": 74
      },
      "relation": "implicit_string_concatenation",
      "result_type": "python_rule_fact"
    },
    {
      "completeness": "complete",
      "id": "767d8a9dd445b1cd75ee01b23f5a7087080d61d7c45762d80a7118456493a291",
      "language": "python",
      "outcome": "issue",
      "owner_id": null,
      "path": "python/public-vocabulary.py",
      "proof": "proven",
      "provenance": [
        {
          "seed": {
            "end_line": 75,
            "kind": "string_literal",
            "path": "python/public-vocabulary.py",
            "result_type": "structural_match",
            "start_line": 74
          },
          "steps": [
            {
              "op": "python_implicit_string_concatenation",
              "result": {
                "id": "767d8a9dd445b1cd75ee01b23f5a7087080d61d7c45762d80a7118456493a291",
                "outcome": "issue",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 13,
                  "end_line": 75,
                  "start_column": 5,
                  "start_line": 75
                },
                "relation": "implicit_string_concatenation",
                "result_type": "python_rule_fact"
              }
            },
            {
              "op": "filter",
              "result": {
                "id": "767d8a9dd445b1cd75ee01b23f5a7087080d61d7c45762d80a7118456493a291",
                "outcome": "issue",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 13,
                  "end_line": 75,
                  "start_column": 5,
                  "start_line": 75
                },
                "relation": "implicit_string_concatenation",
                "result_type": "python_rule_fact"
              }
            }
          ]
        },
        {
          "seed": {
            "end_line": 74,
            "kind": "string_literal",
            "path": "python/public-vocabulary.py",
            "result_type": "structural_match",
            "start_line": 74
          },
          "steps": [
            {
              "op": "python_implicit_string_concatenation",
              "result": {
                "id": "767d8a9dd445b1cd75ee01b23f5a7087080d61d7c45762d80a7118456493a291",
                "outcome": "issue",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 13,
                  "end_line": 75,
                  "start_column": 5,
                  "start_line": 75
                },
                "relation": "implicit_string_concatenation",
                "result_type": "python_rule_fact"
              }
            },
            {
              "op": "filter",
              "result": {
                "id": "767d8a9dd445b1cd75ee01b23f5a7087080d61d7c45762d80a7118456493a291",
                "outcome": "issue",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 13,
                  "end_line": 75,
                  "start_column": 5,
                  "start_line": 75
                },
                "relation": "implicit_string_concatenation",
                "result_type": "python_rule_fact"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 13,
        "end_line": 75,
        "start_column": 5,
        "start_line": 75
      },
      "relation": "implicit_string_concatenation",
      "result_type": "python_rule_fact"
    },
    {
      "completeness": "complete",
      "id": "a7922d6da45640f29127ca6215d6449b82d3ade4654c8bf4028e11bf9e281b3c",
      "language": "python",
      "outcome": "issue",
      "owner_id": null,
      "path": "python/public-vocabulary.py",
      "proof": "proven",
      "provenance": [
        {
          "seed": {
            "end_line": 77,
            "kind": "string_literal",
            "path": "python/public-vocabulary.py",
            "result_type": "structural_match",
            "start_line": 76
          },
          "steps": [
            {
              "op": "python_implicit_string_concatenation",
              "result": {
                "id": "a7922d6da45640f29127ca6215d6449b82d3ade4654c8bf4028e11bf9e281b3c",
                "outcome": "issue",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 21,
                  "end_line": 76,
                  "start_column": 6,
                  "start_line": 76
                },
                "relation": "implicit_string_concatenation",
                "result_type": "python_rule_fact"
              }
            },
            {
              "op": "filter",
              "result": {
                "id": "a7922d6da45640f29127ca6215d6449b82d3ade4654c8bf4028e11bf9e281b3c",
                "outcome": "issue",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 21,
                  "end_line": 76,
                  "start_column": 6,
                  "start_line": 76
                },
                "relation": "implicit_string_concatenation",
                "result_type": "python_rule_fact"
              }
            }
          ]
        },
        {
          "seed": {
            "end_line": 76,
            "kind": "string_literal",
            "path": "python/public-vocabulary.py",
            "result_type": "structural_match",
            "start_line": 76
          },
          "steps": [
            {
              "op": "python_implicit_string_concatenation",
              "result": {
                "id": "a7922d6da45640f29127ca6215d6449b82d3ade4654c8bf4028e11bf9e281b3c",
                "outcome": "issue",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 21,
                  "end_line": 76,
                  "start_column": 6,
                  "start_line": 76
                },
                "relation": "implicit_string_concatenation",
                "result_type": "python_rule_fact"
              }
            },
            {
              "op": "filter",
              "result": {
                "id": "a7922d6da45640f29127ca6215d6449b82d3ade4654c8bf4028e11bf9e281b3c",
                "outcome": "issue",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 21,
                  "end_line": 76,
                  "start_column": 6,
                  "start_line": 76
                },
                "relation": "implicit_string_concatenation",
                "result_type": "python_rule_fact"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 21,
        "end_line": 76,
        "start_column": 6,
        "start_line": 76
      },
      "relation": "implicit_string_concatenation",
      "result_type": "python_rule_fact"
    },
    {
      "completeness": "complete",
      "id": "a4dcf651d6771ec01c239641839e12703b686d0291044d7d14db150756069861",
      "language": "python",
      "outcome": "issue",
      "owner_id": null,
      "path": "python/public-vocabulary.py",
      "proof": "proven",
      "provenance": [
        {
          "seed": {
            "end_line": 77,
            "kind": "string_literal",
            "path": "python/public-vocabulary.py",
            "result_type": "structural_match",
            "start_line": 76
          },
          "steps": [
            {
              "op": "python_implicit_string_concatenation",
              "result": {
                "id": "a4dcf651d6771ec01c239641839e12703b686d0291044d7d14db150756069861",
                "outcome": "issue",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 13,
                  "end_line": 77,
                  "start_column": 6,
                  "start_line": 77
                },
                "relation": "implicit_string_concatenation",
                "result_type": "python_rule_fact"
              }
            },
            {
              "op": "filter",
              "result": {
                "id": "a4dcf651d6771ec01c239641839e12703b686d0291044d7d14db150756069861",
                "outcome": "issue",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 13,
                  "end_line": 77,
                  "start_column": 6,
                  "start_line": 77
                },
                "relation": "implicit_string_concatenation",
                "result_type": "python_rule_fact"
              }
            }
          ]
        },
        {
          "seed": {
            "end_line": 76,
            "kind": "string_literal",
            "path": "python/public-vocabulary.py",
            "result_type": "structural_match",
            "start_line": 76
          },
          "steps": [
            {
              "op": "python_implicit_string_concatenation",
              "result": {
                "id": "a4dcf651d6771ec01c239641839e12703b686d0291044d7d14db150756069861",
                "outcome": "issue",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 13,
                  "end_line": 77,
                  "start_column": 6,
                  "start_line": 77
                },
                "relation": "implicit_string_concatenation",
                "result_type": "python_rule_fact"
              }
            },
            {
              "op": "filter",
              "result": {
                "id": "a4dcf651d6771ec01c239641839e12703b686d0291044d7d14db150756069861",
                "outcome": "issue",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 13,
                  "end_line": 77,
                  "start_column": 6,
                  "start_line": 77
                },
                "relation": "implicit_string_concatenation",
                "result_type": "python_rule_fact"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 13,
        "end_line": 77,
        "start_column": 6,
        "start_line": 77
      },
      "relation": "implicit_string_concatenation",
      "result_type": "python_rule_fact"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:python-tuple-return-groups:rql -->
```lisp
(tuple-return-groups (procedure-of (language python (function :name "tuple_return"))))
```

<!-- code-query-case:python-tuple-return-groups:json -->
```json
{"languages":["python"],"match":{"kind":"function","name":"tuple_return"},"steps":[{"op":"procedure_of"},{"op":"tuple_return_groups"}]}
```

<!-- code-query-case:python-tuple-return-groups:expected -->
```json
{
  "results": [
    {
      "annotated": false,
      "completeness": "complete",
      "distinct_tuple_arities": 2,
      "id": "4f92788b91e35c5d3c727548d34acf1882e9f9c8fe84f2b8c7612b36f11d459e",
      "is_async": false,
      "is_generator": false,
      "language": "python",
      "mixed_tuple_arities": true,
      "outcome": "mixed_tuple_arities",
      "owner_id": "dfed963f58b8d942e4f3b3eab53e42fc880be7cf6c6bd4751134a75a47d3f9b8",
      "path": "python/public-vocabulary.py",
      "proof": "proven",
      "provenance": [
        {
          "seed": {
            "end_line": 23,
            "kind": "function",
            "path": "python/public-vocabulary.py",
            "result_type": "structural_match",
            "start_line": 20
          },
          "steps": [
            {
              "op": "procedure_of",
              "result": {
                "id": "dfed963f58b8d942e4f3b3eab53e42fc880be7cf6c6bd4751134a75a47d3f9b8",
                "path": "python/public-vocabulary.py",
                "procedure_kind": "function",
                "range": {
                  "end_column": 21,
                  "end_line": 23,
                  "start_column": 1,
                  "start_line": 20
                },
                "result_type": "procedure"
              }
            },
            {
              "op": "tuple_return_groups",
              "result": {
                "id": "4f92788b91e35c5d3c727548d34acf1882e9f9c8fe84f2b8c7612b36f11d459e",
                "outcome": "mixed_tuple_arities",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 21,
                  "end_line": 23,
                  "start_column": 1,
                  "start_line": 20
                },
                "relation": "tuple_return_groups",
                "result_type": "python_rule_fact"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 21,
        "end_line": 23,
        "start_column": 1,
        "start_line": 20
      },
      "relation": "tuple_return_groups",
      "result_type": "python_rule_fact",
      "tuple_return_arities": [
        2,
        3
      ],
      "tuple_return_count": 2
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:python-lambda-forwarding:rql -->
```lisp
(lambda-forwarding (language python (lambda)))
```

Each forwarding row also exposes `callable_evaluation_time` and
`default_equivalent`. Use them to keep invocation-time callable expressions
and lambdas with default parameters out of unnecessary-wrapper findings.

<!-- code-query-case:python-lambda-forwarding:json -->
```json
{"languages":["python"],"match":{"kind":"lambda"},"steps":[{"op":"lambda_forwarding"}]}
```

<!-- code-query-case:python-lambda-forwarding:expected -->
```json
{
  "results": [
    {
      "callable_evaluation_time": "stable_at_creation",
      "completeness": "complete",
      "default_equivalent": "yes",
      "forwarded": true,
      "id": "a1782e95e117f60d9416e550fd72ff7d56ef8694aaa9e139aa372f736637bd5e",
      "language": "python",
      "outcome": "forwarded",
      "owner_id": null,
      "parameter_count": 1,
      "path": "python/app.py",
      "proof": "proven",
      "provenance": [
        {
          "seed": {
            "end_line": 16,
            "kind": "lambda",
            "path": "python/app.py",
            "result_type": "structural_match",
            "start_line": 16
          },
          "steps": [
            {
              "op": "lambda_forwarding",
              "result": {
                "id": "a1782e95e117f60d9416e550fd72ff7d56ef8694aaa9e139aa372f736637bd5e",
                "outcome": "forwarded",
                "path": "python/app.py",
                "range": {
                  "end_column": 45,
                  "end_line": 16,
                  "start_column": 15,
                  "start_line": 16
                },
                "relation": "lambda_forwarding",
                "result_type": "python_rule_fact"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 45,
        "end_line": 16,
        "start_column": 15,
        "start_line": 16
      },
      "relation": "lambda_forwarding",
      "result_type": "python_rule_fact",
      "target_id": "c545898d1125110771b5356554b9ebdb1bd0c60619cf3adb6b109b2a47f9369d"
    },
    {
      "callable_evaluation_time": "stable_at_creation",
      "completeness": "complete",
      "default_equivalent": "yes",
      "forwarded": true,
      "id": "9819514d96beef2cbe4a27f75fb4eeb328931cf16871cc344ea29c197e5eeada",
      "language": "python",
      "outcome": "forwarded",
      "owner_id": null,
      "parameter_count": 1,
      "path": "python/public-vocabulary.py",
      "proof": "proven",
      "provenance": [
        {
          "seed": {
            "end_line": 28,
            "kind": "lambda",
            "path": "python/public-vocabulary.py",
            "result_type": "structural_match",
            "start_line": 28
          },
          "steps": [
            {
              "op": "lambda_forwarding",
              "result": {
                "id": "9819514d96beef2cbe4a27f75fb4eeb328931cf16871cc344ea29c197e5eeada",
                "outcome": "forwarded",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 36,
                  "end_line": 28,
                  "start_column": 11,
                  "start_line": 28
                },
                "relation": "lambda_forwarding",
                "result_type": "python_rule_fact"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 36,
        "end_line": 28,
        "start_column": 11,
        "start_line": 28
      },
      "relation": "lambda_forwarding",
      "result_type": "python_rule_fact",
      "target_id": "ad62196126533ebe80c02c4238285b85da0a416c10a9b144d81207165915d0e9"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:python-import-site:rql -->
```lisp
(python-import-site (language python (import :module "query_helper")))
```

<!-- code-query-case:python-import-cycles:rql -->
```lisp
(where "cycle_a.py"
  (filter :where ((python_import_cycle_state eq cyclic))
    (python-import-cycles
      (language python (import :module "cycle_b")))))
```

<!-- code-query-case:python-import-cycles:json -->
```json
{
  "where": ["cycle_a.py"],
  "languages": ["python"],
  "match": {"kind": "import", "module": {"name": "cycle_b"}},
  "steps": [
    {"op": "python_import_cycles"},
    {"op": "filter", "where": [{"field": "python_import_cycle_state", "op": "eq", "value": {"enum": "cyclic"}}]}
  ]
}
```

<!-- code-query-case:python-import-cycles:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "cycle_a",
      "end_line": 1,
      "kind": "import",
      "language": "python",
      "path": "cycle_a.py",
      "provenance": [
        {
          "seed": {
            "end_line": 1,
            "kind": "import",
            "path": "cycle_a.py",
            "result_type": "structural_match",
            "start_line": 1
          },
          "steps": [
            {
              "op": "python_import_cycles",
              "result": {
                "end_line": 1,
                "kind": "import",
                "path": "cycle_a.py",
                "result_type": "structural_match",
                "start_line": 1
              }
            },
            {
              "op": "filter",
              "result": {
                "end_line": 1,
                "kind": "import",
                "path": "cycle_a.py",
                "result_type": "structural_match",
                "start_line": 1
              }
            }
          ]
        }
      ],
      "python_import": {
        "alias": null,
        "aliases": [],
        "complete": true,
        "cycle_state": "cyclic",
        "export_state": "not_wildcard",
        "form": "import",
        "in_import_error_handler": false,
        "in_main_guard": false,
        "mixed_form": false,
        "module": "cycle_b",
        "module_scope": true,
        "modules": [
          "cycle_b"
        ],
        "name": null,
        "names": [],
        "own_module": false,
        "polluting": false,
        "repeated": false,
        "sites": [
          {
            "alias": null,
            "binder_range": {
              "end_column": 15,
              "end_line": 1,
              "start_column": 8,
              "start_line": 1
            },
            "cycle_state": "cyclic",
            "export_state": "not_wildcard",
            "form": "import",
            "mixed_form": false,
            "module": "cycle_b",
            "module_scope": true,
            "name": null,
            "own_module": false,
            "polluting": false,
            "repeated": false,
            "source_order": 0,
            "target_paths": [
              "cycle_b.py"
            ],
            "target_status": "resolved_local",
            "wildcard": false
          }
        ],
        "source_order": 0,
        "target_paths": [
          "cycle_b.py"
        ],
        "target_status": "resolved_local",
        "wildcard": false
      },
      "result_type": "structural_match",
      "start_line": 1,
      "text": "import cycle_b"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:python-import-site:json -->
```json
{"languages":["python"],"match":{"kind":"import","module":{"name":"query_helper"}},"steps":[{"op":"python_import_site"}]}
```

<!-- code-query-case:python-import-site:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "python.public-vocabulary",
      "end_line": 2,
      "kind": "import",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "provenance": [
        {
          "seed": {
            "end_line": 2,
            "kind": "import",
            "path": "python/public-vocabulary.py",
            "result_type": "structural_match",
            "start_line": 2
          },
          "steps": [
            {
              "op": "python_import_site",
              "result": {
                "end_line": 2,
                "kind": "import",
                "path": "python/public-vocabulary.py",
                "result_type": "structural_match",
                "start_line": 2
              }
            }
          ]
        }
      ],
      "python_import": {
        "alias": null,
        "aliases": [],
        "complete": false,
        "export_state": "not_wildcard",
        "form": "import",
        "in_import_error_handler": false,
        "in_main_guard": false,
        "mixed_form": true,
        "module": "query_helper",
        "module_scope": true,
        "modules": [
          "query_helper"
        ],
        "name": null,
        "names": [],
        "own_module": null,
        "polluting": false,
        "repeated": true,
        "sites": [
          {
            "alias": null,
            "binder_range": {
              "end_column": 20,
              "end_line": 2,
              "start_column": 8,
              "start_line": 2
            },
            "export_state": "not_wildcard",
            "form": "import",
            "mixed_form": true,
            "module": "query_helper",
            "module_scope": true,
            "name": null,
            "own_module": null,
            "polluting": false,
            "repeated": true,
            "source_order": 10,
            "target_paths": [],
            "target_status": "no_workspace_target",
            "wildcard": false
          }
        ],
        "source_order": 10,
        "target_paths": [],
        "target_status": "no_workspace_target",
        "wildcard": false
      },
      "result_type": "structural_match",
      "start_line": 2,
      "text": "import query_helper"
    },
    {
      "enclosing_symbol": "python.public-vocabulary",
      "end_line": 3,
      "kind": "import",
      "language": "python",
      "path": "python/public-vocabulary.py",
      "provenance": [
        {
          "seed": {
            "end_line": 3,
            "kind": "import",
            "path": "python/public-vocabulary.py",
            "result_type": "structural_match",
            "start_line": 3
          },
          "steps": [
            {
              "op": "python_import_site",
              "result": {
                "end_line": 3,
                "kind": "import",
                "path": "python/public-vocabulary.py",
                "result_type": "structural_match",
                "start_line": 3
              }
            }
          ]
        }
      ],
      "python_import": {
        "alias": null,
        "aliases": [],
        "complete": false,
        "export_state": "not_wildcard",
        "form": "from",
        "in_import_error_handler": false,
        "in_main_guard": false,
        "mixed_form": true,
        "module": "query_helper",
        "module_scope": true,
        "modules": [
          "query_helper"
        ],
        "name": "chosen",
        "names": [
          "chosen"
        ],
        "own_module": null,
        "polluting": false,
        "repeated": true,
        "sites": [
          {
            "alias": null,
            "binder_range": {
              "end_column": 32,
              "end_line": 3,
              "start_column": 26,
              "start_line": 3
            },
            "export_state": "not_wildcard",
            "form": "from",
            "mixed_form": true,
            "module": "query_helper",
            "module_scope": true,
            "name": "chosen",
            "own_module": null,
            "polluting": false,
            "repeated": true,
            "source_order": 30,
            "target_paths": [],
            "target_status": "no_workspace_target",
            "wildcard": false
          }
        ],
        "source_order": 30,
        "target_paths": [],
        "target_status": "no_workspace_target",
        "wildcard": false
      },
      "result_type": "structural_match",
      "start_line": 3,
      "text": "from query_helper import chosen"
    }
  ],
  "truncated": false
}
```

To select only the later namespace import of the same module into the same binding,
filter the enriched result on `python_import_duplicate`. This is narrower than
`python_import_repeated`, which marks every import in a repeated-module group.

```json
{"languages":["python"],"match":{"kind":"import"},"steps":[{"op":"python_import_site"},{"op":"filter","where":[{"field":"python_import_duplicate","op":"eq","value":{"boolean":true}}]}]}
```

The enriched row also exposes `python_import_in_import_error_handler`. This
lets a deprecated-module policy omit imports in compatibility handlers. Match
the field to `false`; an absent value means the handler identity was unresolved
and must not be treated as proof that the import is outside a fallback.

```json
{"languages":["python"],"match":{"kind":"import"},"steps":[{"op":"python_import_site"},{"op":"filter","where":[{"field":"python_import_in_import_error_handler","op":"eq","value":{"boolean":false}}]}]}
```

The same import row exposes `python_import_in_main_guard` for imports contained
by `if __name__ == "__main__"`. It recognizes either operand order and nested
statements. Select only unguarded imports in a cycle policy by requiring the
field to equal `false`; an absent value means the import context was unavailable.

```json
{"languages":["python"],"match":{"kind":"import"},"steps":[{"op":"python_import_site"},{"op":"filter","where":[{"field":"python_import_in_main_guard","op":"eq","value":{"boolean":false}}]}]}
```

<!-- code-query-case:python-class-hierarchy:rql -->
```lisp
(class-hierarchy (enclosing-decl (language python (class :name "Child"))))
```

<!-- code-query-case:python-class-hierarchy:json -->
```json
{"languages":["python"],"match":{"kind":"class","name":"Child"},"steps":[{"op":"enclosing_decl"},{"op":"class_hierarchy"}]}
```

<!-- code-query-case:python-class-hierarchy:expected -->
```json
{
  "results": [
    {
      "coverage": "complete",
      "fact_kind": "hierarchy",
      "id": "982246ff570854572acfb76529c73b00cef6db33336f8a0406a51dda8121c706",
      "language": "python",
      "outcome": "complete",
      "path": "python/public-vocabulary.py",
      "provenance": [
        {
          "seed": {
            "end_line": 40,
            "kind": "class",
            "path": "python/public-vocabulary.py",
            "result_type": "structural_match",
            "start_line": 38
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 40,
                "fq_name": "python.public-vocabulary.Child",
                "kind": "class",
                "path": "python/public-vocabulary.py",
                "result_type": "declaration",
                "start_line": 38
              }
            },
            {
              "op": "class_hierarchy",
              "result": {
                "fact_kind": "hierarchy",
                "id": "982246ff570854572acfb76529c73b00cef6db33336f8a0406a51dda8121c706",
                "outcome": "complete",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 23,
                  "end_line": 40,
                  "start_column": 1,
                  "start_line": 38
                },
                "result_type": "python_hierarchy_fact",
                "root_id": "4eed335041fddf582844dd582e567637d0f4d8045c0bc0b850028e4f9ffd01a9"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 23,
        "end_line": 40,
        "start_column": 1,
        "start_line": 38
      },
      "result_type": "python_hierarchy_fact",
      "root": {
        "end_line": 40,
        "fq_name": "python.public-vocabulary.Child",
        "kind": "class",
        "language": "python",
        "path": "python/public-vocabulary.py",
        "signature": "class Child(Parent):",
        "start_line": 38
      },
      "root_declaration_id": "4eed335041fddf582844dd582e567637d0f4d8045c0bc0b850028e4f9ffd01a9",
      "root_id": "4eed335041fddf582844dd582e567637d0f4d8045c0bc0b850028e4f9ffd01a9"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:python-class-bases:rql -->
```lisp
(class-bases (enclosing-decl (language python (class :name "Child"))))
```

<!-- code-query-case:python-class-bases:json -->
```json
{"languages":["python"],"match":{"kind":"class","name":"Child"},"steps":[{"op":"enclosing_decl"},{"op":"class_bases"}]}
```

<!-- code-query-case:python-class-bases:expected -->
```json
{
  "results": [
    {
      "base_resolution": "resolved",
      "base_spelling": "Parent",
      "coverage": "complete",
      "fact_kind": "base",
      "id": "3992dd4199c80e39d7240779de3f0f150f9bff91196ed1bed94a41daabf0ca3c",
      "language": "python",
      "ordinal": 0,
      "outcome": "resolved",
      "path": "python/public-vocabulary.py",
      "provenance": [
        {
          "seed": {
            "end_line": 40,
            "kind": "class",
            "path": "python/public-vocabulary.py",
            "result_type": "structural_match",
            "start_line": 38
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 40,
                "fq_name": "python.public-vocabulary.Child",
                "kind": "class",
                "path": "python/public-vocabulary.py",
                "result_type": "declaration",
                "start_line": 38
              }
            },
            {
              "op": "class_bases",
              "result": {
                "fact_kind": "base",
                "id": "3992dd4199c80e39d7240779de3f0f150f9bff91196ed1bed94a41daabf0ca3c",
                "outcome": "resolved",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 23,
                  "end_line": 40,
                  "start_column": 1,
                  "start_line": 38
                },
                "result_type": "python_hierarchy_fact",
                "root_id": "4eed335041fddf582844dd582e567637d0f4d8045c0bc0b850028e4f9ffd01a9"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 23,
        "end_line": 40,
        "start_column": 1,
        "start_line": 38
      },
      "result_type": "python_hierarchy_fact",
      "root": {
        "end_line": 40,
        "fq_name": "python.public-vocabulary.Child",
        "kind": "class",
        "language": "python",
        "path": "python/public-vocabulary.py",
        "signature": "class Child(Parent):",
        "start_line": 38
      },
      "root_declaration_id": "4eed335041fddf582844dd582e567637d0f4d8045c0bc0b850028e4f9ffd01a9",
      "root_id": "4eed335041fddf582844dd582e567637d0f4d8045c0bc0b850028e4f9ffd01a9",
      "target": {
        "end_line": 36,
        "fq_name": "python.public-vocabulary.Parent",
        "kind": "class",
        "language": "python",
        "path": "python/public-vocabulary.py",
        "signature": "class Parent:",
        "start_line": 34
      },
      "target_id": "64b7200500166a9a58338f2ee036837896bfc8b6f13906f8e7d7fac210051b81"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:python-class-mro:rql -->
```lisp
(class-mro (enclosing-decl (language python (class :name "Child"))))
```

<!-- code-query-case:python-class-mro:json -->
```json
{"languages":["python"],"match":{"kind":"class","name":"Child"},"steps":[{"op":"enclosing_decl"},{"op":"class_mro"}]}
```

<!-- code-query-case:python-class-mro:expected -->
```json
{
  "results": [
    {
      "coverage": "complete",
      "declaration": {
        "end_line": 40,
        "fq_name": "python.public-vocabulary.Child",
        "kind": "class",
        "language": "python",
        "path": "python/public-vocabulary.py",
        "signature": "class Child(Parent):",
        "start_line": 38
      },
      "declaration_id": "4eed335041fddf582844dd582e567637d0f4d8045c0bc0b850028e4f9ffd01a9",
      "fact_kind": "mro",
      "id": "8223c8f755d8662c94bfc5492f63a7abdbdfe1dbb6240016bb1a6c1e193920e1",
      "language": "python",
      "mro_rank": 0,
      "ordinal": 0,
      "outcome": "complete",
      "path": "python/public-vocabulary.py",
      "provenance": [
        {
          "seed": {
            "end_line": 40,
            "kind": "class",
            "path": "python/public-vocabulary.py",
            "result_type": "structural_match",
            "start_line": 38
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 40,
                "fq_name": "python.public-vocabulary.Child",
                "kind": "class",
                "path": "python/public-vocabulary.py",
                "result_type": "declaration",
                "start_line": 38
              }
            },
            {
              "op": "class_mro",
              "result": {
                "fact_kind": "mro",
                "id": "8223c8f755d8662c94bfc5492f63a7abdbdfe1dbb6240016bb1a6c1e193920e1",
                "outcome": "complete",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 23,
                  "end_line": 40,
                  "start_column": 1,
                  "start_line": 38
                },
                "result_type": "python_hierarchy_fact",
                "root_id": "4eed335041fddf582844dd582e567637d0f4d8045c0bc0b850028e4f9ffd01a9"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 23,
        "end_line": 40,
        "start_column": 1,
        "start_line": 38
      },
      "result_type": "python_hierarchy_fact",
      "root": {
        "end_line": 40,
        "fq_name": "python.public-vocabulary.Child",
        "kind": "class",
        "language": "python",
        "path": "python/public-vocabulary.py",
        "signature": "class Child(Parent):",
        "start_line": 38
      },
      "root_declaration_id": "4eed335041fddf582844dd582e567637d0f4d8045c0bc0b850028e4f9ffd01a9",
      "root_id": "4eed335041fddf582844dd582e567637d0f4d8045c0bc0b850028e4f9ffd01a9"
    },
    {
      "coverage": "complete",
      "declaration": {
        "end_line": 36,
        "fq_name": "python.public-vocabulary.Parent",
        "kind": "class",
        "language": "python",
        "path": "python/public-vocabulary.py",
        "signature": "class Parent:",
        "start_line": 34
      },
      "declaration_id": "64b7200500166a9a58338f2ee036837896bfc8b6f13906f8e7d7fac210051b81",
      "fact_kind": "mro",
      "id": "a431c4776a01d06c17a8190e567aa53137840a9c3553c164c36b722f6d384f88",
      "language": "python",
      "mro_rank": 1,
      "ordinal": 1,
      "outcome": "complete",
      "path": "python/public-vocabulary.py",
      "provenance": [
        {
          "seed": {
            "end_line": 40,
            "kind": "class",
            "path": "python/public-vocabulary.py",
            "result_type": "structural_match",
            "start_line": 38
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 40,
                "fq_name": "python.public-vocabulary.Child",
                "kind": "class",
                "path": "python/public-vocabulary.py",
                "result_type": "declaration",
                "start_line": 38
              }
            },
            {
              "op": "class_mro",
              "result": {
                "fact_kind": "mro",
                "id": "a431c4776a01d06c17a8190e567aa53137840a9c3553c164c36b722f6d384f88",
                "outcome": "complete",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 23,
                  "end_line": 40,
                  "start_column": 1,
                  "start_line": 38
                },
                "result_type": "python_hierarchy_fact",
                "root_id": "4eed335041fddf582844dd582e567637d0f4d8045c0bc0b850028e4f9ffd01a9"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 23,
        "end_line": 40,
        "start_column": 1,
        "start_line": 38
      },
      "result_type": "python_hierarchy_fact",
      "root": {
        "end_line": 40,
        "fq_name": "python.public-vocabulary.Child",
        "kind": "class",
        "language": "python",
        "path": "python/public-vocabulary.py",
        "signature": "class Child(Parent):",
        "start_line": 38
      },
      "root_declaration_id": "4eed335041fddf582844dd582e567637d0f4d8045c0bc0b850028e4f9ffd01a9",
      "root_id": "4eed335041fddf582844dd582e567637d0f4d8045c0bc0b850028e4f9ffd01a9"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:python-mro-members:rql -->
```lisp
(mro-members (enclosing-decl (language python (class :name "Child"))))
```

<!-- code-query-case:python-mro-members:json -->
```json
{"languages":["python"],"match":{"kind":"class","name":"Child"},"steps":[{"op":"enclosing_decl"},{"op":"mro_members"}]}
```

<!-- code-query-case:python-mro-members:expected -->
```json
{
  "results": [
    {
      "coverage": "complete",
      "base_branch_definition_count": 1,
      "has_strict_ordering": false,
      "has_non_strict_ordering": false,
      "inherited_ne_delegates": false,
      "inherited_ne_present": false,
      "total_ordering_decorator": false,
      "declaration": {
        "end_line": 40,
        "fq_name": "python.public-vocabulary.Child.describe",
        "kind": "function",
        "language": "python",
        "path": "python/public-vocabulary.py",
        "signature": "(self)",
        "start_line": 39
      },
      "declaration_id": "8bf41cd6290eb226a89dd7efbd302a4e535411446bc38a9f4eadd03ed5f27e88",
      "fact_kind": "member",
      "id": "cd0d1f6cde758936887390dc1f99688f2bd746b9cad10edd94186a4f08e1d2d6",
      "language": "python",
      "member_name": "describe",
      "mro_rank": 0,
      "ordinal": 0,
      "outcome": "selected",
      "owner": {
        "end_line": 40,
        "fq_name": "python.public-vocabulary.Child",
        "kind": "class",
        "language": "python",
        "path": "python/public-vocabulary.py",
        "signature": "class Child(Parent):",
        "start_line": 38
      },
      "owner_id": "4eed335041fddf582844dd582e567637d0f4d8045c0bc0b850028e4f9ffd01a9",
      "path": "python/public-vocabulary.py",
      "provenance": [
        {
          "seed": {
            "end_line": 40,
            "kind": "class",
            "path": "python/public-vocabulary.py",
            "result_type": "structural_match",
            "start_line": 38
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 40,
                "fq_name": "python.public-vocabulary.Child",
                "kind": "class",
                "path": "python/public-vocabulary.py",
                "result_type": "declaration",
                "start_line": 38
              }
            },
            {
              "op": "mro_members",
              "result": {
                "fact_kind": "member",
                "id": "cd0d1f6cde758936887390dc1f99688f2bd746b9cad10edd94186a4f08e1d2d6",
                "outcome": "selected",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 23,
                  "end_line": 40,
                  "start_column": 1,
                  "start_line": 38
                },
                "result_type": "python_hierarchy_fact",
                "root_id": "4eed335041fddf582844dd582e567637d0f4d8045c0bc0b850028e4f9ffd01a9"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 23,
        "end_line": 40,
        "start_column": 1,
        "start_line": 38
      },
      "result_type": "python_hierarchy_fact",
      "root": {
        "end_line": 40,
        "fq_name": "python.public-vocabulary.Child",
        "kind": "class",
        "language": "python",
        "path": "python/public-vocabulary.py",
        "signature": "class Child(Parent):",
        "start_line": 38
      },
      "root_declaration_id": "4eed335041fddf582844dd582e567637d0f4d8045c0bc0b850028e4f9ffd01a9",
      "root_id": "4eed335041fddf582844dd582e567637d0f4d8045c0bc0b850028e4f9ffd01a9"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:python-overrides:rql -->
```lisp
(python-overrides (enclosing-decl (language python (method :name "describe"))))
```

<!-- code-query-case:python-overrides:json -->
```json
{"languages":["python"],"match":{"kind":"method","name":"describe"},"steps":[{"op":"enclosing_decl"},{"op":"python_overrides"}]}
```

<!-- code-query-case:python-overrides:expected -->
```json
{
  "results": [
    {
      "coverage": "complete",
      "declaration": {
        "end_line": 36,
        "fq_name": "python.public-vocabulary.Parent.describe",
        "kind": "function",
        "language": "python",
        "path": "python/public-vocabulary.py",
        "signature": "(self)",
        "start_line": 35
      },
      "declaration_id": "f2b5c21a65e24435922f1c892956acbadc5e86d9bc7439608e86a4778e07383a",
      "fact_kind": "override",
      "id": "bfd273de4b81f475a368dd0ab13669724cfb3e4ab0c343d05e1abb5f115713ba",
      "language": "python",
      "member_name": "describe",
      "outcome": "no_override",
      "owner": {
        "end_line": 36,
        "fq_name": "python.public-vocabulary.Parent",
        "kind": "class",
        "language": "python",
        "path": "python/public-vocabulary.py",
        "signature": "class Parent:",
        "start_line": 34
      },
      "owner_id": "64b7200500166a9a58338f2ee036837896bfc8b6f13906f8e7d7fac210051b81",
      "path": "python/public-vocabulary.py",
      "provenance": [
        {
          "seed": {
            "end_line": 36,
            "kind": "method",
            "path": "python/public-vocabulary.py",
            "result_type": "structural_match",
            "start_line": 35
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 36,
                "fq_name": "python.public-vocabulary.Parent.describe",
                "kind": "method",
                "path": "python/public-vocabulary.py",
                "result_type": "declaration",
                "start_line": 35
              }
            },
            {
              "op": "python_overrides",
              "result": {
                "fact_kind": "override",
                "id": "bfd273de4b81f475a368dd0ab13669724cfb3e4ab0c343d05e1abb5f115713ba",
                "outcome": "no_override",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 24,
                  "end_line": 36,
                  "start_column": 5,
                  "start_line": 35
                },
                "result_type": "python_hierarchy_fact",
                "root_id": "f2b5c21a65e24435922f1c892956acbadc5e86d9bc7439608e86a4778e07383a"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 24,
        "end_line": 36,
        "start_column": 5,
        "start_line": 35
      },
      "result_type": "python_hierarchy_fact",
      "root": {
        "end_line": 36,
        "fq_name": "python.public-vocabulary.Parent.describe",
        "kind": "function",
        "language": "python",
        "path": "python/public-vocabulary.py",
        "signature": "(self)",
        "start_line": 35
      },
      "root_declaration_id": "f2b5c21a65e24435922f1c892956acbadc5e86d9bc7439608e86a4778e07383a",
      "root_id": "f2b5c21a65e24435922f1c892956acbadc5e86d9bc7439608e86a4778e07383a"
    },
    {
      "coverage": "complete",
      "declaration": {
        "end_line": 40,
        "fq_name": "python.public-vocabulary.Child.describe",
        "kind": "function",
        "language": "python",
        "path": "python/public-vocabulary.py",
        "signature": "(self)",
        "start_line": 39
      },
      "declaration_id": "8bf41cd6290eb226a89dd7efbd302a4e535411446bc38a9f4eadd03ed5f27e88",
      "fact_kind": "override",
      "id": "a5174125441759829f097453e910510a3c83eb0abc7c0bf2897c1a3c06de045d",
      "language": "python",
      "member_name": "describe",
      "mro_rank": 1,
      "outcome": "overrides",
      "owner": {
        "end_line": 40,
        "fq_name": "python.public-vocabulary.Child",
        "kind": "class",
        "language": "python",
        "path": "python/public-vocabulary.py",
        "signature": "class Child(Parent):",
        "start_line": 38
      },
      "owner_id": "4eed335041fddf582844dd582e567637d0f4d8045c0bc0b850028e4f9ffd01a9",
      "path": "python/public-vocabulary.py",
      "provenance": [
        {
          "seed": {
            "end_line": 40,
            "kind": "method",
            "path": "python/public-vocabulary.py",
            "result_type": "structural_match",
            "start_line": 39
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 40,
                "fq_name": "python.public-vocabulary.Child.describe",
                "kind": "method",
                "path": "python/public-vocabulary.py",
                "result_type": "declaration",
                "start_line": 39
              }
            },
            {
              "op": "python_overrides",
              "result": {
                "fact_kind": "override",
                "id": "a5174125441759829f097453e910510a3c83eb0abc7c0bf2897c1a3c06de045d",
                "outcome": "overrides",
                "path": "python/public-vocabulary.py",
                "range": {
                  "end_column": 23,
                  "end_line": 40,
                  "start_column": 5,
                  "start_line": 39
                },
                "result_type": "python_hierarchy_fact",
                "root_id": "8bf41cd6290eb226a89dd7efbd302a4e535411446bc38a9f4eadd03ed5f27e88"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 23,
        "end_line": 40,
        "start_column": 5,
        "start_line": 39
      },
      "result_type": "python_hierarchy_fact",
      "root": {
        "end_line": 40,
        "fq_name": "python.public-vocabulary.Child.describe",
        "kind": "function",
        "language": "python",
        "path": "python/public-vocabulary.py",
        "signature": "(self)",
        "start_line": 39
      },
      "root_declaration_id": "8bf41cd6290eb226a89dd7efbd302a4e535411446bc38a9f4eadd03ed5f27e88",
      "root_id": "8bf41cd6290eb226a89dd7efbd302a4e535411446bc38a9f4eadd03ed5f27e88",
      "target": {
        "end_line": 36,
        "fq_name": "python.public-vocabulary.Parent.describe",
        "kind": "function",
        "language": "python",
        "path": "python/public-vocabulary.py",
        "signature": "(self)",
        "start_line": 35
      },
      "target_id": "f2b5c21a65e24435922f1c892956acbadc5e86d9bc7439608e86a4778e07383a",
      "target_owner": {
        "end_line": 36,
        "fq_name": "python.public-vocabulary.Parent",
        "kind": "class",
        "language": "python",
        "path": "python/public-vocabulary.py",
        "signature": "class Parent:",
        "start_line": 34
      },
      "target_owner_id": "64b7200500166a9a58338f2ee036837896bfc8b6f13906f8e7d7fac210051b81"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:python-binding-uses:rql -->
```lisp
(project :columns (target_kind)
  (where "python/public-vocabulary.py"
    (binding-uses (bindings :kind [parameter] :name [value]))))
```

<!-- code-query-case:python-binding-uses:json -->
```json
{"where":["python/public-vocabulary.py"],"bindings":{"kind":["parameter"],"name":["value"]},"steps":[{"op":"binding_uses"},{"op":"project","columns":[{"source":"target_kind","name":"target_kind"}]}]}
```

<!-- code-query-case:python-binding-uses:expected -->
```json
{
  "results": [
    {
      "ast_id": "b25d44fc764045ce0d595cfd96133462fe535ea9f23fa3094dc58c26812bf705",
      "class": "reference",
      "enclosing_symbol": "python.public-vocabulary.shapes",
      "end_byte": 164,
      "id": "557423df99cfcbdf51f921b15ff2487aa3447168bbee0153415036118cc3bacf",
      "language": "python",
      "namespace": "value",
      "path": "python/public-vocabulary.py",
      "range": {
        "end_column": 18,
        "end_line": 8,
        "start_column": 13,
        "start_line": 8
      },
      "raw_spelling": "value",
      "result_type": "occurrence",
      "role": "value_reference",
      "start_byte": 159,
      "target": {
        "kind": "parameter",
        "name": "value",
        "range": {
          "end_column": 17,
          "end_line": 6,
          "start_column": 12,
          "start_line": 6
        },
        "target_kind": "lexical"
      }
    },
    {
      "ast_id": "185f2b7cd3d4b474f8975fc9bd844792a811c8f6d77ebbc2c290f3ac3847416c",
      "class": "reference",
      "enclosing_symbol": "python.public-vocabulary.shapes",
      "end_byte": 192,
      "id": "7d2f40d47f3104eaaf42bb66077590f80d761daef7cff35e3152ec4533c12f38",
      "language": "python",
      "namespace": "value",
      "path": "python/public-vocabulary.py",
      "range": {
        "end_column": 24,
        "end_line": 9,
        "start_column": 19,
        "start_line": 9
      },
      "raw_spelling": "value",
      "result_type": "occurrence",
      "role": "value_reference",
      "start_byte": 187,
      "target": {
        "kind": "parameter",
        "name": "value",
        "range": {
          "end_column": 17,
          "end_line": 6,
          "start_column": 12,
          "start_line": 6
        },
        "target_kind": "lexical"
      }
    },
    {
      "ast_id": "0df960175dd2ca8ab9a05415c683cbdf487d3154aad2ebe90aef82f00fc60e93",
      "class": "reference",
      "enclosing_symbol": "python.public-vocabulary.shapes",
      "end_byte": 214,
      "id": "f9168beb8d13f9f9982b0a5f566019d12252b34e72d99a10b6f9e1f86a521ff6",
      "language": "python",
      "namespace": "value",
      "path": "python/public-vocabulary.py",
      "range": {
        "end_column": 18,
        "end_line": 10,
        "start_column": 13,
        "start_line": 10
      },
      "raw_spelling": "value",
      "result_type": "occurrence",
      "role": "value_reference",
      "start_byte": 209,
      "target": {
        "kind": "parameter",
        "name": "value",
        "range": {
          "end_column": 17,
          "end_line": 6,
          "start_column": 12,
          "start_line": 6
        },
        "target_kind": "lexical"
      }
    },
    {
      "ast_id": "9fd73ff692c3fa0320b568687ff69d18642f7e70c79b386e20c3384b2366fc93",
      "class": "reference",
      "enclosing_symbol": "python.public-vocabulary.shapes",
      "end_byte": 243,
      "id": "6af463e9b4358ffe50c75dd540bbfe797b0e40bcf848c085b9aa1153c21fb477",
      "language": "python",
      "namespace": "value",
      "path": "python/public-vocabulary.py",
      "range": {
        "end_column": 24,
        "end_line": 11,
        "start_column": 19,
        "start_line": 11
      },
      "raw_spelling": "value",
      "result_type": "occurrence",
      "role": "value_reference",
      "start_byte": 238,
      "target": {
        "kind": "parameter",
        "name": "value",
        "range": {
          "end_column": 17,
          "end_line": 6,
          "start_column": 12,
          "start_line": 6
        },
        "target_kind": "lexical"
      }
    },
    {
      "ast_id": "e5a1dd8ca3dcdad01278e1af522852b99eb9cf581b2f35f9acb498adbd715fa2",
      "class": "reference",
      "enclosing_symbol": "python.public-vocabulary.shapes",
      "end_byte": 264,
      "id": "13bd82d59794e34b6208097ab72a7ae9a02f6e513e21dc060ba0cadb0bb3b30e",
      "language": "python",
      "namespace": "value",
      "path": "python/public-vocabulary.py",
      "range": {
        "end_column": 17,
        "end_line": 12,
        "start_column": 12,
        "start_line": 12
      },
      "raw_spelling": "value",
      "result_type": "occurrence",
      "role": "value_reference",
      "start_byte": 259,
      "target": {
        "kind": "parameter",
        "name": "value",
        "range": {
          "end_column": 17,
          "end_line": 6,
          "start_column": 12,
          "start_line": 6
        },
        "target_kind": "lexical"
      }
    },
    {
      "ast_id": "4df7c1b1bfeec5f50d4c36321ee5b9cb09715df8157c996d17134b7bed64934b",
      "class": "reference",
      "enclosing_symbol": "python.public-vocabulary.maybe",
      "end_byte": 333,
      "id": "80e9b857eb8dcb3cad4919c73b952cdf373afe4beae4f893706e52c7a221bc1b",
      "language": "python",
      "namespace": "value",
      "path": "python/public-vocabulary.py",
      "range": {
        "end_column": 13,
        "end_line": 16,
        "start_column": 8,
        "start_line": 16
      },
      "raw_spelling": "value",
      "result_type": "occurrence",
      "role": "value_reference",
      "start_byte": 328,
      "target": {
        "kind": "parameter",
        "name": "value",
        "range": {
          "end_column": 16,
          "end_line": 15,
          "start_column": 11,
          "start_line": 15
        },
        "target_kind": "lexical"
      }
    },
    {
      "ast_id": "565d1652ca41ea173d0c267a34dd807ff57b58442de39ce5aa8c1b6905604050",
      "class": "reference",
      "enclosing_symbol": "python.public-vocabulary.maybe",
      "end_byte": 355,
      "id": "81ac9a14287dcc70b969e269ad56c9c72eb04aa537fd6362a3ca487254d4ef88",
      "language": "python",
      "namespace": "value",
      "path": "python/public-vocabulary.py",
      "range": {
        "end_column": 21,
        "end_line": 17,
        "start_column": 16,
        "start_line": 17
      },
      "raw_spelling": "value",
      "result_type": "occurrence",
      "role": "value_reference",
      "start_byte": 350,
      "target": {
        "kind": "parameter",
        "name": "value",
        "range": {
          "end_column": 16,
          "end_line": 15,
          "start_column": 11,
          "start_line": 15
        },
        "target_kind": "lexical"
      }
    },
    {
      "ast_id": "4164ed0b9215cffa48c3dd2212569f1ea959ea87411383a5f13d8bccdc9b5375",
      "class": "reference",
      "enclosing_symbol": "python.public-vocabulary.target",
      "end_byte": 489,
      "id": "a93b57824f11ae9a15470c048c77d90fb76e808ba792d30352c488cd3d674844",
      "language": "python",
      "namespace": "value",
      "path": "python/public-vocabulary.py",
      "range": {
        "end_column": 17,
        "end_line": 26,
        "start_column": 12,
        "start_line": 26
      },
      "raw_spelling": "value",
      "result_type": "occurrence",
      "role": "value_reference",
      "start_byte": 484,
      "target": {
        "kind": "parameter",
        "name": "value",
        "range": {
          "end_column": 17,
          "end_line": 25,
          "start_column": 12,
          "start_line": 25
        },
        "target_kind": "lexical"
      }
    },
    {
      "ast_id": "a3fd93b25025eb812c6fd3102b7353131733317d63ea605577c23d98a848879b",
      "class": "reference",
      "enclosing_symbol": "python.public-vocabulary.consume",
      "end_byte": 573,
      "id": "928ebfba93035743cc0da481ff0ecbbc054c6cffcfbb9534c05e28601fe87700",
      "language": "python",
      "namespace": "value",
      "path": "python/public-vocabulary.py",
      "range": {
        "end_column": 26,
        "end_line": 31,
        "start_column": 21,
        "start_line": 31
      },
      "raw_spelling": "value",
      "result_type": "occurrence",
      "role": "value_reference",
      "start_byte": 568,
      "target": {
        "kind": "parameter",
        "name": "value",
        "range": {
          "end_column": 18,
          "end_line": 30,
          "start_column": 13,
          "start_line": 30
        },
        "target_kind": "lexical"
      }
    }
  ],
  "truncated": false
}
```

## Lexical Variables

`python-variable-of` groups Python binder and identifier rows by their resolved
scope and name. The definition relation preserves each write in source order;
the use relation shows reads and writes, including the nested-scope reads that
close over an enclosing local. Explicit `nonlocal` and `global` declarations
join the variable owned by the enclosing function or module. Definition
reachability is `open` until an exact CFG fact is available; lexical rows do
not claim that a definition executes. Variable rows also expose `is_global`,
`is_nonlocal`, `is_builtin`, and `has_read`. Definition rows include
`definition_is_unused`, `annotation_only`, `is_decorated`, `is_abstract`,
`is_overriding_method`, and `is_overridden_method` for policy exclusions.
Peer rows expose `related_is_pytest_fixture` for the pytest-fixture exclusion.

<!-- code-query-fixture:python/lexical-variables.py -->
```python
shared = 0

def inspect(values):
    item = 0
    for item in values:
        item += 1

    def captured():
        nonlocal item
        item = item + 1
        global shared
        shared += 1
        return item

    return captured()

def local_shadow():
    shared = 1
    return shared

def comprehension_scope(values):
    item = 0
    return [item for item in values]

def nested_loop(items, children):
    for item in items:
        for item in children:
            pass
        consume(item)
```

<!-- code-query-case:python-variable-definitions:rql -->
```lisp
(where "python/lexical-variables.py"
  (python-variable-definitions
    (python-variable-of (bindings :name [item shared]))))
```

<!-- code-query-case:python-variable-definitions:json -->
```json
{
  "where": ["python/lexical-variables.py"],
  "bindings": {"name": ["item", "shared"]},
  "steps": [
    {"op": "python_variable_of"},
    {"op": "python_variable_definitions"}
  ]
}
```

<!-- code-query-case:python-variable-definitions:expected -->
```json
{
  "results": [
    {
      "annotated_assignment": false,
      "annotation_only": false,
      "completeness": "complete",
      "definition_is_unused": false,
      "definition_kind": "assignment",
      "definition_order": 0,
      "first_definition": true,
      "has_read": true,
      "id": "cdcc27697f309f7cc3047ada85005cddd10b62613a3899494b09f6b6b561577a",
      "in_main_guard": false,
      "is_abstract": false,
      "is_builtin": false,
      "is_decorated": false,
      "is_global": true,
      "is_nonlocal": false,
      "is_overridden_method": false,
      "is_overriding_method": false,
      "language": "python",
      "name": "shared",
      "optimizing_parameter": false,
      "outcome": "definition",
      "owner_id": "5df709695362ab2ea6c82ee21a85b191de4eb92792284a3f1fd506abe57188ec",
      "path": "python/lexical-variables.py",
      "proof": "proven",
      "range": {
        "end_column": 7,
        "end_line": 1,
        "start_column": 1,
        "start_line": 1
      },
      "reachability": "open",
      "relation": "lexical_variable_definition",
      "result_type": "python_rule_fact",
      "scope_kind": "module",
      "self_assignment": false,
      "variable_id": "5df709695362ab2ea6c82ee21a85b191de4eb92792284a3f1fd506abe57188ec"
    },
    {
      "annotated_assignment": false,
      "annotation_only": false,
      "completeness": "complete",
      "definition_is_unused": true,
      "definition_kind": "augmented",
      "definition_order": 1,
      "first_definition": false,
      "has_read": true,
      "id": "71b7abf7c067a57b2a21b368d4b9db7d594d4b7a3d994d10334fcefd5a1c8fc1",
      "in_main_guard": false,
      "is_abstract": false,
      "is_builtin": false,
      "is_decorated": false,
      "is_global": true,
      "is_nonlocal": false,
      "is_overridden_method": false,
      "is_overriding_method": false,
      "language": "python",
      "name": "shared",
      "optimizing_parameter": false,
      "outcome": "definition",
      "owner_id": "5df709695362ab2ea6c82ee21a85b191de4eb92792284a3f1fd506abe57188ec",
      "path": "python/lexical-variables.py",
      "proof": "proven",
      "range": {
        "end_column": 15,
        "end_line": 12,
        "start_column": 9,
        "start_line": 12
      },
      "reachability": "open",
      "relation": "lexical_variable_definition",
      "result_type": "python_rule_fact",
      "scope_kind": "module",
      "self_assignment": false,
      "variable_id": "5df709695362ab2ea6c82ee21a85b191de4eb92792284a3f1fd506abe57188ec"
    },
    {
      "annotated_assignment": false,
      "annotation_only": false,
      "completeness": "complete",
      "definition_is_unused": false,
      "definition_kind": "assignment",
      "definition_order": 0,
      "first_definition": true,
      "has_read": true,
      "id": "461562db5f4e869b285dc56c41e6cb75a03a707d3ab735657a3b8e327f471cad",
      "in_main_guard": false,
      "is_abstract": false,
      "is_builtin": false,
      "is_decorated": false,
      "is_global": false,
      "is_nonlocal": true,
      "is_overridden_method": false,
      "is_overriding_method": false,
      "language": "python",
      "name": "item",
      "optimizing_parameter": false,
      "outcome": "definition",
      "owner_id": "dad31f3c3700c051124059ddad4aefa3613f3722ecf73b2ca9304094ab125a32",
      "path": "python/lexical-variables.py",
      "proof": "proven",
      "range": {
        "end_column": 9,
        "end_line": 4,
        "start_column": 5,
        "start_line": 4
      },
      "reachability": "open",
      "relation": "lexical_variable_definition",
      "result_type": "python_rule_fact",
      "scope_kind": "function",
      "self_assignment": false,
      "variable_id": "dad31f3c3700c051124059ddad4aefa3613f3722ecf73b2ca9304094ab125a32"
    },
    {
      "annotated_assignment": false,
      "annotation_only": false,
      "completeness": "complete",
      "definition_is_unused": false,
      "definition_kind": "loop_target",
      "definition_order": 1,
      "first_definition": false,
      "has_read": true,
      "id": "f55081b01a8d769355cb6a091abb2f19cae170ff9980680f5c8e01d01f506653",
      "in_main_guard": false,
      "is_abstract": false,
      "is_builtin": false,
      "is_decorated": false,
      "is_global": false,
      "is_nonlocal": true,
      "is_overridden_method": false,
      "is_overriding_method": false,
      "language": "python",
      "loop_has_body_read": true,
      "loop_policy_excluded": true,
      "name": "item",
      "optimizing_parameter": false,
      "outcome": "definition",
      "owner_id": "dad31f3c3700c051124059ddad4aefa3613f3722ecf73b2ca9304094ab125a32",
      "path": "python/lexical-variables.py",
      "proof": "proven",
      "range": {
        "end_column": 13,
        "end_line": 5,
        "start_column": 9,
        "start_line": 5
      },
      "reachability": "open",
      "relation": "lexical_variable_definition",
      "result_type": "python_rule_fact",
      "scope_kind": "function",
      "self_assignment": false,
      "variable_id": "dad31f3c3700c051124059ddad4aefa3613f3722ecf73b2ca9304094ab125a32"
    },
    {
      "annotated_assignment": false,
      "annotation_only": false,
      "completeness": "complete",
      "definition_is_unused": false,
      "definition_kind": "augmented",
      "definition_order": 2,
      "first_definition": false,
      "has_read": true,
      "id": "95f6cd6f856cb060caba188c79f5e34c710eead2d42e222a67592dfd1a860545",
      "in_main_guard": false,
      "is_abstract": false,
      "is_builtin": false,
      "is_decorated": false,
      "is_global": false,
      "is_nonlocal": true,
      "is_overridden_method": false,
      "is_overriding_method": false,
      "language": "python",
      "name": "item",
      "optimizing_parameter": false,
      "outcome": "definition",
      "owner_id": "dad31f3c3700c051124059ddad4aefa3613f3722ecf73b2ca9304094ab125a32",
      "path": "python/lexical-variables.py",
      "proof": "proven",
      "range": {
        "end_column": 13,
        "end_line": 6,
        "start_column": 9,
        "start_line": 6
      },
      "reachability": "open",
      "relation": "lexical_variable_definition",
      "result_type": "python_rule_fact",
      "scope_kind": "function",
      "self_assignment": false,
      "variable_id": "dad31f3c3700c051124059ddad4aefa3613f3722ecf73b2ca9304094ab125a32"
    },
    {
      "annotated_assignment": false,
      "annotation_only": false,
      "completeness": "complete",
      "definition_is_unused": false,
      "definition_kind": "assignment",
      "definition_order": 3,
      "first_definition": false,
      "has_read": true,
      "id": "646be582688bf5fea2b04621b536e8ab9cbfc64745b9d1eed70f96aebf73dad2",
      "in_main_guard": false,
      "is_abstract": false,
      "is_builtin": false,
      "is_decorated": false,
      "is_global": false,
      "is_nonlocal": true,
      "is_overridden_method": false,
      "is_overriding_method": false,
      "language": "python",
      "name": "item",
      "optimizing_parameter": false,
      "outcome": "definition",
      "owner_id": "dad31f3c3700c051124059ddad4aefa3613f3722ecf73b2ca9304094ab125a32",
      "path": "python/lexical-variables.py",
      "proof": "proven",
      "range": {
        "end_column": 13,
        "end_line": 10,
        "start_column": 9,
        "start_line": 10
      },
      "reachability": "open",
      "relation": "lexical_variable_definition",
      "result_type": "python_rule_fact",
      "scope_kind": "function",
      "self_assignment": false,
      "variable_id": "dad31f3c3700c051124059ddad4aefa3613f3722ecf73b2ca9304094ab125a32"
    },
    {
      "annotated_assignment": false,
      "annotation_only": false,
      "completeness": "complete",
      "definition_is_unused": false,
      "definition_kind": "assignment",
      "definition_order": 0,
      "first_definition": true,
      "has_read": true,
      "id": "551d8c541188ea2bdbff2458cfbabcf7f35d5fd384a864c90dd80e0477cecd08",
      "in_main_guard": false,
      "is_abstract": false,
      "is_builtin": false,
      "is_decorated": false,
      "is_global": false,
      "is_nonlocal": false,
      "is_overridden_method": false,
      "is_overriding_method": false,
      "language": "python",
      "name": "shared",
      "optimizing_parameter": false,
      "outcome": "definition",
      "owner_id": "f615ddc243f41a4313be89fc72e4aa0c06f41c4923a78ac0df7c142a3f1fa60b",
      "path": "python/lexical-variables.py",
      "proof": "proven",
      "range": {
        "end_column": 11,
        "end_line": 18,
        "start_column": 5,
        "start_line": 18
      },
      "reachability": "open",
      "relation": "lexical_variable_definition",
      "result_type": "python_rule_fact",
      "scope_kind": "function",
      "self_assignment": false,
      "variable_id": "f615ddc243f41a4313be89fc72e4aa0c06f41c4923a78ac0df7c142a3f1fa60b"
    },
    {
      "annotated_assignment": false,
      "annotation_only": false,
      "completeness": "complete",
      "definition_is_unused": true,
      "definition_kind": "assignment",
      "definition_order": 0,
      "first_definition": true,
      "has_read": false,
      "id": "81dbf74ee33cea081f44aee33f452a664613cea80f8a8dda82152a8fd53d1e88",
      "in_main_guard": false,
      "is_abstract": false,
      "is_builtin": false,
      "is_decorated": false,
      "is_global": false,
      "is_nonlocal": false,
      "is_overridden_method": false,
      "is_overriding_method": false,
      "language": "python",
      "name": "item",
      "optimizing_parameter": false,
      "outcome": "definition",
      "owner_id": "88895e058b234f75f588b7a20aa882659e5b58e7a164bbc4a64ea707264597cc",
      "path": "python/lexical-variables.py",
      "proof": "proven",
      "range": {
        "end_column": 9,
        "end_line": 22,
        "start_column": 5,
        "start_line": 22
      },
      "reachability": "open",
      "relation": "lexical_variable_definition",
      "result_type": "python_rule_fact",
      "scope_kind": "function",
      "self_assignment": false,
      "variable_id": "88895e058b234f75f588b7a20aa882659e5b58e7a164bbc4a64ea707264597cc"
    },
    {
      "annotated_assignment": false,
      "annotation_only": false,
      "completeness": "complete",
      "definition_is_unused": true,
      "definition_kind": "loop_target",
      "definition_order": 0,
      "first_definition": true,
      "has_read": true,
      "id": "21d1bafeae563731c258656ae765b08d8e628823cc27d21ded55ac9d52f73e40",
      "in_main_guard": false,
      "is_abstract": false,
      "is_builtin": false,
      "is_decorated": false,
      "is_global": false,
      "is_nonlocal": false,
      "is_overridden_method": false,
      "is_overriding_method": false,
      "language": "python",
      "name": "item",
      "optimizing_parameter": false,
      "outcome": "definition",
      "owner_id": "1bdd69213ff0ea1e10ba336ffd0e2b082c830d6538d877e4925689b66d3653c5",
      "path": "python/lexical-variables.py",
      "proof": "proven",
      "range": {
        "end_column": 26,
        "end_line": 23,
        "start_column": 22,
        "start_line": 23
      },
      "reachability": "open",
      "relation": "lexical_variable_definition",
      "result_type": "python_rule_fact",
      "scope_kind": "comprehension",
      "self_assignment": false,
      "variable_id": "1bdd69213ff0ea1e10ba336ffd0e2b082c830d6538d877e4925689b66d3653c5"
    },
    {
      "annotated_assignment": false,
      "annotation_only": false,
      "completeness": "complete",
      "definition_is_unused": false,
      "definition_kind": "loop_target",
      "definition_order": 0,
      "first_definition": true,
      "has_read": true,
      "id": "4c7d3b36610af42227c3de41a9241d645edaa913103f0e788add770d6768ca06",
      "in_main_guard": false,
      "is_abstract": false,
      "is_builtin": false,
      "is_decorated": false,
      "is_global": false,
      "is_nonlocal": false,
      "is_overridden_method": false,
      "is_overriding_method": false,
      "language": "python",
      "loop_has_body_read": true,
      "loop_policy_excluded": false,
      "name": "item",
      "optimizing_parameter": false,
      "outcome": "definition",
      "owner_id": "98ac45064344faa935501eb507c7b884654c6633d76e38fbfbd3d560ef87b9aa",
      "path": "python/lexical-variables.py",
      "proof": "proven",
      "range": {
        "end_column": 13,
        "end_line": 26,
        "start_column": 9,
        "start_line": 26
      },
      "reachability": "open",
      "relation": "lexical_variable_definition",
      "result_type": "python_rule_fact",
      "scope_kind": "function",
      "self_assignment": false,
      "variable_id": "98ac45064344faa935501eb507c7b884654c6633d76e38fbfbd3d560ef87b9aa"
    },
    {
      "annotated_assignment": false,
      "annotation_only": false,
      "completeness": "complete",
      "definition_is_unused": false,
      "definition_kind": "loop_target",
      "definition_order": 1,
      "first_definition": false,
      "has_read": true,
      "id": "b937f8a99da5a84c396a51f662d18d470c3bfdbfa100d8b02cd123271f21ff94",
      "in_main_guard": false,
      "is_abstract": false,
      "is_builtin": false,
      "is_decorated": false,
      "is_global": false,
      "is_nonlocal": false,
      "is_overridden_method": false,
      "is_overriding_method": false,
      "language": "python",
      "loop_has_body_read": false,
      "loop_policy_excluded": true,
      "name": "item",
      "optimizing_parameter": false,
      "outcome": "definition",
      "owner_id": "98ac45064344faa935501eb507c7b884654c6633d76e38fbfbd3d560ef87b9aa",
      "path": "python/lexical-variables.py",
      "proof": "proven",
      "range": {
        "end_column": 17,
        "end_line": 27,
        "start_column": 13,
        "start_line": 27
      },
      "reachability": "open",
      "relation": "lexical_variable_definition",
      "result_type": "python_rule_fact",
      "scope_kind": "function",
      "self_assignment": false,
      "variable_id": "98ac45064344faa935501eb507c7b884654c6633d76e38fbfbd3d560ef87b9aa"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:python-variable-uses:rql -->
```lisp
(where "python/lexical-variables.py"
  (filter :where (
      (relation eq lexical_variable_use)
      (name eq "item")
      (nested_scope eq true))
    (python-variable-uses
      (filter :where ((name eq "item"))
        (python-variable-of (occurrences))))))
```

<!-- code-query-case:python-variable-uses:json -->
```json
{
  "where": ["python/lexical-variables.py"],
  "occurrences": {},
  "steps": [
    {"op": "python_variable_of"},
    {"op": "filter", "where": [
      {"field": "name", "op": "eq", "value": {"string": "item"}}
    ]},
    {"op": "python_variable_uses"},
    {"op": "filter", "where": [
      {"field": "relation", "op": "eq", "value": {"enum": "lexical_variable_use"}},
      {"field": "name", "op": "eq", "value": {"string": "item"}},
      {"field": "nested_scope", "op": "eq", "value": {"boolean": true}}
    ]}
  ]
}
```

<!-- code-query-case:python-variable-uses:expected -->
```json
{
  "diagnostics": [
    {
      "code": "occurrence_role_unsupported",
      "impact": "incomplete",
      "language": "python",
      "message": "structural adapter for python does not support occurrence role(s): pattern_position"
    },
    {
      "code": "occurrence_role_unsupported",
      "impact": "incomplete",
      "language": "python",
      "message": "structural adapter for python does not support occurrence role(s): generated_source"
    }
  ],
  "results": [
    {
      "access_kind": "write",
      "completeness": "complete",
      "id": "c7bddc2907f7fe9fa58cf573254726ba51513320c3daa1134fc9a4e02370f0b7",
      "is_global": false,
      "is_nonlocal": true,
      "language": "python",
      "name": "item",
      "nested_scope": true,
      "outcome": "use",
      "owner_id": "dad31f3c3700c051124059ddad4aefa3613f3722ecf73b2ca9304094ab125a32",
      "path": "python/lexical-variables.py",
      "proof": "proven",
      "range": {
        "end_column": 13,
        "end_line": 10,
        "start_column": 9,
        "start_line": 10
      },
      "relation": "lexical_variable_use",
      "result_type": "python_rule_fact",
      "scope_kind": "function",
      "variable_id": "dad31f3c3700c051124059ddad4aefa3613f3722ecf73b2ca9304094ab125a32"
    },
    {
      "access_kind": "read",
      "completeness": "complete",
      "id": "e1431734401858db1d0fde4b14f90a69a5d14607cb3a7f0242f0b861a0eab127",
      "is_global": false,
      "is_nonlocal": true,
      "language": "python",
      "name": "item",
      "nested_scope": true,
      "outcome": "use",
      "owner_id": "dad31f3c3700c051124059ddad4aefa3613f3722ecf73b2ca9304094ab125a32",
      "path": "python/lexical-variables.py",
      "proof": "proven",
      "range": {
        "end_column": 20,
        "end_line": 10,
        "start_column": 16,
        "start_line": 10
      },
      "relation": "lexical_variable_use",
      "result_type": "python_rule_fact",
      "scope_kind": "function",
      "variable_id": "dad31f3c3700c051124059ddad4aefa3613f3722ecf73b2ca9304094ab125a32"
    },
    {
      "access_kind": "read",
      "completeness": "complete",
      "id": "110250c6c28c1431ba43a5e5b72297cfc500a1c091388315f183fb54760d5f0c",
      "is_global": false,
      "is_nonlocal": true,
      "language": "python",
      "name": "item",
      "nested_scope": true,
      "outcome": "use",
      "owner_id": "dad31f3c3700c051124059ddad4aefa3613f3722ecf73b2ca9304094ab125a32",
      "path": "python/lexical-variables.py",
      "proof": "proven",
      "range": {
        "end_column": 20,
        "end_line": 13,
        "start_column": 16,
        "start_line": 13
      },
      "relation": "lexical_variable_use",
      "result_type": "python_rule_fact",
      "scope_kind": "function",
      "variable_id": "dad31f3c3700c051124059ddad4aefa3613f3722ecf73b2ca9304094ab125a32"
    }
  ],
  "truncated": false
}
```

Same-name variables in different scopes remain separate identities. The peer
step returns a typed relation row with both variable ids and the related
scope. The module-definition flag lets a policy require a module assignment
outside a `__main__` guard.

<!-- code-query-case:python-variable-peers:rql -->
```lisp
(where "python/lexical-variables.py"
  (filter :where (
      (relation eq lexical_variable_peer)
      (scope_kind eq function)
      (related_scope_kind eq module)
      (related_has_definition_outside_main eq true))
    (python-variable-peers
      (filter :where ((name eq "shared"))
        (python-variable-of (bindings :name [shared]))))))
```

<!-- code-query-case:python-variable-peers:json -->
```json
{
  "where": ["python/lexical-variables.py"],
  "bindings": {"name": ["shared"]},
  "steps": [
    {"op": "python_variable_of"},
    {"op": "filter", "where": [
      {"field": "name", "op": "eq", "value": {"string": "shared"}}
    ]},
    {"op": "python_variable_peers"},
    {"op": "filter", "where": [
      {"field": "relation", "op": "eq", "value": {"enum": "lexical_variable_peer"}},
      {"field": "scope_kind", "op": "eq", "value": {"enum": "function"}},
      {"field": "related_scope_kind", "op": "eq", "value": {"enum": "module"}},
      {"field": "related_has_definition_outside_main", "op": "eq", "value": {"boolean": true}}
    ]}
  ]
}
```

<!-- code-query-case:python-variable-peers:expected -->
```json
{
  "results": [
    {
      "completeness": "complete",
      "definition_kind": "assignment",
      "definition_order": 0,
      "first_definition": true,
      "has_read": true,
      "id": "d83af9df2531e61d05e32762e588f26d6d5ee58be7e940c09523d89e66c94d2f",
      "in_main_guard": false,
      "is_builtin": false,
      "is_global": false,
      "is_nonlocal": false,
      "language": "python",
      "name": "shared",
      "optimizing_parameter": false,
      "outcome": "peer",
      "owner_id": "f615ddc243f41a4313be89fc72e4aa0c06f41c4923a78ac0df7c142a3f1fa60b",
      "path": "python/lexical-variables.py",
      "proof": "proven",
      "range": {
        "end_column": 11,
        "end_line": 18,
        "start_column": 5,
        "start_line": 18
      },
      "related_has_definition_outside_main": true,
      "related_has_deletion": false,
      "related_has_import": false,
      "related_is_pytest_fixture": false,
      "related_scope_kind": "module",
      "relation": "lexical_variable_peer",
      "result_type": "python_rule_fact",
      "scope_kind": "function",
      "self_assignment": false,
      "target_id": "5df709695362ab2ea6c82ee21a85b191de4eb92792284a3f1fd506abe57188ec",
      "variable_id": "f615ddc243f41a4313be89fc72e4aa0c06f41c4923a78ac0df7c142a3f1fa60b"
    }
  ],
  "truncated": false
}
```

The nested-loop relation compares loop targets after resolving them to the
same lexical variable. `nested_loop_has_outer_use` follows the CodeQL outer
loop predicate; `nested_loop_reused` is narrower and requires a read after
the inner loop, where its target may have replaced the outer value.

<!-- code-query-case:python-variable-nested-loops:rql -->
```lisp
(where "python/lexical-variables.py"
  (filter :where (
      (relation eq nested_loop_same_variable)
      (nested_loop_has_outer_use eq true)
      (nested_loop_reused eq true))
    (python-variable-nested-loops
      (python-variable-of (bindings :name [item])))))
```

<!-- code-query-case:python-variable-nested-loops:json -->
```json
{
  "where": ["python/lexical-variables.py"],
  "bindings": {"name": ["item"]},
  "steps": [
    {"op": "python_variable_of"},
    {"op": "python_variable_nested_loops"},
    {"op": "filter", "where": [
      {"field": "relation", "op": "eq", "value": {"enum": "nested_loop_same_variable"}},
      {"field": "nested_loop_has_outer_use", "op": "eq", "value": {"boolean": true}},
      {"field": "nested_loop_reused", "op": "eq", "value": {"boolean": true}}
    ]}
  ]
}
```

<!-- code-query-case:python-variable-nested-loops:expected -->
```json
{
  "results": [
    {
      "completeness": "complete",
      "id": "7d849995b0088cdfa42375b116383337a38417ccf250c425d0720ef706554e48",
      "language": "python",
      "name": "item",
      "nested_loop_has_outer_use": true,
      "nested_loop_reused": true,
      "outcome": "loop_pair",
      "owner_id": "98ac45064344faa935501eb507c7b884654c6633d76e38fbfbd3d560ef87b9aa",
      "path": "python/lexical-variables.py",
      "proof": "proven",
      "range": {
        "end_column": 17,
        "end_line": 28,
        "start_column": 9,
        "start_line": 27
      },
      "relation": "nested_loop_same_variable",
      "result_type": "python_rule_fact",
      "scope_kind": "function",
      "target_id": "c05e7c00f750b3727784664c92fe89abbc55b46d42ba4387c8ff99d87f274bbe",
      "variable_id": "98ac45064344faa935501eb507c7b884654c6633d76e38fbfbd3d560ef87b9aa"
    }
  ],
  "truncated": false
}
```

## Query Python Format, Raise, And Builtin Facts

These operations attach structured findings to format calls, raised expressions, exception-protocol methods, and references resolved to builtins. Each query starts from the syntax it analyzes, then applies the Python fact operation.

<!-- code-query-fixture:python/format.py -->
```python
def format_message(value):
    return "{0} {1}".format(value)
```

<!-- code-query-fixture:python/raise-legality.py -->
```python
def invalid_raise():
    raise 1
```

<!-- code-query-fixture:python/special-method-raise.py -->
```python
class BrokenLookup:
    def __getitem__(self, key):
        raise ValueError()
```

<!-- code-query-fixture:python/builtin.py -->
```python
def size():
    return len([])
```

<!-- code-query-fixture:python/not-implemented.py -->
```python
def unfinished():
    raise NotImplemented
```

<!-- code-query-case:python-format-issues:rql -->
```lisp
(result-detail compact
  (where "python/format.py"
    (python-format-issues (language python (call)))))
```

<!-- code-query-case:python-format-issues:json -->
```json
{"where":["python/format.py"],"languages":["python"],"match":{"kind":"call"},"steps":[{"op":"python_format_issues"}],"result_detail":"compact"}
```

<!-- code-query-case:python-format-issues:expected -->
```json
{
  "results": [
    {
      "completeness": "complete",
      "id": "dd3baf447104c67f9eadb883db88188c0851c25e8b1d4fd213c9a433255a0fa4",
      "language": "python",
      "outcome": "issue",
      "owner_id": null,
      "path": "python/format.py",
      "proof": "proven",
      "provenance": [
        {
          "seed": {
            "end_line": 2,
            "kind": "call",
            "path": "python/format.py",
            "result_type": "structural_match",
            "start_line": 2
          },
          "steps": [
            {
              "op": "python_format_issues",
              "result": {
                "id": "dd3baf447104c67f9eadb883db88188c0851c25e8b1d4fd213c9a433255a0fa4",
                "outcome": "issue",
                "path": "python/format.py",
                "range": {
                  "end_column": 35,
                  "end_line": 2,
                  "start_column": 12,
                  "start_line": 2
                },
                "relation": "str_format_missing_argument",
                "result_type": "python_rule_fact"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 35,
        "end_line": 2,
        "start_column": 12,
        "start_line": 2
      },
      "relation": "str_format_missing_argument",
      "result_type": "python_rule_fact"
    },
    {
      "completeness": "complete",
      "id": "492e21fd1ab2f953144f996cf90901ab52358269b3c3ffba28d4257f85924702",
      "language": "python",
      "outcome": "no_issue",
      "owner_id": null,
      "path": "python/format.py",
      "proof": "proven",
      "provenance": [
        {
          "seed": {
            "end_line": 2,
            "kind": "call",
            "path": "python/format.py",
            "result_type": "structural_match",
            "start_line": 2
          },
          "steps": [
            {
              "op": "python_format_issues",
              "result": {
                "id": "492e21fd1ab2f953144f996cf90901ab52358269b3c3ffba28d4257f85924702",
                "outcome": "no_issue",
                "path": "python/format.py",
                "range": {
                  "end_column": 35,
                  "end_line": 2,
                  "start_column": 12,
                  "start_line": 2
                },
                "relation": "str_format_missing_named_argument",
                "result_type": "python_rule_fact"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 35,
        "end_line": 2,
        "start_column": 12,
        "start_line": 2
      },
      "relation": "str_format_missing_named_argument",
      "result_type": "python_rule_fact"
    },
    {
      "completeness": "complete",
      "id": "e5d5a18f825595afaeb837000b427f46b9d49abc7376c6c2e21bdd443d364725",
      "language": "python",
      "outcome": "no_issue",
      "owner_id": null,
      "path": "python/format.py",
      "proof": "proven",
      "provenance": [
        {
          "seed": {
            "end_line": 2,
            "kind": "call",
            "path": "python/format.py",
            "result_type": "structural_match",
            "start_line": 2
          },
          "steps": [
            {
              "op": "python_format_issues",
              "result": {
                "id": "e5d5a18f825595afaeb837000b427f46b9d49abc7376c6c2e21bdd443d364725",
                "outcome": "no_issue",
                "path": "python/format.py",
                "range": {
                  "end_column": 21,
                  "end_line": 2,
                  "start_column": 12,
                  "start_line": 2
                },
                "relation": "str_format_mixed_fields",
                "result_type": "python_rule_fact"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 21,
        "end_line": 2,
        "start_column": 12,
        "start_line": 2
      },
      "relation": "str_format_mixed_fields",
      "result_type": "python_rule_fact"
    },
    {
      "completeness": "complete",
      "id": "86e62533de296ca57fe6a9443dd4df0184ca8ebc2ca95f49718879fb76f17edf",
      "language": "python",
      "outcome": "no_issue",
      "owner_id": null,
      "path": "python/format.py",
      "proof": "proven",
      "provenance": [
        {
          "seed": {
            "end_line": 2,
            "kind": "call",
            "path": "python/format.py",
            "result_type": "structural_match",
            "start_line": 2
          },
          "steps": [
            {
              "op": "python_format_issues",
              "result": {
                "id": "86e62533de296ca57fe6a9443dd4df0184ca8ebc2ca95f49718879fb76f17edf",
                "outcome": "no_issue",
                "path": "python/format.py",
                "range": {
                  "end_column": 35,
                  "end_line": 2,
                  "start_column": 12,
                  "start_line": 2
                },
                "relation": "str_format_surplus_argument",
                "result_type": "python_rule_fact"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 35,
        "end_line": 2,
        "start_column": 12,
        "start_line": 2
      },
      "relation": "str_format_surplus_argument",
      "result_type": "python_rule_fact"
    },
    {
      "completeness": "complete",
      "id": "3d143360e9d6c1b54f4325d3d949cfadbee402287c4ea6c0473f7ce3e44c2034",
      "language": "python",
      "outcome": "no_issue",
      "owner_id": null,
      "path": "python/format.py",
      "proof": "proven",
      "provenance": [
        {
          "seed": {
            "end_line": 2,
            "kind": "call",
            "path": "python/format.py",
            "result_type": "structural_match",
            "start_line": 2
          },
          "steps": [
            {
              "op": "python_format_issues",
              "result": {
                "id": "3d143360e9d6c1b54f4325d3d949cfadbee402287c4ea6c0473f7ce3e44c2034",
                "outcome": "no_issue",
                "path": "python/format.py",
                "range": {
                  "end_column": 35,
                  "end_line": 2,
                  "start_column": 12,
                  "start_line": 2
                },
                "relation": "str_format_surplus_named_argument",
                "result_type": "python_rule_fact"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 35,
        "end_line": 2,
        "start_column": 12,
        "start_line": 2
      },
      "relation": "str_format_surplus_named_argument",
      "result_type": "python_rule_fact"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:python-raise-legality:rql -->
```lisp
(result-detail compact
  (where "python/raise-legality.py"
    (python-raise-legality (language python (throw)))))
```

<!-- code-query-case:python-raise-legality:json -->
```json
{"where":["python/raise-legality.py"],"languages":["python"],"match":{"kind":"throw"},"steps":[{"op":"python_raise_legality"}],"result_detail":"compact"}
```

<!-- code-query-case:python-raise-legality:expected -->
```json
{
  "results": [
    {
      "completeness": "complete",
      "id": "cc21b8dd956ec0dbe64a1a0613781bd33729cdd2605110976d52a8dc25bd38dd",
      "language": "python",
      "operand_kind": "literal",
      "outcome": "illegal",
      "owner_id": null,
      "path": "python/raise-legality.py",
      "proof": "proven",
      "provenance": [
        {
          "seed": {
            "end_line": 2,
            "kind": "throw",
            "path": "python/raise-legality.py",
            "result_type": "structural_match",
            "start_line": 2
          },
          "steps": [
            {
              "op": "python_raise_legality",
              "result": {
                "id": "cc21b8dd956ec0dbe64a1a0613781bd33729cdd2605110976d52a8dc25bd38dd",
                "outcome": "illegal",
                "path": "python/raise-legality.py",
                "range": {
                  "end_column": 12,
                  "end_line": 2,
                  "start_column": 5,
                  "start_line": 2
                },
                "relation": "illegal_raise",
                "result_type": "python_rule_fact"
              }
            }
          ]
        }
      ],
      "raised_expression": "1",
      "range": {
        "end_column": 12,
        "end_line": 2,
        "start_column": 5,
        "start_line": 2
      },
      "reason": "raise_operand_is_not_an_exception",
      "relation": "illegal_raise",
      "result_type": "python_rule_fact"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:python-special-method-raise:rql -->
```lisp
(result-detail compact
  (where "python/special-method-raise.py"
    (python-special-method-raise (language python (throw)))))
```

<!-- code-query-case:python-special-method-raise:json -->
```json
{"where":["python/special-method-raise.py"],"languages":["python"],"match":{"kind":"throw"},"steps":[{"op":"python_special_method_raise"}],"result_detail":"compact"}
```

<!-- code-query-case:python-special-method-raise:expected -->
```json
{
  "results": [
    {
      "completeness": "complete",
      "exception_class": "builtins.ValueError",
      "expected_exception": "LookupError or TypeError",
      "id": "bb0db25c9d27e2c0cb7c00e62a8fd6cbde48e61779e00d6b7f5ef206eed5c08b",
      "language": "python",
      "operand_kind": "exception_instance",
      "outcome": "unexpected",
      "owner_id": "a5ac33b7096a781cfb0426aa1a53fed5ca2cd44827807d9fe3655a0cba4fbd5c",
      "path": "python/special-method-raise.py",
      "proof": "proven",
      "provenance": [
        {
          "seed": {
            "end_line": 3,
            "kind": "throw",
            "path": "python/special-method-raise.py",
            "result_type": "structural_match",
            "start_line": 3
          },
          "steps": [
            {
              "op": "python_special_method_raise",
              "result": {
                "id": "bb0db25c9d27e2c0cb7c00e62a8fd6cbde48e61779e00d6b7f5ef206eed5c08b",
                "outcome": "unexpected",
                "path": "python/special-method-raise.py",
                "range": {
                  "end_column": 32,
                  "end_line": 2,
                  "start_column": 5,
                  "start_line": 2
                },
                "relation": "unexpected_raise_in_special_method",
                "result_type": "python_rule_fact"
              }
            }
          ]
        }
      ],
      "raised_expression": "ValueError()",
      "range": {
        "end_column": 32,
        "end_line": 2,
        "start_column": 5,
        "start_line": 2
      },
      "reason": "exception_family_mismatch",
      "relation": "unexpected_raise_in_special_method",
      "result_type": "python_rule_fact"
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:python-builtin-identity:rql -->
```lisp
(result-detail compact
  (where "python/builtin.py"
    (filter :where ((relation eq builtin_identity))
      (python-builtin-identity
        (language python
          (occurrences :class reference :role [value_reference]))))))
```

<!-- code-query-case:python-builtin-identity:json -->
```json
{"where":["python/builtin.py"],"languages":["python"],"occurrences":{"class":"reference","role":["value_reference"]},"steps":[{"op":"python_builtin_identity"},{"op":"filter","where":[{"field":"relation","op":"eq","value":{"enum":"builtin_identity"}}]}],"result_detail":"compact"}
```

<!-- code-query-case:python-builtin-identity:expected -->
```json
{
  "results": [
    {
      "call_callee": true,
      "completeness": "complete",
      "id": "b635848a471834fa9807c6d7b0de493665bebd92a720809469d80dd0e20a0296",
      "language": "python",
      "outcome": "builtin",
      "owner_id": null,
      "path": "python/builtin.py",
      "proof": "proven",
      "range": {
        "end_column": 15,
        "end_line": 2,
        "start_column": 12,
        "start_line": 2
      },
      "relation": "builtin_identity",
      "result_type": "python_rule_fact",
      "target_id": "builtins.len"
    }
  ],
  "truncated": false
}
```

To keep only the exact builtin function occurrence in a call, filter the
`python_builtin_identity` result on `call_callee`. In `print(print)`, this
selects the callee at column 1 and excludes the same-named argument at column 7.

```json
{"languages":["python"],"match":{"kind":"call","callee":{"name":"print"}},"steps":[{"op":"occurrences_in"},{"op":"python_builtin_identity"},{"op":"filter","where":[{"field":"relation","op":"eq","value":{"enum":"builtin_identity"}},{"field":"outcome","op":"eq","value":{"enum":"builtin"}},{"field":"call_callee","op":"eq","value":{"boolean":true}}]}]}
```

<!-- code-query-case:python-raise-not-implemented:rql -->
```lisp
(result-detail compact
  (where "python/not-implemented.py"
    (python-raise-not-implemented (language python (throw)))))
```

<!-- code-query-case:python-raise-not-implemented:json -->
```json
{"where":["python/not-implemented.py"],"languages":["python"],"match":{"kind":"throw"},"steps":[{"op":"python_raise_not_implemented"}],"result_detail":"compact"}
```

<!-- code-query-case:python-raise-not-implemented:expected -->
```json
{
  "results": [
    {
      "completeness": "complete",
      "id": "ae9dedf69de69e1f9c75e5f3b3120a9eebfff0c90cd3d8322ec3755180016a1e",
      "language": "python",
      "outcome": "builtin",
      "owner_id": null,
      "path": "python/not-implemented.py",
      "proof": "proven",
      "provenance": [
        {
          "seed": {
            "end_line": 2,
            "kind": "throw",
            "path": "python/not-implemented.py",
            "result_type": "structural_match",
            "start_line": 2
          },
          "steps": [
            {
              "op": "python_raise_not_implemented",
              "result": {
                "id": "ae9dedf69de69e1f9c75e5f3b3120a9eebfff0c90cd3d8322ec3755180016a1e",
                "outcome": "builtin",
                "path": "python/not-implemented.py",
                "range": {
                  "end_column": 25,
                  "end_line": 2,
                  "start_column": 11,
                  "start_line": 2
                },
                "relation": "raise_not_implemented",
                "result_type": "python_rule_fact"
              }
            }
          ]
        }
      ],
      "raised_expression": "NotImplemented",
      "range": {
        "end_column": 25,
        "end_line": 2,
        "start_column": 11,
        "start_line": 2
      },
      "relation": "raise_not_implemented",
      "result_type": "python_rule_fact",
      "target_id": "builtins.NotImplemented"
    }
  ],
  "truncated": false
}
```
## Constant and Identity Comparisons

The Python comparison filters use the comparison's AST operands and operator. Constant tuples, string concatenation, and unary `not` and `~` are recognized without folding general arithmetic. `python-comparison-using-is` identifies comparisons where a builtin value type or a complete class MRO supplies value equality, while `python-comparison-using-is-non-portable` selects small integers and short strings whose identities depend on CPython interning.

<!-- code-query-fixture:python/comparison-identity.py -->
```python
class ValueEquality:
    def __eq__(self, other):
        return True

class IdentityOnly:
    pass

def compare():
    constants = (1, "a" + "b", "c" "d", not False, ~1) == (1, "ab", "cd", True, -2)
    custom_equality = ValueEquality() is ValueEquality()
    builtin_string = "a" is "b"
    singleton = None is None
    identity_only = IdentityOnly() is IdentityOnly()
    small_integer = 1 is 2
    short_string = "a" is "b"
    zero = 0 is 0
    empty_string = "" is ""
    long_string = "several characters" is "several characters"
```

<!-- code-query-case:comparison-constants:rql -->
```lisp
(where "python/comparison-identity.py"
  (python-comparison-constants (language python (comparison))))
```

<!-- code-query-case:comparison-constants:json -->
```json
{
  "where": ["python/comparison-identity.py"],
  "languages": ["python"],
  "match": {"kind": "comparison"},
  "steps": [{"op": "python_comparison_constants"}]
}
```

<!-- code-query-case:comparison-constants:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "python.comparison-identity.compare",
      "end_line": 9,
      "kind": "comparison",
      "language": "python",
      "path": "python/comparison-identity.py",
      "provenance": [
        {
          "seed": {
            "end_line": 9,
            "kind": "comparison",
            "path": "python/comparison-identity.py",
            "result_type": "structural_match",
            "start_line": 9
          },
          "steps": [
            {
              "op": "python_comparison_constants",
              "result": {
                "end_line": 9,
                "kind": "comparison",
                "path": "python/comparison-identity.py",
                "result_type": "structural_match",
                "start_line": 9
              }
            }
          ]
        }
      ],
      "result_type": "structural_match",
      "start_line": 9,
      "text": "(1, \"a\" + \"b\", \"c\" \"d\", not False, ~1) == (1, \"ab\", \"cd\", True, -2)"
    },
    {
      "enclosing_symbol": "python.comparison-identity.compare",
      "end_line": 11,
      "kind": "comparison",
      "language": "python",
      "path": "python/comparison-identity.py",
      "provenance": [
        {
          "seed": {
            "end_line": 11,
            "kind": "comparison",
            "path": "python/comparison-identity.py",
            "result_type": "structural_match",
            "start_line": 11
          },
          "steps": [
            {
              "op": "python_comparison_constants",
              "result": {
                "end_line": 11,
                "kind": "comparison",
                "path": "python/comparison-identity.py",
                "result_type": "structural_match",
                "start_line": 11
              }
            }
          ]
        }
      ],
      "result_type": "structural_match",
      "start_line": 11,
      "text": "\"a\" is \"b\""
    },
    {
      "enclosing_symbol": "python.comparison-identity.compare",
      "end_line": 12,
      "kind": "comparison",
      "language": "python",
      "path": "python/comparison-identity.py",
      "provenance": [
        {
          "seed": {
            "end_line": 12,
            "kind": "comparison",
            "path": "python/comparison-identity.py",
            "result_type": "structural_match",
            "start_line": 12
          },
          "steps": [
            {
              "op": "python_comparison_constants",
              "result": {
                "end_line": 12,
                "kind": "comparison",
                "path": "python/comparison-identity.py",
                "result_type": "structural_match",
                "start_line": 12
              }
            }
          ]
        }
      ],
      "result_type": "structural_match",
      "start_line": 12,
      "text": "None is None"
    },
    {
      "enclosing_symbol": "python.comparison-identity.compare",
      "end_line": 14,
      "kind": "comparison",
      "language": "python",
      "path": "python/comparison-identity.py",
      "provenance": [
        {
          "seed": {
            "end_line": 14,
            "kind": "comparison",
            "path": "python/comparison-identity.py",
            "result_type": "structural_match",
            "start_line": 14
          },
          "steps": [
            {
              "op": "python_comparison_constants",
              "result": {
                "end_line": 14,
                "kind": "comparison",
                "path": "python/comparison-identity.py",
                "result_type": "structural_match",
                "start_line": 14
              }
            }
          ]
        }
      ],
      "result_type": "structural_match",
      "start_line": 14,
      "text": "1 is 2"
    },
    {
      "enclosing_symbol": "python.comparison-identity.compare",
      "end_line": 15,
      "kind": "comparison",
      "language": "python",
      "path": "python/comparison-identity.py",
      "provenance": [
        {
          "seed": {
            "end_line": 15,
            "kind": "comparison",
            "path": "python/comparison-identity.py",
            "result_type": "structural_match",
            "start_line": 15
          },
          "steps": [
            {
              "op": "python_comparison_constants",
              "result": {
                "end_line": 15,
                "kind": "comparison",
                "path": "python/comparison-identity.py",
                "result_type": "structural_match",
                "start_line": 15
              }
            }
          ]
        }
      ],
      "result_type": "structural_match",
      "start_line": 15,
      "text": "\"a\" is \"b\""
    },
    {
      "enclosing_symbol": "python.comparison-identity.compare",
      "end_line": 16,
      "kind": "comparison",
      "language": "python",
      "path": "python/comparison-identity.py",
      "provenance": [
        {
          "seed": {
            "end_line": 16,
            "kind": "comparison",
            "path": "python/comparison-identity.py",
            "result_type": "structural_match",
            "start_line": 16
          },
          "steps": [
            {
              "op": "python_comparison_constants",
              "result": {
                "end_line": 16,
                "kind": "comparison",
                "path": "python/comparison-identity.py",
                "result_type": "structural_match",
                "start_line": 16
              }
            }
          ]
        }
      ],
      "result_type": "structural_match",
      "start_line": 16,
      "text": "0 is 0"
    },
    {
      "enclosing_symbol": "python.comparison-identity.compare",
      "end_line": 17,
      "kind": "comparison",
      "language": "python",
      "path": "python/comparison-identity.py",
      "provenance": [
        {
          "seed": {
            "end_line": 17,
            "kind": "comparison",
            "path": "python/comparison-identity.py",
            "result_type": "structural_match",
            "start_line": 17
          },
          "steps": [
            {
              "op": "python_comparison_constants",
              "result": {
                "end_line": 17,
                "kind": "comparison",
                "path": "python/comparison-identity.py",
                "result_type": "structural_match",
                "start_line": 17
              }
            }
          ]
        }
      ],
      "result_type": "structural_match",
      "start_line": 17,
      "text": "\"\" is \"\""
    },
    {
      "enclosing_symbol": "python.comparison-identity.compare",
      "end_line": 18,
      "kind": "comparison",
      "language": "python",
      "path": "python/comparison-identity.py",
      "provenance": [
        {
          "seed": {
            "end_line": 18,
            "kind": "comparison",
            "path": "python/comparison-identity.py",
            "result_type": "structural_match",
            "start_line": 18
          },
          "steps": [
            {
              "op": "python_comparison_constants",
              "result": {
                "end_line": 18,
                "kind": "comparison",
                "path": "python/comparison-identity.py",
                "result_type": "structural_match",
                "start_line": 18
              }
            }
          ]
        }
      ],
      "result_type": "structural_match",
      "start_line": 18,
      "text": "\"several characters\" is \"several characters\""
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:comparison-using-is:rql -->
```lisp
(where "python/comparison-identity.py"
  (python-comparison-using-is (language python (comparison))))
```

<!-- code-query-case:comparison-using-is:json -->
```json
{
  "where": ["python/comparison-identity.py"],
  "languages": ["python"],
  "match": {"kind": "comparison"},
  "steps": [{"op": "python_comparison_using_is"}]
}
```

<!-- code-query-case:comparison-using-is:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "python.comparison-identity.compare",
      "end_line": 10,
      "kind": "comparison",
      "language": "python",
      "path": "python/comparison-identity.py",
      "provenance": [
        {
          "seed": {
            "end_line": 10,
            "kind": "comparison",
            "path": "python/comparison-identity.py",
            "result_type": "structural_match",
            "start_line": 10
          },
          "steps": [
            {
              "op": "python_comparison_using_is",
              "result": {
                "end_line": 10,
                "kind": "comparison",
                "path": "python/comparison-identity.py",
                "result_type": "structural_match",
                "start_line": 10
              }
            }
          ]
        }
      ],
      "result_type": "structural_match",
      "start_line": 10,
      "text": "ValueEquality() is ValueEquality()"
    },
    {
      "enclosing_symbol": "python.comparison-identity.compare",
      "end_line": 11,
      "kind": "comparison",
      "language": "python",
      "path": "python/comparison-identity.py",
      "provenance": [
        {
          "seed": {
            "end_line": 11,
            "kind": "comparison",
            "path": "python/comparison-identity.py",
            "result_type": "structural_match",
            "start_line": 11
          },
          "steps": [
            {
              "op": "python_comparison_using_is",
              "result": {
                "end_line": 11,
                "kind": "comparison",
                "path": "python/comparison-identity.py",
                "result_type": "structural_match",
                "start_line": 11
              }
            }
          ]
        }
      ],
      "result_type": "structural_match",
      "start_line": 11,
      "text": "\"a\" is \"b\""
    },
    {
      "enclosing_symbol": "python.comparison-identity.compare",
      "end_line": 14,
      "kind": "comparison",
      "language": "python",
      "path": "python/comparison-identity.py",
      "provenance": [
        {
          "seed": {
            "end_line": 14,
            "kind": "comparison",
            "path": "python/comparison-identity.py",
            "result_type": "structural_match",
            "start_line": 14
          },
          "steps": [
            {
              "op": "python_comparison_using_is",
              "result": {
                "end_line": 14,
                "kind": "comparison",
                "path": "python/comparison-identity.py",
                "result_type": "structural_match",
                "start_line": 14
              }
            }
          ]
        }
      ],
      "result_type": "structural_match",
      "start_line": 14,
      "text": "1 is 2"
    },
    {
      "enclosing_symbol": "python.comparison-identity.compare",
      "end_line": 15,
      "kind": "comparison",
      "language": "python",
      "path": "python/comparison-identity.py",
      "provenance": [
        {
          "seed": {
            "end_line": 15,
            "kind": "comparison",
            "path": "python/comparison-identity.py",
            "result_type": "structural_match",
            "start_line": 15
          },
          "steps": [
            {
              "op": "python_comparison_using_is",
              "result": {
                "end_line": 15,
                "kind": "comparison",
                "path": "python/comparison-identity.py",
                "result_type": "structural_match",
                "start_line": 15
              }
            }
          ]
        }
      ],
      "result_type": "structural_match",
      "start_line": 15,
      "text": "\"a\" is \"b\""
    },
    {
      "enclosing_symbol": "python.comparison-identity.compare",
      "end_line": 16,
      "kind": "comparison",
      "language": "python",
      "path": "python/comparison-identity.py",
      "provenance": [
        {
          "seed": {
            "end_line": 16,
            "kind": "comparison",
            "path": "python/comparison-identity.py",
            "result_type": "structural_match",
            "start_line": 16
          },
          "steps": [
            {
              "op": "python_comparison_using_is",
              "result": {
                "end_line": 16,
                "kind": "comparison",
                "path": "python/comparison-identity.py",
                "result_type": "structural_match",
                "start_line": 16
              }
            }
          ]
        }
      ],
      "result_type": "structural_match",
      "start_line": 16,
      "text": "0 is 0"
    },
    {
      "enclosing_symbol": "python.comparison-identity.compare",
      "end_line": 17,
      "kind": "comparison",
      "language": "python",
      "path": "python/comparison-identity.py",
      "provenance": [
        {
          "seed": {
            "end_line": 17,
            "kind": "comparison",
            "path": "python/comparison-identity.py",
            "result_type": "structural_match",
            "start_line": 17
          },
          "steps": [
            {
              "op": "python_comparison_using_is",
              "result": {
                "end_line": 17,
                "kind": "comparison",
                "path": "python/comparison-identity.py",
                "result_type": "structural_match",
                "start_line": 17
              }
            }
          ]
        }
      ],
      "result_type": "structural_match",
      "start_line": 17,
      "text": "\"\" is \"\""
    },
    {
      "enclosing_symbol": "python.comparison-identity.compare",
      "end_line": 18,
      "kind": "comparison",
      "language": "python",
      "path": "python/comparison-identity.py",
      "provenance": [
        {
          "seed": {
            "end_line": 18,
            "kind": "comparison",
            "path": "python/comparison-identity.py",
            "result_type": "structural_match",
            "start_line": 18
          },
          "steps": [
            {
              "op": "python_comparison_using_is",
              "result": {
                "end_line": 18,
                "kind": "comparison",
                "path": "python/comparison-identity.py",
                "result_type": "structural_match",
                "start_line": 18
              }
            }
          ]
        }
      ],
      "result_type": "structural_match",
      "start_line": 18,
      "text": "\"several characters\" is \"several characters\""
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:comparison-using-is-non-portable:rql -->
```lisp
(where "python/comparison-identity.py"
  (python-comparison-using-is-non-portable (language python (comparison))))
```

<!-- code-query-case:comparison-using-is-non-portable:json -->
```json
{
  "where": ["python/comparison-identity.py"],
  "languages": ["python"],
  "match": {"kind": "comparison"},
  "steps": [{"op": "python_comparison_using_is_non_portable"}]
}
```

<!-- code-query-case:comparison-using-is-non-portable:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "python.comparison-identity.compare",
      "end_line": 11,
      "kind": "comparison",
      "language": "python",
      "path": "python/comparison-identity.py",
      "provenance": [
        {
          "seed": {
            "end_line": 11,
            "kind": "comparison",
            "path": "python/comparison-identity.py",
            "result_type": "structural_match",
            "start_line": 11
          },
          "steps": [
            {
              "op": "python_comparison_using_is_non_portable",
              "result": {
                "end_line": 11,
                "kind": "comparison",
                "path": "python/comparison-identity.py",
                "result_type": "structural_match",
                "start_line": 11
              }
            }
          ]
        }
      ],
      "result_type": "structural_match",
      "start_line": 11,
      "text": "\"a\" is \"b\""
    },
    {
      "enclosing_symbol": "python.comparison-identity.compare",
      "end_line": 14,
      "kind": "comparison",
      "language": "python",
      "path": "python/comparison-identity.py",
      "provenance": [
        {
          "seed": {
            "end_line": 14,
            "kind": "comparison",
            "path": "python/comparison-identity.py",
            "result_type": "structural_match",
            "start_line": 14
          },
          "steps": [
            {
              "op": "python_comparison_using_is_non_portable",
              "result": {
                "end_line": 14,
                "kind": "comparison",
                "path": "python/comparison-identity.py",
                "result_type": "structural_match",
                "start_line": 14
              }
            }
          ]
        }
      ],
      "result_type": "structural_match",
      "start_line": 14,
      "text": "1 is 2"
    },
    {
      "enclosing_symbol": "python.comparison-identity.compare",
      "end_line": 15,
      "kind": "comparison",
      "language": "python",
      "path": "python/comparison-identity.py",
      "provenance": [
        {
          "seed": {
            "end_line": 15,
            "kind": "comparison",
            "path": "python/comparison-identity.py",
            "result_type": "structural_match",
            "start_line": 15
          },
          "steps": [
            {
              "op": "python_comparison_using_is_non_portable",
              "result": {
                "end_line": 15,
                "kind": "comparison",
                "path": "python/comparison-identity.py",
                "result_type": "structural_match",
                "start_line": 15
              }
            }
          ]
        }
      ],
      "result_type": "structural_match",
      "start_line": 15,
      "text": "\"a\" is \"b\""
    }
  ],
  "truncated": false
}
```
