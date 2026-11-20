---
title: Python inheritance inference
description: Read precise failure facts for unresolved Python bases while retaining open hierarchy coverage.
---

> Last verified end to end: 2026-11-12 (`query_code` schema version 1).

A written base can fail resolution while the fact identifying that base remains definite. The broader hierarchy stays open. This example uses a separate project from the [Python tutorial](/code-query-tutorials/python/) so the deliberately unresolved base does not affect unrelated subclass queries.

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
{
  "diagnostics": [
    {
      "code": "python_hierarchy_derivation_incomplete",
      "impact": "incomplete",
      "incompleteness": "content",
      "language": "python",
      "message": "Python class hierarchy is open: unresolved_base",
      "source": {
        "end_byte": 70,
        "path": "python/inference.py",
        "range": {
          "end_column": 9,
          "end_line": 5,
          "start_column": 1,
          "start_line": 4
        },
        "start_byte": 27
      },
      "step_index": 1,
      "step_op": "class_hierarchy"
    }
  ],
  "results": [
    {
      "ancestry_basis": {
        "claims": []
      },
      "base_resolution": "unresolved",
      "base_spelling": "MissingBase",
      "coverage": "complete",
      "fact_kind": "inference_failure",
      "id": "<public-id>",
      "language": "python",
      "ordinal": 0,
      "outcome": "unresolved",
      "path": "python/inference.py",
      "provenance": [
        {
          "seed": {
            "end_line": 5,
            "kind": "class",
            "path": "python/inference.py",
            "result_type": "structural_match",
            "start_line": 4
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 5,
                "fq_name": "python.inference.UnresolvedBase",
                "kind": "class",
                "path": "python/inference.py",
                "result_type": "declaration",
                "start_line": 4
              }
            },
            {
              "op": "class_hierarchy",
              "result": {
                "ancestry_basis": {
                  "claims": []
                },
                "coverage": "complete",
                "declaration_id": null,
                "fact_kind": "inference_failure",
                "id": "<public-id>",
                "outcome": "unresolved",
                "owner_id": null,
                "path": "python/inference.py",
                "range": {
                  "end_column": 9,
                  "end_line": 5,
                  "start_column": 1,
                  "start_line": 4
                },
                "reason": "unresolved_base",
                "result_type": "python_hierarchy_fact",
                "root_id": "<public-id>",
                "target_id": null,
                "target_owner_id": null
              }
            },
            {
              "op": "filter",
              "result": {
                "ancestry_basis": {
                  "claims": []
                },
                "coverage": "complete",
                "declaration_id": null,
                "fact_kind": "inference_failure",
                "id": "<public-id>",
                "outcome": "unresolved",
                "owner_id": null,
                "path": "python/inference.py",
                "range": {
                  "end_column": 9,
                  "end_line": 5,
                  "start_column": 1,
                  "start_line": 4
                },
                "reason": "unresolved_base",
                "result_type": "python_hierarchy_fact",
                "root_id": "<public-id>",
                "target_id": null,
                "target_owner_id": null
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 9,
        "end_line": 5,
        "start_column": 1,
        "start_line": 4
      },
      "reason": "unresolved_base",
      "result_type": "python_hierarchy_fact",
      "root": {
        "end_line": 5,
        "fq_name": "python.inference.UnresolvedBase",
        "kind": "class",
        "language": "python",
        "path": "python/inference.py",
        "signature": "class UnresolvedBase(MissingBase):",
        "start_line": 4
      },
      "root_declaration_id": "<public-id>",
      "root_id": "<public-id>"
    }
  ],
  "truncated": false
}
```
