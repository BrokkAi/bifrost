---
title: Typed Set Composition
description: Combine compatible query_code pipelines with union, intersection, and subtraction.
---

> Last verified end to end: 2026-07-16 (`query_code` schema version 2).

Typed set composition combines the terminal values of complete query branches. Every branch at one set node must produce the same domain: structural matches, declarations, reference sites, call sites, expression sites, receiver analyses, or files. The result can then feed another ordinary typed step.

This executable project has one caller of only `legacy`, one caller of both APIs, and one caller of only `replacement`.

<!-- code-query-fixture:legacy.py -->
```python
def legacy():
    pass
```

<!-- code-query-fixture:replacement.py -->
```python
def replacement():
    pass
```

<!-- code-query-fixture:old_user.py -->
```python
from legacy import legacy

def old_user():
    legacy()
```

<!-- code-query-fixture:mixed_user.py -->
```python
from legacy import legacy
from replacement import replacement

def mixed_user():
    legacy()
    replacement()
```

<!-- code-query-fixture:new_user.py -->
```python
from replacement import replacement

def new_user():
    replacement()
```

Each operand below finds an API declaration, converts it to its exact project file, and follows resolved reverse import edges. Composition therefore compares exact file identities; it does not compare rendered strings or guess from import text.

## Union: Either API

`union` returns every endpoint once. Ordering is first appearance by branch order, followed by the deterministic order inside that branch. When the same endpoint appears in several branches, its bounded provenance contains every contributing branch path.

<!-- code-query-case:union:rql -->
```lisp
(union
  (importers-of (file-of (function :name "legacy")))
  (importers-of (file-of (function :name "replacement"))))
```

<!-- code-query-case:union:json -->
```json
{
  "union": [
    {
      "match": { "kind": "function", "name": "legacy" },
      "steps": [{ "op": "file_of" }, { "op": "importers_of" }]
    },
    {
      "match": { "kind": "function", "name": "replacement" },
      "steps": [{ "op": "file_of" }, { "op": "importers_of" }]
    }
  ]
}
```

<!-- code-query-case:union:expected -->
```json
{
  "results": [
    {
      "result_type": "file",
      "path": "mixed_user.py",
      "language": "python",
      "provenance": [
        {
          "branch": [0],
          "seed": {
            "result_type": "structural_match",
            "path": "legacy.py",
            "kind": "function",
            "start_line": 1,
            "end_line": 2
          },
          "steps": [
            {
              "op": "file_of",
              "result": { "result_type": "file", "path": "legacy.py" }
            },
            {
              "op": "importers_of",
              "result": { "result_type": "file", "path": "mixed_user.py" }
            }
          ]
        },
        {
          "branch": [1],
          "seed": {
            "result_type": "structural_match",
            "path": "replacement.py",
            "kind": "function",
            "start_line": 1,
            "end_line": 2
          },
          "steps": [
            {
              "op": "file_of",
              "result": { "result_type": "file", "path": "replacement.py" }
            },
            {
              "op": "importers_of",
              "result": { "result_type": "file", "path": "mixed_user.py" }
            }
          ]
        }
      ]
    },
    {
      "result_type": "file",
      "path": "old_user.py",
      "language": "python",
      "provenance": [
        {
          "branch": [0],
          "seed": {
            "result_type": "structural_match",
            "path": "legacy.py",
            "kind": "function",
            "start_line": 1,
            "end_line": 2
          },
          "steps": [
            {
              "op": "file_of",
              "result": { "result_type": "file", "path": "legacy.py" }
            },
            {
              "op": "importers_of",
              "result": { "result_type": "file", "path": "old_user.py" }
            }
          ]
        }
      ]
    },
    {
      "result_type": "file",
      "path": "new_user.py",
      "language": "python",
      "provenance": [
        {
          "branch": [1],
          "seed": {
            "result_type": "structural_match",
            "path": "replacement.py",
            "kind": "function",
            "start_line": 1,
            "end_line": 2
          },
          "steps": [
            {
              "op": "file_of",
              "result": { "result_type": "file", "path": "replacement.py" }
            },
            {
              "op": "importers_of",
              "result": { "result_type": "file", "path": "new_user.py" }
            }
          ]
        }
      ]
    }
  ],
  "truncated": false
}
```

## Intersection: Both APIs

`intersect` keeps endpoints present in every branch and preserves the first branch's order. Retained endpoints carry provenance from every operand.

<!-- code-query-case:intersect:rql -->
```lisp
(intersect
  (importers-of (file-of (function :name "legacy")))
  (importers-of (file-of (function :name "replacement"))))
```

<!-- code-query-case:intersect:json -->
```json
{
  "intersect": [
    {
      "match": { "kind": "function", "name": "legacy" },
      "steps": [{ "op": "file_of" }, { "op": "importers_of" }]
    },
    {
      "match": { "kind": "function", "name": "replacement" },
      "steps": [{ "op": "file_of" }, { "op": "importers_of" }]
    }
  ]
}
```

<!-- code-query-case:intersect:expected -->
```json
{
  "results": [
    {
      "result_type": "file",
      "path": "mixed_user.py",
      "language": "python",
      "provenance": [
        {
          "branch": [0],
          "seed": {
            "result_type": "structural_match",
            "path": "legacy.py",
            "kind": "function",
            "start_line": 1,
            "end_line": 2
          },
          "steps": [
            {
              "op": "file_of",
              "result": { "result_type": "file", "path": "legacy.py" }
            },
            {
              "op": "importers_of",
              "result": { "result_type": "file", "path": "mixed_user.py" }
            }
          ]
        },
        {
          "branch": [1],
          "seed": {
            "result_type": "structural_match",
            "path": "replacement.py",
            "kind": "function",
            "start_line": 1,
            "end_line": 2
          },
          "steps": [
            {
              "op": "file_of",
              "result": { "result_type": "file", "path": "replacement.py" }
            },
            {
              "op": "importers_of",
              "result": { "result_type": "file", "path": "mixed_user.py" }
            }
          ]
        }
      ]
    }
  ],
  "truncated": false
}
```

## Except: Legacy-Only Callers

`except` keeps endpoints from its first branch that occur in none of the later branches. It preserves first-branch order and provenance because later operands provide exclusion evidence, not positive result evidence.

<!-- code-query-case:except:rql -->
```lisp
(except
  (importers-of (file-of (function :name "legacy")))
  (importers-of (file-of (function :name "replacement"))))
```

<!-- code-query-case:except:json -->
```json
{
  "except": [
    {
      "match": { "kind": "function", "name": "legacy" },
      "steps": [{ "op": "file_of" }, { "op": "importers_of" }]
    },
    {
      "match": { "kind": "function", "name": "replacement" },
      "steps": [{ "op": "file_of" }, { "op": "importers_of" }]
    }
  ]
}
```

<!-- code-query-case:except:expected -->
```json
{
  "results": [
    {
      "result_type": "file",
      "path": "old_user.py",
      "language": "python",
      "provenance": [
        {
          "branch": [0],
          "seed": {
            "result_type": "structural_match",
            "path": "legacy.py",
            "kind": "function",
            "start_line": 1,
            "end_line": 2
          },
          "steps": [
            {
              "op": "file_of",
              "result": { "result_type": "file", "path": "legacy.py" }
            },
            {
              "op": "importers_of",
              "result": { "result_type": "file", "path": "old_user.py" }
            }
          ]
        }
      ]
    }
  ],
  "truncated": false
}
```

## Reading Completeness And Provenance

Branch paths are zero-based arrays. A trace labeled `[1, 0]` came from the first operand of a nested set inside root operand 1. Diagnostics produced while evaluating an operand carry the same path. Plain non-composed queries omit `branch`.

The public `limit` is applied once, after the complete root set and its common suffix steps. Execution work remains bounded separately. Immediate operands receive fair shares of the remaining scan, fact, row, and provenance budgets, and unused capacity rolls forward. If any branch exhausts its share, Bifrost keeps the bounded partial result, sets `truncated: true`, and emits a branch-labeled diagnostic. Cancellation preserves the all-or-empty contract.

Never treat a set result as complete unless `truncated` is false, diagnostics are acceptable, and every retained row's `provenance_truncated` is false. Identical structural seeds share scan and fact work inside one request, but each branch still contributes its own labeled provenance.
