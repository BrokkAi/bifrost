---
title: Python parser recovery
description: Query Python syntax-error nodes retained by parser recovery.
---

> Last verified end to end: 2026-10-03 (`query_code` schema version 1).

Python parser recovery preserves malformed source as a structured `syntax_error` node. This fixture stays separate from ordinary syntax tutorials so its recovery diagnostic does not make unrelated queries appear incomplete.

<!-- code-query-fixture:python/recovered.py -->
```python
def unfinished(
```

<!-- code-query-case:syntax-error:rql -->
```lisp
(language python (syntax_error))
```

<!-- code-query-case:syntax-error:json -->
```json
{"languages":["python"],"match":{"kind":"syntax_error"}}
```

<!-- code-query-case:syntax-error:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "python.recovered",
      "end_line": 1,
      "kind": "syntax_error",
      "language": "python",
      "path": "python/recovered.py",
      "result_type": "structural_match",
      "start_line": 1,
      "text": "def unfinished("
    }
  ],
  "truncated": false
}
```
