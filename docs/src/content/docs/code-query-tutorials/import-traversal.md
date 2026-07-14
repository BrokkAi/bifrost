---
title: Import Traversal
description: Find declaring files and direct importers across query_code language adapters.
---

> Last verified end to end: 2026-07-14 (`query_code` schema version 2).

Import traversal starts with an indexed project declaration, not an import spelling. Convert that declaration to its file with `file-of`, then follow either a forward (`imports-of`) or reverse (`importers-of`) direct project-local edge. This keeps the result honest: Bifrost reports the files connected by a resolved import, not a guess that every importer calls a particular member.

## The Four Steps Together

For a project-local callable named `target` and an importing callable named `consume`, these RQL pipelines have the following roles:

```lisp
; The declaration that contains a structural call match.
(enclosing-decl
  (language <language> (call :callee (name "target"))))

; The file that declares target.
(file-of
  (language <language> (callable :name "target")))

; The direct project-local file imported by consume's file.
(imports-of
  (file-of (language <language> (callable :name "consume"))))

; Every project file that directly imports target's file.
(importers-of
  (file-of (language <language> (callable :name "target"))))
```

For MCP or saved JSON queries, replace the last expression with the same structural match and ordered steps:

```json
{
  "languages": ["<language>"],
  "match": {"kind": "callable", "name": "target"},
  "steps": [
    {"op": "file_of"},
    {"op": "importers_of"}
  ]
}
```

`<language>` is the `query_code` filter label shown below. `cpp` deliberately covers both C and C++.

For example, the Ruby form is directly runnable as RQL or JSON:

<!-- code-query-test:rql:cross-language-importers -->
```lisp
(importers-of
  (file-of (language ruby (callable :name "target"))))
```

<!-- code-query-test:json:cross-language-importers -->
```json
{"languages":["ruby"],"match":{"kind":"callable","name":"target"},"steps":[{"op":"file_of"},{"op":"importers_of"}]}
```

## Direct Import Forms By Language

The same reverse pipeline above is verified against a target declaration and one direct importer for every adapter that provides structured import-file analysis.

| Query label | Target declaration | Direct importer |
| --- | --- | --- |
| `python` | `def target(): pass` in `target.py` | `from target import target` |
| `java` | `public static void target() {}` in `example/Target.java` | `import example.Target;` |
| `javascript` | `export function target() {}` in `target.js` | `import { target } from './target.js';` |
| `typescript` | `export function target(): void {}` in `target.ts` | `import { target } from './target';` |
| `go` | `func Target() {}` in `target/target.go` | `import "example.com/project/target"` |
| `cpp` | `inline int target() { return 0; }` in `target.h` | `#include "target.h"` |
| `rust` | `pub fn target() {}` in `src/shared.rs` | `use crate::shared::target;` |
| `scala` | `def target(): Unit = ()` in `example/Target.scala` | `import example.Target` |
| `csharp` | `public static void target() {}` in `Target.cs` | `using Example;` |
| `ruby` | `def target; end` in `target.rb` | `require_relative 'target'` |

The query does not need to duplicate each language's import grammar. The language adapter obtains the structured import facts, and the shared pipeline only sees project files and direct edges.

## Boundary: External Libraries And Member Uses

The table intentionally uses project-local targets. An import of an out-of-scope package can be observed structurally with an `import` pattern, but it has no indexed project declaration or file to start this traversal. Bifrost does not create a synthetic declaration for that package, its types, or its methods.

PHP currently supports structural `import` matching and the declaration/file steps, but does not provide structured import-file analysis. `imports-of` and `importers-of` therefore return a diagnostic for affected PHP files instead of silently guessing.

Likewise, a reverse edge says that a file imports the target file—not that it calls `target`. Use [Reference Traversal](../reference-traversal/) to traverse an indexed declaration to exact reference sites or semantic users. Because reference sites compose with `file-of`, a proven symbol edge can also feed `imports-of` or `importers-of` without turning the import relationship into a synthetic symbol identity.
