---
title: Reference Traversal
description: Traverse exact source references and semantic users with query_code.
---

> Last verified end to end: 2026-07-14 (`query_code` schema version 2).

Reference traversal starts from an exact indexed declaration. `references-of` returns each exact source site, `used-by` returns the smallest exact declaration enclosing each site, and `uses` traverses in the other direction from one exact declaration to the declarations referenced by its body or signature. No operation resolves a display name back into an identity.

## A Field Read, End To End

The fixture deliberately includes an unrelated field with the same short name. The `proven` filter keeps only the receiver-resolved `Target.status` edge.

<!-- code-query-fixture:Target.java -->
```java
class Target { int status; }
```

<!-- code-query-fixture:User.java -->
```java
class User { int read(Target target) { return target.status; } }
```

<!-- code-query-fixture:Unrelated.java -->
```java
class Unrelated { int status; } class Other { int read(Unrelated value) { return value.status; } }
```

<!-- code-query-fixture:WriteTarget.java -->
```java
class WriteTarget { int count; }
```

<!-- code-query-fixture:Writer.java -->
```java
class Writer { void update(WriteTarget target) { target.count = 1; } }
```

<!-- code-query-fixture:Surface.js -->
```javascript
class Surface { target() {} caller() { this.target(); } }
```

<!-- code-query-fixture:api/ImportedTarget.java -->
```java
package api; public class ImportedTarget { public int value; }
```

<!-- code-query-fixture:consumer/ImportedUser.java -->
```java
package consumer; import api.ImportedTarget; class ImportedUser { int read(ImportedTarget target) { return target.value; } }
```

<!-- code-query-case:field-read:rql -->
```lisp
(references-of
  :proof proven
  (members (enclosing-decl (class :name "Target"))))
```

<!-- code-query-case:field-read:json -->
```json
{"match":{"kind":"class","name":"Target"},"steps":[{"op":"enclosing_decl"},{"op":"members"},{"op":"references_of","proof":"proven"}]}
```

<!-- code-query-case:field-read:expected -->
```json
{"results":[{"result_type":"reference_site","path":"User.java","language":"java","range":{"start_line":1,"start_column":54,"end_line":1,"end_column":60},"target":{"path":"Target.java","language":"java","kind":"field","fq_name":"Target.status","start_line":1,"end_line":1,"signature":"int status;"},"enclosing_declaration":{"path":"User.java","language":"java","kind":"function","fq_name":"User.read","start_line":1,"end_line":1,"signature":"(Target)"},"usage_kind":"reference","proof":"proven","reference_kind":"field_read","provenance":[{"seed":{"result_type":"structural_match","path":"Target.java","kind":"class","start_line":1,"end_line":1},"steps":[{"op":"enclosing_decl","result":{"result_type":"declaration","path":"Target.java","kind":"class","fq_name":"Target","start_line":1,"end_line":1}},{"op":"members","result":{"result_type":"declaration","path":"Target.java","kind":"field","fq_name":"Target.status","start_line":1,"end_line":1}},{"op":"references_of","result":{"result_type":"reference_site","path":"User.java","range":{"start_line":1,"start_column":54,"end_line":1,"end_column":60},"target_fq_name":"Target.status","proof":"proven","reference_kind":"field_read"}}]}]}],"truncated":false}
```

## Reference Filters

All three steps accept the same options, in any order before the nested RQL query:

```lisp
(references-of
  :reference-kinds [field-write]
  :proof proven
  :surface external-usages
  (members (enclosing-decl (class :name "Target"))))
```

The JSON form is exact and saveable:

```json
{
  "match": {"kind": "class", "name": "Target"},
  "steps": [
    {"op": "enclosing_decl"},
    {"op": "members"},
    {
      "op": "references_of",
      "reference_kinds": ["field_write"],
      "proof": "proven",
      "surface": "external_usages"
    }
  ]
}
```

The write-only form is executable against `WriteTarget.count`:

<!-- code-query-case:field-write:rql -->
```lisp
(references-of :reference-kinds [field-write] :proof proven
  (members (enclosing-decl (class :name "WriteTarget"))))
```

<!-- code-query-case:field-write:json -->
```json
{"match":{"kind":"class","name":"WriteTarget"},"steps":[{"op":"enclosing_decl"},{"op":"members"},{"op":"references_of","reference_kinds":["field_write"],"proof":"proven"}]}
```

<!-- code-query-case:field-write:expected -->
```json
{"results":[{"result_type":"reference_site","path":"Writer.java","language":"java","range":{"start_line":1,"start_column":57,"end_line":1,"end_column":62},"target":{"path":"WriteTarget.java","language":"java","kind":"field","fq_name":"WriteTarget.count","start_line":1,"end_line":1,"signature":"int count;"},"enclosing_declaration":{"path":"Writer.java","language":"java","kind":"function","fq_name":"Writer.update","start_line":1,"end_line":1,"signature":"(WriteTarget)"},"usage_kind":"reference","proof":"proven","reference_kind":"field_write","provenance":[{"seed":{"result_type":"structural_match","path":"WriteTarget.java","kind":"class","start_line":1,"end_line":1},"steps":[{"op":"enclosing_decl","result":{"result_type":"declaration","path":"WriteTarget.java","kind":"class","fq_name":"WriteTarget","start_line":1,"end_line":1}},{"op":"members","result":{"result_type":"declaration","path":"WriteTarget.java","kind":"field","fq_name":"WriteTarget.count","start_line":1,"end_line":1}},{"op":"references_of","result":{"result_type":"reference_site","path":"Writer.java","range":{"start_line":1,"start_column":57,"end_line":1,"end_column":62},"target_fq_name":"WriteTarget.count","proof":"proven","reference_kind":"field_write"}}]}]}],"truncated":false}
```

Accepted kinds are `method_call`, `constructor_call`, `field_read`, `field_write`, `type_reference`, `static_reference`, `super_call`, and `inheritance`. A supplied kind filter excludes structured hits an adapter cannot classify. With no kind filter, classified and unclassified hits remain visible. `proof` accepts `proven` or `unproven`.

`external_usages` is the default and preserves the existing agent/search surface: imports and self-receiver noise are excluded. Use `lsp_references` when the editor-visible import and `self`/`this` occurrences are part of the question.

## What One Method Uses

`uses` returns declarations, not sites, and records the exact supporting site under `via` in provenance:

```lisp
(uses (enclosing-decl (method :name "read")))
```

<!-- code-query-case:method-uses:rql -->
```lisp
(uses :proof proven
  (enclosing-decl
    (inside (class :name "User") (method :name "read"))))
```

<!-- code-query-case:method-uses:json -->
```json
{"match":{"kind":"method","name":"read"},"inside":{"kind":"class","name":"User"},"steps":[{"op":"enclosing_decl"},{"op":"uses","proof":"proven"}]}
```

<!-- code-query-case:method-uses:expected -->
```json
{"results":[{"result_type":"declaration","path":"Target.java","language":"java","kind":"class","fq_name":"Target","start_line":1,"end_line":1,"signature":"class Target {","provenance":[{"seed":{"result_type":"structural_match","path":"User.java","kind":"method","start_line":1,"end_line":1},"steps":[{"op":"enclosing_decl","result":{"result_type":"declaration","path":"User.java","kind":"function","fq_name":"User.read","start_line":1,"end_line":1}},{"op":"uses","result":{"result_type":"declaration","path":"Target.java","kind":"class","fq_name":"Target","start_line":1,"end_line":1},"via":{"result_type":"reference_site","path":"User.java","range":{"start_line":1,"start_column":23,"end_line":1,"end_column":29},"target_fq_name":"Target","proof":"proven","reference_kind":"type_reference"}}]}]},{"result_type":"declaration","path":"Target.java","language":"java","kind":"field","fq_name":"Target.status","start_line":1,"end_line":1,"signature":"int status;","provenance":[{"seed":{"result_type":"structural_match","path":"User.java","kind":"method","start_line":1,"end_line":1},"steps":[{"op":"enclosing_decl","result":{"result_type":"declaration","path":"User.java","kind":"function","fq_name":"User.read","start_line":1,"end_line":1}},{"op":"uses","result":{"result_type":"declaration","path":"Target.java","kind":"field","fq_name":"Target.status","start_line":1,"end_line":1},"via":{"result_type":"reference_site","path":"User.java","range":{"start_line":1,"start_column":54,"end_line":1,"end_column":60},"target_fq_name":"Target.status","proof":"proven","reference_kind":"field_read"}}]}]}],"truncated":false}
```

To inspect all direct members of a type without attributing nested member bodies to the type itself, compose the ownership steps explicitly:

```lisp
(uses (members (enclosing-decl (class :name "User"))))
```

<!-- code-query-case:members-use:rql -->
```lisp
(uses :proof proven :reference-kinds [field-read]
  (members (enclosing-decl (class :name "User"))))
```

<!-- code-query-case:members-use:json -->
```json
{"match":{"kind":"class","name":"User"},"steps":[{"op":"enclosing_decl"},{"op":"members"},{"op":"uses","proof":"proven","reference_kinds":["field_read"]}]}
```

<!-- code-query-case:members-use:expected -->
```json
{"results":[{"result_type":"declaration","path":"Target.java","language":"java","kind":"field","fq_name":"Target.status","start_line":1,"end_line":1,"signature":"int status;","provenance":[{"seed":{"result_type":"structural_match","path":"User.java","kind":"class","start_line":1,"end_line":1},"steps":[{"op":"enclosing_decl","result":{"result_type":"declaration","path":"User.java","kind":"class","fq_name":"User","start_line":1,"end_line":1}},{"op":"members","result":{"result_type":"declaration","path":"User.java","kind":"function","fq_name":"User.read","start_line":1,"end_line":1}},{"op":"uses","result":{"result_type":"declaration","path":"Target.java","kind":"field","fq_name":"Target.status","start_line":1,"end_line":1},"via":{"result_type":"reference_site","path":"User.java","range":{"start_line":1,"start_column":54,"end_line":1,"end_column":60},"target_fq_name":"Target.status","proof":"proven","reference_kind":"field_read"}}]}]}],"truncated":false}
```

This exact ownership rule makes `A uses B` and `B used-by A` inverses under identical filters.

## External And Editor Surfaces

The default external surface removes `this.target()` because it is self-receiver noise for agent/search consumers:

<!-- code-query-case:external-surface:rql -->
```lisp
(language javascript
  (references-of :proof proven :surface external-usages
    (members (enclosing-decl (class :name "Surface")))))
```

<!-- code-query-case:external-surface:json -->
```json
{"languages":["javascript"],"match":{"kind":"class","name":"Surface"},"steps":[{"op":"enclosing_decl"},{"op":"members"},{"op":"references_of","proof":"proven","surface":"external_usages"}]}
```

<!-- code-query-case:external-surface:expected -->
```json
{"results":[],"truncated":false}
```

The LSP surface retains that same exact site:

<!-- code-query-case:lsp-surface:rql -->
```lisp
(language javascript
  (references-of :proof proven :surface lsp-references
    (members (enclosing-decl (class :name "Surface")))))
```

<!-- code-query-case:lsp-surface:json -->
```json
{"languages":["javascript"],"match":{"kind":"class","name":"Surface"},"steps":[{"op":"enclosing_decl"},{"op":"members"},{"op":"references_of","proof":"proven","surface":"lsp_references"}]}
```

<!-- code-query-case:lsp-surface:expected -->
```json
{"results":[{"result_type":"reference_site","path":"Surface.js","language":"javascript","range":{"start_line":1,"start_column":45,"end_line":1,"end_column":51},"target":{"path":"Surface.js","language":"javascript","kind":"function","fq_name":"Surface.target","start_line":1,"end_line":1,"signature":"function target() ..."},"enclosing_declaration":{"path":"Surface.js","language":"javascript","kind":"function","fq_name":"Surface.caller","start_line":1,"end_line":1,"signature":"function caller() ..."},"usage_kind":"self_receiver","proof":"proven","reference_kind":"method_call","provenance":[{"seed":{"result_type":"structural_match","path":"Surface.js","kind":"class","start_line":1,"end_line":1},"steps":[{"op":"enclosing_decl","result":{"result_type":"declaration","path":"Surface.js","kind":"class","fq_name":"Surface","start_line":1,"end_line":1}},{"op":"members","result":{"result_type":"declaration","path":"Surface.js","kind":"function","fq_name":"Surface.target","start_line":1,"end_line":1}},{"op":"references_of","result":{"result_type":"reference_site","path":"Surface.js","range":{"start_line":1,"start_column":45,"end_line":1,"end_column":51},"target_fq_name":"Surface.target","usage_kind":"self_receiver","proof":"proven","reference_kind":"method_call"}}]}]}],"truncated":false}
```

## Compose References With Imports

Reference sites are accepted by `file-of`, so the file containing a reference can feed the existing direct import graph:

```lisp
(imports-of
  (file-of
    (references-of :proof proven
      (members (enclosing-decl (class :name "Target"))))))
```

The packaged Java fixture makes the composition executable: the reference is in `consumer/ImportedUser.java`, and that file directly imports `api/ImportedTarget.java`.

<!-- code-query-case:reference-import:rql -->
```lisp
(imports-of
  (file-of
    (references-of :proof proven
      (members (enclosing-decl (class :name "ImportedTarget"))))))
```

<!-- code-query-case:reference-import:json -->
```json
{"match":{"kind":"class","name":"ImportedTarget"},"steps":[{"op":"enclosing_decl"},{"op":"members"},{"op":"references_of","proof":"proven"},{"op":"file_of"},{"op":"imports_of"}]}
```

<!-- code-query-case:reference-import:expected -->
```json
{"results":[{"result_type":"file","path":"api/ImportedTarget.java","language":"java","provenance":[{"seed":{"result_type":"structural_match","path":"api/ImportedTarget.java","kind":"class","start_line":1,"end_line":1},"steps":[{"op":"enclosing_decl","result":{"result_type":"declaration","path":"api/ImportedTarget.java","kind":"class","fq_name":"api.ImportedTarget","start_line":1,"end_line":1}},{"op":"members","result":{"result_type":"declaration","path":"api/ImportedTarget.java","kind":"field","fq_name":"api.ImportedTarget.value","start_line":1,"end_line":1}},{"op":"references_of","result":{"result_type":"reference_site","path":"consumer/ImportedUser.java","range":{"start_line":1,"start_column":115,"end_line":1,"end_column":120},"target_fq_name":"api.ImportedTarget.value","proof":"proven","reference_kind":"field_read"}},{"op":"file_of","result":{"result_type":"file","path":"consumer/ImportedUser.java"}},{"op":"imports_of","result":{"result_type":"file","path":"api/ImportedTarget.java"}}]}]}],"truncated":false}
```

Repeat `importers-of` or `imports-of` for additional direct hops. Reference traversal proves the symbol edge; import traversal then reports project-file relationships from the reference's file.

## Cross-Language Support

The same inbound and outbound pipeline is executable in the test suite for every graph-backed adapter:

| Query label | Exact declarations and calls | Notable structured classifications |
| --- | --- | --- |
| `python` | functions, methods, properties | dynamic candidates may be `unproven` |
| `java` | overloads, fields, constructors, types | field read/write and receiver identity |
| `javascript` | module declarations, imports, methods | `this` surface separation |
| `typescript` | JavaScript forms plus typed declarations | type and module identity |
| `go` | package functions, methods, fields, types | package-scoped identity |
| `cpp` | C/C++ functions, members, fields, types | includes and structured receiver resolution |
| `rust` | functions, impl members, fields, types | `self` surface separation |
| `php` | functions, methods, fields, types | namespace and `$this` ownership |
| `scala` | methods, fields, types, inheritance | receiver and overload resolution |
| `csharp` | methods, fields, constructors, types | receiver and overload resolution |
| `ruby` | methods, fields, constants | dynamic candidates may be `unproven` |

External library declarations appear only when they are genuinely indexed and have a renderable source range. Reference traversal itself does not produce alias sets, receiver values, allocation sites, control flow, or data flow. JavaScript/TypeScript reference-site rows may compose into the separate bounded [`member_targets` receiver analysis](../receiver-traversal/#compose-from-a-reference-site); that still does not provide whole-program points-to, general alias analysis, path-sensitive control flow, taint, or general data flow.
