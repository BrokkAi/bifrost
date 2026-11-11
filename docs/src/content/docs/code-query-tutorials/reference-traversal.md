---
title: Reference Traversal
description: Traverse exact source references and semantic users with query_code.
---

> Last verified end to end: 2026-10-01 (`query_code` schema version 1).

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
{"results":[{"enclosing_declaration":{"end_line":1,"fq_name":"User.read","kind":"function","language":"java","path":"User.java","signature":"(Target)","start_line":1},"language":"java","path":"User.java","proof":"proven","provenance":[{"seed":{"end_line":1,"kind":"class","path":"Target.java","result_type":"structural_match","start_line":1},"steps":[{"op":"enclosing_decl","result":{"end_line":1,"fq_name":"Target","kind":"class","path":"Target.java","result_type":"declaration","start_line":1}},{"op":"members","result":{"end_line":1,"fq_name":"Target.status","kind":"field","path":"Target.java","result_type":"declaration","start_line":1}},{"op":"references_of","result":{"path":"User.java","proof":"proven","range":{"end_column":60,"end_line":1,"start_column":54,"start_line":1},"reference_facets":{"known":[],"undecided":["field_read","field_write","static_reference"]},"result_type":"reference_site","target_fq_name":"Target.status"}}]}],"range":{"end_column":60,"end_line":1,"start_column":54,"start_line":1},"reference_facets":{"known":[],"undecided":["field_read","field_write","static_reference"]},"result_type":"reference_site","target":{"end_line":1,"fq_name":"Target.status","kind":"field","language":"java","path":"Target.java","signature":"int status;","start_line":1},"usage_kind":"reference"}],"truncated":false}
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
{"results":[{"enclosing_declaration":{"end_line":1,"fq_name":"Writer.update","kind":"function","language":"java","path":"Writer.java","signature":"(WriteTarget)","start_line":1},"language":"java","path":"Writer.java","proof":"proven","provenance":[{"seed":{"end_line":1,"kind":"class","path":"WriteTarget.java","result_type":"structural_match","start_line":1},"steps":[{"op":"enclosing_decl","result":{"end_line":1,"fq_name":"WriteTarget","kind":"class","path":"WriteTarget.java","result_type":"declaration","start_line":1}},{"op":"members","result":{"end_line":1,"fq_name":"WriteTarget.count","kind":"field","path":"WriteTarget.java","result_type":"declaration","start_line":1}},{"op":"references_of","result":{"path":"Writer.java","proof":"proven","range":{"end_column":62,"end_line":1,"start_column":57,"start_line":1},"reference_facets":{"known":["field_write"],"undecided":["static_reference"]},"result_type":"reference_site","target_fq_name":"WriteTarget.count"}}]}],"range":{"end_column":62,"end_line":1,"start_column":57,"start_line":1},"reference_facets":{"known":["field_write"],"undecided":["static_reference"]},"result_type":"reference_site","target":{"end_line":1,"fq_name":"WriteTarget.count","kind":"field","language":"java","path":"WriteTarget.java","signature":"int count;","start_line":1},"usage_kind":"reference"}],"truncated":false}
```

Accepted kinds are `method_call`, `constructor_call`, `field_read`, `field_write`, `type_reference`, `self_type_alias`, `static_reference`, `super_call`, and `inheritance`. Each site reports `reference_facets`: the kinds proven for it (`known`) and the kinds that may hold (`undecided`). A kind filter keeps a site with a known requested kind, reports the answer incomplete when only an undecided kind could match, and excludes a site only when every requested kind is proven absent. With no kind filter, every site remains visible with its facets. `proof` accepts `proven` or `unproven`.

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
{"diagnostics":[{"code":"uses_candidates_omitted","impact":"incomplete","language":"java","message":"uses omitted 4 candidate reference sites in User.java because the structured usage analyzer did not confirm every exact edge"}],"results":[{"end_line":1,"fq_name":"Target","kind":"class","language":"java","path":"Target.java","provenance":[{"seed":{"end_line":1,"kind":"method","path":"User.java","result_type":"structural_match","start_line":1},"steps":[{"op":"enclosing_decl","result":{"end_line":1,"fq_name":"User.read","kind":"method","path":"User.java","result_type":"declaration","start_line":1}},{"op":"uses","result":{"end_line":1,"fq_name":"Target","kind":"class","path":"Target.java","result_type":"declaration","start_line":1},"via":{"path":"User.java","proof":"proven","range":{"end_column":29,"end_line":1,"start_column":23,"start_line":1},"reference_facets":{"known":["type_reference"],"undecided":["self_type_alias","static_reference"]},"result_type":"reference_site","target_fq_name":"Target"}}]}],"result_type":"declaration","signature":"class Target {","start_line":1},{"end_line":1,"fq_name":"Target.status","kind":"field","language":"java","path":"Target.java","provenance":[{"seed":{"end_line":1,"kind":"method","path":"User.java","result_type":"structural_match","start_line":1},"steps":[{"op":"enclosing_decl","result":{"end_line":1,"fq_name":"User.read","kind":"method","path":"User.java","result_type":"declaration","start_line":1}},{"op":"uses","result":{"end_line":1,"fq_name":"Target.status","kind":"field","path":"Target.java","result_type":"declaration","start_line":1},"via":{"path":"User.java","proof":"proven","range":{"end_column":60,"end_line":1,"start_column":54,"start_line":1},"reference_facets":{"known":[],"undecided":["field_read","field_write","static_reference"]},"result_type":"reference_site","target_fq_name":"Target.status"}}]}],"result_type":"declaration","signature":"int status;","start_line":1}],"truncated":false}
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
{"diagnostics":[{"code":"uses_candidates_omitted","impact":"incomplete","language":"java","message":"uses omitted 4 candidate reference sites in User.java because the structured usage analyzer did not confirm every exact edge"},{"code":"reference_kind_undecided","impact":"incomplete","language":"java","message":"reference sites without a classified kind could not be excluded for requested kinds [\"field_read\"]: [\"User.java:1@53\"]"}],"results":[],"truncated":false}
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
{"results":[{"enclosing_declaration":{"end_line":1,"fq_name":"Surface.caller","kind":"function","language":"javascript","path":"Surface.js","signature":"function caller() ...","start_line":1},"language":"javascript","path":"Surface.js","proof":"proven","provenance":[{"seed":{"end_line":1,"kind":"class","path":"Surface.js","result_type":"structural_match","start_line":1},"steps":[{"op":"enclosing_decl","result":{"end_line":1,"fq_name":"Surface","kind":"class","path":"Surface.js","result_type":"declaration","start_line":1}},{"op":"members","result":{"end_line":1,"fq_name":"Surface.target","kind":"function","path":"Surface.js","result_type":"declaration","start_line":1}},{"op":"references_of","result":{"path":"Surface.js","proof":"proven","range":{"end_column":51,"end_line":1,"start_column":45,"start_line":1},"reference_facets":{"known":["method_call"],"undecided":["static_reference"]},"result_type":"reference_site","target_fq_name":"Surface.target","usage_kind":"self_receiver"}}]}],"range":{"end_column":51,"end_line":1,"start_column":45,"start_line":1},"reference_facets":{"known":["method_call"],"undecided":["static_reference"]},"result_type":"reference_site","target":{"end_line":1,"fq_name":"Surface.target","kind":"function","language":"javascript","path":"Surface.js","signature":"function target() ...","start_line":1},"usage_kind":"self_receiver"}],"truncated":false}
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
{"results":[{"language":"java","package_fq":"api","package_syntactic":true,"path":"api/ImportedTarget.java","provenance":[{"seed":{"end_line":1,"kind":"class","path":"api/ImportedTarget.java","result_type":"structural_match","start_line":1},"steps":[{"op":"enclosing_decl","result":{"end_line":1,"fq_name":"api.ImportedTarget","kind":"class","path":"api/ImportedTarget.java","result_type":"declaration","start_line":1}},{"op":"members","result":{"end_line":1,"fq_name":"api.ImportedTarget.value","kind":"field","path":"api/ImportedTarget.java","result_type":"declaration","start_line":1}},{"op":"references_of","result":{"path":"consumer/ImportedUser.java","proof":"proven","range":{"end_column":120,"end_line":1,"start_column":115,"start_line":1},"reference_facets":{"known":[],"undecided":["field_read","field_write","static_reference"]},"result_type":"reference_site","target_fq_name":"api.ImportedTarget.value"}},{"op":"file_of","result":{"path":"consumer/ImportedUser.java","result_type":"file"}},{"op":"imports_of","result":{"path":"api/ImportedTarget.java","result_type":"file"}}]}],"result_type":"file"}],"truncated":false}
```

Repeat `importers-of` or `imports-of` for additional direct hops. Reference traversal proves the symbol edge; import traversal then reports project-file relationships from the reference's file.

## Cross-Language Support

The same inbound and outbound pipeline is executable in the test suite for every graph-backed adapter:

| Query label | Exact declarations and calls | Notable structured classifications |
| --- | --- | --- |
| `python` | functions, methods, properties | import-resolved functions and constructor-created receivers |
| `java` | overloads, fields, constructors, types | field read/write and receiver identity |
| `javascript` | module declarations, imports, methods | `this` surface separation |
| `typescript` | JavaScript forms plus typed declarations | type and module identity |
| `go` | package functions, methods, fields, types | package-scoped identity |
| `cpp` | C/C++ functions, members, fields, types | includes and structured receiver resolution |
| `rust` | functions, impl members, fields, types | `self` surface separation |
| `php` | functions, methods, fields, types | namespace and `$this` ownership |
| `scala` | methods, fields, types, inheritance | receiver and overload resolution |
| `csharp` | methods, fields, constructors, types | receiver and overload resolution |
| `ruby` | methods, fields, constants | receivers created by `Class.new` |
| `kotlin` | functions, methods, constructors, properties, types | inheritance, companion objects, extensions, and receiver chains |

Any adapter can return `unproven` sites. An adapter marks a site `unproven` when the receiver type is unknown or several declarations are possible, for example a call through a Java `var` whose initializer has an unknown type, or a Go call through an interface that several types implement. Check `proof` in every language; use `:proof proven` when you need exact edges only.

External library declarations appear only when they are genuinely indexed and have a renderable source range. Reference traversal itself does not produce alias sets, receiver values, allocation sites, control flow, or data flow. Reference-site rows may compose into the separate bounded [`member_targets` receiver analysis](/code-query-tutorials/receiver-traversal/#compose-from-a-reference-site) when the selected adapter exposes the necessary structured facts; that still does not provide whole-program points-to, general alias analysis, path-sensitive control flow, taint, or general data flow.
