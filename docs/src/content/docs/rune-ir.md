---
title: Rune IR
description: Inspect Bifrost's normalized structural representation and its language-adapter mappings.
---

Rune IR is Bifrost's normalized, language-neutral representation of source structure. Every structural language adapter starts with a tree-sitter parse and emits the same vocabulary of kinds, roles, names, source spans, and containment relationships. The `query_code` matcher sees Rune IR rather than language-specific grammar nodes.

## Place In The Query Pipeline

Rune IR and `CodeQuery` are separate representations on opposite sides of the matcher:

```text
source -> language adapter -> Rune IR
RQL    -> CodeQuery
matcher(CodeQuery, Rune IR)
```

Rune IR describes source. [Rune Query Language](/rune-query-language/) describes a query and lowers into `CodeQuery`. Rune IR is not a raw tree-sitter tree, and `CodeQuery` is not a copy of source structure. This separation lets one normalized query match equivalent structure across several languages.

Internally, `FileFacts` is the arena-backed storage for one source file. Rune IR is the public, inspectable rendering of those facts.

## Rune IR Documents

The VS Code extension associates `.rune` files with **Bifrost Rune IR** and uses the same language mode for generated previews. It highlights:

- normalized kinds such as `function`, `call`, and `field_access`
- normalized role forms such as `callee`, `args`, and `right`
- metadata fields such as `:range`, `:span`, `:name`, `:keyword`, and `:text`
- byte offsets, quoted source values, truncation markers, and `;` comments

A preview is an inspection document, not an executable query file. Save queries as `.rql` or canonical JSON; `--query-file` does not execute `.rune` files.

For this Rust source:

```rust
fn greet(name: &str) {
    audit(name);
}
```

Rune IR has this shape:

```text
; Rune IR for greet (rust)

(function :range (0 41) :name "greet"
  (identifier :range (3 8) :name "greet"
  )
  (identifier :range (9 13) :name "name"
  )
  (call :range (27 38) :name "audit"
    (callee :span (27 32) :name "audit" :text "audit")
    (args :span (33 37) :name "name" :text "name")
    (identifier :range (27 32) :name "audit"
    )
    (identifier :range (33 37) :name "name"
    )
  )
)

; Starter RQL
(function :name "greet")
```

Nested kind forms express containment. Role forms express typed edges from their enclosing fact to a related source span; they are not child nodes and do not expose internal arena IDs. Ranges and spans are zero-based, half-open UTF-8 byte offsets into the inspected source.

The final starter form is deliberately conservative. It uses the selected top-level kind and exact name when available, then passes through the real RQL frontend to ensure it parses. A complete Rune IR document can express containment and role edges that one starter pattern does not attempt to reproduce.

## Inspect Rune IR

In the query REPL, `:ir <language>` captures pasted source until a line containing only `:end` and renders Rune IR without initializing a workspace index:

```text
:ir rust
fn greet(name: &str) {
    audit(name);
}
:end
```

Use `:ir tsx` for TypeScript containing JSX. `:ir typescript` uses the ordinary `.ts` grammar.

In VS Code, place the cursor or a selection inside an indexed declaration and run **Bifrost: Show Rune IR** from the command palette or editor context menu. Bifrost reads the unsaved overlay, preserves file-specific parser variants such as TSX, selects the smallest enclosing indexed code unit, and opens a highlighted Rune IR preview. The first line and starter heading are `;` comments, so saving the preview as a `.rune` file preserves its document structure.

Rune IR accepts at most 256 KiB of source per request or REPL capture. Oversized input is rejected before structural parsing. Rendering also bounds node count, depth, copied source bytes, and output bytes; a balanced `(truncated "...")` form records when a render limit is reached.

## Language Adapter Mappings

These notes describe how the current tree-sitter adapters feed the normalized `query_code` model. They are not query syntax. Query against normalized kinds and roles such as `call`, `assignment`, `callee`, and `right`; tree-sitter node names stay behind the adapter boundary.

Every adapter follows the same basic pattern:

- grammar node types become normalized kinds
- grammar fields become normalized roles
- expression helpers find terminal names, so `service.run(...)` can be queried as a call whose `callee` is `run` and whose `receiver` is `service`
- adapters skip facts they cannot model precisely, such as uninitialized declarations as assignments
- unsupported roles are reported as diagnostics instead of being silently guessed

### Python

Python maps `call` to `call`, `attribute` to `field_access`, `function_definition` to `function`, `class_definition` to `class`, and `assignment` to `assignment`. A `function_definition` whose nearest normalized parent is a class is refined to `method`.

Role extraction uses the `function` field of a `call` as `callee`, `arguments` children as `args`, `keyword_argument` nodes as `kwargs`, and the `object` / `attribute` fields of `attribute` nodes as `object` and `field`. `import_statement` and `import_from_statement` both map to `import` with a `module` role. Decorators are attached from the surrounding `decorated_definition` wrapper.

Toy shape:

```python
def run(code):
    password = "hunter2"
    audit(code)
```

### Java

Java maps `method_invocation` and `object_creation_expression` to `call`, `field_access` to `field_access`, `method_declaration` to `method`, `constructor_declaration` to `constructor`, and `variable_declarator` / `assignment_expression` to `assignment`.

Role extraction uses the `name` field of `method_invocation` as `callee`, the `object` field as `receiver`, and the `arguments` field as positional `args`. `object_creation_expression` uses the `type` field as the call target. `import_declaration` contributes a `module` role. `annotation` and `marker_annotation` nodes under modifiers become `decorators`.

Toy shape:

```java
class App {
    void run(String code) {
        String password = "hunter2";
        audit(code);
    }
}
```

### JavaScript

JavaScript maps `call_expression` and `new_expression` to `call`, `member_expression` to `field_access`, function declarations and expressions to `function`, `method_definition` to `method`, `arrow_function` to `lambda`, `class` / `class_declaration` to `class`, and variable declarators or assignment expressions to `assignment`.

Role extraction uses the `function` field of `call_expression` or the `constructor` field of `new_expression` as `callee`. If that target is a `member_expression`, its `object` becomes `receiver`. `member_expression` also supplies `object` and `field` for field-access queries. `import_statement` maps to `import`, and `decorator` nodes are attached to classes and class members. JavaScript does not model `kwargs`.

Toy shape:

```js
function run(code) {
  const password = "hunter2";
  audit(code);
}
```

### TypeScript

TypeScript uses the JavaScript mapping and adds TypeScript grammar nodes such as `interface_declaration`, `enum_declaration`, and `abstract_class_declaration` as `class`, plus `type_alias_declaration` as `declaration`. `type_identifier` and `nested_identifier` feed normalized `identifier` facts.

Calls, member access, imports, decorators, assignments, and lambdas use the same normalized roles as JavaScript: `callee`, `receiver`, `args`, `object`, `field`, `module`, `decorators`, `left`, and `right`.

Toy shape:

```ts
function run(code: string): void {
  const password = "hunter2";
  audit(code);
}
```

### Go

Go maps `call_expression` to `call`, `selector_expression` to `field_access`, `function_declaration` to `function`, `method_declaration` to `method`, `func_literal` to `lambda`, `type_spec` to `class`, and `type_alias` to `declaration`. `assignment_statement`, `short_var_declaration`, `var_spec`, and `const_spec` all feed `assignment` when they have values.

Role extraction uses a call's `function` field as `callee`. If the call target is a `selector_expression`, the `operand` field becomes `receiver`. Selector `operand` and `field` fields become field-access `object` and `field`. Imports use every `import_spec` path under an `import_declaration`. Go does not model `kwargs` or decorators.

Toy shape:

```go
func run(code string) {
    var password = "hunter2"
    audit(code)
}
```

### C And C++

C and C++ files share the `cpp` analyzer, structural adapter, and language-filter label. C++ maps `call_expression` and `new_expression` to `call`, `field_expression` to `field_access`, `function_definition` to `function`, `lambda_expression` to `lambda`, class/struct/union specifiers to `class`, `alias_declaration` to `declaration`, and `assignment_expression` / `init_declarator` to `assignment`. C files naturally expose only the subset their syntax contains.

Role extraction uses the `function` field of `call_expression` or `type` field of `new_expression` as `callee`. Field calls use the field expression's `argument` as `receiver`, and qualified calls expose the qualified scope as `receiver`. Class-contained or scoped function definitions are refined to `method`, and matching scope/name constructor definitions are refined to `constructor`. `preproc_include` maps to `import`. C++ does not model `kwargs` or decorators.

Toy shape:

```cpp
void run(const char* code) {
    auto password = "hunter2";
    audit(code);
}
```

### Rust

Rust maps `call_expression` to `call`, `field_expression` to `field_access`, `function_item` and `function_signature_item` to `function`, `closure_expression` to `lambda`, `struct_item` / `enum_item` / `trait_item` to `class`, `type_item` to `declaration`, and `let_declaration`, `const_item`, `static_item`, assignment expressions, and compound assignment expressions to `assignment`.

Role extraction uses the `function` field of a call as `callee`; generic functions are unwrapped to their terminal function name. Field-expression call targets provide `receiver`, and scoped identifiers expose the path as `receiver`. `use_declaration` maps to `import` with `module` roles for the imported path or alias. Rust does not model `kwargs` or decorators.

Toy shape:

```rust
fn run(code: &str) {
    let password = "hunter2";
    audit(code);
}
```

### PHP

PHP maps function, member, nullsafe member, scoped, and object-creation expressions to `call`. Member access, nullsafe member access, scoped property access, and class constant access map to `field_access`. Function definitions, method declarations, anonymous functions, arrow functions, class-like declarations, namespace imports, attributes, and several assignment forms map into the normalized vocabulary.

Role extraction uses call target fields as `callee`, object or scope fields as `receiver`, `argument` nodes as positional `args`, and named arguments as `kwargs`. Constructors are refined from `method` when the method name is `__construct`. Namespace `use` declarations provide `module` roles, including aliases. PHP attributes map to `decorators`.

Toy shape:

```php
function run(string $code): void {
    $password = "hunter2";
    audit($code);
}
```

### Scala

Scala maps `call_expression` to `call`, `field_expression` to `field_access`, function definitions and declarations to `function`, `lambda_expression` to `lambda`, class/object/trait/enum definitions to `class`, `val_definition`, `var_definition`, and assignment expressions to `assignment`, and `import_declaration` to `import`.

Role extraction unwraps generic functions, uses field-expression receivers as `receiver`, supports positional args, named args, and block-style args, and treats named arguments as `kwargs` rather than assignment facts. Functions inside classes become `method`. Annotations map to `decorators`.

Toy shape:

```scala
object App {
  def run(code: String): Unit = {
    val password = "hunter2"
    audit(code)
  }
}
```

### C#

C# maps `invocation_expression` and `object_creation_expression` to `call`, member and conditional access expressions to `field_access`, method and constructor declarations to `method` and `constructor`, local functions to `function`, lambda and anonymous methods to `lambda`, class-like declarations to `class`, properties to `declaration`, variable declarators and assignment expressions to `assignment`, and `using_directive` to `import`.

Role extraction uses invocation `function` targets or object-creation `type` targets as `callee`. Member and conditional access targets provide `receiver`, `object`, and `field`. Arguments can be positional `args` or named `kwargs`. Attributes map to `decorators`, and using aliases are exposed as import `module` names.

Toy shape:

```csharp
class App {
    void run(string code) {
        var password = "hunter2";
        audit(code);
    }
}
```

### Ruby

Ruby maps `call` to `call`, `scope_resolution` to `field_access`, `method` and `singleton_method` to function-like declarations, `lambda`, `block`, and `do_block` to `lambda`, classes and modules to `class`, assignments to `assignment`, and bare `require`, `require_relative`, `load`, and `autoload` calls with static string arguments to `import`.

Role extraction uses the call `method` field as `callee`, optional `receiver` as `receiver`, ordinary arguments as `args`, and hash-pair arguments as `kwargs`. A `method` inside a class or module is refined to `method`; top-level `def` remains `function`. Static import strings expose a `module` role, but interpolated strings do not pretend to have a precise module name. Ruby does not model decorators.

Toy shape:

```ruby
def run(code)
  password = "hunter2"
  audit(code)
end
```

## From Mappings To Queries

Query normalized kinds and roles rather than the tree-sitter names listed above. Start from **Bifrost: Show Rune IR** or `:ir <language>`, copy the generated starter RQL, and refine it with the [Rune Query Language reference](/rune-query-language/). For complete executable examples, see the [language tutorials](/code-query-tutorials/).
