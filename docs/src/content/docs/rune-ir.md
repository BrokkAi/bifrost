---
title: Rune IR
description: Inspect Bifrost's normalized structural representation and look up how each language adapter maps grammar nodes to it.
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

## Inspect Rune IR

The query REPL renders Rune IR for pasted source. It does not index a workspace. Start the REPL with `bifrost --repl`, then enter `:ir <language>`, paste the source, and finish with a line that contains only `:end`:

```text
:ir rust
fn greet(name: &str) {
    audit(name);
}
:end
```

The REPL prints a `Rune IR (<label>):` header, the rendered facts, a `Starter RQL:` header, and one starter query:

```text
Rune IR (rust):
(function :range (0 41) :name "greet"
  (identifier :range (3 8) :name "greet"
  )
  (identifier :range (9 13) :name "name"
  )
  (block :range (21 41)
    (call :range (27 38) :name "audit"
      (callee :span (27 32) :name "audit" :text "audit")
      (args :span (33 37) :name "name" :text "name")
      (identifier :range (27 32) :name "audit"
      )
      (identifier :range (33 37) :name "name"
      )
    )
  )
)
Starter RQL:
(function :name "greet")
```

`<label>` is the language label that the REPL resolved from your input. For example, `:ir c` prints `Rune IR (cpp):`.

### Read The Output

- A kind form such as `(function ...)` or `(call ...)` is one fact. Nesting expresses containment: the `block` fact is inside the function, and the `call` fact is inside the block.
- `:range (start end)` gives the fact's source range.
- A role form such as `(callee ...)` or `(args ...)` is a typed edge from the enclosing fact to a related source span. It is not a child fact and does not expose internal arena IDs. `:span (start end)` gives the related span.
- `:name` is the fact's or role target's name when the adapter can state one. `:keyword` is the argument name of a `kwargs` role. `:text` is the exact source text of the role span.
- Ranges and spans are zero-based, half-open UTF-8 byte offsets into the source you pasted.

The starter query uses the kind of the first top-level fact and its exact name when the fact has one. Bifrost parses the starter query with the RQL frontend before printing it. A Rune IR document can express containment and role edges that the starter query does not reproduce.

A Rune IR rendering is an inspection document, not a query. Save queries as `.rql` or canonical JSON. `--query-file` does not execute `.rune` files.

### Language Labels

`:ir` accepts these labels. Matching ignores case, a leading `.`, `-`, and `_`. Run `:languages` in the REPL to print the label list.

| You type | Grammar and dialect | Printed label |
| --- | --- | --- |
| `java` | Java | `java` |
| `go` | Go | `go` |
| `cpp`, `c++`, or a C or C++ file extension (`c`, `cc`, `cpp`, `cxx`, `h`, `hin`, `hpp`, `hh`, `hxx`) | C++ grammar, C++ rules | `cpp` |
| `cpp-c` | C++ grammar, C dialect | `cpp-c` |
| `javascript`, `js`, `mjs`, or `cjs` | JavaScript grammar | `javascript` |
| `jsx`, `javascriptreact`, or `javascript-jsx` | TSX grammar, JavaScript adapter (the grammar Bifrost uses for `.jsx` files) | `jsx` |
| `typescript` or `ts` | TypeScript grammar | `typescript` |
| `tsx`, `typescriptreact`, or `typescript-tsx` | TSX grammar, TypeScript adapter | `tsx` |
| `python` or `py` | Python | `python` |
| `rust` or `rs` | Rust | `rust` |
| `php` | PHP | `php` |
| `scala` | Scala | `scala` |
| `csharp`, `c#`, or `cs` | C# | `csharp` |
| `ruby` or `rb` | Ruby | `ruby` |
| `kotlin`, `kt`, or `kts` | Kotlin | `kotlin` |

`c` is a C++ file extension, so `:ir c` uses the `cpp` label. C and C++ share one tree-sitter grammar and one structural adapter. The `cpp-c` dialect changes how the indexed analyzer interprets declaration scopes in `.c` files. It does not change the Rune IR facts.

An unknown label prints `unsupported Rune IR language` and does not start a capture.

### Limits And Rejected Input

| Limit | Value | What happens |
| --- | --- | --- |
| Source size | 256 KiB (262,144 bytes) | The REPL cancels the capture when the pasted source would exceed the limit. |
| Rendered facts | 10,000 | Rendering stops and prints `(truncated "node limit reached")`. |
| Nesting depth | 128 | Rendering stops and prints `(truncated "depth limit reached")`. |
| Source text copied into `:name`, `:keyword`, and `:text` values | 64 KiB | Rendering stops and prints `(truncated "source byte limit reached")`. |
| Output size | 256 KiB | Rendering stops and prints `(truncated "output byte limit reached")`. |

The truncation form closes every open form, so a truncated document stays balanced.

Bifrost rejects input with an error and renders nothing when:

- the source is empty;
- the source contains a NUL byte;
- a line is longer than the parser line-length limit, which is 16,000 bytes by default (the `BIFROST_MAX_LINE_LENGTH` environment variable changes it; see [Environment Variables](/reference/environment/));
- the adapter produces no facts for the source.

### VS Code

The VS Code extension has a **Bifrost: Show Rune IR** command. The language server runs that command, and the language server is now the separate `bifrost-lsp` program. The `bifrost` binary described here does not serve it. See [LSP Server](/lsp/) and [VS Code LSP](/vscode/) for its status.

## Language Adapter Mappings

These tables describe how the tree-sitter adapters feed the normalized `query_code` model. They are not query syntax. Query normalized kinds and roles such as `call`, `assignment`, `callee`, and `right`; tree-sitter node names stay behind the adapter boundary. For the meaning of each kind and role, see [Code Query Vocabulary](/reference/code-query/).

Every adapter follows the same pattern:

- grammar node types become normalized kinds;
- grammar fields become normalized roles;
- expression helpers find terminal names, so `service.run(...)` is a call whose `callee` is `run` and whose `receiver` is `service`;
- adapters skip facts they cannot model precisely, such as a declaration without a value as an assignment;
- a query that uses a kind or role the adapter does not support returns an `unsupported_structural_feature` diagnostic instead of a guessed match.

### Kind Support By Language

`yes` means the adapter can produce facts that match the kind. `-` means a query for that kind returns an `unsupported_structural_feature` diagnostic for that language. A broad kind such as `declaration`, `callable`, `literal`, or `loop` matches its subtypes, so it is supported wherever one of its subtypes is.

| Kind | python | java | javascript | typescript | go | cpp | csharp | php | ruby | rust | scala | kotlin |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `declaration` | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `callable` | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `function` | yes | - | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `method` | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `constructor` | - | yes | yes | yes | - | yes | yes | yes | - | - | - | yes |
| `lambda` | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `class` | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `import` | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `parameter` | - | yes | yes | yes | - | - | - | - | - | - | - | - |
| `module` | - | - | - | - | - | yes | yes | yes | yes | yes | - | - |
| `call` | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `concurrent_spawn` | - | - | - | - | yes | - | - | - | - | - | - | - |
| `resource_release` | yes | yes | - | - | - | - | - | - | - | - | - | - |
| `assignment` | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `field_access` | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `identifier` | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `literal` | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `string_literal` | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `numeric_literal` | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `boolean_literal` | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `null_literal` | yes | yes | yes | yes | yes | yes | yes | yes | yes | - | yes | yes |
| `collection_literal` | yes | yes | yes | yes | - | - | - | - | - | yes | - | - |
| `jsx_element` | - | - | yes | yes | - | - | - | - | - | - | - | - |
| `jsx_attribute` | - | - | yes | yes | - | - | - | - | - | - | - | - |
| `jsx_spread_attribute` | - | - | yes | yes | - | - | - | - | - | - | - | - |
| `object_property` | - | - | yes | yes | - | - | - | - | - | - | - | - |
| `computed_property` | - | - | yes | yes | - | - | - | - | - | - | - | - |
| `spread_element` | - | - | yes | yes | - | - | - | - | - | - | - | - |
| `return` | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `throw` | yes | yes | yes | yes | - | yes | yes | yes | - | - | yes | yes |
| `catch` | yes | yes | yes | yes | - | yes | yes | yes | yes | - | yes | yes |
| `if` | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `loop` | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `for_loop` | yes | yes | yes | yes | - | - | yes | yes | yes | yes | yes | yes |
| `while_loop` | yes | yes | yes | yes | - | yes | yes | yes | yes | yes | yes | yes |
| `decorator` | yes | yes | yes | yes | - | - | yes | yes | - | yes | yes | yes |
| `block` | yes | yes | yes | yes | yes | yes | yes | - | - | yes | yes | yes |

The JavaScript adapter reports `parameter` as supported for every JavaScript file. A `parameter` query matches formal parameters in `.js`, `.mjs`, `.cjs`, and `.jsx` files. A rest parameter (`...args`) and a single unparenthesized arrow parameter (`x => x`) are not `parameter` facts.

### Role Support By Language

`yes` means a query can constrain the role in that language. `-` means the query returns an `unsupported_structural_feature` diagnostic, either for the role or for every kind that can carry it. A role is valid only on certain query kinds; for example, `iterable` is valid only on `for_loop`, and `tag` only on `jsx_element`. See [Code Query Vocabulary](/reference/code-query/) for the kinds each role accepts.

| Role | python | java | javascript | typescript | go | cpp | csharp | php | ruby | rust | scala | kotlin |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `callee` | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `receiver` | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `args` | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `kwargs` | yes | - | - | - | - | - | yes | yes | yes | - | yes | yes |
| `left` | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `right` | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `operator` | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `module` | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `decorators` | yes | yes | yes | yes | - | - | yes | yes | - | yes | yes | yes |
| `object` | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `field` | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `iterable` | yes | yes | yes | yes | - | - | - | - | - | yes | - | - |
| `elements` | yes | yes | yes | yes | - | - | - | - | - | yes | - | - |
| `tag` | - | - | yes | yes | - | - | - | - | - | - | - | - |
| `attributes` | - | - | yes | yes | - | - | - | - | - | - | - | - |
| `children` | - | - | yes | yes | - | - | - | - | - | - | - | - |
| `value` | - | - | yes | yes | - | - | - | - | - | - | - | - |
| `key` | - | - | yes | yes | - | - | - | - | - | - | - | - |

### Python

| Kind | Grammar node types |
| --- | --- |
| `call` | `call` |
| `field_access` | `attribute` |
| `function` | `function_definition` |
| `method` | `function_definition` inside a class body (see below) |
| `lambda` | `lambda` |
| `class` | `class_definition` |
| `assignment` | `assignment` |
| `resource_release` | `with_statement` |
| `import` | `import_statement`, `import_from_statement` |
| `identifier` | `identifier` |
| `string_literal` | `string`, `concatenated_string` |
| `numeric_literal` | `integer`, `float` |
| `boolean_literal` | `true`, `false` |
| `null_literal` | `none` |
| `collection_literal` | `list`, `set`, `dictionary`, `tuple` |
| `return` | `return_statement` |
| `throw` | `raise_statement` |
| `catch` | `except_clause` |
| `if` | `if_statement` |
| `for_loop` | `for_statement` |
| `while_loop` | `while_statement` |
| `block` | `block` |
| `decorator` | `decorator` |

A `function_definition` becomes `method` when its parent is a class body, including through a `decorated_definition` wrapper. An `assignment` node becomes an `assignment` fact only when it has a right-hand side, so `x: int` alone is not an assignment.

Roles: the `function` field of a `call` is the `callee`, `arguments` children are `args`, and `keyword_argument` nodes are `kwargs`. The `object` and `attribute` fields of an `attribute` node are `object` and `field`. Both import statements carry a `module` role. Decorators come from the surrounding `decorated_definition` wrapper.

Toy shape:

```python
def run(code):
    password = "hunter2"
    audit(code)
```

### Java

| Kind | Grammar node types |
| --- | --- |
| `call` | `method_invocation`, `method_reference`, `object_creation_expression` |
| `resource_release` | `try_with_resources_statement` |
| `field_access` | `field_access` |
| `method` | `method_declaration` |
| `constructor` | `constructor_declaration`, `compact_constructor_declaration` |
| `lambda` | `lambda_expression` |
| `parameter` | `formal_parameter`, `spread_parameter` |
| `class` | `class_declaration`, `interface_declaration`, `enum_declaration`, `record_declaration`, `annotation_type_declaration` |
| `assignment` | `variable_declarator`, `assignment_expression` |
| `import` | `import_declaration` |
| `identifier` | `identifier`, `type_identifier`, `scoped_identifier`, `scoped_type_identifier` |
| `string_literal` | `string_literal` |
| `numeric_literal` | `decimal_integer_literal`, `hex_integer_literal`, `octal_integer_literal`, `binary_integer_literal`, `decimal_floating_point_literal` |
| `boolean_literal` | `true`, `false` |
| `null_literal` | `null_literal` |
| `collection_literal` | `array_initializer` |
| `return` | `return_statement` |
| `throw` | `throw_statement` |
| `catch` | `catch_clause` |
| `if` | `if_statement` |
| `loop` | `for_statement` |
| `for_loop` | `enhanced_for_statement` |
| `while_loop` | `while_statement`, `do_statement` |
| `block` | `block`, `switch_block` |
| `decorator` | `annotation`, `marker_annotation` |

A `variable_declarator` becomes an `assignment` fact only when it has a value.

Roles: the `name` field of `method_invocation` is the `callee`, the `object` field is the `receiver`, and the `arguments` field supplies positional `args`. `object_creation_expression` uses its `type` field as the call target. `import_declaration` carries a `module` role. `annotation` and `marker_annotation` nodes under modifiers become `decorators`. Java has no keyword arguments.

Toy shape:

```java
class App {
    void run(String code) {
        String password = "hunter2";
        audit(code);
    }
}
```

### JavaScript And TypeScript

JavaScript and TypeScript share one adapter. This table applies to both:

| Kind | Grammar node types |
| --- | --- |
| `call` | `call_expression`, `new_expression` |
| `field_access` | `member_expression` |
| `function` | `function_declaration`, `function_expression`, `generator_function_declaration`, `generator_function` |
| `method` | `method_definition` |
| `constructor` | `method_definition` named `constructor` |
| `lambda` | `arrow_function` |
| `class` | `class`, `class_declaration` |
| `assignment` | `assignment_expression`, `variable_declarator` |
| `import` | `import_statement` |
| `identifier` | `identifier`, `property_identifier`, `private_property_identifier`, `shorthand_property_identifier`, `shorthand_property_identifier_pattern` |
| `collection_literal` | `array`, `object` |
| `jsx_element` | `jsx_element`, `jsx_self_closing_element` |
| `jsx_attribute` | `jsx_attribute` |
| `jsx_spread_attribute` | `jsx_expression` whose only named child is a `spread_element`, directly inside an opening or self-closing JSX element |
| `object_property` | `pair` |
| `computed_property` | `computed_property_name` |
| `spread_element` | `spread_element` |
| `string_literal` | `string`, `template_string` |
| `numeric_literal` | `number` |
| `boolean_literal` | `true`, `false` |
| `null_literal` | `null` |
| `return` | `return_statement` |
| `throw` | `throw_statement` |
| `catch` | `catch_clause` |
| `if` | `if_statement` |
| `loop` | `for_statement` |
| `for_loop` | `for_in_statement` |
| `while_loop` | `while_statement`, `do_statement` |
| `block` | `statement_block`, `switch_body` |
| `decorator` | `decorator` |

Plain JavaScript (`.js`, `.mjs`, and `.cjs`) has no parameter wrapper node. The JavaScript adapter maps a node that is a direct child of `formal_parameters` to `parameter`: `identifier`, `assignment_pattern`, `object_pattern`, and `array_pattern`. An identifier in that position is a `parameter` fact and not an `identifier` fact. `rest_pattern` under `formal_parameters` is not a `parameter` fact.

`.jsx` files use the TSX grammar, which wraps every parameter. For them, the JavaScript adapter also maps:

| Kind | Grammar node types |
| --- | --- |
| `identifier` | `type_identifier` |
| `parameter` | `required_parameter`, `optional_parameter` |

TypeScript (`.ts` and `.tsx`) also maps:

| Kind | Grammar node types |
| --- | --- |
| `class` | `abstract_class_declaration`, `interface_declaration`, `enum_declaration`, `type_alias_declaration` |
| `function` | `function_signature` |
| `method` | `method_signature`, `abstract_method_signature` |
| `parameter` | `required_parameter`, `optional_parameter` |
| `identifier` | `type_identifier`, `nested_identifier` |

A TypeScript `type` alias is a `class` fact because it declares a name in the type namespace. A query for `(class)` therefore matches type aliases, interfaces, and enums. A rest parameter (`...args`) is not a `parameter` fact, because the grammar uses the same node for destructuring. A `variable_declarator` becomes an `assignment` fact only when it has a value.

Roles: the `function` field of `call_expression`, or the `constructor` field of `new_expression`, is the `callee`. When that target is a `member_expression`, its `object` is the `receiver`. `member_expression` supplies `object` and `field`. `import_statement` carries a `module` role, and `decorator` nodes attach to classes and class members. Assignments carry `left` and `right`. JSX elements carry `tag`, `attributes`, and `children`; attributes, object properties, computed properties, and spreads carry `value`; object properties carry `key`. JavaScript and TypeScript have no keyword arguments.

Toy shapes:

```js
function run(code) {
  const password = "hunter2";
  audit(code);
}
```

```ts
function run(code: string): void {
  const password = "hunter2";
  audit(code);
}
```

### Go

| Kind | Grammar node types |
| --- | --- |
| `call` | `call_expression` |
| `concurrent_spawn` | `go_statement` |
| `field_access` | `selector_expression` |
| `function` | `function_declaration` |
| `method` | `method_declaration` |
| `lambda` | `func_literal` |
| `class` | `type_spec` |
| `declaration` | `type_alias` |
| `assignment` | `assignment_statement`, `short_var_declaration`, `var_spec`, `const_spec` |
| `import` | `import_declaration` |
| `identifier` | `identifier`, `field_identifier`, `package_identifier`, `type_identifier` |
| `string_literal` | `interpreted_string_literal`, `raw_string_literal` |
| `numeric_literal` | `int_literal`, `float_literal` |
| `boolean_literal` | `true`, `false` |
| `null_literal` | `nil` |
| `return` | `return_statement` |
| `if` | `if_statement` |
| `loop` | `for_statement` |
| `block` | `block`, `expression_case`, `type_case`, `communication_case`, `default_case`, `expression_switch_statement`, `type_switch_statement` |

A `var_spec` or `const_spec` becomes an `assignment` fact only when it has a value. A Go type alias (`type A = B`) is a `declaration` fact, not a `class` fact. Every Go `for` form is a `loop`; Go has no `for_loop` or `while_loop` facts.

Roles: a call's `function` field is the `callee`. When the call target is a `selector_expression`, its `operand` field is the `receiver`. A selector's `operand` and `field` fields are the field-access `object` and `field`. Imports use every `import_spec` path under an `import_declaration`. Go has no keyword arguments or decorators.

Toy shape:

```go
func run(code string) {
    var password = "hunter2"
    audit(code)
}
```

### C And C++

C and C++ files share the `cpp` analyzer, structural adapter, and language-filter label.

| Kind | Grammar node types |
| --- | --- |
| `call` | `call_expression`, `new_expression` |
| `field_access` | `field_expression` |
| `function` | `function_definition` |
| `method` | `function_definition` inside a class or with a scoped name (see below) |
| `constructor` | `function_definition` whose scope and name match a class (see below) |
| `lambda` | `lambda_expression` |
| `class` | `class_specifier`, `struct_specifier`, `union_specifier` |
| `declaration` | `alias_declaration` |
| `module` | `namespace_definition` |
| `assignment` | `assignment_expression`, `init_declarator` |
| `import` | `preproc_include` |
| `identifier` | `identifier`, `field_identifier`, `namespace_identifier`, `qualified_identifier`, `type_identifier`, `template_function`, `template_method`, `template_type`, `dependent_name`, `destructor_name`, `operator_name`, `primitive_type` |
| `string_literal` | `char_literal`, `string_literal`, `raw_string_literal` |
| `numeric_literal` | `number_literal` |
| `boolean_literal` | `true`, `false` |
| `null_literal` | `null` |
| `return` | `return_statement` |
| `throw` | `throw_statement` |
| `catch` | `catch_clause` |
| `if` | `if_statement` |
| `loop` | `for_statement`, `for_range_loop` |
| `while_loop` | `while_statement`, `do_statement` |
| `block` | `compound_statement`, `switch_statement` |

A `function_definition` inside a class, or one with a scoped name such as `Widget::draw`, is refined to `method`. A definition whose scope and name match, such as `Widget::Widget`, is refined to `constructor`. A `using` alias is a `declaration` fact. C files expose only the subset their syntax contains.

Roles: the `function` field of `call_expression`, or the `type` field of `new_expression`, is the `callee`. A field call uses the field expression's `argument` as the `receiver`, and a qualified call uses the qualified scope as the `receiver`. `preproc_include` carries a `module` role. C and C++ have no keyword arguments or decorators.

Toy shape:

```cpp
void run(const char* code) {
    auto password = "hunter2";
    audit(code);
}
```

### Rust

| Kind | Grammar node types |
| --- | --- |
| `call` | `call_expression`, `macro_invocation` |
| `decorator` | `attribute`; also an `identifier` inside a `derive` attribute |
| `declaration` | `field_declaration` |
| `field_access` | `field_expression` |
| `function` | `function_item`, `function_signature_item` |
| `method` | `function_item` or `function_signature_item` inside an `impl` or `trait` block |
| `lambda` | `closure_expression` |
| `class` | `struct_item`, `enum_item`, `trait_item`, `type_item` |
| `module` | `mod_item` |
| `assignment` | `const_item`, `static_item`, `let_declaration`, `assignment_expression`, `compound_assignment_expr` |
| `import` | `use_declaration` |
| `identifier` | `identifier`, `field_identifier`, `scoped_identifier`, `type_identifier` |
| `string_literal` | `char_literal`, `string_literal`, `raw_string_literal` |
| `numeric_literal` | `integer_literal`, `float_literal`, `negative_literal`, and a `unary_expression` that negates a numeric literal |
| `boolean_literal` | `boolean_literal` |
| `collection_literal` | `array_expression`, `tuple_expression` |
| `return` | `return_expression` |
| `if` | `if_expression` |
| `loop` | `loop_expression` |
| `for_loop` | `for_expression` |
| `while_loop` | `while_expression` |
| `block` | `block` |

A Rust `type` alias is a `class` fact because it declares a name in the type namespace. A `const`, `static`, or `let` becomes an `assignment` fact only when it has a value. A negated numeric literal such as `-1` is one `numeric_literal` fact; the inner literal is not a second fact. Rust has no null literal.

Roles: the `function` field of a call is the `callee`; generic functions are unwrapped to their terminal function name. A field-expression call target provides the `receiver`, and a scoped identifier exposes its path as the `receiver`. Macro invocations carry `args` from their token tree. `use_declaration` carries `module` roles for the imported path or alias. Outer attributes are `attribute_item` siblings that come before the item they annotate; each one adds a `decorators` edge to the item below it. Rust has no keyword arguments.

Toy shape:

```rust
fn run(code: &str) {
    let password = "hunter2";
    audit(code);
}
```

### PHP

| Kind | Grammar node types |
| --- | --- |
| `call` | `function_call_expression`, `member_call_expression`, `nullsafe_member_call_expression`, `scoped_call_expression`, `object_creation_expression` |
| `field_access` | `member_access_expression`, `nullsafe_member_access_expression`, `scoped_property_access_expression`, `class_constant_access_expression` |
| `function` | `function_definition` |
| `method` | `method_declaration` |
| `constructor` | `method_declaration` named `__construct` |
| `lambda` | `anonymous_function`, `arrow_function` |
| `class` | `class_declaration`, `interface_declaration`, `trait_declaration`, `enum_declaration` |
| `module` | `namespace_definition` |
| `assignment` | `property_element`, `const_element`, `assignment_expression`, `augmented_assignment_expression`, `reference_assignment_expression` |
| `import` | `namespace_use_declaration` |
| `decorator` | `attribute` |
| `identifier` | `name`, `namespace_name`, `qualified_name`, `relative_scope`, `variable_name` |
| `string_literal` | `string`, `encapsed_string` |
| `numeric_literal` | `integer`, `float`, and a `unary_op_expression` that signs a numeric literal |
| `boolean_literal` | `boolean` |
| `null_literal` | `null` |
| `return` | `return_statement` |
| `throw` | `throw_expression` |
| `catch` | `catch_clause` |
| `if` | `if_statement` |
| `loop` | `for_statement` |
| `for_loop` | `foreach_statement` |
| `while_loop` | `while_statement`, `do_statement` |

A `namespace_definition` is a `module` fact named by the last segment of its namespace name. A `property_element` or `const_element` becomes an `assignment` fact only when it has a value. PHP produces no `block` facts.

Roles: call target fields are the `callee`, object or scope fields are the `receiver`, `argument` nodes are positional `args`, and named arguments are `kwargs`. Namespace `use` declarations carry `module` roles, including aliases. PHP attributes are `decorators`.

Toy shape:

```php
function run(string $code): void {
    $password = "hunter2";
    audit($code);
}
```

### Scala

| Kind | Grammar node types |
| --- | --- |
| `call` | `call_expression`, `infix_expression`, `postfix_expression` |
| `field_access` | `field_expression` |
| `function` | `function_definition`, `function_declaration`, `given_definition` |
| `method` | a `function` fact inside a class, object, trait, or enum body |
| `lambda` | `lambda_expression` |
| `class` | `class_definition`, `object_definition`, `trait_definition`, `enum_definition`, `package_object`, `type_definition` |
| `assignment` | `val_definition`, `var_definition`, `assignment_expression` |
| `import` | `import_declaration` |
| `decorator` | `annotation` |
| `identifier` | `identifier`, `operator_identifier`, `type_identifier`, `stable_type_identifier` |
| `string_literal` | `string`, `interpolated_string_expression`, `character_literal` |
| `numeric_literal` | `integer_literal`, `floating_point_literal`, and a `prefix_expression` that signs a numeric literal |
| `boolean_literal` | `boolean_literal` |
| `null_literal` | `null_literal` |
| `return` | `return_expression` |
| `throw` | `throw_expression` |
| `catch` | `catch_clause` |
| `if` | `if_expression` |
| `for_loop` | `for_expression` |
| `while_loop` | `while_expression`, `do_while_expression` |
| `block` | `block`, `indented_block`, `case_clause`, `extension_definition` |

A function inside a template body (including one inside an `extension` block within it) is refined to `method`. A named argument such as `f(x = 1)` is a `kwargs` entry, not an `assignment` fact.

Roles: generic functions are unwrapped to their terminal name, field-expression receivers are the `receiver`, and calls support positional `args`, named `kwargs`, and block-style arguments. Annotations are `decorators`.

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

| Kind | Grammar node types |
| --- | --- |
| `call` | `invocation_expression`, `object_creation_expression` |
| `field_access` | `member_access_expression`, `conditional_access_expression` (only when it has a member binding) |
| `function` | `local_function_statement` |
| `method` | `method_declaration` |
| `constructor` | `constructor_declaration` |
| `lambda` | `lambda_expression`, `anonymous_method_expression` |
| `class` | `class_declaration`, `interface_declaration`, `struct_declaration`, `enum_declaration`, `record_declaration` |
| `module` | `namespace_declaration`, `file_scoped_namespace_declaration` |
| `declaration` | `property_declaration` |
| `assignment` | `variable_declarator`, `assignment_expression` |
| `import` | `using_directive` |
| `decorator` | `attribute` |
| `identifier` | `identifier`, `implicit_parameter`, `generic_name`, `qualified_name`, `alias_qualified_name`, `predefined_type` |
| `string_literal` | `string_literal`, `verbatim_string_literal`, `raw_string_literal`, `character_literal` |
| `numeric_literal` | `integer_literal`, `real_literal`, and a `prefix_unary_expression` that signs a numeric literal |
| `boolean_literal` | `boolean_literal` |
| `null_literal` | `null_literal` |
| `return` | `return_statement` |
| `throw` | `throw_statement`, `throw_expression` |
| `catch` | `catch_clause` |
| `if` | `if_statement`, `switch_statement` |
| `loop` | `for_statement` |
| `for_loop` | `foreach_statement` |
| `while_loop` | `while_statement`, `do_statement` |
| `block` | `block` |

A namespace is a `module` fact named by the last segment of a qualified namespace name. A `switch` statement is an `if` fact. A `variable_declarator` becomes an `assignment` fact only when it has a value.

Roles: invocation `function` targets and object-creation `type` targets are the `callee`. Member and conditional access targets provide `receiver`, `object`, and `field`. Arguments are positional `args` or named `kwargs`. Attributes are `decorators`, and `using` aliases are import `module` names.

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

| Kind | Grammar node types |
| --- | --- |
| `call` | `call`; also a bare `identifier` that Ruby evaluates as a method call |
| `import` | a `call` to `require`, `require_relative`, `load`, or `autoload` with no receiver and a module argument |
| `function` | `method` |
| `method` | `singleton_method`; also a `method` directly inside a `class` |
| `lambda` | `lambda`, `block`, `do_block` |
| `class` | `class`, `singleton_class` |
| `module` | `module` |
| `assignment` | `assignment`, `operator_assignment` |
| `field_access` | `scope_resolution` |
| `identifier` | `identifier`, `constant`, `instance_variable`, `class_variable`, `global_variable`, `self`, `simple_symbol`, `delimited_symbol`, `hash_key_symbol` |
| `string_literal` | `string` |
| `numeric_literal` | `integer`, `float`, and a `unary` that signs a numeric literal |
| `boolean_literal` | `true`, `false` |
| `null_literal` | `nil` |
| `return` | `return` |
| `catch` | `rescue` |
| `if` | `if`, `unless` |
| `for_loop` | `for` |
| `while_loop` | `while`, `until` |

A `def` directly inside a `class` is `method`. A `def` at the top level or inside a `module` stays `function`. The `block` or `do_block` that forms the body of a `lambda` is not a second `lambda` fact. Ruby produces no `throw` facts (`raise` is a call) and no `block` facts.

Roles: the call `method` field is the `callee`, the optional `receiver` is the `receiver`, ordinary arguments are `args`, and hash-pair arguments are `kwargs`. A static import string carries a `module` role. An interpolated string carries no module name. Ruby has no decorators.

Toy shape:

```ruby
def run(code)
  password = "hunter2"
  audit(code)
end
```

### Kotlin

| Kind | Grammar node types |
| --- | --- |
| `call` | `call_expression`, `constructor_invocation`, `infix_expression` |
| `field_access` | `navigation_expression` |
| `function` | `function_declaration` |
| `method` | `function_declaration` directly inside a class-like declaration |
| `constructor` | `primary_constructor`, `secondary_constructor` |
| `lambda` | `lambda_literal`, `anonymous_function` |
| `class` | `class_declaration`, `object_declaration`, `companion_object`, `object_literal`, `type_alias` |
| `assignment` | `property_declaration`, `assignment` |
| `import` | `import_header` |
| `decorator` | `annotation`, `file_annotation` |
| `identifier` | `simple_identifier`, `type_identifier` |
| `string_literal` | `string_literal`, `character_literal` |
| `numeric_literal` | `integer_literal`, `real_literal`, `hex_literal`, `bin_literal`, `long_literal`, `unsigned_literal`, and a `prefix_expression` that signs a numeric literal |
| `boolean_literal` | `boolean_literal` |
| `null_literal` | `null_literal` |
| `return` | `jump_expression` that is a `return` |
| `throw` | `jump_expression` that is a `throw` |
| `catch` | `catch_block` |
| `if` | `if_expression`, `when_expression` |
| `for_loop` | `for_statement` |
| `while_loop` | `while_statement`, `do_while_statement` |
| `block` | `statements` |

A `break` or `continue` jump is neither `return` nor `throw`. A `property_declaration` becomes an `assignment` fact only when it has a value; an uninitialized property stays a declaration. A `when` expression is an `if` fact. A Kotlin `typealias` is a `class` fact.

Roles: the adapter derives terminal callees and navigation receivers, and calls carry positional `args`, named `kwargs`, and trailing lambdas. Navigation expressions expose `object` and `field`. Initialized properties and assignments carry `left` and `right`. Imports carry the terminal and qualified `module` names. Annotations attach to declarations as `decorators`.

Toy shape:

```kotlin
fun run(code: String) {
    val password = "hunter2"
    audit(code)
}
```

## From Mappings To Queries

Query normalized kinds and roles rather than the tree-sitter names listed above. Start from `:ir <language>`, copy the starter RQL, and refine it with the [Rune Query Language](/rune-query-language/) guide. For complete executable examples, see the [language tutorials](/code-query-tutorials/). For the list of languages Bifrost analyzes, see [Languages](/reference/languages/).
