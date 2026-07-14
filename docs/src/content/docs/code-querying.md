---
title: Code Querying
description: Understand Bifrost's structural code-querying model and its query representations.
---

Bifrost's composable code-query engine is `query_code`. Version 2 searches normalized syntactic structure and can transform matches through enclosing declarations, exact source references and semantic users, direct import-file edges, indexed type hierarchies, and declaration ownership. It answers questions such as “find calls to this callee,” “which declarations use this field,” “which types derive from this type,” and “which declarations are direct members of those types” across supported languages.

The broader name is intentional. Future versions may add more steps backed by Bifrost's existing usage and type analyses or by future control-flow and data-flow analyses. Version 2 does not traverse call graphs, resolve arbitrary types or aliases, or prove control/data flow.

## Choose The Right Tool

Use the narrowest tool that directly answers the question:

| Question | Tool | Why |
| --- | --- | --- |
| “Where is `Parser.parse` declared?” | `search_symbols` | Searches indexed declarations by name. |
| “Who references this exact symbol?” | `scan_usages_by_reference` or `scan_usages_by_location` | Resolves a known declaration to reference sites from a symbol or source location. |
| “What is the workspace caller/callee graph?” | `usage_graph` | Returns the existing whole-workspace resolved usage graph. |
| “Which code has this shape, enclosing declaration, import relationship, or indexed type/member relationship?” | `query_code` | Matches normalized kinds and applies typed declaration/file steps. |
| “Which code is conceptually about retry policy?” | `semantic_search` | Retrieves code by meaning rather than exact structure. |
| “Where does this literal text occur?” | `search_file_contents` | Searches source text without structural interpretation. |

Start with `search_symbols` or the mode-appropriate scan-usages tool when you already know the symbol. Use `query_code` when the shape matters more than symbol identity. A useful workflow is to capture structural candidates with `query_code`, then pass their locations or enclosing symbols to the more semantic tools.

Each language adapter starts from tree-sitter parses, then maps grammar-specific nodes and fields into a shared structural model:

- normalized kinds such as `function`, `method`, `class`, `call`, `literal`, and `field_access`
- normalized roles such as `callee`, `receiver`, `args`, `left`, `right`, `module`, `decorators`, `object`, and `field`
- source ranges, names, parent links, and role edges that let the matcher reason about containment and relationships

The matcher only sees this normalized fact arena. Language-specific tree-sitter node names stop at the adapter boundary, so a query can ask for a `call` with a `callee` across supported languages without knowing each grammar's internal node labels.

## Version 2 Typed Pipelines

`query_code` validates the structural seed query, chooses candidate files and facts, and then applies an ordered typed pipeline. Queries without steps return tagged structural matches. `enclosing_decl` returns exact indexed declarations; `references_of`, `used_by`, and `uses` traverse exact structured references; `file_of`, `imports_of`, and `importers_of` navigate project files; `supertypes` and `subtypes` traverse direct, bounded, or transitive indexed hierarchy edges; and `members` / `owner` navigate exact declaration ownership. Derived results retain seed-and-edge provenance.

Semantic declaration steps intentionally stop at the analyzer's indexed declaration boundary. Seeing a reference or usage into a dependency is not evidence that the dependency declaration is indexed. Until Bifrost can target library code for indexing, unindexed library declarations are omitted rather than reconstructed from names, and their absence is not reported as a capability error.

| RQL wrapper | JSON step | Input → output | Use it to |
| --- | --- | --- | --- |
| `enclosing-decl` | `enclosing_decl` | structural match → indexed declaration | Find the smallest real declaration that contains a matching expression. |
| `references-of` | `references_of` | declaration → reference site | Return exact structured sites targeting a declaration. |
| `used-by` | `used_by` | declaration → declaration | Return each smallest exact semantic user, with its proving site under `via`. |
| `uses` | `uses` | declaration → declaration | Return exact indexed targets used by one semantic declaration, with `via`. |
| `file-of` | `file_of` | structural match, declaration, or reference site → file | Move from code, a declaration, or a reference to the exact project file. |
| `imports-of` | `imports_of` | file → file | Follow one resolved direct project-local import. |
| `importers-of` | `importers_of` | file → file | Find every project file with a resolved direct import of that file. |

For example, `(importers-of (file-of (function :name "target")))` answers “which project files directly import the file declaring `target`?” It is deliberately a file relationship: it does not prove that an importer uses that particular declaration, resolve an out-of-scope library's members, or manufacture external declarations. The schema-v2 `references-of`, `used-by`, and `uses` steps provide that exact declaration relationship separately, and `references-of` can compose through `file-of` when both symbol and import-file provenance matter. See [Reference Traversal](./code-query-tutorials/reference-traversal/).

The engine has one semantic query model: `CodeQuery`. Different input formats must lower into that same model before execution.

## Query Representations

Bifrost currently has two representations for `CodeQuery`:

- [Rune Query Language](/rune-query-language/) is the experimental S-expression syntax used by the human REPL.
- [JSON CodeQuery](/code-query-json/) is the canonical JSON representation used by `query_code` over MCP and by `:json` output in the REPL.

JSON is not a separate query language. It is the stable serialization of the `CodeQuery` model. RQL is a convenience language that compiles to that JSON-shaped model.

See [JSON CodeQuery](/code-query-json/) for the complete schema, validation rules, result model, and copy-paste examples. See [Rune Query Language](/rune-query-language/) for interactive authoring and canonical JSON inspection.

For source-first walkthroughs, see the [per-language `query_code` tutorials](/code-query-tutorials/). Their fixtures, RQL and JSON forms, and exact results are exercised against the real structural adapters.

## Adapter Mapping Notes

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

## CLI Mini Tutorial

The examples below use one-shot CLI mode. They were validated against a toy workspace containing the small per-language shapes shown above, with one file for each supported language. The [JSON reference](/code-query-json/) contains the complete, test-parsed input examples.

### Saved Queries

For a reusable query, save the complete RQL or canonical JSON query under the workspace and run it directly:

```bash
bifrost --query-file queries/audit.rql
bifrost --root ./code-query-toy --query-file queries/audit.json
```

The current directory is the default workspace root. Query files must stay within that workspace after symlinks resolve. `--query-file` selects the complete query and does not merge command-line filters or inline JSON.

Find calls to `audit` across every structural adapter:

```bash
bifrost --root ./code-query-toy --tool query_code --args '{"match":{"kind":"call","callee":{"name":"audit"}},"limit":20}'
```

The result contains one `call` match for each current analyzable language and no diagnostics. Representative rows look like:

```json
{"result_type":"structural_match","language":"python","path":"python/app.py","kind":"call","text":"audit(code)"}
{"result_type":"structural_match","language":"typescript","path":"typescript/app.ts","kind":"call","text":"audit(code)"}
{"result_type":"structural_match","language":"ruby","path":"ruby/app.rb","kind":"call","text":"audit(code)"}
```

Find assignments to `password` whose right-hand side is a string literal, and capture the value:

```bash
bifrost --root ./code-query-toy --tool query_code --args '{"match":{"kind":"assignment","left":{"name":"password"},"right":{"kind":"string_literal","capture":"value"}},"limit":20}'
```

The result contains one assignment match per language. The captured `value` is `"hunter2"` in each match, even though the source syntax varies:

```json
{"result_type":"structural_match","language":"java","text":"password = \"hunter2\"","captures":[{"name":"value","text":"\"hunter2\""}]}
{"result_type":"structural_match","language":"php","text":"$password = \"hunter2\"","captures":[{"name":"value","text":"\"hunter2\""}]}
{"result_type":"structural_match","language":"rust","text":"let password = \"hunter2\";","captures":[{"name":"value","text":"\"hunter2\""}]}
```

Limit a query to one adapter while debugging a mapping:

```bash
bifrost --root ./code-query-toy --tool query_code --args '{"languages":["typescript"],"match":{"kind":"call","callee":{"name":"audit"},"args":[{"capture":"argument"}]},"result_detail":"full"}'
```

This searches only TypeScript files and returns the matched call plus deterministic byte and line ranges because `result_detail` is `full`.

## Where To Start

Use RQL when you are exploring a repository interactively:

```bash
bifrost --root /path/to/project --repl
```

Use JSON `CodeQuery` when a host, script, or MCP client needs a stable machine-facing payload for the `query_code` tool.
